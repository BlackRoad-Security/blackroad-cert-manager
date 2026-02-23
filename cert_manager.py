"""
BlackRoad Certificate Manager - TLS certificate lifecycle management.
Uses Python stdlib ssl/socket only for certificate inspection. SQLite backend.
"""

import json
import socket
import sqlite3
import ssl
import uuid
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class CertStatus(str, Enum):
    VALID = "valid"
    EXPIRING = "expiring"
    EXPIRED = "expired"
    REVOKED = "revoked"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass
class Certificate:
    id: str
    domain: str
    sans: list             # Subject Alternative Names
    issuer: str
    subject: str
    serial: str
    not_before: str
    not_after: str
    fingerprint: str       # SHA-256
    key_size: int
    algorithm: str
    status: CertStatus
    port: int = 443
    last_checked: str = ""
    notes: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    @property
    def days_until_expiry(self) -> int:
        try:
            expiry = datetime.fromisoformat(self.not_after.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            return (expiry - now).days
        except Exception:
            return -1

    @property
    def is_expired(self) -> bool:
        return self.days_until_expiry < 0

    @property
    def is_expiring_soon(self, days: int = 30) -> bool:
        d = self.days_until_expiry
        return 0 <= d <= days


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS certificates (
    id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    sans TEXT NOT NULL,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    serial TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    key_size INTEGER NOT NULL DEFAULT 0,
    algorithm TEXT NOT NULL,
    status TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 443,
    last_checked TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_certs_domain ON certificates(domain);
CREATE INDEX IF NOT EXISTS idx_certs_status ON certificates(status);
CREATE INDEX IF NOT EXISTS idx_certs_expiry ON certificates(not_after);

CREATE TABLE IF NOT EXISTS scan_history (
    id TEXT PRIMARY KEY,
    cert_id TEXT NOT NULL,
    status TEXT NOT NULL,
    days_remaining INTEGER NOT NULL,
    scanned_at TEXT NOT NULL,
    FOREIGN KEY (cert_id) REFERENCES certificates(id)
);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    message TEXT NOT NULL,
    severity TEXT NOT NULL,
    created_at TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_cert(row: tuple) -> Certificate:
    (id_, domain, sans_j, issuer, subject, serial, not_before, not_after,
     fp, key_size, algo, status, port, last_checked, notes) = row
    return Certificate(
        id=id_, domain=domain, sans=json.loads(sans_j),
        issuer=issuer, subject=subject, serial=serial,
        not_before=not_before, not_after=not_after,
        fingerprint=fp, key_size=key_size, algorithm=algo,
        status=CertStatus(status), port=port,
        last_checked=last_checked, notes=notes,
    )


# ---------------------------------------------------------------------------
# Certificate parsing helpers (stdlib only)
# ---------------------------------------------------------------------------

def _parse_dn(dn_dict: dict) -> str:
    """Convert ssl cert DN dict to string."""
    parts = []
    for item in dn_dict:
        for k, v in item:
            parts.append(f"{k}={v}")
    return ", ".join(parts)


def _extract_sans(cert_dict: dict) -> list:
    """Extract Subject Alternative Names from ssl cert dict."""
    sans = []
    for key, values in cert_dict.get("subjectAltName", []):
        if key.lower() == "dns":
            sans.append(values)
    return sans


def _parse_ssl_date(date_str: str) -> str:
    """Parse SSL certificate date to ISO format."""
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            dt = datetime.strptime(date_str.strip(), fmt)
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    return date_str


def fetch_cert_from_host(domain: str, port: int = 443, timeout: int = 10) -> dict:
    """
    Connect to host and retrieve the certificate as a dict.
    Returns raw ssl cert dict plus raw PEM-like info.
    Uses stdlib ssl/socket only.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # still get cert even if invalid

    with socket.create_connection((domain, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
            cert_dict = ssock.getpeercert()
            cipher = ssock.cipher()

    import hashlib
    fingerprint = hashlib.sha256(cert_der).hexdigest()

    # Try to determine key size from cipher name
    key_size = 0
    algo = "unknown"
    if cipher:
        cipher_name = cipher[0] or ""
        if "RSA" in cipher_name:
            algo = "RSA"
        elif "ECDSA" in cipher_name or "ECDH" in cipher_name:
            algo = "ECDSA"
        # Key size not directly available without cryptography lib, estimate from DER size
        # Rough estimate
        key_size = _estimate_key_size(cert_der)

    return {
        "cert_dict": cert_dict,
        "fingerprint": fingerprint,
        "key_size": key_size,
        "algorithm": algo,
        "cipher": cipher,
        "der_size": len(cert_der),
    }


def _estimate_key_size(der_bytes: bytes) -> int:
    """Very rough key size estimate based on DER certificate size."""
    size = len(der_bytes)
    if size > 1500:
        return 4096
    elif size > 1000:
        return 2048
    elif size > 600:
        return 1024
    return 256


# ---------------------------------------------------------------------------
# CertManager
# ---------------------------------------------------------------------------

class CertManager:
    """TLS certificate lifecycle management."""

    def __init__(self, db_path: str = "cert_manager.db"):
        self.db_path = db_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def add_cert_from_host(self, domain: str, port: int = 443) -> Certificate:
        """
        Connect to host and add its certificate to the database.
        Uses stdlib ssl/socket only.
        """
        try:
            info = fetch_cert_from_host(domain, port)
        except Exception as e:
            raise RuntimeError(f"Failed to fetch certificate from {domain}:{port}: {e}")

        cert_dict = info["cert_dict"]
        return self._store_cert(domain, cert_dict, info, port)

    def _store_cert(self, domain: str, cert_dict: dict, extra: dict, port: int) -> Certificate:
        subject_str = _parse_dn(cert_dict.get("subject", []))
        issuer_str = _parse_dn(cert_dict.get("issuer", []))
        sans = _extract_sans(cert_dict)
        if not sans:
            sans = [domain]

        not_before_raw = cert_dict.get("notBefore", "")
        not_after_raw = cert_dict.get("notAfter", "")
        not_before = _parse_ssl_date(not_before_raw)
        not_after = _parse_ssl_date(not_after_raw)

        serial = str(cert_dict.get("serialNumber", "unknown"))
        fingerprint = extra.get("fingerprint", "")

        cert_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{domain}:{fingerprint}"))
        now = _now()

        # Determine initial status
        cert = Certificate(
            id=cert_id,
            domain=domain,
            sans=sans,
            issuer=issuer_str,
            subject=subject_str,
            serial=serial,
            not_before=not_before,
            not_after=not_after,
            fingerprint=fingerprint,
            key_size=extra.get("key_size", 0),
            algorithm=extra.get("algorithm", "unknown"),
            status=CertStatus.VALID,
            port=port,
            last_checked=now,
        )
        cert = self._compute_status(cert)

        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO certificates
                   (id, domain, sans, issuer, subject, serial, not_before, not_after,
                    fingerprint, key_size, algorithm, status, port, last_checked, notes)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (cert.id, cert.domain, json.dumps(cert.sans), cert.issuer, cert.subject,
                 cert.serial, cert.not_before, cert.not_after, cert.fingerprint,
                 cert.key_size, cert.algorithm, cert.status.value, cert.port,
                 cert.last_checked, cert.notes),
            )
            conn.execute(
                """INSERT INTO scan_history (id, cert_id, status, days_remaining, scanned_at)
                   VALUES (?,?,?,?,?)""",
                (str(uuid.uuid4()), cert.id, cert.status.value,
                 cert.days_until_expiry, now),
            )
        return cert

    def add_cert(self, domain: str, cert_pem: str = None, port: int = 443) -> Certificate:
        """Add a certificate. If cert_pem is None, fetches from host."""
        if cert_pem:
            return self._parse_and_store_pem(domain, cert_pem, port)
        return self.add_cert_from_host(domain, port)

    def _parse_and_store_pem(self, domain: str, pem_data: str, port: int) -> Certificate:
        """Parse PEM data and store. Uses ssl module for parsing."""
        info = self.parse_cert_info(pem_data)
        cert = Certificate(
            id=str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{domain}:{info.get('fingerprint', '')}")),
            domain=domain,
            sans=info.get("sans", [domain]),
            issuer=info.get("issuer", ""),
            subject=info.get("subject", ""),
            serial=info.get("serial", ""),
            not_before=info.get("not_before", ""),
            not_after=info.get("not_after", ""),
            fingerprint=info.get("fingerprint", ""),
            key_size=info.get("key_size", 0),
            algorithm=info.get("algorithm", "unknown"),
            status=CertStatus.UNKNOWN,
            port=port,
            last_checked=_now(),
        )
        cert = self._compute_status(cert)
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO certificates
                   (id, domain, sans, issuer, subject, serial, not_before, not_after,
                    fingerprint, key_size, algorithm, status, port, last_checked, notes)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (cert.id, cert.domain, json.dumps(cert.sans), cert.issuer, cert.subject,
                 cert.serial, cert.not_before, cert.not_after, cert.fingerprint,
                 cert.key_size, cert.algorithm, cert.status.value, cert.port,
                 cert.last_checked, cert.notes),
            )
        return cert

    def parse_cert_info(self, pem_data: str) -> dict:
        """
        Parse a PEM certificate and extract metadata.
        Uses Python stdlib ssl module only.
        """
        import hashlib
        try:
            # Convert PEM to DER
            lines = pem_data.strip().splitlines()
            b64 = "".join(
                line for line in lines
                if not line.startswith("-----")
            )
            import base64
            der_bytes = base64.b64decode(b64)
        except Exception as e:
            raise ValueError(f"Invalid PEM data: {e}")

        # Use ssl.DER_cert_to_PEM_cert + ssl to get metadata
        try:
            pem_clean = ssl.DER_cert_to_PEM_cert(der_bytes)
            cert_dict = ssl.PEM_cert_to_DER_cert(pem_clean)
            # We can't easily parse the DER fully without cryptography lib
            # but we can get fingerprint and rough info
        except Exception:
            pass

        fingerprint = hashlib.sha256(der_bytes).hexdigest()

        # Try to load via ssl context (will fail for self-signed/untrusted)
        result = {
            "fingerprint": fingerprint,
            "key_size": _estimate_key_size(der_bytes),
            "algorithm": "RSA",  # default assumption
            "sans": [],
            "issuer": "",
            "subject": "",
            "serial": "",
            "not_before": "",
            "not_after": "",
        }

        # Best-effort extraction using ssl.PEM_cert_to_DER_cert
        try:
            # Build a fake SSL connection to parse - not possible without server
            # Instead, use a temp file approach with ssl
            import tempfile, os
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as f:
                f.write(pem_data)
                tmp_path = f.name
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                # Load PEM and get what info we can
                cert_info = ssl.PEM_cert_to_DER_cert(pem_data)
                result["der_size"] = len(cert_info)
                result["key_size"] = _estimate_key_size(cert_info)
            except Exception:
                pass
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
        except Exception:
            pass

        return result

    def _compute_status(self, cert: Certificate, warning_days: int = 30) -> Certificate:
        """Compute and update certificate status based on expiry."""
        days = cert.days_until_expiry
        if days < 0:
            cert.status = CertStatus.EXPIRED
        elif days <= warning_days:
            cert.status = CertStatus.EXPIRING
        else:
            cert.status = CertStatus.VALID
        return cert

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_cert(self, cert_id: str) -> Optional[Certificate]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM certificates WHERE id=?", (cert_id,)).fetchone()
        return _row_to_cert(row) if row else None

    def get_cert_by_domain(self, domain: str) -> Optional[Certificate]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM certificates WHERE domain=? ORDER BY last_checked DESC LIMIT 1",
                (domain,),
            ).fetchone()
        return _row_to_cert(row) if row else None

    def list_certs(self) -> list:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM certificates ORDER BY not_after"
            ).fetchall()
        return [_row_to_cert(r) for r in rows]

    def get_expiring(self, days: int = 30) -> list:
        """Return certificates expiring within `days` days."""
        certs = self.list_certs()
        return [c for c in certs if 0 <= c.days_until_expiry <= days]

    def get_expired(self) -> list:
        """Return all expired certificates."""
        certs = self.list_certs()
        return [c for c in certs if c.days_until_expiry < 0]

    def check_expiry(self, domain: str, days_warning: int = 30) -> dict:
        """
        Check expiry for a domain. Refreshes from live host if possible.
        Returns a status dict.
        """
        result = {"domain": domain, "status": "not_found", "days_remaining": None}
        try:
            cert = self.add_cert_from_host(domain)
        except Exception:
            # Fall back to stored cert
            cert = self.get_cert_by_domain(domain)
        if not cert:
            return result
        days = cert.days_until_expiry
        result.update({
            "domain": domain,
            "cert_id": cert.id,
            "days_remaining": days,
            "not_after": cert.not_after,
            "issuer": cert.issuer,
            "status": cert.status.value,
            "action_required": days < days_warning,
        })
        return result

    def refresh_all(self) -> list:
        """Refresh all stored certificates from live hosts."""
        certs = self.list_certs()
        results = []
        for cert in certs:
            try:
                updated = self.add_cert_from_host(cert.domain, cert.port)
                results.append({"domain": cert.domain, "status": "refreshed",
                                 "days": updated.days_until_expiry})
            except Exception as e:
                results.append({"domain": cert.domain, "status": "error", "error": str(e)})
        return results

    def remove_cert(self, cert_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM certificates WHERE id=?", (cert_id,))
        return cur.rowcount > 0

    def update_notes(self, cert_id: str, notes: str) -> Optional[Certificate]:
        with self._connect() as conn:
            conn.execute("UPDATE certificates SET notes=? WHERE id=?", (notes, cert_id))
        return self.get_cert(cert_id)

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_chain(self, cert_id: str) -> dict:
        """
        Verify the certificate chain for a domain using stdlib ssl.
        Returns verification result dict.
        """
        cert = self.get_cert(cert_id)
        if not cert:
            return {"cert_id": cert_id, "valid": False, "error": "Certificate not found"}

        result = {
            "cert_id": cert_id,
            "domain": cert.domain,
            "valid": False,
            "error": None,
            "issuer": cert.issuer,
            "days_remaining": cert.days_until_expiry,
        }

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((cert.domain, cert.port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=cert.domain) as ssock:
                    verified_cert = ssock.getpeercert()
                    result["valid"] = True
                    result["verified_issuer"] = _parse_dn(
                        verified_cert.get("issuer", [])
                    )
                    result["verified_subject"] = _parse_dn(
                        verified_cert.get("subject", [])
                    )
        except ssl.SSLCertVerificationError as e:
            result["error"] = f"Chain verification failed: {e}"
        except ssl.SSLError as e:
            result["error"] = f"SSL error: {e}"
        except Exception as e:
            result["error"] = f"Connection error: {e}"

        return result

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def _create_alert(self, domain: str, alert_type: str, message: str, severity: str):
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO alerts (id, domain, alert_type, message, severity, created_at)
                   VALUES (?,?,?,?,?,?)""",
                (str(uuid.uuid4()), domain, alert_type, message, severity, _now()),
            )

    def check_and_alert(self, days_warning: int = 30, days_critical: int = 7) -> list:
        """Check all certs and generate alerts for expiring/expired ones."""
        certs = self.list_certs()
        alerts_generated = []
        for cert in certs:
            days = cert.days_until_expiry
            if days < 0:
                msg = f"Certificate for {cert.domain} EXPIRED {abs(days)} days ago"
                self._create_alert(cert.domain, "expired", msg, "critical")
                alerts_generated.append({"domain": cert.domain, "severity": "critical", "days": days})
            elif days <= days_critical:
                msg = f"Certificate for {cert.domain} expires in {days} days (CRITICAL)"
                self._create_alert(cert.domain, "expiring_critical", msg, "critical")
                alerts_generated.append({"domain": cert.domain, "severity": "critical", "days": days})
            elif days <= days_warning:
                msg = f"Certificate for {cert.domain} expires in {days} days"
                self._create_alert(cert.domain, "expiring_warning", msg, "warning")
                alerts_generated.append({"domain": cert.domain, "severity": "warning", "days": days})
        return alerts_generated

    def get_alerts(self) -> list:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE acknowledged=0 ORDER BY created_at DESC"
            ).fetchall()
        return [{"id": r[0], "domain": r[1], "type": r[2], "message": r[3],
                 "severity": r[4], "created_at": r[5]} for r in rows]

    # ------------------------------------------------------------------
    # Export / Inventory
    # ------------------------------------------------------------------

    def export_inventory(self, format: str = "json") -> str:
        """Export full certificate inventory as JSON or CSV text."""
        certs = self.list_certs()
        if format.lower() == "json":
            data = [c.to_dict() for c in certs]
            for d in data:
                d["days_until_expiry"] = Certificate(
                    id=d["id"], domain=d["domain"], sans=d["sans"],
                    issuer=d["issuer"], subject=d["subject"], serial=d["serial"],
                    not_before=d["not_before"], not_after=d["not_after"],
                    fingerprint=d["fingerprint"], key_size=d["key_size"],
                    algorithm=d["algorithm"], status=CertStatus(d["status"]),
                    port=d["port"], last_checked=d["last_checked"], notes=d["notes"],
                ).days_until_expiry
            return json.dumps({"exported_at": _now(), "count": len(data), "certificates": data}, indent=2)
        elif format.lower() == "csv":
            lines = ["domain,issuer,not_after,days_remaining,status,key_size,algorithm,fingerprint"]
            for c in certs:
                lines.append(
                    f"{c.domain},{c.issuer},{c.not_after},"
                    f"{c.days_until_expiry},{c.status.value},"
                    f"{c.key_size},{c.algorithm},{c.fingerprint[:16]}..."
                )
            return "\n".join(lines)
        else:
            raise ValueError(f"Unknown format: {format}")

    def stats(self) -> dict:
        """Return certificate statistics."""
        certs = self.list_certs()
        valid = [c for c in certs if c.status == CertStatus.VALID]
        expiring = [c for c in certs if c.status == CertStatus.EXPIRING]
        expired = [c for c in certs if c.status == CertStatus.EXPIRED]
        return {
            "total": len(certs),
            "valid": len(valid),
            "expiring_soon": len(expiring),
            "expired": len(expired),
            "algorithms": {},
            "expiring_domains": [c.domain for c in expiring],
            "expired_domains": [c.domain for c in expired],
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import sys
    db = CertManager()
    args = sys.argv[1:]

    if not args:
        print("BlackRoad Certificate Manager")
        print("Usage: python cert_manager.py <command> [args]")
        print()
        print("Commands:")
        print("  add <domain> [port]         - Add cert by scanning host")
        print("  check <domain> [days]       - Check expiry for domain")
        print("  get <domain>                - Get stored cert details")
        print("  expiring [days]             - List expiring certs")
        print("  expired                     - List expired certs")
        print("  list                        - List all certificates")
        print("  verify <domain>             - Verify certificate chain")
        print("  refresh                     - Refresh all certs from live hosts")
        print("  alerts [days_warn] [days_crit] - Check and list alerts")
        print("  export [json|csv]           - Export inventory")
        print("  remove <cert_id>            - Remove a certificate")
        print("  stats                       - Certificate statistics")
        print("  demo                        - Add demo certificates")
        return

    cmd = args[0]

    def _print_cert(cert: Certificate):
        status_colors = {
            "valid": "\033[92m", "expiring": "\033[93m",
            "expired": "\033[91m", "revoked": "\033[95m", "unknown": "\033[94m",
        }
        reset = "\033[0m"
        color = status_colors.get(cert.status.value, "")
        days = cert.days_until_expiry
        days_str = f"{days}d" if days >= 0 else f"EXPIRED {abs(days)}d ago"
        print(f"  [{color}{cert.status.value.upper()}{reset}] {cert.domain}")
        print(f"    Issuer:   {cert.issuer[:60]}")
        print(f"    Expires:  {cert.not_after[:10]} ({days_str})")
        print(f"    Algo:     {cert.algorithm}  Key: {cert.key_size}b  Port: {cert.port}")
        print(f"    SANs:     {', '.join(cert.sans[:5])}")
        print(f"    SHA256:   {cert.fingerprint[:32]}...")
        if cert.notes:
            print(f"    Notes:    {cert.notes}")

    if cmd == "add":
        if len(args) < 2:
            print("Usage: add <domain> [port]"); return
        port = int(args[2]) if len(args) > 2 else 443
        print(f"Fetching certificate from {args[1]}:{port}...")
        try:
            cert = db.add_cert(args[1], port=port)
            print(f"✓ Certificate added:")
            _print_cert(cert)
        except Exception as e:
            print(f"✗ Error: {e}")

    elif cmd == "check":
        if len(args) < 2:
            print("Usage: check <domain> [days]"); return
        days = int(args[2]) if len(args) > 2 else 30
        result = db.check_expiry(args[1], days)
        print(f"Expiry check for {args[1]}:")
        print(f"  Status:        {result['status']}")
        print(f"  Days remaining: {result.get('days_remaining', 'N/A')}")
        print(f"  Not after:     {result.get('not_after', 'N/A')}")
        print(f"  Action needed: {'YES' if result.get('action_required') else 'no'}")

    elif cmd == "get":
        if len(args) < 2:
            print("Usage: get <domain>"); return
        cert = db.get_cert_by_domain(args[1])
        if cert:
            _print_cert(cert)
        else:
            print(f"✗ No certificate found for {args[1]}")

    elif cmd == "expiring":
        days = int(args[1]) if len(args) > 1 else 30
        certs = db.get_expiring(days)
        print(f"Certificates expiring within {days} days: {len(certs)}")
        for c in certs:
            _print_cert(c)

    elif cmd == "expired":
        certs = db.get_expired()
        print(f"Expired certificates: {len(certs)}")
        for c in certs:
            _print_cert(c)

    elif cmd == "list":
        certs = db.list_certs()
        print(f"All certificates: {len(certs)}")
        for c in certs:
            _print_cert(c)

    elif cmd == "verify":
        if len(args) < 2:
            print("Usage: verify <domain>"); return
        cert = db.get_cert_by_domain(args[1])
        if not cert:
            # Try adding first
            try:
                cert = db.add_cert(args[1])
            except Exception as e:
                print(f"✗ Could not fetch cert: {e}"); return
        result = db.verify_chain(cert.id)
        status = "✓ VALID" if result["valid"] else f"✗ INVALID: {result.get('error')}"
        print(f"Chain verification for {args[1]}: {status}")
        if result.get("verified_issuer"):
            print(f"  Issuer: {result['verified_issuer']}")
        print(f"  Days remaining: {result['days_remaining']}")

    elif cmd == "refresh":
        print("Refreshing all certificates from live hosts...")
        results = db.refresh_all()
        for r in results:
            if r["status"] == "refreshed":
                print(f"  ✓ {r['domain']}: {r['days']}d remaining")
            else:
                print(f"  ✗ {r['domain']}: {r.get('error', 'error')}")

    elif cmd == "alerts":
        days_warn = int(args[1]) if len(args) > 1 else 30
        days_crit = int(args[2]) if len(args) > 2 else 7
        new_alerts = db.check_and_alert(days_warn, days_crit)
        all_alerts = db.get_alerts()
        print(f"New alerts generated: {len(new_alerts)}")
        print(f"Total unacknowledged alerts: {len(all_alerts)}")
        for a in all_alerts[:20]:
            print(f"  [{a['severity'].upper()}] {a['domain']}: {a['message']}")

    elif cmd == "export":
        fmt = args[1] if len(args) > 1 else "json"
        output = db.export_inventory(fmt)
        fname = f"cert_inventory.{fmt}"
        with open(fname, "w") as f:
            f.write(output)
        print(f"✓ Inventory exported to {fname}")

    elif cmd == "remove":
        if len(args) < 2:
            print("Usage: remove <cert_id>"); return
        ok = db.remove_cert(args[1])
        print("✓ Certificate removed" if ok else "✗ Not found")

    elif cmd == "stats":
        s = db.stats()
        print("Certificate Statistics:")
        print(f"  Total:        {s['total']}")
        print(f"  Valid:        {s['valid']}")
        print(f"  Expiring:     {s['expiring_soon']}")
        print(f"  Expired:      {s['expired']}")
        if s['expiring_domains']:
            print(f"  Expiring:     {', '.join(s['expiring_domains'])}")
        if s['expired_domains']:
            print(f"  Expired:      {', '.join(s['expired_domains'])}")

    elif cmd == "demo":
        # Add some real public domains
        demo_domains = ["github.com", "google.com", "cloudflare.com"]
        added = 0
        for domain in demo_domains:
            try:
                cert = db.add_cert(domain)
                print(f"  ✓ {domain}: {cert.days_until_expiry}d remaining [{cert.status.value}]")
                added += 1
            except Exception as e:
                print(f"  ✗ {domain}: {e}")

        # Add a fake expired cert directly via internal method
        import datetime as dt
        fake = Certificate(
            id=str(uuid.uuid4()),
            domain="expired-example.internal",
            sans=["expired-example.internal"],
            issuer="CN=Internal CA",
            subject="CN=expired-example.internal",
            serial="DEADBEEF01",
            not_before=(dt.datetime.now(timezone.utc) - timedelta(days=730)).isoformat(),
            not_after=(dt.datetime.now(timezone.utc) - timedelta(days=10)).isoformat(),
            fingerprint="a" * 64,
            key_size=2048,
            algorithm="RSA",
            status=CertStatus.EXPIRED,
            port=443,
            last_checked=_now(),
            notes="Demo expired certificate",
        )
        with db._connect() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO certificates
                   (id, domain, sans, issuer, subject, serial, not_before, not_after,
                    fingerprint, key_size, algorithm, status, port, last_checked, notes)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (fake.id, fake.domain, json.dumps(fake.sans), fake.issuer, fake.subject,
                 fake.serial, fake.not_before, fake.not_after, fake.fingerprint,
                 fake.key_size, fake.algorithm, fake.status.value, fake.port,
                 fake.last_checked, fake.notes),
            )
        print(f"  ✓ demo expired cert added")
        print(f"\n✓ Demo complete: added {added} live + 1 demo cert")
        s = db.stats()
        print(f"  Total: {s['total']}  Valid: {s['valid']}  Expired: {s['expired']}")
    else:
        print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()
