"""Tests for BlackRoad Certificate Manager."""
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta
import json
from cert_manager import CertManager, Certificate, CertStatus, _parse_ssl_date, _estimate_key_size


@pytest.fixture
def db(tmp_path):
    return CertManager(db_path=str(tmp_path / "cert_test.db"))


def _make_fake_cert(domain: str, days_valid: int = 90) -> Certificate:
    now = datetime.now(timezone.utc)
    return Certificate(
        id=f"test-{domain}",
        domain=domain,
        sans=[domain, f"www.{domain}"],
        issuer="CN=Test CA, O=Test Org",
        subject=f"CN={domain}",
        serial="AABBCC001",
        not_before=(now - timedelta(days=30)).isoformat(),
        not_after=(now + timedelta(days=days_valid)).isoformat(),
        fingerprint="a" * 64,
        key_size=2048,
        algorithm="RSA",
        status=CertStatus.VALID,
        port=443,
        last_checked=now.isoformat(),
    )


def _insert_cert(db: CertManager, cert: Certificate):
    with db._connect() as conn:
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


def test_list_certs_empty(db):
    assert db.list_certs() == []


def test_list_certs(db):
    _insert_cert(db, _make_fake_cert("example.com"))
    _insert_cert(db, _make_fake_cert("test.com"))
    certs = db.list_certs()
    assert len(certs) == 2


def test_get_cert_by_domain(db):
    _insert_cert(db, _make_fake_cert("example.com"))
    cert = db.get_cert_by_domain("example.com")
    assert cert is not None
    assert cert.domain == "example.com"


def test_get_cert_by_domain_not_found(db):
    assert db.get_cert_by_domain("notexist.com") is None


def test_get_cert_by_id(db):
    c = _make_fake_cert("test.com")
    _insert_cert(db, c)
    found = db.get_cert(c.id)
    assert found is not None
    assert found.id == c.id


def test_remove_cert(db):
    c = _make_fake_cert("removeme.com")
    _insert_cert(db, c)
    ok = db.remove_cert(c.id)
    assert ok is True
    assert db.get_cert(c.id) is None


def test_remove_nonexistent(db):
    assert db.remove_cert("bad-id") is False


def test_update_notes(db):
    c = _make_fake_cert("notes-test.com")
    _insert_cert(db, c)
    updated = db.update_notes(c.id, "Renewed by infra team")
    assert updated.notes == "Renewed by infra team"


def test_get_expiring(db):
    valid_cert = _make_fake_cert("valid.com", days_valid=60)
    expiring_cert = _make_fake_cert("expiring.com", days_valid=15)
    _insert_cert(db, valid_cert)
    _insert_cert(db, expiring_cert)
    expiring = db.get_expiring(days=30)
    domains = [c.domain for c in expiring]
    assert "expiring.com" in domains
    assert "valid.com" not in domains


def test_get_expired(db):
    now = datetime.now(timezone.utc)
    expired_cert = _make_fake_cert("expired.com", days_valid=-10)
    expired_cert.not_after = (now - timedelta(days=10)).isoformat()
    expired_cert.status = CertStatus.EXPIRED
    _insert_cert(db, expired_cert)
    _insert_cert(db, _make_fake_cert("valid.com"))
    expired = db.get_expired()
    domains = [c.domain for c in expired]
    assert "expired.com" in domains
    assert "valid.com" not in domains


def test_days_until_expiry_future(db):
    c = _make_fake_cert("future.com", days_valid=45)
    _insert_cert(db, c)
    cert = db.get_cert_by_domain("future.com")
    assert cert.days_until_expiry > 0
    assert cert.days_until_expiry <= 46


def test_days_until_expiry_past(db):
    now = datetime.now(timezone.utc)
    c = _make_fake_cert("past.com", days_valid=-5)
    c.not_after = (now - timedelta(days=5)).isoformat()
    _insert_cert(db, c)
    cert = db.get_cert_by_domain("past.com")
    assert cert.days_until_expiry < 0


def test_check_and_alert_expired(db):
    now = datetime.now(timezone.utc)
    c = _make_fake_cert("alert-expired.com", days_valid=-5)
    c.not_after = (now - timedelta(days=5)).isoformat()
    c.status = CertStatus.EXPIRED
    _insert_cert(db, c)
    new_alerts = db.check_and_alert()
    domains = [a["domain"] for a in new_alerts]
    assert "alert-expired.com" in domains


def test_check_and_alert_expiring_critical(db):
    now = datetime.now(timezone.utc)
    c = _make_fake_cert("alert-critical.com", days_valid=5)
    c.not_after = (now + timedelta(days=5)).isoformat()
    _insert_cert(db, c)
    new_alerts = db.check_and_alert(days_warning=30, days_critical=7)
    domains = [a["domain"] for a in new_alerts]
    assert "alert-critical.com" in domains
    severities = {a["domain"]: a["severity"] for a in new_alerts}
    assert severities.get("alert-critical.com") == "critical"


def test_check_and_alert_valid_no_alert(db):
    _insert_cert(db, _make_fake_cert("healthy.com", days_valid=120))
    new_alerts = db.check_and_alert()
    domains = [a["domain"] for a in new_alerts]
    assert "healthy.com" not in domains


def test_get_alerts_empty(db):
    alerts = db.get_alerts()
    assert isinstance(alerts, list)


def test_get_alerts_after_check(db):
    now = datetime.now(timezone.utc)
    c = _make_fake_cert("needs-alert.com", days_valid=-1)
    c.not_after = (now - timedelta(days=1)).isoformat()
    c.status = CertStatus.EXPIRED
    _insert_cert(db, c)
    db.check_and_alert()
    alerts = db.get_alerts()
    assert len(alerts) >= 1


def test_export_inventory_json(db):
    _insert_cert(db, _make_fake_cert("export.com"))
    output = db.export_inventory("json")
    data = json.loads(output)
    assert "certificates" in data
    assert data["count"] >= 1
    assert data["certificates"][0]["domain"] == "export.com"


def test_export_inventory_csv(db):
    _insert_cert(db, _make_fake_cert("csv-test.com"))
    output = db.export_inventory("csv")
    assert "domain" in output.lower()
    assert "csv-test.com" in output


def test_export_inventory_invalid_format(db):
    with pytest.raises(ValueError):
        db.export_inventory("xml")


def test_stats_empty(db):
    s = db.stats()
    assert s["total"] == 0


def test_stats(db):
    _insert_cert(db, _make_fake_cert("valid1.com"))
    _insert_cert(db, _make_fake_cert("valid2.com"))
    now = datetime.now(timezone.utc)
    expired = _make_fake_cert("expired.com")
    expired.not_after = (now - timedelta(days=5)).isoformat()
    expired.status = CertStatus.EXPIRED
    _insert_cert(db, expired)
    s = db.stats()
    assert s["total"] == 3
    assert s["expired"] >= 1


def test_parse_ssl_date():
    date_str = "Jan  1 00:00:00 2025 GMT"
    parsed = _parse_ssl_date(date_str)
    assert "2025" in parsed


def test_estimate_key_size():
    # Small DER = small key
    small = bytes(300)
    large = bytes(1600)
    assert _estimate_key_size(small) <= 1024
    assert _estimate_key_size(large) >= 2048


def test_cert_is_expired():
    now = datetime.now(timezone.utc)
    c = _make_fake_cert("expired.com")
    c.not_after = (now - timedelta(days=5)).isoformat()
    assert c.is_expired is True


def test_cert_not_expired():
    c = _make_fake_cert("valid.com", days_valid=90)
    assert c.is_expired is False


def test_add_cert_fetch_live():
    """Integration test - requires network. Skip if no network."""
    import socket
    try:
        socket.create_connection(("github.com", 443), timeout=5).close()
    except Exception:
        pytest.skip("No network access")

    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".db") as f:
        db = CertManager(db_path=f.name)
        cert = db.add_cert("github.com")
        assert cert.domain == "github.com"
        assert cert.days_until_expiry > 0
        assert cert.fingerprint != ""


def test_verify_chain_live():
    """Integration test - requires network."""
    import socket
    try:
        socket.create_connection(("github.com", 443), timeout=5).close()
    except Exception:
        pytest.skip("No network access")

    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".db") as f:
        db = CertManager(db_path=f.name)
        cert = db.add_cert("github.com")
        result = db.verify_chain(cert.id)
        assert result["valid"] is True
