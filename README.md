# blackroad-cert-manager

> TLS certificate lifecycle management — BlackRoad Security

[![CI](https://github.com/BlackRoad-Security/blackroad-cert-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/BlackRoad-Security/blackroad-cert-manager/actions/workflows/ci.yml)

Monitor, track, and manage TLS certificates at scale. Detect expiring or expired certs, verify certificate chains, and export inventory reports. **stdlib only** — uses Python's built-in `ssl` and `socket` modules.

## Features

- 🔒 **Live Scanning**: Fetch cert info from any TLS-enabled host
- ⏰ **Expiry Tracking**: Days-to-expiry with configurable warning thresholds
- 🔗 **Chain Verification**: Verify full certificate chain using stdlib `ssl`
- 🚨 **Alerting**: Auto-generate alerts for expiring/expired certs
- 📊 **Inventory Export**: JSON and CSV inventory reports
- 🔄 **Bulk Refresh**: Refresh all stored certs from live hosts
- 💾 **SQLite**: Self-contained, zero-config backend
- 📦 **Zero dependencies**: Only Python stdlib

## Quick Start

```bash
# Add real certificates by scanning live hosts
python cert_manager.py add github.com
python cert_manager.py add cloudflare.com

# Check expiry for a domain
python cert_manager.py check github.com 30

# List all certificates
python cert_manager.py list

# Get expiring certs (within 30 days)
python cert_manager.py expiring 30

# Get expired certs
python cert_manager.py expired

# Verify certificate chain
python cert_manager.py verify github.com

# Generate alerts for expiring/expired certs
python cert_manager.py alerts 30 7

# Refresh all certs from live hosts
python cert_manager.py refresh

# Export inventory
python cert_manager.py export json
python cert_manager.py export csv

# Stats
python cert_manager.py stats

# Demo (scans github.com, google.com, cloudflare.com)
python cert_manager.py demo
```

## Certificate Lifecycle

```
[Add/Scan] → [valid] → ... → [expiring] → [expired] → [remove]
                                  ↑
                           Alert at 30d, critical at 7d
```

## API

```python
from cert_manager import CertManager

db = CertManager("certs.db")

# Scan and add certificate
cert = db.add_cert("github.com")
print(f"{cert.domain}: {cert.days_until_expiry} days remaining")

# Check expiry
result = db.check_expiry("github.com", days_warning=30)

# Get expiring certs
expiring = db.get_expiring(days=30)

# Verify chain
result = db.verify_chain(cert.id)

# Export inventory
json_inventory = db.export_inventory("json")
csv_inventory = db.export_inventory("csv")

# Check and generate alerts
alerts = db.check_and_alert(days_warning=30, days_critical=7)
```

## Certificate Status

| Status | Meaning |
|--------|---------|
| `valid` | Certificate is valid (> 30 days remaining) |
| `expiring` | Certificate expires within warning threshold |
| `expired` | Certificate has expired |
| `revoked` | Certificate has been revoked |

## Running Tests

```bash
pip install pytest
pytest test_cert_manager.py -v
```

> Note: Integration tests (`test_add_cert_fetch_live`, `test_verify_chain_live`) require network access. They are automatically skipped if no network is available.
