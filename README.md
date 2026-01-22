# CloudSentry

**OCI Security Posture Monitor** - A Cloud Security Posture Management (CSPM) tool for Oracle Cloud Infrastructure.

CloudSentry scans your OCI tenancy for security misconfigurations, stores findings in PostgreSQL, visualizes security posture in Grafana, and sends real-time alerts via Slack.

## Features

- **21 Security Checks** across 5 categories:
  - Storage (5 checks): Public buckets, versioning, lifecycle, encryption, PAR permissions
  - Network (5 checks): Permissive security lists/NSGs, unused rules, WAF, flow logs
  - Compute (4 checks): Public IPs, boot volume encryption, monitoring, legacy shapes
  - IAM (4 checks): MFA, API key rotation, permissive policies, inactive users
  - Database (3 checks): Private endpoints, public access, encrypted connections

- **CIS Benchmark Mapping** - Checks mapped to CIS OCI Benchmark controls
- **PostgreSQL Persistence** - Track finding history, resolution, and trends
- **Grafana Dashboard** - Pre-built security posture visualization
- **Slack Alerts** - Real-time notifications for critical/high findings
- **Compliance Scoring** - Track CIS compliance percentage over time

## Quick Start

### Prerequisites

- Python 3.9+
- Docker & Docker Compose (for PostgreSQL + Grafana)
- OCI CLI configured (`~/.oci/config`)

### Installation

```bash
# Clone the repository
git clone https://github.com/sinCodes11/cloudsentry.git
cd cloudsentry

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install dependencies
pip install -r requirements.txt

# Copy and configure
cp config.example.yaml config.yaml
cp .env.example .env
# Edit config.yaml and .env with your settings
```

### Start Infrastructure

```bash
# Start PostgreSQL and Grafana
docker-compose up -d

# Initialize database
python main.py init-db
```

### Run a Scan

```bash
# Dry run (no database, no alerts)
python main.py scan --dry-run

# Full scan
python main.py scan

# Scan specific compartment
python main.py scan -C ocid1.compartment.oc1..xxx

# Export findings to JSON
python main.py scan -o findings.json
```

## CLI Commands

```bash
# List available checks
python main.py checks

# View open findings
python main.py findings
python main.py findings --severity CRITICAL
python main.py findings -f json

# View compliance score
python main.py compliance

# Suppress a finding
python main.py suppress STORAGE-001 bucket-name

# Test Slack integration
python main.py test-slack
```

## Configuration

### config.yaml

```yaml
oci:
  config_file: ~/.oci/config
  profile: DEFAULT
  compartments:
    - ALL  # Scan all compartments recursively

database:
  host: localhost
  port: 5432
  name: cloudsentry
  user: cloudsentry
  password: ${DB_PASSWORD}  # From environment

alerts:
  slack:
    enabled: true
    webhook_url: ${SLACK_WEBHOOK}
    min_severity: HIGH  # CRITICAL, HIGH, MEDIUM, LOW
```

### Environment Variables

```bash
DB_PASSWORD=your_database_password
SLACK_WEBHOOK=https://hooks.slack.com/services/xxx/xxx/xxx
GRAFANA_PASSWORD=admin
```

## Security Checks

| ID | Category | Severity | Title | CIS |
|----|----------|----------|-------|-----|
| STORAGE-001 | Storage | CRITICAL | Public Object Storage Bucket | 2.1.1 |
| STORAGE-002 | Storage | MEDIUM | Bucket Versioning Disabled | 2.1.2 |
| STORAGE-003 | Storage | LOW | Bucket Missing Lifecycle Policy | - |
| STORAGE-004 | Storage | MEDIUM | Bucket Using Default Encryption | 2.1.3 |
| STORAGE-005 | Storage | HIGH | Overly Permissive PAR | - |
| NETWORK-001 | Network | HIGH | Security List Allows 0.0.0.0/0 | 3.1.1 |
| NETWORK-002 | Network | HIGH | NSG Allows Unrestricted Access | 3.1.2 |
| NETWORK-003 | Network | LOW | Unused Security List | - |
| NETWORK-004 | Network | MEDIUM | Load Balancer Without WAF | - |
| NETWORK-005 | Network | MEDIUM | VCN Flow Logs Disabled | 3.2.1 |
| COMPUTE-001 | Compute | MEDIUM | Instance With Public IP | 4.1.1 |
| COMPUTE-002 | Compute | MEDIUM | Boot Volume Default Encryption | 4.2.1 |
| COMPUTE-003 | Compute | LOW | Instance Monitoring Disabled | - |
| COMPUTE-004 | Compute | LOW | Instance Using Legacy Shape | - |
| IAM-001 | IAM | HIGH | User Without MFA Enabled | 1.1.1 |
| IAM-002 | IAM | MEDIUM | API Key Older Than 90 Days | 1.2.1 |
| IAM-003 | IAM | HIGH | Overly Permissive IAM Policy | 1.3.1 |
| IAM-004 | IAM | MEDIUM | Inactive User Account | 1.1.2 |
| DATABASE-001 | Database | HIGH | Autonomous DB Without Private Endpoint | 5.1.1 |
| DATABASE-002 | Database | HIGH | DB System Publicly Accessible | 5.1.2 |
| DATABASE-003 | Database | MEDIUM | Database Allows Unencrypted Connections | - |

## Grafana Dashboard

Access Grafana at `http://localhost:3000` (default: admin/admin)

The pre-built dashboard includes:
- Total findings by severity
- CIS compliance score trend
- Findings by resource type
- Recent open findings table
- Top failing checks

## Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌─────────────┐
│   OCI Tenancy   │────▶│  CloudSentry │────▶│  PostgreSQL │
│  (SDK Scan)     │     │   Scanner    │     │  (Findings) │
└─────────────────┘     └──────┬───────┘     └──────┬──────┘
                               │                    │
                               ▼                    ▼
                        ┌──────────────┐     ┌─────────────┐
                        │    Slack     │     │   Grafana   │
                        │   Alerts     │     │  Dashboard  │
                        └──────────────┘     └─────────────┘
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black cloudsentry/

# Type checking
mypy cloudsentry/
```

## CI/CD Integration

Exit codes for CI pipelines:
- `0`: No critical or high findings
- `1`: High severity findings detected
- `2`: Critical severity findings detected

```bash
# Example GitHub Actions usage
python main.py scan --dry-run || exit $?
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

**Daniel Gregg Jr**
- GitHub: [@sinCodes11](https://github.com/sinCodes11)
- LinkedIn: [danielsin-1881ske89](https://linkedin.com/in/danielsin-1881ske89)
