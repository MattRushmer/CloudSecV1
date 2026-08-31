# CloudSec

Ideas:

1. Cloud Access Security Brokers (CASBs)
   Function: Enforce security policies and monitor cloud usage.
   Purpose: Provide visibility and control over cloud applications.

2. Cloud Security Posture Management (CSPM)
   Function: Continuously evaluate cloud resource configurations.
   Purpose: Ensure compliance with security benchmarks and standards.

3. Cloud Workload Protection Platforms (CWPP)
   Function: Protect workloads across various cloud environments.
   Purpose: Detect vulnerabilities and secure applications in real-time.

4. Identity and Access Management (IAM)
   Function: Manage user identities and access permissions.
   Purpose: Ensure that only authorized users can access sensitive data.

5. Cloud Detection and Response (CDR)
   Function: Monitor for security incidents and respond to threats.
   Purpose: Provide real-time threat detection and mitigation.

6. Data Security Posture Management (DSPM)
   Function: Identify and protect sensitive data across cloud services.
   Purpose: Manage data access controls and compliance.

7. Cloud Infrastructure Entitlement Management (CIEM)
   Function: Manage permissions and entitlements for cloud resources.
   Purpose: Reduce the risk of excessive permissions and misconfigurations.

8. Kubernetes Security Posture Management (KSPM)
   Function: Secure Kubernetes environments.
   Purpose: Enforce security best practices for container orchestration.

9. Runtime Application Self-Protection (RASP)
   Function: Protect applications during runtime.
   Purpose: Detect and block attacks in real-time.

10. Security Information and Event Management (SIEM)
    Function: Aggregate and analyze security data from various sources.
    Purpose: Provide insights into security incidents and compliance.

## Current build: Azure CSPM scanner

A minimal Cloud Security Posture Management tool (idea #2) targeting Azure.
It authenticates against a subscription, runs a set of configuration checks,
and prints a pass/fail report.

### Checks implemented

- `STORAGE-001` — storage accounts require HTTPS-only traffic
- `STORAGE-002` — storage accounts don't allow public blob access
- `NETWORK-001` — NSGs don't expose SSH/RDP (22/3389) to the internet
- `KEYVAULT-001` — Key Vaults have soft delete enabled
- `SQL-001` — SQL server firewalls don't allow all IP addresses

### Setup

```bash
python -m venv .venv
.venv\Scripts\activate      # or `source .venv/bin/activate` on macOS/Linux
pip install -r requirements.txt        # runtime only
pip install -r requirements-dev.txt    # runtime + pytest, for running tests
```

Authenticate to Azure — either run `az login`, or copy `env.example` to
`.env` and fill in a service principal's credentials
(`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`). Either way,
set `AZURE_SUBSCRIPTION_ID` in `.env` (or pass `--subscription-id`).

### Run

```bash
python -m cspm
python -m cspm --json-out findings.json
python -m cspm --fail-on-finding   # exit 1 if any check fails, useful in CI
```

### Tests

```bash
pytest
```

### Adding a new check

1. Create a class in `cspm/checks/` implementing `Check` (see `cspm/checks/base.py`).
2. Yield a `Finding` per resource evaluated.
3. Register an instance of it in `ALL_CHECKS` in `cspm/checks/__init__.py`.
