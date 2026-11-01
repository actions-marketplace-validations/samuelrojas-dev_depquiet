# Example: Python Web App

Demonstrates depquiet triaging a Python Flask app with 3 vulnerabilities across 2 packages.

## Run the example

```bash
# From this directory:
depquiet --stdin < audit-output.json --offline
```

## What happens

| CVE | Package | depquiet verdict | Why |
|---|---|---|---|
| CVE-2023-32681 | requests | **REVIEW** | Template match — only affects proxy auth + redirect |
| CVE-2024-0727 | cryptography | **REVIEW** | Template match — only affects PKCS12 loading |
| CVE-2023-49083 | cryptography | **ACTION** | No template, moderate severity |

Without depquiet: 3 alerts, unclear priority.
With depquiet: 1 actionable, 2 to review. Time saved: ~4 minutes.
