# Example: Node.js API

Demonstrates depquiet triaging a Node.js API project with 3 vulnerabilities.

## Run the example

```bash
# From this directory:
depquiet --stdin < audit-output.json --offline

# Or with config file (uses .depquiet.yaml):
depquiet --stdin < audit-output.json --offline --path .
```

## What happens

| CVE | Package | Raw severity | depquiet verdict | Why |
|---|---|---|---|---|
| CVE-2020-8203 | lodash | high | **FILTERED** | `lodash.merge` not imported — template match |
| CVE-2024-29041 | express | moderate | **ACTION** | `always_flag` in `.depquiet.yaml` |
| CVE-2024-29180 | webpack-dev-middleware | high | **FILTERED** | devDependency only |

Without depquiet: 3 alerts, all look urgent.
With depquiet: 1 actionable alert. Time saved: ~6 minutes.
