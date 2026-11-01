# Example: Trivy Container Scan

Demonstrates depquiet triaging Trivy's `--format json` output from a container image scan.

## Run the example

```bash
# From this directory:
depquiet --stdin < trivy-output.json --offline
```

## What happens

Trivy reports 4 vulnerabilities: 3 in npm packages and 1 OS-level (Alpine `libssl3`).

| CVE | Package | Source | depquiet verdict | Why |
|---|---|---|---|---|
| CVE-2020-8203 | lodash | npm | **FILTERED** | Template match — merge/defaultsDeep not imported |
| CVE-2024-29041 | express | npm | **REVIEW** | Template match — only affects unvalidated redirects |
| CVE-2022-46175 | json5 | npm | **FILTERED** | Template match — parse() with reviver not used |
| CVE-2024-5535 | libssl3 | alpine | *(skipped)* | OS packages are outside depquiet's scope |

depquiet processes only `lang-pkgs` results from Trivy — OS-level packages (`os-pkgs`)
are skipped because they belong to a different triage workflow (distro patch management).

Without depquiet: 4 alerts, mixed sources, unclear priority.
With depquiet: 1 to review, 2 filtered, 1 skipped. Time saved: ~5 minutes.
