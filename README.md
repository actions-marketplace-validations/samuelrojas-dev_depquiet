# depquiet

[![CI](https://github.com/samuelrojas-dev/depquiet/actions/workflows/ci.yml/badge.svg)](https://github.com/samuelrojas-dev/depquiet/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/depquiet)](https://pypi.org/project/depquiet/)
[![Python versions](https://img.shields.io/pypi/pyversions/depquiet)](https://pypi.org/project/depquiet/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![codecov](https://codecov.io/gh/samuelrojas-dev/depquiet/graph/badge.svg)](https://codecov.io/gh/samuelrojas-dev/depquiet)

**Cut through vulnerability alert noise. Surface the signal.**

`depquiet` triages your `npm audit` / `pip-audit` / Dependabot alerts and tells you which CVEs actually matter — in seconds, not hours.

```
$ depquiet

depquiet scan — npm (847 packages)

✅ FILTERED: 89 alerts (92%)
   ├─ 34 unreachable — vulnerable function never imported
   ├─ 28 devDependency only — never reaches production
   ├─ 19 EPSS < 10% — no known exploits in the wild
   └─  8 community template — confirmed false positive

⚠️  REVIEW: 5 alerts
   CVE-2024-48930       lodash                    moderate   EPSS 3%
   CVE-2024-21538       semver                    moderate   EPSS 1%
   ...

🔴 ACTION REQUIRED: 3 alerts
   • CVE-2024-4068  braces  EPSS 67%  FIX: update to 3.0.3
     → src/config/parser.ts
     → src/utils/glob.ts
     Uncontrolled resource consumption in braces

Total: 97 alerts — 3 actionable | 5 review | 89 filtered
You just saved ~178 minutes of triage time.
```

## The problem

Developers spend **3.5 hours per week** triaging vulnerability alerts that are mostly noise:

- **60-80% of CVEs are unreachable** — the vulnerable function is never called
- **npm audit is "broken by design"** — 80% false positive rate ([Dan Abramov](https://overreacted.io/npm-audit-broken-by-design/))
- **Dependabot is a "noise machine"** — Filippo Valsorda recommends [disabling it entirely](https://words.filippo.io/dispatches/vulnerability-management/)

The result? **Alert fatigue.** Teams either waste hours triaging noise, or ignore alerts entirely and miss the real threats.

## How it works

depquiet applies four deterministic filters to separate signal from noise:

| Filter | What it catches | Impact |
|---|---|---|
| **Reachability** | Package/function never imported in your source code | 40-60% reduction |
| **Dev dependencies** | Vulnerabilities in devDependencies that never reach production | 10-20% reduction |
| **EPSS scoring** | CVEs with near-zero probability of real-world exploitation | 5-15% reduction |
| **Community templates** | Known false positives confirmed by the community (nuclei-style YAML) | Growing over time |

### Zero false negatives by design

depquiet is **conservative**: it would rather let a false positive through than dismiss a real vulnerability. Grep-based reachability misses dynamic imports, so it only filters when there are **zero references** to the package in your source code.

## Install

```bash
pip install depquiet
```

## Usage

```bash
# Auto-detect package manager and scan
depquiet

# Scan a specific directory
depquiet --path ./my-app

# Pipe in existing audit output
npm audit --json | depquiet --stdin
pip-audit --format json | depquiet --stdin

# Fully offline (skip EPSS API)
depquiet --offline

# SARIF output for GitHub Code Scanning
depquiet --sarif results.sarif

# JSON output for scripting
depquiet --json

# Custom EPSS threshold
depquiet --epss-threshold 0.05
```

## CI Integration

### Exit codes

- `0` — No ACTION items (safe to pass)
- `1` — ACTION items found (fail the build)

### GitHub Actions (Marketplace)

```yaml
- name: Triage vulnerabilities
  uses: samuelrojas-dev/depquiet@v0
  with:
    sarif: results.sarif
    epss-threshold: "0.1"
```

The action installs depquiet, runs it, uploads SARIF to GitHub Code Scanning, and fails the build if ACTION items are found.

### GitHub Actions (manual)

```yaml
- name: Triage vulnerabilities
  run: |
    pip install depquiet
    depquiet --sarif results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Community templates

depquiet uses [nuclei-style](https://github.com/projectdiscovery/nuclei-templates) YAML templates to encode community knowledge about known false positives:

```yaml
id: CVE-2024-48930-lodash-merge
reason: "Only defaultsDeep/merge are affected. Other lodash functions are safe."
author: "@contributor"
cves:
  - CVE-2024-48930
not-imported: ["lodash.defaultsDeep", "lodash.merge"]
```

### Contributing a template

1. Create a YAML file in `templates/dismiss/`
2. Add the CVE, affected package, and dismiss conditions
3. Open a PR — the community reviews and merges

Templates are the growth engine: each contribution helps every depquiet user.

## Configuration

Create `.depquiet.yaml` in your project root:

```yaml
# EPSS threshold (default: 0.1 = 10%)
epss_threshold: 0.05

# Extra template directories
template_dirs:
  - ./my-templates

# Packages to always flag (never filter)
always_flag:
  - lodash
  - express
```

## Compared to

| Tool | Approach | Limitation |
|---|---|---|
| `npm audit` | Flags everything | 80% false positives |
| Dependabot | GitHub-only, flags everything | No triage, overwhelming noise |
| GitHub Dependabot Reachability | AST analysis (Oct 2026) | JS/TS only, Enterprise Cloud only, preview |
| Snyk / Mend | SaaS, paid | $100K+/year for reachability |
| **depquiet** | Deterministic triage, community templates | Free, offline, works everywhere |

## License

MIT

## Contributing

depquiet is designed to reach 10,000 stars through community templates. Every template you contribute helps thousands of developers skip a false positive.

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
