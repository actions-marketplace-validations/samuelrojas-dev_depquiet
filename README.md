# depquiet

[![CI](https://github.com/samuelrojas-dev/depquiet/actions/workflows/ci.yml/badge.svg)](https://github.com/samuelrojas-dev/depquiet/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/depquiet)](https://pypi.org/project/depquiet/)
[![Python versions](https://img.shields.io/pypi/pyversions/depquiet)](https://pypi.org/project/depquiet/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![codecov](https://codecov.io/gh/samuelrojas-dev/depquiet/graph/badge.svg)](https://codecov.io/gh/samuelrojas-dev/depquiet)

**Cut through vulnerability alert noise. Surface the signal.**

`depquiet` triages your `npm audit` / `pip-audit` / `trivy` / `grype` / Dependabot / Snyk alerts and tells you which CVEs actually matter — in seconds, not hours.

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
- **Dependabot is a "noise machine"** — Filippo Valsorda recommends [disabling it entirely](https://words.filippo.io/dependabot)

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

depquiet is **conservative**: it would rather let a false positive through than dismiss a real vulnerability. Python, JS/TS, Go, Rust, Java/Kotlin, and C# reachability all use proper import analysis — no string matching, no regex against raw source. Only filter when there are **zero real references** to the package in your source code.

### Reachability analysis in depth

The reachability filter is where depquiet eliminates the most noise (40-60% of alerts). It works differently for each language:

**Python** — Full AST parsing via `ast.parse()`. Extracts `import`, `from … import`, and `__import__()` calls from the syntax tree. Immune to false positives from comments, docstrings, and string literals. Falls back to regex only for files that fail to parse (Python 2, encoding issues) — conservative: treats unparseable files as potentially importing the package.

**JavaScript / TypeScript** — Comment-stripping pipeline + pattern matching on actual import syntax. Handles all major import styles:
- ESM: `import X from 'pkg'`, `import {a, b} from 'pkg'`, `import 'pkg'` (side-effect)
- CommonJS: `require('pkg')`
- Dynamic: `import('pkg')`
- Re-exports: `export {a} from 'pkg'`, `export * from 'pkg'`
- Scoped packages: `@scope/name` resolved correctly
- Strips `//` and `/* */` comments so commented-out imports don't cause false positives
- Zero runtime dependencies — no external JS parser needed

**Go** — Import statement parsing with comment stripping. Handles:
- Single imports: `import "pkg"`
- Grouped imports: `import ( "pkg1" ; "pkg2" )`
- Aliased, dot, and blank imports: `import m "pkg"`, `import _ "pkg"`
- Module path resolution: `github.com/user/repo/sub` → `github.com/user/repo`
- `golang.org/x/*` packages resolved correctly
- Skips `vendor/` directory

**Rust** — Import statement parsing with comment stripping. Handles:
- `use crate_name::...` and `use crate_name;`
- `extern crate crate_name;` and `extern crate crate_name as alias;`
- Nested use: `use crate_name::{a, b};`
- Hyphen-to-underscore normalization: `my-crate` in Cargo.toml → `my_crate` in source
- Skips Rust-internal path roots: `self`, `super`, `crate`, `std`, `core`, `alloc`
- Skips `target/` directory

**Java / Kotlin** — Import statement parsing with comment stripping. Handles:
- Standard imports: `import com.example.Foo;`
- Static imports: `import static org.junit.Assert.assertEquals;`
- Wildcard imports: `import com.example.*;`
- Kotlin imports (no semicolons): `import com.example.Foo`
- Maven coordinate splitting: `groupId:artifactId` → matches against `groupId` prefix
- Package-path heuristic: walks dot-separated segments until an uppercase class name or `*`
- Skips `build/` directory

**C#** — Using directive parsing with comment stripping. Handles:
- Standard usings: `using Newtonsoft.Json;`
- Static usings: `using static System.Math;`
- Alias usings: `using Json = Newtonsoft.Json.JsonConvert;`
- Global usings: `global using System.Linq;`
- NuGet namespace matching: package name matches the root namespace prefix
- Skips `build/` directory

All six analyzers map aliased package names (e.g., `my-package` → `my_package` for Python, `@scope/name/sub` → `@scope/name` for JS, `github.com/user/repo/sub` → `github.com/user/repo` for Go, `my-crate` → `my_crate` for Rust, `com.fasterxml.jackson.core:jackson-databind` → `com.fasterxml.jackson.core` for Java, `Newtonsoft.Json.Linq` → `Newtonsoft.Json` for C#) and check all source files in the project, skipping `node_modules`, `.git`, `__pycache__`, `dist`, `build`, `vendor`, `target`, and other vendored directories.

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
trivy fs --format json . | depquiet --stdin
grype dir:. -o json | depquiet --stdin
snyk test --json | depquiet --stdin
gh api /repos/OWNER/REPO/dependabot/alerts --paginate | depquiet --stdin

# Fully offline (skip EPSS API)
depquiet --offline

# SARIF output for GitHub Code Scanning
depquiet --sarif results.sarif

# JSON output for scripting
depquiet --json

# Custom EPSS threshold
depquiet --epss-threshold 0.05

# Use a custom config file
depquiet --config ./ci-config.yaml
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

depquiet ships with **21 built-in templates** and uses [nuclei-style](https://github.com/projectdiscovery/nuclei-templates) YAML to encode community knowledge about known false positives:

| Template | CVE | What it catches |
|---|---|---|
| lodash prototype pollution | CVE-2020-8203, CVE-2019-10744 | Only merge/defaultsDeep affected |
| semver ReDoS | CVE-2022-25883 | Only untrusted input to `semver.clean()` |
| express open redirect | CVE-2024-29041 | Only unvalidated `res.redirect()` |
| axios SSRF | CVE-2023-45857 | Server-side only, cookies header |
| json5 prototype pollution | CVE-2022-46175 | Only `parse()` with `reviver` |
| webpack-dev-middleware | CVE-2024-29180 | devDependency only |
| ip SSRF | CVE-2023-42282 | `isPrivate()` bypass, private networks only |
| requests proxy-auth leak | CVE-2023-32681 | Only proxy + redirect |
| cryptography null dereference | CVE-2024-0727 | Only PKCS12 loading |
| minimist prototype pollution | CVE-2021-44906, CVE-2020-7598 | Only direct argv parsing |
| nth-check ReDoS | CVE-2021-3803 | Only attacker-controlled CSS selectors |
| postcss ReDoS | CVE-2023-44270 | Only attacker-controlled CSS input |
| glob-parent ReDoS | CVE-2020-28469 | Only attacker-controlled glob patterns |
| node-forge timing attack | CVE-2022-24771 | Network-level timing measurement needed |
| shell-quote injection | CVE-2021-42740 | Only untrusted input to shell-quote |
| qs prototype pollution | CVE-2022-24999 | Mitigated by Express 4.x defaults |
| word-wrap ReDoS | CVE-2023-26115 | Only very long strings without spaces |
| tough-cookie prototype pollution | CVE-2023-26136 | Only attacker-controlled cookie jar |
| js-yaml code execution | CVE-2013-4660 | Only `yaml.load()` with default schema |
| certifi root CA removal | CVE-2023-37920 | Only chains through distrusted CAs |

```yaml
id: prototype-pollution-lodash
reason: "Only defaultsDeep/merge are affected. Other lodash functions are safe."
cves:
  - CVE-2020-8203
  - CVE-2019-10744
not-imported: ["lodash.defaultsDeep", "lodash.merge"]
```

### Contributing a template

1. Create a YAML file in `templates/dismiss/`
2. Add the CVE, affected package, and dismiss conditions
3. Open a PR — the community reviews and merges

Templates are the growth engine: each contribution helps every depquiet user.

## Configuration

Create `.depquiet.yaml` in your project root (or pass `--config path/to/config.yaml`):

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

# Skip EPSS API (fully offline)
offline: false
```

CLI flags override config values. `template_dirs` from both sources are merged.

## Benchmarks

Tested against realistic audit output from popular project types (offline mode, all filters active):

| Scenario | Parser | Alerts | Filtered | Rate |
|----------|--------|-------:|---------:|-----:|
| Express web app | npm | 15 | 13 | **87%** |
| Django web app | pip | 9 | 8 | **89%** |
| Node.js container | trivy | 8 | 8 | **100%** |
| Python container | grype | 6 | 5 | **83%** |
| **Total** | | **38** | **34** | **89%** |

**89% noise reduction** — from 38 alerts down to 4 that actually matter. All scans complete in under 10ms.

Run the benchmarks yourself: `python -I benchmarks/run_benchmark.py`

## Compared to

| Tool | Approach | Limitation |
|---|---|---|
| `npm audit` | Flags everything | 80% false positives |
| `pip-audit` | Flags everything | No triage, no context |
| Trivy | Multi-scanner, flags everything | Great detection, no triage |
| Grype | Container scanner, flags everything | Great detection, no triage |
| Dependabot | GitHub-only, flags everything | No triage, overwhelming noise |
| Snyk | SaaS, paid | $100K+/year for reachability |
| GitHub Dependabot Reachability | AST analysis (Oct 2026) | JS/TS only, Enterprise Cloud ($21/user/mo), preview |
| Mend / Black Duck | SaaS, paid | Enterprise pricing, vendor lock-in |
| **depquiet** | AST reachability (Python, JS/TS, Go, Rust, Java/Kotlin, C#), deterministic triage, community templates | Free, offline, works everywhere |

## License

MIT

## Contributing

depquiet is designed to grow through community templates. Every template you contribute helps thousands of developers skip a false positive.

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
