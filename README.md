# depquiet

[![CI](https://github.com/samuelrojas-dev/depquiet/actions/workflows/ci.yml/badge.svg)](https://github.com/samuelrojas-dev/depquiet/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/depquiet)](https://pypi.org/project/depquiet/)
[![Python versions](https://img.shields.io/pypi/pyversions/depquiet)](https://pypi.org/project/depquiet/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/samuelrojas-dev/depquiet/blob/main/LICENSE)
[![codecov](https://codecov.io/gh/samuelrojas-dev/depquiet/graph/badge.svg)](https://codecov.io/gh/samuelrojas-dev/depquiet)

**Cut through vulnerability alert noise. Surface the signal.**

`depquiet` triages your `npm audit` / `pip-audit` / `trivy` / `grype` / Dependabot / Snyk alerts and tells you which CVEs actually matter — in seconds, not hours. It can also **scan lockfiles directly** using the [OSV.dev](https://osv.dev) API — no external scanner required.

![depquiet on a real Express app: npm audit, then depquiet, then depquiet explain](https://raw.githubusercontent.com/samuelrojas-dev/depquiet/main/docs/demo/demo.gif)

Every line in the recording is real command output ([how it's made](https://github.com/samuelrojas-dev/depquiet/blob/main/docs/demo/make_demo.py)).
The same run as text ([reproduce it](https://github.com/samuelrojas-dev/depquiet/blob/main/benchmarks/RESULTS.md#real-npm-express)):

```
$ npm audit --json | depquiet --stdin

depquiet scan — npm (14 packages)

✅ FILTERED: 13 alerts (45%)
   ├─ 13 unreachable — not imported, directly or via a parent
   └─ 8 devDependency only — never reaches production
   (an alert can match more than one reason)

⚠️  REVIEW: 3 alerts
   GHSA-pxg6-pf52-xh8x  cookie                    low        no EPSS
   ...

🔴 ACTION REQUIRED: 13 alerts
   • GHSA-9wv6-86v2-598j  path-to-regexp  FIX: update express to 4.22.3
     via express
     → app.js
     path-to-regexp outputs backtracking regular expressions
   ...

Total: 29 alerts — 13 actionable | 3 review | 13 filtered
```

`path-to-regexp` is never imported by the app, but Express calls it on every request, so
depquiet keeps it. The 13 filtered alerts are in packages that only build tools pull in
(eslint, nodemon, webpack-dev-middleware) or that the app declares but never imports.

## Quick start

```bash
pip install depquiet pip-audit             # pip-audit is optional; without it Python
                                           # projects are scanned through OSV.dev
cd your-project
depquiet                                   # runs npm audit / pip-audit, or scans lockfiles via OSV.dev
npm audit --json | depquiet --stdin        # or triage any scanner's output
depquiet explain GHSA-9wv6-86v2-598j       # why did this alert get its verdict?
```

Works on npm, yarn, Python (uv, Poetry, pip-tools, Pipfile), Rust, Ruby, PHP, .NET, Dart, Go
and Maven projects. In CI, use the [GitHub Action](#github-actions-marketplace).

## The problem

Dependency scanners report every advisory that matches a version range, whether or not
your application can reach the vulnerable code:

- **npm audit is "broken by design"** ([Dan Abramov](https://overreacted.io/npm-audit-broken-by-design/))
- **Dependabot is a "noise machine"**: Filippo Valsorda recommends [turning it off](https://words.filippo.io/dependabot) in favor of reachability-aware tools like `govulncheck`

The result is alert fatigue: teams either spend hours triaging noise or start ignoring
alerts, real ones included.

## How it works

depquiet applies four deterministic filters to separate signal from noise:

| Filter | Filters an alert when |
|---|---|
| **Reachability** | No source file imports the package, and (for a transitive package) no source file imports any direct dependency that pulls it in |
| **Dev dependencies** | Every known dependency path is for development, with no production parent |
| **EPSS scoring** | The CVE's probability of exploitation is below the threshold (default 10%) |
| **Community templates** | A matching template's dismissal conditions can be verified against the project |

See [benchmarks](#benchmarks) for measured results on a real project.

### Conservative by design

depquiet would rather let a false positive through than dismiss a real vulnerability:

- **Transitive dependencies are judged by their parents.** Your code never imports
  `path-to-regexp`; Express does. depquiet reads your manifests and lockfiles to find the
  direct dependencies that pull a package in, and keeps the alert if your code imports any
  of them. See [Direct vs. transitive](#direct-vs-transitive-dependencies).
- **Unknown means not filtered.** If no manifest or lockfile says whether a package is direct
  or transitive, or a file fails to parse, the alert is not filtered on reachability.
- **Production paths override development labels.** A package listed in `devDependencies`
  is still kept when a production dependency also pulls it in. A transitive package
  imported by the application is kept even when its declared parent is unused.
- **Import-level, not call-graph.** Reachability means "the package enters your app", not
  "the vulnerable function is called". It removes packages your app never loads; it does not
  prove an imported package's vulnerable function is unused. For Go, `govulncheck` does
  symbol-level analysis and is the better tool.

### Supported inputs

depquiet accepts output from any vulnerability scanner — natively or via SARIF:

| Scanner | Format | Input method |
|---|---|---|
| **None (standalone)** | **Lockfiles** | **`depquiet` (auto-detects lockfiles, queries OSV.dev)** |
| npm audit | JSON | `npm audit --json \| depquiet --stdin` |
| pip-audit | JSON | `pip-audit --format json \| depquiet --stdin` |
| Trivy | JSON or SARIF | `trivy fs --format json . \| depquiet --stdin` |
| Grype | JSON | `grype dir:. -o json \| depquiet --stdin` |
| Snyk | JSON | `snyk test --json \| depquiet --stdin` |
| Dependabot | API JSON | `gh api /repos/O/R/dependabot/alerts \| depquiet --stdin` |
| **Any SARIF scanner** | **SARIF v2.1.0** | `<scanner> --sarif \| depquiet --stdin` |
| **CycloneDX SBOM** | **JSON** | `depquiet --from-sbom vendor.cdx.json` |
| **SPDX SBOM** | **JSON** | `depquiet --from-sbom vendor.spdx.json` |

The SARIF parser handles output from CodeQL, Semgrep, Trivy SARIF, Grype SARIF, Snyk SARIF, Checkmarx, Fortify, and any other tool that emits SARIF v2.1.0. CVE, package name, severity (CVSS or level-based), and fix version are extracted automatically from the standard SARIF fields and common scanner-specific properties.

### Standalone scanning with OSV.dev

When no scanner output is piped in and no native package manager is detected, depquiet falls back to **lockfile scanning via [OSV.dev](https://osv.dev)** — Google's open, free vulnerability database. Just run `depquiet` in any project with a lockfile:

| Lockfile | Ecosystem |
|---|---|
| `package-lock.json` / `yarn.lock` | npm |
| `requirements.txt` / `Pipfile.lock` | PyPI |
| `go.sum` | Go |
| `Cargo.lock` | crates.io |
| `pubspec.lock` | Pub (Dart/Flutter) |
| `Gemfile.lock` | RubyGems |
| `composer.lock` | Packagist (PHP) |
| `packages.lock.json` | NuGet (C#) |

Multiple lockfiles in the same project are merged and deduplicated. OSV.dev queries
are batched in groups of up to 1000 packages, then each distinct advisory is fetched
for its severity, CVE aliases and fixed versions. All pages and advisory lookups must
succeed before the scan is considered complete. Use `--offline` to skip OSV.dev queries.

### SBOM generation (CycloneDX + SPDX)

depquiet generates both major SBOM standards required by US Executive Order 14028:

```bash
# CycloneDX 1.5 (OWASP standard)
depquiet --sbom sbom.json              # CycloneDX JSON
depquiet --sbom sbom.xml               # CycloneDX XML (auto-detected)
depquiet --sbom out.cdx --sbom-format xml

# SPDX 2.3 (ISO/IEC 5962:2021)
depquiet --sbom sbom.spdx.json         # SPDX JSON (auto-detected)
depquiet --sbom out.spdx --sbom-format spdx
```

Both formats include full component inventory with Package URLs (purl), vulnerability references for known CVEs, depquiet triage verdicts, and tool creator metadata. CycloneDX additionally maps verdicts to analysis states; SPDX uses SECURITY external references with NVD links.

SBOM output works alongside all other flags — combine `--sbom` with `--sarif` to generate both in one pass.

### SBOM import — triage from third-party SBOMs

depquiet can consume CycloneDX and SPDX SBOMs as input, enabling triage on third-party SBOMs from vendors, container registries, or build systems — without needing the original lockfile:

```bash
# Explicit file input
depquiet --from-sbom vendor-sbom.cdx.json    # CycloneDX 1.4/1.5 JSON
depquiet --from-sbom vendor-sbom.spdx.json   # SPDX 2.3 JSON

# Piped via stdin (auto-detected)
cat container-sbom.json | depquiet --stdin
```

Two-mode operation:
- **Vulnerability mode** — if the SBOM contains vulnerability data (CycloneDX `vulnerabilities` array or SPDX SECURITY external refs), those are extracted and triaged directly
- **Package mode** — if no vulnerability data is present, the package inventory is extracted and queried against OSV.dev for known advisories

An inventory-only SBOM cannot be scanned with `--offline`. Missing packages or a failed
OSV.dev lookup produce "nothing scanned" and exit code `2`, rather than a clean report.

All standard depquiet flags work with SBOM input: `--epss-threshold`, `--kev`, `--sbom` (re-export), `--sarif`, `--html`, etc.

### Reachability analysis in depth

Import detection works differently for each language:

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

**PHP** — Use statement parsing with comment stripping. Handles:
- Standard use: `use Monolog\Logger;`
- Function use: `use function GuzzleHttp\Promise\all;`
- Const use: `use const GuzzleHttp\Promise\FULFILLED;`
- Composer vendor/package convention: first two namespace segments lowercased and joined with `/`
- Case-insensitive matching (PHP namespaces are case-insensitive)
- Strips `//`, `#`, and `/* */` comments
- Skips `vendor/` directory

**Ruby** — Require statement parsing with comment stripping. Handles:
- `require 'gem_name'` (single and double quotes)
- `require 'gem_name/sub'` → extracts top-level `gem_name`
- `require_relative` skipped (project-internal files)
- Hyphenated gem convention: `aws-sdk-s3` matches both `require 'aws-sdk-s3'` and `require 'aws/sdk/s3'`
- Strips `#` and `=begin`/`=end` comments
- Skips `vendor/` directory

**Swift** — Import statement parsing with comment stripping. Handles:
- Standard imports: `import ModuleName`
- Kind imports: `import struct Module.Type`, `import class Module.Class`, `import func Module.func`
- Testable imports: `@testable import ModuleName`
- SwiftPM package-to-module mapping: hyphens become underscores (`swift-argument-parser` → `swift_argument_parser`)
- Top-level module name extraction from dotted imports
- Skips `.build/` directory

**Dart / Flutter** — Import statement parsing with comment stripping. Handles:
- Package imports: `import 'package:name/file.dart';`
- Subpath imports: `import 'package:name/src/sub.dart';` → extracts `name`
- `dart:` SDK imports skipped (SDK-internal)
- Relative imports skipped (project-internal)
- Hyphen-to-underscore normalization for scanners that report with hyphens
- Skips `.dart_tool/` directory

All ten analyzers map aliased package names (e.g., `my-package` → `my_package` for Python, `@scope/name/sub` → `@scope/name` for JS, `github.com/user/repo/sub` → `github.com/user/repo` for Go, `my-crate` → `my_crate` for Rust, `com.fasterxml.jackson.core:jackson-databind` → `com.fasterxml.jackson.core` for Java, `Newtonsoft.Json.Linq` → `Newtonsoft.Json` for C#, `Monolog\Logger\Handler` → `monolog/logger` for PHP, `aws-sdk-s3` → matches `require 'aws/sdk/s3'` for Ruby, `swift-argument-parser` → `swift_argument_parser` for Swift, `flutter-bloc` → `flutter_bloc` for Dart) and check all source files in the project, skipping `node_modules`, `.git`, `__pycache__`, `dist`, `build`, `.build`, `.dart_tool`, `vendor`, `target`, and other vendored directories.

### Direct vs. transitive dependencies

The import check only answers "does my code import this package?", which is the right
question for direct dependencies and the wrong one for transitive ones. Since v0.28.0
depquiet builds a dependency graph from the project before filtering:

| Ecosystem | Direct dependencies from | Dependency paths from |
|---|---|---|
| npm | `package.json`, `package-lock.json` | `package-lock.json` (v1-v3), `yarn.lock` (v1, berry) |
| Python | `uv.lock`, `pyproject.toml` (PEP 621, PEP 735, Poetry), `Pipfile`, `requirements.in`, hand-written `requirements.txt` | `uv.lock`, `poetry.lock`, pip-compile `# via` comments |
| Rust | `Cargo.lock` workspace crates | `Cargo.lock` |
| Ruby | `Gemfile.lock` | `Gemfile.lock` |
| PHP | `composer.json` | `composer.lock` |
| .NET | `packages.lock.json` | `packages.lock.json` |
| Dart | `pubspec.lock` | — |
| Go | `go.mod` (`// indirect`) | — |
| Java (Maven) | `pom.xml` | — |

Rules, in order:

1. **Direct** dependency: filtered when nothing imports it, the project never runs it as a
   command, *and* no used direct dependency also pulls it in.
2. **Transitive** dependency: filtered only when none of the direct dependencies that pull it
   in are used. With no known path (Go, Dart, Maven), it is never filtered.

A direct dependency is **used** when any of these holds:

- a source file imports it. Python distribution names are mapped to module names
  (`PyYAML` → `yaml`, `llama-index-core` → `llama_index`) from installed metadata in the
  project's virtualenv, a table of known mismatches, and naming rules;
- the project runs one of its executables: `pm2 start` in a `package.json` script, a
  `Procfile` entry, or a Dockerfile command;
- it is named in the project's code, scripts or config (`INSTALLED_APPS = ["allauth"]`,
  `postgresql+psycopg2://`, `celery flower` in a service script). Docs, manifests and
  lockfiles don't count;
- a used dependency loads it itself (FastAPI loads `python-multipart`, SQLAlchemy loads
  database drivers).

Every rule only ever keeps alerts: a wrong match makes depquiet filter less, never more.
3. **Unknown**: never filtered. This includes a `requirements.txt` where every line is pinned
   with `==` and there are no `# via` comments, since that is indistinguishable from
   `pip freeze` output.

`depquiet explain <CVE>` shows the dependency type and the packages that pull it in, and
`--json` output includes `dependency_type` and `introduced_by` for every alert.

## Install

```bash
pip install depquiet
```

## Usage

```bash
# Auto-detect lockfiles and scan (no scanner needed — uses OSV.dev)
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

# SARIF input — any scanner that emits SARIF works
semgrep --sarif . | depquiet --stdin
codeql database analyze db --format=sarif-latest | depquiet --stdin
trivy fs --format sarif . | depquiet --stdin
checkmarx-cli scan --output-format sarif | depquiet --stdin

# Fully offline (skip EPSS API)
depquiet --offline

# SARIF output for GitHub Code Scanning
depquiet --sarif results.sarif

# SBOM (EO 14028 compliance)
depquiet --sbom sbom.json                     # CycloneDX 1.5 JSON
depquiet --sbom sbom.xml --sbom-format xml    # CycloneDX 1.5 XML
depquiet --sbom sbom.spdx.json               # SPDX 2.3 JSON

# JSON output for scripting
depquiet --json

# Custom EPSS threshold
depquiet --epss-threshold 0.05

# Use a custom config file
depquiet --config ./ci-config.yaml

# Auto-fix ACTION items that have a known fix version
depquiet --fix

# See what --fix would do without changing anything
depquiet --fix --dry-run

# License compliance scan
depquiet --license

# Use a suppression file (auto-detected from project root)
depquiet   # reads .depquiet-ignore if present

# Explicit ignore file
depquiet --ignore ./custom-ignore.yaml

# Write GitHub-flavored Markdown summary (for CI)
depquiet --summary report.md

# Self-contained HTML report (share via email/Slack/artifact)
depquiet --html report.html

# Configurable CI gate — fail only on critical findings
depquiet --fail-on critical

# Fail on high and above (skip moderate/low)
depquiet --fail-on high

# Never fail on findings (informational mode)
depquiet --fail-on none
```

### Auto-remediation (`--fix`)

`depquiet --fix` upgrades packages that have ACTION verdicts **and** a known fix version.
It runs `npm install <pkg>@<ver>` or `pip install <pkg>==<ver>` under the hood.

```
$ depquiet --fix

depquiet scan — npm (847 packages)
...

✅ Fixed 2 vulnerabilities:
   CVE-2024-4068  braces 3.0.2 → 3.0.3
   CVE-2024-33883  ejs 3.1.9 → 3.1.10

⚠️  1 ACTION items have no fix available:
   CVE-2024-21538  semver 7.5.4
```

Use `--dry-run` to preview changes without touching `node_modules` or `site-packages`:

```
$ depquiet --fix --dry-run

[dry-run] ✅ Fixed 2 vulnerabilities:
   CVE-2024-4068  braces 3.0.2 → 3.0.3   Would run: npm install braces@3.0.3
   CVE-2024-33883  ejs 3.1.9 → 3.1.10    Would run: npm install ejs@3.1.10
```

**Exit codes with `--fix`:** returns `0` when every ACTION item is resolved; returns `1` when any remain unfixed (no fix version, or the upgrade command failed).

### License compliance (`--license`)

`depquiet --license` scans every installed dependency for license risk — copyleft contamination, unknown licenses, and restrictive terms that could block enterprise adoption or open-source distribution.

```
$ depquiet --license

depquiet license scan — npm (847 packages)

LOW (permissive):  812 packages
   MIT, Apache-2.0, BSD-2-Clause, ISC, ...

MEDIUM (weak copyleft):  4 packages
   LGPL-2.1   libfoo 3.2.1
   MPL-2.0    bar-utils 1.0.0
   ...

🔴 HIGH (copyleft):  2 packages
   GPL-3.0    gpl-thing 1.0.0
   GPL-2.0    another-gpl 2.1.0

🔴 CRITICAL (network copyleft / non-OSS):  1 package
   AGPL-3.0   agpl-server 0.5.0

⚠️  UNKNOWN:  1 package
   ???        mystery-pkg 1.2.3

License scan: FAIL — 4 packages need review
```

Risk levels:

| Level | Licenses | Meaning |
|-------|----------|---------|
| **LOW** | MIT, BSD, Apache-2.0, ISC, Unlicense, ... | Permissive — safe for any use |
| **MEDIUM** | LGPL-2.1, LGPL-3.0, MPL-2.0, EPL-2.0 | Weak copyleft — check linking requirements |
| **HIGH** | GPL-2.0, GPL-3.0 | Strong copyleft — derivative works must be GPL |
| **CRITICAL** | AGPL-3.0, SSPL-1.0, BUSL-1.1 | Network copyleft or non-OSS — high legal risk |
| **UNKNOWN** | Unrecognized or missing | Needs manual review |

SPDX expressions are handled automatically: `MIT OR GPL-3.0` picks the most permissive (MIT → LOW), `MIT AND GPL-3.0` picks the most restrictive (GPL-3.0 → HIGH). Common non-SPDX strings like `"Apache License 2.0"` and `"GPLv3"` are normalized to their SPDX IDs.

**Exit codes with `--license`:** returns `0` when all dependencies are LOW or MEDIUM; returns `1` when any HIGH, CRITICAL, or UNKNOWN licenses are found.

Combine with JSON output for CI integration:

```bash
depquiet --license --json
```

With `--json`, the command emits one scan document. License results are included in its
`license` field; the vulnerability `summary` and `results` fields keep their existing shape.

### Suppression file (`.depquiet-ignore`)

Teams need a way to acknowledge accepted risk without disabling the tool. The `.depquiet-ignore` file provides per-CVE and per-package suppressions with accountability:

```yaml
ignores:
  # Suppress a specific CVE (any package)
  - cve: CVE-2024-1234
    reason: "Mitigated by WAF rule WR-123"
    expires: 2025-06-01
    author: alice

  # Suppress a CVE only for a specific package
  - cve: CVE-2024-5678
    package: lodash
    reason: "Only used in tests, no production exposure"

  # Suppress all CVEs for a package (migration planned)
  - package: deprecated-pkg
    reason: "Migration to replacement-pkg planned for Q2"
    expires: 2025-07-01
```

Place `.depquiet-ignore` in the project root (auto-detected) or pass `--ignore path/to/file.yaml`.

**Match priority:** CVE+package > CVE-only > package-only. Only ACTION and REVIEW items are suppressed — already-filtered items are left as-is.

**Expiry dates:** When an entry's `expires` date passes, it stops suppressing and depquiet prints a warning. This prevents suppressions from rotting forever — teams must re-evaluate periodically.

**Audit trail:** The `reason` field (recommended) explains why the risk was accepted. The `author` field records who made the decision.

### Scan comparison (`depquiet diff`)

Compare two depquiet scans to see exactly what changed — new vulnerabilities introduced, old ones fixed, and verdicts that shifted. This is the core of the CI review workflow: "was this PR safe to merge?"

```bash
# Compare a base branch scan against a PR branch scan
depquiet diff base-scan.json pr-scan.json

# Machine-readable output
depquiet diff base-scan.json pr-scan.json --json

# Fail CI only when new ACTION items appear
depquiet diff base-scan.json pr-scan.json --fail-on-new
```

Typical CI workflow:

```yaml
- name: Scan base
  run: git stash && depquiet --json > /tmp/base.json && git stash pop

- name: Scan head
  run: depquiet --json > /tmp/head.json

- name: Diff
  run: depquiet diff /tmp/base.json /tmp/head.json --fail-on-new
```

Output shows new, fixed, and changed findings with severity, EPSS scores, and verdict transitions:

```
🆕 2 new | ✅ 1 fixed | 🔄 1 changed | — 12 unchanged

── New findings ──────────────────────────────────────
  [HIGH] CVE-2024-0001 in lodash@4.17.20 — Prototype Pollution → ACTION (EPSS: 42.0%)
```

### GitHub PR comments

Post scan diff results directly on pull requests as rich Markdown comments — severity badges, EPSS scores, fix versions, and verdict changes at a glance.

```bash
# Markdown output for piping to gh pr comment
depquiet diff base.json head.json --markdown

# Write markdown to a file (e.g. for $GITHUB_STEP_SUMMARY)
depquiet diff base.json head.json --summary diff-report.md
```

**GitHub Action** — automatic PR comments with the `diff-base` and `pr-comment` inputs:

```yaml
- uses: samuelrojas-dev/depquiet@v0
  with:
    diff-base: base-scan.json    # path to a base branch scan
    pr-comment: true             # post/update a PR comment with the diff
```

The action auto-updates the comment on re-runs (deletes previous depquiet comments first), writes a diff summary to `$GITHUB_STEP_SUMMARY`, and exposes `diff-new` / `diff-fixed` outputs for downstream steps.

### Config scaffolder (`depquiet init`)

Bootstrap a `.depquiet.yaml` for your project in seconds. `init` auto-detects the package manager, CI provider, and existing scanners, then generates a config with sensible defaults.

```bash
# Interactive — shows detection results, asks before writing
depquiet init

# Non-interactive — accept all defaults (great for scripts)
depquiet init --yes

# Overwrite an existing config
depquiet init --yes --force

# Write to a custom path
depquiet init -o configs/depquiet.yaml
```

Detection covers 11 package managers (npm, pip, Go, Cargo, Maven, Gradle, Gem, Composer, Pub, NuGet), 6 CI providers (GitHub Actions, GitLab CI, Jenkins, CircleCI, Bitbucket, Azure DevOps), and 6 scanner tools (Snyk, Trivy, Grype, OSV-Scanner, Dependabot, Renovate). GitHub Actions projects automatically get SARIF and summary outputs enabled.

### Verdict explainer (`depquiet explain`)

Understand exactly why a CVE received its verdict. Every contributing signal — EPSS score, reachability, dependency type, community template, KEV status, ignore rules — is laid out step-by-step so developers and security teams can audit triage decisions.

```bash
# Explain a CVE from a previous scan (saved with --json)
depquiet explain GHSA-9wv6-86v2-598j --from-json scan.json

# Machine-readable output
depquiet explain GHSA-9wv6-86v2-598j --from-json scan.json --json

# Live scan and explain
depquiet explain GHSA-9wv6-86v2-598j --path ./my-project
```

Each signal shows its effect on the final verdict:

```
🔴 GHSA-9wv6-86v2-598j — path-to-regexp outputs backtracking regular expressions
   Package: path-to-regexp@<0.1.10
   Severity: HIGH
   Verdict: ACTION (no automatic filter matched; product impact unverified)
   Fix: upgrade to express@4.22.3

   Signals:
  - EPSS score: unavailable — EPSS lookup was skipped or failed
  ↑ Reachability: reachable — Transitive, pulled in by express. Entry points: app.js
  · Dependency type: production — Included in production builds
  · CISA KEV: not listed
```

(The [real Express benchmark](https://github.com/samuelrojas-dev/depquiet/blob/main/benchmarks/RESULTS.md), scanned with `--offline`, so no EPSS.)

### Scan statistics (`depquiet stats`)

Get aggregate metrics for security dashboards and management reports. Works from `--json` output or a live scan.

```bash
# Stats from a saved scan
depquiet stats --from-json scan.json

# Machine-readable JSON
depquiet stats --from-json scan.json --json

# Top 5 affected packages
depquiet stats --from-json scan.json --top 5
```

Output includes verdict breakdown, severity distribution, filter reason analysis, top affected packages, EPSS distribution, and fix availability:

```
depquiet scan statistics
========================================

Total vulnerabilities: 29
Total dependencies:   14
Filter rate:          44.8%

Verdicts:
  🔴 ACTION       13 ( 44.8%) █████████░░░░░░░░░░░
  🟡 REVIEW        3 ( 10.3%) ██░░░░░░░░░░░░░░░░░░
  🟢 FILTERED     13 ( 44.8%) █████████░░░░░░░░░░░

Filter reasons:
  unreachable                 13 ( 61.9%)
  dev dependency               8 ( 38.1%)
...
```

### CISA KEV integration (`--kev`)

The [CISA Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog lists CVEs with confirmed active exploitation. Under [BOD 22-01](https://www.cisa.gov/binding-operational-directive-22-01), federal agencies must remediate KEV-listed CVEs within strict deadlines — and any organization should treat them as top priority.

```bash
# Check scan results against the KEV catalog
depquiet --kev

# Air-gapped environments: use a local copy of the catalog
depquiet --kev-file /path/to/known_exploited_vulnerabilities.json
```

How it works: KEV-listed CVEs are **auto-escalated to ACTION** regardless of other filters. A low-EPSS, devDependency, or unreachable vulnerability that's on the KEV catalog gets promoted to ACTION because active exploitation trumps all other signals.

The KEV feed is cached locally for 24 hours. On network failure, depquiet falls back to the expired cache. In `--offline` mode, only the cache is used.

JSON output includes KEV enrichment:

```json
{
  "cve": "CVE-2021-44228",
  "verdict": "action",
  "kev": {
    "date_added": "2021-12-10",
    "due_date": "2021-12-24",
    "required_action": "Apply updates per vendor instructions.",
    "ransomware_use": true
  }
}
```

Combine with baseline and fail-on for maximum control:

```bash
# Accept known debt, but always flag KEV-listed CVEs
depquiet --baseline .depquiet-baseline.json --kev --fail-on high
```

### HTML report (`--html`)

Generate a self-contained interactive HTML report — zero external dependencies, all CSS and JS inline, ready to share via email, Slack, or upload as a CI artifact.

```bash
depquiet --html report.html
```

The report includes a severity donut chart, collapsible sections (review auto-collapses when >5 findings, filtered always starts collapsed), dark mode support, and client-side text search. All data is embedded as JSON for future extensibility. XSS-safe: user-controlled values are escaped in both HTML and embedded JSON contexts.

### PR annotations (`--annotations`)

Post vulnerability findings as inline annotations on PR diffs — like CodeQL or ESLint. Each ACTION or REVIEW finding becomes a GitHub Check Run annotation pointing at the package manifest or the file that imports the vulnerable package.

```bash
# Generate annotations JSON
depquiet --annotations annotations.json
```

In the GitHub Action, just add `annotations: true`:

```yaml
- uses: samuelrojas-dev/depquiet@v1
  with:
    annotations: true
```

Annotations are automatically posted via the Check Runs API. Critical/high findings appear as errors, moderate as warnings, and low/info as notices. Each annotation includes the CVE, severity, EPSS score, fix version, and a link to the NVD advisory.

### OpenVEX documents (`--vex`)

Generate [OpenVEX](https://openvex.dev) documents that communicate the exploitability status of every vulnerability in your project. VEX (Vulnerability Exploitability eXchange) is the CISA-recommended format for telling downstream consumers which CVEs actually affect your software — and which don't.

```bash
# Generate an OpenVEX document
depquiet --vex vex.json
```

Priority and product impact are separate. The current engine observes dependency
relationships and imports; it does not prove vulnerable-function execution or
product-specific mitigations. Automatic exports preserve this uncertainty:

| Output | Automatic impact state | Priority and context |
|---|---|---|
| OpenVEX | `under_investigation` | `status_notes` contains priority, observations and limits |
| CycloneDX JSON/XML | `in_triage` | `analysis.detail` and per-component `depquiet:triage` properties |
| Scan JSON | `assessment.status: under_investigation` | Existing `verdict`, plus `evidence` and `decision_trace` |

A low EPSS, dev-only metadata, baseline, ignore or policy match never becomes an
automatic `not_affected` claim. The existing remediation priorities and exit-code
policy remain available. See the [assessment contract](docs/assessment-contract.md).

The output is consumable by policy engines like Sigstore's policy-controller and OPA/Gatekeeper to gate container deployments.

```yaml
# In the GitHub Action
- uses: samuelrojas-dev/depquiet@v1
  with:
    vex: depquiet-vex.json
```

### Baseline diffing (`--baseline`)

Adopting depquiet on an existing codebase? The `--baseline` flag lets you accept the current state and only fail on **new** vulnerabilities — just like Snyk's `--new-only` or Trivy's `--ignore-unfixed`.

```bash
# Step 1: Save current state as baseline
depquiet --json > .depquiet-baseline.json

# Step 2: In CI, only fail on NEW findings
depquiet --baseline .depquiet-baseline.json
```

How it works: each finding is identified by its `CVE:package` key. Findings that exist in the baseline are demoted from ACTION/REVIEW to FILTERED. Only genuinely new vulnerabilities trigger failure.

Combine with `--fail-on` for layered control:

```bash
# Accept known debt, fail only on new critical/high findings
depquiet --baseline .depquiet-baseline.json --fail-on high
```

**Updating the baseline:** periodically regenerate it as the team fixes existing debt:

```bash
# After fixing some findings, update the baseline
depquiet --json > .depquiet-baseline.json
git add .depquiet-baseline.json
git commit -m "chore: update depquiet baseline"
```

### Configurable CI gate (`--fail-on`)

By default, depquiet exits `1` whenever any ACTION item exists — just like Snyk's `--severity-threshold`. The `--fail-on` flag lets you control the minimum severity that fails the build:

| `--fail-on` value | Fails on |
|---|---|
| (default) | Any ACTION item, regardless of severity |
| `critical` | Critical only |
| `high` | High + Critical |
| `moderate` | Moderate + High + Critical |
| `low` | Low + Moderate + High + Critical |
| `none` | Never fails on findings (informational mode) |

This is useful for gradual adoption: start with `--fail-on critical` to block only the most dangerous vulnerabilities, then tighten the threshold as the team addresses lower-severity items.

```bash
# Block only critical and high vulnerabilities in CI
depquiet --fail-on high

# Informational mode — report everything, block nothing
depquiet --fail-on none --summary $GITHUB_STEP_SUMMARY
```

## CI Integration

### Exit codes

- `0` — No ACTION items at or above the `--fail-on` threshold (safe to pass)
- `1` — ACTION items found at or above the threshold (fail the build)
- `2` — Nothing was scanned: no supported manifest or lockfile, or a lockfile that needs
  OSV.dev while `--offline` is set. depquiet never reports an unscanned project as clean.

### GitHub Actions (Marketplace)

```yaml
- name: Triage vulnerabilities
  uses: samuelrojas-dev/depquiet@v0
  with:
    sarif: results.sarif
    epss-threshold: "0.1"
    policy: .depquiet-policy.yaml
    sbom: sbom.cdx.json
```

The action installs depquiet, runs it, uploads SARIF to GitHub Code Scanning, uploads the SBOM as a build artifact, and fails the build if ACTION items are found.

The action automatically writes a **Job Summary** to the PR checks page with severity badges, EPSS scores, fix versions, and a filtered breakdown.

**Action inputs:** `path`, `epss-threshold`, `offline`, `sarif`, `templates`, `policy`, `sbom`, `sbom-format`, `ignore`, `license`, `baseline`, `kev`, `kev-file`, `html`, `annotations`, `vex`, `fail-on-action`, `fail-on`, `python-version`.

> **Note:** `fail-on` (severity-based) supersedes `fail-on-action` (boolean). When `fail-on` is set, `fail-on-action` is ignored.

`fail-on-action: false` only permits vulnerability findings. Scanner failures still fail
the step. Diff summaries and PR comments use the saved scan, including when findings
cause the scanning step to fail; they do not run another scan.

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

Built-in templates require readable project source and evidence that the package and
its dependency ancestors are unused. Absence of a vulnerable function name in application
code does not prove that an imported library never calls it. Unverifiable conditions
keep the alert. Custom templates without conditions are explicit unconditional dismissal
rules, so add `not-imported` conditions when that is not your intention.

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

Create `.depquiet.yaml` in your project root (or pass `--config path/to/config.yaml`).
Every key is optional — add only what you need:

```yaml
# Triage tuning
epss_threshold: 0.05          # EPSS score cutoff (default: 0.1)
offline: false                # skip EPSS API (default: false)
always_flag:                  # packages that must never be filtered
  - lodash
  - express
template_dirs:                # extra template directories
  - ./my-templates

# CI gate
fail_on: high                 # severity threshold: critical | high | moderate | low | none

# Integrations
kev: true                     # check CISA KEV catalog
kev_file: data/kev.json       # local KEV catalog (air-gapped)
license: true                 # run license compliance analysis

# Input paths (relative to project root)
policy: .depquiet-policy.yaml
ignore: .depquiet-ignore
baseline: reports/baseline.json

# Output files (relative to project root)
sarif: reports/depquiet.sarif
html: reports/depquiet.html
summary: reports/summary.md
sbom: reports/sbom.cdx.json
sbom_format: json             # json | xml | spdx
vex: reports/vex.json
annotations: reports/annotations.json
```

CLI flags always override config values when explicitly passed. `template_dirs` from both sources are merged. This enables zero-flag CI — just run `depquiet` and the config drives everything.

## Policy engine

Commit security policies alongside your code. Rules match on vulnerability attributes and override
the default triage verdict — first matching rule wins.

Create `.depquiet-policy.yaml` in your project root (or pass `--policy path/to/policy.yaml`):

```yaml
rules:
  # Always block critical CVEs, even if filters would dismiss them
  - id: block-critical
    action: action
    severity: critical

  # Dismiss low-EPSS noise in dev dependencies
  - id: dismiss-low-epss-dev
    action: filter
    is_dev: true
    epss_below: 0.01

  # Always flag these core packages
  - id: block-core-packages
    action: action
    packages: [express, lodash]

  # Specific CVE override
  - id: accept-cve-1234
    action: filter
    cves: [CVE-2024-1234]
```

### Match conditions

All conditions on a rule must match (AND logic):

| Condition | Type | Description |
|-----------|------|-------------|
| `severity` | string or list | `critical`, `high`, `medium`, `low`, `info` |
| `packages` | string or list | Package names to match |
| `epss_below` | float | EPSS score below this threshold |
| `epss_above` | float | EPSS score above this threshold |
| `is_dev` | bool | Match dev dependencies only |
| `has_fix` | bool | Match vulnerabilities with a known fix |
| `cves` | string or list | Specific CVE IDs |

### Actions

| Action | Aliases | Effect |
|--------|---------|--------|
| `action` | `block` | Escalate to ACTION REQUIRED |
| `review` | | Mark for review |
| `filter` | `filtered`, `dismiss`, `ignore` | Filter out |

## Benchmarks

Six real projects: five popular open-source apps pinned to a commit, plus a small Express
app pinned to 2022 versions. npm projects are audited with `npm audit`, Python projects with
`pip-audit` on every version in their `uv.lock` / `poetry.lock`. Every verdict is listed in
[benchmarks/RESULTS.md](https://github.com/samuelrojas-dev/depquiet/blob/main/benchmarks/RESULTS.md).

| Project | Scanner | Alerts | Filtered by 0.27 | Filtered now | Filtered by 0.27, kept now |
|---|---|---:|---:|---:|---:|
| [mealie-recipes/mealie](https://github.com/mealie-recipes/mealie) | pip-audit | 229 | 200 | 28 | 172 |
| [hagopj13/node-express-boilerplate](https://github.com/hagopj13/node-express-boilerplate) | npm audit | 163 | 115 | 18 | 97 |
| [gothinkster/node-express-realworld-example-app](https://github.com/gothinkster/node-express-realworld-example-app) | npm audit | 95 | 59 | 41 | 18 |
| Express app, 2022 versions | npm audit | 29 | 26 | 13 | 13 |
| [paperless-ngx/paperless-ngx](https://github.com/paperless-ngx/paperless-ngx) | pip-audit | 17 | 17 | 0 | 17 |
| [sahat/hackathon-starter](https://github.com/sahat/hackathon-starter) | npm audit | 2 | 2 | 2 | 0 |
| **Total** | | **535** | **419 (78%)** | **102 (19%)** | **317** |

0.27 dismissed 317 alerts without evidence. It counted any package the app didn't import
itself as unreachable, which is true of nearly every transitive package, and it compared
Python distribution names literally, so `Django`, `PyYAML` or `llama-index-core` never matched
`import django`, `import yaml` or `import llama_index`.

What depquiet filters now is almost entirely packages that only development tooling pulls in
(jest, eslint, nx, nodemon, pre-commit, mkdocs). On these projects nearly every production
dependency is in use, so the useful output is less the filtering than the trace: each kept
alert names the direct dependency it comes through and where the app uses it.

Run them yourself: `python -I benchmarks/run_benchmark.py`. The first run clones the pinned
commits into `benchmarks/.cache/`; `benchmarks/capture_real.py` re-captures the audits. The
synthetic fixtures in the same report are parser regression tests, not evidence.

## Compared to

depquiet ingests reports from npm audit, pip-audit, Trivy, Grype, Dependabot,
Snyk and SARIF-producing tools. It adds dependency/import context, configurable
priorities and decision history, and can query OSV directly from lockfiles.

The alert-reduction figures above describe captured scans; they do not establish
false-positive rates or superiority over another scanner. The new
[reference evaluator](benchmarks/reference/README.md) checks labelled cases,
including missing findings and unsafe dismissals. Two explicitly synthetic
contract examples exercise its mechanics:

```bash
python benchmarks/reference/run.py --output synthetic-scan.json
python benchmarks/evaluate.py --labels benchmarks/reference/synthetic.labels.json --scan synthetic-scan.json --snapshot benchmarks/reference/synthetic.snapshot.json --json
```

The separate [upstream reference set](benchmarks/reference/real/README.md) contains
10 selected advisory contexts from four pinned npm/Python projects, with frozen
audits, source hashes and review evidence. CI checks that five `retain` and five
`unknown` cases remain visible. Labels are agent-reviewed; human review is pending.
There are no real `filter` labels, so this set does not measure safe dismissal,
full-project coverage or real-world accuracy. Replay requires no upstream code
execution or package installation.

## License

MIT

## Contributing

depquiet is designed to grow through community templates. Every template you contribute helps thousands of developers skip a false positive.

See [CONTRIBUTING.md](https://github.com/samuelrojas-dev/depquiet/blob/main/CONTRIBUTING.md) for guidelines.
