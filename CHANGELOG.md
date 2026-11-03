# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.14.0] - 2026-11-03

### Added

- **Configurable CI gate (`--fail-on`)** — exit 1 only when ACTION items at or above a severity threshold exist. Options: `critical`, `high`, `moderate`, `low`, `none`
- `fail-on` input for the GitHub Action — overrides the boolean `fail-on-action` with severity-based control
- 15 tests for the fail-on module covering threshold logic, mixed severities, edge cases, and CLI integration

## [0.13.0] - 2026-11-03

### Added

- **GitHub Actions Job Summary** — rich Markdown report rendered directly in PR checks via `$GITHUB_STEP_SUMMARY`. Shows action items table with severity badges, EPSS scores, and fix versions; review items (auto-collapsed when >5); and filtered breakdown by reason
- `--summary` CLI flag to write GitHub-flavored Markdown summary to any file
- `ignore` input for the GitHub Action — pass a custom `.depquiet-ignore` path
- `license` input for the GitHub Action — run license compliance in CI
- `review` output from the GitHub Action — number of review-level items
- 18 tests for the summary module covering all verdict combinations, table rendering, severity badges, collapsing, and file output

## [0.12.0] - 2026-11-03

### Added

- **Suppression file (`.depquiet-ignore`)** — per-CVE and per-package suppressions with required reason, optional expiry dates, and author tracking for audit trails
- Match priority: CVE+package > CVE-only > package-only
- Expired entries print warnings instead of silently suppressing
- `--ignore` CLI flag for custom ignore file path
- Auto-detection of `.depquiet-ignore`, `.depquiet-ignore.yaml`, `.depquiet-ignore.yml` in the project root
- New `FilterReason.IGNORED` for suppressed items
- 45 tests for the ignore module covering parsing, matching, expiry, apply_ignores, and edge cases

## [0.11.0] - 2026-11-03

### Added

- **License compliance analysis (`--license`)** — scan all dependencies for license risk. Classifies ~60 SPDX license IDs into LOW / MEDIUM / HIGH / CRITICAL / UNKNOWN risk levels.
- Copyleft detection: flags GPL, AGPL, SSPL, BUSL and other restrictive licenses that may contaminate proprietary code
- SPDX expression support: `OR` picks the most permissive option, `AND` picks the most restrictive
- Common alias normalization: `"Apache License 2.0"` → `Apache-2.0`, `"GPLv3"` → `GPL-3.0`, etc.
- npm scanner: reads `license` / `licenses` fields from every `node_modules/*/package.json` (including scoped packages)
- pip scanner: uses `pip list` + `importlib.metadata` classifiers to resolve license IDs
- `--license --json` for machine-readable license output
- 33 tests for the license module covering classification, npm/pip scanning, report output, and edge cases

## [0.10.0] - 2026-11-03

### Added

- **Auto-remediation (`--fix`)** — automatically upgrade vulnerable packages with known fix versions. Runs `npm install pkg@ver` or `pip install pkg==ver` for ACTION items that have a `fix_version`.
- `--dry-run` flag — preview what `--fix` would do without changing `node_modules` or `site-packages`
- `FixResult` and `FixReport` dataclasses for programmatic fix tracking
- 17 tests for the fix module covering dry-run, success, failure, timeout, and edge cases

## [0.9.0] - 2026-11-03

### Added

- **Policy engine** — commit security policies alongside code (`.depquiet-policy.yaml`). Rules match on severity, EPSS, package, dev status, CVE IDs; first matching rule wins.
- `--policy` CLI flag and `policy` input for the GitHub Action
- Action aliases: `block` → ACTION, `dismiss`/`ignore`/`filtered` → FILTERED
- Custom lightweight YAML parser — no PyYAML dependency required

## [0.8.0] - 2026-11-03

### Added

- **CycloneDX 1.5 SBOM generation** — JSON and XML output formats compliant with OWASP CycloneDX 1.5 (EO 14028 ready)
- `--sbom` and `--sbom-format` CLI flags; format auto-detected from file extension
- `sbom`, `sbom-format` inputs for the GitHub Action; SBOM auto-uploaded as build artifact
- Package URL (purl) generation for 9 ecosystems: npm, PyPI, Go, crates.io, Maven, NuGet, Packagist, RubyGems, Pub

## [0.7.0] - 2026-11-03

### Added

- **SARIF v2.1.0 input parser** — pipe SARIF output from any scanner into depquiet via `--stdin`
- **Standalone lockfile scanning** via the OSV.dev API — no external scanner required; auto-detects lockfiles when no native scanner is found

## [0.6.0] - 2026-11-02

### Added

- **Reachability analysis for 10 languages**: Python (AST), JavaScript/TypeScript (AST), Go, Rust, Java/Kotlin, C#, PHP, Ruby, Swift, Dart/Flutter
- Each analyzer detects ecosystem-specific import patterns and build directory exclusions

## [0.5.0] - 2026-11-02

### Added

- **JavaScript/TypeScript AST-based reachability** — detects `require()`, `import` statements, and dynamic imports using `acorn`-style parsing
- **Go reachability analysis** — scans `.go` files for `import` blocks

## [0.4.0] - 2026-11-01

### Added

- **Snyk parser**: triage Snyk CLI output via `snyk test --json | depquiet --stdin` — auto-detects `vulnerabilities` array + `packageManager` key, extracts CVEs from `identifiers`, maps dependency chain depth from `from[]`, deduplicates CVE+package
- **AST-based Python reachability** (v2): upgraded from regex to `ast.parse()` — immune to false positives from comments, docstrings, strings, and variable names that tripped up the old regex. Falls back to regex for unparseable files (Python 2, encoding issues)
- **12 new community templates** (21 total): minimist prototype pollution, nth-check ReDoS, postcss ReDoS, glob-parent ReDoS, node-forge timing attack, shell-quote injection, qs prototype pollution, semver ReDoS, word-wrap ReDoS, tough-cookie prototype pollution, js-yaml code execution, certifi root CA removal

### Changed

- Test suite expanded from 234 to 292 tests
- Coverage maintained at **100%** across all 20 source files (948/948 statements)
- 6 parsers now supported: npm, pip, trivy, dependabot, grype, snyk

## [0.3.0] - 2026-11-01

### Added

- **Grype parser**: triage Anchore Grype output via `grype dir:. -o json | depquiet --stdin` — auto-detects `matches` array, deduplicates CVE+package, maps artifact types to depquiet ecosystems, handles both modern and legacy fix formats
- **Dependabot parser**: triage GitHub Dependabot alerts via `gh api /repos/OWNER/REPO/dependabot/alerts --paginate | depquiet --stdin` — auto-detects JSON arrays, processes only open alerts, deduplicates CVE+package, handles GHSA-only advisories
- **Dependabot example** in `examples/dependabot-alerts/` with sample alerts and expected verdicts
- **Benchmark suite**: reproducible filter-rate measurement across 4 scenarios — **89% noise reduction** proven across npm, pip, trivy, and grype

### Changed

- **Python reachability analysis**: upgraded from bare string matching to proper `import X` / `from X import Y` / `__import__('X')` detection — prevents false positives from package names appearing in comments or prose
- **Mixed-project reachability**: `check()` now searches both JS and Python files instead of picking one ecosystem, so mixed-language projects triage correctly
- trivy.py test coverage raised from 84% to 100%
- Test suite expanded from 156 to 234 tests
- Coverage maintained at **100%** across all 19 source files (869/869 statements)

## [0.2.0] - 2026-11-01

### Added

- **Trivy parser**: auto-detects `trivy fs --format json` output via `--stdin`, processes `lang-pkgs` results (skips OS packages)
- **`.depquiet.yaml` config file**: commit triage preferences alongside code — `epss_threshold`, `template_dirs`, `always_flag`, `offline`
- **`--config` CLI flag**: specify a custom config file path instead of the default `.depquiet.yaml` in the project root
- **`always_flag`**: packages that must never be filtered — forced to ACTION verdict regardless of filters
- **7 new community templates**: express open redirect, axios SSRF, webpack-dev-middleware, json5 prototype pollution, ip SSRF, requests proxy-auth leak, cryptography null dereference (9 total)
- **Trivy container example** in `examples/trivy-container/`
- **Node.js API example** with `.depquiet.yaml` config in `examples/node-api/`
- **Python web app example** in `examples/python-web/`
- PEP 561 `py.typed` marker for typed package compliance

### Changed

- Full `mypy --strict` compliance across all source files
- All bare `dict` annotations replaced with `dict[str, Any]`
- Parser list uses `Protocol` for structural typing
- Test suite expanded from 29 to 156 tests
- Coverage raised from 84% to 99%

### Fixed

- SARIF output bug: `_build_locations` crashed on missing imports field
- `_parse_yaml_simple` return type narrowed from `dict` to `dict[str, object]` for mypy strict

## [0.1.0] - 2026-10-31

### Added

- Core triage engine with four filters: devDependency, reachability, EPSS, and community templates
- npm audit JSON parser with full advisory support
- pip-audit JSON parser (stub, expandable)
- EPSS score integration via FIRST.org API (`--offline` to skip)
- Import reachability analysis for JavaScript/TypeScript projects
- Community template system with YAML-based dismiss rules
- Bundled templates: lodash prototype pollution, semver ReDoS
- SARIF v2.1.0 output for GitHub Code Scanning integration
- JSON output mode for programmatic consumption
- Colored terminal output with before/after noise reduction display
- CLI with `--sarif`, `--json`, `--offline`, `--stdin`, `--epss-threshold`, `--templates`
- CI exit code: 1 if ACTION items found, 0 otherwise
- Full test suite with 29 tests
- CI workflow with lint, typecheck, test matrix (3.11/3.12/3.13), and build
- Automated release workflow with trusted PyPI publishing

[Unreleased]: https://github.com/samuelrojas-dev/depquiet/compare/v0.14.0...HEAD
[0.14.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/samuelrojas-dev/depquiet/releases/tag/v0.1.0
