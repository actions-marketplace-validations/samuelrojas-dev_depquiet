# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/samuelrojas-dev/depquiet/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/samuelrojas-dev/depquiet/releases/tag/v0.1.0
