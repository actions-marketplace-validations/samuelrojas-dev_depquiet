# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/samuelrojas-dev/depquiet/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/samuelrojas-dev/depquiet/releases/tag/v0.1.0
