"""Tests for the Trivy JSON parser and its integration with the engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from depquiet.models import Severity, Verdict
from depquiet.parsers.trivy import TrivyParser

# ── Fixtures ──────────────────────────────────────────────────────────

TRIVY_BASIC: dict = {
    "Results": [
        {
            "Target": "package-lock.json",
            "Class": "lang-pkgs",
            "Type": "npm",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2020-8203",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.15",
                    "FixedVersion": "4.17.19",
                    "Severity": "HIGH",
                    "Title": "Prototype Pollution in lodash",
                    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-8203",
                },
                {
                    "VulnerabilityID": "CVE-2024-29041",
                    "PkgName": "express",
                    "InstalledVersion": "4.18.2",
                    "FixedVersion": "4.19.2",
                    "Severity": "MODERATE",
                    "Title": "Open redirect in express",
                    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-29041",
                },
            ],
        }
    ]
}

TRIVY_MULTI_TARGET: dict = {
    "Results": [
        {
            "Target": "package-lock.json",
            "Class": "lang-pkgs",
            "Type": "npm",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2020-8203",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.15",
                    "FixedVersion": "4.17.19",
                    "Severity": "HIGH",
                    "Title": "Prototype Pollution",
                },
            ],
        },
        {
            "Target": "requirements.txt",
            "Class": "lang-pkgs",
            "Type": "pip",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-32681",
                    "PkgName": "requests",
                    "InstalledVersion": "2.28.0",
                    "FixedVersion": "2.31.0",
                    "Severity": "MODERATE",
                    "Title": "Proxy-Auth header leak on redirect",
                },
            ],
        },
    ]
}

TRIVY_WITH_OS_PKGS: dict = {
    "Results": [
        {
            "Target": "alpine:3.18",
            "Class": "os-pkgs",
            "Type": "alpine",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-99999",
                    "PkgName": "openssl",
                    "InstalledVersion": "3.0.0",
                    "Severity": "CRITICAL",
                    "Title": "Should be skipped",
                },
            ],
        },
        {
            "Target": "app/package-lock.json",
            "Class": "lang-pkgs",
            "Type": "npm",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2020-8203",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.15",
                    "FixedVersion": "4.17.19",
                    "Severity": "HIGH",
                    "Title": "Prototype Pollution",
                },
            ],
        },
    ]
}


# ── Parser unit tests ─────────────────────────────────────────────────


class TestTrivyParser:
    """Basic parsing of Trivy JSON."""

    def test_parse_basic(self, tmp_path: Path) -> None:
        vulns = TrivyParser.parse(TRIVY_BASIC, tmp_path)
        assert len(vulns) == 2
        assert vulns[0].cve == "CVE-2020-8203"
        assert vulns[0].package == "lodash"
        assert vulns[0].severity == Severity.HIGH
        assert vulns[0].version == "4.17.15"
        assert vulns[0].fix_version == "4.17.19"
        assert vulns[0].url == "https://avd.aquasec.com/nvd/cve-2020-8203"

    def test_parse_multi_target(self, tmp_path: Path) -> None:
        vulns = TrivyParser.parse(TRIVY_MULTI_TARGET, tmp_path)
        assert len(vulns) == 2
        packages = {v.package for v in vulns}
        assert packages == {"lodash", "requests"}

    def test_skips_os_pkgs(self, tmp_path: Path) -> None:
        vulns = TrivyParser.parse(TRIVY_WITH_OS_PKGS, tmp_path)
        assert len(vulns) == 1
        assert vulns[0].package == "lodash"

    def test_deduplicates(self, tmp_path: Path) -> None:
        """Same CVE+package across targets is counted once."""
        duped = {
            "Results": [
                {
                    "Target": "a/package-lock.json",
                    "Class": "lang-pkgs",
                    "Type": "npm",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2020-8203",
                            "PkgName": "lodash",
                            "InstalledVersion": "4.17.15",
                            "Severity": "HIGH",
                            "Title": "Prototype Pollution",
                        },
                    ],
                },
                {
                    "Target": "b/package-lock.json",
                    "Class": "lang-pkgs",
                    "Type": "npm",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2020-8203",
                            "PkgName": "lodash",
                            "InstalledVersion": "4.17.15",
                            "Severity": "HIGH",
                            "Title": "Prototype Pollution",
                        },
                    ],
                },
            ]
        }
        vulns = TrivyParser.parse(duped, tmp_path)
        assert len(vulns) == 1

    def test_empty_results(self, tmp_path: Path) -> None:
        vulns = TrivyParser.parse({}, tmp_path)
        assert vulns == []

    def test_null_vulnerabilities(self, tmp_path: Path) -> None:
        """Trivy returns null for Vulnerabilities when a target is clean."""
        clean = {
            "Results": [
                {
                    "Target": "package-lock.json",
                    "Class": "lang-pkgs",
                    "Type": "npm",
                    "Vulnerabilities": None,
                }
            ]
        }
        vulns = TrivyParser.parse(clean, tmp_path)
        assert vulns == []

    def test_severity_mapping(self, tmp_path: Path) -> None:
        data = {
            "Results": [
                {
                    "Target": "lock",
                    "Class": "lang-pkgs",
                    "Type": "npm",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-1",
                            "PkgName": "a",
                            "InstalledVersion": "1.0",
                            "Severity": "CRITICAL",
                            "Title": "t",
                        },
                        {
                            "VulnerabilityID": "CVE-2",
                            "PkgName": "b",
                            "InstalledVersion": "1.0",
                            "Severity": "LOW",
                            "Title": "t",
                        },
                    ],
                }
            ]
        }
        vulns = TrivyParser.parse(data, tmp_path)
        assert vulns[0].severity == Severity.CRITICAL
        assert vulns[1].severity == Severity.LOW

    def test_detect_always_false(self, tmp_path: Path) -> None:
        """Trivy is never auto-detected; users pipe via --stdin."""
        (tmp_path / "package-lock.json").touch()
        assert TrivyParser.detect(tmp_path) is False

    def test_title_truncation(self, tmp_path: Path) -> None:
        long_title = "x" * 200
        data = {
            "Results": [
                {
                    "Target": "lock",
                    "Class": "lang-pkgs",
                    "Type": "npm",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-1",
                            "PkgName": "a",
                            "InstalledVersion": "1.0",
                            "Severity": "HIGH",
                            "Title": long_title,
                        },
                    ],
                }
            ]
        }
        vulns = TrivyParser.parse(data, tmp_path)
        assert len(vulns[0].title) == 120


# ── Engine integration ────────────────────────────────────────────────


class TestTrivyEngineIntegration:
    """Verify Trivy JSON is auto-detected when piped via --stdin."""

    def test_engine_auto_detects_trivy(self, tmp_path: Path) -> None:
        from depquiet.engine import scan

        result = scan(tmp_path, audit_json=TRIVY_BASIC, skip_epss=True)
        assert len(result.results) == 2
        cves = {r.vuln.cve for r in result.results}
        assert "CVE-2020-8203" in cves

    def test_engine_trivy_with_always_flag(self, tmp_path: Path) -> None:
        from depquiet.engine import scan

        result = scan(
            tmp_path,
            audit_json=TRIVY_BASIC,
            skip_epss=True,
            always_flag=["lodash"],
        )
        for r in result.results:
            if r.vuln.package == "lodash":
                assert r.verdict == Verdict.ACTION

    def test_engine_trivy_with_templates(self, tmp_path: Path) -> None:
        from depquiet.engine import scan

        # Create a template that matches lodash
        tmpl_dir = tmp_path / "templates"
        tmpl_dir.mkdir()
        (tmpl_dir / "lodash.yaml").write_text(
            "id: test-lodash\ncves:\n  - CVE-2020-8203\nreason: test\n"
        )
        result = scan(
            tmp_path,
            audit_json=TRIVY_BASIC,
            skip_epss=True,
            template_dirs=[tmpl_dir],
        )
        for r in result.results:
            if r.vuln.cve == "CVE-2020-8203":
                assert r.verdict == Verdict.FILTERED


# ── CLI integration ───────────────────────────────────────────────────


class TestTrivyCli:
    """Verify --config flag works."""

    def test_config_flag_loads_custom_file(self, tmp_path: Path) -> None:
        config_file = tmp_path / "custom.yaml"
        config_file.write_text("epss_threshold: 0.05\nalways_flag:\n  - express\n")

        from depquiet.config import load_config

        config = load_config(tmp_path, config_path=config_file)
        assert config.epss_threshold == 0.05
        assert "express" in config.always_flag

    def test_config_flag_missing_file_warns(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from depquiet.config import load_config

        config = load_config(tmp_path, config_path=tmp_path / "nope.yaml")
        assert config.epss_threshold == 0.1  # default
        assert "not found" in capsys.readouterr().err
