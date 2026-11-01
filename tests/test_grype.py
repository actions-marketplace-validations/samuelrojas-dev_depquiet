"""Tests for the Grype JSON parser."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from depquiet.models import Severity
from depquiet.parsers.grype import GrypeParser

# ── Fixtures ──────────────────────────────────────────────────────────

GRYPE_BASIC: dict[str, Any] = {
    "matches": [
        {
            "vulnerability": {
                "id": "CVE-2020-8203",
                "dataSource": "https://github.com/advisories/GHSA-p6mc-m468-83gw",
                "severity": "High",
                "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2020-8203"],
                "description": "Prototype Pollution in lodash",
                "fix": {"versions": ["4.17.19"], "state": "fixed"},
            },
            "artifact": {
                "name": "lodash",
                "version": "4.17.15",
                "type": "npm",
                "language": "javascript",
            },
        },
        {
            "vulnerability": {
                "id": "CVE-2024-29041",
                "dataSource": "https://github.com/advisories/GHSA-rv95-896h-c2f7",
                "severity": "Medium",
                "urls": [],
                "description": "Open redirect in express",
                "fix": {"versions": ["4.19.2"], "state": "fixed"},
            },
            "artifact": {
                "name": "express",
                "version": "4.18.2",
                "type": "npm",
                "language": "javascript",
            },
        },
    ]
}

GRYPE_NO_FIX: dict[str, Any] = {
    "matches": [
        {
            "vulnerability": {
                "id": "CVE-2023-99999",
                "severity": "Critical",
                "description": "No fix available yet",
                "fix": {"versions": [], "state": "not-fixed"},
            },
            "artifact": {
                "name": "vulnerable-pkg",
                "version": "1.0.0",
                "type": "python",
                "language": "python",
            },
        }
    ]
}

GRYPE_DUPLICATES: dict[str, Any] = {
    "matches": [
        {
            "vulnerability": {
                "id": "CVE-2020-8203",
                "severity": "High",
                "description": "Prototype Pollution in lodash",
                "fix": {"versions": ["4.17.19"], "state": "fixed"},
            },
            "artifact": {
                "name": "lodash",
                "version": "4.17.15",
                "type": "npm",
            },
        },
        {
            "vulnerability": {
                "id": "CVE-2020-8203",
                "severity": "High",
                "description": "Prototype Pollution in lodash (duplicate)",
                "fix": {"versions": ["4.17.19"], "state": "fixed"},
            },
            "artifact": {
                "name": "lodash",
                "version": "4.17.15",
                "type": "npm",
            },
        },
    ]
}

GRYPE_MULTI_ECOSYSTEM: dict[str, Any] = {
    "matches": [
        {
            "vulnerability": {
                "id": "CVE-2023-32681",
                "severity": "Medium",
                "description": "Proxy-auth leak in requests",
                "fix": {"versions": ["2.31.0"], "state": "fixed"},
            },
            "artifact": {
                "name": "requests",
                "version": "2.28.0",
                "type": "python",
                "language": "python",
            },
        },
        {
            "vulnerability": {
                "id": "CVE-2020-8203",
                "severity": "High",
                "description": "Prototype Pollution in lodash",
                "fix": {"versions": ["4.17.19"], "state": "fixed"},
            },
            "artifact": {
                "name": "lodash",
                "version": "4.17.15",
                "type": "npm",
                "language": "javascript",
            },
        },
    ]
}

GRYPE_EMPTY: dict[str, Any] = {"matches": []}

GRYPE_MINIMAL_FIELDS: dict[str, Any] = {
    "matches": [
        {
            "vulnerability": {
                "id": "GHSA-xxxx-yyyy-zzzz",
                "severity": "Low",
            },
            "artifact": {
                "name": "some-pkg",
                "version": "0.1.0",
            },
        }
    ]
}


# ── Parser tests ─────────────────────────────────────────────────────


class TestGrypeParser:
    """Tests for GrypeParser.parse()."""

    def test_parse_basic(self, tmp_path: Path) -> None:
        vulns = GrypeParser.parse(GRYPE_BASIC, tmp_path)
        assert len(vulns) == 2
        assert vulns[0].cve == "CVE-2020-8203"
        assert vulns[0].package == "lodash"
        assert vulns[0].version == "4.17.15"
        assert vulns[0].severity == Severity.HIGH
        assert vulns[0].fix_version == "4.17.19"
        assert "nvd.nist.gov" in vulns[0].url
        assert vulns[1].cve == "CVE-2024-29041"
        assert vulns[1].severity == Severity.MODERATE

    def test_parse_no_fix(self, tmp_path: Path) -> None:
        vulns = GrypeParser.parse(GRYPE_NO_FIX, tmp_path)
        assert len(vulns) == 1
        assert vulns[0].fix_version == ""
        assert vulns[0].severity == Severity.CRITICAL

    def test_parse_deduplicates(self, tmp_path: Path) -> None:
        vulns = GrypeParser.parse(GRYPE_DUPLICATES, tmp_path)
        assert len(vulns) == 1

    def test_parse_multi_ecosystem(self, tmp_path: Path) -> None:
        vulns = GrypeParser.parse(GRYPE_MULTI_ECOSYSTEM, tmp_path)
        assert len(vulns) == 2
        packages = {v.package for v in vulns}
        assert packages == {"requests", "lodash"}

    def test_parse_empty(self, tmp_path: Path) -> None:
        vulns = GrypeParser.parse(GRYPE_EMPTY, tmp_path)
        assert vulns == []

    def test_parse_empty_dict(self, tmp_path: Path) -> None:
        vulns = GrypeParser.parse({}, tmp_path)
        assert vulns == []

    def test_parse_minimal_fields(self, tmp_path: Path) -> None:
        """Parse works even with minimal fields (no fix, urls, description)."""
        vulns = GrypeParser.parse(GRYPE_MINIMAL_FIELDS, tmp_path)
        assert len(vulns) == 1
        assert vulns[0].cve == "GHSA-xxxx-yyyy-zzzz"
        assert vulns[0].severity == Severity.LOW
        assert vulns[0].fix_version == ""
        assert vulns[0].title == "GHSA-xxxx-yyyy-zzzz"  # fallback to CVE ID

    def test_parse_url_fallback_to_datasource(self, tmp_path: Path) -> None:
        """When urls is empty, fall back to dataSource."""
        data: dict[str, Any] = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2024-0001",
                        "severity": "High",
                        "dataSource": "https://security.example.com/CVE-2024-0001",
                        "urls": [],
                    },
                    "artifact": {"name": "pkg", "version": "1.0"},
                }
            ]
        }
        vulns = GrypeParser.parse(data, tmp_path)
        assert vulns[0].url == "https://security.example.com/CVE-2024-0001"

    def test_parse_title_truncation(self, tmp_path: Path) -> None:
        """Long descriptions are truncated to 120 chars."""
        data: dict[str, Any] = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2024-0002",
                        "severity": "Medium",
                        "description": "A" * 200,
                    },
                    "artifact": {"name": "pkg", "version": "1.0"},
                }
            ]
        }
        vulns = GrypeParser.parse(data, tmp_path)
        assert len(vulns[0].title) == 120

    def test_detect_returns_false(self, tmp_path: Path) -> None:
        assert GrypeParser.detect(tmp_path) is False

    def test_scan_returns_empty(self, tmp_path: Path) -> None:
        assert GrypeParser.scan(tmp_path) == []

    def test_name(self) -> None:
        assert GrypeParser.name == "grype"

    def test_is_direct_always_true(self, tmp_path: Path) -> None:
        vulns = GrypeParser.parse(GRYPE_BASIC, tmp_path)
        assert all(v.is_direct for v in vulns)


class TestGrypeEngineIntegration:
    """Test that the engine recognizes grype JSON via --stdin."""

    def test_stdin_grype_json(self, tmp_path: Path) -> None:
        from depquiet.engine import scan

        result = scan(
            project=tmp_path,
            epss_threshold=0.1,
            skip_epss=True,
            audit_json=GRYPE_BASIC,
        )
        # Grype matches are parsed as vulnerabilities
        assert len(result.results) == 2
