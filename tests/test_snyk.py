"""Tests for the Snyk JSON parser."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from depquiet.models import Severity
from depquiet.parsers.snyk import SnykParser

# ── Fixtures ──────────────────────────────────────────────────────────

SNYK_BASIC: dict[str, Any] = {
    "ok": False,
    "vulnerabilities": [
        {
            "id": "SNYK-JS-LODASH-567746",
            "title": "Prototype Pollution",
            "severity": "high",
            "packageName": "lodash",
            "version": "4.17.15",
            "fixedIn": ["4.17.21"],
            "from": ["my-app@1.0.0", "lodash@4.17.15"],
            "identifiers": {"CVE": ["CVE-2020-8203"]},
            "isUpgradable": True,
            "language": "js",
            "packageManager": "npm",
        },
        {
            "id": "SNYK-JS-EXPRESS-1024",
            "title": "Open Redirect",
            "severity": "medium",
            "packageName": "express",
            "version": "4.18.2",
            "fixedIn": ["4.19.2"],
            "from": ["my-app@1.0.0", "express@4.18.2"],
            "identifiers": {"CVE": ["CVE-2024-29041"]},
            "language": "js",
            "packageManager": "npm",
        },
    ],
    "dependencyCount": 200,
    "packageManager": "npm",
}

SNYK_NO_CVE: dict[str, Any] = {
    "ok": False,
    "vulnerabilities": [
        {
            "id": "SNYK-JS-FOO-9999",
            "title": "Some issue with no CVE assigned",
            "severity": "low",
            "packageName": "foo",
            "version": "1.0.0",
            "fixedIn": [],
            "from": ["my-app@1.0.0", "foo@1.0.0"],
            "identifiers": {},
            "packageManager": "npm",
        }
    ],
    "packageManager": "npm",
}

SNYK_TRANSITIVE: dict[str, Any] = {
    "ok": False,
    "vulnerabilities": [
        {
            "id": "SNYK-JS-MINIMIST-559764",
            "title": "Prototype Pollution",
            "severity": "high",
            "packageName": "minimist",
            "version": "1.2.5",
            "fixedIn": ["1.2.6"],
            "from": ["my-app@1.0.0", "mkdirp@0.5.5", "minimist@1.2.5"],
            "identifiers": {"CVE": ["CVE-2021-44906"]},
            "packageManager": "npm",
        }
    ],
    "packageManager": "npm",
}

SNYK_DUPLICATES: dict[str, Any] = {
    "ok": False,
    "vulnerabilities": [
        {
            "id": "SNYK-JS-LODASH-567746",
            "title": "Prototype Pollution",
            "severity": "high",
            "packageName": "lodash",
            "version": "4.17.15",
            "fixedIn": ["4.17.21"],
            "from": ["my-app@1.0.0", "lodash@4.17.15"],
            "identifiers": {"CVE": ["CVE-2020-8203"]},
            "packageManager": "npm",
        },
        {
            "id": "SNYK-JS-LODASH-567746",
            "title": "Prototype Pollution",
            "severity": "high",
            "packageName": "lodash",
            "version": "4.17.15",
            "fixedIn": ["4.17.21"],
            "from": ["my-app@1.0.0", "other@2.0.0", "lodash@4.17.15"],
            "identifiers": {"CVE": ["CVE-2020-8203"]},
            "packageManager": "npm",
        },
    ],
    "packageManager": "npm",
}

SNYK_PYTHON: dict[str, Any] = {
    "ok": False,
    "vulnerabilities": [
        {
            "id": "SNYK-PYTHON-DJANGO-174321",
            "title": "SQL Injection",
            "severity": "critical",
            "packageName": "django",
            "version": "3.2.0",
            "fixedIn": ["3.2.25"],
            "from": ["my-app", "django@3.2.0"],
            "identifiers": {"CVE": ["CVE-2024-12345"]},
            "packageManager": "pip",
        }
    ],
    "packageManager": "pip",
}

SNYK_EMPTY: dict[str, Any] = {
    "ok": True,
    "vulnerabilities": [],
    "dependencyCount": 50,
    "packageManager": "npm",
}

SNYK_NO_FIX: dict[str, Any] = {
    "ok": False,
    "vulnerabilities": [
        {
            "id": "SNYK-JS-QS-3153490",
            "title": "Prototype Pollution",
            "severity": "high",
            "packageName": "qs",
            "version": "6.5.2",
            "fixedIn": [],
            "from": ["my-app@1.0.0", "express@4.17.1", "qs@6.5.2"],
            "identifiers": {"CVE": ["CVE-2022-24999"]},
            "packageManager": "npm",
        }
    ],
    "packageManager": "npm",
}

SNYK_LONG_TITLE: dict[str, Any] = {
    "ok": False,
    "vulnerabilities": [
        {
            "id": "SNYK-JS-TEST-9999",
            "title": "A" * 200,
            "severity": "medium",
            "packageName": "test-pkg",
            "version": "1.0.0",
            "fixedIn": [],
            "from": ["app@1.0.0", "test-pkg@1.0.0"],
            "identifiers": {"CVE": ["CVE-2024-99999"]},
            "packageManager": "npm",
        }
    ],
    "packageManager": "npm",
}

_PROJECT = Path("/tmp/fake-project")


# ── Tests ─────────────────────────────────────────────────────────────


class TestSnykParser:
    def test_basic_parse(self) -> None:
        vulns = SnykParser.parse(SNYK_BASIC, _PROJECT)
        assert len(vulns) == 2

    def test_cve_from_identifiers(self) -> None:
        vulns = SnykParser.parse(SNYK_BASIC, _PROJECT)
        assert vulns[0].cve == "CVE-2020-8203"
        assert vulns[1].cve == "CVE-2024-29041"

    def test_fallback_to_snyk_id(self) -> None:
        """When no CVE exists, use the Snyk ID as the cve field."""
        vulns = SnykParser.parse(SNYK_NO_CVE, _PROJECT)
        assert len(vulns) == 1
        assert vulns[0].cve == "SNYK-JS-FOO-9999"

    def test_package_and_version(self) -> None:
        vulns = SnykParser.parse(SNYK_BASIC, _PROJECT)
        assert vulns[0].package == "lodash"
        assert vulns[0].version == "4.17.15"

    def test_severity_mapping(self) -> None:
        vulns = SnykParser.parse(SNYK_BASIC, _PROJECT)
        assert vulns[0].severity == Severity.HIGH
        assert vulns[1].severity == Severity.MODERATE

    def test_fix_version(self) -> None:
        vulns = SnykParser.parse(SNYK_BASIC, _PROJECT)
        assert vulns[0].fix_version == "4.17.21"

    def test_no_fix_version(self) -> None:
        vulns = SnykParser.parse(SNYK_NO_FIX, _PROJECT)
        assert vulns[0].fix_version == ""

    def test_url_from_snyk_id(self) -> None:
        vulns = SnykParser.parse(SNYK_BASIC, _PROJECT)
        assert vulns[0].url == "https://security.snyk.io/vuln/SNYK-JS-LODASH-567746"

    def test_transitive_dependency(self) -> None:
        """from[] chain of length 3 means transitive (depth=2)."""
        vulns = SnykParser.parse(SNYK_TRANSITIVE, _PROJECT)
        assert vulns[0].is_direct is False
        assert vulns[0].depth == 2

    def test_direct_dependency(self) -> None:
        """from[] chain of length 2 means direct (depth=1)."""
        vulns = SnykParser.parse(SNYK_BASIC, _PROJECT)
        assert vulns[0].is_direct is True
        assert vulns[0].depth == 1

    def test_deduplication(self) -> None:
        """Same CVE+package appearing twice should be deduplicated."""
        vulns = SnykParser.parse(SNYK_DUPLICATES, _PROJECT)
        assert len(vulns) == 1

    def test_empty_vulnerabilities(self) -> None:
        vulns = SnykParser.parse(SNYK_EMPTY, _PROJECT)
        assert vulns == []

    def test_title(self) -> None:
        vulns = SnykParser.parse(SNYK_BASIC, _PROJECT)
        assert vulns[0].title == "Prototype Pollution"

    def test_long_title_truncated(self) -> None:
        vulns = SnykParser.parse(SNYK_LONG_TITLE, _PROJECT)
        assert len(vulns[0].title) == 120
        assert vulns[0].title.endswith("...")

    def test_python_parser(self) -> None:
        """Snyk supports Python too — severity critical maps correctly."""
        vulns = SnykParser.parse(SNYK_PYTHON, _PROJECT)
        assert len(vulns) == 1
        assert vulns[0].package == "django"
        assert vulns[0].severity == Severity.CRITICAL

    def test_detect_returns_false(self) -> None:
        """Snyk requires auth — detect always returns False."""
        assert SnykParser.detect(_PROJECT) is False

    def test_scan_returns_empty(self) -> None:
        """Snyk requires auth — scan returns empty list."""
        assert SnykParser.scan(_PROJECT) == []

    def test_invalid_vulnerabilities_type(self) -> None:
        """If vulnerabilities is a dict (npm format), return empty."""
        data: dict[str, Any] = {"vulnerabilities": {"lodash": {}}, "packageManager": "npm"}
        assert SnykParser.parse(data, _PROJECT) == []

    def test_missing_package_name_skipped(self) -> None:
        """Entries without packageName are skipped."""
        data: dict[str, Any] = {
            "vulnerabilities": [{"id": "SNYK-TEST-1", "severity": "high", "version": "1.0.0"}],
            "packageManager": "npm",
        }
        assert SnykParser.parse(data, _PROJECT) == []

    def test_missing_id_and_cve_skipped(self) -> None:
        """Entries without any id or CVE are skipped."""
        data: dict[str, Any] = {
            "vulnerabilities": [{"packageName": "foo", "severity": "high", "version": "1.0.0"}],
            "packageManager": "npm",
        }
        assert SnykParser.parse(data, _PROJECT) == []

    def test_non_dict_entry_skipped(self) -> None:
        """Non-dict entries in the array are skipped."""
        data: dict[str, Any] = {
            "vulnerabilities": ["not-a-dict", 42, None],
            "packageManager": "npm",
        }
        assert SnykParser.parse(data, _PROJECT) == []

    def test_no_from_chain(self) -> None:
        """Missing from[] defaults to depth=0, is_direct=True."""
        data: dict[str, Any] = {
            "vulnerabilities": [
                {
                    "id": "SNYK-TEST-1",
                    "severity": "high",
                    "packageName": "foo",
                    "version": "1.0.0",
                    "identifiers": {"CVE": ["CVE-2024-0001"]},
                }
            ],
            "packageManager": "npm",
        }
        vulns = SnykParser.parse(data, _PROJECT)
        assert vulns[0].depth == 0
        assert vulns[0].is_direct is True


class TestSnykAutoDetection:
    """Test that engine.scan() auto-detects Snyk JSON format."""

    def test_snyk_detected_over_npm(self) -> None:
        """Snyk has 'vulnerabilities' as list + 'packageManager' → Snyk parser."""
        import tempfile

        from depquiet.engine import scan

        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            result = scan(project, audit_json=SNYK_BASIC, skip_epss=True)
            assert len(result.results) == 2
            assert result.results[0].vuln.cve == "CVE-2020-8203"
