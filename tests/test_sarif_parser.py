"""Tests for SARIF v2.1.0 input parser.

Covers:
- CVE extraction from result properties, ruleId, rule properties
- Package name extraction from result/rule properties, message text
- Version and fix version extraction
- Severity from CVSS score, properties, SARIF level, rule defaults
- Deduplication
- Multi-run SARIF documents
- Rule resolution via ruleId and ruleIndex
- Extensions rules (CodeQL pattern)
- Engine integration (auto-detection of SARIF format)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from depquiet.models import Severity
from depquiet.parsers.sarif import (
    SarifParser,
    _extract_cve,
    _extract_fix_version,
    _extract_package,
    _extract_severity,
    _extract_version,
    _severity_from_cvss,
)

# ---------------------------------------------------------------------------
# Helper: minimal SARIF document builder
# ---------------------------------------------------------------------------


def _sarif_doc(
    results: list[dict[str, Any]],
    rules: list[dict[str, Any]] | None = None,
    extensions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a minimal valid SARIF v2.1.0 document."""
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "TestScanner",
                "version": "1.0.0",
                "rules": rules or [],
            },
        },
        "results": results,
    }
    if extensions:
        run["tool"]["extensions"] = extensions
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


# ---------------------------------------------------------------------------
# _severity_from_cvss
# ---------------------------------------------------------------------------


class TestSeverityFromCvss:
    def test_critical(self) -> None:
        assert _severity_from_cvss(9.8) == Severity.CRITICAL

    def test_high(self) -> None:
        assert _severity_from_cvss(7.5) == Severity.HIGH

    def test_moderate(self) -> None:
        assert _severity_from_cvss(5.0) == Severity.MODERATE

    def test_low(self) -> None:
        assert _severity_from_cvss(2.0) == Severity.LOW

    def test_info(self) -> None:
        assert _severity_from_cvss(0.0) == Severity.INFO

    def test_boundary_9(self) -> None:
        assert _severity_from_cvss(9.0) == Severity.CRITICAL

    def test_boundary_7(self) -> None:
        assert _severity_from_cvss(7.0) == Severity.HIGH

    def test_boundary_4(self) -> None:
        assert _severity_from_cvss(4.0) == Severity.MODERATE


# ---------------------------------------------------------------------------
# _extract_cve
# ---------------------------------------------------------------------------


class TestExtractCve:
    def test_from_result_properties_cve(self) -> None:
        result = {"properties": {"cve": "CVE-2024-1234"}}
        assert _extract_cve(result, None) == "CVE-2024-1234"

    def test_from_result_properties_cveId(self) -> None:
        result = {"properties": {"cveId": "CVE-2024-5678"}}
        assert _extract_cve(result, None) == "CVE-2024-5678"

    def test_from_ruleId_cve_pattern(self) -> None:
        result = {"ruleId": "CVE-2024-9999", "properties": {}}
        assert _extract_cve(result, None) == "CVE-2024-9999"

    def test_from_rule_properties(self) -> None:
        result = {"ruleId": "RULE-001", "properties": {}}
        rule = {"id": "RULE-001", "properties": {"cve": "CVE-2023-1111"}}
        assert _extract_cve(result, rule) == "CVE-2023-1111"

    def test_from_rule_id_cve_pattern(self) -> None:
        result = {"ruleId": "RULE-001", "properties": {}}
        rule = {"id": "CVE-2023-2222", "properties": {}}
        assert _extract_cve(result, rule) == "CVE-2023-2222"

    def test_fallback_to_ruleId(self) -> None:
        """Non-CVE ruleIds (GHSA, CWE, etc.) are kept as-is."""
        result = {"ruleId": "GHSA-abcd-1234-efgh", "properties": {}}
        assert _extract_cve(result, None) == "GHSA-abcd-1234-efgh"

    def test_no_identifier(self) -> None:
        result = {"properties": {}}
        assert _extract_cve(result, None) == "UNKNOWN"

    def test_result_properties_take_priority(self) -> None:
        """result.properties.cve wins over ruleId."""
        result = {"ruleId": "CVE-2024-0001", "properties": {"cve": "CVE-2024-0002"}}
        assert _extract_cve(result, None) == "CVE-2024-0002"


# ---------------------------------------------------------------------------
# _extract_package
# ---------------------------------------------------------------------------


class TestExtractPackage:
    def test_from_result_properties_packageName(self) -> None:
        result = {"properties": {"packageName": "lodash"}}
        assert _extract_package(result, None) == "lodash"

    def test_from_result_properties_component(self) -> None:
        result = {"properties": {"component": "express"}}
        assert _extract_package(result, None) == "express"

    def test_from_rule_properties(self) -> None:
        result = {"properties": {}}
        rule = {"properties": {"package": "requests"}}
        assert _extract_package(result, rule) == "requests"

    def test_from_message_in_pattern(self) -> None:
        result = {
            "properties": {},
            "message": {"text": "Prototype pollution vulnerability in lodash"},
        }
        assert _extract_package(result, None) == "lodash"

    def test_no_package_found(self) -> None:
        result = {"properties": {}, "message": {"text": "Something bad"}}
        assert _extract_package(result, None) == ""


# ---------------------------------------------------------------------------
# _extract_version
# ---------------------------------------------------------------------------


class TestExtractVersion:
    def test_from_result_properties(self) -> None:
        result = {"properties": {"version": "4.17.20"}}
        assert _extract_version(result, None) == "4.17.20"

    def test_from_result_installedVersion(self) -> None:
        result = {"properties": {"installedVersion": "1.2.3"}}
        assert _extract_version(result, None) == "1.2.3"

    def test_from_rule_properties(self) -> None:
        result = {"properties": {}}
        rule = {"properties": {"version": "2.0.0"}}
        assert _extract_version(result, rule) == "2.0.0"

    def test_no_version(self) -> None:
        result = {"properties": {}}
        assert _extract_version(result, None) == ""


# ---------------------------------------------------------------------------
# _extract_fix_version
# ---------------------------------------------------------------------------


class TestExtractFixVersion:
    def test_from_result_properties(self) -> None:
        result = {"properties": {"fixVersion": "4.17.21"}}
        assert _extract_fix_version(result, None) == "4.17.21"

    def test_from_rule_properties(self) -> None:
        result = {"properties": {}}
        rule = {"properties": {"fixedVersion": "2.1.0"}}
        assert _extract_fix_version(result, rule) == "2.1.0"

    def test_non_string_fix_ignored(self) -> None:
        """fixAvailable: true (boolean) should be ignored."""
        result = {"properties": {"fixAvailable": True}}
        assert _extract_fix_version(result, None) == ""

    def test_no_fix(self) -> None:
        result = {"properties": {}}
        assert _extract_fix_version(result, None) == ""


# ---------------------------------------------------------------------------
# _extract_severity
# ---------------------------------------------------------------------------


class TestExtractSeverity:
    def test_from_cvss_score(self) -> None:
        result = {"properties": {"cvssScore": 9.8}}
        assert _extract_severity(result, None) == Severity.CRITICAL

    def test_from_severity_property(self) -> None:
        result = {"properties": {"severity": "high"}}
        assert _extract_severity(result, None) == Severity.HIGH

    def test_from_security_severity_property(self) -> None:
        result = {"properties": {"security-severity": "low"}}
        assert _extract_severity(result, None) == Severity.LOW

    def test_from_rule_security_severity_numeric(self) -> None:
        """CodeQL puts a numeric security-severity in rule.properties."""
        result = {"properties": {}}
        rule = {"properties": {"security-severity": "8.5"}}
        assert _extract_severity(result, rule) == Severity.HIGH

    def test_from_sarif_level(self) -> None:
        result = {"level": "error", "properties": {}}
        assert _extract_severity(result, None) == Severity.HIGH

    def test_from_rule_default_level(self) -> None:
        result = {"properties": {}}
        rule = {"defaultConfiguration": {"level": "warning"}}
        assert _extract_severity(result, rule) == Severity.MODERATE

    def test_no_severity_is_unknown(self) -> None:
        assert _extract_severity({"properties": {}}, None) is None


# ---------------------------------------------------------------------------
# SarifParser.parse — full documents
# ---------------------------------------------------------------------------


class TestSarifParserParse:
    def test_basic_result(self) -> None:
        doc = _sarif_doc(
            results=[
                {
                    "ruleId": "CVE-2024-1234",
                    "level": "error",
                    "message": {"text": "Vulnerability in lodash"},
                    "properties": {
                        "packageName": "lodash",
                        "version": "4.17.20",
                        "fixVersion": "4.17.21",
                    },
                }
            ]
        )
        vulns = SarifParser.parse(doc, Path("."))
        assert len(vulns) == 1
        v = vulns[0]
        assert v.cve == "CVE-2024-1234"
        assert v.package == "lodash"
        assert v.version == "4.17.20"
        assert v.fix_version == "4.17.21"
        assert v.severity == Severity.HIGH

    def test_deduplication(self) -> None:
        """Same CVE:package across results is deduplicated."""
        result = {
            "ruleId": "CVE-2024-1234",
            "message": {"text": "vuln"},
            "properties": {"packageName": "lodash", "version": "4.17.20"},
        }
        doc = _sarif_doc(results=[result, result])
        vulns = SarifParser.parse(doc, Path("."))
        assert len(vulns) == 1

    def test_skips_no_package(self) -> None:
        """Results without an identifiable package are skipped."""
        doc = _sarif_doc(
            results=[
                {
                    "ruleId": "CVE-2024-1234",
                    "message": {"text": "Something bad"},
                    "properties": {},
                }
            ]
        )
        vulns = SarifParser.parse(doc, Path("."))
        assert len(vulns) == 0

    def test_multiple_results(self) -> None:
        doc = _sarif_doc(
            results=[
                {
                    "ruleId": "CVE-2024-0001",
                    "level": "error",
                    "message": {"text": "vuln1"},
                    "properties": {"packageName": "lodash", "version": "4.17.20"},
                },
                {
                    "ruleId": "CVE-2024-0002",
                    "level": "warning",
                    "message": {"text": "vuln2"},
                    "properties": {"packageName": "express", "version": "4.18.0"},
                },
            ]
        )
        vulns = SarifParser.parse(doc, Path("."))
        assert len(vulns) == 2
        packages = {v.package for v in vulns}
        assert packages == {"lodash", "express"}

    def test_rule_resolution_by_id(self) -> None:
        """Rule metadata supplements the result (CVE, URL from rule)."""
        doc = _sarif_doc(
            results=[
                {
                    "ruleId": "VULN-001",
                    "message": {},
                    "properties": {"packageName": "axios", "version": "0.21.0"},
                }
            ],
            rules=[
                {
                    "id": "VULN-001",
                    "shortDescription": {"text": "SSRF in axios"},
                    "helpUri": "https://example.com/VULN-001",
                    "properties": {"cve": "CVE-2023-45857"},
                }
            ],
        )
        vulns = SarifParser.parse(doc, Path("."))
        assert len(vulns) == 1
        assert vulns[0].cve == "CVE-2023-45857"
        assert vulns[0].title == "SSRF in axios"
        assert vulns[0].url == "https://example.com/VULN-001"

    def test_rule_resolution_by_index(self) -> None:
        """When ruleId doesn't match, fall back to ruleIndex."""
        rules = [
            {"id": "R0", "properties": {"cve": "CVE-2024-0000"}},
            {"id": "R1", "properties": {"cve": "CVE-2024-1111"}},
        ]
        doc = _sarif_doc(
            results=[
                {
                    "ruleId": "NOMATCH",
                    "ruleIndex": 1,
                    "message": {"text": "vuln"},
                    "properties": {"packageName": "pkg"},
                }
            ],
            rules=rules,
        )
        vulns = SarifParser.parse(doc, Path("."))
        assert len(vulns) == 1
        assert vulns[0].cve == "CVE-2024-1111"

    def test_extensions_rules(self) -> None:
        """CodeQL puts rules in tool.extensions[].rules."""
        doc = _sarif_doc(
            results=[
                {
                    "ruleId": "EXT-001",
                    "message": {"text": "vuln"},
                    "properties": {"packageName": "django"},
                }
            ],
            extensions=[
                {
                    "name": "codeql-python",
                    "rules": [
                        {
                            "id": "EXT-001",
                            "properties": {"cve": "CVE-2023-9999", "severity": "critical"},
                        }
                    ],
                }
            ],
        )
        vulns = SarifParser.parse(doc, Path("."))
        assert len(vulns) == 1
        assert vulns[0].cve == "CVE-2023-9999"

    def test_multi_run(self) -> None:
        """SARIF documents can have multiple runs."""
        doc = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Scanner1", "rules": []}},
                    "results": [
                        {
                            "ruleId": "CVE-2024-0001",
                            "message": {"text": "vuln1"},
                            "properties": {"packageName": "pkg1"},
                        }
                    ],
                },
                {
                    "tool": {"driver": {"name": "Scanner2", "rules": []}},
                    "results": [
                        {
                            "ruleId": "CVE-2024-0002",
                            "message": {"text": "vuln2"},
                            "properties": {"packageName": "pkg2"},
                        }
                    ],
                },
            ],
        }
        vulns = SarifParser.parse(doc, Path("."))
        assert len(vulns) == 2

    def test_empty_runs(self) -> None:
        doc = {"$schema": "...", "version": "2.1.0", "runs": []}
        vulns = SarifParser.parse(doc, Path("."))
        assert len(vulns) == 0

    def test_no_runs_key(self) -> None:
        doc = {"$schema": "...", "version": "2.1.0"}
        vulns = SarifParser.parse(doc, Path("."))
        assert len(vulns) == 0

    def test_title_from_rule_shortDescription(self) -> None:
        doc = _sarif_doc(
            results=[
                {
                    "ruleId": "R1",
                    "message": {},
                    "properties": {"packageName": "pkg"},
                }
            ],
            rules=[
                {
                    "id": "R1",
                    "shortDescription": {"text": "SQL injection vulnerability"},
                }
            ],
        )
        vulns = SarifParser.parse(doc, Path("."))
        assert vulns[0].title == "SQL injection vulnerability"

    def test_title_from_rule_name(self) -> None:
        doc = _sarif_doc(
            results=[
                {
                    "ruleId": "R1",
                    "message": {},
                    "properties": {"packageName": "pkg"},
                }
            ],
            rules=[{"id": "R1", "name": "SqlInjection"}],
        )
        vulns = SarifParser.parse(doc, Path("."))
        assert vulns[0].title == "SqlInjection"

    def test_title_truncated(self) -> None:
        long_msg = "A" * 300
        doc = _sarif_doc(
            results=[
                {
                    "ruleId": "R1",
                    "message": {"text": long_msg},
                    "properties": {"packageName": "pkg"},
                }
            ]
        )
        vulns = SarifParser.parse(doc, Path("."))
        assert len(vulns[0].title) == 200

    def test_cvss_severity_in_result(self) -> None:
        doc = _sarif_doc(
            results=[
                {
                    "ruleId": "CVE-2024-1234",
                    "message": {"text": "vuln"},
                    "properties": {
                        "packageName": "pkg",
                        "cvssScore": 9.1,
                    },
                }
            ]
        )
        vulns = SarifParser.parse(doc, Path("."))
        assert vulns[0].severity == Severity.CRITICAL

    def test_ghsa_id_preserved(self) -> None:
        """GHSA IDs are kept as-is when no CVE is available."""
        doc = _sarif_doc(
            results=[
                {
                    "ruleId": "GHSA-abcd-1234-efgh",
                    "message": {"text": "vuln"},
                    "properties": {"packageName": "pkg"},
                }
            ]
        )
        vulns = SarifParser.parse(doc, Path("."))
        assert vulns[0].cve == "GHSA-abcd-1234-efgh"


# ---------------------------------------------------------------------------
# SarifParser.detect / scan
# ---------------------------------------------------------------------------


class TestSarifParserMisc:
    def test_detect_always_false(self) -> None:
        assert SarifParser.detect(Path(".")) is False

    def test_scan_returns_empty(self) -> None:
        assert SarifParser.scan(Path(".")) == []


# ---------------------------------------------------------------------------
# Engine integration — SARIF format auto-detection
# ---------------------------------------------------------------------------


class TestSarifEngineIntegration:
    def test_sarif_with_schema_detected(self, tmp_path: Path) -> None:
        """Engine auto-detects SARIF by $schema + runs."""
        from depquiet.engine import scan

        doc = _sarif_doc(
            results=[
                {
                    "ruleId": "CVE-2024-1234",
                    "level": "error",
                    "message": {"text": "Vulnerability in lodash"},
                    "properties": {
                        "packageName": "lodash",
                        "version": "4.17.20",
                    },
                }
            ]
        )
        result = scan(tmp_path, audit_json=doc, skip_epss=True)
        assert len(result.results) > 0
        assert result.results[0].vuln.cve == "CVE-2024-1234"

    def test_sarif_with_version_detected(self, tmp_path: Path) -> None:
        """Engine detects SARIF by version=2.1.0 + runs (no $schema)."""
        from depquiet.engine import scan

        doc = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Test", "rules": []}},
                    "results": [
                        {
                            "ruleId": "CVE-2024-5678",
                            "message": {"text": "vuln"},
                            "properties": {"packageName": "express", "version": "4.18.0"},
                        }
                    ],
                }
            ],
        }
        result = scan(tmp_path, audit_json=doc, skip_epss=True)
        assert len(result.results) > 0
        assert result.results[0].vuln.package == "express"

    def test_trivy_json_not_confused_with_sarif(self, tmp_path: Path) -> None:
        """Trivy native JSON has 'Results' but no 'runs' — shouldn't hit SARIF."""
        from depquiet.engine import scan

        doc = {
            "Results": [
                {
                    "Target": "package-lock.json",
                    "Class": "lang-pkgs",
                    "Type": "npm",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-0001",
                            "PkgName": "braces",
                            "InstalledVersion": "3.0.2",
                            "Severity": "HIGH",
                            "Title": "Test vuln",
                        }
                    ],
                }
            ]
        }
        result = scan(tmp_path, audit_json=doc, skip_epss=True)
        # Should be parsed by Trivy parser, not SARIF
        assert len(result.results) > 0
        assert result.results[0].vuln.package == "braces"
