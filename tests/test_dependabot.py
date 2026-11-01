"""Tests for the Dependabot/GitHub Advisory parser."""

from __future__ import annotations

import io
import json
from pathlib import Path
from unittest.mock import patch

from depquiet.engine import scan
from depquiet.models import Severity
from depquiet.parsers.dependabot import DependabotParser


def _make_alert(
    *,
    cve_id: str = "CVE-2024-1234",
    ghsa_id: str = "GHSA-xxxx-yyyy-zzzz",
    pkg_name: str = "lodash",
    ecosystem: str = "npm",
    severity: str = "high",
    summary: str = "Prototype Pollution in lodash",
    fix_version: str = "4.17.21",
    vuln_range: str = ">= 4.17.0, < 4.17.21",
    scope: str = "runtime",
    state: str = "open",
) -> dict:
    """Build a minimal Dependabot alert object for testing."""
    alert: dict = {
        "number": 1,
        "state": state,
        "dependency": {
            "package": {"ecosystem": ecosystem, "name": pkg_name},
            "manifest_path": "package-lock.json",
            "scope": scope,
        },
        "security_advisory": {
            "ghsa_id": ghsa_id,
            "cve_id": cve_id,
            "summary": summary,
            "severity": severity,
        },
        "security_vulnerability": {
            "severity": severity,
            "vulnerable_version_range": vuln_range,
            "first_patched_version": {"identifier": fix_version},
        },
    }
    return alert


class TestDependabotParser:
    """Unit tests for DependabotParser.parse()."""

    def test_parse_basic(self) -> None:
        data = {"alerts": [_make_alert()]}
        vulns = DependabotParser.parse(data, Path("."))
        assert len(vulns) == 1
        v = vulns[0]
        assert v.cve == "CVE-2024-1234"
        assert v.package == "lodash"
        assert v.severity == Severity.HIGH
        assert v.fix_version == "4.17.21"
        assert v.title == "Prototype Pollution in lodash"
        assert "GHSA-xxxx-yyyy-zzzz" in v.url
        assert v.is_dev is False

    def test_parse_dev_scope(self) -> None:
        data = {"alerts": [_make_alert(scope="development")]}
        vulns = DependabotParser.parse(data, Path("."))
        assert len(vulns) == 1
        assert vulns[0].is_dev is True

    def test_skips_dismissed(self) -> None:
        data = {
            "alerts": [
                _make_alert(state="dismissed"),
                _make_alert(state="open", cve_id="CVE-2024-9999", pkg_name="express"),
            ]
        }
        vulns = DependabotParser.parse(data, Path("."))
        assert len(vulns) == 1
        assert vulns[0].cve == "CVE-2024-9999"

    def test_skips_fixed(self) -> None:
        data = {"alerts": [_make_alert(state="fixed")]}
        vulns = DependabotParser.parse(data, Path("."))
        assert len(vulns) == 0

    def test_deduplicates(self) -> None:
        alert = _make_alert()
        data = {"alerts": [alert, alert]}
        vulns = DependabotParser.parse(data, Path("."))
        assert len(vulns) == 1

    def test_multiple_alerts(self) -> None:
        data = {
            "alerts": [
                _make_alert(cve_id="CVE-2024-001", pkg_name="lodash"),
                _make_alert(cve_id="CVE-2024-002", pkg_name="express", severity="critical"),
                _make_alert(cve_id="CVE-2024-003", pkg_name="semver", severity="moderate"),
            ]
        }
        vulns = DependabotParser.parse(data, Path("."))
        assert len(vulns) == 3
        severities = {v.package: v.severity for v in vulns}
        assert severities["express"] == Severity.CRITICAL
        assert severities["semver"] == Severity.MODERATE

    def test_ghsa_only_no_cve(self) -> None:
        """Alerts may have a GHSA but no CVE — use GHSA as the identifier."""
        data = {"alerts": [_make_alert(cve_id=None, ghsa_id="GHSA-abcd-efgh-ijkl")]}
        vulns = DependabotParser.parse(data, Path("."))
        assert len(vulns) == 1
        assert vulns[0].cve == "GHSA-abcd-efgh-ijkl"

    def test_empty_alerts(self) -> None:
        data = {"alerts": []}
        vulns = DependabotParser.parse(data, Path("."))
        assert len(vulns) == 0

    def test_no_alerts_key(self) -> None:
        data: dict = {}
        vulns = DependabotParser.parse(data, Path("."))
        assert len(vulns) == 0

    def test_no_fix_version(self) -> None:
        alert = _make_alert()
        alert["security_vulnerability"]["first_patched_version"] = None
        data = {"alerts": [alert]}
        vulns = DependabotParser.parse(data, Path("."))
        assert vulns[0].fix_version == ""

    def test_title_truncation(self) -> None:
        long_summary = "A" * 200
        data = {"alerts": [_make_alert(summary=long_summary)]}
        vulns = DependabotParser.parse(data, Path("."))
        assert len(vulns[0].title) == 120

    def test_severity_mapping(self) -> None:
        for sev, expected in [
            ("critical", Severity.CRITICAL),
            ("high", Severity.HIGH),
            ("moderate", Severity.MODERATE),
            ("low", Severity.LOW),
        ]:
            data = {
                "alerts": [
                    _make_alert(
                        severity=sev,
                        cve_id=f"CVE-{sev}",
                        pkg_name=f"pkg-{sev}",
                    )
                ]
            }
            vulns = DependabotParser.parse(data, Path("."))
            assert vulns[0].severity == expected, f"Failed for severity={sev}"

    def test_detect_always_false(self) -> None:
        assert DependabotParser.detect(Path(".")) is False

    def test_vuln_range_as_version(self) -> None:
        data = {"alerts": [_make_alert(vuln_range="< 2.0.0")]}
        vulns = DependabotParser.parse(data, Path("."))
        assert vulns[0].version == "< 2.0.0"


class TestDependabotEngineIntegration:
    """Test that the engine correctly routes Dependabot JSON."""

    def test_engine_auto_detects_dependabot(self) -> None:
        data = {"alerts": [_make_alert()]}
        result = scan(Path("."), audit_json=data, skip_epss=True)
        assert len(result.results) == 1
        assert result.results[0].vuln.package == "lodash"

    def test_engine_dependabot_with_always_flag(self) -> None:
        data = {"alerts": [_make_alert(severity="low")]}
        result = scan(Path("."), audit_json=data, skip_epss=True, always_flag=["lodash"])
        assert len(result.results) == 1
        from depquiet.models import Verdict

        assert result.results[0].verdict == Verdict.ACTION

    def test_engine_dependabot_filters_dev(self) -> None:
        data = {"alerts": [_make_alert(scope="development")]}
        result = scan(Path("."), audit_json=data, skip_epss=True)
        assert len(result.results) == 1
        from depquiet.models import Verdict

        assert result.results[0].verdict == Verdict.FILTERED


class TestDependabotCli:
    """Test CLI array-wrapping for Dependabot input."""

    def test_stdin_wraps_array(self) -> None:
        """CLI wraps a JSON array (Dependabot export) into {"alerts": [...]}."""
        alerts = [_make_alert()]
        stdin_data = json.dumps(alerts)

        with patch("sys.stdin", io.StringIO(stdin_data)):
            from depquiet.cli import main

            exit_code = main(["--stdin", "--offline", "--json"])
        # Should parse without error (exit 0 or 1 depending on verdicts)
        assert exit_code in (0, 1)

    def test_stdin_dict_passthrough(self) -> None:
        """CLI passes dict-shaped JSON (npm/pip/trivy) unchanged."""
        npm_data = {"vulnerabilities": {}}
        stdin_data = json.dumps(npm_data)

        with patch("sys.stdin", io.StringIO(stdin_data)):
            from depquiet.cli import main

            exit_code = main(["--stdin", "--offline", "--json"])
        assert exit_code == 0
