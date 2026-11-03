"""Tests for the --fail-on configurable CI gate."""

from __future__ import annotations

from unittest.mock import patch

from depquiet.cli import _should_fail, main
from depquiet.models import (
    ScanResult,
    Severity,
    TriageResult,
    Verdict,
    Vulnerability,
)


def _vuln(severity: Severity = Severity.HIGH) -> Vulnerability:
    return Vulnerability(
        cve="CVE-2024-1234",
        package="test-pkg",
        version="1.0.0",
        severity=severity,
    )


def _result(severities: list[Severity]) -> ScanResult:
    results = [TriageResult(vuln=_vuln(sev), verdict=Verdict.ACTION) for sev in severities]
    return ScanResult(
        project_path=".", package_manager="npm", total_dependencies=10, results=results
    )


def _empty_result() -> ScanResult:
    return ScanResult(project_path=".", package_manager="npm", total_dependencies=10, results=[])


def _filtered_result() -> ScanResult:
    return ScanResult(
        project_path=".",
        package_manager="npm",
        total_dependencies=10,
        results=[TriageResult(vuln=_vuln(), verdict=Verdict.FILTERED)],
    )


class TestShouldFail:
    def test_default_any_action_fails(self):
        assert _should_fail(_result([Severity.LOW]), None) is True

    def test_default_no_action_passes(self):
        assert _should_fail(_empty_result(), None) is False

    def test_default_filtered_only_passes(self):
        assert _should_fail(_filtered_result(), None) is False

    def test_none_never_fails(self):
        assert _should_fail(_result([Severity.CRITICAL]), "none") is False

    def test_critical_only_critical(self):
        assert _should_fail(_result([Severity.CRITICAL]), "critical") is True
        assert _should_fail(_result([Severity.HIGH]), "critical") is False
        assert _should_fail(_result([Severity.MODERATE]), "critical") is False
        assert _should_fail(_result([Severity.LOW]), "critical") is False

    def test_high_includes_critical(self):
        assert _should_fail(_result([Severity.CRITICAL]), "high") is True
        assert _should_fail(_result([Severity.HIGH]), "high") is True
        assert _should_fail(_result([Severity.MODERATE]), "high") is False
        assert _should_fail(_result([Severity.LOW]), "high") is False

    def test_moderate_includes_high_and_critical(self):
        assert _should_fail(_result([Severity.CRITICAL]), "moderate") is True
        assert _should_fail(_result([Severity.HIGH]), "moderate") is True
        assert _should_fail(_result([Severity.MODERATE]), "moderate") is True
        assert _should_fail(_result([Severity.LOW]), "moderate") is False

    def test_low_includes_all(self):
        assert _should_fail(_result([Severity.CRITICAL]), "low") is True
        assert _should_fail(_result([Severity.HIGH]), "low") is True
        assert _should_fail(_result([Severity.MODERATE]), "low") is True
        assert _should_fail(_result([Severity.LOW]), "low") is True

    def test_mixed_severities_highest_wins(self):
        result = _result([Severity.LOW, Severity.CRITICAL])
        assert _should_fail(result, "critical") is True
        assert _should_fail(result, "high") is True

    def test_mixed_severities_below_threshold(self):
        result = _result([Severity.LOW, Severity.MODERATE])
        assert _should_fail(result, "high") is False

    def test_empty_always_passes(self):
        empty = _empty_result()
        for level in ["critical", "high", "moderate", "low", "none", None]:
            assert _should_fail(empty, level) is False

    def test_info_severity_below_all(self):
        result = _result([Severity.INFO])
        assert _should_fail(result, "low") is False
        assert _should_fail(result, None) is True  # default: any ACTION


def _mock_cli(tmp_path, fail_on: str, severities: list[Severity]) -> int:
    """Run main() with mocked scan returning ACTION items at given severities."""
    mock_result = _result(severities)
    with (
        patch("depquiet.cli.scan", return_value=mock_result),
        patch("depquiet.cli.load_config") as mock_config,
        patch("depquiet.cli.load_policy", return_value=None),
        patch("depquiet.cli.load_ignore", return_value=None),
    ):
        mock_config.return_value.merge_cli.return_value = mock_config.return_value
        mock_config.return_value.epss_threshold = 0.1
        mock_config.return_value.offline = False
        mock_config.return_value.template_dirs = None
        mock_config.return_value.always_flag = None
        return main(["--path", str(tmp_path), "--json", "--fail-on", fail_on])


class TestCliIntegration:
    def test_fail_on_critical_passes_with_high(self, tmp_path):
        assert _mock_cli(tmp_path, "critical", [Severity.HIGH]) == 0

    def test_fail_on_critical_fails_with_critical(self, tmp_path):
        assert _mock_cli(tmp_path, "critical", [Severity.CRITICAL]) == 1

    def test_fail_on_none_always_passes(self, tmp_path):
        assert _mock_cli(tmp_path, "none", [Severity.CRITICAL, Severity.HIGH]) == 0
