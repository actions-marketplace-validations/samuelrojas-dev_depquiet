"""Tests for the auto-remediation engine."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from depquiet.fix import FixReport, FixResult, apply_fixes, find_fixable, print_fix_report
from depquiet.models import ScanResult, Severity, TriageResult, Verdict, Vulnerability

# -- Fixtures --


def _vuln(
    cve: str = "CVE-2024-1234",
    package: str = "lodash",
    version: str = "4.17.20",
    severity: Severity = Severity.HIGH,
    fix_version: str = "4.17.21",
) -> Vulnerability:
    return Vulnerability(
        cve=cve,
        package=package,
        version=version,
        severity=severity,
        fix_version=fix_version,
    )


def _tr(
    vuln: Vulnerability | None = None,
    verdict: Verdict = Verdict.ACTION,
) -> TriageResult:
    return TriageResult(vuln=vuln or _vuln(), verdict=verdict)


def _scan_result(
    results: list[TriageResult] | None = None,
    pm: str = "npm",
) -> ScanResult:
    return ScanResult(
        project_path="/tmp/test",
        package_manager=pm,
        total_dependencies=10,
        results=results or [],
    )


# -- find_fixable --


class TestFindFixable:
    def test_returns_action_items_with_fix_version(self):
        results = [
            _tr(_vuln(fix_version="4.17.21"), verdict=Verdict.ACTION),
            _tr(_vuln(package="express", fix_version=""), verdict=Verdict.ACTION),
            _tr(_vuln(package="react", fix_version="18.0.1"), verdict=Verdict.FILTERED),
        ]
        fixable = find_fixable(_scan_result(results))
        assert len(fixable) == 1
        assert fixable[0].vuln.package == "lodash"

    def test_deduplicates_same_package_version(self):
        v = _vuln(fix_version="4.17.21")
        results = [
            _tr(v, verdict=Verdict.ACTION),
            _tr(
                _vuln(cve="CVE-2024-9999", fix_version="4.17.21"),
                verdict=Verdict.ACTION,
            ),
        ]
        fixable = find_fixable(_scan_result(results))
        assert len(fixable) == 1

    def test_empty_results(self):
        assert find_fixable(_scan_result([])) == []


# -- apply_fixes --


class TestApplyFixes:
    def test_dry_run_reports_without_running(self):
        results = [_tr(_vuln(fix_version="4.17.21"), verdict=Verdict.ACTION)]
        report = apply_fixes(_scan_result(results), Path("/tmp"), dry_run=True)
        assert len(report.fixed) == 1
        assert "Would run" in report.fixed[0].message
        assert "npm install lodash@4.17.21" in report.fixed[0].message

    def test_dry_run_pip(self):
        results = [_tr(_vuln(package="requests", fix_version="2.32.0"), verdict=Verdict.ACTION)]
        report = apply_fixes(_scan_result(results, pm="pip"), Path("/tmp"), dry_run=True)
        assert "pip install requests==2.32.0" in report.fixed[0].message

    def test_no_fixable_returns_empty_report(self):
        results = [_tr(_vuln(fix_version=""), verdict=Verdict.ACTION)]
        report = apply_fixes(_scan_result(results), Path("/tmp"), dry_run=True)
        assert len(report.fixed) == 0
        assert len(report.skipped) == 1

    def test_successful_fix(self):
        results = [_tr(_vuln(fix_version="4.17.21"), verdict=Verdict.ACTION)]
        with patch("depquiet.fix.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            report = apply_fixes(_scan_result(results), Path("/tmp"))
        assert len(report.fixed) == 1
        assert report.fixed[0].success

    def test_failed_fix(self):
        results = [_tr(_vuln(fix_version="4.17.21"), verdict=Verdict.ACTION)]
        with patch("depquiet.fix.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1
            mock_run.return_value.stderr = "ERESOLVE could not resolve"
            report = apply_fixes(_scan_result(results), Path("/tmp"))
        assert len(report.failed) == 1
        assert not report.failed[0].success

    def test_command_not_found(self):
        results = [_tr(_vuln(fix_version="4.17.21"), verdict=Verdict.ACTION)]
        with patch("depquiet.fix.subprocess.run", side_effect=FileNotFoundError):
            report = apply_fixes(_scan_result(results), Path("/tmp"))
        assert len(report.failed) == 1
        assert "not found" in report.failed[0].message

    def test_command_timeout(self):
        import subprocess

        results = [_tr(_vuln(fix_version="4.17.21"), verdict=Verdict.ACTION)]
        with patch(
            "depquiet.fix.subprocess.run", side_effect=subprocess.TimeoutExpired("npm", 120)
        ):
            report = apply_fixes(_scan_result(results), Path("/tmp"))
        assert len(report.failed) == 1
        assert "timed out" in report.failed[0].message

    def test_skipped_items_no_fix_version(self):
        results = [
            _tr(_vuln(fix_version="4.17.21"), verdict=Verdict.ACTION),
            _tr(
                _vuln(package="express", cve="CVE-2024-9999", fix_version=""),
                verdict=Verdict.ACTION,
            ),
        ]
        with patch("depquiet.fix.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            report = apply_fixes(_scan_result(results), Path("/tmp"))
        assert len(report.fixed) == 1
        assert len(report.skipped) == 1
        assert report.skipped[0].package == "express"


# -- FixReport --


class TestFixReport:
    def test_total_fixable(self):
        report = FixReport(
            fixed=[
                FixResult("a", "1.0", "2.0", "CVE-1", True),
            ],
            failed=[
                FixResult("b", "1.0", "2.0", "CVE-2", False),
            ],
        )
        assert report.total_fixable == 2


# -- print_fix_report --


class TestPrintFixReport:
    def test_prints_fixed(self, capsys):
        report = FixReport(fixed=[FixResult("lodash", "4.17.20", "4.17.21", "CVE-2024-1234", True)])
        print_fix_report(report)
        captured = capsys.readouterr()
        assert "Fixed 1" in captured.err
        assert "lodash" in captured.err

    def test_prints_dry_run_prefix(self, capsys):
        report = FixReport(fixed=[FixResult("lodash", "4.17.20", "4.17.21", "CVE-2024-1234", True)])
        print_fix_report(report, dry_run=True)
        captured = capsys.readouterr()
        assert "[dry-run]" in captured.err

    def test_prints_failed(self, capsys):
        report = FixReport(
            failed=[FixResult("lodash", "4.17.20", "4.17.21", "CVE-2024-1234", False, "error")]
        )
        print_fix_report(report)
        captured = capsys.readouterr()
        assert "Failed" in captured.err

    def test_prints_skipped(self, capsys):
        report = FixReport(
            skipped=[FixResult("express", "4.0.0", "", "CVE-2024-9999", False, "No fix version")]
        )
        print_fix_report(report)
        captured = capsys.readouterr()
        assert "no fix available" in captured.err

    def test_empty_report_prints_nothing(self, capsys):
        print_fix_report(FixReport())
        captured = capsys.readouterr()
        assert captured.err == ""
