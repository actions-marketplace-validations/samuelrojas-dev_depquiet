"""A scanner that reports no severity must not slip past a severity gate.

pip-audit and uv audit carry no severity, so their findings hold a placeholder
("moderate"). Before this, ``--fail-on high`` passed a build with every
Python ACTION alert, critical or not.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from depquiet.cli import _should_fail
from depquiet.models import ScanResult, Severity, TriageResult, Verdict, Vulnerability
from depquiet.parsers.pip import PipAuditParser
from depquiet.parsers.uv import UvAuditParser


def _result(*, known: bool, severity: Severity = Severity.MODERATE) -> ScanResult:
    vuln = Vulnerability(
        cve="PYSEC-1",
        package="werkzeug",
        version="3.1.0",
        severity=severity,
        severity_known=known,
    )
    return ScanResult(
        project_path=".",
        package_manager="pip",
        total_dependencies=1,
        results=[TriageResult(vuln=vuln, verdict=Verdict.ACTION)],
    )


@pytest.mark.parametrize("threshold", ["high", "critical", "moderate", "low"])
def test_unknown_severity_meets_any_threshold(threshold: str, capsys) -> None:
    assert _should_fail(_result(known=False), threshold) is True
    assert "without a severity" in capsys.readouterr().err


def test_known_severity_is_still_compared() -> None:
    assert _should_fail(_result(known=True), "high") is False
    assert _should_fail(_result(known=True, severity=Severity.CRITICAL), "high") is True


def test_fail_on_none_still_never_fails() -> None:
    assert _should_fail(_result(known=False), "none") is False


def test_pip_audit_findings_have_no_known_severity() -> None:
    report = {
        "dependencies": [
            {
                "name": "werkzeug",
                "version": "3.1.0",
                "vulns": [{"id": "PYSEC-1", "fix_versions": ["3.1.4"], "aliases": []}],
            }
        ]
    }
    vulns = PipAuditParser.parse(report, Path("."))
    assert vulns and not vulns[0].severity_known


def test_uv_audit_findings_have_no_known_severity() -> None:
    fixture = Path(__file__).parent / "fixtures" / "uv_audit_saleor.json"
    vulns = UvAuditParser.parse(json.loads(fixture.read_text(encoding="utf-8")), Path("."))
    assert vulns and not any(v.severity_known for v in vulns)
