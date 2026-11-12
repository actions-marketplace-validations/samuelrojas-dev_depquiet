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


# --- Displays and exports say "unknown"; GitHub levels fail safe -------------


def _with(verdict: Verdict) -> ScanResult:
    result = _result(known=False)
    result.results[0].verdict = verdict
    result.scanned = True
    return result


def test_sarif_marks_unknown_action_as_error_and_says_unknown() -> None:
    from depquiet.sarif import to_sarif

    run = to_sarif(_with(Verdict.ACTION))["runs"][0]
    (result,) = run["results"]
    assert result["level"] == "error"
    assert result["properties"]["severity"] == "unknown"
    assert run["tool"]["driver"]["rules"][0]["defaultConfiguration"]["level"] == "error"
    assert to_sarif(_with(Verdict.REVIEW))["runs"][0]["results"][0]["level"] == "warning"


def test_annotation_marks_unknown_action_as_failure() -> None:
    from depquiet.annotations import _finding_to_annotation

    annotation = _finding_to_annotation(_with(Verdict.ACTION).results[0], "uv.lock", ".")
    assert annotation.annotation_level == "failure"
    assert "UNKNOWN" in annotation.message and "MODERATE" not in annotation.message


def test_summary_and_label_say_unknown() -> None:
    from depquiet.summary import render_summary

    result = _with(Verdict.ACTION)
    assert result.results[0].vuln.severity_label == "unknown"
    assert "⚪ Unknown" in render_summary(result)


def test_sbom_never_writes_a_placeholder_rating() -> None:
    from depquiet.sbom import generate_cyclonedx_json

    doc = generate_cyclonedx_json(_with(Verdict.ACTION))
    ratings = [r["severity"] for v in doc.get("vulnerabilities", []) for r in v["ratings"]]
    assert ratings and set(ratings) == {"unknown"}
