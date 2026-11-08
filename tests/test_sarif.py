"""SARIF retains triage context without asserting product impact."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from depquiet.models import (
    DecisionChange,
    DependencyEvidence,
    FilterReason,
    ScanResult,
    Severity,
    TriageResult,
    Verdict,
    Vulnerability,
)
from depquiet.sarif import to_sarif, write_sarif


@pytest.mark.parametrize("verdict", [Verdict.ACTION, Verdict.REVIEW])
def test_sarif_priority_keeps_uncertainty_evidence_and_policy_history(verdict: Verdict) -> None:
    finding = TriageResult(
        vuln=Vulnerability(
            cve="CVE-2024-12345", package="widget", version="1.0", severity=Severity.HIGH
        ),
        verdict=verdict,
        evidence=DependencyEvidence(usage="observed", import_sites=["app.js"]),
        decision_trace=[
            DecisionChange(
                source="policy",
                previous_verdict=Verdict.FILTERED,
                verdict=verdict,
                rule_id="review-widget",
                path=".depquiet-policy.yaml",
                reason="Team policy",
            )
        ],
        epss_score=0.1,
    )
    scan = ScanResult(".", "npm", 1, [finding])
    doc = json.loads(json.dumps(to_sarif(scan)))
    result = doc["runs"][0]["results"][0]
    props = result["properties"]
    assert props["assessment"]["status"] == "under_investigation"
    assert props["assessment"]["limitations"]
    assert props["evidence"]["usage"] == "observed"
    assert props["evidence"]["import_sites"] == ["app.js"]
    assert props["decision_trace"][0]["previous_verdict"] == "filtered"
    assert props["decision_trace"][0]["verdict"] == verdict.value
    assert props["decision_trace"][0]["rule_id"] == "review-widget"
    assert props["decision_trace"][0]["path"] == ".depquiet-policy.yaml"
    assert props["epss_score"] == 0.1
    assert "Product impact remains under investigation" in result["message"]["text"]


def test_filtered_findings_still_omitted_from_sarif() -> None:
    finding = TriageResult(
        vuln=Vulnerability(
            cve="CVE-2024-12345", package="widget", version="1.0", severity=Severity.HIGH
        ),
        verdict=Verdict.FILTERED,
        reasons=[FilterReason.LOW_EPSS],
        epss_score=0.001,
    )
    doc = to_sarif(ScanResult(".", "npm", 1, [finding]))
    assert doc["runs"][0]["results"] == []


def test_incomplete_scan_cannot_be_exported_as_empty_sarif(tmp_path: Path) -> None:
    scan = ScanResult(".", "osv", 0, [], scanned=False, note="OSV lookup failed.")
    with pytest.raises(ValueError, match="incomplete scan"):
        to_sarif(scan)
    target = tmp_path / "report.sarif"
    with pytest.raises(ValueError, match="incomplete scan"):
        write_sarif(scan, target)
    assert not target.exists()
