"""Priority decisions and observed usage must never certify product impact."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import pytest

from depquiet.assessment import assess_finding
from depquiet.baseline import apply_baseline
from depquiet.cli import _print_json, _should_fail
from depquiet.engine import scan
from depquiet.explain import explain_triage, find_cve_in_json, format_explanation
from depquiet.kev import KevCatalog, KevEntry, apply_kev
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
from depquiet.policy import Policy, PolicyRule


def _audit(severity: str = "high", package: str = "library") -> dict:
    return {
        "vulnerabilities": {
            package: {
                "severity": severity,
                "isDirect": True,
                "via": [
                    {"title": "Controlled case", "url": "https://github.com/advisories/TEST-1"}
                ],
            }
        }
    }


def _project(path: Path, package: str = "library", source: str | None = None) -> None:
    (path / "package.json").write_text(
        json.dumps({"dependencies": {package: "1.0.0"}}), encoding="utf-8"
    )
    (path / "app.js").write_text(source or f"require('{package}');\n", encoding="utf-8")


@pytest.mark.parametrize("verdict", list(Verdict))
@pytest.mark.parametrize("reason", [None, *FilterReason])
def test_priority_and_filter_signals_do_not_prove_impact(verdict, reason) -> None:
    finding = TriageResult(
        Vulnerability("TEST-1", "library", "1.0.0", Severity.HIGH),
        verdict,
        reasons=[reason] if reason else [],
        epss_score=0.001,
    )
    assessment = assess_finding(finding)
    assert assessment.status == "under_investigation"
    assert assessment.limitations
    assert f"Priority: {verdict.value}." in assessment.detail
    assert finding.verdict == verdict


@pytest.mark.parametrize("severity", ["high", "low"])
def test_engine_collects_usage_for_action_and_review(tmp_path: Path, severity: str) -> None:
    _project(tmp_path)
    finding = scan(tmp_path, audit_json=_audit(severity), skip_epss=True).results[0]
    assert finding.evidence.usage == "observed"
    assert finding.evidence.import_sites == [str(tmp_path / "app.js")]
    assert finding.reachable_imports == finding.evidence.import_sites
    assert finding.decision_trace[0].source == "engine"
    assert assess_finding(finding).status == "under_investigation"


def test_policy_and_baseline_preserve_observed_evidence(tmp_path: Path) -> None:
    _project(tmp_path)
    policy = Policy(
        rules=[PolicyRule("accepted-risk", Verdict.FILTERED, reason="Investigate next sprint")],
        path=".depquiet-policy.yaml",
    )
    result = scan(tmp_path, audit_json=_audit(), skip_epss=True, policy=policy)
    finding = result.results[0]
    assert finding.verdict == Verdict.FILTERED
    assert finding.evidence.usage == "observed"
    assert [event.source for event in finding.decision_trace] == ["engine", "policy"]
    assert finding.decision_trace[-1].rule_id == "accepted-risk"
    assert finding.decision_trace[-1].path == ".depquiet-policy.yaml"
    assert "Investigate next sprint" in assess_finding(finding).detail
    assert _should_fail(result, "high") is False

    unsuppressed = scan(tmp_path, audit_json=_audit(), skip_epss=True)
    apply_baseline(unsuppressed, {"TEST-1:library"}, source_path="baseline.json")
    assert unsuppressed.results[0].evidence == finding.evidence
    assert assess_finding(unsuppressed.results[0]).status == "under_investigation"


def test_command_references_are_not_invented_import_locations(tmp_path: Path) -> None:
    _project(tmp_path, source="console.log('ready');\n")
    manifest = json.loads((tmp_path / "package.json").read_text())
    manifest["scripts"] = {"start": "library serve"}
    (tmp_path / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    finding = scan(tmp_path, audit_json=_audit(), skip_epss=True).results[0]
    assert finding.evidence.usage == "observed"
    assert finding.reachable_imports == []
    assert finding.evidence.import_sites == []
    assert any("commands" in note for note in finding.evidence.observations)


def test_always_flag_records_decision_without_manufacturing_usage(tmp_path: Path) -> None:
    _project(tmp_path, source="console.log('ready');\n")
    finding = scan(tmp_path, audit_json=_audit(), skip_epss=True, always_flag=["library"]).results[
        0
    ]
    assert finding.verdict == Verdict.ACTION
    assert finding.evidence.usage == "not_observed"
    assert finding.decision_trace[0].source == "always_flag"
    assert assess_finding(finding).status == "under_investigation"


def test_json_and_explain_round_trip_evidence_and_decision_history(capsys) -> None:
    finding = TriageResult(
        Vulnerability("TEST-1", "library", "1.0", Severity.HIGH),
        Verdict.FILTERED,
        reasons=[FilterReason.LOW_EPSS],
        epss_score=0.001,
        epss_percentile=0.1,
        template_id="custom-rule",
        template_reason="Accepted risk",
        evidence=DependencyEvidence(
            usage="observed", import_sites=["app.js"], observations=["Import observed."]
        ),
        decision_trace=[DecisionChange("engine", None, Verdict.FILTERED, reason="low_epss")],
    )
    result = ScanResult("project", "npm", 1, [finding])
    apply_baseline(result, {finding.vuln.key})
    kev = KevEntry("TEST-1", "vendor", "product", "name", "2026-01-01", "2026-01-20", "Fix", False)
    apply_kev(result, KevCatalog({"TEST-1": kev}))
    _print_json(result)
    report = json.loads(capsys.readouterr().out)
    assert report["scanned"] is True
    row = report["results"][0]
    assert row["assessment"]["status"] == "under_investigation"
    assert [event["source"] for event in row["decision_trace"]] == ["engine", "kev"]
    restored = find_cve_in_json(report, "TEST-1")
    assert restored is not None
    assert asdict(restored.evidence) == asdict(finding.evidence)
    assert restored.decision_trace == finding.decision_trace
    assert restored.epss_percentile == 0.1
    assert restored.template_id == "custom-rule"
    assert restored.kev_entry == kev
    explanation = explain_triage(restored)
    assert explanation.assessment["status"] == "under_investigation"
    assert explanation.decision_trace == row["decision_trace"]
    assert "Decision history:" in format_explanation(explanation)


def test_old_json_defaults_to_unverified_assessment() -> None:
    finding = find_cve_in_json(
        {"results": [{"cve": "TEST-1", "verdict": "filtered", "reasons": []}]}, "TEST-1"
    )
    assert finding is not None
    assert finding.evidence.usage == "unknown"
    assert finding.decision_trace == []
    assert assess_finding(finding).status == "under_investigation"
