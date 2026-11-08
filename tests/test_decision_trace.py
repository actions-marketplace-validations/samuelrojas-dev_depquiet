"""Suppression and escalation history survives subsequent priority changes."""

from __future__ import annotations

from datetime import date
from pathlib import Path

from depquiet.baseline import apply_baseline
from depquiet.cli import _should_fail
from depquiet.ignore import IgnoreEntry, IgnoreFile, apply_ignores
from depquiet.kev import KevCatalog, KevEntry, apply_kev
from depquiet.models import (
    DecisionChange,
    FilterReason,
    ScanResult,
    Severity,
    TriageResult,
    Verdict,
    Vulnerability,
)
from depquiet.policy import load_policy


def _scan(verdict: Verdict = Verdict.ACTION) -> ScanResult:
    return ScanResult(
        project_path=".",
        package_manager="npm",
        total_dependencies=1,
        results=[
            TriageResult(
                vuln=Vulnerability(
                    cve="CVE-2024-12345", package="widget", version="1.0", severity=Severity.HIGH
                ),
                verdict=verdict,
            )
        ],
    )


def _kev() -> KevCatalog:
    entry = KevEntry(
        cve_id="CVE-2024-12345",
        vendor="Example",
        product="Widget",
        name="Widget command injection",
        date_added="2024-01-01",
        due_date="2024-01-15",
        required_action="Apply vendor updates.",
        ransomware_use=False,
    )
    return KevCatalog(entries={entry.cve_id: entry})


def test_ignore_then_kev_retains_complete_history_and_gates() -> None:
    result = _scan()
    finding = result.results[0]
    prior = DecisionChange(
        source="policy",
        previous_verdict=Verdict.FILTERED,
        verdict=Verdict.ACTION,
        rule_id="flag-widget",
    )
    finding.decision_trace.append(prior)
    finding.reasons.append(FilterReason.LOW_EPSS)
    finding.reachable_imports = ["app.js"]
    ignore = IgnoreFile(
        path=".depquiet-ignore",
        entries=[
            IgnoreEntry(
                cve=finding.vuln.cve,
                package=finding.vuln.package,
                reason="Risk accepted during migration.",
                author="security-team",
                expires=date(2099, 12, 31),
            )
        ],
    )
    assert _should_fail(result, "high")
    assert apply_ignores(result, ignore) is result
    assert not _should_fail(result, "high")
    suppressed = finding.decision_trace[-1]
    assert suppressed == DecisionChange(
        source="ignore",
        previous_verdict=Verdict.ACTION,
        verdict=Verdict.FILTERED,
        rule_id="CVE-2024-12345:widget",
        reason="Risk accepted during migration.",
        path=".depquiet-ignore",
        author="security-team",
        expires="2099-12-31",
    )

    apply_ignores(result, ignore)
    assert finding.decision_trace == [prior, suppressed]
    stats = apply_kev(result, _kev())
    assert stats.escalated == 1
    assert _should_fail(result, "high")
    assert finding.reasons == [FilterReason.LOW_EPSS, FilterReason.IGNORED]
    assert finding.reachable_imports == ["app.js"]
    assert finding.decision_trace[:2] == [prior, suppressed]
    assert finding.decision_trace[-1].source == "kev"
    assert finding.decision_trace[-1].previous_verdict == Verdict.FILTERED
    assert finding.decision_trace[-1].verdict == Verdict.ACTION
    assert finding.decision_trace[-1].rule_id == finding.vuln.cve

    apply_kev(result, _kev())
    assert len(finding.decision_trace) == 3


def test_baseline_records_source_and_matching_scope_without_rewriting_evidence() -> None:
    result = _scan(Verdict.REVIEW)
    finding = result.results[0]
    prior = DecisionChange(source="triage", previous_verdict=None, verdict=Verdict.REVIEW)
    finding.decision_trace.append(prior)
    finding.reasons = [FilterReason.LOW_EPSS]
    finding.reachable_imports = ["app.js"]

    stats = apply_baseline(
        result, {finding.vuln.key}, source_path="security/accepted-findings.json"
    )
    assert stats.known_findings == 1
    assert finding.decision_trace[0] is prior
    assert finding.decision_trace[-1] == DecisionChange(
        source="baseline",
        previous_verdict=Verdict.REVIEW,
        verdict=Verdict.FILTERED,
        rule_id="CVE-2024-12345:widget",
        reason="Finding matches the accepted baseline by advisory and package.",
        path="security/accepted-findings.json",
    )
    assert finding.reasons == [FilterReason.LOW_EPSS]
    assert finding.reachable_imports == ["app.js"]

    stats = apply_baseline(result, {finding.vuln.key}, source_path="different.json")
    assert stats.known_findings == 0
    assert len(finding.decision_trace) == 2


def test_nonmatching_and_expired_suppressions_do_not_claim_a_decision() -> None:
    result = _scan()
    finding = result.results[0]
    ignore = IgnoreFile(
        entries=[
            IgnoreEntry(cve=finding.vuln.cve, reason="Expired", expires=date(2000, 1, 1)),
            IgnoreEntry(cve="CVE-OTHER", reason="Unrelated"),
        ]
    )
    apply_ignores(result, ignore)
    apply_baseline(result, {"CVE-OTHER:widget"})
    apply_kev(result, KevCatalog(entries={}))
    assert finding.verdict == Verdict.ACTION
    assert finding.decision_trace == []
    assert finding.reasons == []


def test_ignore_after_prior_escalation_does_not_duplicate_reason() -> None:
    result = _scan()
    finding = result.results[0]
    finding.reasons = [FilterReason.IGNORED]
    apply_ignores(result, IgnoreFile(entries=[IgnoreEntry(package="widget", reason="Accepted")]))
    assert finding.reasons == [FilterReason.IGNORED]
    assert finding.decision_trace[-1].rule_id == "widget"


def test_policy_source_and_reason_survive_loading(tmp_path: Path) -> None:
    policy_path = tmp_path / "accepted-risk.yaml"
    policy_path.write_text(
        "rules:\n"
        "  - id: accepted-widget\n"
        "    match:\n"
        "      packages: [widget]\n"
        "    action: filter\n"
        "    reason: Migration ticket SEC-123\n"
        "    description: Temporary acceptance\n",
        encoding="utf-8",
    )
    policy = load_policy(tmp_path, policy_path=policy_path)
    assert policy is not None
    assert policy.path == str(policy_path)
    assert policy.rules[0].reason == "Migration ticket SEC-123"
    assert policy.rules[0].description == "Temporary acceptance"
    finding = _scan().results[0]
    assert policy.apply(finding) == (Verdict.FILTERED, "accepted-widget")
    assert finding.verdict == Verdict.ACTION
    assert finding.decision_trace == []
