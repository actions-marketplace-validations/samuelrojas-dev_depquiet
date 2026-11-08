"""``depquiet explain`` — verdict explainer for a single CVE.

Shows exactly why a vulnerability received its verdict: every contributing
signal (EPSS score, reachability, dev-dependency status, template match,
KEV listing, policy override, ignore rule) laid out step-by-step so
developers and security teams can understand and audit triage decisions.

Works in two modes:

1. **Live** — runs a scan and explains the verdict for the given CVE.
2. **From JSON** — reads a previous ``depquiet --json`` output file.

Output is human-readable by default, or ``--json`` for machine consumption.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

from depquiet.assessment import assess_finding, decision_trace_to_json
from depquiet.kev import KevEntry
from depquiet.models import (
    DecisionChange,
    DependencyEvidence,
    FilterReason,
    ScanResult,
    TriageResult,
    Verdict,
)

# ---------------------------------------------------------------------------
# Explanation model
# ---------------------------------------------------------------------------


@dataclass
class Signal:
    """One contributing signal to the verdict."""

    name: str
    value: str
    effect: str  # "filtered", "escalated", "neutral", "not_applicable"
    detail: str = ""


@dataclass
class Explanation:
    """Full explanation for a CVE verdict."""

    cve: str
    package: str
    version: str
    severity: str
    title: str
    verdict: str
    reason_summary: str
    signals: list[Signal] = field(default_factory=list)
    fix_available: bool = False
    fix_version: str = ""
    assessment: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    decision_trace: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "cve": self.cve,
            "package": self.package,
            "version": self.version,
            "severity": self.severity,
            "title": self.title,
            "verdict": self.verdict,
            "reason_summary": self.reason_summary,
            "fix_available": self.fix_available,
            "fix_version": self.fix_version,
            "signals": [asdict(s) for s in self.signals],
            "assessment": self.assessment,
            "evidence": self.evidence,
            "decision_trace": self.decision_trace,
        }
        return d


# ---------------------------------------------------------------------------
# Explain logic
# ---------------------------------------------------------------------------


def explain_triage(tr: TriageResult) -> Explanation:
    """Build an Explanation from a TriageResult."""
    signals: list[Signal] = []

    # 1. EPSS score
    if tr.epss_score is not None:
        pct = tr.epss_score * 100
        if FilterReason.LOW_EPSS in tr.reasons:
            effect = "filtered"
            detail = "Below threshold — low probability of exploitation"
        elif pct >= 50:
            effect = "escalated"
            detail = "High probability of exploitation"
        else:
            effect = "neutral"
            detail = "Above threshold"
        signals.append(
            Signal(
                name="EPSS score",
                value=f"{pct:.1f}%",
                effect=effect,
                detail=detail,
            )
        )
    else:
        signals.append(
            Signal(
                name="EPSS score",
                value="unavailable",
                effect="not_applicable",
                detail="EPSS lookup was skipped or failed",
            )
        )

    # 2. Reachability
    via = ", ".join(tr.introduced_by)
    if tr.reachable_imports:
        imports = ", ".join(tr.reachable_imports)
        detail = f"Imported by: {imports}"
        if tr.dependency_type == "transitive" and via:
            detail = f"Transitive, pulled in by {via}. Entry points: {imports}"
        signals.append(
            Signal(
                name="Reachability",
                value="reachable",
                effect="escalated",
                detail=detail,
            )
        )
    elif FilterReason.UNREACHABLE in tr.reasons:
        detail = "No package usage was observed in inspected project sources"
        if tr.dependency_type == "transitive" and via:
            detail = f"Transitive; none of the packages that pull it in are imported ({via})"
        signals.append(
            Signal(
                name="Reachability",
                value="unreachable",
                effect="filtered",
                detail=detail,
            )
        )
    elif tr.dependency_type == "unknown":
        signals.append(
            Signal(
                name="Reachability",
                value="unknown",
                effect="neutral",
                detail=(
                    "No manifest or lockfile says whether this package is direct or "
                    "transitive, so it was not filtered on reachability"
                ),
            )
        )
    elif tr.dependency_type == "transitive":
        detail = "Transitive dependency"
        detail += f", pulled in by {via}" if via else "; no lockfile path to a direct dependency"
        signals.append(
            Signal(
                name="Reachability",
                value="transitive",
                effect="neutral",
                detail=detail + ". Not filtered on reachability",
            )
        )
    else:
        signals.append(
            Signal(
                name="Reachability",
                value="unknown",
                effect="neutral",
                detail="Reachability analysis did not run or was inconclusive",
            )
        )

    # 3. Dev dependency
    if tr.vuln.is_dev or FilterReason.DEV_DEPENDENCY in tr.reasons:
        effect = "filtered" if FilterReason.DEV_DEPENDENCY in tr.reasons else "neutral"
        detail = "Development dependency metadata; deployment contents were not verified"
        if not tr.vuln.is_dev and tr.introduced_by:
            detail = f"Only pulled in by devDependencies ({', '.join(tr.introduced_by)})"
        signals.append(
            Signal(
                name="Dependency type",
                value="devDependency",
                effect=effect,
                detail=detail,
            )
        )
    else:
        signals.append(
            Signal(
                name="Dependency type",
                value="production",
                effect="neutral",
                detail="Not marked development-only by available metadata",
            )
        )

    # 4. Community template match
    if tr.template_id is not None:
        signals.append(
            Signal(
                name="Community template",
                value=tr.template_id,
                effect="filtered" if FilterReason.COMMUNITY_TEMPLATE in tr.reasons else "neutral",
                detail=tr.template_reason or "Matched a known-benign pattern",
            )
        )

    # 5. KEV catalog
    if tr.kev_entry is not None:
        signals.append(
            Signal(
                name="CISA KEV",
                value="listed",
                effect="escalated",
                detail=f"Added {tr.kev_entry.date_added}, due {tr.kev_entry.due_date}",
            )
        )
    else:
        signals.append(
            Signal(
                name="CISA KEV",
                value="not listed",
                effect="neutral",
            )
        )

    # 6. Ignore rule
    if FilterReason.IGNORED in tr.reasons:
        signals.append(
            Signal(
                name="Ignore rule",
                value="suppressed",
                effect="filtered",
                detail="Matched an entry in the ignore file",
            )
        )

    return Explanation(
        cve=tr.vuln.cve,
        package=tr.vuln.package,
        version=tr.vuln.version,
        severity=tr.vuln.severity.value,
        title=tr.vuln.title,
        verdict=tr.verdict.value,
        reason_summary=tr.reason_summary,
        signals=signals,
        fix_available=bool(tr.vuln.fix_version),
        fix_version=tr.vuln.fix_label,
        assessment=assess_finding(tr).to_dict(),
        evidence=asdict(tr.evidence),
        decision_trace=decision_trace_to_json(tr),
    )


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------


def find_cve(result: ScanResult, cve_id: str) -> TriageResult | None:
    """Find a TriageResult by CVE ID (case-insensitive)."""
    target = cve_id.upper()
    for tr in result.results:
        if tr.vuln.cve.upper() == target:
            return tr
    return None


def find_cve_in_json(data: dict[str, Any], cve_id: str) -> TriageResult | None:
    """Find a CVE in a depquiet --json output dict.

    Reconstructs a minimal TriageResult from the JSON shape for explain.
    """
    from depquiet.models import Severity, Vulnerability

    target = cve_id.upper()
    for entry in data.get("results", []):
        if entry.get("cve", "").upper() == target:
            vuln = Vulnerability(
                cve=entry["cve"],
                package=entry.get("package", ""),
                version=entry.get("version", ""),
                severity=Severity.from_str(entry.get("severity", "moderate")),
                title=entry.get("title", ""),
                fix_version=entry.get("fix_version", ""),
                fix_package=entry.get("fix_package", ""),
                is_dev=entry.get("is_dev", "dev_dependency" in entry.get("reasons", [])),
                is_direct=entry.get("is_direct", True),
            )
            reasons = [
                FilterReason(r)
                for r in entry.get("reasons", [])
                if r in FilterReason._value2member_map_
            ]
            raw_evidence = entry.get("evidence") or {}
            evidence = DependencyEvidence(
                analysis=raw_evidence.get("analysis", "dependency_imports"),
                usage=raw_evidence.get("usage", "unknown"),
                import_sites=raw_evidence.get("import_sites", []),
                observations=raw_evidence.get("observations", []),
            )
            trace = [
                DecisionChange(
                    source=change["source"],
                    previous_verdict=(
                        Verdict(change["previous_verdict"])
                        if change.get("previous_verdict")
                        else None
                    ),
                    verdict=Verdict(change["verdict"]),
                    rule_id=change.get("rule_id", ""),
                    reason=change.get("reason", ""),
                    path=change.get("path", ""),
                    author=change.get("author", ""),
                    expires=change.get("expires", ""),
                )
                for change in entry.get("decision_trace", [])
            ]
            raw_kev = entry.get("kev")
            kev_entry = None
            if raw_kev:
                kev_entry = KevEntry(
                    cve_id=vuln.cve,
                    vendor=raw_kev.get("vendor", ""),
                    product=raw_kev.get("product", ""),
                    name=raw_kev.get("name", ""),
                    description=raw_kev.get("description", ""),
                    date_added=raw_kev.get("date_added", ""),
                    due_date=raw_kev.get("due_date", ""),
                    required_action=raw_kev.get("required_action", ""),
                    ransomware_use=raw_kev.get("ransomware_use", False),
                )
            return TriageResult(
                vuln=vuln,
                verdict=Verdict(entry.get("verdict", "review")),
                reasons=reasons,
                epss_score=entry.get("epss_score"),
                epss_percentile=entry.get("epss_percentile"),
                reachable_imports=entry.get("reachable_imports", []),
                dependency_type=entry.get("dependency_type", ""),
                introduced_by=entry.get("introduced_by", []),
                template_id=entry.get("template_id"),
                template_reason=entry.get("template_reason"),
                evidence=evidence,
                decision_trace=trace,
                kev_entry=kev_entry,
            )
    return None


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

_EFFECT_ICONS = {
    "filtered": "  ↓ ",
    "escalated": "  ↑ ",
    "neutral": "  · ",
    "not_applicable": "  - ",
}

_VERDICT_ICONS = {
    "action": "🔴",
    "review": "🟡",
    "filtered": "🟢",
}


def format_explanation(exp: Explanation) -> str:
    """Format an Explanation as a human-readable string."""
    lines: list[str] = []

    icon = _VERDICT_ICONS.get(exp.verdict, "·")
    lines.append(f"{icon} {exp.cve} — {exp.title}")
    lines.append(f"   Package: {exp.package}@{exp.version}")
    lines.append(f"   Severity: {exp.severity.upper()}")
    lines.append(f"   Verdict: {exp.verdict.upper()} ({exp.reason_summary})")
    if exp.assessment:
        status = exp.assessment.get("status", "under_investigation").replace("_", " ")
        lines.append(f"   Product impact: {status} (dependency-level analysis)")

    if exp.fix_available:
        lines.append(f"   Fix: upgrade to {exp.fix_version}")

    lines.append("")
    lines.append("   Signals:")

    for sig in exp.signals:
        icon_str = _EFFECT_ICONS.get(sig.effect, "  · ")
        line = f"{icon_str}{sig.name}: {sig.value}"
        if sig.detail:
            line += f" — {sig.detail}"
        lines.append(line)

    if exp.decision_trace:
        lines.append("")
        lines.append("   Decision history:")
        for change in exp.decision_trace:
            previous = change.get("previous_verdict") or "unassigned"
            detail = change.get("reason") or change.get("rule_id") or ""
            lines.append(
                f"   {change['source']}: {previous} -> {change['verdict']} {detail}".rstrip()
            )

    lines.append("")
    return "\n".join(lines)


def format_explanation_json(exp: Explanation) -> str:
    """Format an Explanation as JSON."""
    return json.dumps(exp.to_dict(), indent=2)
