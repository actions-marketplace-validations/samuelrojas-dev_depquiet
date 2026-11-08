"""Keep dependency triage observations separate from product-impact claims.

The current engine inspects package imports, dependency paths and priority
signals. It does not establish a vulnerable-function call graph, observe
runtime execution, or validate a product-specific mitigation. Its automatic
assessments therefore remain under investigation, whatever the priority.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from depquiet.models import TriageResult

_LIMITATIONS = (
    "Dependency and import analysis does not prove vulnerable-function reachability "
    "or product impact.",
    "Priority, EPSS, development scope and user suppressions are not proof of non-affectedness.",
)


@dataclass(frozen=True)
class FindingAssessment:
    """A product-impact assessment supported by the current analysis scope."""

    status: str
    scope: str
    observations: tuple[str, ...]
    limitations: tuple[str, ...]

    @property
    def detail(self) -> str:
        return " ".join((*self.observations, *self.limitations))

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "scope": self.scope,
            "observations": list(self.observations),
            "limitations": list(self.limitations),
        }


def assess_finding(tr: TriageResult) -> FindingAssessment:
    """Describe available evidence without converting priority into impact."""
    observations = [
        f"Scanner reported {tr.vuln.cve} for {tr.vuln.package}@{tr.vuln.version}.",
        f"Priority: {tr.verdict.value}.",
    ]
    if tr.reasons:
        observations.append("Triage signals: " + ", ".join(r.value for r in tr.reasons) + ".")
    if tr.epss_score is not None:
        observations.append(f"Observed EPSS probability: {tr.epss_score:g}.")
    if tr.dependency_type:
        observations.append(f"Dependency classification: {tr.dependency_type}.")
    if tr.introduced_by:
        observations.append("Dependency roots: " + ", ".join(tr.introduced_by) + ".")
    observations.append(f"Dependency usage observation: {tr.evidence.usage}.")
    observations.extend(tr.evidence.observations)
    if tr.evidence.import_sites:
        observations.append("Import sites: " + ", ".join(tr.evidence.import_sites) + ".")
    if tr.template_id:
        observations.append(f"Template matched: {tr.template_id}.")
    if tr.kev_entry is not None:
        observations.append("The advisory is listed in the supplied KEV catalog.")
    for decision in tr.decision_trace:
        note = f"Decision by {decision.source}: {decision.verdict.value}"
        if decision.rule_id:
            note += f" ({decision.rule_id})"
        if decision.reason:
            note += f"; {decision.reason}"
        observations.append(note + ".")
    return FindingAssessment(
        status="under_investigation",
        scope="dependency_triage",
        observations=tuple(observations),
        limitations=_LIMITATIONS,
    )


def decision_trace_to_json(tr: TriageResult) -> list[dict[str, Any]]:
    """Serialize priority history without losing enum values or rule metadata."""
    return [
        {
            **asdict(change),
            "previous_verdict": change.previous_verdict.value if change.previous_verdict else None,
            "verdict": change.verdict.value,
        }
        for change in tr.decision_trace
    ]
