"""OpenVEX document generation from depquiet triage results.

Generates VEX (Vulnerability Exploitability eXchange) documents following the
OpenVEX specification (https://openvex.dev).  A VEX document communicates the
status of vulnerabilities in a software product — which CVEs actually affect
it, which don't, and why.

depquiet's triage verdicts map naturally to VEX statuses:

    ACTION   → affected          (must be fixed)
    REVIEW   → under_investigation
    FILTERED → not_affected      (with machine-readable justification)

FilterReasons become VEX justifications:

    UNREACHABLE        → vulnerable_code_not_in_execute_path
    DEV_DEPENDENCY     → vulnerable_code_not_in_execute_path
    LOW_EPSS           → inline_mitigations_already_exist
    COMMUNITY_TEMPLATE → component_not_present
    IGNORED            → vulnerability_not_exploitable

The output conforms to the OpenVEX v0.2.0 specification and can be consumed
by policy engines (e.g. Sigstore policy-controller, OPA/Gatekeeper) to gate
container deployments or artifact promotion.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from depquiet.models import FilterReason, ScanResult, TriageResult, Verdict

# OpenVEX context URI — identifies the document format
_CONTEXT = "https://openvex.dev/ns/v0.2.0"

# Mapping from depquiet verdict to OpenVEX status
_STATUS_MAP: dict[str, str] = {
    Verdict.ACTION.value: "affected",
    Verdict.REVIEW.value: "under_investigation",
    Verdict.FILTERED.value: "not_affected",
}

# Mapping from FilterReason to OpenVEX justification (only for not_affected)
_JUSTIFICATION_MAP: dict[str, str] = {
    FilterReason.UNREACHABLE.value: "vulnerable_code_not_in_execute_path",
    FilterReason.DEV_DEPENDENCY.value: "vulnerable_code_not_in_execute_path",
    FilterReason.LOW_EPSS.value: "inline_mitigations_already_exist",
    FilterReason.COMMUNITY_TEMPLATE.value: "component_not_present",
    FilterReason.IGNORED.value: "vulnerability_not_exploitable",
}


@dataclass
class VexStatement:
    """A single VEX statement about one vulnerability in one product."""

    vulnerability_id: str
    status: str
    justification: str | None = None
    impact_statement: str | None = None
    # Product and subcomponent identifiers
    product_id: str = ""
    subcomponent_id: str = ""
    # Action statement for affected status
    action_statement: str | None = None


@dataclass
class VexDocument:
    """An OpenVEX document containing one or more statements."""

    doc_id: str
    author: str
    timestamp: str
    statements: list[VexStatement] = field(default_factory=list)
    tooling: str = ""
    # Counts for summary
    affected: int = 0
    under_investigation: int = 0
    not_affected: int = 0


def build_vex(
    result: ScanResult,
    *,
    author: str = "depquiet",
    product_id: str | None = None,
    timestamp: str | None = None,
) -> VexDocument:
    """Build an OpenVEX document from a ScanResult.

    Args:
        result: The triage scan result.
        author: Author identity for the VEX document.
        product_id: Package URL or product identifier.  Defaults to
            ``pkg:<manager>/<project_path>``.
        timestamp: ISO 8601 timestamp.  Defaults to now (UTC).

    Returns:
        A VexDocument ready for serialization.
    """
    if product_id is None:
        manager = result.package_manager or "generic"
        project = Path(result.project_path).name or "unknown"
        product_id = f"pkg:{manager}/{project}"

    ts = timestamp or datetime.now(UTC).isoformat()
    doc_id = f"https://openvex.dev/docs/{uuid.uuid4()}"

    statements: list[VexStatement] = []
    counts = {"affected": 0, "under_investigation": 0, "not_affected": 0}

    for tr in result.results:
        stmt = _triage_to_statement(tr, product_id)
        statements.append(stmt)
        status = _STATUS_MAP.get(tr.verdict.value, "under_investigation")
        counts[status] = counts.get(status, 0) + 1

    return VexDocument(
        doc_id=doc_id,
        author=author,
        timestamp=ts,
        statements=statements,
        tooling=f"depquiet/{_get_version()}",
        affected=counts["affected"],
        under_investigation=counts["under_investigation"],
        not_affected=counts["not_affected"],
    )


def _triage_to_statement(tr: TriageResult, product_id: str) -> VexStatement:
    """Convert a single TriageResult into a VEX statement."""
    status = _STATUS_MAP.get(tr.verdict.value, "under_investigation")

    justification: str | None = None
    impact_statement: str | None = None
    action_statement: str | None = None

    if status == "not_affected" and tr.reasons:
        # Use the first reason for the justification
        reason_value = tr.reasons[0].value
        justification = _JUSTIFICATION_MAP.get(reason_value)
        # Build a human-readable impact statement from all reasons
        impact_statement = _build_impact(tr)

    if status == "affected":
        action_statement = _build_action(tr)

    # Build purl-style subcomponent identifier
    subcomponent = f"pkg:generic/{tr.vuln.package}@{tr.vuln.version}"

    return VexStatement(
        vulnerability_id=tr.vuln.cve,
        status=status,
        justification=justification,
        impact_statement=impact_statement,
        product_id=product_id,
        subcomponent_id=subcomponent,
        action_statement=action_statement,
    )


def _build_impact(tr: TriageResult) -> str:
    """Build a human-readable impact statement for not_affected findings."""
    parts: list[str] = []
    for reason in tr.reasons:
        if reason == FilterReason.UNREACHABLE:
            parts.append("vulnerable code paths are not reachable in this project")
        elif reason == FilterReason.DEV_DEPENDENCY:
            parts.append("package is a development-only dependency")
        elif reason == FilterReason.LOW_EPSS:
            score = f" (EPSS: {tr.epss_score:.1%})" if tr.epss_score is not None else ""
            parts.append(f"low exploitation probability{score}")
        elif reason == FilterReason.COMMUNITY_TEMPLATE:
            parts.append("matched community suppression template")
        elif reason == FilterReason.IGNORED:
            parts.append("suppressed by project ignore rules")
    return "; ".join(parts) if parts else "filtered by depquiet triage"


def _build_action(tr: TriageResult) -> str:
    """Build an action statement for affected findings."""
    parts: list[str] = [f"Update {tr.vuln.package}"]
    if tr.vuln.fix_version:
        parts[0] += f" to {tr.vuln.fix_label}"
    parts[0] += "."
    if tr.epss_score is not None and tr.epss_score >= 0.1:
        parts.append(f"EPSS score: {tr.epss_score:.1%}.")
    if tr.kev_entry is not None:
        parts.append("Listed in the CISA Known Exploited Vulnerabilities catalog.")
    return " ".join(parts)


def vex_to_json(doc: VexDocument) -> dict[str, Any]:
    """Serialize a VexDocument to the OpenVEX JSON structure."""
    statements = []
    for stmt in doc.statements:
        s: dict[str, Any] = {
            "vulnerability": {"@id": stmt.vulnerability_id},
            "products": [
                {
                    "@id": stmt.product_id,
                    "subcomponents": [{"@id": stmt.subcomponent_id}],
                }
            ],
            "status": stmt.status,
        }
        if stmt.justification:
            s["justification"] = stmt.justification
        if stmt.impact_statement:
            s["impact_statement"] = stmt.impact_statement
        if stmt.action_statement:
            s["action_statement"] = stmt.action_statement
        statements.append(s)

    return {
        "@context": _CONTEXT,
        "@id": doc.doc_id,
        "author": doc.author,
        "timestamp": doc.timestamp,
        "tooling": doc.tooling,
        "statements": statements,
    }


def write_vex(doc: VexDocument, path: Path) -> None:
    """Write a VEX document to a JSON file."""
    data = vex_to_json(doc)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _get_version() -> str:
    """Get the depquiet version string."""
    try:
        from depquiet import __version__

        return __version__
    except ImportError:
        return "unknown"
