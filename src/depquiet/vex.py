"""OpenVEX document generation from depquiet triage results.

Generates VEX (Vulnerability Exploitability eXchange) documents following the
OpenVEX specification (https://openvex.dev).  A VEX document communicates the
status of vulnerabilities in a software product — which CVEs actually affect
it, which don't, and why.

Automatic statements remain ``under_investigation``. Prioritization and
import-level observations do not establish whether a product is affected.
Their evidence and limitations are recorded in ``status_notes`` instead.

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

from depquiet.assessment import assess_finding
from depquiet.component_refs import association_notes, finding_components
from depquiet.models import ScanResult, TriageResult

# OpenVEX context URI — identifies the document format
_CONTEXT = "https://openvex.dev/ns/v0.2.0"


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
    status_notes: str | None = None
    vulnerability_url: str = ""
    subcomponents: list[dict[str, Any]] = field(default_factory=list)


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
    version: int = 1


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
    if not result.scanned:
        raise ValueError("Cannot generate OpenVEX from an incomplete scan.")
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
        counts[stmt.status] = counts.get(stmt.status, 0) + 1

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
    if not tr.vuln.cve:
        raise ValueError("Cannot export a VEX finding without a vulnerability identifier.")
    assessment = assess_finding(tr)

    components = finding_components(tr.vuln)
    subcomponent = components[0].ref if components else ""
    notes = " ".join(part for part in (assessment.detail, association_notes(tr.vuln)) if part)

    return VexStatement(
        vulnerability_id=tr.vuln.cve,
        status=assessment.status,
        product_id=product_id,
        subcomponent_id=subcomponent,
        status_notes=notes,
        vulnerability_url=tr.vuln.url,
        subcomponents=(
            [
                {"@id": component.ref, "identifiers": {"purl": component.purl}}
                for component in components
            ]
            if tr.vuln.version_kind == "advisory_range"
            else []
        ),
    )


def vex_to_json(doc: VexDocument) -> dict[str, Any]:
    """Serialize a VexDocument to the OpenVEX JSON structure."""
    statements = []
    for stmt in doc.statements:
        product: dict[str, Any] = {"@id": stmt.product_id}
        if stmt.subcomponents:
            product["subcomponents"] = stmt.subcomponents
        elif stmt.subcomponent_id:
            product["subcomponents"] = [{"@id": stmt.subcomponent_id}]
        s: dict[str, Any] = {
            "vulnerability": {"name": stmt.vulnerability_id},
            "products": [product],
            "status": stmt.status,
        }
        if stmt.vulnerability_url:
            s["vulnerability"]["@id"] = stmt.vulnerability_url
        if stmt.justification:
            s["justification"] = stmt.justification
        if stmt.impact_statement:
            s["impact_statement"] = stmt.impact_statement
        if stmt.action_statement:
            s["action_statement"] = stmt.action_statement
        if stmt.status_notes:
            s["status_notes"] = stmt.status_notes
        statements.append(s)

    return {
        "@context": _CONTEXT,
        "@id": doc.doc_id,
        "author": doc.author,
        "timestamp": doc.timestamp,
        "version": doc.version,
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
