"""Generate SPDX 2.3 SBOM from parsed lockfiles.

SPDX (Software Package Data Exchange) is the ISO/IEC 5962:2021 standard
for SBOM, required alongside CycloneDX by US EO 14028.  This module
produces SPDX 2.3 JSON documents from depquiet scan results.

Usage::

    depquiet --sbom sbom.spdx.json --sbom-format spdx

The SPDX document includes:
- All packages from detected lockfiles (or fallback from triage results)
- Known vulnerabilities as SECURITY external references
- Package URLs (purl) per the purl spec
- Tool metadata identifying depquiet as the creator
- DESCRIBES and DEPENDS_ON relationships
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from depquiet import __version__
from depquiet.assessment import assess_finding
from depquiet.component_refs import (
    ExportComponent,
    association_metadata,
    association_notes,
    component_inventory,
    finding_components,
)
from depquiet.models import ScanResult, TriageResult


def _spdx_id(name: str, version: str) -> str:
    """Build a valid SPDX identifier from a package name and version.

    SPDX identifiers must match [a-zA-Z0-9.-]+, so we replace any
    other characters with hyphens.
    """
    raw = f"SPDXRef-Package-{name}-{version}"
    return "".join(c if c.isalnum() or c in ".-" else "-" for c in raw)


def _verdict_to_annotation(tr: TriageResult, component: ExportComponent | None = None) -> str:
    """Record prioritization observations without asserting product impact."""
    parts = [assess_finding(tr).detail, association_notes(tr.vuln)]
    if tr.vuln.version_kind == "advisory_range" and component is not None:
        association = next(
            (item for item in finding_components(tr.vuln) if item.ref == component.ref), component
        )
        parts.append(
            "Advisory association: "
            + json.dumps(association_metadata(tr.vuln, association), sort_keys=True)
        )
    return " ".join(part for part in parts if part)


def generate_spdx_json(
    scan_result: ScanResult,
    packages: list[tuple[str, str, str]] | None = None,
) -> dict[str, Any]:
    """Generate an SPDX 2.3 JSON SBOM.

    Args:
        scan_result: The triage scan result.
        packages: Optional list of (name, version, ecosystem) from lockfile parsing.
                  If not provided, components are derived from the scan results.

    Returns:
        SPDX 2.3 JSON as a Python dict.
    """
    if not scan_result.scanned:
        raise ValueError("Cannot generate SPDX from an incomplete scan.")
    doc_uuid = str(uuid.uuid4())
    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    project_name = Path(scan_result.project_path).name or "unknown"
    doc_name = f"depquiet-{project_name}"

    # Build packages list
    spdx_packages: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []

    inventory = component_inventory(scan_result, packages)
    vuln_by_ref: dict[str, list[TriageResult]] = {}
    unassociated: list[TriageResult] = []
    for tr in scan_result.results:
        associated = finding_components(tr.vuln, inventory)
        for component in associated:
            vuln_by_ref.setdefault(component.ref, []).append(tr)
        if not associated:
            unassociated.append(tr)

    for component in inventory:
        name, version = component.package, component.version
        spdx_id = (
            "SPDXRef-" + component.ref.replace(":", "-")
            if component.evidence is not None
            else _spdx_id(name, version or "")
        )
        pkg_entry = _build_package_entry(
            spdx_id, name, version, component.purl, vuln_by_ref.get(component.ref, []), component
        )
        spdx_packages.append(pkg_entry)
        relationships.append(
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": spdx_id,
                "relationshipType": "DESCRIBES",
            }
        )

    doc: dict[str, Any] = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": doc_name,
        "documentNamespace": f"https://spdx.org/spdxdocs/{doc_name}-{doc_uuid}",
        "creationInfo": {
            "created": timestamp,
            "creators": [
                f"Tool: depquiet-{__version__}",
            ],
            "licenseListVersion": "3.22",
        },
        "packages": spdx_packages,
        "relationships": relationships,
    }
    if unassociated:
        doc["annotations"] = [
            {
                "annotationDate": timestamp,
                "annotationType": "OTHER",
                "annotator": f"Tool: depquiet-{__version__}",
                "comment": _verdict_to_annotation(tr),
            }
            for tr in unassociated
        ]

    return doc


def _build_package_entry(
    spdx_id: str,
    name: str,
    version: str | None,
    purl: str,
    triage_results: list[TriageResult],
    component: ExportComponent | None = None,
) -> dict[str, Any]:
    """Build a single SPDX package entry."""
    pkg: dict[str, Any] = {
        "SPDXID": spdx_id,
        "name": name,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            },
        ],
    }
    if version is not None:
        pkg["versionInfo"] = version
    if component is not None and component.provenance():
        pkg["comment"] = (
            "Lockfile candidate evidence; not an observed runtime installation: "
            + json.dumps(component.provenance(), sort_keys=True)
        )
    elif component is not None and version is None:
        pkg["comment"] = (
            "Version unresolved; no lockfile candidate or runtime installation established."
        )

    # Add SECURITY external refs for known CVEs
    cve_seen: set[str] = set()
    for tr in triage_results:
        cve = tr.vuln.cve
        if cve and cve not in cve_seen:
            cve_seen.add(cve)
            pkg["externalRefs"].append(
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "advisory",
                    "referenceLocator": tr.vuln.url or f"https://nvd.nist.gov/vuln/detail/{cve}",
                    "comment": _verdict_to_annotation(tr, component),
                }
            )

    return pkg


def write_spdx(
    scan_result: ScanResult,
    output_path: Path,
    packages: list[tuple[str, str, str]] | None = None,
) -> None:
    """Write SPDX 2.3 JSON SBOM to a file.

    Args:
        scan_result: Triage results.
        output_path: Where to write the SBOM.
        packages: Optional lockfile packages for component inventory.
    """
    doc = generate_spdx_json(scan_result, packages)
    output_path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
