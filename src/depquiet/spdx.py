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
from depquiet.models import ScanResult, TriageResult
from depquiet.sbom import _components_with_references


def _spdx_id(name: str, version: str) -> str:
    """Build a valid SPDX identifier from a package name and version.

    SPDX identifiers must match [a-zA-Z0-9.-]+, so we replace any
    other characters with hyphens.
    """
    raw = f"SPDXRef-Package-{name}-{version}"
    return "".join(c if c.isalnum() or c in ".-" else "-" for c in raw)


def _verdict_to_annotation(tr: TriageResult) -> str:
    """Record prioritization observations without asserting product impact."""
    return assess_finding(tr).detail


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

    # Build vulnerability lookup: CVE → list of TriageResults
    vuln_by_pkg: dict[str, list[TriageResult]] = {}
    for tr in scan_result.results:
        key = f"{tr.vuln.package}@{tr.vuln.version}"
        vuln_by_pkg.setdefault(key, []).append(tr)

    components, _ = _components_with_references(scan_result, packages)
    for component in components:
        name, version = component["name"], component["version"]
        spdx_id = _spdx_id(name, version)
        pkg_entry = _build_package_entry(
            spdx_id, name, version, component["purl"], vuln_by_pkg.get(f"{name}@{version}", [])
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

    return doc


def _build_package_entry(
    spdx_id: str,
    name: str,
    version: str,
    purl: str,
    triage_results: list[TriageResult],
) -> dict[str, Any]:
    """Build a single SPDX package entry."""
    pkg: dict[str, Any] = {
        "SPDXID": spdx_id,
        "name": name,
        "versionInfo": version,
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

    # Add SECURITY external refs for known CVEs
    cve_seen: set[str] = set()
    for tr in triage_results:
        cve = tr.vuln.cve
        if cve and cve not in cve_seen:
            cve_seen.add(cve)
            pkg["externalRefs"].append(
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": f"https://nvd.nist.gov/vuln/detail/{cve}",
                    "comment": _verdict_to_annotation(tr),
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
