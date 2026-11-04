"""Generate CycloneDX 1.5 SBOM from parsed lockfiles.

Software Bill of Materials (SBOM) is a formal, machine-readable inventory
of all software components in a project.  CycloneDX is the OWASP standard
for SBOM, required by EO 14028 (US federal supply chain security) and
increasingly by enterprise procurement.

Usage::

    depquiet --sbom sbom.json           # CycloneDX 1.5 JSON
    depquiet --sbom sbom.xml --format xml  # CycloneDX 1.5 XML

The SBOM includes:
- All packages from detected lockfiles
- Known vulnerabilities from the triage results
- Package URLs (purl) per the purl spec
- Tool metadata identifying depquiet as the creator

This module reuses the lockfile parsers from ``parsers.osv`` and the
vulnerability data from the triage engine, so no extra scanning is needed.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from xml.etree.ElementTree import Element, SubElement, tostring

from depquiet import __version__
from depquiet.models import ScanResult, TriageResult

# Ecosystem → purl type mapping
_PURL_TYPE: dict[str, str] = {
    "npm": "npm",
    "PyPI": "pypi",
    "Go": "golang",
    "crates.io": "cargo",
    "Maven": "maven",
    "NuGet": "nuget",
    "Packagist": "composer",
    "RubyGems": "gem",
    "Pub": "pub",
}


def _make_purl(name: str, version: str, ecosystem: str) -> str:
    """Build a Package URL (purl) string.

    See https://github.com/package-url/purl-spec
    """
    purl_type = _PURL_TYPE.get(ecosystem, ecosystem.lower())

    # Scoped npm packages: @scope/name → pkg:npm/%40scope/name
    if purl_type == "npm" and name.startswith("@"):
        # purl spec: @ in namespace is percent-encoded
        name = name.replace("@", "%40", 1)

    # Go modules use the full path as name
    # Maven uses groupId/artifactId
    return f"pkg:{purl_type}/{name}@{version}"


def _purl_from_vuln(vuln_result: TriageResult) -> str:
    """Build purl from a triage result (best effort)."""
    v = vuln_result.vuln
    # Guess ecosystem from package manager context
    # This is a heuristic — in practice the engine knows the ecosystem
    return f"pkg:generic/{v.package}@{v.version}" if v.package else ""


def generate_cyclonedx_json(
    scan_result: ScanResult,
    packages: list[tuple[str, str, str]] | None = None,
) -> dict[str, Any]:
    """Generate a CycloneDX 1.5 JSON SBOM.

    Args:
        scan_result: The triage scan result.
        packages: Optional list of (name, version, ecosystem) from lockfile parsing.
                  If not provided, components are derived from the scan results.

    Returns:
        CycloneDX 1.5 JSON as a Python dict.
    """
    serial = str(uuid.uuid4())
    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Build components list
    components: list[dict[str, Any]] = []
    seen: set[str] = set()

    if packages:
        for name, version, ecosystem in packages:
            purl = _make_purl(name, version, ecosystem)
            if purl in seen:
                continue
            seen.add(purl)
            components.append(
                {
                    "type": "library",
                    "name": name,
                    "version": version,
                    "purl": purl,
                    "bom-ref": purl,
                }
            )
    else:
        # Fall back to scan results
        for tr in scan_result.results:
            v = tr.vuln
            key = f"{v.package}@{v.version}"
            if key in seen:
                continue
            seen.add(key)
            purl = f"pkg:generic/{v.package}@{v.version}"
            components.append(
                {
                    "type": "library",
                    "name": v.package,
                    "version": v.version,
                    "purl": purl,
                    "bom-ref": purl,
                }
            )

    # Build vulnerabilities list from triage results
    vuln_list: list[dict[str, Any]] = []
    vuln_seen: set[str] = set()
    for tr in scan_result.results:
        v = tr.vuln
        if v.cve in vuln_seen or not v.cve:
            continue
        vuln_seen.add(v.cve)

        vuln_entry: dict[str, Any] = {
            "id": v.cve,
            "source": {"name": "depquiet", "url": "https://github.com/samuelrojas-dev/depquiet"},
            "description": v.title,
            "affects": [
                {
                    "ref": f"pkg:generic/{v.package}@{v.version}",
                }
            ],
            "analysis": {
                "state": _verdict_to_state(tr),
                "detail": tr.reason_summary,
            },
        }

        if v.severity:
            vuln_entry["ratings"] = [
                {
                    "severity": v.severity.value,
                    "source": {"name": "depquiet"},
                }
            ]

        if v.url:
            vuln_entry["source"]["url"] = v.url

        vuln_list.append(vuln_entry)

    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "depquiet",
                        "version": __version__,
                        "author": "samuelrojas-dev",
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": Path(scan_result.project_path).name or "unknown",
                "version": "0.0.0",
            },
        },
        "components": components,
    }

    if vuln_list:
        bom["vulnerabilities"] = vuln_list

    return bom


def _verdict_to_state(tr: TriageResult) -> str:
    """Map depquiet verdict to CycloneDX analysis state."""
    from depquiet.models import Verdict

    if tr.verdict == Verdict.FILTERED:
        return "false_positive" if tr.reasons else "not_affected"
    if tr.verdict == Verdict.REVIEW:
        return "in_triage"
    return "exploitable"


def generate_cyclonedx_xml(
    scan_result: ScanResult,
    packages: list[tuple[str, str, str]] | None = None,
) -> bytes:
    """Generate a CycloneDX 1.5 XML SBOM.

    Returns:
        UTF-8 encoded XML bytes.
    """
    ns = "http://cyclonedx.org/schema/bom/1.5"
    bom = Element("bom", xmlns=ns, version="1", serialNumber=f"urn:uuid:{uuid.uuid4()}")

    # Metadata
    metadata = SubElement(bom, "metadata")
    ts = SubElement(metadata, "timestamp")
    ts.text = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    tools = SubElement(metadata, "tools")
    tools_components = SubElement(tools, "components")
    tool = SubElement(tools_components, "component", type="application")
    SubElement(tool, "name").text = "depquiet"
    SubElement(tool, "version").text = __version__

    comp_root = SubElement(metadata, "component", type="application")
    SubElement(comp_root, "name").text = Path(scan_result.project_path).name or "unknown"
    SubElement(comp_root, "version").text = "0.0.0"

    # Components
    components_el = SubElement(bom, "components")
    seen: set[str] = set()

    if packages:
        for name, version, ecosystem in packages:
            purl = _make_purl(name, version, ecosystem)
            if purl in seen:
                continue
            seen.add(purl)
            comp = SubElement(components_el, "component", type="library")
            SubElement(comp, "name").text = name
            SubElement(comp, "version").text = version
            SubElement(comp, "purl").text = purl
    else:
        for tr in scan_result.results:
            v = tr.vuln
            key = f"{v.package}@{v.version}"
            if key in seen:
                continue
            seen.add(key)
            comp = SubElement(components_el, "component", type="library")
            SubElement(comp, "name").text = v.package
            SubElement(comp, "version").text = v.version
            SubElement(comp, "purl").text = f"pkg:generic/{v.package}@{v.version}"

    # Vulnerabilities
    if scan_result.results:
        vulns_el = SubElement(bom, "vulnerabilities")
        vuln_seen: set[str] = set()
        for tr in scan_result.results:
            v = tr.vuln
            if v.cve in vuln_seen or not v.cve:
                continue
            vuln_seen.add(v.cve)

            vuln_el = SubElement(vulns_el, "vulnerability", ref=v.cve)
            SubElement(vuln_el, "id").text = v.cve
            source = SubElement(vuln_el, "source")
            SubElement(source, "name").text = "depquiet"

            if v.title:
                SubElement(vuln_el, "description").text = v.title

            if v.severity:
                ratings = SubElement(vuln_el, "ratings")
                rating = SubElement(ratings, "rating")
                SubElement(rating, "severity").text = v.severity.value

            analysis = SubElement(vuln_el, "analysis")
            SubElement(analysis, "state").text = _verdict_to_state(tr)
            SubElement(analysis, "detail").text = tr.reason_summary

    return tostring(bom, encoding="unicode").encode("utf-8")


def write_sbom(
    scan_result: ScanResult,
    output_path: Path,
    fmt: str = "json",
    packages: list[tuple[str, str, str]] | None = None,
) -> None:
    """Write SBOM to a file.

    Args:
        scan_result: Triage results.
        output_path: Where to write the SBOM.
        fmt: "json", "xml", or "spdx" (SPDX 2.3 JSON).
        packages: Optional lockfile packages for component inventory.
    """
    if fmt == "spdx":
        from depquiet.spdx import write_spdx

        write_spdx(scan_result, output_path, packages)
    elif fmt == "xml":
        data = generate_cyclonedx_xml(scan_result, packages)
        output_path.write_bytes(data)
    else:
        bom = generate_cyclonedx_json(scan_result, packages)
        output_path.write_text(json.dumps(bom, indent=2) + "\n")
