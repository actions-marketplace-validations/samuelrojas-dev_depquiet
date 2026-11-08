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
from depquiet.assessment import assess_finding
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


def _components_with_references(
    scan_result: ScanResult, packages: list[tuple[str, str, str]] | None
) -> tuple[list[dict[str, Any]], dict[tuple[str, str], list[str]]]:
    """Keep inventory references and add any finding contexts it does not contain."""
    components: list[dict[str, Any]] = []
    references: dict[tuple[str, str], list[str]] = {}
    seen: set[str] = set()

    def add(name: str, version: str, purl: str) -> None:
        if purl in seen:
            return
        seen.add(purl)
        components.append(
            {"type": "library", "name": name, "version": version, "purl": purl, "bom-ref": purl}
        )
        references.setdefault((name, version), []).append(purl)

    for name, version, ecosystem in packages or []:
        add(name, version, _make_purl(name, version, ecosystem))
    for tr in scan_result.results:
        v = tr.vuln
        if (v.package, v.version) not in references:
            add(v.package, v.version, f"pkg:generic/{v.package}@{v.version}")
    return components, references


def _vulnerabilities_with_assessments(
    scan_result: ScanResult, references: dict[tuple[str, str], list[str]]
) -> list[dict[str, Any]]:
    """Group advisory contexts without converting priority into impact claims."""
    groups: dict[str, list[TriageResult]] = {}
    for tr in scan_result.results:
        if tr.vuln.cve:
            groups.setdefault(tr.vuln.cve, []).append(tr)

    vulnerabilities: list[dict[str, Any]] = []
    severity_order = {"info": 0, "low": 1, "moderate": 2, "high": 3, "critical": 4}
    for cve, findings in groups.items():
        first = findings[0].vuln
        affects: list[dict[str, str]] = []
        seen_refs: set[str] = set()
        details: list[str] = []
        contexts: dict[str, dict[str, str]] = {}
        for tr in findings:
            v = tr.vuln
            detail = assess_finding(tr).detail
            details.append(f"{v.package}@{v.version}: {detail}" if len(findings) > 1 else detail)
            for ref in references[(v.package, v.version)]:
                if ref not in seen_refs:
                    seen_refs.add(ref)
                    affects.append({"ref": ref})
                # Standard CycloneDX properties preserve machine-readable
                # priority and reasons per component, apart from VEX state.
                context = json.dumps(
                    {
                        "ref": ref,
                        "priority": tr.verdict.value,
                        "reasons": [reason.value for reason in tr.reasons],
                    },
                    sort_keys=True,
                )
                contexts[context] = {"name": "depquiet:triage", "value": context}

        severity = max((tr.vuln.severity.value for tr in findings), key=severity_order.__getitem__)
        vulnerabilities.append(
            {
                "id": cve,
                "source": {
                    "name": "depquiet",
                    "url": first.url or "https://github.com/samuelrojas-dev/depquiet",
                },
                "description": first.title,
                "ratings": [
                    {
                        "severity": "medium" if severity == "moderate" else severity,
                        "source": {"name": "depquiet"},
                    }
                ],
                "affects": affects,
                "analysis": {"state": "in_triage", "detail": "\n".join(dict.fromkeys(details))},
                "properties": list(contexts.values()),
            }
        )
    return vulnerabilities


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
    if not scan_result.scanned:
        raise ValueError("Cannot generate CycloneDX from an incomplete scan.")
    serial = str(uuid.uuid4())
    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    components, references = _components_with_references(scan_result, packages)
    vuln_list = _vulnerabilities_with_assessments(scan_result, references)

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
    """Automatic prioritization does not establish product impact."""
    return "in_triage"


def generate_cyclonedx_xml(
    scan_result: ScanResult,
    packages: list[tuple[str, str, str]] | None = None,
) -> bytes:
    """Generate a CycloneDX 1.5 XML SBOM.

    Returns:
        UTF-8 encoded XML bytes.
    """
    data = generate_cyclonedx_json(scan_result, packages)
    ns = "http://cyclonedx.org/schema/bom/1.5"
    bom = Element("bom", xmlns=ns, version="1", serialNumber=data["serialNumber"])

    # Metadata
    metadata = SubElement(bom, "metadata")
    ts = SubElement(metadata, "timestamp")
    ts.text = data["metadata"]["timestamp"]

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
    for component in data["components"]:
        comp = SubElement(
            components_el, "component", {"type": "library", "bom-ref": component["bom-ref"]}
        )
        SubElement(comp, "name").text = component["name"]
        SubElement(comp, "version").text = component["version"]
        SubElement(comp, "purl").text = component["purl"]

    # Vulnerabilities
    if data.get("vulnerabilities"):
        vulns_el = SubElement(bom, "vulnerabilities")
        for vulnerability in data["vulnerabilities"]:
            vuln_el = SubElement(vulns_el, "vulnerability")
            SubElement(vuln_el, "id").text = vulnerability["id"]
            source = SubElement(vuln_el, "source")
            SubElement(source, "name").text = vulnerability["source"]["name"]
            SubElement(source, "url").text = vulnerability["source"]["url"]
            ratings = SubElement(vuln_el, "ratings")
            for rating_data in vulnerability["ratings"]:
                rating = SubElement(ratings, "rating")
                SubElement(rating, "severity").text = rating_data["severity"]
            if vulnerability["description"]:
                SubElement(vuln_el, "description").text = vulnerability["description"]

            analysis = SubElement(vuln_el, "analysis")
            SubElement(analysis, "state").text = vulnerability["analysis"]["state"]
            SubElement(analysis, "detail").text = vulnerability["analysis"]["detail"]
            affects = SubElement(vuln_el, "affects")
            for affected in vulnerability["affects"]:
                target = SubElement(affects, "target")
                SubElement(target, "ref").text = affected["ref"]
            properties = SubElement(vuln_el, "properties")
            for prop in vulnerability["properties"]:
                SubElement(properties, "property", name=prop["name"]).text = prop["value"]

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
        output_path.write_text(json.dumps(bom, indent=2) + "\n", encoding="utf-8")
