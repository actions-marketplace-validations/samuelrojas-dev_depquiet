"""Export component identities separately from scanner advisory ranges.

Lockfile candidates are evidence about resolution, not observations of an
installed runtime. Advisory association belongs to each finding, so the same
component can have different range-match results for different advisories.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from depquiet.models import ComponentEvidence, ScanResult, Vulnerability

_PURL_TYPE = {
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


def make_purl(name: str, version: str | None, ecosystem: str) -> str:
    """A missing version is an unversioned identity, never an advisory range."""
    purl_type = _PURL_TYPE.get(ecosystem, ecosystem.lower())
    if purl_type == "npm" and name.startswith("@"):
        name = name.replace("@", "%40", 1)
    # PURL encoding keeps ':' literal even as data (specification clause 5.4).
    suffix = "" if version is None else "@" + quote(version, safe="-._~:")
    return f"pkg:{purl_type}/{name}{suffix}"


@dataclass(frozen=True)
class ExportComponent:
    """An inventory identity and optional lockfile provenance."""

    ref: str
    purl: str
    package: str
    version: str | None
    evidence: ComponentEvidence | None = None

    def provenance(self) -> dict[str, str]:
        """Component-only facts; range matching is advisory-specific."""
        if self.evidence is None:
            return {}
        data = self.evidence.to_dict()
        return {key: value for key, value in data.items() if key not in {"range_match", "reason"}}


def _candidate(component: ComponentEvidence) -> ExportComponent:
    return ExportComponent(
        component.instance_id,
        make_purl(component.package, component.version, component.ecosystem),
        component.package,
        component.version,
        component,
    )


def finding_components(
    vuln: Vulnerability, inventory: list[ExportComponent] | None = None
) -> list[ExportComponent]:
    """Associate matched/uncertain candidates, preserving all legacy identities."""
    if vuln.version_kind == "advisory_range":
        if vuln.components:
            associated = [
                _candidate(component)
                for component in vuln.components
                if component.range_match != "not_matched"
            ]
            if vuln.component_resolution_complete:
                return associated
        else:
            associated = []
        purl = make_purl(vuln.package, None, "npm")
        return [*associated, ExportComponent(purl, purl, vuln.package, None)]
    if inventory is not None:
        matching = [
            component
            for component in inventory
            if (component.package, component.version) == (vuln.package, vuln.version)
        ]
        if matching:
            return matching
    purl = make_purl(vuln.package, vuln.version, "generic")
    return [ExportComponent(purl, purl, vuln.package, vuln.version)]


def component_inventory(
    result: ScanResult, packages: list[tuple[str, str, str]] | None = None
) -> list[ExportComponent]:
    """Keep every resolved candidate, including versions outside an advisory."""
    candidates: dict[str, ExportComponent] = {}
    candidate_packages: set[tuple[str, str, str]] = set()
    for finding in result.results:
        if finding.vuln.version_kind == "advisory_range":
            for evidence in finding.vuln.components:
                candidates.setdefault(evidence.instance_id, _candidate(evidence))
                candidate_packages.add((evidence.package, evidence.version, evidence.ecosystem))

    inventory: dict[str, ExportComponent] = {}
    for name, version, ecosystem in packages or []:
        if (name, version, ecosystem) not in candidate_packages:
            purl = make_purl(name, version, ecosystem)
            inventory.setdefault(purl, ExportComponent(purl, purl, name, version))
    inventory.update(candidates)
    for finding in result.results:
        for component in finding_components(finding.vuln, list(inventory.values())):
            inventory.setdefault(component.ref, component)
    return list(inventory.values())


def association_metadata(vuln: Vulnerability, component: ExportComponent | None) -> dict[str, Any]:
    """Machine-readable advisory association, independent of priority/impact."""
    metadata: dict[str, Any] = {"advisory": vuln.cve}
    if component is not None:
        metadata["ref"] = component.ref
    if vuln.version_kind == "advisory_range":
        metadata.update(
            version_kind="advisory_range",
            advisory_range=vuln.advisory_range or vuln.version,
            component_resolution_complete=vuln.component_resolution_complete,
            range_match=component.evidence.range_match
            if component and component.evidence
            else "unknown",
        )
        if component and component.evidence:
            metadata["component_evidence"] = component.evidence.to_dict()
        elif component is not None:
            metadata["reason"] = (
                "Component resolution is incomplete; unresolved npm locations remain "
                "associated with an unversioned package identity."
                if vuln.components
                else "No resolved lockfile candidate; version is unspecified."
            )
        else:
            metadata["range_match"] = "not_matched"
            metadata["reason"] = "All resolved candidates are outside this advisory range."
    return metadata


def association_notes(vuln: Vulnerability) -> str:
    """Explain resolution boundaries using standard export text fields."""
    if vuln.version_kind != "advisory_range":
        return ""
    notes = [
        f"Scanner version value is an advisory range ({vuln.advisory_range or vuln.version}), "
        "not an installed version.",
        "Lockfile resolution does not establish runtime installation or product impact.",
        (
            "All reported npm node locations were resolved to lockfile candidates."
            if vuln.component_resolution_complete
            else "Component resolution is incomplete; unresolved node locations remain "
            "unknown at an unversioned npm package identity."
        ),
    ]
    for component in vuln.components:
        notes.append(
            f"Lockfile candidate {component.package}@{component.version} "
            f"[{component.instance_id}] at {component.location} in {component.lockfile} "
            f"(SHA-256 {component.lockfile_sha256}); advisory {vuln.cve} "
            f"range match: {component.range_match}. {component.reason}".strip()
        )
    if not vuln.components:
        notes.append(
            "No lockfile-resolved candidate was established; the npm package identity "
            "has no version and its association is unknown."
        )
    elif (
        all(component.range_match == "not_matched" for component in vuln.components)
        and vuln.component_resolution_complete
    ):
        notes.append(
            "No resolved candidate is associated: all are outside this advisory range. "
            "The scanner alert remains under investigation."
        )
    elif all(component.range_match == "not_matched" for component in vuln.components):
        notes.append(
            "All resolved candidates are outside this advisory range; "
            "unresolved locations remain associated as unknown."
        )
    notes.extend(vuln.component_notes)
    return " ".join(dict.fromkeys(notes))
