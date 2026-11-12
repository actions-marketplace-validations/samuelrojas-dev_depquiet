"""Parse CycloneDX and SPDX SBOMs into Vulnerability objects or package lists.

SBOM import closes the loop: depquiet can now *consume* the same SBOM formats
it generates.  This enables triage on third-party SBOMs from vendors, build
systems, or container registries — without needing the original lockfile.

Two modes:

1. **Vulnerability mode** — if the SBOM contains vulnerability data (CycloneDX
   ``vulnerabilities`` array, or SPDX SECURITY external refs), those are
   extracted as Vulnerability objects for triage.

2. **Package mode** — if no vulnerability data is present, the component/package
   inventory is extracted as ``(name, version, ecosystem)`` tuples.  The caller
   (engine.py) then queries OSV.dev for vulnerabilities against those packages.

Usage::

    cat vendor-sbom.json | depquiet --stdin          # auto-detected
    depquiet --from-sbom vendor-sbom.cdx.json        # explicit SBOM input

Supported formats:
- CycloneDX 1.4 / 1.5 JSON
- SPDX 2.3 JSON
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from depquiet.models import Severity, Vulnerability

# -- Purl parsing --

_PURL_ECOSYSTEM: dict[str, str] = {
    "npm": "npm",
    "pypi": "PyPI",
    "golang": "Go",
    "cargo": "crates.io",
    "maven": "Maven",
    "nuget": "NuGet",
    "composer": "Packagist",
    "gem": "RubyGems",
    "pub": "Pub",
}

_PURL_RE = re.compile(
    r"^pkg:([a-zA-Z][a-zA-Z0-9._-]*)/"  # type
    r"(?:([^/]+)/)?"  # optional namespace (greedy)
    r"([^@]+)"  # name
    r"(?:@(.+))?$"  # optional version
)


def _parse_purl(purl: str) -> tuple[str, str, str]:
    """Extract (name, version, ecosystem) from a purl string.

    Returns ("", "", "") if the purl cannot be parsed.
    """
    m = _PURL_RE.match(purl)
    if not m:
        return ("", "", "")
    purl_type = m.group(1).lower()
    namespace = m.group(2) or ""
    name = m.group(3)
    version = m.group(4) or ""

    # Reconstruct scoped names (e.g., npm @babel/core)
    if namespace:
        # URL-decode %40 → @
        namespace = namespace.replace("%40", "@")
        name = f"{namespace}/{name}"

    ecosystem = _PURL_ECOSYSTEM.get(purl_type, purl_type)
    return (name, version, ecosystem)


# -- CycloneDX severity mapping --

_CDX_SEVERITY: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MODERATE,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "none": Severity.INFO,
    "unknown": Severity.MODERATE,
}


# -- Detection --


def is_cyclonedx(data: dict[str, Any]) -> bool:
    """Check if a JSON dict looks like a CycloneDX SBOM."""
    return data.get("bomFormat") == "CycloneDX" or ("components" in data and "specVersion" in data)


def is_spdx(data: dict[str, Any]) -> bool:
    """Check if a JSON dict looks like an SPDX document."""
    return isinstance(data.get("spdxVersion"), str) and data.get("spdxVersion", "").startswith(
        "SPDX-"
    )


# -- CycloneDX parsing --


def _parse_cyclonedx_packages(
    data: dict[str, Any],
) -> list[tuple[str, str, str]]:
    """Extract (name, version, ecosystem) from CycloneDX components."""
    packages: list[tuple[str, str, str]] = []
    seen: set[str] = set()

    for comp in data.get("components", []):
        name = comp.get("name", "")
        version = comp.get("version", "")
        if not name:
            continue

        # Try purl first for ecosystem
        purl = comp.get("purl", "")
        ecosystem = ""
        if purl:
            _, _, ecosystem = _parse_purl(purl)
            # purl might have a better name (scoped packages)
            purl_name, purl_version, _ = _parse_purl(purl)
            if purl_name:
                name = purl_name
            if purl_version and not version:
                version = purl_version

        key = f"{name}@{version}"
        if key in seen:
            continue
        seen.add(key)
        packages.append((name, version, ecosystem))

    return packages


def _parse_cyclonedx_vulns(
    data: dict[str, Any],
) -> list[Vulnerability]:
    """Extract vulnerabilities from CycloneDX vulnerability array."""
    vulns: list[Vulnerability] = []
    seen: set[str] = set()

    # Build component lookup: bom-ref → component
    comp_by_ref: dict[str, dict[str, Any]] = {}
    for comp in data.get("components", []):
        ref = comp.get("bom-ref", "")
        if ref:
            comp_by_ref[ref] = comp

    for vuln_entry in data.get("vulnerabilities", []):
        vuln_id = vuln_entry.get("id", "")
        if not vuln_id:
            continue

        # Severity from ratings
        severity = Severity.MODERATE
        severity_known = False
        for rating in vuln_entry.get("ratings", []):
            sev_str = rating.get("severity", "").lower()
            if sev_str in _CDX_SEVERITY:
                severity = _CDX_SEVERITY[sev_str]
                severity_known = sev_str != "unknown"
                break
            # Try CVSS score
            score = rating.get("score")
            if score is not None:
                try:
                    s = float(score)
                    if s >= 9.0:
                        severity = Severity.CRITICAL
                    elif s >= 7.0:
                        severity = Severity.HIGH
                    elif s >= 4.0:
                        severity = Severity.MODERATE
                    else:
                        severity = Severity.LOW
                    severity_known = True
                    break
                except (ValueError, TypeError):
                    pass

        # Description / title
        desc = vuln_entry.get("description", vuln_id)
        title = desc[:200] if desc else vuln_id

        # Source URL
        url = ""
        source = vuln_entry.get("source", {})
        if isinstance(source, dict):
            url = source.get("url", "")
        if not url:
            for ref in vuln_entry.get("references", []):
                ref_url = ref.get("url", "")
                if ref_url:
                    url = ref_url
                    break

        # Affected components
        affects = vuln_entry.get("affects", [])
        if not affects:
            # No component link — create a generic entry
            key = vuln_id
            if key not in seen:
                seen.add(key)
                vulns.append(
                    Vulnerability(
                        cve=vuln_id,
                        package="unknown",
                        version="",
                        severity=severity,
                        severity_known=severity_known,
                        title=title,
                        url=url,
                    )
                )
            continue

        for affect in affects:
            ref = affect.get("ref", "")
            comp = comp_by_ref.get(ref, {})
            pkg_name = comp.get("name", "unknown")
            pkg_version = comp.get("version", "")

            # Use purl for better name resolution
            purl = comp.get("purl", "")
            if purl:
                purl_name, purl_ver, _ = _parse_purl(purl)
                if purl_name:
                    pkg_name = purl_name
                if purl_ver and not pkg_version:
                    pkg_version = purl_ver

            # Fix version from affect.versions
            fix_version = ""
            for ver_entry in affect.get("versions", []):
                status = ver_entry.get("status", "")
                if status == "unaffected":
                    fix_version = ver_entry.get("version", "")
                    break

            key = f"{vuln_id}:{pkg_name}"
            if key in seen:
                continue
            seen.add(key)

            vulns.append(
                Vulnerability(
                    cve=vuln_id,
                    package=pkg_name,
                    version=pkg_version,
                    severity=severity,
                    severity_known=severity_known,
                    title=title,
                    url=url,
                    fix_version=fix_version,
                )
            )

    return vulns


# -- SPDX parsing --


def _parse_spdx_packages(
    data: dict[str, Any],
) -> list[tuple[str, str, str]]:
    """Extract (name, version, ecosystem) from SPDX packages."""
    packages: list[tuple[str, str, str]] = []
    seen: set[str] = set()

    for pkg in data.get("packages", []):
        name = pkg.get("name", "")
        version = pkg.get("versionInfo", "")
        if not name:
            continue

        # Try purl from external refs
        ecosystem = ""
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator", "")
                if purl:
                    purl_name, purl_ver, eco = _parse_purl(purl)
                    if purl_name:
                        name = purl_name
                    if purl_ver and not version:
                        version = purl_ver
                    ecosystem = eco
                    break

        key = f"{name}@{version}"
        if key in seen:
            continue
        seen.add(key)
        packages.append((name, version, ecosystem))

    return packages


def _parse_spdx_vulns(
    data: dict[str, Any],
) -> list[Vulnerability]:
    """Extract vulnerabilities from SPDX SECURITY external refs.

    SPDX 2.3 has no dedicated vulnerability object.  Vulnerabilities appear as
    externalRefs with referenceCategory "SECURITY" on package entries.
    """
    vulns: list[Vulnerability] = []
    seen: set[str] = set()

    for pkg in data.get("packages", []):
        pkg_name = pkg.get("name", "")
        pkg_version = pkg.get("versionInfo", "")

        # Resolve name from purl if available
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator", "")
                if purl:
                    purl_name, purl_ver, _ = _parse_purl(purl)
                    if purl_name:
                        pkg_name = purl_name
                    if purl_ver and not pkg_version:
                        pkg_version = purl_ver
                break

        # Extract SECURITY refs
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceCategory") != "SECURITY":
                continue

            locator = ref.get("referenceLocator", "")
            # Extract CVE from locator URL or direct ID
            cve = ""
            cve_match = re.search(r"(CVE-\d{4}-\d+)", locator, re.IGNORECASE)
            if cve_match:
                cve = cve_match.group(1).upper()
            elif locator.upper().startswith("CVE-"):
                cve = locator.upper()
            else:
                # Use locator as-is for non-CVE identifiers
                cve = locator or "UNKNOWN"

            if not cve:
                continue

            key = f"{cve}:{pkg_name}"
            if key in seen:
                continue
            seen.add(key)

            vulns.append(
                Vulnerability(
                    cve=cve,
                    package=pkg_name,
                    version=pkg_version,
                    severity=Severity.MODERATE,  # SPDX has no severity field
                    severity_known=False,
                    title=ref.get("comment", cve),
                    url=locator if locator.startswith("http") else "",
                )
            )

    return vulns


# -- Public API --


class SbomParser:
    """Parse CycloneDX or SPDX SBOM JSON input."""

    name = "sbom"

    @staticmethod
    def detect(project: Path) -> bool:
        """SBOM is never auto-detected from project files."""
        return False

    @staticmethod
    def parse(data: dict[str, Any], project: Path) -> list[Vulnerability]:
        """Parse an SBOM and extract vulnerabilities.

        If the SBOM contains vulnerability data, returns those.
        Otherwise returns an empty list (caller should use extract_packages
        and query OSV.dev).
        """
        if is_cyclonedx(data):
            vuln_list = data.get("vulnerabilities", [])
            if vuln_list:
                return _parse_cyclonedx_vulns(data)
        elif is_spdx(data):
            # Check if any package has SECURITY refs
            for pkg in data.get("packages", []):
                for ref in pkg.get("externalRefs", []):
                    if ref.get("referenceCategory") == "SECURITY":
                        return _parse_spdx_vulns(data)
        return []

    @staticmethod
    def extract_packages(
        data: dict[str, Any],
    ) -> list[tuple[str, str, str]]:
        """Extract package inventory from an SBOM.

        Returns a list of (name, version, ecosystem) tuples suitable for
        OSV.dev batch queries.
        """
        if is_cyclonedx(data):
            return _parse_cyclonedx_packages(data)
        elif is_spdx(data):
            return _parse_spdx_packages(data)
        return []

    @classmethod
    def scan(cls, project: Path) -> list[Vulnerability]:
        """SBOM must be piped via ``--stdin`` or ``--from-sbom``."""
        return []
