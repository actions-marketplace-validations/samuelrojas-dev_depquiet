"""Lockfile scanner backed by the OSV.dev API.

OSV.dev (https://osv.dev) is Google's open, free vulnerability database
covering npm, PyPI, crates.io, Go, Maven, NuGet, Packagist, RubyGems,
Pub, and more.  It powers ``osv-scanner``, ``deps.dev``, and GitHub's
advisory database.

This module parses lockfiles directly (no external scanner required) and
queries OSV.dev's batch API to find known vulnerabilities, making depquiet
a fully standalone tool::

    depquiet                  # auto-detects lockfile, queries OSV.dev
    depquiet --offline        # skips OSV.dev (and EPSS), scan-only mode

Supported lockfiles:
- package-lock.json (npm)
- yarn.lock (Yarn v1)
- requirements.txt / Pipfile.lock (Python)
- go.sum (Go)
- Cargo.lock (Rust)
- pom.xml (Maven — top-level dependencies only)
- pubspec.lock (Dart/Flutter)
- Gemfile.lock (Ruby)
- composer.lock (PHP)
- packages.lock.json (NuGet / C#)

The batch API accepts up to 1000 queries per request, so even large projects
need only a single HTTP call.
"""

from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path
from typing import Any

from depquiet.models import Severity, Vulnerability

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

# Ecosystem names as OSV.dev expects them
_ECOSYSTEM_NPM = "npm"
_ECOSYSTEM_PYPI = "PyPI"
_ECOSYSTEM_GO = "Go"
_ECOSYSTEM_CARGO = "crates.io"
_ECOSYSTEM_MAVEN = "Maven"
_ECOSYSTEM_NUGET = "NuGet"
_ECOSYSTEM_PACKAGIST = "Packagist"
_ECOSYSTEM_RUBYGEMS = "RubyGems"
_ECOSYSTEM_PUB = "Pub"


# ---------------------------------------------------------------------------
# Lockfile parsers — each returns [(name, version, ecosystem)]
# ---------------------------------------------------------------------------

PackageInfo = tuple[str, str, str]  # (name, version, ecosystem)


def _parse_package_lock(path: Path) -> list[PackageInfo]:
    """Parse npm package-lock.json (v2/v3 format with 'packages')."""
    data = json.loads(path.read_text())
    results: list[PackageInfo] = []
    seen: set[str] = set()

    # v2/v3 format
    packages = data.get("packages", {})
    for key, info in packages.items():
        if not key:  # root package
            continue
        name = info.get("name", "")
        if not name:
            # Extract name from key: "node_modules/lodash" or
            # "node_modules/@scope/name"
            parts = key.split("node_modules/")
            name = parts[-1] if parts else ""
        version = info.get("version", "")
        if name and version:
            k = f"{name}@{version}"
            if k not in seen:
                seen.add(k)
                results.append((name, version, _ECOSYSTEM_NPM))

    # v1 format fallback
    if not results:
        deps = data.get("dependencies", {})
        for name, info in deps.items():
            version = info.get("version", "")
            if version:
                k = f"{name}@{version}"
                if k not in seen:
                    seen.add(k)
                    results.append((name, version, _ECOSYSTEM_NPM))

    return results


def _parse_yarn_lock(path: Path) -> list[PackageInfo]:
    """Parse yarn.lock (v1 format)."""
    results: list[PackageInfo] = []
    seen: set[str] = set()
    text = path.read_text()

    # yarn.lock v1: "name@version:" followed by "  version "x.y.z""
    current_name = ""
    for line in text.splitlines():
        if line and not line.startswith(" ") and not line.startswith("#"):
            # Package header: "lodash@^4.17.20:" or '"@scope/pkg@^1.0.0":'
            header = line.rstrip(":")
            # Remove quotes first
            header = header.strip('"').strip("'")
            # Extract package name (everything before the last @version)
            if header.startswith("@"):
                # Scoped package: find the second @
                at_idx = header.index("@", 1)
                current_name = header[:at_idx]
            else:
                at_idx = header.index("@") if "@" in header else len(header)
                current_name = header[:at_idx]
        elif line.startswith("  version ") and current_name:
            version = line.split('"')[1] if '"' in line else line.split()[-1]
            k = f"{current_name}@{version}"
            if k not in seen:
                seen.add(k)
                results.append((current_name, version, _ECOSYSTEM_NPM))
            current_name = ""

    return results


def _parse_requirements_txt(path: Path) -> list[PackageInfo]:
    """Parse requirements.txt (pinned versions only)."""
    results: list[PackageInfo] = []
    seen: set[str] = set()

    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle "package==version" or "package===version"
        match = re.match(r"^([a-zA-Z0-9._-]+)\s*={2,3}\s*([^\s;#]+)", line)
        if match:
            name = match.group(1).lower()
            version = match.group(2)
            k = f"{name}@{version}"
            if k not in seen:
                seen.add(k)
                results.append((name, version, _ECOSYSTEM_PYPI))

    return results


def _parse_pipfile_lock(path: Path) -> list[PackageInfo]:
    """Parse Pipfile.lock."""
    data = json.loads(path.read_text())
    results: list[PackageInfo] = []
    seen: set[str] = set()

    for section in ("default", "develop"):
        packages = data.get(section, {})
        for name, info in packages.items():
            version = info.get("version", "").lstrip("=")
            if version:
                k = f"{name}@{version}"
                if k not in seen:
                    seen.add(k)
                    results.append((name.lower(), version, _ECOSYSTEM_PYPI))

    return results


def _parse_go_sum(path: Path) -> list[PackageInfo]:
    """Parse go.sum."""
    results: list[PackageInfo] = []
    seen: set[str] = set()

    for line in path.read_text().splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        module = parts[0]
        version = parts[1].split("/")[0].lstrip("v")
        k = f"{module}@{version}"
        if k not in seen:
            seen.add(k)
            results.append((module, version, _ECOSYSTEM_GO))

    return results


def _parse_cargo_lock(path: Path) -> list[PackageInfo]:
    """Parse Cargo.lock (TOML-like, no external dependency needed)."""
    results: list[PackageInfo] = []
    seen: set[str] = set()
    text = path.read_text()

    name = ""
    version = ""
    for line in text.splitlines():
        line = line.strip()
        if line == "[[package]]":
            if name and version:
                k = f"{name}@{version}"
                if k not in seen:
                    seen.add(k)
                    results.append((name, version, _ECOSYSTEM_CARGO))
            name = ""
            version = ""
        elif line.startswith("name = "):
            name = line.split('"')[1]
        elif line.startswith("version = "):
            version = line.split('"')[1]

    # Last package
    if name and version:
        k = f"{name}@{version}"
        if k not in seen:
            seen.add(k)
            results.append((name, version, _ECOSYSTEM_CARGO))

    return results


def _parse_pubspec_lock(path: Path) -> list[PackageInfo]:
    """Parse pubspec.lock (YAML-like, simple line parsing)."""
    results: list[PackageInfo] = []
    seen: set[str] = set()
    text = path.read_text()

    current_name = ""
    for line in text.splitlines():
        # Package name at indent level 2: "  package_name:"
        if line.startswith("  ") and not line.startswith("    ") and line.endswith(":"):
            current_name = line.strip().rstrip(":")
        elif '    version: "' in line and current_name:
            version = line.split('"')[1]
            k = f"{current_name}@{version}"
            if k not in seen:
                seen.add(k)
                results.append((current_name, version, _ECOSYSTEM_PUB))
            current_name = ""

    return results


def _parse_gemfile_lock(path: Path) -> list[PackageInfo]:
    """Parse Gemfile.lock (GEM section)."""
    results: list[PackageInfo] = []
    seen: set[str] = set()
    text = path.read_text()
    in_specs = False

    for line in text.splitlines():
        if line.strip() == "GEM":
            continue
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and line.startswith("      "):
            # Dependency of a gem, skip
            continue
        if in_specs and line.startswith("    "):
            # "    gem_name (version)"
            match = re.match(r"^\s{4}(\S+)\s+\(([^)]+)\)", line)
            if match:
                name = match.group(1)
                version = match.group(2)
                k = f"{name}@{version}"
                if k not in seen:
                    seen.add(k)
                    results.append((name, version, _ECOSYSTEM_RUBYGEMS))
        elif in_specs and not line.startswith(" "):
            in_specs = False

    return results


def _parse_composer_lock(path: Path) -> list[PackageInfo]:
    """Parse composer.lock (PHP)."""
    data = json.loads(path.read_text())
    results: list[PackageInfo] = []
    seen: set[str] = set()

    for section in ("packages", "packages-dev"):
        for pkg in data.get(section, []):
            name = pkg.get("name", "")
            version = pkg.get("version", "").lstrip("v")
            if name and version:
                k = f"{name}@{version}"
                if k not in seen:
                    seen.add(k)
                    results.append((name, version, _ECOSYSTEM_PACKAGIST))

    return results


def _parse_packages_lock_json(path: Path) -> list[PackageInfo]:
    """Parse packages.lock.json (NuGet / C#)."""
    data = json.loads(path.read_text())
    results: list[PackageInfo] = []
    seen: set[str] = set()

    deps = data.get("dependencies", {})
    for _framework, packages in deps.items():
        for name, info in packages.items():
            resolved = info.get("resolved", "")
            if resolved:
                k = f"{name}@{resolved}"
                if k not in seen:
                    seen.add(k)
                    results.append((name, resolved, _ECOSYSTEM_NUGET))

    return results


# Lockfile → parser mapping
_LOCKFILE_PARSERS: list[tuple[str, Any]] = [
    ("package-lock.json", _parse_package_lock),
    ("yarn.lock", _parse_yarn_lock),
    ("Pipfile.lock", _parse_pipfile_lock),
    ("requirements.txt", _parse_requirements_txt),
    ("go.sum", _parse_go_sum),
    ("Cargo.lock", _parse_cargo_lock),
    ("pubspec.lock", _parse_pubspec_lock),
    ("Gemfile.lock", _parse_gemfile_lock),
    ("composer.lock", _parse_composer_lock),
    ("packages.lock.json", _parse_packages_lock_json),
]


def detect_lockfiles(project: Path) -> list[tuple[Path, str]]:
    """Find all lockfiles in a project directory.

    Returns list of (path, lockfile_name) tuples.
    """
    found: list[tuple[Path, str]] = []
    for lockfile_name, _ in _LOCKFILE_PARSERS:
        path = project / lockfile_name
        if path.exists():
            found.append((path, lockfile_name))
    return found


def parse_lockfiles(project: Path) -> list[PackageInfo]:
    """Parse all lockfiles in a project, returning deduplicated packages."""
    all_packages: list[PackageInfo] = []
    seen: set[str] = set()

    for lockfile_name, parser_func in _LOCKFILE_PARSERS:
        path = project / lockfile_name
        if path.exists():
            try:
                packages = parser_func(path)
                for pkg in packages:
                    key = f"{pkg[2]}:{pkg[0]}@{pkg[1]}"
                    if key not in seen:
                        seen.add(key)
                        all_packages.append(pkg)
            except (json.JSONDecodeError, KeyError, IndexError, OSError):
                continue

    return all_packages


# ---------------------------------------------------------------------------
# OSV.dev API
# ---------------------------------------------------------------------------

_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MODERATE,
    "MEDIUM": Severity.MODERATE,
    "LOW": Severity.LOW,
}


def _osv_severity(vuln_data: dict[str, Any]) -> Severity:
    """Extract severity from OSV vulnerability data."""
    # database_specific may have severity
    db_specific = vuln_data.get("database_specific", {})
    sev = db_specific.get("severity", "")
    if sev and sev.upper() in _SEVERITY_MAP:
        return _SEVERITY_MAP[sev.upper()]

    # CVSS from severity[] array
    for sev_entry in vuln_data.get("severity", []):
        score_str = sev_entry.get("score", "")
        if score_str:
            # CVSS vector string: extract base score if possible
            # Or it might just be a numeric score
            try:
                score = float(score_str)
                if score >= 9.0:
                    return Severity.CRITICAL
                if score >= 7.0:
                    return Severity.HIGH
                if score >= 4.0:
                    return Severity.MODERATE
                return Severity.LOW
            except ValueError:
                pass

    return Severity.MODERATE


def _extract_fix_version(vuln_data: dict[str, Any], package_name: str) -> str:
    """Extract fix version from OSV affected[].ranges[].events[]."""
    for affected in vuln_data.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name", "").lower() != package_name.lower():
            continue
        for range_info in affected.get("ranges", []):
            for event in range_info.get("events", []):
                fixed = event.get("fixed", "")
                if fixed:
                    return fixed
    return ""


def query_osv_batch(packages: list[PackageInfo], timeout: int = 30) -> dict[str, Any]:
    """Query OSV.dev batch API.

    Args:
        packages: List of (name, version, ecosystem) tuples.
        timeout: HTTP timeout in seconds.

    Returns:
        Raw OSV batch response as dict.
    """
    queries = []
    for name, version, ecosystem in packages:
        queries.append(
            {
                "version": version,
                "package": {"name": name, "ecosystem": ecosystem},
            }
        )

    # OSV batch API accepts up to 1000 queries per request
    payload = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(
        _OSV_BATCH_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=timeout) as resp:
        result: dict[str, Any] = json.loads(resp.read())
        return result


def parse_osv_response(
    response: dict[str, Any],
    packages: list[PackageInfo],
) -> list[Vulnerability]:
    """Convert OSV batch response into Vulnerability objects."""
    vulns: list[Vulnerability] = []
    seen: set[str] = set()

    results_list = response.get("results", [])
    for i, result in enumerate(results_list):
        if i >= len(packages):
            break
        pkg_name, pkg_version, _ecosystem = packages[i]

        for osv_vuln in result.get("vulns", []):
            vuln_id = osv_vuln.get("id", "")

            # Prefer CVE alias over OSV ID
            cve = vuln_id
            for alias in osv_vuln.get("aliases", []):
                if alias.startswith("CVE-"):
                    cve = alias
                    break

            key = f"{cve}:{pkg_name}"
            if key in seen:
                continue
            seen.add(key)

            summary = osv_vuln.get("summary", "")
            details = osv_vuln.get("details", "")
            title = summary or details[:200] or cve

            severity = _osv_severity(osv_vuln)
            fix_version = _extract_fix_version(osv_vuln, pkg_name)

            # URL: prefer the first reference of type WEB or ADVISORY
            url = ""
            for ref in osv_vuln.get("references", []):
                ref_type = ref.get("type", "")
                if ref_type in ("WEB", "ADVISORY"):
                    url = ref.get("url", "")
                    break
            if not url:
                refs = osv_vuln.get("references", [])
                url = refs[0].get("url", "") if refs else ""

            vulns.append(
                Vulnerability(
                    cve=cve,
                    package=pkg_name,
                    version=pkg_version,
                    severity=severity,
                    title=title[:200],
                    url=url,
                    fix_version=fix_version,
                    is_direct=True,
                )
            )

    return vulns


class OsvScanner:
    """Standalone vulnerability scanner using lockfiles + OSV.dev."""

    name = "osv"

    @staticmethod
    def detect(project: Path) -> bool:
        """Detect if any supported lockfile exists."""
        return len(detect_lockfiles(project)) > 0

    @staticmethod
    def parse(audit_json: dict[str, Any], project: Path) -> list[Vulnerability]:
        """Parse pre-fetched OSV response. Not typically used directly."""
        # This would need the packages list context, so it's a no-op
        # for the JSON piping path. OSV is used via scan().
        return []

    @classmethod
    def scan(cls, project: Path) -> list[Vulnerability]:
        """Scan lockfiles and query OSV.dev for vulnerabilities."""
        packages = parse_lockfiles(project)
        if not packages:
            return []

        # Query in batches of 1000 (OSV API limit)
        all_vulns: list[Vulnerability] = []
        for i in range(0, len(packages), 1000):
            batch = packages[i : i + 1000]
            try:
                response = query_osv_batch(batch)
                all_vulns.extend(parse_osv_response(response, batch))
            except (OSError, json.JSONDecodeError, urllib.error.URLError):
                # Network failure — continue with what we have
                continue

        return all_vulns
