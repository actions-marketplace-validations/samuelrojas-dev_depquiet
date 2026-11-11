"""License compliance analysis — detect OSS license risk in dependencies.

Classifies dependency licenses into risk categories and flags copyleft
contamination in proprietary projects. Supports npm (package.json) and
pip (importlib.metadata) ecosystems.

Usage::

    depquiet --license              # scan + license report
    depquiet --license --json       # machine-readable output
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class LicenseRisk(Enum):
    """License risk level for enterprise compliance."""

    LOW = "low"  # MIT, BSD, Apache-2.0, ISC, Unlicense
    MEDIUM = "medium"  # LGPL, MPL, EPL, CDDL (weak copyleft)
    HIGH = "high"  # GPL-2.0, GPL-3.0 (strong copyleft)
    CRITICAL = "critical"  # AGPL, SSPL, BUSL (network copyleft / source-available)
    UNKNOWN = "unknown"  # Unrecognized or missing license


# SPDX ID -> risk mapping.  Covers the most common ~60 licenses.
_LICENSE_RISK: dict[str, LicenseRisk] = {
    # -- LOW (permissive) --
    "MIT": LicenseRisk.LOW,
    "ISC": LicenseRisk.LOW,
    "BSD-2-Clause": LicenseRisk.LOW,
    "BSD-3-Clause": LicenseRisk.LOW,
    "Apache-2.0": LicenseRisk.LOW,
    "Unlicense": LicenseRisk.LOW,
    "0BSD": LicenseRisk.LOW,
    "CC0-1.0": LicenseRisk.LOW,
    "Zlib": LicenseRisk.LOW,
    "BSL-1.0": LicenseRisk.LOW,
    "PSF-2.0": LicenseRisk.LOW,
    "Python-2.0": LicenseRisk.LOW,
    "BlueOak-1.0.0": LicenseRisk.LOW,
    "Artistic-2.0": LicenseRisk.LOW,
    "CC-BY-4.0": LicenseRisk.LOW,
    "CC-BY-3.0": LicenseRisk.LOW,
    "WTFPL": LicenseRisk.LOW,
    # -- MEDIUM (weak copyleft) --
    "LGPL-2.1": LicenseRisk.MEDIUM,
    "LGPL-2.1-only": LicenseRisk.MEDIUM,
    "LGPL-2.1-or-later": LicenseRisk.MEDIUM,
    "LGPL-3.0": LicenseRisk.MEDIUM,
    "LGPL-3.0-only": LicenseRisk.MEDIUM,
    "LGPL-3.0-or-later": LicenseRisk.MEDIUM,
    "MPL-2.0": LicenseRisk.MEDIUM,
    "EPL-1.0": LicenseRisk.MEDIUM,
    "EPL-2.0": LicenseRisk.MEDIUM,
    "CDDL-1.0": LicenseRisk.MEDIUM,
    "CDDL-1.1": LicenseRisk.MEDIUM,
    "CPL-1.0": LicenseRisk.MEDIUM,
    "CC-BY-SA-4.0": LicenseRisk.MEDIUM,
    "CC-BY-SA-3.0": LicenseRisk.MEDIUM,
    # -- HIGH (strong copyleft) --
    "GPL-2.0": LicenseRisk.HIGH,
    "GPL-2.0-only": LicenseRisk.HIGH,
    "GPL-2.0-or-later": LicenseRisk.HIGH,
    "GPL-3.0": LicenseRisk.HIGH,
    "GPL-3.0-only": LicenseRisk.HIGH,
    "GPL-3.0-or-later": LicenseRisk.HIGH,
    # -- CRITICAL (network copyleft / source-available) --
    "AGPL-3.0": LicenseRisk.CRITICAL,
    "AGPL-3.0-only": LicenseRisk.CRITICAL,
    "AGPL-3.0-or-later": LicenseRisk.CRITICAL,
    "SSPL-1.0": LicenseRisk.CRITICAL,
    "BUSL-1.1": LicenseRisk.CRITICAL,
    "Elastic-2.0": LicenseRisk.CRITICAL,
    "Commons-Clause": LicenseRisk.CRITICAL,
}

# Common non-SPDX license strings -> normalized SPDX ID
_LICENSE_ALIASES: dict[str, str] = {
    "mit": "MIT",
    "isc": "ISC",
    "bsd": "BSD-3-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "apache 2.0": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "gpl-2.0": "GPL-2.0",
    "gpl-3.0": "GPL-3.0",
    "gplv2": "GPL-2.0",
    "gplv3": "GPL-3.0",
    "gnu general public license v2": "GPL-2.0",
    "gnu general public license v3": "GPL-3.0",
    "lgpl-2.1": "LGPL-2.1",
    "lgpl-3.0": "LGPL-3.0",
    "lgplv2.1": "LGPL-2.1",
    "lgplv3": "LGPL-3.0",
    "agpl-3.0": "AGPL-3.0",
    "mpl-2.0": "MPL-2.0",
    "unlicense": "Unlicense",
    "public domain": "Unlicense",
    "cc0-1.0": "CC0-1.0",
    "python software foundation license": "PSF-2.0",
    "psf": "PSF-2.0",
    "artistic-2.0": "Artistic-2.0",
    "0bsd": "0BSD",
    "wtfpl": "WTFPL",
    "zlib": "Zlib",
}


@dataclass
class LicenseInfo:
    """License information for a single package."""

    package: str
    version: str
    license_id: str  # SPDX ID or raw string
    license_raw: str  # Original string from the package manager
    risk: LicenseRisk


@dataclass
class LicenseReport:
    """Aggregate license compliance report."""

    packages: list[LicenseInfo] = field(default_factory=list)
    project_path: str = ""
    package_manager: str = ""

    @property
    def low(self) -> list[LicenseInfo]:
        return [p for p in self.packages if p.risk == LicenseRisk.LOW]

    @property
    def medium(self) -> list[LicenseInfo]:
        return [p for p in self.packages if p.risk == LicenseRisk.MEDIUM]

    @property
    def high(self) -> list[LicenseInfo]:
        return [p for p in self.packages if p.risk == LicenseRisk.HIGH]

    @property
    def critical(self) -> list[LicenseInfo]:
        return [p for p in self.packages if p.risk == LicenseRisk.CRITICAL]

    @property
    def unknown(self) -> list[LicenseInfo]:
        return [p for p in self.packages if p.risk == LicenseRisk.UNKNOWN]

    @property
    def has_issues(self) -> bool:
        """True if any HIGH, CRITICAL, or UNKNOWN licenses found."""
        return bool(self.high or self.critical or self.unknown)


_RISK_ORDER = [
    LicenseRisk.LOW,
    LicenseRisk.MEDIUM,
    LicenseRisk.HIGH,
    LicenseRisk.CRITICAL,
    LicenseRisk.UNKNOWN,
]


def classify_license(raw: str) -> tuple[str, LicenseRisk]:
    """Classify a license string into an SPDX ID and risk level.

    Handles SPDX expressions (e.g., "MIT OR Apache-2.0") by taking the
    most permissive option (lowest risk). For AND expressions, takes the
    most restrictive (highest risk).
    """
    if not raw or raw.strip().lower() in ("none", "unknown", "unlicensed", "custom"):
        return raw or "UNKNOWN", LicenseRisk.UNKNOWN

    stripped = raw.strip()

    # Try direct SPDX match first
    if stripped in _LICENSE_RISK:
        return stripped, _LICENSE_RISK[stripped]

    # Try alias lookup
    lower = stripped.lower()
    if lower in _LICENSE_ALIASES:
        spdx = _LICENSE_ALIASES[lower]
        return spdx, _LICENSE_RISK[spdx]

    # Handle SPDX OR expressions — pick lowest risk (most permissive)
    risk_order = _RISK_ORDER
    if " OR " in stripped:
        parts = [p.strip().strip("()") for p in stripped.split(" OR ")]
        best_id = stripped
        best_risk = LicenseRisk.UNKNOWN
        for part in parts:
            pid, prisk = classify_license(part)
            if risk_order.index(prisk) < risk_order.index(best_risk):
                best_id = pid
                best_risk = prisk
        return best_id, best_risk

    # Handle SPDX AND expressions — pick highest risk (most restrictive)
    if " AND " in stripped:
        parts = [p.strip().strip("()") for p in stripped.split(" AND ")]
        worst_id = stripped
        worst_risk = LicenseRisk.LOW
        for part in parts:
            pid, prisk = classify_license(part)
            if risk_order.index(prisk) > risk_order.index(worst_risk):
                worst_id = pid
                worst_risk = prisk
        return worst_id, worst_risk

    return stripped, LicenseRisk.UNKNOWN


def scan_npm_licenses(project: Path) -> list[LicenseInfo]:
    """Extract license info from npm dependencies."""
    package_json = project / "package.json"
    if not package_json.exists():
        return []

    node_modules = project / "node_modules"
    if not node_modules.exists():
        return []

    results: list[LicenseInfo] = []

    for pkg_dir in sorted(node_modules.iterdir()):
        if pkg_dir.name.startswith("."):
            continue

        # Handle scoped packages (@scope/name)
        if pkg_dir.name.startswith("@") and pkg_dir.is_dir():
            for scoped_dir in sorted(pkg_dir.iterdir()):
                info = _read_npm_package_license(scoped_dir, f"{pkg_dir.name}/{scoped_dir.name}")
                if info:
                    results.append(info)
        else:
            info = _read_npm_package_license(pkg_dir, pkg_dir.name)
            if info:
                results.append(info)

    return results


def _read_npm_package_license(pkg_dir: Path, name: str) -> LicenseInfo | None:
    """Read license from a single npm package's package.json."""
    pkg_json = pkg_dir / "package.json"
    if not pkg_json.exists():
        return None

    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None

    version = data.get("version", "0.0.0")
    raw_license = ""

    # npm supports both "license" (string) and "licenses" (array of objects)
    if "license" in data:
        lic = data["license"]
        if isinstance(lic, str):
            raw_license = lic
        elif isinstance(lic, dict):
            raw_license = lic.get("type", "")
    elif "licenses" in data:
        lics = data["licenses"]
        if isinstance(lics, list):
            parts = []
            for item in lics:
                if isinstance(item, dict) and "type" in item:
                    parts.append(item["type"])
                elif isinstance(item, str):
                    parts.append(item)
            raw_license = " OR ".join(parts) if parts else ""

    if not raw_license:
        raw_license = "UNKNOWN"

    license_id, risk = classify_license(raw_license)
    return LicenseInfo(
        package=name,
        version=version,
        license_id=license_id,
        license_raw=raw_license,
        risk=risk,
    )


def scan_pip_licenses(project: Path) -> list[LicenseInfo]:
    """Extract license info from pip dependencies using pip list + importlib.metadata."""
    results: list[LicenseInfo] = []

    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=json"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=project,
        )
        if proc.returncode != 0:
            return []
        packages = json.loads(proc.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        return []

    for pkg in packages:
        name = pkg.get("name", "")
        version = pkg.get("version", "0.0.0")
        if not name:
            continue

        # Get license from metadata
        raw_license = _get_pip_license(name)
        license_id, risk = classify_license(raw_license)
        results.append(
            LicenseInfo(
                package=name,
                version=version,
                license_id=license_id,
                license_raw=raw_license,
                risk=risk,
            )
        )

    return results


def _get_pip_license(package_name: str) -> str:
    """Get license string for a pip package via importlib.metadata."""
    try:
        from importlib.metadata import metadata as get_metadata

        meta = get_metadata(package_name)
        # Try License field first
        # get_all() returns None for a missing key; meta["License"] is
        # deprecated for missing keys and will raise KeyError in future Pythons.
        lic = (meta.get_all("License") or [""])[0] or ""
        if lic and lic.strip().lower() not in ("unknown", "", "none"):
            return str(lic.strip())

        # Fall back to classifiers
        classifiers = meta.get_all("Classifier") or []
        for c in classifiers:
            if c.startswith("License :: OSI Approved :: "):
                return _classifier_to_spdx(c)

        return "UNKNOWN"
    except Exception:
        return "UNKNOWN"


def _classifier_to_spdx(classifier: str) -> str:
    """Convert a PyPI classifier to an approximate SPDX ID."""
    mapping: dict[str, str] = {
        "MIT License": "MIT",
        "BSD License": "BSD-3-Clause",
        "Apache Software License": "Apache-2.0",
        "ISC License (ISCL)": "ISC",
        "GNU General Public License v2 (GPLv2)": "GPL-2.0",
        "GNU General Public License v2 or later (GPLv2+)": "GPL-2.0-or-later",
        "GNU General Public License v3 (GPLv3)": "GPL-3.0",
        "GNU General Public License v3 or later (GPLv3+)": "GPL-3.0-or-later",
        "GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.1",
        "GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.1-or-later",
        "GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0",
        "GNU Lesser General Public License v3 or later (LGPLv3+)": "LGPL-3.0-or-later",
        "GNU Affero General Public License v3": "AGPL-3.0",
        "GNU Affero General Public License v3 or later (AGPLv3+)": "AGPL-3.0-or-later",
        "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
        "Eclipse Public License 1.0 (EPL-1.0)": "EPL-1.0",
        "Eclipse Public License 2.0 (EPL-2.0)": "EPL-2.0",
        "The Unlicense (Unlicense)": "Unlicense",
        "Public Domain": "Unlicense",
        "Python Software Foundation License": "PSF-2.0",
        "Artistic License": "Artistic-2.0",
        "Zlib License": "Zlib",
    }
    suffix = classifier.replace("License :: OSI Approved :: ", "")
    return mapping.get(suffix, suffix)


def scan_licenses(project: Path, package_manager: str | None = None) -> LicenseReport:
    """Run a license scan on a project.

    Args:
        project: Path to the project root.
        package_manager: Force a specific package manager ("npm" or "pip").
                        Auto-detects if None.

    Returns:
        LicenseReport with all dependency license info.
    """
    pm = package_manager

    if pm is None:
        if (project / "package.json").exists():
            pm = "npm"
        elif any(
            (project / f).exists() for f in ("requirements.txt", "setup.py", "pyproject.toml")
        ):
            pm = "pip"
        else:
            pm = "unknown"

    # "npm+pip" from a scan that merged ecosystems: report each one's licenses.
    packages = []
    for manager in pm.split("+"):
        if manager in ("npm", "pnpm"):
            packages += scan_npm_licenses(project)
        elif manager == "pip":
            packages += scan_pip_licenses(project)

    return LicenseReport(
        packages=packages,
        project_path=str(project),
        package_manager=pm,
    )


def print_license_report(report: LicenseReport) -> None:
    """Print a human-readable license compliance report to stderr."""
    if not report.packages:
        print("\nNo dependencies found for license analysis.", file=sys.stderr)
        return

    total = len(report.packages)
    print(f"\ndepquiet license scan — {report.package_manager} ({total} packages)", file=sys.stderr)
    print(file=sys.stderr)

    if report.critical:
        n = len(report.critical)
        print(f"  {n} CRITICAL (AGPL/SSPL/BUSL)", file=sys.stderr)
        for p in report.critical:
            print(f"     {p.package}@{p.version}  {p.license_id}", file=sys.stderr)
        print(file=sys.stderr)

    if report.high:
        print(f"  {len(report.high)} HIGH (GPL — strong copyleft)", file=sys.stderr)
        for p in report.high:
            print(f"     {p.package}@{p.version}  {p.license_id}", file=sys.stderr)
        print(file=sys.stderr)

    if report.medium:
        print(f"  {len(report.medium)} MEDIUM (LGPL/MPL — weak copyleft)", file=sys.stderr)
        for p in report.medium:
            print(f"     {p.package}@{p.version}  {p.license_id}", file=sys.stderr)
        print(file=sys.stderr)

    if report.unknown:
        print(f"  {len(report.unknown)} UNKNOWN (review manually)", file=sys.stderr)
        for p in report.unknown:
            raw = f"  ({p.license_raw})" if p.license_raw and p.license_raw != "UNKNOWN" else ""
            print(f"     {p.package}@{p.version}{raw}", file=sys.stderr)
        print(file=sys.stderr)

    print(f"  {len(report.low)} LOW (permissive — MIT, BSD, Apache, etc.)", file=sys.stderr)
    print(file=sys.stderr)

    if report.has_issues:
        print(
            "  License compliance: FAIL — review HIGH/CRITICAL/UNKNOWN packages above",
            file=sys.stderr,
        )
    else:
        print("  License compliance: PASS", file=sys.stderr)
