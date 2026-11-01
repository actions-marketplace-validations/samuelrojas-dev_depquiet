"""Parse npm audit JSON output into Vulnerability objects.

npm audit --json returns a structure like:
{
  "vulnerabilities": {
    "<package>": {
      "name": "...",
      "severity": "high",
      "isDirect": true,
      "via": [
        { "source": 1234, "name": "...", "title": "...", "url": "...", "severity": "high",
          "cwe": [...], "cvss": {...}, "range": "..." }
        or just a string (transitive reference)
      ],
      "effects": [...],
      "range": "...",
      "fixAvailable": true | { "name": "...", "version": "...", "isSemVerMajor": false }
    }
  }
}
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from depquiet.models import Severity, Vulnerability


def _read_package_json(project: Path) -> dict:
    """Read package.json to determine devDependencies."""
    pkg = project / "package.json"
    if pkg.exists():
        return json.loads(pkg.read_text())
    return {}


def _get_dev_packages(pkg_json: dict) -> set[str]:
    """Extract devDependency names from package.json."""
    return set(pkg_json.get("devDependencies", {}).keys())


class NpmAuditParser:
    """Parse npm audit --json output."""

    name = "npm"

    @staticmethod
    def detect(project: Path) -> bool:
        """Check if this is an npm project."""
        return (project / "package-lock.json").exists() or (project / "yarn.lock").exists()

    @staticmethod
    def run_audit(project: Path) -> dict:
        """Run npm audit and return JSON output."""
        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                cwd=project,
                capture_output=True,
                text=True,
                timeout=120,
            )
            # npm audit exits non-zero when vulnerabilities are found, which is normal
            return json.loads(result.stdout) if result.stdout else {}
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            return {}

    @staticmethod
    def parse(audit_json: dict, project: Path) -> list[Vulnerability]:
        """Parse npm audit JSON into Vulnerability objects."""
        vulns: list[Vulnerability] = []
        pkg_json = _read_package_json(project)
        dev_packages = _get_dev_packages(pkg_json)
        seen: set[str] = set()

        raw_vulns = audit_json.get("vulnerabilities", {})
        for pkg_name, pkg_data in raw_vulns.items():
            severity = Severity.from_str(pkg_data.get("severity", "moderate"))
            is_direct = pkg_data.get("isDirect", False)
            is_dev = pkg_name in dev_packages

            via = pkg_data.get("via", [])
            for entry in via:
                if isinstance(entry, str):
                    # Transitive reference, skip (the source package has the real advisory)
                    continue

                cve = ""
                title = entry.get("title", "Unknown vulnerability")
                url = entry.get("url", "")
                source = entry.get("source", "")

                # Extract CVE from url (e.g. https://github.com/advisories/GHSA-xxxx)
                # or from title
                if url and "advisories" in url:
                    cve = url.rsplit("/", 1)[-1]
                if not cve and source:
                    cve = f"GHSA-{source}"

                key = f"{cve}:{pkg_name}"
                if key in seen:
                    continue
                seen.add(key)

                fix_available = pkg_data.get("fixAvailable", False)
                fix_version = ""
                if isinstance(fix_available, dict):
                    fix_version = fix_available.get("version", "")

                vulns.append(
                    Vulnerability(
                        cve=cve,
                        package=pkg_name,
                        version=entry.get("range", ""),
                        severity=severity,
                        title=title,
                        url=url,
                        fix_version=fix_version,
                        is_direct=is_direct,
                        is_dev=is_dev,
                        depth=0 if is_direct else 1,
                    )
                )

        return vulns

    @classmethod
    def scan(cls, project: Path) -> list[Vulnerability]:
        """Run audit and parse in one step."""
        audit_json = cls.run_audit(project)
        return cls.parse(audit_json, project)
