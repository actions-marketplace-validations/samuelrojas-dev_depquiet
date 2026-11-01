"""Parse pip-audit JSON output into Vulnerability objects.

pip-audit --format json returns:
{
  "dependencies": [
    {
      "name": "...",
      "version": "...",
      "vulns": [
        { "id": "CVE-...", "fix_versions": ["..."], "description": "..." }
      ]
    }
  ]
}
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from depquiet.models import Severity, Vulnerability


class PipAuditParser:
    """Parse pip-audit --format json output."""

    name = "pip"

    @staticmethod
    def detect(project: Path) -> bool:
        """Check if this is a Python project."""
        return (
            (project / "requirements.txt").exists()
            or (project / "pyproject.toml").exists()
            or (project / "Pipfile.lock").exists()
            or (project / "poetry.lock").exists()
        )

    @staticmethod
    def run_audit(project: Path) -> dict:
        """Run pip-audit and return JSON output."""
        try:
            result = subprocess.run(
                ["pip-audit", "--format", "json"],
                cwd=project,
                capture_output=True,
                text=True,
                timeout=120,
            )
            return json.loads(result.stdout) if result.stdout else {}
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            return {}

    @staticmethod
    def parse(audit_json: dict, project: Path) -> list[Vulnerability]:
        """Parse pip-audit JSON into Vulnerability objects."""
        vulns: list[Vulnerability] = []

        for dep in audit_json.get("dependencies", []):
            pkg_name = dep.get("name", "")
            pkg_version = dep.get("version", "")

            for vuln_entry in dep.get("vulns", []):
                cve = vuln_entry.get("id", "")
                fix_versions = vuln_entry.get("fix_versions", [])
                description = vuln_entry.get("description", "")

                # pip-audit doesn't provide severity in its JSON by default
                severity = Severity.MODERATE

                vulns.append(
                    Vulnerability(
                        cve=cve,
                        package=pkg_name,
                        version=pkg_version,
                        severity=severity,
                        title=description[:120] if description else cve,
                        fix_version=fix_versions[0] if fix_versions else "",
                        is_direct=True,
                    )
                )

        return vulns

    @classmethod
    def scan(cls, project: Path) -> list[Vulnerability]:
        """Run audit and parse in one step."""
        audit_json = cls.run_audit(project)
        return cls.parse(audit_json, project)
