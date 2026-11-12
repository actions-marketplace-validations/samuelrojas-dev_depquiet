"""Parse ``uv audit --output-format json`` into Vulnerability objects.

uv (0.13+) audits a ``uv.lock`` against OSV.dev. Its JSON is marked preview
(``"schema": {"version": "preview"}``) and looks like this:

{
  "schema": {"version": "preview"},
  "summary": {"audited_packages": 231, "vulnerabilities": 16, "adverse_statuses": 1},
  "vulnerabilities": [
    {
      "dependency": {"name": "oauthlib", "version": "4.0.0"},
      "id": "GHSA-3jp2-3mrg-2vxc",
      "display_id": "GHSA-3jp2-3mrg-2vxc",
      "aliases": ["CVE-2026-49272"],
      "summary": "OAuthLib: Bearer token can be retrieved ...",
      "link": "https://github.com/oauthlib/oauthlib/security/advisories/...",
      "fix_versions": ["4.0.1"]
    }
  ],
  "adverse_statuses": [{"name": "rsa", "status": "archived", "reason": null}]
}

A finding names a package and a version, nothing about how it is reached:
``uv audit`` includes the default groups (``dev``) unless told otherwise. That
is the part depquiet adds, from the lockfile and the project's groups.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from depquiet.models import Severity, Vulnerability, nearest_fix


def is_uv_audit(audit_json: dict[str, Any]) -> bool:
    schema = audit_json.get("schema")
    findings = audit_json.get("vulnerabilities")
    return (
        isinstance(schema, dict)
        and "version" in schema
        and isinstance(findings, list)
        and all(isinstance(f, dict) and isinstance(f.get("dependency"), dict) for f in findings)
    )


def adverse_note(audit_json: dict[str, Any]) -> str:
    """``rsa (archived)``: packages uv flags without a vulnerability."""
    entries = audit_json.get("adverse_statuses")
    if not isinstance(entries, list):
        return ""
    flagged = [
        f"{e['name']} ({e['status']})"
        for e in entries
        if isinstance(e, dict)
        and isinstance(e.get("name"), str)
        and isinstance(e.get("status"), str)
    ]
    if not flagged:
        return ""
    return "uv audit also flags packages with an adverse status: " + ", ".join(flagged) + "."


class UvAuditParser:
    """Parse uv audit JSON output."""

    name = "uv"

    @staticmethod
    def detect(project: Path) -> bool:
        return (project / "uv.lock").exists()

    @staticmethod
    def parse(audit_json: dict[str, Any], project: Path) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        seen: set[tuple[str, str]] = set()
        for finding in audit_json.get("vulnerabilities") or []:
            if not isinstance(finding, dict):
                continue
            dependency = finding.get("dependency") or {}
            package = dependency.get("name")
            advisory = finding.get("id") or finding.get("display_id")
            if not isinstance(package, str) or not package or not isinstance(advisory, str):
                continue
            version = dependency.get("version")
            version = version if isinstance(version, str) else ""
            aliases = [a for a in finding.get("aliases") or [] if isinstance(a, str)]
            # The same advisory under another id (a GHSA and its PYSEC twin).
            if any((package, i) in seen for i in (advisory, *aliases)):
                continue
            seen.update((package, i) for i in (advisory, *aliases))
            fixes = [f for f in finding.get("fix_versions") or [] if isinstance(f, str)]
            summary = finding.get("summary")
            link = finding.get("link")
            vulns.append(
                Vulnerability(
                    cve=advisory,
                    package=package,
                    version=version,
                    # uv reports no severity yet.
                    severity=Severity.MODERATE,
                    title=summary[:120] if isinstance(summary, str) and summary else advisory,
                    url=link if isinstance(link, str) else "",
                    fix_version=nearest_fix(version, fixes),
                    is_direct=True,
                )
            )
        return vulns
