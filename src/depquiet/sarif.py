"""SARIF output — integrates with GitHub Code Scanning and VS Code.

SARIF (Static Analysis Results Interchange Format) is the universal format
for vulnerability findings. GitHub Code Scanning, VS Code, and most CI
tools can consume it.

We emit SARIF v2.1.0 with one run per scan. Each ACTION or REVIEW result
becomes a result; FILTERED items are omitted (that's the point).
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from depquiet import __version__
from depquiet.assessment import assess_finding, decision_trace_to_json
from depquiet.models import ScanResult, TriageResult, Verdict


def to_sarif(result: ScanResult) -> dict[str, Any]:
    """Convert a ScanResult to a SARIF v2.1.0 document."""
    if not result.scanned:
        raise ValueError("Cannot generate SARIF from an incomplete scan.")
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}

    actionable = [r for r in result.results if r.verdict != Verdict.FILTERED]

    for tr in actionable:
        vuln = tr.vuln
        rule_id = vuln.cve or f"{vuln.package}-{vuln.severity.value}"

        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            rule: dict[str, Any] = {
                "id": rule_id,
                "shortDescription": {"text": vuln.title or f"{vuln.package} {vuln.severity.value}"},
                "defaultConfiguration": {
                    "level": _severity_to_level(vuln.severity.value),
                },
            }
            if vuln.url:
                rule["helpUri"] = vuln.url
            rules.append(rule)

        sarif_result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_index[rule_id],
            "level": _severity_to_level(vuln.severity.value),
            "message": {
                "text": _build_message(tr),
            },
            "locations": _build_locations(tr, result.project_path, result.package_manager),
            "properties": {
                "assessment": assess_finding(tr).to_dict(),
                "evidence": asdict(tr.evidence),
                "decision_trace": decision_trace_to_json(tr),
            },
        }

        if tr.epss_score is not None:
            sarif_result.setdefault("properties", {})["epss_score"] = tr.epss_score

        if tr.kev_entry is not None:
            props = sarif_result.setdefault("properties", {})
            props["kev"] = True
            props["kev_date_added"] = tr.kev_entry.date_added
            props["kev_due_date"] = tr.kev_entry.due_date
            props["kev_ransomware_use"] = tr.kev_entry.ransomware_use

        results.append(sarif_result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "depquiet",
                        "version": __version__,
                        "informationUri": "https://github.com/samuelrojas-dev/depquiet",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(result: ScanResult, path: Path) -> None:
    """Write SARIF output to a file."""
    sarif = to_sarif(result)
    path.write_text(json.dumps(sarif, indent=2))


def _severity_to_level(severity: str) -> str:
    """Map vulnerability severity to SARIF level."""
    return {
        "critical": "error",
        "high": "error",
        "moderate": "warning",
        "low": "note",
        "info": "note",
    }.get(severity, "warning")


def _build_message(tr: TriageResult) -> str:
    """Build a human-readable message for a SARIF result."""
    vuln = tr.vuln
    parts = [f"{vuln.package}@{vuln.version}: {vuln.title or vuln.cve}"]

    if vuln.fix_version:
        parts.append(f"Fix: update to {vuln.fix_label}")

    if tr.epss_score is not None:
        parts.append(f"EPSS: {tr.epss_score:.1%}")

    if tr.kev_entry is not None:
        parts.append("⚠ CISA KEV: actively exploited")

    if tr.verdict == Verdict.REVIEW:
        parts.append("Verdict: REVIEW")
    else:
        parts.append("Verdict: ACTION REQUIRED")

    parts.append("Product impact remains under investigation")

    return " | ".join(parts)


def _build_locations(
    tr: TriageResult,
    project_path: str,
    package_manager: str = "npm",
) -> list[dict[str, Any]]:
    """Build SARIF locations from reachable imports or package files."""
    locations: list[dict[str, Any]] = []

    if tr.reachable_imports:
        for imp in tr.reachable_imports[:5]:
            # Make path relative to project
            try:
                rel = Path(imp).relative_to(project_path).as_posix()
            except ValueError:
                rel = imp
            locations.append(
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": rel},
                    }
                }
            )

    if not locations:
        # Default to package manifest
        pm_files = {
            "npm": "package.json",
            "pip": "requirements.txt",
        }
        manifest = pm_files.get(package_manager, "package.json")
        locations.append(
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": manifest},
                }
            }
        )

    return locations
