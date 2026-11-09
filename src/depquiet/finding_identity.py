"""Project-scoped finding contexts shared by instance baselines and diffs.

Component identity is lockfile evidence, not installation or product impact.
Unresolved associations remain explicit and cannot become v2 acceptances.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from depquiet.models import ComponentEvidence, ScanResult


def validate_project_id(value: Any) -> str:
    """Validate an explicit stable scope without inferring repository ownership."""
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 256
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ValueError(
            "project_id must be a nonempty stable identifier without control characters"
        )
    return value


def bind_project_id(report: dict[str, Any], explicit: str | None = None) -> str:
    """Bind missing scope explicitly; a declared scope cannot be overridden."""
    declared = report.get("project_id", "")
    if declared != "":
        declared = validate_project_id(declared)
    supplied = validate_project_id(explicit) if explicit is not None else ""
    if declared and supplied and declared != supplied:
        raise ValueError("project_id conflicts with the report's declared project scope")
    scope = declared or supplied
    if not scope:
        raise ValueError("instance identities require project_id; supply --project-id or rescan")
    return scope


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _invalid_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON constant {value}")


def read_report(path: Path, *, require_complete: bool = True) -> dict[str, Any]:
    return parse_report(path.read_bytes(), require_complete=require_complete)


def parse_report(raw: bytes | str, *, require_complete: bool = True) -> dict[str, Any]:
    """Parse the same immutable bytes whose hash a caller records as provenance."""
    raw = json.loads(
        raw,
        object_pairs_hook=_unique_keys,
        parse_constant=_invalid_constant,
    )
    if not isinstance(raw, dict):
        raise ValueError("scan report must be a JSON object")
    _validate_report(raw, require_complete=require_complete)
    return raw


def _validate_report(report: dict[str, Any], *, require_complete: bool = True) -> None:
    if "scanned" in report and type(report["scanned"]) is not bool:
        raise ValueError("scan.scanned must be a boolean")
    if report.get("scanned") is False or (require_complete and report.get("scanned") is not True):
        raise ValueError("instance identities require a complete scan with scanned: true")
    if not isinstance(report.get("results"), list):
        raise ValueError("scan.results must be an array")


def _text(value: Any, name: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value.strip()):
        raise ValueError(f"{name} must be a {'possibly empty' if empty else 'nonempty'} string")
    return value


def validate_finding(row: Any) -> dict[str, Any]:
    if not isinstance(row, dict):
        raise ValueError("finding must be a JSON object")
    _text(row.get("cve"), "finding.cve")
    _text(row.get("package"), "finding.package")
    _text(row.get("version", ""), "finding.version", empty=True)
    if row.get("verdict") not in ("action", "review", "filtered"):
        raise ValueError("finding.verdict must be action, review or filtered")
    for key in ("severity", "title", "fix_version", "fix_package"):
        if key in row:
            _text(row[key], f"finding.{key}", empty=True)
    score = row.get("epss_score")
    if score is not None:
        try:
            valid = (
                isinstance(score, (int, float))
                and not isinstance(score, bool)
                and math.isfinite(score)
            )
        except OverflowError:
            valid = False
        if not valid:
            raise ValueError("finding.epss_score must be a finite number or null")
    return row


def _digest(value: Any) -> str:
    raw = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class FindingContext:
    context_id: str
    project_id: str
    advisory: str
    package: str
    version: str
    kind: str
    instance_id: str = ""
    location: str = ""
    lockfile: str = ""
    advisory_range: str = ""
    range_match: str = ""
    accept_eligible: bool = False
    component: ComponentEvidence | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "context_id": self.context_id,
            "project_id": self.project_id,
            "advisory": self.advisory,
            "package": self.package,
            "version": self.version,
            "kind": self.kind,
            "instance_id": self.instance_id,
            "location": self.location,
            "lockfile": self.lockfile,
            "advisory_range": self.advisory_range,
            "range_match": self.range_match,
            "accept_eligible": self.accept_eligible,
        }
        if self.component is not None:
            data["component"] = self.component.to_dict()
        return data


def finding_contexts(
    row: dict[str, Any], project_id: str, *, package_manager: str = ""
) -> list[FindingContext]:
    """Expand observed candidates; uncertainty gets a context, never an instance."""
    validate_finding(row)
    scope = validate_project_id(project_id)
    advisory, package = row["cve"], row["package"]
    version = row.get("version", "")
    kind = row.get("version_kind", "reported")
    if kind not in ("reported", "advisory_range"):
        raise ValueError("finding.version_kind is unsupported")
    base: dict[str, Any] = {"project_id": scope, "advisory": advisory, "package": package}
    if kind == "reported":
        if package_manager == "npm" and "version_kind" not in row:
            raise ValueError(
                "npm instance mode requires explicit version semantics or component evidence; "
                "rescan or use legacy identities"
            )
        identity = {
            **base,
            "kind": "reported",
            "package_manager": package_manager,
            "version": version,
        }
        return [
            FindingContext(
                "finding-sha256:" + _digest(identity), scope, advisory, package, version, "reported"
            )
        ]

    advisory_range = _text(row.get("advisory_range", version), "finding.advisory_range", empty=True)
    if advisory_range != version:
        raise ValueError("advisory_range conflicts with the reported npm version context")
    complete = row.get("component_resolution_complete", False)
    if type(complete) is not bool:
        raise ValueError("component_resolution_complete must be a boolean")
    raw_components = row.get("components", [])
    notes = row.get("component_notes", [])
    if (
        not isinstance(raw_components, list)
        or not isinstance(notes, list)
        or not all(isinstance(note, str) for note in notes)
    ):
        raise ValueError("component evidence and notes must be arrays")
    components = [ComponentEvidence.from_dict(raw) for raw in raw_components]
    seen: set[str] = set()
    for component in components:
        if component.package != package or component.ecosystem != "npm":
            raise ValueError("component identity conflicts with the finding package/ecosystem")
        if component.instance_id in seen:
            raise ValueError("duplicate component instance identity in finding")
        seen.add(component.instance_id)
    associated = [component for component in components if component.range_match != "not_matched"]
    eligible = (
        complete
        and bool(associated)
        and bool(advisory_range)
        and all(component.range_match == "matched" for component in associated)
    )
    contexts: list[FindingContext] = []
    for component in associated:
        identity = {
            **base,
            "kind": "component",
            "instance_id": component.instance_id,
            "advisory_range": advisory_range,
            "range_match": component.range_match,
        }
        contexts.append(
            FindingContext(
                context_id="finding-sha256:" + _digest(identity),
                project_id=scope,
                advisory=advisory,
                package=package,
                version=component.version,
                kind="component",
                instance_id=component.instance_id,
                location=component.location,
                lockfile=component.lockfile,
                advisory_range=advisory_range,
                range_match=component.range_match,
                accept_eligible=eligible,
                component=component,
            )
        )
    if not complete or not associated:
        evidence = {
            "component_resolution_complete": complete,
            "components": sorted(
                (component.instance_id, component.range_match) for component in components
            ),
            "component_notes": sorted(notes),
        }
        identity = {
            **base,
            "kind": "unresolved",
            "advisory_range": advisory_range,
            "evidence": evidence,
        }
        contexts.append(
            FindingContext(
                context_id="finding-sha256:" + _digest(identity),
                project_id=scope,
                advisory=advisory,
                package=package,
                version="",
                kind="unresolved",
                advisory_range=advisory_range,
                range_match="unknown",
            )
        )
    return contexts


def report_contexts(
    report: dict[str, Any], *, project_id: str | None = None
) -> list[tuple[FindingContext, dict[str, Any]]]:
    _validate_report(report)
    scope = bind_project_id(report, project_id)
    manager = _text(report.get("package_manager", ""), "package_manager", empty=True)
    contexts: list[tuple[FindingContext, dict[str, Any]]] = []
    seen: set[str] = set()
    for row in report["results"]:
        for context in finding_contexts(row, scope, package_manager=manager):
            if context.context_id in seen:
                raise ValueError("duplicate finding context identity in scan")
            seen.add(context.context_id)
            contexts.append((context, row))
    return contexts


def report_for_scan(result: ScanResult) -> dict[str, Any]:
    return {
        "scanned": result.scanned,
        "project_id": result.project_id,
        "package_manager": result.package_manager,
        "results": [
            {
                "cve": finding.vuln.cve,
                "package": finding.vuln.package,
                "version": finding.vuln.version,
                "verdict": finding.verdict.value,
                "version_kind": finding.vuln.version_kind,
                "advisory_range": finding.vuln.advisory_range,
                "components": [component.to_dict() for component in finding.vuln.components],
                "component_notes": list(finding.vuln.component_notes),
                "component_resolution_complete": finding.vuln.component_resolution_complete,
            }
            for finding in result.results
        ],
    }
