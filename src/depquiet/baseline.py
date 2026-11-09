"""Accepted priorities with explicit instance-v2 and legacy matching.

Version 2 accepts every exact eligible context within an explicit project scope.
Legacy saved scans retain advisory/package acceptance. Neither establishes
product impact. See docs/instance-baselines.md for creation and migration.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from depquiet.finding_identity import (
    FindingContext,
    bind_project_id,
    report_contexts,
    report_for_scan,
    validate_project_id,
)
from depquiet.models import DecisionChange, ScanResult, Verdict


@dataclass
class BaselineResult:
    """Result of applying a baseline to a scan."""

    total_before: int
    total_after: int
    new_findings: int
    known_findings: int


@dataclass(frozen=True)
class InstanceBaseline:
    """Accepted, project-scoped finding contexts from a version 2 baseline."""

    project_id: str
    accepted: frozenset[str]
    reason: str = ""
    author: str = ""
    source_scan_sha256: str = ""
    source_scan_hash_kind: str = "canonical_json"


class ScopedLegacyBaseline(set[str]):
    """Legacy advisory/package acceptance with an explicitly declared scope."""

    def __init__(self, keys: Iterable[str], *, project_id: str) -> None:
        super().__init__(keys)
        self.project_id = validate_project_id(project_id)


def _text(value: Any, field: str, *, nonempty: bool = False) -> str:
    if not isinstance(value, str) or (nonempty and not value.strip()):
        raise ValueError(
            f"Invalid baseline: {field} must be a string" + (" (nonempty)" if nonempty else "")
        )
    return value


def _source_hash(value: Any) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[a-fA-F0-9]{64}", value) is None:
        raise ValueError("Invalid baseline: source_scan_sha256 must be a SHA-256 hex digest")
    return value.lower()


def _hash_kind(value: Any) -> str:
    if not isinstance(value, str) or value not in {"canonical_json", "file_bytes"}:
        raise ValueError(
            "Invalid baseline: source_scan_hash_kind must be canonical_json or file_bytes"
        )
    return value


def _unaccepted_reason(context: FindingContext, row: dict[str, Any]) -> str:
    components = row.get("components", [])
    if components and all(
        component.get("range_match") == "not_matched" for component in components
    ):
        return (
            "No resolved candidate matches the advisory range; there is no accept-eligible context."
        )
    if context.kind != "component":
        return "Reported or unresolved findings do not identify an accept-eligible component."
    if row.get("component_resolution_complete") is not True:
        return "Component resolution is incomplete; the finding remains visible."
    return "Advisory range comparison is unknown; the finding remains visible."


def create_baseline(
    report: dict[str, Any],
    *,
    project_id: str | None = None,
    reason: str = "",
    author: str = "",
    source_scan_sha256: str = "",
    source_scan_hash_kind: str = "file_bytes",
) -> dict[str, Any]:
    """Create an instance baseline without accepting unresolved scan context.

    The optional source digest refers to the original report bytes. Without
    one, the digest covers this complete report serialized as canonical JSON;
    the hash-kind field makes that distinction explicit.
    """
    if not isinstance(report, dict) or report.get("scanned") is not True:
        raise ValueError("Cannot create an instance baseline from an incomplete scan")
    scope = bind_project_id(report, project_id)
    reason = _text(reason, "reason")
    author = _text(author, "author")
    hash_kind = _hash_kind(source_scan_hash_kind)
    source_scan_sha256 = _text(source_scan_sha256, "source_scan_sha256")
    if source_scan_sha256:
        source_hash = _source_hash(source_scan_sha256)
    else:
        raw = json.dumps(
            report, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
        source_hash = hashlib.sha256(raw).hexdigest()
        hash_kind = "canonical_json"

    accepted: list[dict[str, Any]] = []
    unaccepted: list[dict[str, Any]] = []
    for context, row in report_contexts(report, project_id=scope):
        if context.accept_eligible and context.component is not None:
            accepted.append(
                {
                    "context_id": context.context_id,
                    "advisory": context.advisory,
                    "package": context.package,
                    "advisory_range": context.advisory_range,
                    "component": context.component.to_dict(),
                }
            )
        else:
            unaccepted.append({**context.to_dict(), "reason": _unaccepted_reason(context, row)})
    return {
        "baseline_schema_version": 2,
        "project_id": scope,
        "accepted": accepted,
        "unaccepted": unaccepted,
        "reason": reason,
        "author": author,
        "source_scan_sha256": source_hash,
        "source_scan_hash_kind": hash_kind,
    }


def _load_instance_baseline(data: dict[str, Any]) -> InstanceBaseline:
    scope = bind_project_id(data)
    reason = _text(data.get("reason"), "reason")
    author = _text(data.get("author"), "author")
    source_hash = _source_hash(data.get("source_scan_sha256"))
    hash_kind = _hash_kind(data.get("source_scan_hash_kind"))
    entries = data.get("accepted")
    unaccepted = data.get("unaccepted")
    if not isinstance(entries, list) or not isinstance(unaccepted, list):
        raise ValueError("Invalid baseline: accepted and unaccepted must be arrays")
    for entry in unaccepted:
        if not isinstance(entry, dict):
            raise ValueError("Invalid baseline: unaccepted entries must be objects")
        _text(entry.get("reason"), "unaccepted reason", nonempty=True)

    accepted: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Invalid baseline: accepted entries must be objects")
        context_id = _text(entry.get("context_id"), "context_id", nonempty=True)
        advisory = _text(entry.get("advisory"), "advisory", nonempty=True)
        package = _text(entry.get("package"), "package", nonempty=True)
        advisory_range = _text(entry.get("advisory_range"), "advisory_range", nonempty=True)
        component = entry.get("component")
        if not isinstance(component, dict) or not isinstance(component.get("instance_id"), str):
            raise ValueError("Invalid baseline: accepted component requires its instance ID")
        synthetic = {
            "project_id": scope,
            "package_manager": "npm",
            "scanned": True,
            "results": [
                {
                    "cve": advisory,
                    "package": package,
                    "version": advisory_range,
                    "version_kind": "advisory_range",
                    "advisory_range": advisory_range,
                    "components": [component],
                    "component_resolution_complete": True,
                    "verdict": "action",
                }
            ],
        }
        contexts = report_contexts(synthetic, project_id=scope)
        if (
            len(contexts) != 1
            or not contexts[0][0].accept_eligible
            or contexts[0][0].context_id != context_id
        ):
            raise ValueError("Invalid baseline: accepted context ID or component is inconsistent")
        if context_id in accepted:
            raise ValueError("Invalid baseline: duplicate accepted context ID")
        accepted.add(context_id)
    return InstanceBaseline(scope, frozenset(accepted), reason, author, source_hash, hash_kind)


def load_baseline(path: Path) -> set[str] | InstanceBaseline:
    """Load a legacy advisory/package set or a validated instance baseline.

    Version 2 IDs are recomputed from their component fields and project
    scope. Legacy depquiet scan files keep their advisory/package semantics.
    """
    duplicate_keys: list[str] = []
    nonfinite_constants: list[str] = []

    def unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                duplicate_keys.append(key)
            result[key] = value
        return result

    def record_constant(value: str) -> float:
        nonfinite_constants.append(value)
        return float(value)

    data = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=unique_keys,
        parse_constant=record_constant,
    )
    if not isinstance(data, dict):
        raise ValueError("Invalid baseline: expected a JSON object")
    if "baseline_schema_version" in data:
        version = data["baseline_schema_version"]
        if isinstance(version, bool) or not isinstance(version, int) or version != 2:
            raise ValueError("Invalid baseline: unsupported baseline_schema_version")
        if duplicate_keys:
            raise ValueError("Invalid baseline: duplicate JSON keys")
        if nonfinite_constants:
            raise ValueError("Invalid baseline: non-finite JSON constants")
        return _load_instance_baseline(data)
    if "accepted" in data or "unaccepted" in data:
        raise ValueError("Invalid baseline: instance acceptance requires baseline_schema_version")
    if "project_id" in data and duplicate_keys:
        raise ValueError("Invalid baseline: duplicate JSON keys in a project-scoped report")

    keys: set[str] = set()
    for result in data.get("results", []):
        cve = result.get("cve", "")
        package = result.get("package", "")
        if cve and package:
            keys.add(f"{cve}:{package}")
    if data.get("project_id", "") != "":
        return ScopedLegacyBaseline(keys, project_id=data["project_id"])
    return keys


def apply_baseline(
    result: ScanResult,
    baseline_keys: set[str] | InstanceBaseline,
    *,
    source_path: str = "",
) -> BaselineResult:
    """Demote ACTION/REVIEW priorities accepted by the baseline to FILTERED.

    Legacy sets match advisory/package. Version 2 requires complete eligible
    contexts and acceptance of every context in a finding's project scope.
    Neither form establishes product impact.

    Returns a BaselineResult with counts for reporting.
    """
    total_before = len(result.action) + len(result.review)
    known = 0

    if isinstance(baseline_keys, ScopedLegacyBaseline):
        scope = validate_project_id(result.project_id)
        if scope != validate_project_id(baseline_keys.project_id):
            raise ValueError("Legacy baseline project_id must match the explicitly scoped scan")

    accepted_rows: dict[int, list[str]] = {}
    if isinstance(baseline_keys, InstanceBaseline):
        if not result.scanned:
            raise ValueError("Cannot apply an instance baseline to an incomplete scan")
        report = report_for_scan(result)
        if not report.get("project_id") or report["project_id"] != baseline_keys.project_id:
            raise ValueError("Instance baseline project_id must match the explicitly scoped scan")
        bind_project_id(report, baseline_keys.project_id)
        # Validate every row before changing any verdict. A malformed later row
        # must never leave an earlier finding suppressed after an exception.
        contexts = report_contexts(report, project_id=baseline_keys.project_id)
        by_row: dict[int, list[FindingContext]] = {}
        for context, row in contexts:
            by_row.setdefault(id(row), []).append(context)
        for index, row in enumerate(report["results"]):
            row_contexts = by_row.get(id(row), [])
            if row_contexts and all(
                context.accept_eligible and context.context_id in baseline_keys.accepted
                for context in row_contexts
            ):
                accepted_rows[index] = [context.context_id for context in row_contexts]

    for index, tr in enumerate(result.results):
        if isinstance(baseline_keys, InstanceBaseline):
            matched = index in accepted_rows
            rule_id = "baseline:v2:" + ",".join(accepted_rows.get(index, []))
            reason = "Finding priority accepted for every exact project-scoped baseline v2 context."
            if baseline_keys.reason:
                reason += " " + baseline_keys.reason
            author = baseline_keys.author
        else:
            matched = tr.vuln.key in baseline_keys
            rule_id = tr.vuln.key
            reason = "Finding matches the accepted baseline by advisory and package."
            author = ""
        if tr.verdict in (Verdict.ACTION, Verdict.REVIEW) and matched:
            tr.decision_trace.append(
                DecisionChange(
                    source="baseline",
                    previous_verdict=tr.verdict,
                    verdict=Verdict.FILTERED,
                    rule_id=rule_id,
                    reason=reason,
                    path=source_path,
                    author=author,
                )
            )
            tr.verdict = Verdict.FILTERED
            known += 1

    total_after = len(result.action) + len(result.review)
    new_findings = total_after

    return BaselineResult(
        total_before=total_before,
        total_after=total_after,
        new_findings=new_findings,
        known_findings=known,
    )
