"""Scan comparison — diff two depquiet scans to show what changed.

The diff module answers the PR-level question: "did this change introduce
new vulnerabilities or fix existing ones?" It compares two depquiet --json
outputs and categorizes each finding as new, fixed, unchanged, or changed.

This is the core of the CI review workflow:
1. Run depquiet on the base branch (or use a cached baseline)
2. Run depquiet on the PR branch
3. `depquiet diff base.json head.json` shows only what changed
"""

from __future__ import annotations

import contextlib
import json
import math
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, TypeVar

from depquiet.finding_identity import (
    FindingContext,
    bind_project_id,
    report_contexts,
    validate_project_id,
)

_FindingKey = TypeVar("_FindingKey", str, tuple[str, str, str])


@dataclass
class DiffFinding:
    """A single finding in the diff output."""

    cve: str
    package: str
    version: str
    severity: str
    title: str
    verdict: str
    # Only set when the finding changed verdict between base and head
    previous_verdict: str | None = None
    epss_score: float | None = None
    fix_version: str = ""
    instance_id: str = ""
    context_id: str = ""
    identity_kind: str = ""
    location: str = ""
    lockfile: str = ""
    advisory_range: str = ""
    range_match: str = ""

    @property
    def key(self) -> str:
        return f"{self.cve}:{self.package}"


@dataclass
class ScanDiff:
    """Result of comparing two scans."""

    new: list[DiffFinding] = field(default_factory=list)
    fixed: list[DiffFinding] = field(default_factory=list)
    changed: list[DiffFinding] = field(default_factory=list)
    unchanged: int = 0
    identity_mode: str = "legacy"
    project_id: str = ""
    unresolved_contexts: int = 0

    @property
    def has_changes(self) -> bool:
        return bool(self.new or self.fixed or self.changed)

    @property
    def has_new_action(self) -> bool:
        """Whether any new finding has an ACTION verdict."""
        return any(f.verdict == "action" for f in self.new)


def _read_diff_report(path: Path) -> dict[str, Any]:
    """Read once with the historical legacy diagnostics before choosing identity mode."""

    def unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Invalid scan {path}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_keys)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid scan {path}: report must be a JSON object")
    if "scanned" in data:
        if not isinstance(data["scanned"], bool):
            raise ValueError(f"Invalid scan {path}: scanned must be a boolean")
        if not data["scanned"]:
            raise ValueError(f"Cannot compare incomplete scan {path}")
    rows = data.get("results")
    if not isinstance(rows, list):
        raise ValueError(f"Invalid scan {path}: results must be an array")
    return data


def _load_findings(
    path: Path, *, report: dict[str, Any] | None = None
) -> dict[tuple[str, str, str], dict[str, Any]]:
    """Load legacy identities without inferring versions or advisory aliases.

    Old reports without ``scanned`` retain their historical behavior of skipping
    rows without an advisory/package. A present completion flag must be true,
    and modern rows require nonempty advisory/package identities.
    """
    data = _read_diff_report(path) if report is None else report
    rows = data["results"]

    findings: dict[tuple[str, str, str], dict[str, Any]] = {}
    for index, r in enumerate(rows):
        if not isinstance(r, dict):
            raise ValueError(f"Invalid scan {path}: result {index} must be an object")
        cve = r.get("cve", "")
        pkg = r.get("package", "")
        version = r.get("version", "")
        if not all(isinstance(value, str) for value in (cve, pkg, version)):
            raise ValueError(
                f"Invalid scan {path}: result {index} advisory, package and version must be strings"
            )
        if "scanned" in data and (not cve.strip() or not pkg.strip()):
            raise ValueError(
                f"Invalid scan {path}: result {index} advisory and package must be nonempty"
            )
        if cve and pkg:
            verdict = r.get("verdict")
            if not isinstance(verdict, str) or verdict not in {"action", "review", "filtered"}:
                raise ValueError(f"Invalid scan {path}: result {index} has an invalid verdict")
            for name in ("severity", "title", "fix_version", "fix_package"):
                if name in r and not isinstance(r[name], str):
                    raise ValueError(f"Invalid scan {path}: result {index}.{name} must be a string")
            epss = r.get("epss_score")
            if epss is not None:
                finite = False
                if isinstance(epss, (int, float)) and not isinstance(epss, bool):
                    with contextlib.suppress(OverflowError):
                        finite = math.isfinite(epss)
                if not finite:
                    raise ValueError(
                        f"Invalid scan {path}: result {index}.epss_score "
                        "must be a finite number or null"
                    )
            key = (cve, pkg, version)
            if key in findings:
                raise ValueError(f"Invalid scan {path}: duplicate finding identity {key!r}")
            findings[key] = r
    return findings


def _to_diff_finding(raw: dict[str, Any], previous_verdict: str | None = None) -> DiffFinding:
    """Convert a raw JSON finding to a DiffFinding."""
    return DiffFinding(
        cve=raw.get("cve", ""),
        package=raw.get("package", ""),
        version=raw.get("version", ""),
        severity=raw.get("severity", ""),
        title=raw.get("title", ""),
        verdict=raw.get("verdict", ""),
        previous_verdict=previous_verdict,
        epss_score=raw.get("epss_score"),
        fix_version=(
            f"{raw['fix_package']}@{raw.get('fix_version', '')}"
            if raw.get("fix_package") and raw.get("fix_version")
            else raw.get("fix_version", "")
        ),
    )


def _context_finding(context: FindingContext, raw: dict[str, Any]) -> DiffFinding:
    return replace(
        _to_diff_finding(raw),
        version=context.version,
        instance_id=context.instance_id,
        context_id=context.context_id,
        identity_kind=context.kind,
        location=context.location,
        lockfile=context.lockfile,
        advisory_range=context.advisory_range,
        range_match=context.range_match,
    )


def _optional_scope(report: dict[str, Any], explicit: str | None) -> str:
    declared = report.get("project_id", "")
    if declared != "":
        validate_project_id(declared)
    if declared or explicit is not None:
        return bind_project_id(report, explicit)
    return ""


def _compare_findings(
    base: dict[_FindingKey, DiffFinding],
    head: dict[_FindingKey, DiffFinding],
    result: ScanDiff,
) -> ScanDiff:
    base_keys, head_keys = set(base), set(head)
    result.new.extend(head[key] for key in sorted(head_keys - base_keys))
    result.fixed.extend(base[key] for key in sorted(base_keys - head_keys))
    for key in sorted(base_keys & head_keys):
        if base[key].verdict != head[key].verdict:
            result.changed.append(replace(head[key], previous_verdict=base[key].verdict))
        else:
            result.unchanged += 1
    return result


def diff_scans(
    base_path: Path,
    head_path: Path,
    *,
    project_id: str | None = None,
    instance_aware: bool | None = None,
) -> ScanDiff:
    """Compare two depquiet --json outputs.

    Args:
        base_path: Path to the base/before scan JSON.
        head_path: Path to the head/after scan JSON.

    Returns:
        ScanDiff with new, fixed, changed, and unchanged identity-context counts.
        ``fixed`` is the historical field for a context absent from the head
        report, not proof of remediation or a non-affected product.
    """
    base_report, head_report = _read_diff_report(base_path), _read_diff_report(head_path)
    base_scope = _optional_scope(base_report, project_id)
    head_scope = _optional_scope(head_report, project_id)
    if base_scope and head_scope and base_scope != head_scope:
        raise ValueError("Cannot compare reports from different project_id scopes")
    if instance_aware is not None and not isinstance(instance_aware, bool):
        raise ValueError("instance_aware must be a boolean or None")
    if instance_aware is None:
        if bool(base_scope) != bool(head_scope):
            raise ValueError(
                "Only one report declares project_id; supply --project-id to bind the "
                "missing scope or select --legacy-identities explicitly"
            )
        instance_aware = bool(base_scope)

    if instance_aware:
        if not base_scope or not head_scope:
            raise ValueError(
                "Instance identities require project_id for both reports; supply --project-id "
                "to bind missing scope explicitly"
            )
        scope = base_scope
        base_contexts = report_contexts(base_report, project_id=scope)
        head_contexts = report_contexts(head_report, project_id=scope)
        unresolved = sum(
            context.kind == "unresolved"
            or (context.kind == "component" and context.range_match == "unknown")
            or (context.kind == "reported" and not context.version.strip())
            for context, _ in head_contexts
        )
        return _compare_findings(
            {context.context_id: _context_finding(context, raw) for context, raw in base_contexts},
            {context.context_id: _context_finding(context, raw) for context, raw in head_contexts},
            ScanDiff(identity_mode="instances", project_id=scope, unresolved_contexts=unresolved),
        )

    return _compare_findings(
        {
            key: _to_diff_finding(raw)
            for key, raw in _load_findings(base_path, report=base_report).items()
        },
        {
            key: _to_diff_finding(raw)
            for key, raw in _load_findings(head_path, report=head_report).items()
        },
        ScanDiff(),
    )


def _finding_label(finding: DiffFinding, *, instances: bool) -> str:
    if not instances:
        return f"{finding.package}@{finding.version}"
    if finding.identity_kind == "unresolved":
        label = f"{finding.package} (unresolved association)"
    elif finding.identity_kind == "reported" and not finding.version.strip():
        label = f"{finding.package} (reported version unspecified)"
    else:
        label = f"{finding.package}@{finding.version}"
    if finding.location:
        label += f" [{finding.location}]"
    if finding.identity_kind == "component" and finding.range_match == "unknown":
        label += " (range association unknown)"
    return label


def format_diff(diff: ScanDiff) -> str:
    """Format a ScanDiff as a human-readable report."""
    lines: list[str] = []
    instances = diff.identity_mode == "instances"
    if instances:
        lines.extend(
            [
                f"Project: {diff.project_id} — finding contexts",
                f"Unresolved or uncertain contexts in head: {diff.unresolved_contexts}.",
                "Absent contexts do not prove remediation or a non-affected product.",
                "",
            ]
        )

    if not diff.has_changes:
        lines.append(
            "✅ No finding context changes."
            if instances
            else "✅ No changes — scan results are identical."
        )
        unit = "finding contexts" if instances else "findings"
        lines.append(f"   {diff.unchanged} {unit} unchanged.")
        return "\n".join(lines)

    # Summary line
    parts: list[str] = []
    if diff.new:
        parts.append(f"🆕 {len(diff.new)} new")
    if diff.fixed:
        parts.append(f"{len(diff.fixed)} absent" if instances else f"✅ {len(diff.fixed)} fixed")
    if diff.changed:
        parts.append(f"🔄 {len(diff.changed)} changed")
    if diff.unchanged:
        parts.append(f"— {diff.unchanged} unchanged")
    lines.append(" | ".join(parts))
    lines.append("")

    # New findings
    if diff.new:
        lines.append("── New findings ──────────────────────────────────────")
        for f in diff.new:
            severity = f.severity.upper()
            verdict = f.verdict.upper()
            line = f"  [{severity}] {f.cve} in {_finding_label(f, instances=instances)}"
            if f.title:
                line += f" — {f.title}"
            line += f" → {verdict}"
            if f.epss_score is not None:
                line += f" (EPSS: {f.epss_score:.1%})"
            lines.append(line)
        lines.append("")

    # Fixed findings
    if diff.fixed:
        lines.append(
            "── Contexts absent from head ─────────────────────────"
            if instances
            else "── Fixed findings ───────────────────────────────────"
        )
        for f in diff.fixed:
            severity = f.severity.upper()
            line = f"  [{severity}] {f.cve} in {_finding_label(f, instances=instances)}"
            if f.title:
                line += f" — {f.title}"
            lines.append(line)
        lines.append("")

    # Changed findings
    if diff.changed:
        lines.append("── Changed findings ─────────────────────────────────")
        for f in diff.changed:
            prev = (f.previous_verdict or "?").upper()
            curr = f.verdict.upper()
            line = f"  {f.cve} in {_finding_label(f, instances=instances)}: {prev} → {curr}"
            lines.append(line)
        lines.append("")

    return "\n".join(lines)


_SEVERITY_BADGE: dict[str, str] = {
    "critical": "🔴",
    "high": "🟠",
    "moderate": "🟡",
    "low": "🔵",
    "info": "⚪",
}


def format_diff_markdown(diff: ScanDiff) -> str:
    """Format a ScanDiff as GitHub-flavored Markdown for PR comments."""
    lines: list[str] = []
    instances = diff.identity_mode == "instances"

    # Header
    lines.append("## 🔍 depquiet scan diff")
    lines.append("")
    if instances:
        lines.extend(
            [
                f"Project: `{diff.project_id}` — finding contexts.",
                f"Unresolved or uncertain contexts in head: **{diff.unresolved_contexts}**.",
                "Absent contexts do not prove remediation or a non-affected product.",
                "",
            ]
        )

    if not diff.has_changes:
        lines.append(
            "✅ **No finding context changes.**"
            if instances
            else "✅ **No changes** — scan results are identical."
        )
        if diff.unchanged:
            unit = "finding contexts" if instances else "findings"
            lines.append(f"  {diff.unchanged} {unit} unchanged.")
        return "\n".join(lines)

    # Summary badges
    parts: list[str] = []
    if diff.new:
        parts.append(f"🆕 **{len(diff.new)} new**")
    if diff.fixed:
        parts.append(
            f"**{len(diff.fixed)} absent**" if instances else f"✅ **{len(diff.fixed)} fixed**"
        )
    if diff.changed:
        parts.append(f"🔄 **{len(diff.changed)} changed**")
    if diff.unchanged:
        parts.append(f"{diff.unchanged} unchanged")
    lines.append(" · ".join(parts))
    lines.append("")

    # New findings table
    if diff.new:
        lines.append("### 🆕 New findings")
        lines.append("")
        lines.append("| Severity | CVE | Package | Verdict | EPSS | Fix |")
        lines.append("|----------|-----|---------|---------|------|-----|")
        for f in diff.new:
            badge = _SEVERITY_BADGE.get(f.severity, "⚪")
            sev = f.severity.upper()
            epss = f"{f.epss_score:.1%}" if f.epss_score is not None else "—"
            fix = f"`{f.fix_version}`" if f.fix_version else "—"
            verdict = f.verdict.upper()
            lines.append(
                f"| {badge} {sev} | `{f.cve}` | `{_finding_label(f, instances=instances)}` "
                f"| {verdict} | {epss} | {fix} |"
            )
        lines.append("")

    # Fixed findings table
    if diff.fixed:
        lines.append("### Contexts absent from head" if instances else "### ✅ Fixed findings")
        lines.append("")
        lines.append("| Severity | CVE | Package |")
        lines.append("|----------|-----|---------|")
        for f in diff.fixed:
            badge = _SEVERITY_BADGE.get(f.severity, "⚪")
            sev = f.severity.upper()
            lines.append(
                f"| {badge} {sev} | `{f.cve}` | `{_finding_label(f, instances=instances)}` |"
            )
        lines.append("")

    # Changed findings
    if diff.changed:
        lines.append("### 🔄 Changed verdicts")
        lines.append("")
        lines.append("| CVE | Package | Before | After |")
        lines.append("|-----|---------|--------|-------|")
        for f in diff.changed:
            prev = (f.previous_verdict or "?").upper()
            curr = f.verdict.upper()
            lines.append(
                f"| `{f.cve}` | `{_finding_label(f, instances=instances)}` | {prev} | {curr} |"
            )
        lines.append("")

    # Footer
    lines.append("---")
    lines.append("*Generated by [depquiet](https://github.com/samuelrojas-dev/depquiet)*")

    return "\n".join(lines)


def diff_to_json(diff: ScanDiff) -> dict[str, Any]:
    """Convert a ScanDiff to a JSON-serializable dict."""

    def _finding_dict(f: DiffFinding) -> dict[str, Any]:
        d: dict[str, Any] = {
            "cve": f.cve,
            "package": f.package,
            "version": f.version,
            "severity": f.severity,
            "title": f.title,
            "verdict": f.verdict,
        }
        if f.previous_verdict is not None:
            d["previous_verdict"] = f.previous_verdict
        if f.epss_score is not None:
            d["epss_score"] = f.epss_score
        if f.fix_version:
            d["fix_version"] = f.fix_version
        if diff.identity_mode == "instances":
            for name in (
                "instance_id",
                "context_id",
                "identity_kind",
                "location",
                "lockfile",
                "advisory_range",
                "range_match",
            ):
                value = getattr(f, name)
                if value:
                    d[name] = value
        return d

    data: dict[str, Any] = {
        "summary": {
            "new": len(diff.new),
            "fixed": len(diff.fixed),
            "changed": len(diff.changed),
            "unchanged": diff.unchanged,
        },
        "new": [_finding_dict(f) for f in diff.new],
        "fixed": [_finding_dict(f) for f in diff.fixed],
        "changed": [_finding_dict(f) for f in diff.changed],
    }
    if diff.identity_mode == "instances":
        data.update(
            identity_mode="instances",
            project_id=diff.project_id,
            count_unit="finding_contexts",
            fixed_meaning="context_absent_from_head",
        )
        data["summary"]["unresolved_contexts"] = diff.unresolved_contexts
    return data
