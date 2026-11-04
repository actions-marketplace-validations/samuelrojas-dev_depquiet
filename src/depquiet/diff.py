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

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


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

    @property
    def has_changes(self) -> bool:
        return bool(self.new or self.fixed or self.changed)

    @property
    def has_new_action(self) -> bool:
        """Whether any new finding has an ACTION verdict."""
        return any(f.verdict == "action" for f in self.new)


def _load_findings(path: Path) -> dict[str, dict[str, Any]]:
    """Load a depquiet --json output and return findings keyed by cve:package."""
    data = json.loads(path.read_text(encoding="utf-8"))
    findings: dict[str, dict[str, Any]] = {}
    for r in data.get("results", []):
        cve = r.get("cve", "")
        pkg = r.get("package", "")
        if cve and pkg:
            key = f"{cve}:{pkg}"
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
        fix_version=raw.get("fix_version", ""),
    )


def diff_scans(base_path: Path, head_path: Path) -> ScanDiff:
    """Compare two depquiet --json outputs.

    Args:
        base_path: Path to the base/before scan JSON.
        head_path: Path to the head/after scan JSON.

    Returns:
        ScanDiff with new, fixed, changed, and unchanged counts.
    """
    base = _load_findings(base_path)
    head = _load_findings(head_path)

    result = ScanDiff()

    base_keys = set(base.keys())
    head_keys = set(head.keys())

    # New findings: in head but not in base
    for key in sorted(head_keys - base_keys):
        result.new.append(_to_diff_finding(head[key]))

    # Fixed findings: in base but not in head
    for key in sorted(base_keys - head_keys):
        result.fixed.append(_to_diff_finding(base[key]))

    # Shared: check for verdict changes
    for key in sorted(base_keys & head_keys):
        base_verdict = base[key].get("verdict", "")
        head_verdict = head[key].get("verdict", "")
        if base_verdict != head_verdict:
            result.changed.append(_to_diff_finding(head[key], previous_verdict=base_verdict))
        else:
            result.unchanged += 1

    return result


def format_diff(diff: ScanDiff) -> str:
    """Format a ScanDiff as a human-readable report."""
    lines: list[str] = []

    if not diff.has_changes:
        lines.append("✅ No changes — scan results are identical.")
        lines.append(f"   {diff.unchanged} findings unchanged.")
        return "\n".join(lines)

    # Summary line
    parts: list[str] = []
    if diff.new:
        parts.append(f"🆕 {len(diff.new)} new")
    if diff.fixed:
        parts.append(f"✅ {len(diff.fixed)} fixed")
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
            line = f"  [{severity}] {f.cve} in {f.package}@{f.version}"
            if f.title:
                line += f" — {f.title}"
            line += f" → {verdict}"
            if f.epss_score is not None:
                line += f" (EPSS: {f.epss_score:.1%})"
            lines.append(line)
        lines.append("")

    # Fixed findings
    if diff.fixed:
        lines.append("── Fixed findings ───────────────────────────────────")
        for f in diff.fixed:
            severity = f.severity.upper()
            line = f"  [{severity}] {f.cve} in {f.package}@{f.version}"
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
            line = f"  {f.cve} in {f.package}: {prev} → {curr}"
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

    # Header
    lines.append("## 🔍 depquiet scan diff")
    lines.append("")

    if not diff.has_changes:
        lines.append("✅ **No changes** — scan results are identical.")
        if diff.unchanged:
            lines.append(f"  {diff.unchanged} findings unchanged.")
        return "\n".join(lines)

    # Summary badges
    parts: list[str] = []
    if diff.new:
        parts.append(f"🆕 **{len(diff.new)} new**")
    if diff.fixed:
        parts.append(f"✅ **{len(diff.fixed)} fixed**")
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
                f"| {badge} {sev} | `{f.cve}` | `{f.package}@{f.version}` "
                f"| {verdict} | {epss} | {fix} |"
            )
        lines.append("")

    # Fixed findings table
    if diff.fixed:
        lines.append("### ✅ Fixed findings")
        lines.append("")
        lines.append("| Severity | CVE | Package |")
        lines.append("|----------|-----|---------|")
        for f in diff.fixed:
            badge = _SEVERITY_BADGE.get(f.severity, "⚪")
            sev = f.severity.upper()
            lines.append(f"| {badge} {sev} | `{f.cve}` | `{f.package}@{f.version}` |")
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
            lines.append(f"| `{f.cve}` | `{f.package}` | {prev} | {curr} |")
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
        return d

    return {
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
