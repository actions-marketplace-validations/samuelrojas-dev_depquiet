"""GitHub Check Run annotations — inline PR feedback on vulnerability findings.

Maps depquiet findings to GitHub Check Run annotation objects so they appear
as inline comments on the PR diff, similar to CodeQL or ESLint annotations.

Each ACTION or REVIEW finding becomes one annotation pointing at the package
manifest (package.json, requirements.txt, etc.) or, when reachability data is
available, the file that imports the vulnerable package.

The GitHub Check Runs API accepts at most 50 annotations per API call.
We batch them accordingly and return the full list for the caller to post.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from depquiet.models import ScanResult, TriageResult, Verdict

# GitHub annotation_level values
_LEVEL_MAP: dict[str, str] = {
    "critical": "failure",
    "high": "failure",
    "moderate": "warning",
    "low": "notice",
    "info": "notice",
}

# Default manifest files per package manager
_MANIFEST_FILES: dict[str, str] = {
    "npm": "package.json",
    "pip": "requirements.txt",
    "go": "go.mod",
    "cargo": "Cargo.toml",
    "maven": "pom.xml",
    "nuget": "packages.config",
    "composer": "composer.json",
    "gem": "Gemfile",
    "pub": "pubspec.yaml",
}

# Max annotations per GitHub API call
MAX_ANNOTATIONS_PER_CALL = 50


@dataclass
class Annotation:
    """A single GitHub Check Run annotation."""

    path: str
    start_line: int
    end_line: int
    annotation_level: str  # "notice" | "warning" | "failure"
    title: str
    message: str


@dataclass
class AnnotationReport:
    """All annotations for a scan, ready to post to the Check Runs API."""

    annotations: list[Annotation] = field(default_factory=list)
    summary: str = ""
    conclusion: str = "success"  # "success" | "failure" | "neutral"

    @property
    def batches(self) -> list[list[Annotation]]:
        """Split annotations into batches of MAX_ANNOTATIONS_PER_CALL."""
        result: list[list[Annotation]] = []
        for i in range(0, len(self.annotations), MAX_ANNOTATIONS_PER_CALL):
            result.append(self.annotations[i : i + MAX_ANNOTATIONS_PER_CALL])
        return result


def build_annotations(
    result: ScanResult,
    manifest_path: str | None = None,
) -> AnnotationReport:
    """Convert a ScanResult into GitHub Check Run annotations.

    Only ACTION and REVIEW findings get annotations; FILTERED items are
    excluded (that's the point of depquiet).

    Args:
        result: The scan result to convert.
        manifest_path: Override the default manifest file path. When None,
            inferred from the package manager.

    Returns:
        An AnnotationReport with all annotations, a summary, and a conclusion.
    """
    manifest = manifest_path or _MANIFEST_FILES.get(result.package_manager, "package.json")

    annotations: list[Annotation] = []
    for tr in result.results:
        if tr.verdict == Verdict.FILTERED:
            continue
        annotations.append(_finding_to_annotation(tr, manifest, result.project_path))

    # Build summary text
    action_count = len(result.action)
    review_count = len(result.review)
    filtered_count = len(result.filtered)
    total = len(result.results)

    parts: list[str] = []
    if action_count:
        parts.append(f"{action_count} action required")
    if review_count:
        parts.append(f"{review_count} to review")
    parts.append(f"{filtered_count}/{total} filtered as noise")

    summary = f"depquiet found {total} vulnerabilities: {', '.join(parts)}."

    # Conclusion: failure if any ACTION items, neutral if only REVIEW
    if action_count > 0:
        conclusion = "failure"
    elif review_count > 0:
        conclusion = "neutral"
    else:
        conclusion = "success"

    return AnnotationReport(
        annotations=annotations,
        summary=summary,
        conclusion=conclusion,
    )


def annotations_to_json(report: AnnotationReport) -> dict[str, Any]:
    """Serialize an AnnotationReport to a JSON-compatible dict.

    The output matches the GitHub Check Runs API shape so it can be
    posted directly with minimal transformation.
    """
    return {
        "summary": report.summary,
        "conclusion": report.conclusion,
        "annotations": [
            {
                "path": a.path,
                "start_line": a.start_line,
                "end_line": a.end_line,
                "annotation_level": a.annotation_level,
                "title": a.title,
                "message": a.message,
            }
            for a in report.annotations
        ],
    }


def write_annotations(report: AnnotationReport, path: Path) -> None:
    """Write annotation report as JSON to a file."""
    data = annotations_to_json(report)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _finding_to_annotation(
    tr: TriageResult,
    manifest: str,
    project_path: str,
) -> Annotation:
    """Convert a single TriageResult to a GitHub annotation."""
    vuln = tr.vuln
    level = _LEVEL_MAP.get(vuln.severity.value, "warning")

    # Pick the annotation file: reachable import if available, else manifest
    annotation_path = manifest
    if tr.reachable_imports:
        imp = tr.reachable_imports[0]
        try:
            annotation_path = str(Path(imp).relative_to(project_path))
        except ValueError:
            annotation_path = imp

    # Build title
    verdict_label = "ACTION" if tr.verdict == Verdict.ACTION else "REVIEW"
    title = f"[{verdict_label}] {vuln.cve}: {vuln.package}@{vuln.version}"

    # Build message
    message_parts: list[str] = []
    if vuln.title:
        message_parts.append(vuln.title)

    message_parts.append(f"Severity: {vuln.severity.value.upper()}")

    if vuln.fix_version:
        message_parts.append(f"Fix: upgrade to {vuln.fix_label}")

    if tr.epss_score is not None:
        message_parts.append(f"EPSS: {tr.epss_score:.1%}")

    if tr.kev_entry is not None:
        message_parts.append("CISA KEV: actively exploited in the wild")

    if vuln.url:
        message_parts.append(f"Details: {vuln.url}")

    message = "\n".join(message_parts)

    return Annotation(
        path=annotation_path,
        start_line=1,
        end_line=1,
        annotation_level=level,
        title=title,
        message=message,
    )
