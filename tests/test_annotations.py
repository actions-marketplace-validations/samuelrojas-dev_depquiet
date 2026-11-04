"""Tests for the GitHub Check Run annotations module."""

from __future__ import annotations

import json
from pathlib import Path

from depquiet.annotations import (
    MAX_ANNOTATIONS_PER_CALL,
    Annotation,
    AnnotationReport,
    annotations_to_json,
    build_annotations,
    write_annotations,
)
from depquiet.models import (
    FilterReason,
    ScanResult,
    Severity,
    TriageResult,
    Verdict,
    Vulnerability,
)


def _make_result(
    action: int = 0,
    review: int = 0,
    filtered: int = 0,
    package_manager: str = "npm",
) -> ScanResult:
    """Build a ScanResult with the specified number of findings per verdict."""
    results: list[TriageResult] = []

    for i in range(action):
        results.append(
            TriageResult(
                vuln=Vulnerability(
                    cve=f"CVE-2024-{1000 + i}",
                    package=f"action-pkg-{i}",
                    version="1.0.0",
                    severity=Severity.HIGH if i % 2 == 0 else Severity.CRITICAL,
                    title=f"Action finding {i}",
                    url=f"https://nvd.nist.gov/vuln/detail/CVE-2024-{1000 + i}",
                    fix_version="2.0.0",
                ),
                verdict=Verdict.ACTION,
                epss_score=0.85,
                epss_percentile=0.95,
                reachable_imports=["import_a"],
            )
        )

    for i in range(review):
        results.append(
            TriageResult(
                vuln=Vulnerability(
                    cve=f"CVE-2024-{2000 + i}",
                    package=f"review-pkg-{i}",
                    version="3.0.0",
                    severity=Severity.MODERATE,
                    title=f"Review finding {i}",
                ),
                verdict=Verdict.REVIEW,
                epss_score=0.05,
            )
        )

    for i in range(filtered):
        results.append(
            TriageResult(
                vuln=Vulnerability(
                    cve=f"CVE-2024-{3000 + i}",
                    package=f"filtered-pkg-{i}",
                    version="0.1.0",
                    severity=Severity.LOW,
                    title=f"Filtered finding {i}",
                    is_dev=True,
                ),
                verdict=Verdict.FILTERED,
                reasons=[FilterReason.DEV_DEPENDENCY],
                epss_score=0.001,
            )
        )

    return ScanResult(
        project_path="/test/project",
        package_manager=package_manager,
        total_dependencies=42,
        results=results,
    )


# ---- Annotation generation ----


class TestBuildAnnotations:
    """Test the core annotation builder."""

    def test_empty_scan_produces_no_annotations(self) -> None:
        report = build_annotations(_make_result())
        assert len(report.annotations) == 0
        assert report.conclusion == "success"

    def test_filtered_items_excluded(self) -> None:
        report = build_annotations(_make_result(filtered=5))
        assert len(report.annotations) == 0

    def test_action_items_become_annotations(self) -> None:
        report = build_annotations(_make_result(action=3))
        assert len(report.annotations) == 3

    def test_review_items_become_annotations(self) -> None:
        report = build_annotations(_make_result(review=2))
        assert len(report.annotations) == 2

    def test_mixed_findings(self) -> None:
        report = build_annotations(_make_result(action=2, review=3, filtered=10))
        assert len(report.annotations) == 5  # only action + review

    def test_conclusion_failure_when_action_items(self) -> None:
        report = build_annotations(_make_result(action=1))
        assert report.conclusion == "failure"

    def test_conclusion_neutral_when_only_review(self) -> None:
        report = build_annotations(_make_result(review=2))
        assert report.conclusion == "neutral"

    def test_conclusion_success_when_all_filtered(self) -> None:
        report = build_annotations(_make_result(filtered=5))
        assert report.conclusion == "success"

    def test_conclusion_failure_when_action_and_review(self) -> None:
        report = build_annotations(_make_result(action=1, review=3))
        assert report.conclusion == "failure"


# ---- Annotation content ----


class TestAnnotationContent:
    """Test the content of individual annotations."""

    def test_action_annotation_level_high(self) -> None:
        report = build_annotations(_make_result(action=1))
        # First action item has HIGH severity → failure
        assert report.annotations[0].annotation_level == "failure"

    def test_review_annotation_level_moderate(self) -> None:
        report = build_annotations(_make_result(review=1))
        assert report.annotations[0].annotation_level == "warning"

    def test_title_contains_cve_and_package(self) -> None:
        report = build_annotations(_make_result(action=1))
        ann = report.annotations[0]
        assert "CVE-2024-1000" in ann.title
        assert "action-pkg-0" in ann.title

    def test_title_contains_verdict_label(self) -> None:
        report = build_annotations(_make_result(action=1))
        assert "[ACTION]" in report.annotations[0].title

        report2 = build_annotations(_make_result(review=1))
        assert "[REVIEW]" in report2.annotations[0].title

    def test_message_contains_severity(self) -> None:
        report = build_annotations(_make_result(action=1))
        assert "HIGH" in report.annotations[0].message

    def test_message_contains_fix_version(self) -> None:
        report = build_annotations(_make_result(action=1))
        assert "2.0.0" in report.annotations[0].message

    def test_message_contains_epss(self) -> None:
        report = build_annotations(_make_result(action=1))
        assert "85.0%" in report.annotations[0].message

    def test_message_contains_url(self) -> None:
        report = build_annotations(_make_result(action=1))
        assert "nvd.nist.gov" in report.annotations[0].message

    def test_message_contains_title(self) -> None:
        report = build_annotations(_make_result(action=1))
        assert "Action finding 0" in report.annotations[0].message


# ---- Annotation paths ----


class TestAnnotationPaths:
    """Test file path resolution for annotations."""

    def test_default_manifest_npm(self) -> None:
        report = build_annotations(_make_result(review=1, package_manager="npm"))
        assert report.annotations[0].path == "package.json"

    def test_default_manifest_pip(self) -> None:
        report = build_annotations(_make_result(review=1, package_manager="pip"))
        assert report.annotations[0].path == "requirements.txt"

    def test_default_manifest_go(self) -> None:
        report = build_annotations(_make_result(review=1, package_manager="go"))
        assert report.annotations[0].path == "go.mod"

    def test_default_manifest_cargo(self) -> None:
        report = build_annotations(_make_result(review=1, package_manager="cargo"))
        assert report.annotations[0].path == "Cargo.toml"

    def test_custom_manifest_path(self) -> None:
        report = build_annotations(
            _make_result(review=1),
            manifest_path="apps/web/package.json",
        )
        assert report.annotations[0].path == "apps/web/package.json"

    def test_reachable_import_takes_priority(self) -> None:
        """When reachable imports exist, use the first one as annotation path."""
        report = build_annotations(_make_result(action=1))
        # action items have reachable_imports=["import_a"]
        assert report.annotations[0].path == "import_a"

    def test_unknown_pm_falls_back_to_package_json(self) -> None:
        report = build_annotations(_make_result(review=1, package_manager="unknown"))
        assert report.annotations[0].path == "package.json"


# ---- Severity mapping ----


class TestSeverityMapping:
    """Test severity-to-annotation_level mapping."""

    def test_critical_is_failure(self) -> None:
        result = ScanResult(
            project_path="/test",
            package_manager="npm",
            total_dependencies=1,
            results=[
                TriageResult(
                    vuln=Vulnerability(
                        cve="CVE-2024-0001",
                        package="pkg",
                        version="1.0.0",
                        severity=Severity.CRITICAL,
                    ),
                    verdict=Verdict.ACTION,
                )
            ],
        )
        report = build_annotations(result)
        assert report.annotations[0].annotation_level == "failure"

    def test_low_is_notice(self) -> None:
        result = ScanResult(
            project_path="/test",
            package_manager="npm",
            total_dependencies=1,
            results=[
                TriageResult(
                    vuln=Vulnerability(
                        cve="CVE-2024-0002",
                        package="pkg",
                        version="1.0.0",
                        severity=Severity.LOW,
                    ),
                    verdict=Verdict.REVIEW,
                )
            ],
        )
        report = build_annotations(result)
        assert report.annotations[0].annotation_level == "notice"

    def test_info_is_notice(self) -> None:
        result = ScanResult(
            project_path="/test",
            package_manager="npm",
            total_dependencies=1,
            results=[
                TriageResult(
                    vuln=Vulnerability(
                        cve="CVE-2024-0003",
                        package="pkg",
                        version="1.0.0",
                        severity=Severity.INFO,
                    ),
                    verdict=Verdict.REVIEW,
                )
            ],
        )
        report = build_annotations(result)
        assert report.annotations[0].annotation_level == "notice"


# ---- Summary text ----


class TestSummary:
    """Test the summary text generation."""

    def test_summary_contains_counts(self) -> None:
        report = build_annotations(_make_result(action=2, review=3, filtered=10))
        assert "2 action required" in report.summary
        assert "3 to review" in report.summary
        assert "10/15 filtered" in report.summary

    def test_summary_with_no_findings(self) -> None:
        report = build_annotations(_make_result())
        assert "0 vulnerabilities" in report.summary

    def test_summary_filtered_only(self) -> None:
        report = build_annotations(_make_result(filtered=5))
        assert "5/5 filtered" in report.summary


# ---- Batching ----


class TestBatching:
    """Test annotation batching for the GitHub API limit."""

    def test_single_batch_under_limit(self) -> None:
        report = build_annotations(_make_result(action=10))
        batches = report.batches
        assert len(batches) == 1
        assert len(batches[0]) == 10

    def test_multiple_batches_over_limit(self) -> None:
        report = AnnotationReport(
            annotations=[
                Annotation(
                    path="package.json",
                    start_line=1,
                    end_line=1,
                    annotation_level="warning",
                    title=f"Test {i}",
                    message=f"Test message {i}",
                )
                for i in range(120)
            ]
        )
        batches = report.batches
        assert len(batches) == 3
        assert len(batches[0]) == MAX_ANNOTATIONS_PER_CALL
        assert len(batches[1]) == MAX_ANNOTATIONS_PER_CALL
        assert len(batches[2]) == 20

    def test_empty_report_no_batches(self) -> None:
        report = AnnotationReport()
        assert report.batches == []


# ---- JSON serialization ----


class TestAnnotationsToJson:
    """Test JSON output for the GitHub API."""

    def test_json_structure(self) -> None:
        report = build_annotations(_make_result(action=1, review=1))
        data = annotations_to_json(report)
        assert "summary" in data
        assert "conclusion" in data
        assert "annotations" in data
        assert len(data["annotations"]) == 2

    def test_json_annotation_fields(self) -> None:
        report = build_annotations(_make_result(action=1))
        data = annotations_to_json(report)
        ann = data["annotations"][0]
        assert "path" in ann
        assert "start_line" in ann
        assert "end_line" in ann
        assert "annotation_level" in ann
        assert "title" in ann
        assert "message" in ann

    def test_json_roundtrip(self) -> None:
        report = build_annotations(_make_result(action=2, review=1))
        data = annotations_to_json(report)
        # Should be JSON-serializable
        raw = json.dumps(data)
        parsed = json.loads(raw)
        assert len(parsed["annotations"]) == 3


# ---- File output ----


class TestWriteAnnotations:
    """Test writing annotations to a file."""

    def test_writes_json_file(self, tmp_path: Path) -> None:
        out = tmp_path / "annotations.json"
        report = build_annotations(_make_result(action=1, review=2))
        write_annotations(report, out)
        assert out.exists()
        data = json.loads(out.read_text(encoding="utf-8"))
        assert len(data["annotations"]) == 3
        assert data["conclusion"] == "failure"

    def test_writes_empty_report(self, tmp_path: Path) -> None:
        out = tmp_path / "annotations.json"
        report = build_annotations(_make_result(filtered=5))
        write_annotations(report, out)
        data = json.loads(out.read_text(encoding="utf-8"))
        assert len(data["annotations"]) == 0
        assert data["conclusion"] == "success"


# ---- KEV annotation ----


class TestKevAnnotation:
    """Test that KEV entries are reflected in annotations."""

    def test_kev_in_message(self) -> None:
        from dataclasses import dataclass

        @dataclass
        class FakeKev:
            date_added: str = "2024-01-01"
            due_date: str = "2024-01-22"
            required_action: str = "Apply update"
            ransomware_use: str = "Known"

        result = ScanResult(
            project_path="/test",
            package_manager="npm",
            total_dependencies=1,
            results=[
                TriageResult(
                    vuln=Vulnerability(
                        cve="CVE-2024-9999",
                        package="kev-pkg",
                        version="1.0.0",
                        severity=Severity.CRITICAL,
                        title="KEV vulnerability",
                        fix_version="2.0.0",
                    ),
                    verdict=Verdict.ACTION,
                    kev_entry=FakeKev(),
                )
            ],
        )
        report = build_annotations(result)
        assert "CISA KEV" in report.annotations[0].message
        assert "actively exploited" in report.annotations[0].message
