"""Tests for the GitHub Actions Job Summary module."""

from __future__ import annotations

from pathlib import Path

from depquiet.models import (
    FilterReason,
    ScanResult,
    Severity,
    TriageResult,
    Verdict,
    Vulnerability,
)
from depquiet.summary import render_summary, write_summary


def _vuln(
    cve: str = "CVE-2024-1234",
    package: str = "lodash",
    severity: Severity = Severity.HIGH,
    fix_version: str = "",
    url: str = "",
) -> Vulnerability:
    return Vulnerability(
        cve=cve,
        package=package,
        version="1.0.0",
        severity=severity,
        fix_version=fix_version,
        url=url,
    )


def _result(
    items: list[tuple[str, str, Verdict, Severity]],
    reasons: dict[str, list[FilterReason]] | None = None,
) -> ScanResult:
    reasons = reasons or {}
    results = []
    for cve, pkg, verdict, sev in items:
        tr = TriageResult(
            vuln=_vuln(cve=cve, package=pkg, severity=sev),
            verdict=verdict,
            reasons=reasons.get(cve, []),
            epss_score=0.05,
        )
        results.append(tr)
    return ScanResult(
        project_path=".", package_manager="npm", total_dependencies=100, results=results
    )


class TestRenderSummary:
    def test_empty_results(self):
        result = ScanResult(
            project_path=".", package_manager="npm", total_dependencies=50, results=[]
        )
        md = render_summary(result)
        assert "All clear" in md
        assert "No vulnerabilities found" in md

    def test_all_filtered(self):
        result = _result(
            [("CVE-1", "lodash", Verdict.FILTERED, Severity.HIGH)],
            reasons={"CVE-1": [FilterReason.UNREACHABLE]},
        )
        md = render_summary(result)
        assert "No action-priority findings" in md
        assert "All clear" not in md
        assert "1 alerts filtered" in md
        assert "No dependency usage observed" in md
        assert "Product impact remains under investigation" in md

    def test_low_epss_does_not_claim_an_all_clear(self):
        result = _result(
            [("CVE-1", "widget", Verdict.FILTERED, Severity.HIGH)],
            reasons={"CVE-1": [FilterReason.LOW_EPSS]},
        )
        result.results[0].epss_score = 0.001
        md = render_summary(result)
        assert "No action-priority findings" in md
        assert "All clear" not in md
        assert "No vulnerabilities found" not in md
        assert "Product impact remains under investigation" in md

    def test_incomplete_scan_reports_the_reason_without_an_all_clear(self):
        result = ScanResult(
            project_path=".",
            package_manager="osv",
            total_dependencies=0,
            results=[],
            scanned=False,
            note="OSV advisory details could not be fetched.",
        )
        md = render_summary(result)
        assert "Scan incomplete" in md
        assert result.note in md
        assert "All clear" not in md
        assert "No vulnerabilities found" not in md
        assert "alerts scanned" not in md

    def test_action_items_table(self):
        result = _result(
            [("CVE-1", "express", Verdict.ACTION, Severity.CRITICAL)],
        )
        md = render_summary(result)
        assert "action required" in md
        assert "| CVE | Package |" in md
        assert "CVE-1" in md
        assert "`express`" in md
        assert "🟣 Critical" in md

    def test_action_with_fix_version(self):
        sr = ScanResult(
            project_path=".",
            package_manager="npm",
            total_dependencies=10,
            results=[
                TriageResult(
                    vuln=_vuln(fix_version="2.0.0"),
                    verdict=Verdict.ACTION,
                    epss_score=0.5,
                )
            ],
        )
        md = render_summary(sr)
        assert "`2.0.0`" in md

    def test_action_with_url(self):
        sr = ScanResult(
            project_path=".",
            package_manager="npm",
            total_dependencies=10,
            results=[
                TriageResult(
                    vuln=_vuln(url="https://nvd.nist.gov/vuln/detail/CVE-2024-1234"),
                    verdict=Verdict.ACTION,
                    epss_score=0.5,
                )
            ],
        )
        md = render_summary(sr)
        assert "[CVE-2024-1234](https://nvd.nist.gov" in md

    def test_review_items_table(self):
        result = _result(
            [("CVE-1", "lodash", Verdict.REVIEW, Severity.MODERATE)],
        )
        md = render_summary(result)
        assert "### ⚠️ Review" in md
        assert "🟡 Moderate" in md
        assert "No action-priority findings" in md
        assert "All clear" not in md

    def test_review_collapsed_when_many(self):
        items = [(f"CVE-{i}", f"pkg-{i}", Verdict.REVIEW, Severity.LOW) for i in range(8)]
        result = _result(items)
        md = render_summary(result)
        assert "<details>" in md
        assert "8 items to review" in md

    def test_review_not_collapsed_when_few(self):
        items = [(f"CVE-{i}", f"pkg-{i}", Verdict.REVIEW, Severity.LOW) for i in range(3)]
        result = _result(items)
        md = render_summary(result)
        # Should have the table but no <details> wrapping it
        lines = md.split("\n")
        # Find the Review section
        review_idx = next(idx for idx, line in enumerate(lines) if "Review" in line)
        # Check no <details> between Review header and the table
        section = "\n".join(lines[review_idx : review_idx + 5])
        assert "<details>" not in section

    def test_filtered_breakdown(self):
        result = _result(
            [
                ("CVE-1", "a", Verdict.FILTERED, Severity.HIGH),
                ("CVE-2", "b", Verdict.FILTERED, Severity.LOW),
                ("CVE-3", "c", Verdict.FILTERED, Severity.LOW),
            ],
            reasons={
                "CVE-1": [FilterReason.UNREACHABLE],
                "CVE-2": [FilterReason.LOW_EPSS],
                "CVE-3": [FilterReason.LOW_EPSS],
            },
        )
        md = render_summary(result)
        assert "Low EPSS score" in md
        assert "| 2 |" in md  # 2 low EPSS
        assert "| 1 |" in md  # 1 unreachable

    def test_ignored_reason_label(self):
        result = _result(
            [("CVE-1", "a", Verdict.FILTERED, Severity.HIGH)],
            reasons={"CVE-1": [FilterReason.IGNORED]},
        )
        md = render_summary(result)
        assert ".depquiet-ignore" in md

    def test_mixed_verdicts(self):
        result = _result(
            [
                ("CVE-1", "express", Verdict.ACTION, Severity.CRITICAL),
                ("CVE-2", "lodash", Verdict.REVIEW, Severity.MODERATE),
                ("CVE-3", "qs", Verdict.FILTERED, Severity.LOW),
            ],
            reasons={"CVE-3": [FilterReason.COMMUNITY_TEMPLATE]},
        )
        md = render_summary(result)
        assert "1 action required" in md
        assert "**3** alerts scanned" in md
        assert "**1** filtered" in md
        assert "**1** review" in md

    def test_severity_badges(self):
        from depquiet.summary import _severity_badge

        assert "🟣" in _severity_badge("critical")
        assert "🔴" in _severity_badge("high")
        assert "🟡" in _severity_badge("moderate")
        assert "🟢" in _severity_badge("low")
        assert "Info" in _severity_badge("info")

    def test_footer_has_version(self):
        result = _result([("CVE-1", "a", Verdict.ACTION, Severity.HIGH)])
        md = render_summary(result)
        assert "depquiet" in md
        assert "Generated by" in md

    def test_epss_dash_when_none(self):
        sr = ScanResult(
            project_path=".",
            package_manager="npm",
            total_dependencies=10,
            results=[
                TriageResult(
                    vuln=_vuln(),
                    verdict=Verdict.ACTION,
                    epss_score=None,
                )
            ],
        )
        md = render_summary(sr)
        assert "| — |" in md


class TestWriteSummary:
    def test_writes_to_file(self, tmp_path: Path):
        result = _result([("CVE-1", "a", Verdict.ACTION, Severity.HIGH)])
        out = tmp_path / "summary.md"
        write_summary(result, out)
        content = out.read_text(encoding="utf-8")
        assert "action required" in content
        assert content.endswith("\n")

    def test_writes_empty_result(self, tmp_path: Path):
        result = ScanResult(
            project_path=".", package_manager="npm", total_dependencies=10, results=[]
        )
        out = tmp_path / "summary.md"
        write_summary(result, out)
        content = out.read_text(encoding="utf-8")
        assert "All clear" in content
