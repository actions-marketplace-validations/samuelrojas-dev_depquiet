"""Tests for the self-contained HTML report generator."""

from __future__ import annotations

from pathlib import Path

from depquiet.html_report import render_html, write_html
from depquiet.models import (
    DecisionChange,
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
                reasons=[FilterReason.DEV_DEPENDENCY, FilterReason.LOW_EPSS],
                epss_score=0.001,
            )
        )

    return ScanResult(
        project_path="/test/project",
        package_manager="npm",
        total_dependencies=42,
        results=results,
    )


# ---- Structure tests ----


class TestRenderHtmlStructure:
    """Verify the HTML report contains required structural elements."""

    def test_html_is_valid_document(self) -> None:
        result = _make_result(action=1, review=1, filtered=1)
        html = render_html(result)
        assert html.startswith("<!DOCTYPE html>")
        assert "<html" in html
        assert "</html>" in html
        assert "<head>" in html
        assert "<body>" in html

    def test_contains_title(self) -> None:
        html = render_html(_make_result())
        assert "<title>depquiet report</title>" in html

    def test_contains_viewport_meta(self) -> None:
        html = render_html(_make_result())
        assert 'name="viewport"' in html

    def test_self_contained_no_external_links(self) -> None:
        """CSS and JS must be inline — no external stylesheet or script src."""
        html = render_html(_make_result(action=2, review=3, filtered=5))
        assert 'rel="stylesheet"' not in html
        assert "<script src=" not in html
        assert "<style>" in html
        assert "<script>" in html

    def test_contains_dark_mode_support(self) -> None:
        html = render_html(_make_result())
        assert "prefers-color-scheme: dark" in html


# ---- Content tests ----


class TestRenderHtmlContent:
    """Verify the report shows correct data."""

    def test_no_action_priority_badge_does_not_claim_an_all_clear(self) -> None:
        html = render_html(_make_result(review=2, filtered=5))
        assert "No action-priority findings" in html
        assert "All clear" not in html
        assert "Product impact remains under investigation" in html

    def test_low_epss_filter_does_not_claim_an_all_clear(self) -> None:
        result = _make_result(filtered=1)
        result.results[0].reasons = [FilterReason.LOW_EPSS]
        html = render_html(result)
        assert "No action-priority findings" in html
        assert "All clear" not in html
        assert "No vulnerabilities found" not in html
        assert "Product impact remains under investigation" in html

    def test_complete_empty_scan_can_be_all_clear(self) -> None:
        html = render_html(_make_result())
        assert "All clear" in html

    def test_incomplete_scan_shows_the_reason(self) -> None:
        result = _make_result()
        result.scanned = False
        result.note = "Could not fetch <OSV> advisory details."
        html = render_html(result)
        assert "Scan incomplete" in html
        assert "Could not fetch &lt;OSV&gt; advisory details." in html
        assert "All clear" not in html
        assert "No vulnerabilities found" not in html

    def test_action_required_badge(self) -> None:
        html = render_html(_make_result(action=3))
        assert "3 action required" in html
        assert "badge-alert" in html

    def test_stat_cards_show_counts(self) -> None:
        result = _make_result(action=2, review=3, filtered=10)
        html = render_html(result)
        # Total = 15
        assert ">15<" in html
        assert ">10<" in html
        assert ">3<" in html
        assert ">2<" in html

    def test_action_table_contains_cve(self) -> None:
        html = render_html(_make_result(action=1))
        assert "CVE-2024-1000" in html
        assert "action-pkg-0" in html

    def test_action_table_contains_fix_version(self) -> None:
        html = render_html(_make_result(action=1))
        assert "2.0.0" in html

    def test_action_table_contains_epss(self) -> None:
        html = render_html(_make_result(action=1))
        assert "85%" in html

    def test_review_section_present(self) -> None:
        html = render_html(_make_result(review=2))
        assert "Review" in html
        assert "CVE-2024-2000" in html

    def test_filtered_section_present(self) -> None:
        html = render_html(_make_result(filtered=3))
        assert "Filtered" in html
        assert "priority filtering" in html

    def test_filtered_reason_breakdown(self) -> None:
        html = render_html(_make_result(filtered=2))
        assert "Dev dependency only" in html
        assert "Low EPSS score" in html

    def test_cve_links_to_url(self) -> None:
        html = render_html(_make_result(action=1))
        assert 'href="https://nvd.nist.gov/vuln/detail/CVE-2024-1000"' in html

    def test_severity_badges_in_table(self) -> None:
        html = render_html(_make_result(action=2))
        assert "High" in html
        assert "Critical" in html

    def test_empty_scan_shows_no_tables(self) -> None:
        html = render_html(_make_result())
        assert "action-section" not in html
        assert "review-section" not in html
        assert "filtered-section" not in html


# ---- Chart tests ----


class TestChart:
    def test_donut_chart_present_with_findings(self) -> None:
        html = render_html(_make_result(action=1, filtered=2))
        assert "conic-gradient" in html
        assert "chart-section" in html

    def test_no_chart_when_empty(self) -> None:
        html = render_html(_make_result())
        assert "conic-gradient" not in html

    def test_legend_shows_severities(self) -> None:
        html = render_html(_make_result(action=1, review=1, filtered=1))
        assert "legend-item" in html


# ---- Collapsible sections ----


class TestCollapsible:
    def test_review_collapsed_when_many(self) -> None:
        html = render_html(_make_result(review=10))
        assert 'class="findings collapsed"' in html

    def test_review_expanded_when_few(self) -> None:
        result = _make_result(review=3)
        html = render_html(result)
        # The review section should NOT have collapsed class
        assert 'id="review-section"' in html
        # Check that the section tag for review doesn't have collapsed
        idx = html.index('id="review-section"')
        section_start = html.rfind("<section", 0, idx)
        section_tag = html[section_start : idx + 30]
        assert "collapsed" not in section_tag

    def test_filtered_always_collapsed(self) -> None:
        html = render_html(_make_result(filtered=1))
        idx = html.index('id="filtered-section"')
        section_start = html.rfind("<section", 0, idx)
        section_tag = html[section_start : idx + 30]
        assert "collapsed" in section_tag

    def test_toggle_js_included(self) -> None:
        html = render_html(_make_result(review=1))
        assert "toggle" in html
        assert "classList.toggle" in html


# ---- Write to file ----


class TestWriteHtml:
    def test_writes_file(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        result = _make_result(action=1, review=2, filtered=3)
        write_html(result, out)
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "depquiet" in content

    def test_file_is_utf8(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        write_html(_make_result(), out)
        content = out.read_bytes()
        assert b'charset="utf-8"' in content


# ---- CLI integration ----


class TestCliHtmlFlag:
    def test_html_flag_generates_file(self, tmp_path: Path) -> None:
        """--html FILE should produce an HTML report."""
        from depquiet.cli import main

        out = tmp_path / "test-report.html"
        # Run with --stdin and empty results
        import io
        import sys

        stdin_data = io.StringIO('{"vulnerabilities": {}, "metadata": {"totalDependencies": 0}}')
        old_stdin = sys.stdin
        try:
            sys.stdin = stdin_data
            exit_code = main(["--path", str(tmp_path), "--stdin", "--offline", "--html", str(out)])
        finally:
            sys.stdin = old_stdin

        assert exit_code == 0
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content

    def test_html_flag_with_findings(self, tmp_path: Path) -> None:
        """--html should include findings in the report via direct render."""
        out = tmp_path / "findings-report.html"
        result = _make_result(action=2, review=1, filtered=3)
        write_html(result, out)

        content = out.read_text(encoding="utf-8")
        assert "action-pkg-0" in content
        assert "CVE-2024-1000" in content
        assert "action required" in content


# ---- JSON data for client-side filtering ----


class TestFindingsJson:
    def test_findings_json_embedded(self) -> None:
        """The findings JSON array must be embedded in the page for JS filtering."""
        html = render_html(_make_result(action=1, review=1))
        assert "const findings = [" in html

    def test_findings_json_contains_all_fields(self) -> None:
        from depquiet.html_report import _build_findings_json

        result = _make_result(action=1)
        data = _build_findings_json(result)
        import json as json_mod

        parsed = json_mod.loads(data)
        assert len(parsed) == 1
        item = parsed[0]
        assert item["cve"] == "CVE-2024-1000"
        assert item["package"] == "action-pkg-0"
        assert item["severity"] == "high"
        assert item["verdict"] == "action"
        assert item["epss"] == 0.85
        assert item["fix"] == "2.0.0"

    def test_filtered_findings_retain_assessment_evidence_and_history(self) -> None:
        import json

        from depquiet.html_report import _build_findings_json

        result = _make_result(filtered=1)
        tr = result.results[0]
        tr.evidence.usage = "observed"
        tr.evidence.import_sites = ["app.js"]
        tr.decision_trace.append(
            DecisionChange(
                source="ignore",
                previous_verdict=Verdict.ACTION,
                verdict=Verdict.FILTERED,
                rule_id=tr.vuln.cve,
                reason="Accepted until migration",
                path=".depquiet-ignore",
                author="security-team",
            )
        )
        finding = json.loads(_build_findings_json(result))[0]
        assert finding["assessment"]["status"] == "under_investigation"
        assert finding["assessment"]["limitations"]
        assert finding["evidence"]["usage"] == "observed"
        assert finding["evidence"]["import_sites"] == ["app.js"]
        assert finding["decision_trace"][0]["previous_verdict"] == "action"
        assert finding["decision_trace"][0]["verdict"] == "filtered"
        assert finding["decision_trace"][0]["author"] == "security-team"
        assert finding["decision_trace"][0]["path"] == ".depquiet-ignore"


# ---- XSS prevention ----


class TestXssPrevention:
    def test_package_name_escaped(self) -> None:
        """Package names with HTML chars must be escaped."""
        result = ScanResult(
            project_path="/test",
            package_manager="npm",
            total_dependencies=1,
            results=[
                TriageResult(
                    vuln=Vulnerability(
                        cve="CVE-2024-9999",
                        package='<script>alert("xss")</script>',
                        version="1.0.0",
                        severity=Severity.HIGH,
                        title='<img onerror="alert(1)">',
                    ),
                    verdict=Verdict.ACTION,
                )
            ],
        )
        html = render_html(result)
        assert "<script>alert" not in html
        assert "&lt;script&gt;" in html
        assert '<img onerror="alert(1)">' not in html


# ---- Footer ----


class TestFooter:
    def test_footer_contains_link(self) -> None:
        html = render_html(_make_result())
        assert "github.com/samuelrojas-dev/depquiet" in html

    def test_footer_contains_version(self) -> None:
        html = render_html(_make_result())
        # Version is dynamic but should be present
        assert "Generated by" in html
