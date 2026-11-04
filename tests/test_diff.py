"""Tests for the scan comparison (diff) module."""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

from depquiet.diff import (
    DiffFinding,
    ScanDiff,
    diff_scans,
    diff_to_json,
    format_diff,
    format_diff_markdown,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_scan(tmp_path: Path, name: str, results: list[dict]) -> Path:
    """Write a minimal depquiet --json output file."""
    path = tmp_path / name
    path.write_text(
        json.dumps(
            {
                "project": ".",
                "package_manager": "npm",
                "total_dependencies": 10,
                "summary": {
                    "total": len(results),
                    "action": 0,
                    "review": 0,
                    "filtered": 0,
                    "filter_rate": 0.0,
                },
                "results": results,
            }
        ),
        encoding="utf-8",
    )
    return path


def _finding(
    cve: str = "CVE-2024-0001",
    package: str = "lodash",
    version: str = "4.17.20",
    severity: str = "high",
    title: str = "Prototype Pollution",
    verdict: str = "action",
    epss_score: float | None = 0.42,
    fix_version: str = "4.17.21",
) -> dict:
    return {
        "cve": cve,
        "package": package,
        "version": version,
        "severity": severity,
        "title": title,
        "verdict": verdict,
        "epss_score": epss_score,
        "fix_version": fix_version,
    }


# ---------------------------------------------------------------------------
# DiffFinding
# ---------------------------------------------------------------------------


class TestDiffFinding:
    def test_key(self):
        f = DiffFinding(
            cve="CVE-2024-0001",
            package="lodash",
            version="4.17.20",
            severity="high",
            title="Prototype Pollution",
            verdict="action",
        )
        assert f.key == "CVE-2024-0001:lodash"

    def test_previous_verdict_default(self):
        f = DiffFinding(
            cve="CVE-2024-0001",
            package="lodash",
            version="4.17.20",
            severity="high",
            title="x",
            verdict="action",
        )
        assert f.previous_verdict is None


# ---------------------------------------------------------------------------
# ScanDiff properties
# ---------------------------------------------------------------------------


class TestScanDiff:
    def test_has_changes_empty(self):
        d = ScanDiff()
        assert not d.has_changes

    def test_has_changes_with_new(self):
        d = ScanDiff(
            new=[
                DiffFinding(
                    cve="CVE-2024-0001",
                    package="x",
                    version="1",
                    severity="high",
                    title="x",
                    verdict="action",
                )
            ]
        )
        assert d.has_changes

    def test_has_changes_with_fixed(self):
        d = ScanDiff(
            fixed=[
                DiffFinding(
                    cve="CVE-2024-0001",
                    package="x",
                    version="1",
                    severity="high",
                    title="x",
                    verdict="action",
                )
            ]
        )
        assert d.has_changes

    def test_has_changes_with_changed(self):
        d = ScanDiff(
            changed=[
                DiffFinding(
                    cve="CVE-2024-0001",
                    package="x",
                    version="1",
                    severity="high",
                    title="x",
                    verdict="review",
                    previous_verdict="action",
                )
            ]
        )
        assert d.has_changes

    def test_has_new_action_true(self):
        d = ScanDiff(
            new=[
                DiffFinding(
                    cve="CVE-2024-0001",
                    package="x",
                    version="1",
                    severity="high",
                    title="x",
                    verdict="action",
                )
            ]
        )
        assert d.has_new_action

    def test_has_new_action_false_review(self):
        d = ScanDiff(
            new=[
                DiffFinding(
                    cve="CVE-2024-0001",
                    package="x",
                    version="1",
                    severity="high",
                    title="x",
                    verdict="review",
                )
            ]
        )
        assert not d.has_new_action

    def test_has_new_action_false_empty(self):
        d = ScanDiff()
        assert not d.has_new_action


# ---------------------------------------------------------------------------
# diff_scans
# ---------------------------------------------------------------------------


class TestDiffScans:
    def test_identical_scans(self, tmp_path: Path):
        findings = [_finding()]
        base = _write_scan(tmp_path, "base.json", findings)
        head = _write_scan(tmp_path, "head.json", findings)

        diff = diff_scans(base, head)

        assert len(diff.new) == 0
        assert len(diff.fixed) == 0
        assert len(diff.changed) == 0
        assert diff.unchanged == 1

    def test_new_finding(self, tmp_path: Path):
        base = _write_scan(tmp_path, "base.json", [])
        head = _write_scan(tmp_path, "head.json", [_finding()])

        diff = diff_scans(base, head)

        assert len(diff.new) == 1
        assert diff.new[0].cve == "CVE-2024-0001"
        assert diff.new[0].package == "lodash"

    def test_fixed_finding(self, tmp_path: Path):
        base = _write_scan(tmp_path, "base.json", [_finding()])
        head = _write_scan(tmp_path, "head.json", [])

        diff = diff_scans(base, head)

        assert len(diff.fixed) == 1
        assert diff.fixed[0].cve == "CVE-2024-0001"

    def test_changed_verdict(self, tmp_path: Path):
        base = _write_scan(tmp_path, "base.json", [_finding(verdict="review")])
        head = _write_scan(tmp_path, "head.json", [_finding(verdict="action")])

        diff = diff_scans(base, head)

        assert len(diff.changed) == 1
        assert diff.changed[0].verdict == "action"
        assert diff.changed[0].previous_verdict == "review"

    def test_mixed_changes(self, tmp_path: Path):
        base_findings = [
            _finding(cve="CVE-2024-0001"),  # will be fixed
            _finding(cve="CVE-2024-0002", verdict="review"),  # will change
            _finding(cve="CVE-2024-0003"),  # unchanged
        ]
        head_findings = [
            _finding(cve="CVE-2024-0002", verdict="action"),  # changed
            _finding(cve="CVE-2024-0003"),  # unchanged
            _finding(cve="CVE-2024-0004"),  # new
        ]
        base = _write_scan(tmp_path, "base.json", base_findings)
        head = _write_scan(tmp_path, "head.json", head_findings)

        diff = diff_scans(base, head)

        assert len(diff.new) == 1
        assert diff.new[0].cve == "CVE-2024-0004"
        assert len(diff.fixed) == 1
        assert diff.fixed[0].cve == "CVE-2024-0001"
        assert len(diff.changed) == 1
        assert diff.changed[0].cve == "CVE-2024-0002"
        assert diff.unchanged == 1

    def test_empty_scans(self, tmp_path: Path):
        base = _write_scan(tmp_path, "base.json", [])
        head = _write_scan(tmp_path, "head.json", [])

        diff = diff_scans(base, head)

        assert not diff.has_changes
        assert diff.unchanged == 0

    def test_skips_entries_without_cve(self, tmp_path: Path):
        base = _write_scan(tmp_path, "base.json", [_finding(cve="")])
        head = _write_scan(tmp_path, "head.json", [])

        diff = diff_scans(base, head)

        assert len(diff.fixed) == 0
        assert diff.unchanged == 0

    def test_skips_entries_without_package(self, tmp_path: Path):
        base = _write_scan(tmp_path, "base.json", [_finding(package="")])
        head = _write_scan(tmp_path, "head.json", [])

        diff = diff_scans(base, head)

        assert len(diff.fixed) == 0

    def test_epss_score_preserved(self, tmp_path: Path):
        base = _write_scan(tmp_path, "base.json", [])
        head = _write_scan(tmp_path, "head.json", [_finding(epss_score=0.85)])

        diff = diff_scans(base, head)

        assert diff.new[0].epss_score == pytest.approx(0.85)

    def test_fix_version_preserved(self, tmp_path: Path):
        base = _write_scan(tmp_path, "base.json", [])
        head = _write_scan(tmp_path, "head.json", [_finding(fix_version="5.0.0")])

        diff = diff_scans(base, head)

        assert diff.new[0].fix_version == "5.0.0"


# ---------------------------------------------------------------------------
# format_diff
# ---------------------------------------------------------------------------


class TestFormatDiff:
    def test_no_changes(self):
        diff = ScanDiff(unchanged=5)
        text = format_diff(diff)
        assert "No changes" in text
        assert "5 findings unchanged" in text

    def test_new_findings_shown(self):
        diff = ScanDiff(
            new=[
                DiffFinding(
                    cve="CVE-2024-0001",
                    package="lodash",
                    version="4.17.20",
                    severity="high",
                    title="Prototype Pollution",
                    verdict="action",
                    epss_score=0.42,
                )
            ]
        )
        text = format_diff(diff)
        assert "New findings" in text
        assert "CVE-2024-0001" in text
        assert "lodash@4.17.20" in text
        assert "HIGH" in text
        assert "ACTION" in text
        assert "EPSS: 42.0%" in text

    def test_fixed_findings_shown(self):
        diff = ScanDiff(
            fixed=[
                DiffFinding(
                    cve="CVE-2024-0001",
                    package="lodash",
                    version="4.17.20",
                    severity="high",
                    title="Prototype Pollution",
                    verdict="action",
                )
            ]
        )
        text = format_diff(diff)
        assert "Fixed findings" in text
        assert "CVE-2024-0001" in text

    def test_changed_findings_shown(self):
        diff = ScanDiff(
            changed=[
                DiffFinding(
                    cve="CVE-2024-0001",
                    package="lodash",
                    version="4.17.20",
                    severity="high",
                    title="x",
                    verdict="action",
                    previous_verdict="review",
                )
            ]
        )
        text = format_diff(diff)
        assert "Changed findings" in text
        assert "REVIEW" in text
        assert "ACTION" in text

    def test_summary_line(self):
        diff = ScanDiff(
            new=[
                DiffFinding(
                    cve="CVE-2024-0001",
                    package="a",
                    version="1",
                    severity="high",
                    title="x",
                    verdict="action",
                )
            ],
            fixed=[
                DiffFinding(
                    cve="CVE-2024-0002",
                    package="b",
                    version="1",
                    severity="low",
                    title="y",
                    verdict="filtered",
                )
            ],
            unchanged=3,
        )
        text = format_diff(diff)
        assert "1 new" in text
        assert "1 fixed" in text
        assert "3 unchanged" in text


# ---------------------------------------------------------------------------
# diff_to_json
# ---------------------------------------------------------------------------


class TestDiffToJson:
    def test_structure(self):
        diff = ScanDiff(
            new=[
                DiffFinding(
                    cve="CVE-2024-0001",
                    package="lodash",
                    version="4.17.20",
                    severity="high",
                    title="Prototype Pollution",
                    verdict="action",
                    epss_score=0.42,
                    fix_version="4.17.21",
                )
            ],
            unchanged=2,
        )
        out = diff_to_json(diff)

        assert out["summary"]["new"] == 1
        assert out["summary"]["fixed"] == 0
        assert out["summary"]["changed"] == 0
        assert out["summary"]["unchanged"] == 2
        assert len(out["new"]) == 1
        assert out["new"][0]["cve"] == "CVE-2024-0001"
        assert out["new"][0]["epss_score"] == pytest.approx(0.42)
        assert out["new"][0]["fix_version"] == "4.17.21"

    def test_changed_includes_previous_verdict(self):
        diff = ScanDiff(
            changed=[
                DiffFinding(
                    cve="CVE-2024-0001",
                    package="lodash",
                    version="4.17.20",
                    severity="high",
                    title="x",
                    verdict="action",
                    previous_verdict="review",
                )
            ]
        )
        out = diff_to_json(diff)
        assert out["changed"][0]["previous_verdict"] == "review"

    def test_optional_fields_omitted(self):
        diff = ScanDiff(
            new=[
                DiffFinding(
                    cve="CVE-2024-0001",
                    package="lodash",
                    version="4.17.20",
                    severity="high",
                    title="x",
                    verdict="action",
                )
            ]
        )
        out = diff_to_json(diff)
        assert "epss_score" not in out["new"][0]
        assert "fix_version" not in out["new"][0]
        assert "previous_verdict" not in out["new"][0]

    def test_roundtrip_json_serializable(self):
        diff = ScanDiff(
            new=[
                DiffFinding(
                    cve="CVE-2024-0001",
                    package="a",
                    version="1",
                    severity="high",
                    title="x",
                    verdict="action",
                    epss_score=0.5,
                )
            ],
            fixed=[
                DiffFinding(
                    cve="CVE-2024-0002",
                    package="b",
                    version="2",
                    severity="low",
                    title="y",
                    verdict="filtered",
                )
            ],
            changed=[
                DiffFinding(
                    cve="CVE-2024-0003",
                    package="c",
                    version="3",
                    severity="moderate",
                    title="z",
                    verdict="action",
                    previous_verdict="review",
                )
            ],
            unchanged=5,
        )
        text = json.dumps(diff_to_json(diff))
        parsed = json.loads(text)
        assert parsed["summary"]["new"] == 1


# ---------------------------------------------------------------------------
# CLI: depquiet diff
# ---------------------------------------------------------------------------


class TestCliDiff:
    def test_diff_text_output(self, tmp_path: Path):
        base = _write_scan(tmp_path, "base.json", [_finding(cve="CVE-2024-0001")])
        head = _write_scan(
            tmp_path,
            "head.json",
            [
                _finding(cve="CVE-2024-0001"),
                _finding(cve="CVE-2024-0002"),
            ],
        )

        from depquiet.cli import main

        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            code = main(["diff", str(base), str(head)])

        output = mock_out.getvalue()
        assert code == 0
        assert "CVE-2024-0002" in output
        assert "1 new" in output

    def test_diff_json_output(self, tmp_path: Path):
        base = _write_scan(tmp_path, "base.json", [])
        head = _write_scan(tmp_path, "head.json", [_finding()])

        from depquiet.cli import main

        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            code = main(["diff", str(base), str(head), "--json"])

        parsed = json.loads(mock_out.getvalue())
        assert code == 0
        assert parsed["summary"]["new"] == 1

    def test_diff_fail_on_new_action(self, tmp_path: Path):
        base = _write_scan(tmp_path, "base.json", [])
        head = _write_scan(tmp_path, "head.json", [_finding(verdict="action")])

        from depquiet.cli import main

        with patch("sys.stdout", new_callable=StringIO):
            code = main(["diff", str(base), str(head), "--fail-on-new"])

        assert code == 1

    def test_diff_fail_on_new_no_action(self, tmp_path: Path):
        base = _write_scan(tmp_path, "base.json", [])
        head = _write_scan(tmp_path, "head.json", [_finding(verdict="review")])

        from depquiet.cli import main

        with patch("sys.stdout", new_callable=StringIO):
            code = main(["diff", str(base), str(head), "--fail-on-new"])

        assert code == 0

    def test_diff_missing_file(self, tmp_path: Path):
        base = _write_scan(tmp_path, "base.json", [])

        from depquiet.cli import main

        with patch("sys.stderr", new_callable=StringIO) as mock_err:
            code = main(["diff", str(base), str(tmp_path / "nope.json")])

        assert code == 1
        assert "not found" in mock_err.getvalue()

    def test_diff_identical_scans(self, tmp_path: Path):
        findings = [_finding()]
        base = _write_scan(tmp_path, "base.json", findings)
        head = _write_scan(tmp_path, "head.json", findings)

        from depquiet.cli import main

        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            code = main(["diff", str(base), str(head)])

        assert code == 0
        assert "No changes" in mock_out.getvalue()

    def test_diff_markdown_output(self, tmp_path: Path):
        base = _write_scan(tmp_path, "base.json", [])
        head = _write_scan(tmp_path, "head.json", [_finding()])

        from depquiet.cli import main

        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            code = main(["diff", str(base), str(head), "--markdown"])

        output = mock_out.getvalue()
        assert code == 0
        assert "## 🔍 depquiet scan diff" in output
        assert "| Severity |" in output
        assert "`CVE-2024-0001`" in output

    def test_diff_summary_file(self, tmp_path: Path):
        base = _write_scan(tmp_path, "base.json", [])
        head = _write_scan(tmp_path, "head.json", [_finding()])
        summary_file = tmp_path / "summary.md"

        from depquiet.cli import main

        with patch("sys.stdout", new_callable=StringIO):
            code = main(["diff", str(base), str(head), "--summary", str(summary_file)])

        assert code == 0
        assert summary_file.exists()
        content = summary_file.read_text()
        assert "## 🔍 depquiet scan diff" in content
        assert "`CVE-2024-0001`" in content


# ---------------------------------------------------------------------------
# format_diff_markdown
# ---------------------------------------------------------------------------


class TestFormatDiffMarkdown:
    def test_no_changes(self):
        diff = ScanDiff(unchanged=5)
        md = format_diff_markdown(diff)
        assert "## 🔍 depquiet scan diff" in md
        assert "No changes" in md

    def test_new_findings_table(self):
        diff = ScanDiff(
            new=[
                DiffFinding(
                    cve="CVE-2024-0001",
                    package="lodash",
                    version="4.17.20",
                    severity="high",
                    title="Prototype Pollution",
                    verdict="action",
                    epss_score=0.42,
                    fix_version="4.17.21",
                )
            ]
        )
        md = format_diff_markdown(diff)
        assert "### 🆕 New findings" in md
        assert "| Severity | CVE | Package | Verdict | EPSS | Fix |" in md
        assert "`CVE-2024-0001`" in md
        assert "`lodash@4.17.20`" in md
        assert "42.0%" in md
        assert "`4.17.21`" in md
        assert "🟠 HIGH" in md

    def test_fixed_findings_table(self):
        diff = ScanDiff(
            fixed=[
                DiffFinding(
                    cve="CVE-2024-0001",
                    package="lodash",
                    version="4.17.20",
                    severity="critical",
                    title="x",
                    verdict="action",
                )
            ]
        )
        md = format_diff_markdown(diff)
        assert "### ✅ Fixed findings" in md
        assert "🔴 CRITICAL" in md

    def test_changed_findings_table(self):
        diff = ScanDiff(
            changed=[
                DiffFinding(
                    cve="CVE-2024-0001",
                    package="lodash",
                    version="4.17.20",
                    severity="high",
                    title="x",
                    verdict="action",
                    previous_verdict="review",
                )
            ]
        )
        md = format_diff_markdown(diff)
        assert "### 🔄 Changed verdicts" in md
        assert "REVIEW" in md
        assert "ACTION" in md

    def test_footer(self):
        diff = ScanDiff(
            new=[
                DiffFinding(
                    cve="CVE-2024-0001",
                    package="a",
                    version="1",
                    severity="high",
                    title="x",
                    verdict="action",
                )
            ]
        )
        md = format_diff_markdown(diff)
        assert "Generated by [depquiet]" in md

    def test_severity_badges(self):
        for severity, badge in [
            ("critical", "🔴"),
            ("high", "🟠"),
            ("moderate", "🟡"),
            ("low", "🔵"),
        ]:
            diff = ScanDiff(
                new=[
                    DiffFinding(
                        cve="CVE-2024-0001",
                        package="a",
                        version="1",
                        severity=severity,
                        title="x",
                        verdict="action",
                    )
                ]
            )
            md = format_diff_markdown(diff)
            assert badge in md

    def test_no_epss_shows_dash(self):
        diff = ScanDiff(
            new=[
                DiffFinding(
                    cve="CVE-2024-0001",
                    package="a",
                    version="1",
                    severity="high",
                    title="x",
                    verdict="action",
                    epss_score=None,
                )
            ]
        )
        md = format_diff_markdown(diff)
        # The EPSS column should show a dash when no score
        assert "| — |" in md

    def test_no_fix_shows_dash(self):
        diff = ScanDiff(
            new=[
                DiffFinding(
                    cve="CVE-2024-0001",
                    package="a",
                    version="1",
                    severity="high",
                    title="x",
                    verdict="action",
                    fix_version="",
                )
            ]
        )
        md = format_diff_markdown(diff)
        # The table should contain a cell with just dash for fix
        lines = md.split("\n")
        table_row = next(line for line in lines if "CVE-2024-0001" in line)
        assert table_row.endswith("— |")
