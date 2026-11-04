"""Tests for baseline diffing (--baseline)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from depquiet.baseline import apply_baseline, load_baseline
from depquiet.cli import main
from depquiet.config import Config
from depquiet.models import (
    ScanResult,
    Severity,
    TriageResult,
    Verdict,
    Vulnerability,
)


def _vuln(
    cve: str = "CVE-2024-1234", pkg: str = "test-pkg", sev: Severity = Severity.HIGH
) -> Vulnerability:
    return Vulnerability(cve=cve, package=pkg, version="1.0.0", severity=sev)


def _result(items: list[tuple[str, str, Verdict]]) -> ScanResult:
    """Build a ScanResult from (cve, package, verdict) tuples."""
    results = [
        TriageResult(vuln=_vuln(cve=cve, pkg=pkg), verdict=verdict) for cve, pkg, verdict in items
    ]
    return ScanResult(
        project_path=".", package_manager="npm", total_dependencies=10, results=results
    )


class TestLoadBaseline:
    def test_loads_keys_from_json(self, tmp_path: Path) -> None:
        baseline = {
            "results": [
                {"cve": "CVE-2024-0001", "package": "foo", "verdict": "action"},
                {"cve": "CVE-2024-0002", "package": "bar", "verdict": "filtered"},
            ]
        }
        p = tmp_path / "baseline.json"
        p.write_text(json.dumps(baseline))
        keys = load_baseline(p)
        assert keys == {"CVE-2024-0001:foo", "CVE-2024-0002:bar"}

    def test_empty_results(self, tmp_path: Path) -> None:
        p = tmp_path / "baseline.json"
        p.write_text(json.dumps({"results": []}))
        assert load_baseline(p) == set()

    def test_missing_fields_skipped(self, tmp_path: Path) -> None:
        baseline = {"results": [{"cve": "", "package": "foo"}, {"cve": "CVE-1", "package": ""}]}
        p = tmp_path / "baseline.json"
        p.write_text(json.dumps(baseline))
        assert load_baseline(p) == set()

    def test_no_results_key(self, tmp_path: Path) -> None:
        p = tmp_path / "baseline.json"
        p.write_text(json.dumps({"summary": {}}))
        assert load_baseline(p) == set()


class TestApplyBaseline:
    def test_known_action_demoted(self) -> None:
        result = _result([("CVE-2024-0001", "foo", Verdict.ACTION)])
        baseline = {"CVE-2024-0001:foo"}
        bl = apply_baseline(result, baseline)
        assert result.results[0].verdict == Verdict.FILTERED
        assert bl.known_findings == 1
        assert bl.new_findings == 0

    def test_known_review_demoted(self) -> None:
        result = _result([("CVE-2024-0001", "foo", Verdict.REVIEW)])
        baseline = {"CVE-2024-0001:foo"}
        bl = apply_baseline(result, baseline)
        assert result.results[0].verdict == Verdict.FILTERED
        assert bl.known_findings == 1

    def test_new_finding_kept(self) -> None:
        result = _result([("CVE-2024-9999", "new-pkg", Verdict.ACTION)])
        baseline = {"CVE-2024-0001:foo"}
        bl = apply_baseline(result, baseline)
        assert result.results[0].verdict == Verdict.ACTION
        assert bl.new_findings == 1
        assert bl.known_findings == 0

    def test_already_filtered_untouched(self) -> None:
        result = _result([("CVE-2024-0001", "foo", Verdict.FILTERED)])
        baseline = {"CVE-2024-0001:foo"}
        bl = apply_baseline(result, baseline)
        assert result.results[0].verdict == Verdict.FILTERED
        assert bl.known_findings == 0  # was already filtered, not counted

    def test_mixed_known_and_new(self) -> None:
        result = _result(
            [
                ("CVE-2024-0001", "foo", Verdict.ACTION),
                ("CVE-2024-0002", "bar", Verdict.ACTION),
                ("CVE-2024-9999", "new-pkg", Verdict.ACTION),
            ]
        )
        baseline = {"CVE-2024-0001:foo", "CVE-2024-0002:bar"}
        bl = apply_baseline(result, baseline)
        assert result.results[0].verdict == Verdict.FILTERED
        assert result.results[1].verdict == Verdict.FILTERED
        assert result.results[2].verdict == Verdict.ACTION
        assert bl.known_findings == 2
        assert bl.new_findings == 1

    def test_empty_baseline_changes_nothing(self) -> None:
        result = _result([("CVE-2024-0001", "foo", Verdict.ACTION)])
        bl = apply_baseline(result, set())
        assert result.results[0].verdict == Verdict.ACTION
        assert bl.known_findings == 0
        assert bl.new_findings == 1

    def test_empty_result_with_baseline(self) -> None:
        result = _result([])
        bl = apply_baseline(result, {"CVE-2024-0001:foo"})
        assert bl.total_before == 0
        assert bl.new_findings == 0
        assert bl.known_findings == 0

    def test_same_cve_different_package_not_matched(self) -> None:
        result = _result([("CVE-2024-0001", "bar", Verdict.ACTION)])
        baseline = {"CVE-2024-0001:foo"}
        bl = apply_baseline(result, baseline)
        assert result.results[0].verdict == Verdict.ACTION
        assert bl.known_findings == 0

    def test_counts_correct(self) -> None:
        result = _result(
            [
                ("CVE-2024-0001", "foo", Verdict.ACTION),
                ("CVE-2024-0002", "bar", Verdict.REVIEW),
                ("CVE-2024-0003", "baz", Verdict.ACTION),
                ("CVE-2024-0004", "qux", Verdict.FILTERED),
            ]
        )
        baseline = {"CVE-2024-0001:foo", "CVE-2024-0002:bar"}
        bl = apply_baseline(result, baseline)
        assert bl.total_before == 3  # 2 action + 1 review
        assert bl.known_findings == 2
        assert bl.new_findings == 1  # only CVE-0003 remains


class TestCliBaseline:
    def test_baseline_suppresses_known(self, tmp_path: Path) -> None:
        # Create baseline file
        baseline = {
            "results": [
                {"cve": "CVE-2024-1234", "package": "test-pkg", "verdict": "action"},
            ]
        }
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text(json.dumps(baseline))

        # Mock scan to return the same finding
        mock_result = _result([("CVE-2024-1234", "test-pkg", Verdict.ACTION)])
        with (
            patch("depquiet.cli.scan", return_value=mock_result),
            patch("depquiet.cli.load_config", return_value=Config()),
            patch("depquiet.cli.load_policy", return_value=None),
            patch("depquiet.cli.load_ignore", return_value=None),
        ):
            exit_code = main(
                [
                    "--path",
                    str(tmp_path),
                    "--json",
                    "--baseline",
                    str(baseline_path),
                ]
            )
        assert exit_code == 0  # known finding demoted, no ACTION left

    def test_baseline_new_finding_fails(self, tmp_path: Path) -> None:
        baseline = {"results": [{"cve": "CVE-2024-0001", "package": "old", "verdict": "action"}]}
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text(json.dumps(baseline))

        mock_result = _result([("CVE-2024-9999", "new-pkg", Verdict.ACTION)])
        with (
            patch("depquiet.cli.scan", return_value=mock_result),
            patch("depquiet.cli.load_config", return_value=Config()),
            patch("depquiet.cli.load_policy", return_value=None),
            patch("depquiet.cli.load_ignore", return_value=None),
        ):
            exit_code = main(
                [
                    "--path",
                    str(tmp_path),
                    "--json",
                    "--baseline",
                    str(baseline_path),
                ]
            )
        assert exit_code == 1  # new finding triggers failure

    def test_baseline_with_fail_on(self, tmp_path: Path) -> None:
        """Baseline + --fail-on work together: known demoted, threshold applied to new."""
        baseline = {"results": [{"cve": "CVE-2024-0001", "package": "old", "verdict": "action"}]}
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text(json.dumps(baseline))

        # New finding is only moderate
        mock_result = _result(
            [
                ("CVE-2024-0001", "old", Verdict.ACTION),  # known — will be demoted
                ("CVE-2024-9999", "new-pkg", Verdict.ACTION),  # new, moderate
            ]
        )
        # Override severity of the new finding to moderate
        mock_result.results[1].vuln.severity = Severity.MODERATE

        with (
            patch("depquiet.cli.scan", return_value=mock_result),
            patch("depquiet.cli.load_config", return_value=Config()),
            patch("depquiet.cli.load_policy", return_value=None),
            patch("depquiet.cli.load_ignore", return_value=None),
        ):
            exit_code = main(
                [
                    "--path",
                    str(tmp_path),
                    "--json",
                    "--baseline",
                    str(baseline_path),
                    "--fail-on",
                    "high",
                ]
            )
        # Known demoted, new is moderate but threshold is high → pass
        assert exit_code == 0
