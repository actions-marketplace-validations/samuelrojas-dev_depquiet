"""Tests for v0.27.0 ``depquiet stats`` aggregate statistics.

Covers: compute_stats, stats_from_json, formatting, and CLI dispatch.
"""

from __future__ import annotations

import json
from pathlib import Path

from depquiet.models import (
    FilterReason,
    Severity,
    TriageResult,
    Verdict,
    Vulnerability,
)
from depquiet.stats import (
    compute_stats,
    format_stats,
    format_stats_json,
    stats_from_json,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _vuln(**kw) -> Vulnerability:
    defaults = {
        "cve": "CVE-2024-0001",
        "package": "lodash",
        "version": "4.17.20",
        "severity": Severity.HIGH,
        "title": "Prototype Pollution",
    }
    defaults.update(kw)
    return Vulnerability(**defaults)


def _triage(**kw) -> TriageResult:
    if "vuln" not in kw:
        kw["vuln"] = _vuln()
    if "verdict" not in kw:
        kw["verdict"] = Verdict.ACTION
    return TriageResult(**kw)


def _sample_results() -> list[TriageResult]:
    """A mixed set of results for testing."""
    return [
        _triage(
            vuln=_vuln(
                cve="CVE-2024-0001",
                package="lodash",
                severity=Severity.HIGH,
                fix_version="4.17.21",
            ),
            verdict=Verdict.ACTION,
            epss_score=0.85,
        ),
        _triage(
            vuln=_vuln(
                cve="CVE-2024-0002",
                package="lodash",
                severity=Severity.MODERATE,
            ),
            verdict=Verdict.REVIEW,
            epss_score=0.15,
        ),
        _triage(
            vuln=_vuln(
                cve="CVE-2024-0003",
                package="semver",
                severity=Severity.LOW,
                is_dev=True,
            ),
            verdict=Verdict.FILTERED,
            reasons=[FilterReason.DEV_DEPENDENCY],
            epss_score=0.02,
        ),
        _triage(
            vuln=_vuln(
                cve="CVE-2024-0004",
                package="express",
                severity=Severity.CRITICAL,
                fix_version="4.19.0",
            ),
            verdict=Verdict.ACTION,
            epss_score=0.95,
        ),
        _triage(
            vuln=_vuln(
                cve="CVE-2024-0005",
                package="express",
                severity=Severity.HIGH,
            ),
            verdict=Verdict.FILTERED,
            reasons=[FilterReason.UNREACHABLE],
            epss_score=None,
        ),
        _triage(
            vuln=_vuln(
                cve="CVE-2024-0006",
                package="braces",
                severity=Severity.MODERATE,
            ),
            verdict=Verdict.FILTERED,
            reasons=[FilterReason.LOW_EPSS],
            epss_score=0.01,
        ),
    ]


# ---------------------------------------------------------------------------
# compute_stats tests
# ---------------------------------------------------------------------------


class TestComputeStats:
    def test_empty_results(self):
        stats = compute_stats([], total_dependencies=100)
        assert stats.total_vulnerabilities == 0
        assert stats.filter_rate == 0.0
        assert stats.action_count == 0

    def test_verdict_counts(self):
        results = _sample_results()
        stats = compute_stats(results)
        assert stats.total_vulnerabilities == 6
        assert stats.action_count == 2
        assert stats.review_count == 1
        assert stats.filtered_count == 3

    def test_filter_rate(self):
        results = _sample_results()
        stats = compute_stats(results)
        assert stats.filter_rate == 50.0  # 3/6

    def test_severity_counts(self):
        results = _sample_results()
        stats = compute_stats(results)
        assert stats.severity_counts["critical"] == 1
        assert stats.severity_counts["high"] == 2
        assert stats.severity_counts["moderate"] == 2
        assert stats.severity_counts["low"] == 1

    def test_severity_ordered(self):
        results = _sample_results()
        stats = compute_stats(results)
        keys = list(stats.severity_counts.keys())
        expected_order = ["critical", "high", "moderate", "low"]
        assert keys == expected_order

    def test_reason_counts(self):
        results = _sample_results()
        stats = compute_stats(results)
        assert "dev_dependency" in stats.reason_counts
        assert "unreachable" in stats.reason_counts
        assert "low_epss" in stats.reason_counts
        assert stats.reason_counts["dev_dependency"] == 1

    def test_top_packages(self):
        results = _sample_results()
        stats = compute_stats(results, top_n=3)
        names = [pkg for pkg, _ in stats.top_packages]
        assert "lodash" in names
        assert "express" in names
        # lodash and express each have 2
        assert stats.top_packages[0][1] == 2

    def test_top_n_limit(self):
        results = _sample_results()
        stats = compute_stats(results, top_n=1)
        assert len(stats.top_packages) == 1

    def test_epss_distribution(self):
        results = _sample_results()
        stats = compute_stats(results)
        assert stats.epss.low == 2  # 0.02, 0.01
        assert stats.epss.medium == 1  # 0.15
        assert stats.epss.high == 1  # 0.85
        assert stats.epss.critical == 1  # 0.95
        assert stats.epss.unavailable == 1

    def test_fix_availability(self):
        results = _sample_results()
        stats = compute_stats(results)
        assert stats.fixable_count == 2
        assert stats.unfixable_count == 4

    def test_total_dependencies(self):
        stats = compute_stats(_sample_results(), total_dependencies=847)
        assert stats.total_dependencies == 847


# ---------------------------------------------------------------------------
# to_dict tests
# ---------------------------------------------------------------------------


class TestScanStatsModel:
    def test_to_dict(self):
        stats = compute_stats(_sample_results(), total_dependencies=100)
        d = stats.to_dict()
        assert d["total_vulnerabilities"] == 6
        assert d["verdicts"]["action"] == 2
        assert d["filter_rate"] == 50.0
        assert isinstance(d["top_packages"], list)
        assert isinstance(d["epss_distribution"], dict)
        assert d["fix_availability"]["fixable"] == 2

    def test_to_dict_empty(self):
        stats = compute_stats([])
        d = stats.to_dict()
        assert d["total_vulnerabilities"] == 0
        assert d["filter_rate"] == 0.0


# ---------------------------------------------------------------------------
# stats_from_json tests
# ---------------------------------------------------------------------------


class TestStatsFromJson:
    def test_basic_json(self):
        data = {
            "total_dependencies": 200,
            "results": [
                {
                    "cve": "CVE-2024-0001",
                    "package": "lodash",
                    "version": "4.17.20",
                    "severity": "high",
                    "verdict": "action",
                    "reasons": [],
                    "epss_score": 0.85,
                    "fix_version": "4.17.21",
                },
                {
                    "cve": "CVE-2024-0002",
                    "package": "semver",
                    "version": "7.5.0",
                    "severity": "low",
                    "verdict": "filtered",
                    "reasons": ["low_epss"],
                    "epss_score": 0.01,
                },
            ],
        }
        stats = stats_from_json(data)
        assert stats.total_vulnerabilities == 2
        assert stats.total_dependencies == 200
        assert stats.action_count == 1
        assert stats.filtered_count == 1
        assert stats.filter_rate == 50.0

    def test_empty_results(self):
        data = {"results": []}
        stats = stats_from_json(data)
        assert stats.total_vulnerabilities == 0

    def test_minimal_entries(self):
        data = {"results": [{"cve": "CVE-2024-0001", "verdict": "review", "reasons": []}]}
        stats = stats_from_json(data)
        assert stats.total_vulnerabilities == 1
        assert stats.review_count == 1


# ---------------------------------------------------------------------------
# Formatting tests
# ---------------------------------------------------------------------------


class TestFormatStats:
    def test_human_format_header(self):
        stats = compute_stats(_sample_results())
        text = format_stats(stats)
        assert "depquiet scan statistics" in text
        assert "Total vulnerabilities: 6" in text

    def test_human_format_verdicts(self):
        stats = compute_stats(_sample_results())
        text = format_stats(stats)
        assert "ACTION" in text
        assert "REVIEW" in text
        assert "FILTERED" in text

    def test_human_format_filter_rate(self):
        stats = compute_stats(_sample_results())
        text = format_stats(stats)
        assert "50.0%" in text

    def test_human_format_severity(self):
        stats = compute_stats(_sample_results())
        text = format_stats(stats)
        assert "critical" in text
        assert "high" in text

    def test_human_format_reasons(self):
        stats = compute_stats(_sample_results())
        text = format_stats(stats)
        assert "dev dependency" in text
        assert "unreachable" in text

    def test_human_format_top_packages(self):
        stats = compute_stats(_sample_results())
        text = format_stats(stats)
        assert "lodash" in text
        assert "express" in text

    def test_human_format_empty(self):
        stats = compute_stats([])
        text = format_stats(stats)
        assert "Total vulnerabilities: 0" in text

    def test_json_format_valid(self):
        stats = compute_stats(_sample_results())
        text = format_stats_json(stats)
        parsed = json.loads(text)
        assert parsed["total_vulnerabilities"] == 6
        assert "verdicts" in parsed

    def test_json_format_roundtrip(self):
        stats = compute_stats(_sample_results(), total_dependencies=100)
        text = format_stats_json(stats)
        parsed = json.loads(text)
        assert parsed["total_dependencies"] == 100
        assert parsed["verdicts"]["action"] == 2
        assert parsed["filter_rate"] == 50.0


# ---------------------------------------------------------------------------
# CLI dispatch tests
# ---------------------------------------------------------------------------


class TestCLIDispatch:
    def test_stats_from_json(self, tmp_path: Path):
        from depquiet.cli import main

        scan_file = tmp_path / "scan.json"
        scan_data = {
            "total_dependencies": 100,
            "results": [
                {
                    "cve": "CVE-2024-0001",
                    "package": "lodash",
                    "version": "4.17.20",
                    "severity": "high",
                    "verdict": "action",
                    "reasons": [],
                    "epss_score": 0.85,
                    "fix_version": "4.17.21",
                },
                {
                    "cve": "CVE-2024-0002",
                    "verdict": "filtered",
                    "reasons": ["low_epss"],
                    "epss_score": 0.01,
                },
            ],
        }
        scan_file.write_text(json.dumps(scan_data), encoding="utf-8")

        rc = main(["stats", "--from-json", str(scan_file)])
        assert rc == 0

    def test_stats_json_output(self, tmp_path: Path, capsys):
        from depquiet.cli import main

        scan_file = tmp_path / "scan.json"
        scan_data = {
            "results": [
                {
                    "cve": "CVE-2024-0001",
                    "verdict": "action",
                    "reasons": [],
                    "epss_score": 0.42,
                }
            ]
        }
        scan_file.write_text(json.dumps(scan_data), encoding="utf-8")

        rc = main(["stats", "--from-json", str(scan_file), "--json"])
        assert rc == 0
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert parsed["total_vulnerabilities"] == 1

    def test_stats_top_flag(self, tmp_path: Path, capsys):
        from depquiet.cli import main

        scan_file = tmp_path / "scan.json"
        scan_data = {
            "results": [
                {
                    "cve": f"CVE-2024-{i:04d}",
                    "package": f"pkg-{i}",
                    "verdict": "action",
                    "reasons": [],
                }
                for i in range(20)
            ]
        }
        scan_file.write_text(json.dumps(scan_data), encoding="utf-8")

        rc = main(["stats", "--from-json", str(scan_file), "--json", "--top", "5"])
        assert rc == 0
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert len(parsed["top_packages"]) == 5

    def test_stats_missing_file(self, tmp_path: Path):
        from depquiet.cli import main

        rc = main(["stats", "--from-json", str(tmp_path / "nope.json")])
        assert rc == 1

    def test_stats_invalid_json(self, tmp_path: Path):
        from depquiet.cli import main

        bad = tmp_path / "bad.json"
        bad.write_text("not json", encoding="utf-8")
        rc = main(["stats", "--from-json", str(bad)])
        assert rc == 1
