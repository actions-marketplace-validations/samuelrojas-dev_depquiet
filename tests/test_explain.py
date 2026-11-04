"""Tests for v0.26.0 ``depquiet explain`` verdict explainer.

Covers: signal extraction from TriageResult, verdict formatting,
JSON output, lookup by CVE ID, from-json mode, and CLI dispatch.
"""

from __future__ import annotations

import json
from pathlib import Path

from depquiet.explain import (
    Explanation,
    Signal,
    explain_triage,
    find_cve,
    find_cve_in_json,
    format_explanation,
    format_explanation_json,
)
from depquiet.models import (
    FilterReason,
    ScanResult,
    Severity,
    TriageResult,
    Verdict,
    Vulnerability,
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


def _scan_result(results: list[TriageResult]) -> ScanResult:
    return ScanResult(
        project_path=".",
        package_manager="npm",
        total_dependencies=100,
        results=results,
    )


# ---------------------------------------------------------------------------
# Signal extraction tests
# ---------------------------------------------------------------------------


class TestExplainSignals:
    def test_epss_high_score(self):
        tr = _triage(epss_score=0.85)
        exp = explain_triage(tr)
        epss = next(s for s in exp.signals if s.name == "EPSS score")
        assert epss.value == "85.0%"
        assert epss.effect == "escalated"

    def test_epss_low_score_filtered(self):
        tr = _triage(
            verdict=Verdict.FILTERED,
            reasons=[FilterReason.LOW_EPSS],
            epss_score=0.02,
        )
        exp = explain_triage(tr)
        epss = next(s for s in exp.signals if s.name == "EPSS score")
        assert epss.value == "2.0%"
        assert epss.effect == "filtered"

    def test_epss_unavailable(self):
        tr = _triage(epss_score=None)
        exp = explain_triage(tr)
        epss = next(s for s in exp.signals if s.name == "EPSS score")
        assert epss.value == "unavailable"
        assert epss.effect == "not_applicable"

    def test_epss_moderate_score(self):
        tr = _triage(epss_score=0.15)
        exp = explain_triage(tr)
        epss = next(s for s in exp.signals if s.name == "EPSS score")
        assert epss.effect == "neutral"

    def test_reachable_imports(self):
        tr = _triage(reachable_imports=["app.js", "utils.js"])
        exp = explain_triage(tr)
        reach = next(s for s in exp.signals if s.name == "Reachability")
        assert reach.value == "reachable"
        assert reach.effect == "escalated"
        assert "app.js" in reach.detail

    def test_unreachable(self):
        tr = _triage(
            verdict=Verdict.FILTERED,
            reasons=[FilterReason.UNREACHABLE],
        )
        exp = explain_triage(tr)
        reach = next(s for s in exp.signals if s.name == "Reachability")
        assert reach.value == "unreachable"
        assert reach.effect == "filtered"

    def test_reachability_unknown(self):
        tr = _triage()
        exp = explain_triage(tr)
        reach = next(s for s in exp.signals if s.name == "Reachability")
        assert reach.value == "unknown"
        assert reach.effect == "neutral"

    def test_dev_dependency(self):
        tr = _triage(
            vuln=_vuln(is_dev=True),
            verdict=Verdict.FILTERED,
            reasons=[FilterReason.DEV_DEPENDENCY],
        )
        exp = explain_triage(tr)
        dep = next(s for s in exp.signals if s.name == "Dependency type")
        assert dep.value == "devDependency"
        assert dep.effect == "filtered"

    def test_production_dependency(self):
        tr = _triage(vuln=_vuln(is_dev=False))
        exp = explain_triage(tr)
        dep = next(s for s in exp.signals if s.name == "Dependency type")
        assert dep.value == "production"
        assert dep.effect == "neutral"

    def test_community_template(self):
        tr = _triage(
            verdict=Verdict.FILTERED,
            reasons=[FilterReason.COMMUNITY_TEMPLATE],
            template_id="npm/lodash-prototype-pollution",
            template_reason=(
                "Prototype pollution in lodash.merge"
                " — only exploitable via untrusted input"
            ),
        )
        exp = explain_triage(tr)
        tmpl = next(s for s in exp.signals if s.name == "Community template")
        assert tmpl.value == "npm/lodash-prototype-pollution"
        assert tmpl.effect == "filtered"
        assert "untrusted input" in tmpl.detail

    def test_kev_listed(self):
        from dataclasses import dataclass

        @dataclass
        class FakeKev:
            date_added: str = "2021-12-10"
            due_date: str = "2021-12-24"
            required_action: str = "Apply updates."
            ransomware_use: bool = True

        tr = _triage(kev_entry=FakeKev())
        exp = explain_triage(tr)
        kev = next(s for s in exp.signals if s.name == "CISA KEV")
        assert kev.value == "listed"
        assert kev.effect == "escalated"
        assert "2021-12-10" in kev.detail

    def test_kev_not_listed(self):
        tr = _triage(kev_entry=None)
        exp = explain_triage(tr)
        kev = next(s for s in exp.signals if s.name == "CISA KEV")
        assert kev.value == "not listed"
        assert kev.effect == "neutral"

    def test_ignored(self):
        tr = _triage(
            verdict=Verdict.FILTERED,
            reasons=[FilterReason.IGNORED],
        )
        exp = explain_triage(tr)
        ign = next(s for s in exp.signals if s.name == "Ignore rule")
        assert ign.value == "suppressed"
        assert ign.effect == "filtered"

    def test_fix_version(self):
        tr = _triage(vuln=_vuln(fix_version="4.17.21"))
        exp = explain_triage(tr)
        assert exp.fix_available is True
        assert exp.fix_version == "4.17.21"

    def test_no_fix_version(self):
        tr = _triage(vuln=_vuln(fix_version=""))
        exp = explain_triage(tr)
        assert exp.fix_available is False


# ---------------------------------------------------------------------------
# Explanation model tests
# ---------------------------------------------------------------------------


class TestExplanationModel:
    def test_to_dict(self):
        exp = Explanation(
            cve="CVE-2024-0001",
            package="lodash",
            version="4.17.20",
            severity="high",
            title="Prototype Pollution",
            verdict="action",
            reason_summary="reachable, exploitable",
            signals=[Signal(name="EPSS score", value="85.0%", effect="escalated")],
            fix_available=True,
            fix_version="4.17.21",
        )
        d = exp.to_dict()
        assert d["cve"] == "CVE-2024-0001"
        assert d["verdict"] == "action"
        assert len(d["signals"]) == 1
        assert d["signals"][0]["name"] == "EPSS score"
        assert d["fix_available"] is True

    def test_verdict_fields(self):
        tr = _triage(verdict=Verdict.REVIEW)
        exp = explain_triage(tr)
        assert exp.verdict == "review"


# ---------------------------------------------------------------------------
# Formatting tests
# ---------------------------------------------------------------------------


class TestFormatExplanation:
    def test_human_format_contains_cve(self):
        tr = _triage(epss_score=0.42)
        exp = explain_triage(tr)
        text = format_explanation(exp)
        assert "CVE-2024-0001" in text
        assert "lodash" in text
        assert "ACTION" in text
        assert "Signals:" in text

    def test_human_format_shows_fix(self):
        tr = _triage(vuln=_vuln(fix_version="4.17.21"))
        exp = explain_triage(tr)
        text = format_explanation(exp)
        assert "4.17.21" in text

    def test_human_format_verdict_icons(self):
        for verdict, icon in [
            (Verdict.ACTION, "\U0001f534"),
            (Verdict.REVIEW, "\U0001f7e1"),
            (Verdict.FILTERED, "\U0001f7e2"),
        ]:
            tr = _triage(verdict=verdict)
            exp = explain_triage(tr)
            text = format_explanation(exp)
            assert icon in text

    def test_json_format_valid(self):
        tr = _triage(epss_score=0.42)
        exp = explain_triage(tr)
        text = format_explanation_json(exp)
        parsed = json.loads(text)
        assert parsed["cve"] == "CVE-2024-0001"
        assert isinstance(parsed["signals"], list)


# ---------------------------------------------------------------------------
# Lookup tests
# ---------------------------------------------------------------------------


class TestFindCve:
    def test_find_existing(self):
        tr = _triage()
        result = _scan_result([tr])
        found = find_cve(result, "CVE-2024-0001")
        assert found is tr

    def test_find_case_insensitive(self):
        tr = _triage()
        result = _scan_result([tr])
        found = find_cve(result, "cve-2024-0001")
        assert found is tr

    def test_not_found(self):
        tr = _triage()
        result = _scan_result([tr])
        found = find_cve(result, "CVE-9999-9999")
        assert found is None


class TestFindCveInJson:
    def test_find_in_json(self):
        data = {
            "results": [
                {
                    "cve": "CVE-2024-0001",
                    "package": "lodash",
                    "version": "4.17.20",
                    "severity": "high",
                    "title": "Prototype Pollution",
                    "verdict": "action",
                    "reasons": [],
                    "epss_score": 0.42,
                    "fix_version": "4.17.21",
                    "reachable_imports": ["app.js"],
                }
            ]
        }
        tr = find_cve_in_json(data, "CVE-2024-0001")
        assert tr is not None
        assert tr.vuln.cve == "CVE-2024-0001"
        assert tr.verdict == Verdict.ACTION
        assert tr.epss_score == 0.42

    def test_find_case_insensitive(self):
        data = {"results": [{"cve": "CVE-2024-0001", "verdict": "action", "reasons": []}]}
        tr = find_cve_in_json(data, "cve-2024-0001")
        assert tr is not None

    def test_not_found(self):
        data = {"results": []}
        tr = find_cve_in_json(data, "CVE-9999-9999")
        assert tr is None

    def test_with_filter_reasons(self):
        data = {
            "results": [
                {
                    "cve": "CVE-2024-0002",
                    "verdict": "filtered",
                    "reasons": ["low_epss", "dev_dependency"],
                    "epss_score": 0.01,
                }
            ]
        }
        tr = find_cve_in_json(data, "CVE-2024-0002")
        assert tr is not None
        assert tr.verdict == Verdict.FILTERED
        assert FilterReason.LOW_EPSS in tr.reasons
        assert FilterReason.DEV_DEPENDENCY in tr.reasons


# ---------------------------------------------------------------------------
# CLI dispatch tests
# ---------------------------------------------------------------------------


class TestCLIDispatch:
    def test_explain_from_json(self, tmp_path: Path):
        from depquiet.cli import main

        scan_file = tmp_path / "scan.json"
        scan_data = {
            "results": [
                {
                    "cve": "CVE-2024-0001",
                    "package": "lodash",
                    "version": "4.17.20",
                    "severity": "high",
                    "title": "Prototype Pollution",
                    "verdict": "action",
                    "reasons": [],
                    "epss_score": 0.42,
                    "fix_version": "4.17.21",
                    "reachable_imports": [],
                }
            ]
        }
        scan_file.write_text(json.dumps(scan_data), encoding="utf-8")

        rc = main(["explain", "CVE-2024-0001", "--from-json", str(scan_file)])
        assert rc == 0

    def test_explain_json_output(self, tmp_path: Path, capsys):
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

        rc = main(["explain", "CVE-2024-0001", "--from-json", str(scan_file), "--json"])
        assert rc == 0
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert parsed["cve"] == "CVE-2024-0001"

    def test_explain_not_found(self, tmp_path: Path):
        from depquiet.cli import main

        scan_file = tmp_path / "scan.json"
        scan_file.write_text('{"results": []}', encoding="utf-8")
        rc = main(["explain", "CVE-9999-9999", "--from-json", str(scan_file)])
        assert rc == 1

    def test_explain_missing_file(self, tmp_path: Path):
        from depquiet.cli import main

        rc = main(["explain", "CVE-2024-0001", "--from-json", str(tmp_path / "nope.json")])
        assert rc == 1

    def test_explain_invalid_json(self, tmp_path: Path):
        from depquiet.cli import main

        bad = tmp_path / "bad.json"
        bad.write_text("not json", encoding="utf-8")
        rc = main(["explain", "CVE-2024-0001", "--from-json", str(bad)])
        assert rc == 1
