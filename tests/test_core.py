"""Core tests — models, parsers, filters, engine, CLI, SARIF.

All offline, no network, no API keys. Uses fixture data.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from depquiet.cli import main
from depquiet.engine import scan
from depquiet.filters.devdep import DevDepFilter
from depquiet.filters.epss import EpssFilter
from depquiet.filters.reachability import ReachabilityFilter
from depquiet.filters.templates import TemplateFilter, _parse_yaml_simple
from depquiet.models import (
    FilterReason,
    ScanResult,
    Severity,
    TriageResult,
    Verdict,
    Vulnerability,
)
from depquiet.output import print_scan_result
from depquiet.parsers.npm import NpmAuditParser
from depquiet.sarif import to_sarif

FIXTURES = Path(__file__).parent / "fixtures"


# ── Models ──────────────────────────────────────────────────────────────


def test_severity_ordering():
    assert Severity.CRITICAL.value == "critical"
    assert Severity.LOW.value == "low"


def test_verdict_values():
    assert Verdict.ACTION.value == "action"
    assert Verdict.FILTERED.value == "filtered"


def test_scan_result_properties():
    v1 = Vulnerability(cve="CVE-1", package="a", version="1.0", severity=Severity.HIGH)
    v2 = Vulnerability(cve="CVE-2", package="b", version="2.0", severity=Severity.LOW)

    r1 = TriageResult(vuln=v1, verdict=Verdict.ACTION, reasons=[])
    r2 = TriageResult(vuln=v2, verdict=Verdict.FILTERED, reasons=[FilterReason.DEV_DEPENDENCY])

    sr = ScanResult(
        project_path="/test",
        package_manager="npm",
        total_dependencies=10,
        results=[r1, r2],
    )
    assert len(sr.action) == 1
    assert len(sr.filtered) == 1
    assert sr.filter_rate == 50.0


def test_scan_result_empty():
    sr = ScanResult(project_path="/test", package_manager="npm", total_dependencies=0, results=[])
    assert sr.filter_rate == 0.0
    assert sr.action == []


# ── npm parser ──────────────────────────────────────────────────────────


def test_npm_parser_parse():
    audit_json = json.loads((FIXTURES / "npm_audit.json").read_text())
    # Create a temp project with a package.json
    with tempfile.TemporaryDirectory() as tmp:
        project = Path(tmp)
        (project / "package.json").write_text(
            json.dumps(
                {
                    "dependencies": {"lodash": "^4.17.0", "braces": "^2.3.0"},
                    "devDependencies": {"debug": "^2.0.0"},
                }
            )
        )
        vulns = NpmAuditParser.parse(audit_json, project)

    assert len(vulns) >= 3
    packages = {v.package for v in vulns}
    assert "lodash" in packages
    assert "braces" in packages

    # Check debug is marked as dev
    debug_vulns = [v for v in vulns if v.package == "debug"]
    if debug_vulns:
        assert debug_vulns[0].is_dev is True


def test_npm_parser_detect():
    with tempfile.TemporaryDirectory() as tmp:
        project = Path(tmp)
        assert NpmAuditParser.detect(project) is False
        (project / "package-lock.json").write_text("{}")
        assert NpmAuditParser.detect(project) is True


# ── Filters ─────────────────────────────────────────────────────────────


def test_devdep_filter():
    v = Vulnerability(cve="CVE-1", package="a", version="1.0", severity=Severity.HIGH, is_dev=True)
    assert DevDepFilter.check(v) is True

    v2 = Vulnerability(
        cve="CVE-2",
        package="b",
        version="1.0",
        severity=Severity.HIGH,
        is_dev=False,
    )
    assert DevDepFilter.check(v2) is False


def test_reachability_filter_unreachable():
    with tempfile.TemporaryDirectory() as tmp:
        project = Path(tmp)
        # Create a JS source file that does NOT import lodash
        (project / "app.js").write_text(
            "const express = require('express');\nconsole.log('hello');\n"
        )

        rf = ReachabilityFilter(project)
        v = Vulnerability(cve="CVE-1", package="lodash", version="4.17.20", severity=Severity.HIGH)
        assert rf.check(v) is True  # unreachable


def test_reachability_filter_reachable():
    with tempfile.TemporaryDirectory() as tmp:
        project = Path(tmp)
        (project / "app.js").write_text("const _ = require('lodash');\n_.get(obj, 'path');\n")

        rf = ReachabilityFilter(project)
        v = Vulnerability(cve="CVE-1", package="lodash", version="4.17.20", severity=Severity.HIGH)
        assert rf.check(v) is False  # reachable — not filtered


def test_reachability_filter_vulnerable_functions():
    with tempfile.TemporaryDirectory() as tmp:
        project = Path(tmp)
        # File uses lodash.get but NOT the vulnerable merge
        (project / "app.js").write_text("const _ = require('lodash');\n_.get(obj, 'x');\n")

        rf = ReachabilityFilter(project)
        v = Vulnerability(
            cve="CVE-1",
            package="lodash",
            version="4.17.20",
            severity=Severity.HIGH,
            vulnerable_functions=["merge", "defaultsDeep"],
        )
        assert rf.check(v) is True  # vulnerable functions not used


def test_reachability_find_imports():
    with tempfile.TemporaryDirectory() as tmp:
        project = Path(tmp)
        (project / "a.js").write_text("import lodash from 'lodash';\n")
        (project / "b.js").write_text("console.log('hello world');\n")

        rf = ReachabilityFilter(project)
        v = Vulnerability(cve="CVE-1", package="lodash", version="1.0", severity=Severity.HIGH)
        imports = rf.find_imports(v)
        assert len(imports) == 1
        assert "a.js" in imports[0]


def test_epss_filter_no_data():
    """Without lookup, EPSS filter should not filter anything (conservative)."""
    ef = EpssFilter(threshold=0.1)
    v = Vulnerability(cve="CVE-2024-12345", package="a", version="1.0", severity=Severity.HIGH)
    assert ef.check(v) is False  # no data → don't filter


def test_epss_filter_with_cached_data():
    ef = EpssFilter(threshold=0.1)
    ef._cache["CVE-2024-12345"] = (0.05, 0.30)  # 5% score — below threshold
    ef._cache["CVE-2024-99999"] = (0.67, 0.95)  # 67% score — above threshold

    v_low = Vulnerability(cve="CVE-2024-12345", package="a", version="1.0", severity=Severity.HIGH)
    v_high = Vulnerability(cve="CVE-2024-99999", package="b", version="1.0", severity=Severity.HIGH)

    assert ef.check(v_low) is True  # low EPSS → filter
    assert ef.check(v_high) is False  # high EPSS → don't filter


def test_epss_filter_ghsa_ids_skipped():
    ef = EpssFilter()
    v = Vulnerability(cve="GHSA-abcd-1234-efgh", package="a", version="1.0", severity=Severity.HIGH)
    assert ef.check(v) is False  # GHSA IDs can't be looked up


# ── Templates ───────────────────────────────────────────────────────────


def test_yaml_parser():
    text = """
id: test-template
reason: "This is a test"
cves:
  - CVE-2024-1111
  - CVE-2024-2222
not-imported: ["merge", "defaultsDeep"]
author: "@test"
"""
    data = _parse_yaml_simple(text)
    assert data["id"] == "test-template"
    assert data["reason"] == "This is a test"
    assert "CVE-2024-1111" in data["cves"]
    assert "merge" in data["not-imported"]


def test_template_filter_loads_bundled():
    tf = TemplateFilter()
    assert tf.count >= 2  # We have at least 2 bundled templates


def test_template_filter_matches_cve(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies":{"lodash":"4.17.0"}}')
    (tmp_path / "app.js").write_text("console.log('no dependency use');\n")
    tf = TemplateFilter()
    match = tf.find_match("CVE-2020-8203", "lodash", project=tmp_path)
    assert match is not None
    assert "lodash" in match.id or "prototype" in match.id


def test_template_filter_no_match():
    tf = TemplateFilter()
    match = tf.find_match("CVE-9999-0000", "nonexistent-pkg")
    assert match is None


# ── Engine ──────────────────────────────────────────────────────────────


def test_engine_scan_with_fixture():
    audit_json = json.loads((FIXTURES / "npm_audit.json").read_text())

    with tempfile.TemporaryDirectory() as tmp:
        project = Path(tmp)
        # Create package.json + lock for parser detection
        (project / "package.json").write_text(
            json.dumps(
                {
                    "dependencies": {"lodash": "^4.17.0", "braces": "^2.3.0"},
                    "devDependencies": {"debug": "^2.0.0"},
                }
            )
        )
        (project / "package-lock.json").write_text("{}")
        # Source files that import braces but NOT lodash
        (project / "app.js").write_text("const braces = require('braces');\nbraces('a{b,c}');\n")

        result = scan(project, skip_epss=True, audit_json=audit_json)

    assert result.package_manager == "npm"
    assert len(result.results) > 0

    # lodash is declared but never imported: kept for review, not dismissed,
    # because another package could load it at runtime.
    lodash_results = [r for r in result.results if r.vuln.package == "lodash"]
    if lodash_results:
        assert lodash_results[0].verdict == Verdict.REVIEW
        assert FilterReason.UNREACHABLE not in lodash_results[0].reasons

    # braces should NOT be filtered (it's imported)
    braces_results = [r for r in result.results if r.vuln.package == "braces"]
    if braces_results:
        assert braces_results[0].verdict != Verdict.FILTERED

    # debug should be filtered (devDependency)
    debug_results = [r for r in result.results if r.vuln.package == "debug"]
    if debug_results:
        assert debug_results[0].verdict == Verdict.FILTERED
        assert FilterReason.DEV_DEPENDENCY in debug_results[0].reasons


def test_engine_no_package_manager():
    with tempfile.TemporaryDirectory() as tmp:
        result = scan(Path(tmp), skip_epss=True)
    assert result.package_manager == "unknown"
    assert len(result.results) == 0


def test_engine_filter_rate():
    audit_json = json.loads((FIXTURES / "npm_audit.json").read_text())

    with tempfile.TemporaryDirectory() as tmp:
        project = Path(tmp)
        (project / "package.json").write_text(
            json.dumps(
                {
                    "dependencies": {"braces": "^2.3.0"},
                    "devDependencies": {"debug": "^2.0.0", "lodash": "^4.17.0"},
                }
            )
        )
        # Only import braces
        (project / "index.js").write_text("require('braces');\n")

        result = scan(project, skip_epss=True, audit_json=audit_json)

    # Some vulns should be filtered
    assert result.filter_rate > 0


# ── SARIF ───────────────────────────────────────────────────────────────


def test_sarif_structure():
    v = Vulnerability(
        cve="CVE-2024-1234",
        package="test-pkg",
        version="1.0.0",
        severity=Severity.HIGH,
        title="Test vulnerability",
        url="https://example.com",
    )
    tr = TriageResult(vuln=v, verdict=Verdict.ACTION, reasons=[], epss_score=0.45)
    sr = ScanResult(
        project_path="/test",
        package_manager="npm",
        total_dependencies=10,
        results=[tr],
    )

    sarif = to_sarif(sr)

    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "depquiet"
    assert len(run["results"]) == 1
    assert run["results"][0]["ruleId"] == "CVE-2024-1234"
    assert run["results"][0]["level"] == "error"


def test_sarif_excludes_filtered():
    v1 = Vulnerability(cve="CVE-1", package="a", version="1.0", severity=Severity.HIGH)
    v2 = Vulnerability(cve="CVE-2", package="b", version="1.0", severity=Severity.LOW)

    r1 = TriageResult(vuln=v1, verdict=Verdict.ACTION, reasons=[])
    r2 = TriageResult(vuln=v2, verdict=Verdict.FILTERED, reasons=[FilterReason.DEV_DEPENDENCY])

    sr = ScanResult(
        project_path="/test",
        package_manager="npm",
        total_dependencies=5,
        results=[r1, r2],
    )
    sarif = to_sarif(sr)

    # FILTERED should be excluded
    assert len(sarif["runs"][0]["results"]) == 1
    assert sarif["runs"][0]["results"][0]["ruleId"] == "CVE-1"


# ── CLI ─────────────────────────────────────────────────────────────────


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "depquiet" in captured.out


def test_cli_no_project(capsys):
    """An empty directory must not be reported as clean."""
    with tempfile.TemporaryDirectory() as tmp:
        code = main(["--path", tmp])
    assert code == 2
    captured = capsys.readouterr()
    assert "nothing scanned" in captured.err
    assert "No vulnerabilities found" not in captured.out


def test_cli_offline_lockfile_without_scanner_is_not_clean(capsys):
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "Cargo.lock").write_text('[[package]]\nname = "x"\nversion = "1.0.0"\n')
        code = main(["--path", tmp, "--offline"])
    assert code == 2
    assert "--offline" in capsys.readouterr().err


def test_cli_empty_audit_is_clean(capsys, monkeypatch):
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO('{"vulnerabilities": {}}'))
    with tempfile.TemporaryDirectory() as tmp:
        code = main(["--path", tmp, "--offline", "--stdin"])
    assert code == 0
    assert "No vulnerabilities found" in capsys.readouterr().out


def test_cli_output_survives_non_utf8_stdout(monkeypatch, tmp_path):
    """Windows redirects stdout with cp1252, which can't encode the status symbols."""
    import io
    import sys

    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", stream)
    monkeypatch.setattr("sys.stdin", io.StringIO('{"vulnerabilities": {}}'))
    code = main(["--path", str(tmp_path), "--offline", "--stdin"])
    stream.flush()
    assert code == 0
    assert "✅".encode() in raw.getvalue()


def test_cli_stdin_json(capsys):
    import io
    import sys

    audit_json = json.loads((FIXTURES / "npm_audit.json").read_text())

    with tempfile.TemporaryDirectory() as tmp:
        project = Path(tmp)
        (project / "package.json").write_text(
            json.dumps(
                {
                    "dependencies": {"braces": "^2.3.0"},
                    "devDependencies": {"debug": "^2.0.0"},
                }
            )
        )
        (project / "app.js").write_text("require('braces');\n")

        old_stdin = sys.stdin
        sys.stdin = io.StringIO(json.dumps(audit_json))
        try:
            main(["--path", tmp, "--stdin", "--offline", "--json"])
        finally:
            sys.stdin = old_stdin

    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert "summary" in output
    assert output["summary"]["total"] > 0


def test_cli_sarif_output():
    audit_json = json.loads((FIXTURES / "npm_audit.json").read_text())

    with tempfile.TemporaryDirectory() as tmp:
        project = Path(tmp)
        (project / "package.json").write_text(
            json.dumps(
                {
                    "dependencies": {"braces": "^2.3.0"},
                }
            )
        )
        (project / "app.js").write_text("require('braces');\n")

        sarif_path = Path(tmp) / "out.sarif"

        import io
        import sys

        old_stdin = sys.stdin
        sys.stdin = io.StringIO(json.dumps(audit_json))
        try:
            main(["--path", tmp, "--stdin", "--offline", "--sarif", str(sarif_path)])
        finally:
            sys.stdin = old_stdin

        assert sarif_path.exists()
        sarif = json.loads(sarif_path.read_text())
        assert sarif["version"] == "2.1.0"


# ── Output ──────────────────────────────────────────────────────────────


def test_output_no_vulns(capsys):
    sr = ScanResult(project_path="/test", package_manager="npm", total_dependencies=0, results=[])
    print_scan_result(sr)
    captured = capsys.readouterr()
    assert "No vulnerabilities found" in captured.out


def test_output_with_results(capsys):
    v1 = Vulnerability(
        cve="CVE-2024-1234",
        package="test-pkg",
        version="1.0.0",
        severity=Severity.HIGH,
        title="Test vuln",
        fix_version="2.0.0",
    )
    r1 = TriageResult(vuln=v1, verdict=Verdict.ACTION, reasons=[], epss_score=0.67)
    v2 = Vulnerability(
        cve="CVE-2024-5678",
        package="dev-pkg",
        version="1.0.0",
        severity=Severity.LOW,
        is_dev=True,
    )
    r2 = TriageResult(
        vuln=v2,
        verdict=Verdict.FILTERED,
        reasons=[FilterReason.DEV_DEPENDENCY],
    )

    sr = ScanResult(
        project_path="/test",
        package_manager="npm",
        total_dependencies=50,
        results=[r1, r2],
    )
    print_scan_result(sr)
    captured = capsys.readouterr()
    assert "ACTION REQUIRED" in captured.out
    assert "FILTERED" in captured.out
    assert "1 actionable" in captured.out
    assert "1 filtered" in captured.out
