"""Advisories reported as GHSA or PYSEC keep their CVE alias.

uv audit names every advisory by its GHSA id and pip-audit by PYSEC or GHSA,
with the CVE in ``aliases``. The CISA KEV catalog lists CVE ids only, so
before this ``--kev`` never matched a uv audit finding.
"""

from __future__ import annotations

import json
from pathlib import Path

from depquiet.ignore import IgnoreEntry, IgnoreFile, apply_ignores
from depquiet.kev import _parse_catalog, apply_kev
from depquiet.models import ScanResult, Severity, TriageResult, Verdict, Vulnerability
from depquiet.parsers.pip import PipAuditParser
from depquiet.parsers.uv import UvAuditParser

FIXTURES = Path(__file__).parent / "fixtures"


def _kev(*cves: str):
    return _parse_catalog(
        {"vulnerabilities": [{"cveID": c, "vendorProject": "v", "product": "p"} for c in cves]}
    )


def _result(vuln: Vulnerability, verdict: Verdict = Verdict.FILTERED) -> ScanResult:
    return ScanResult(
        project_path=".",
        package_manager="uv",
        total_dependencies=1,
        results=[TriageResult(vuln=vuln, verdict=verdict)],
    )


def _ghsa() -> Vulnerability:
    return Vulnerability(
        cve="GHSA-567q-5qvw-pf92",
        package="filelock",
        version="3.0",
        severity=Severity.MODERATE,
        aliases=["CVE-2026-112907"],
    )


def test_uv_audit_keeps_the_cve_alias() -> None:
    data = json.loads((FIXTURES / "uv_audit_saleor.json").read_text(encoding="utf-8"))
    vulns = UvAuditParser.parse(data, Path("."))
    first = next(v for v in vulns if v.cve == "GHSA-567q-5qvw-pf92")
    assert first.aliases == ["CVE-2026-112907"]
    assert first.ids == ["GHSA-567q-5qvw-pf92", "CVE-2026-112907"]


def test_pip_audit_keeps_the_cve_alias() -> None:
    report = {
        "dependencies": [
            {
                "name": "cryptography",
                "version": "46.0.0",
                "vulns": [
                    {
                        "id": "PYSEC-2026-3552",
                        "aliases": ["CVE-2026-69247", "GHSA-g6cj-pr64-35w5"],
                        "fix_versions": ["46.0.5"],
                    }
                ],
            }
        ]
    }
    (vuln,) = PipAuditParser.parse(report, Path("."))
    assert vuln.cve == "PYSEC-2026-3552"
    assert "CVE-2026-69247" in vuln.aliases


def test_kev_matches_the_cve_alias_and_escalates() -> None:
    result = _result(_ghsa())
    kev = apply_kev(result, _kev("CVE-2026-112907"))
    assert (kev.kev_matches, kev.escalated) == (1, 1)
    assert result.results[0].verdict == Verdict.ACTION


def test_ignore_entry_by_cve_matches_a_ghsa_finding() -> None:
    result = _result(_ghsa(), Verdict.ACTION)
    apply_ignores(result, IgnoreFile([IgnoreEntry(cve="CVE-2026-112907", reason="waf")]))
    assert result.results[0].verdict == Verdict.FILTERED


def test_package_only_ignore_still_matches_without_an_id() -> None:
    vuln = Vulnerability(cve="", package="filelock", version="3.0", severity=Severity.LOW)
    result = _result(vuln, Verdict.ACTION)
    apply_ignores(result, IgnoreFile([IgnoreEntry(package="filelock", reason="tests only")]))
    assert result.results[0].verdict == Verdict.FILTERED
