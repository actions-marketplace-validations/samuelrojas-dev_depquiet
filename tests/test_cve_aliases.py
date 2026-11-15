"""CVE ids for advisories reported without one (npm audit gives only GHSA ids).

Found with a real ``npm audit`` run: 0 of 72 alerts carried a CVE id, so EPSS
and KEV never applied to npm projects, and ``--kev`` still printed
"0 of 72 CVEs on the CISA KEV catalog".
"""

from __future__ import annotations

import io
import json
import urllib.error
from pathlib import Path

import pytest

import depquiet.cve_aliases as ca
from depquiet.cve_aliases import resolve_cve_aliases
from depquiet.kev import KevCatalog, KevEntry, apply_kev
from depquiet.models import ScanResult, Severity, TriageResult, Verdict, Vulnerability


def _vuln(advisory: str, aliases: list[str] | None = None) -> Vulnerability:
    return Vulnerability(advisory, "lodash", "4.17.15", Severity.HIGH, aliases=aliases or [])


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _osv(monkeypatch, answers: dict[str, object]) -> list[str]:
    """Fake OSV.dev: advisory id -> aliases list, an HTTP status, or an exception."""
    asked: list[str] = []

    def urlopen(req, timeout=0):
        advisory = req.full_url.rsplit("/", 1)[1]
        asked.append(advisory)
        answer = answers.get(advisory, 404)
        if isinstance(answer, int):
            raise urllib.error.HTTPError(req.full_url, answer, "x", None, None)  # type: ignore[arg-type]
        if isinstance(answer, Exception):
            raise answer
        return _Response(json.dumps({"id": advisory, "aliases": answer}).encode())

    monkeypatch.setattr(ca.urllib.request, "urlopen", urlopen)
    return asked


def test_ghsa_advisory_gets_its_cve(tmp_path, monkeypatch) -> None:
    _osv(monkeypatch, {"GHSA-35jh-r3h4-6jhm": ["CVE-2021-23337", "SNYK-JS-LODASH-1"]})
    vuln = _vuln("GHSA-35jh-r3h4-6jhm")
    assert resolve_cve_aliases([vuln], cache_path=tmp_path / "c.json") == 0
    assert vuln.cve_id == "CVE-2021-23337"
    assert vuln.aliases == ["CVE-2021-23337"]  # only CVE ids are added


def test_advisories_that_already_have_a_cve_are_not_looked_up(tmp_path, monkeypatch) -> None:
    asked = _osv(monkeypatch, {})
    vulns = [_vuln("CVE-2021-1"), _vuln("PYSEC-2021-1", ["CVE-2021-2"]), _vuln("TEST-1")]
    assert resolve_cve_aliases(vulns, cache_path=tmp_path / "c.json") == 0
    assert asked == []


def test_each_advisory_is_asked_once_and_cached(tmp_path, monkeypatch) -> None:
    asked = _osv(monkeypatch, {"GHSA-aaaa-aaaa-aaaa": ["CVE-2024-1"]})
    cache = tmp_path / "c.json"
    first = [_vuln("GHSA-aaaa-aaaa-aaaa"), _vuln("GHSA-aaaa-aaaa-aaaa")]
    resolve_cve_aliases(first, cache_path=cache)
    again = _vuln("GHSA-aaaa-aaaa-aaaa")
    resolve_cve_aliases([again], cache_path=cache)
    assert asked == ["GHSA-aaaa-aaaa-aaaa"]
    assert all(v.cve_id == "CVE-2024-1" for v in [*first, again])


def test_no_cve_is_remembered_for_a_week_only(tmp_path, monkeypatch) -> None:
    asked = _osv(monkeypatch, {"GHSA-bbbb-bbbb-bbbb": []})
    cache = tmp_path / "c.json"
    resolve_cve_aliases([_vuln("GHSA-bbbb-bbbb-bbbb")], cache_path=cache, now=1000.0)
    resolve_cve_aliases([_vuln("GHSA-bbbb-bbbb-bbbb")], cache_path=cache, now=1000.0 + 86400)
    assert len(asked) == 1
    # A CVE can be assigned later: after a week it is asked again.
    resolve_cve_aliases([_vuln("GHSA-bbbb-bbbb-bbbb")], cache_path=cache, now=1000.0 + 8 * 86400)
    assert len(asked) == 2


def test_network_failure_is_counted_not_cached_and_never_raises(tmp_path, monkeypatch) -> None:
    asked = _osv(
        monkeypatch,
        {"GHSA-cccc-cccc-cccc": OSError("no route"), "GHSA-dddd-dddd-dddd": 500},
    )
    cache = tmp_path / "c.json"
    vulns = [_vuln("GHSA-cccc-cccc-cccc"), _vuln("GHSA-dddd-dddd-dddd")]
    assert resolve_cve_aliases(vulns, cache_path=cache) == 2
    assert all(v.cve_id == "" for v in vulns)
    resolve_cve_aliases(vulns, cache_path=cache)
    assert len(asked) == 4  # a failure is retried on the next scan


def test_unknown_advisory_is_not_a_failure(tmp_path, monkeypatch) -> None:
    _osv(monkeypatch, {})  # OSV answers 404
    assert resolve_cve_aliases([_vuln("GHSA-eeee-eeee-eeee")], cache_path=tmp_path / "c") == 0


def test_corrupt_cache_is_ignored(tmp_path, monkeypatch) -> None:
    _osv(monkeypatch, {"GHSA-aaaa-aaaa-aaaa": ["CVE-2024-1"]})
    cache = tmp_path / "c.json"
    cache.write_text("{not json")
    vuln = _vuln("GHSA-aaaa-aaaa-aaaa")
    assert resolve_cve_aliases([vuln], cache_path=cache) == 0
    assert vuln.cve_id == "CVE-2024-1"


def _result(*vulns: Vulnerability) -> ScanResult:
    return ScanResult(
        project_path=".",
        package_manager="npm",
        total_dependencies=1,
        results=[TriageResult(vuln=v, verdict=Verdict.REVIEW) for v in vulns],
    )


def test_kev_does_not_count_advisories_it_cannot_match() -> None:
    entry = KevEntry("CVE-2021-23337", "v", "p", "n", "2026-01-01", "2026-01-20", "Fix", False)
    catalog = KevCatalog({"CVE-2021-23337": entry})
    result = _result(
        _vuln("GHSA-35jh-r3h4-6jhm", ["CVE-2021-23337"]),  # resolved: matches
        _vuln("GHSA-aaaa-aaaa-aaaa", ["CVE-2024-1"]),  # resolved: checked, no match
        _vuln("GHSA-bbbb-bbbb-bbbb"),  # no CVE: cannot be checked
    )
    kev = apply_kev(result, catalog)
    assert (kev.total_checked, kev.kev_matches, kev.unchecked) == (2, 1, 1)
    assert result.results[0].verdict == Verdict.ACTION


AUDIT = {
    "auditReportVersion": 2,
    "vulnerabilities": {
        "lodash": {
            "name": "lodash",
            "severity": "high",
            "isDirect": True,
            "via": [
                {
                    "source": 1,
                    "name": "lodash",
                    "title": "Command Injection in lodash",
                    "url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
                    "severity": "high",
                    "range": "<4.17.21",
                }
            ],
            "range": "<4.17.21",
            "nodes": ["node_modules/lodash"],
            "fixAvailable": True,
        }
    },
}


def _project(tmp_path: Path) -> Path:
    (tmp_path / "package.json").write_text('{"dependencies": {"lodash": "4.17.15"}}')
    (tmp_path / "app.js").write_text("require('lodash');\n")
    return tmp_path


@pytest.mark.cve_alias_lookups
def test_npm_scan_matches_kev_through_the_looked_up_cve(tmp_path, monkeypatch, capsys) -> None:
    from depquiet.cli import main

    monkeypatch.setattr(ca, "_DEFAULT_CACHE", tmp_path / "cache.json")
    monkeypatch.setattr("depquiet.filters.epss.EpssFilter.lookup", lambda self, cves: {})
    _osv(monkeypatch, {"GHSA-35jh-r3h4-6jhm": ["CVE-2021-23337"]})
    kev = tmp_path / "kev.json"
    kev.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {"cveID": "CVE-2021-23337", "vendorProject": "v", "product": "lodash"}
                ]
            }
        )
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(AUDIT)))
    main(["--path", str(_project(tmp_path)), "--stdin", "--kev-file", str(kev), "--json"])
    out = capsys.readouterr()
    [finding] = json.loads(out.out)["results"]
    assert "CVE-2021-23337" in finding["aliases"]
    assert finding["kev"] is not None or finding.get("kev_entry") is not None
    assert "have no CVE id" not in out.err


@pytest.mark.cve_alias_lookups
def test_scan_says_when_cve_lookups_failed_and_kev_could_not_check(
    tmp_path, monkeypatch, capsys
) -> None:
    from depquiet.cli import main

    monkeypatch.setattr(ca, "_DEFAULT_CACHE", tmp_path / "cache.json")
    monkeypatch.setattr("depquiet.filters.epss.EpssFilter.lookup", lambda self, cves: {})
    _osv(monkeypatch, {"GHSA-35jh-r3h4-6jhm": OSError("offline")})
    kev = tmp_path / "kev.json"
    kev.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2021-23337"}]}))
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(AUDIT)))
    main(["--path", str(_project(tmp_path)), "--stdin", "--kev-file", str(kev)])
    out = capsys.readouterr()
    assert "Could not look up the CVE id of 1 advisories" in out.err
    assert "1 advisories have no CVE id" in out.err
    assert "0 of 0 CVEs" in out.out  # not "0 of 1": nothing could be checked


def test_offline_scan_makes_no_lookup(tmp_path, monkeypatch) -> None:
    from depquiet.cli import main

    asked = _osv(monkeypatch, {})
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(AUDIT)))
    main(["--path", str(_project(tmp_path)), "--stdin", "--offline", "--json"])
    assert asked == []
