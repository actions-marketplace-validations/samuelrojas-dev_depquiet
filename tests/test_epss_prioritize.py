"""EPSS orders the report; it filters only when a threshold is asked for.

Scanners for Python and npm name advisories by PYSEC or GHSA ids, so the
lookup has to use the CVE alias or EPSS never applies to them.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from depquiet.filters.epss import EpssFilter
from depquiet.models import Severity, TriageResult, Verdict, Vulnerability
from depquiet.output import _priority


def _vuln(cve: str, aliases: list[str] | None = None, severity: Severity = Severity.HIGH):
    return Vulnerability(
        cve=cve, package="pkg", version="1.0", severity=severity, aliases=aliases or []
    )


def _response(cve: str, epss: float):
    resp = MagicMock()
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    resp.read.return_value = json.dumps(
        {"data": [{"cve": cve, "epss": str(epss), "percentile": "0.5"}]}
    ).encode()
    return resp


def test_cve_id_prefers_the_advisory_then_its_alias():
    assert _vuln("CVE-2024-1").cve_id == "CVE-2024-1"
    assert _vuln("GHSA-xxxx-yyyy-zzzz", ["PYSEC-2024-9", "CVE-2024-2"]).cve_id == "CVE-2024-2"
    assert _vuln("PYSEC-2024-9").cve_id == ""


def test_default_filter_never_filters_even_a_tiny_score():
    f = EpssFilter()
    with patch(
        "depquiet.filters.epss.urllib.request.urlopen", return_value=_response("CVE-2024-2", 0.0001)
    ):
        f.lookup(["CVE-2024-2"])
    assert not f.check(_vuln("GHSA-xxxx-yyyy-zzzz", ["CVE-2024-2"]))


def test_explicit_threshold_filters_through_the_alias():
    f = EpssFilter(threshold=0.1)
    with patch(
        "depquiet.filters.epss.urllib.request.urlopen", return_value=_response("CVE-2024-2", 0.02)
    ):
        f.lookup(["CVE-2024-2"])
    assert f.check(_vuln("GHSA-xxxx-yyyy-zzzz", ["CVE-2024-2"]))
    assert not f.check(_vuln("GHSA-aaaa-bbbb-cccc"))  # no CVE, no score: kept


def _result(epss: float | None, severity: Severity = Severity.HIGH, kev: bool = False):
    return TriageResult(
        vuln=_vuln("CVE-2024-1", severity=severity),
        verdict=Verdict.ACTION,
        epss_score=epss,
        kev_entry=object() if kev else None,
    )


def test_priority_puts_kev_first_then_epss_then_severity():
    kev = _result(0.01, kev=True)
    high_epss = _result(0.9, Severity.LOW)
    low_epss = _result(0.05)
    none_critical = _result(None, Severity.CRITICAL)
    none_low = _result(None, Severity.LOW)
    ordered = sorted([none_low, low_epss, none_critical, high_epss, kev], key=_priority)
    assert ordered == [kev, high_epss, low_epss, none_critical, none_low]
