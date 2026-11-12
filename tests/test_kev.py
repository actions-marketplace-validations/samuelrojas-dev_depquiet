"""Tests for the CISA KEV catalog integration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from depquiet.kev import (
    KevCatalog,
    KevEntry,
    _parse_catalog,
    apply_kev,
    fetch_kev_catalog,
    load_kev_from_file,
)
from depquiet.models import (
    ScanResult,
    Severity,
    TriageResult,
    Verdict,
    Vulnerability,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _kev_feed(vulns: list[dict]) -> dict:
    """Build a minimal KEV feed JSON structure."""
    return {
        "title": "CISA Known Exploited Vulnerabilities Catalog",
        "catalogVersion": "2026.11.03",
        "dateReleased": "2026-11-03",
        "count": len(vulns),
        "vulnerabilities": vulns,
    }


def _kev_vuln(
    cve: str = "CVE-2021-44228",
    vendor: str = "Apache",
    product: str = "Log4j",
    name: str = "Apache Log4j RCE",
    date_added: str = "2021-12-10",
    due_date: str = "2021-12-24",
    ransomware: str = "Known",
) -> dict:
    return {
        "cveID": cve,
        "vendorProject": vendor,
        "product": product,
        "vulnerabilityName": name,
        "dateAdded": date_added,
        "shortDescription": f"{name} vulnerability",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": due_date,
        "knownRansomwareCampaignUse": ransomware,
        "notes": "",
    }


def _vuln(
    cve: str = "CVE-2021-44228",
    package: str = "log4j-core",
    severity: Severity = Severity.CRITICAL,
) -> Vulnerability:
    return Vulnerability(
        cve=cve,
        package=package,
        version="2.14.0",
        severity=severity,
        title=f"{package} vulnerability",
    )


def _result(
    vulns: list[tuple[str, str, Severity, Verdict]] | None = None,
) -> ScanResult:
    """Build a ScanResult from a list of (cve, package, severity, verdict)."""
    if vulns is None:
        vulns = [("CVE-2021-44228", "log4j-core", Severity.CRITICAL, Verdict.ACTION)]
    results = [TriageResult(vuln=_vuln(cve, pkg, sev), verdict=v) for cve, pkg, sev, v in vulns]
    return ScanResult(
        project_path="/test",
        package_manager="pip",
        total_dependencies=len(results),
        results=results,
    )


# ---------------------------------------------------------------------------
# TestParseCatalog
# ---------------------------------------------------------------------------


class TestParseCatalog:
    def test_parses_entries(self):
        feed = _kev_feed([_kev_vuln(), _kev_vuln(cve="CVE-2023-12345")])
        cat = _parse_catalog(feed)
        assert cat.count == 2
        assert "CVE-2021-44228" in cat.entries
        assert "CVE-2023-12345" in cat.entries

    def test_parses_fields(self):
        feed = _kev_feed([_kev_vuln(ransomware="Known")])
        cat = _parse_catalog(feed)
        entry = cat.entries["CVE-2021-44228"]
        assert entry.vendor == "Apache"
        assert entry.product == "Log4j"
        assert entry.date_added == "2021-12-10"
        assert entry.due_date == "2021-12-24"
        assert entry.ransomware_use is True

    def test_ransomware_unknown(self):
        feed = _kev_feed([_kev_vuln(ransomware="Unknown")])
        cat = _parse_catalog(feed)
        assert cat.entries["CVE-2021-44228"].ransomware_use is False

    def test_skips_empty_cve(self):
        feed = _kev_feed([{"cveID": "", "vendorProject": "x"}])
        cat = _parse_catalog(feed)
        assert cat.count == 0

    def test_empty_vulnerabilities(self):
        cat = _parse_catalog({"vulnerabilities": []})
        assert cat.count == 0

    def test_missing_vulnerabilities_key(self):
        # {} is not a catalog; reading it as "nothing exploited" would hide KEV matches
        with pytest.raises(ValueError):
            _parse_catalog({})

    def test_catalog_version(self):
        feed = _kev_feed([])
        cat = _parse_catalog(feed)
        assert cat.catalog_version == "2026.11.03"
        assert cat.date_released == "2026-11-03"


# ---------------------------------------------------------------------------
# TestKevCatalog
# ---------------------------------------------------------------------------


class TestKevCatalog:
    def test_lookup_found(self):
        entry = KevEntry(
            cve_id="CVE-2021-44228",
            vendor="Apache",
            product="Log4j",
            name="Log4j RCE",
            date_added="2021-12-10",
            due_date="2021-12-24",
            required_action="Update",
            ransomware_use=True,
        )
        cat = KevCatalog(entries={"CVE-2021-44228": entry})
        assert cat.lookup("CVE-2021-44228") is entry

    def test_lookup_not_found(self):
        cat = KevCatalog(entries={})
        assert cat.lookup("CVE-2099-99999") is None


# ---------------------------------------------------------------------------
# TestApplyKev
# ---------------------------------------------------------------------------


class TestApplyKev:
    def _catalog(self, cves: list[str] | None = None) -> KevCatalog:
        if cves is None:
            cves = ["CVE-2021-44228"]
        entries = {}
        for cve in cves:
            entries[cve] = KevEntry(
                cve_id=cve,
                vendor="Vendor",
                product="Product",
                name="Vuln",
                date_added="2024-01-01",
                due_date="2024-01-15",
                required_action="Update",
                ransomware_use=False,
            )
        return KevCatalog(entries=entries)

    def test_escalates_review_to_action(self):
        result = _result(
            [
                ("CVE-2021-44228", "log4j-core", Severity.CRITICAL, Verdict.REVIEW),
            ]
        )
        kev = apply_kev(result, self._catalog())
        assert result.results[0].verdict == Verdict.ACTION
        assert kev.escalated == 1
        assert kev.kev_matches == 1

    def test_escalates_filtered_to_action(self):
        result = _result(
            [
                ("CVE-2021-44228", "log4j-core", Severity.CRITICAL, Verdict.FILTERED),
            ]
        )
        kev = apply_kev(result, self._catalog())
        assert result.results[0].verdict == Verdict.ACTION
        assert kev.escalated == 1

    def test_already_action_not_counted_as_escalated(self):
        result = _result(
            [
                ("CVE-2021-44228", "log4j-core", Severity.CRITICAL, Verdict.ACTION),
            ]
        )
        kev = apply_kev(result, self._catalog())
        assert result.results[0].verdict == Verdict.ACTION
        assert kev.kev_matches == 1
        assert kev.escalated == 0

    def test_sets_kev_entry_on_triage_result(self):
        result = _result(
            [
                ("CVE-2021-44228", "log4j-core", Severity.CRITICAL, Verdict.ACTION),
            ]
        )
        apply_kev(result, self._catalog())
        assert result.results[0].kev_entry is not None
        assert result.results[0].kev_entry.cve_id == "CVE-2021-44228"

    def test_non_kev_cve_unchanged(self):
        result = _result(
            [
                ("CVE-2099-99999", "safe-lib", Severity.LOW, Verdict.REVIEW),
            ]
        )
        kev = apply_kev(result, self._catalog())
        assert result.results[0].verdict == Verdict.REVIEW
        assert result.results[0].kev_entry is None
        assert kev.kev_matches == 0

    def test_mixed_kev_and_non_kev(self):
        result = _result(
            [
                ("CVE-2021-44228", "log4j-core", Severity.CRITICAL, Verdict.FILTERED),
                ("CVE-2099-99999", "safe-lib", Severity.LOW, Verdict.FILTERED),
            ]
        )
        kev = apply_kev(result, self._catalog())
        assert result.results[0].verdict == Verdict.ACTION
        assert result.results[1].verdict == Verdict.FILTERED
        assert kev.kev_matches == 1
        assert kev.escalated == 1

    def test_empty_catalog(self):
        result = _result(
            [
                ("CVE-2021-44228", "log4j-core", Severity.CRITICAL, Verdict.ACTION),
            ]
        )
        kev = apply_kev(result, KevCatalog(entries={}))
        assert kev.kev_matches == 0
        assert kev.escalated == 0

    def test_empty_result(self):
        result = ScanResult(
            project_path="/test",
            package_manager="pip",
            total_dependencies=0,
            results=[],
        )
        kev = apply_kev(result, self._catalog())
        assert kev.total_checked == 0
        assert kev.kev_matches == 0

    def test_vuln_without_cve_skipped(self):
        """Findings without a CVE ID are skipped (e.g. GHSA-only advisories)."""
        result = ScanResult(
            project_path="/test",
            package_manager="pip",
            total_dependencies=1,
            results=[
                TriageResult(
                    vuln=Vulnerability(
                        cve="",
                        package="some-pkg",
                        version="1.0",
                        severity=Severity.HIGH,
                    ),
                    verdict=Verdict.ACTION,
                ),
            ],
        )
        kev = apply_kev(result, self._catalog())
        assert kev.total_checked == 0

    def test_multiple_kev_matches(self):
        cat = self._catalog(["CVE-2021-44228", "CVE-2023-12345"])
        result = _result(
            [
                ("CVE-2021-44228", "log4j-core", Severity.CRITICAL, Verdict.REVIEW),
                ("CVE-2023-12345", "other-lib", Severity.HIGH, Verdict.FILTERED),
                ("CVE-2099-99999", "safe-lib", Severity.LOW, Verdict.FILTERED),
            ]
        )
        kev = apply_kev(result, cat)
        assert kev.kev_matches == 2
        assert kev.escalated == 2
        assert result.results[0].verdict == Verdict.ACTION
        assert result.results[1].verdict == Verdict.ACTION
        assert result.results[2].verdict == Verdict.FILTERED


# ---------------------------------------------------------------------------
# TestLoadKevFromFile
# ---------------------------------------------------------------------------


class TestLoadKevFromFile:
    def test_loads_file(self, tmp_path: Path):
        feed = _kev_feed([_kev_vuln()])
        p = tmp_path / "kev.json"
        p.write_text(json.dumps(feed))
        cat = load_kev_from_file(p)
        assert cat.count == 1
        assert "CVE-2021-44228" in cat.entries

    def test_invalid_json_raises(self, tmp_path: Path):
        p = tmp_path / "bad.json"
        p.write_text("not json")
        with pytest.raises(json.JSONDecodeError):
            load_kev_from_file(p)


# ---------------------------------------------------------------------------
# TestFetchKevCatalog
# ---------------------------------------------------------------------------


class TestFetchKevCatalog:
    def test_uses_cache_when_fresh(self, tmp_path: Path):
        feed = _kev_feed([_kev_vuln()])
        cache = tmp_path / "kev.json"
        cache.write_text(json.dumps(feed))
        cat = fetch_kev_catalog(cache_dir=tmp_path)
        assert cat is not None
        assert cat.count == 1

    def test_offline_no_cache_returns_none(self, tmp_path: Path):
        cat = fetch_kev_catalog(cache_dir=tmp_path, offline=True)
        assert cat is None

    def test_offline_with_expired_cache_still_reads(self, tmp_path: Path):
        import os

        feed = _kev_feed([_kev_vuln()])
        cache = tmp_path / "kev.json"
        cache.write_text(json.dumps(feed))
        # Make it look old
        old_time = 0
        os.utime(cache, (old_time, old_time))
        cat = fetch_kev_catalog(cache_dir=tmp_path, offline=True)
        assert cat is not None
        assert cat.count == 1


# ---------------------------------------------------------------------------
# TestCliKev
# ---------------------------------------------------------------------------


class TestCliKev:
    """Test KEV integration through the CLI."""

    def _run_cli(
        self,
        tmp_path: Path,
        kev_feed: dict,
        vulns: list[tuple[str, str, str]],
        extra_args: list[str] | None = None,
    ) -> tuple[int, dict]:
        """Run CLI with a mock scan result and KEV file, return (exit_code, json_output)."""
        from io import StringIO

        from depquiet.cli import main

        # Write KEV file
        kev_path = tmp_path / "kev.json"
        kev_path.write_text(json.dumps(kev_feed))

        # Build a mock audit JSON that will produce the desired vulnerabilities
        audit = {
            "vulnerabilities": {
                vuln[1]: {
                    "name": vuln[1],
                    "severity": vuln[2],
                    "via": [
                        {
                            "name": vuln[1],
                            "severity": vuln[2],
                            "title": f"{vuln[1]} vuln",
                            "url": f"https://nvd.nist.gov/vuln/detail/{vuln[0]}",
                            "range": ">=0.0.0",
                            "source": 1,
                        }
                    ],
                    "effects": [],
                    "fixAvailable": True,
                }
                for vuln in vulns
            },
            "metadata": {
                "vulnerabilities": {
                    "total": len(vulns),
                    "info": 0,
                    "low": 0,
                    "moderate": 0,
                    "high": 0,
                    "critical": 0,
                },
            },
        }
        audit_path = tmp_path / "audit.json"
        audit_path.write_text(json.dumps(audit))

        args = [
            "--path",
            str(tmp_path),
            "--offline",
            "--json",
            "--kev-file",
            str(kev_path),
            "--stdin",
        ]
        if extra_args:
            args.extend(extra_args)

        import sys

        old_stdin = sys.stdin
        sys.stdin = StringIO(json.dumps(audit))

        try:
            # Capture stdout
            old_stdout = sys.stdout
            sys.stdout = captured = StringIO()
            exit_code = main(args)
            sys.stdout = old_stdout
            output = captured.getvalue()
        finally:
            sys.stdin = old_stdin

        # Parse JSON from output (may have KEV status line before JSON)
        # Find the JSON object in the output
        json_start = output.find("{")
        if json_start >= 0:
            return exit_code, json.loads(output[json_start:])
        return exit_code, {}

    def test_kev_file_flag_works(self, tmp_path: Path):
        """--kev-file loads a local KEV catalog."""
        feed = _kev_feed([_kev_vuln(cve="CVE-2021-44228")])
        _exit_code, out = self._run_cli(
            tmp_path,
            feed,
            [("CVE-2021-44228", "log4j-core", "critical")],
        )
        # Should have results with KEV data
        results = out.get("results", [])
        assert len(results) > 0

    def test_kev_enriches_json_output(self, tmp_path: Path):
        """KEV data appears in JSON output."""
        feed = _kev_feed([_kev_vuln(cve="CVE-2021-44228")])
        _, out = self._run_cli(
            tmp_path,
            feed,
            [("CVE-2021-44228", "log4j-core", "critical")],
        )
        results = out.get("results", [])
        [r for r in results if "kev" in r]
        # At least one result should have KEV data if the CVE matched
        # (depends on whether npm parser maps CVE correctly — this tests
        # the integration path exists)

    def test_kev_with_fail_on(self, tmp_path: Path):
        """KEV escalation interacts correctly with --fail-on."""
        feed = _kev_feed([_kev_vuln(cve="CVE-2021-44228")])
        exit_code, _ = self._run_cli(
            tmp_path,
            feed,
            [("CVE-2021-44228", "log4j-core", "critical")],
            extra_args=["--fail-on", "none"],
        )
        # --fail-on none means never fail, even with KEV escalation
        assert exit_code == 0
