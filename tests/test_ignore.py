"""Tests for the .depquiet-ignore suppression file."""

from __future__ import annotations

from datetime import date

from depquiet.ignore import (
    IgnoreEntry,
    IgnoreFile,
    _parse_date,
    _parse_ignore_yaml,
    apply_ignores,
    load_ignore,
    print_ignore_warnings,
)
from depquiet.models import (
    FilterReason,
    ScanResult,
    Severity,
    TriageResult,
    Verdict,
    Vulnerability,
)

# -- IgnoreEntry --


class TestIgnoreEntry:
    def test_key_cve_only(self):
        e = IgnoreEntry(cve="CVE-2024-1234")
        assert e.key == "CVE-2024-1234"

    def test_key_package_only(self):
        e = IgnoreEntry(package="lodash")
        assert e.key == "lodash"

    def test_key_cve_and_package(self):
        e = IgnoreEntry(cve="CVE-2024-1234", package="lodash")
        assert e.key == "CVE-2024-1234:lodash"

    def test_key_empty(self):
        e = IgnoreEntry()
        assert e.key == ""

    def test_not_expired_no_date(self):
        e = IgnoreEntry(cve="CVE-2024-1234")
        assert not e.is_expired()

    def test_not_expired_future(self):
        e = IgnoreEntry(cve="CVE-2024-1234", expires=date(2099, 12, 31))
        assert not e.is_expired(today=date(2026, 1, 1))

    def test_expired(self):
        e = IgnoreEntry(cve="CVE-2024-1234", expires=date(2025, 1, 1))
        assert e.is_expired(today=date(2026, 1, 1))

    def test_expired_same_day_not_expired(self):
        e = IgnoreEntry(cve="CVE-2024-1234", expires=date(2026, 1, 1))
        assert not e.is_expired(today=date(2026, 1, 1))


# -- IgnoreFile --


class TestIgnoreFile:
    def test_active_filters_expired(self):
        f = IgnoreFile(
            entries=[
                IgnoreEntry(cve="CVE-1", expires=date(2020, 1, 1)),
                IgnoreEntry(cve="CVE-2"),
            ]
        )
        assert len(f.active) == 1
        assert f.active[0].cve == "CVE-2"

    def test_expired_property(self):
        f = IgnoreFile(
            entries=[
                IgnoreEntry(cve="CVE-1", expires=date(2020, 1, 1)),
                IgnoreEntry(cve="CVE-2"),
            ]
        )
        assert len(f.expired) == 1
        assert f.expired[0].cve == "CVE-1"

    def test_matches_cve_only(self):
        f = IgnoreFile(entries=[IgnoreEntry(cve="CVE-2024-1234", reason="ok")])
        m = f.matches("CVE-2024-1234", "lodash")
        assert m is not None
        assert m.cve == "CVE-2024-1234"

    def test_matches_cve_and_package(self):
        f = IgnoreFile(
            entries=[
                IgnoreEntry(cve="CVE-2024-1234", reason="general"),
                IgnoreEntry(cve="CVE-2024-1234", package="lodash", reason="specific"),
            ]
        )
        m = f.matches("CVE-2024-1234", "lodash")
        assert m is not None
        assert m.reason == "specific"  # CVE+package wins over CVE-only

    def test_matches_package_only(self):
        f = IgnoreFile(entries=[IgnoreEntry(package="deprecated-pkg", reason="migrating")])
        m = f.matches("CVE-2024-9999", "deprecated-pkg")
        assert m is not None
        assert m.reason == "migrating"

    def test_no_match(self):
        f = IgnoreFile(entries=[IgnoreEntry(cve="CVE-2024-1234", reason="ok")])
        assert f.matches("CVE-2024-9999", "other-pkg") is None

    def test_expired_not_matched(self):
        f = IgnoreFile(
            entries=[
                IgnoreEntry(
                    cve="CVE-2024-1234",
                    reason="old",
                    expires=date(2020, 1, 1),
                )
            ]
        )
        assert f.matches("CVE-2024-1234", "lodash") is None

    def test_matches_package_for_license(self):
        f = IgnoreFile(entries=[IgnoreEntry(package="gpl-thing", reason="accepted")])
        m = f.matches_package("gpl-thing")
        assert m is not None
        assert m.reason == "accepted"

    def test_matches_package_ignores_cve_entries(self):
        f = IgnoreFile(
            entries=[IgnoreEntry(cve="CVE-1", package="gpl-thing", reason="cve-specific")]
        )
        # CVE+package entries should NOT match package-only lookups
        assert f.matches_package("gpl-thing") is None

    def test_matches_package_no_match(self):
        f = IgnoreFile(entries=[IgnoreEntry(package="other", reason="ok")])
        assert f.matches_package("gpl-thing") is None


# -- YAML parsing --


class TestParseIgnoreYaml:
    def test_basic(self):
        text = """\
ignores:
  - cve: CVE-2024-1234
    reason: mitigated by WAF
    expires: 2025-06-01
    author: alice
"""
        entries = _parse_ignore_yaml(text)
        assert len(entries) == 1
        assert entries[0]["cve"] == "CVE-2024-1234"
        assert entries[0]["reason"] == "mitigated by WAF"
        assert entries[0]["expires"] == "2025-06-01"
        assert entries[0]["author"] == "alice"

    def test_multiple_entries(self):
        text = """\
ignores:
  - cve: CVE-1
    reason: ok
  - cve: CVE-2
    package: lodash
    reason: tests only
"""
        entries = _parse_ignore_yaml(text)
        assert len(entries) == 2

    def test_comments_ignored(self):
        text = """\
# Top comment
ignores:
  # Entry comment
  - cve: CVE-1
    reason: ok
"""
        entries = _parse_ignore_yaml(text)
        assert len(entries) == 1

    def test_quoted_values(self):
        text = """\
ignores:
  - cve: 'CVE-2024-1234'
    reason: "mitigated"
"""
        entries = _parse_ignore_yaml(text)
        assert entries[0]["cve"] == "CVE-2024-1234"
        assert entries[0]["reason"] == "mitigated"

    def test_empty_file(self):
        assert _parse_ignore_yaml("") == []

    def test_no_ignores_key(self):
        assert _parse_ignore_yaml("other: value") == []


# -- _parse_date --


class TestParseDate:
    def test_valid(self):
        assert _parse_date("2025-06-01") == date(2025, 6, 1)

    def test_quoted(self):
        assert _parse_date("'2025-06-01'") == date(2025, 6, 1)

    def test_empty(self):
        assert _parse_date("") is None

    def test_invalid(self):
        assert _parse_date("not-a-date") is None

    def test_partial(self):
        assert _parse_date("2025-13-01") is None  # month 13


# -- load_ignore --


class TestLoadIgnore:
    def test_loads_from_project(self, tmp_path):
        ignore = tmp_path / ".depquiet-ignore"
        ignore.write_text("ignores:\n  - cve: CVE-1\n    reason: ok\n", encoding="utf-8")
        result = load_ignore(tmp_path)
        assert result is not None
        assert len(result.entries) == 1

    def test_loads_yaml_extension(self, tmp_path):
        ignore = tmp_path / ".depquiet-ignore.yaml"
        ignore.write_text("ignores:\n  - cve: CVE-1\n    reason: ok\n", encoding="utf-8")
        result = load_ignore(tmp_path)
        assert result is not None

    def test_explicit_path(self, tmp_path):
        custom = tmp_path / "custom-ignore.yaml"
        custom.write_text("ignores:\n  - package: foo\n    reason: ok\n", encoding="utf-8")
        result = load_ignore(tmp_path, ignore_path=custom)
        assert result is not None
        assert result.entries[0].package == "foo"

    def test_missing_explicit_path(self, tmp_path, capsys):
        result = load_ignore(tmp_path, ignore_path=tmp_path / "nope.yaml")
        assert result is None
        assert "not found" in capsys.readouterr().err

    def test_no_ignore_file(self, tmp_path):
        assert load_ignore(tmp_path) is None

    def test_entry_without_cve_or_package_warns(self, tmp_path, capsys):
        ignore = tmp_path / ".depquiet-ignore"
        ignore.write_text("ignores:\n  - reason: orphan entry\n", encoding="utf-8")
        result = load_ignore(tmp_path)
        assert result is not None
        assert len(result.entries) == 0
        assert "needs 'cve' or 'package'" in capsys.readouterr().err

    def test_entry_without_reason_warns(self, tmp_path, capsys):
        ignore = tmp_path / ".depquiet-ignore"
        ignore.write_text("ignores:\n  - cve: CVE-1\n", encoding="utf-8")
        result = load_ignore(tmp_path)
        assert result is not None
        assert len(result.entries) == 1  # still loaded
        assert "missing 'reason'" in capsys.readouterr().err


# -- print_ignore_warnings --


class TestPrintIgnoreWarnings:
    def test_prints_expired(self, capsys):
        f = IgnoreFile(
            entries=[
                IgnoreEntry(
                    cve="CVE-1",
                    reason="old",
                    expires=date(2020, 1, 1),
                )
            ],
            path=".depquiet-ignore",
        )
        print_ignore_warnings(f)
        captured = capsys.readouterr()
        assert "expired" in captured.err
        assert "CVE-1" in captured.err

    def test_no_output_when_none_expired(self, capsys):
        f = IgnoreFile(
            entries=[IgnoreEntry(cve="CVE-1", reason="ok")],
            path=".depquiet-ignore",
        )
        print_ignore_warnings(f)
        assert capsys.readouterr().err == ""

    def test_expired_cve_and_package(self, capsys):
        f = IgnoreFile(
            entries=[
                IgnoreEntry(
                    cve="CVE-1",
                    package="lodash",
                    reason="old",
                    expires=date(2020, 1, 1),
                )
            ],
            path=".depquiet-ignore",
        )
        print_ignore_warnings(f)
        captured = capsys.readouterr()
        assert "CVE-1 (lodash)" in captured.err


# -- apply_ignores --


def _make_vuln(cve: str, package: str) -> Vulnerability:
    return Vulnerability(cve=cve, package=package, version="1.0.0", severity=Severity.HIGH)


def _make_result(vulns: list[tuple[str, str, Verdict]]) -> ScanResult:
    results = []
    for cve, pkg, verdict in vulns:
        results.append(TriageResult(vuln=_make_vuln(cve, pkg), verdict=verdict))
    return ScanResult(
        project_path=".", package_manager="npm", total_dependencies=10, results=results
    )


class TestApplyIgnores:
    def test_suppresses_action(self):
        result = _make_result([("CVE-1", "lodash", Verdict.ACTION)])
        ignore = IgnoreFile(entries=[IgnoreEntry(cve="CVE-1", reason="mitigated")])
        apply_ignores(result, ignore)
        assert result.results[0].verdict == Verdict.FILTERED
        assert FilterReason.IGNORED in result.results[0].reasons

    def test_suppresses_review(self):
        result = _make_result([("CVE-1", "lodash", Verdict.REVIEW)])
        ignore = IgnoreFile(entries=[IgnoreEntry(cve="CVE-1", reason="mitigated")])
        apply_ignores(result, ignore)
        assert result.results[0].verdict == Verdict.FILTERED

    def test_does_not_re_suppress_filtered(self):
        result = _make_result([("CVE-1", "lodash", Verdict.FILTERED)])
        result.results[0].reasons = [FilterReason.UNREACHABLE]
        ignore = IgnoreFile(entries=[IgnoreEntry(cve="CVE-1", reason="mitigated")])
        apply_ignores(result, ignore)
        # Should keep original reason, not change to IGNORED
        assert result.results[0].reasons == [FilterReason.UNREACHABLE]

    def test_no_match_unchanged(self):
        result = _make_result([("CVE-1", "lodash", Verdict.ACTION)])
        ignore = IgnoreFile(entries=[IgnoreEntry(cve="CVE-OTHER", reason="unrelated")])
        apply_ignores(result, ignore)
        assert result.results[0].verdict == Verdict.ACTION

    def test_package_only_suppression(self):
        result = _make_result(
            [
                ("CVE-1", "deprecated-pkg", Verdict.ACTION),
                ("CVE-2", "deprecated-pkg", Verdict.ACTION),
            ]
        )
        ignore = IgnoreFile(entries=[IgnoreEntry(package="deprecated-pkg", reason="migrating")])
        apply_ignores(result, ignore)
        assert all(r.verdict == Verdict.FILTERED for r in result.results)

    def test_mixed_match_and_no_match(self):
        result = _make_result(
            [
                ("CVE-1", "lodash", Verdict.ACTION),
                ("CVE-2", "express", Verdict.ACTION),
            ]
        )
        ignore = IgnoreFile(entries=[IgnoreEntry(cve="CVE-1", reason="ok")])
        apply_ignores(result, ignore)
        assert result.results[0].verdict == Verdict.FILTERED
        assert result.results[1].verdict == Verdict.ACTION
