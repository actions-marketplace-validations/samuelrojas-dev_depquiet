"""Tests for the license compliance engine."""

from __future__ import annotations

import json

from depquiet.license import (
    LicenseInfo,
    LicenseReport,
    LicenseRisk,
    classify_license,
    print_license_report,
    scan_licenses,
    scan_npm_licenses,
)

# -- classify_license --


class TestClassifyLicense:
    def test_spdx_mit(self):
        lid, risk = classify_license("MIT")
        assert lid == "MIT"
        assert risk == LicenseRisk.LOW

    def test_spdx_apache(self):
        lid, risk = classify_license("Apache-2.0")
        assert lid == "Apache-2.0"
        assert risk == LicenseRisk.LOW

    def test_spdx_gpl3(self):
        lid, risk = classify_license("GPL-3.0")
        assert lid == "GPL-3.0"
        assert risk == LicenseRisk.HIGH

    def test_spdx_agpl(self):
        lid, risk = classify_license("AGPL-3.0")
        assert lid == "AGPL-3.0"
        assert risk == LicenseRisk.CRITICAL

    def test_spdx_lgpl(self):
        lid, risk = classify_license("LGPL-2.1")
        assert lid == "LGPL-2.1"
        assert risk == LicenseRisk.MEDIUM

    def test_alias_lowercase_mit(self):
        lid, risk = classify_license("mit")
        assert lid == "MIT"
        assert risk == LicenseRisk.LOW

    def test_alias_apache_long(self):
        lid, risk = classify_license("Apache License 2.0")
        assert lid == "Apache-2.0"
        assert risk == LicenseRisk.LOW

    def test_alias_gplv3(self):
        lid, risk = classify_license("GPLv3")
        assert lid == "GPL-3.0"
        assert risk == LicenseRisk.HIGH

    def test_or_expression_picks_most_permissive(self):
        lid, risk = classify_license("MIT OR GPL-3.0")
        assert lid == "MIT"
        assert risk == LicenseRisk.LOW

    def test_and_expression_picks_most_restrictive(self):
        lid, risk = classify_license("MIT AND GPL-3.0")
        assert lid == "GPL-3.0"
        assert risk == LicenseRisk.HIGH

    def test_unknown_license(self):
        _lid, risk = classify_license("My-Custom-License-1.0")
        assert risk == LicenseRisk.UNKNOWN

    def test_empty_string(self):
        _lid, risk = classify_license("")
        assert risk == LicenseRisk.UNKNOWN

    def test_none_keyword(self):
        _lid, risk = classify_license("NONE")
        assert risk == LicenseRisk.UNKNOWN

    def test_sspl(self):
        lid, risk = classify_license("SSPL-1.0")
        assert lid == "SSPL-1.0"
        assert risk == LicenseRisk.CRITICAL

    def test_mpl(self):
        lid, risk = classify_license("MPL-2.0")
        assert lid == "MPL-2.0"
        assert risk == LicenseRisk.MEDIUM

    def test_or_with_parens(self):
        _lid, risk = classify_license("(MIT OR Apache-2.0)")
        # The parens are on the outer level, not inside the OR split
        # classify_license strips parens from each part
        assert risk == LicenseRisk.LOW


# -- scan_npm_licenses --


class TestScanNpmLicenses:
    def test_reads_package_licenses(self, tmp_path):
        # Create project structure
        (tmp_path / "package.json").write_text("{}")
        nm = tmp_path / "node_modules"
        nm.mkdir()

        # MIT package
        lodash = nm / "lodash"
        lodash.mkdir()
        (lodash / "package.json").write_text(
            json.dumps({"name": "lodash", "version": "4.17.21", "license": "MIT"})
        )

        # GPL package
        gpl_pkg = nm / "gpl-thing"
        gpl_pkg.mkdir()
        (gpl_pkg / "package.json").write_text(
            json.dumps({"name": "gpl-thing", "version": "1.0.0", "license": "GPL-3.0"})
        )

        results = scan_npm_licenses(tmp_path)
        assert len(results) == 2

        by_name = {r.package: r for r in results}
        assert by_name["lodash"].risk == LicenseRisk.LOW
        assert by_name["gpl-thing"].risk == LicenseRisk.HIGH

    def test_handles_licenses_array(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        nm = tmp_path / "node_modules"
        nm.mkdir()

        pkg = nm / "dual-license"
        pkg.mkdir()
        (pkg / "package.json").write_text(
            json.dumps(
                {
                    "name": "dual-license",
                    "version": "1.0.0",
                    "licenses": [{"type": "MIT"}, {"type": "Apache-2.0"}],
                }
            )
        )

        results = scan_npm_licenses(tmp_path)
        assert len(results) == 1
        assert results[0].risk == LicenseRisk.LOW  # OR expression, picks most permissive

    def test_scoped_packages(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        nm = tmp_path / "node_modules"
        scope = nm / "@babel"
        scope.mkdir(parents=True)

        pkg = scope / "core"
        pkg.mkdir()
        (pkg / "package.json").write_text(
            json.dumps({"name": "@babel/core", "version": "7.0.0", "license": "MIT"})
        )

        results = scan_npm_licenses(tmp_path)
        assert len(results) == 1
        assert results[0].package == "@babel/core"

    def test_no_node_modules(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        assert scan_npm_licenses(tmp_path) == []

    def test_no_package_json(self, tmp_path):
        assert scan_npm_licenses(tmp_path) == []

    def test_missing_license_field(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        nm = tmp_path / "node_modules"
        nm.mkdir()

        pkg = nm / "no-license"
        pkg.mkdir()
        (pkg / "package.json").write_text(json.dumps({"name": "no-license", "version": "1.0.0"}))

        results = scan_npm_licenses(tmp_path)
        assert len(results) == 1
        assert results[0].risk == LicenseRisk.UNKNOWN


# -- LicenseReport --


class TestLicenseReport:
    def test_has_issues_with_high(self):
        report = LicenseReport(
            packages=[LicenseInfo("gpl-pkg", "1.0", "GPL-3.0", "GPL-3.0", LicenseRisk.HIGH)]
        )
        assert report.has_issues

    def test_has_issues_with_unknown(self):
        report = LicenseReport(
            packages=[LicenseInfo("mystery", "1.0", "???", "???", LicenseRisk.UNKNOWN)]
        )
        assert report.has_issues

    def test_no_issues_all_permissive(self):
        report = LicenseReport(
            packages=[
                LicenseInfo("a", "1.0", "MIT", "MIT", LicenseRisk.LOW),
                LicenseInfo("b", "1.0", "Apache-2.0", "Apache-2.0", LicenseRisk.LOW),
            ]
        )
        assert not report.has_issues

    def test_property_filters(self):
        report = LicenseReport(
            packages=[
                LicenseInfo("a", "1.0", "MIT", "MIT", LicenseRisk.LOW),
                LicenseInfo("b", "1.0", "LGPL-2.1", "LGPL-2.1", LicenseRisk.MEDIUM),
                LicenseInfo("c", "1.0", "GPL-3.0", "GPL-3.0", LicenseRisk.HIGH),
                LicenseInfo("d", "1.0", "AGPL-3.0", "AGPL-3.0", LicenseRisk.CRITICAL),
                LicenseInfo("e", "1.0", "???", "???", LicenseRisk.UNKNOWN),
            ]
        )
        assert len(report.low) == 1
        assert len(report.medium) == 1
        assert len(report.high) == 1
        assert len(report.critical) == 1
        assert len(report.unknown) == 1


# -- scan_licenses --


class TestScanLicenses:
    def test_auto_detect_npm(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        nm = tmp_path / "node_modules"
        nm.mkdir()
        pkg = nm / "test-pkg"
        pkg.mkdir()
        (pkg / "package.json").write_text(
            json.dumps({"name": "test-pkg", "version": "1.0.0", "license": "MIT"})
        )

        report = scan_licenses(tmp_path)
        assert report.package_manager == "npm"
        assert len(report.packages) == 1

    def test_force_package_manager(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        report = scan_licenses(tmp_path, package_manager="pip")
        assert report.package_manager == "pip"

    def test_unknown_pm(self, tmp_path):
        report = scan_licenses(tmp_path)
        assert report.package_manager == "unknown"
        assert len(report.packages) == 0


# -- print_license_report --


class TestPrintLicenseReport:
    def test_prints_critical(self, capsys):
        report = LicenseReport(
            packages=[LicenseInfo("agpl-pkg", "1.0", "AGPL-3.0", "AGPL-3.0", LicenseRisk.CRITICAL)],
            package_manager="npm",
        )
        print_license_report(report)
        captured = capsys.readouterr()
        assert "CRITICAL" in captured.err
        assert "agpl-pkg" in captured.err

    def test_prints_pass(self, capsys):
        report = LicenseReport(
            packages=[LicenseInfo("a", "1.0", "MIT", "MIT", LicenseRisk.LOW)],
            package_manager="npm",
        )
        print_license_report(report)
        captured = capsys.readouterr()
        assert "PASS" in captured.err

    def test_prints_fail(self, capsys):
        report = LicenseReport(
            packages=[LicenseInfo("a", "1.0", "GPL-3.0", "GPL-3.0", LicenseRisk.HIGH)],
            package_manager="npm",
        )
        print_license_report(report)
        captured = capsys.readouterr()
        assert "FAIL" in captured.err

    def test_empty_report(self, capsys):
        report = LicenseReport(package_manager="npm")
        print_license_report(report)
        captured = capsys.readouterr()
        assert "No dependencies" in captured.err


class TestGetPipLicense:
    """Regression: packages whose metadata has no License field."""

    def _fake_meta(self, headers: list[tuple[str, str]]):
        from email.message import Message

        msg = Message()
        for k, v in headers:
            msg[k] = v
        return msg

    def test_missing_license_falls_back_to_classifier(self, monkeypatch):
        import importlib.metadata

        from depquiet.license import _get_pip_license

        meta = self._fake_meta([("Classifier", "License :: OSI Approved :: MIT License")])
        monkeypatch.setattr(importlib.metadata, "metadata", lambda _name: meta)
        assert _get_pip_license("pkg") == "MIT"

    def test_missing_license_and_classifiers_is_unknown(self, monkeypatch):
        import importlib.metadata

        from depquiet.license import _get_pip_license

        monkeypatch.setattr(importlib.metadata, "metadata", lambda _name: self._fake_meta([]))
        assert _get_pip_license("pkg") == "UNKNOWN"

    def test_license_field_used_when_present(self, monkeypatch):
        import importlib.metadata

        from depquiet.license import _get_pip_license

        meta = self._fake_meta([("License", " Apache-2.0 ")])
        monkeypatch.setattr(importlib.metadata, "metadata", lambda _name: meta)
        assert _get_pip_license("pkg") == "Apache-2.0"
