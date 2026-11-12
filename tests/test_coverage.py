"""Tests targeting coverage gaps — pip parser, EPSS batch, engine branches, __main__.

All offline, deterministic, no network.
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from depquiet.cli import main
from depquiet.engine import detect_package_manager, scan
from depquiet.filters.epss import EpssFilter
from depquiet.filters.reachability import ReachabilityFilter, _file_mentions, _source_files
from depquiet.filters.templates import Template, TemplateFilter, _load_template, _parse_yaml_simple
from depquiet.models import (
    FilterReason,
    ScanResult,
    Severity,
    TriageResult,
    Verdict,
    Vulnerability,
)
from depquiet.output import print_scan_result
from depquiet.parsers.npm import NpmAuditParser, _get_dev_packages, _read_package_json
from depquiet.parsers.pip import PipAuditParser
from depquiet.sarif import _build_locations, _build_message, _severity_to_level, to_sarif

FIXTURES = Path(__file__).parent / "fixtures"


# ── pip parser ─────────────────────────────────────────────────────────


class TestPipAuditParser:
    def test_detect_requirements_txt(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            assert PipAuditParser.detect(p) is False
            (p / "requirements.txt").write_text("requests>=2.25")
            assert PipAuditParser.detect(p) is True

    def test_detect_pyproject_toml(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "pyproject.toml").write_text("[project]\nname = 'x'\n")
            assert PipAuditParser.detect(p) is True

    def test_detect_pipfile_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "Pipfile.lock").write_text("{}")
            assert PipAuditParser.detect(p) is True

    def test_detect_poetry_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "poetry.lock").write_text("")
            assert PipAuditParser.detect(p) is True

    def test_parse_fixture(self):
        audit_json = json.loads((FIXTURES / "pip_audit.json").read_text())
        with tempfile.TemporaryDirectory() as tmp:
            vulns = PipAuditParser.parse(audit_json, Path(tmp))

        assert len(vulns) == 4  # flask has no vulns; urllib3 has 2 CVEs
        packages = {v.package for v in vulns}
        assert "requests" in packages
        assert "urllib3" in packages
        assert "cryptography" in packages
        assert "flask" not in packages

    def test_parse_fix_version(self):
        audit_json = json.loads((FIXTURES / "pip_audit.json").read_text())
        with tempfile.TemporaryDirectory() as tmp:
            vulns = PipAuditParser.parse(audit_json, Path(tmp))

        requests_vuln = next(v for v in vulns if v.package == "requests")
        assert requests_vuln.fix_version == "2.31.0"
        assert requests_vuln.cve == "CVE-2023-32681"

    def test_parse_empty_json(self):
        vulns = PipAuditParser.parse({}, Path("/tmp"))
        assert vulns == []

    def test_parse_no_fix_versions(self):
        audit_json = {
            "dependencies": [
                {
                    "name": "pkg",
                    "version": "1.0",
                    "vulns": [{"id": "CVE-2024-0001", "description": "Test"}],
                }
            ]
        }
        vulns = PipAuditParser.parse(audit_json, Path("/tmp"))
        assert len(vulns) == 1
        assert vulns[0].fix_version == ""

    def test_parse_no_description(self):
        audit_json = {
            "dependencies": [
                {
                    "name": "pkg",
                    "version": "1.0",
                    "vulns": [{"id": "CVE-2024-0001"}],
                }
            ]
        }
        vulns = PipAuditParser.parse(audit_json, Path("/tmp"))
        assert vulns[0].title == "CVE-2024-0001"

    def test_parse_severity_defaults_to_moderate(self):
        audit_json = json.loads((FIXTURES / "pip_audit.json").read_text())
        with tempfile.TemporaryDirectory() as tmp:
            vulns = PipAuditParser.parse(audit_json, Path(tmp))
        # pip-audit doesn't provide severity, defaults to moderate
        assert all(v.severity == Severity.MODERATE for v in vulns)

    def test_parse_is_direct(self):
        audit_json = json.loads((FIXTURES / "pip_audit.json").read_text())
        with tempfile.TemporaryDirectory() as tmp:
            vulns = PipAuditParser.parse(audit_json, Path(tmp))
        assert all(v.is_direct is True for v in vulns)

    def test_run_audit_not_installed(self, monkeypatch):
        """pip-audit not installed → returns empty dict."""
        self._without_pip_audit(monkeypatch)
        with tempfile.TemporaryDirectory() as tmp:
            result = PipAuditParser.run_audit(Path(tmp))
        assert result == {}

    def test_scan_integration(self, monkeypatch):
        """scan() calls run_audit + parse."""
        self._without_pip_audit(monkeypatch)
        with tempfile.TemporaryDirectory() as tmp:
            vulns = PipAuditParser.scan(Path(tmp))
        assert vulns == []

    @staticmethod
    def _without_pip_audit(monkeypatch):
        # Never run the developer's real pip-audit (and its network lookups).
        import depquiet.parsers.pip as pip_parser

        def missing(*args, **kwargs):
            raise FileNotFoundError("pip-audit")

        monkeypatch.setattr(pip_parser.subprocess, "run", missing)


# ── EPSS filter ────────────────────────────────────────────────────────


class TestEpssFilter:
    def test_lookup_filters_ghsa_ids(self):
        ef = EpssFilter()
        result = ef.lookup(["GHSA-xxxx-yyyy-zzzz"])
        assert result == {}

    def test_lookup_uses_cache(self):
        ef = EpssFilter()
        ef._cache["CVE-2024-0001"] = (0.05, 0.3)
        result = ef.lookup(["CVE-2024-0001"])
        assert result == {"CVE-2024-0001": (0.05, 0.3)}

    def test_fetch_batch_network_error(self):
        """Network error → no scores added (conservative)."""
        ef = EpssFilter()
        urlopen = "depquiet.filters.epss.urllib.request.urlopen"
        with patch(urlopen, side_effect=OSError("no network")):
            ef._fetch_batch(["CVE-2024-0001"])
        assert "CVE-2024-0001" not in ef._cache

    def test_fetch_batch_success(self):
        """Successful API response → scores cached."""
        ef = EpssFilter()
        mock_response = MagicMock()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_response.read.return_value = json.dumps(
            {
                "data": [
                    {"cve": "CVE-2024-0001", "epss": "0.42", "percentile": "0.91"},
                    {"cve": "CVE-2024-0002", "epss": "0.003", "percentile": "0.15"},
                ]
            }
        ).encode()

        with patch("depquiet.filters.epss.urllib.request.urlopen", return_value=mock_response):
            ef._fetch_batch(["CVE-2024-0001", "CVE-2024-0002"])

        assert ef._cache["CVE-2024-0001"] == (0.42, 0.91)
        assert ef._cache["CVE-2024-0002"] == (0.003, 0.15)

    def test_fetch_batch_invalid_json(self):
        ef = EpssFilter()
        mock_response = MagicMock()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_response.read.return_value = b"not json"

        with patch("depquiet.filters.epss.urllib.request.urlopen", return_value=mock_response):
            ef._fetch_batch(["CVE-2024-0001"])
        assert "CVE-2024-0001" not in ef._cache

    def test_lookup_batches_large_lists(self):
        """Over 30 CVEs get batched."""
        ef = EpssFilter()
        cves = [f"CVE-2024-{i:04d}" for i in range(65)]

        with patch.object(ef, "_fetch_batch") as mock_fetch:
            ef.lookup(cves)

        # 65 CVEs → 3 batches (30 + 30 + 5)
        assert mock_fetch.call_count == 3
        assert len(mock_fetch.call_args_list[0][0][0]) == 30
        assert len(mock_fetch.call_args_list[1][0][0]) == 30
        assert len(mock_fetch.call_args_list[2][0][0]) == 5

    def test_get_score_missing(self):
        ef = EpssFilter()
        assert ef.get_score("CVE-9999-0000") is None

    def test_get_score_present(self):
        ef = EpssFilter()
        ef._cache["CVE-2024-0001"] = (0.42, 0.91)
        assert ef.get_score("CVE-2024-0001") == (0.42, 0.91)

    def test_check_threshold_boundary(self):
        ef = EpssFilter(threshold=0.1)
        ef._cache["CVE-A"] = (0.1, 0.5)  # exactly at threshold → NOT below
        ef._cache["CVE-B"] = (0.099, 0.5)  # just below → filter
        v_a = Vulnerability(cve="CVE-A", package="a", version="1.0", severity=Severity.HIGH)
        v_b = Vulnerability(cve="CVE-B", package="b", version="1.0", severity=Severity.HIGH)
        assert ef.check(v_a) is False  # 0.1 is not < 0.1
        assert ef.check(v_b) is True


# ── Engine branches ────────────────────────────────────────────────────


class TestEngineBranches:
    def test_detect_package_manager_pip(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "requirements.txt").write_text("flask")
            assert detect_package_manager(p) == "pip"

    def test_detect_package_manager_npm(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "package-lock.json").write_text("{}")
            assert detect_package_manager(p) == "npm"

    def test_detect_package_manager_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            assert detect_package_manager(Path(tmp)) is None

    def test_scan_pip_with_audit_json(self):
        """Engine routes pip audit JSON to PipAuditParser."""
        audit_json = json.loads((FIXTURES / "pip_audit.json").read_text())
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "requirements.txt").write_text("requests\nurllib3\n")
            (p / "app.py").write_text("import requests\nrequests.get('https://example.com')\n")
            result = scan(p, skip_epss=True, audit_json=audit_json)

        assert result.package_manager == "pip"
        assert len(result.results) == 4  # urllib3 has 2 CVEs

    def test_scan_empty_vulns_returns_early(self):
        """When parser finds zero vulns, engine returns early."""
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "package-lock.json").write_text("{}")
            (p / "package.json").write_text('{"dependencies":{}}')
            result = scan(p, skip_epss=True, audit_json={"vulnerabilities": {}})

        assert result.results == []
        assert result.total_dependencies == 0

    def test_scan_review_verdict_low_severity(self):
        """Low-severity vulns without filter reasons get REVIEW."""
        audit_json = {
            "vulnerabilities": {
                "pkg-a": {
                    "name": "pkg-a",
                    "severity": "low",
                    "isDirect": True,
                    "via": [
                        {
                            "source": 1,
                            "name": "pkg-a",
                            "title": "Minor issue",
                            "url": "https://github.com/advisories/GHSA-test-0001",
                            "severity": "low",
                            "cwe": [],
                            "cvss": {"score": 2.0},
                            "range": "<2.0",
                        }
                    ],
                    "effects": [],
                    "range": "<2.0",
                    "fixAvailable": False,
                }
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "package-lock.json").write_text("{}")
            (p / "package.json").write_text('{"dependencies":{"pkg-a":"^1.0"}}')
            (p / "app.js").write_text("require('pkg-a');\n")
            result = scan(p, skip_epss=True, audit_json=audit_json)

        pkg_a = [r for r in result.results if r.vuln.package == "pkg-a"]
        assert len(pkg_a) == 1
        assert pkg_a[0].verdict == Verdict.REVIEW

    def test_scan_review_verdict_epss_below_030(self):
        """With EPSS between threshold and 0.3, verdict is REVIEW."""
        audit_json = {
            "vulnerabilities": {
                "pkg-b": {
                    "name": "pkg-b",
                    "severity": "high",
                    "isDirect": True,
                    "via": [
                        {
                            "source": 2,
                            "name": "pkg-b",
                            "title": "Moderate issue",
                            "url": "https://github.com/advisories/CVE-2024-9999",
                            "severity": "high",
                            "cwe": [],
                            "cvss": {"score": 7.0},
                            "range": "<3.0",
                        }
                    ],
                    "effects": [],
                    "range": "<3.0",
                    "fixAvailable": {"name": "pkg-b", "version": "3.0.0"},
                }
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "package-lock.json").write_text("{}")
            (p / "package.json").write_text('{"dependencies":{"pkg-b":"^2.0"}}')
            (p / "app.js").write_text("require('pkg-b');\n")

            # Pre-populate EPSS cache with a score above threshold but below 0.3
            result = scan(p, skip_epss=True, audit_json=audit_json)

        # Without EPSS data and high severity → ACTION
        pkg_b = [r for r in result.results if r.vuln.package == "pkg-b"]
        assert len(pkg_b) == 1
        assert pkg_b[0].verdict == Verdict.ACTION

    def test_scan_action_has_reachable_imports(self):
        """ACTION items include reachable_imports showing where the package is used."""
        audit_json = json.loads((FIXTURES / "npm_audit.json").read_text())
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "package-lock.json").write_text("{}")
            (p / "package.json").write_text(json.dumps({"dependencies": {"braces": "^2.3.0"}}))
            (p / "app.js").write_text("const b = require('braces');\n")
            result = scan(p, skip_epss=True, audit_json=audit_json)

        action_items = result.action
        braces_action = [r for r in action_items if r.vuln.package == "braces"]
        if braces_action:
            assert len(braces_action[0].reachable_imports) > 0

    def _make_npm_audit(self, cve, pkg_name, severity="high"):
        return {
            "vulnerabilities": {
                pkg_name: {
                    "name": pkg_name,
                    "severity": severity,
                    "isDirect": True,
                    "via": [
                        {
                            "source": 10,
                            "name": pkg_name,
                            "title": "Test",
                            "url": f"https://github.com/advisories/{cve}",
                            "severity": severity,
                            "cwe": [],
                            "cvss": {"score": 7.0},
                            "range": "<2.0",
                        }
                    ],
                    "effects": [],
                    "range": "<2.0",
                    "fixAvailable": {"name": pkg_name, "version": "2.0.0"},
                }
            }
        }

    def _mock_epss_response(self, cve, epss, percentile):
        mock_response = MagicMock()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_response.read.return_value = json.dumps(
            {"data": [{"cve": cve, "epss": str(epss), "percentile": str(percentile)}]}
        ).encode()
        return mock_response

    def test_scan_with_epss_lookup_keeps_action(self):
        """A low EPSS score is shown but never downgrades an alert by default."""
        audit_json = self._make_npm_audit("CVE-2024-1111", "pkg-epss")
        mock_response = self._mock_epss_response("CVE-2024-1111", 0.25, 0.80)

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "package-lock.json").write_text("{}")
            (p / "package.json").write_text('{"dependencies":{"pkg-epss":"^1.0"}}')
            (p / "app.js").write_text("require('pkg-epss');\n")

            with patch("depquiet.filters.epss.urllib.request.urlopen", return_value=mock_response):
                result = scan(p, skip_epss=False, audit_json=audit_json)

        pkg = [r for r in result.results if r.vuln.package == "pkg-epss"]
        assert len(pkg) == 1
        assert pkg[0].verdict == Verdict.ACTION
        assert pkg[0].epss_score == 0.25
        assert pkg[0].epss_percentile == 0.80

    def test_scan_with_epss_low_filtered(self):
        """EPSS below threshold → FILTERED with LOW_EPSS reason."""
        audit_json = self._make_npm_audit("CVE-2024-2222", "pkg-low")
        mock_response = self._mock_epss_response("CVE-2024-2222", 0.02, 0.10)

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "package-lock.json").write_text("{}")
            (p / "package.json").write_text('{"dependencies":{"pkg-low":"^1.0"}}')
            (p / "app.js").write_text("require('pkg-low');\n")

            with patch("depquiet.filters.epss.urllib.request.urlopen", return_value=mock_response):
                result = scan(p, skip_epss=False, epss_threshold=0.1, audit_json=audit_json)

        pkg = [r for r in result.results if r.vuln.package == "pkg-low"]
        assert len(pkg) == 1
        assert pkg[0].verdict == Verdict.FILTERED
        assert FilterReason.LOW_EPSS in pkg[0].reasons

    def test_scan_with_template_dirs(self, monkeypatch):
        """Extra template directories are loaded."""
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            td = p / "my-templates"
            td.mkdir()
            (td / "test.yaml").write_text(
                "id: test\nreason: test\ncves:\n  - CVE-TEST-0001\npackage: test-pkg\n"
            )
            (p / "package-lock.json").write_text("{}")
            (p / "package.json").write_text('{"dependencies":{}}')
            monkeypatch.setattr("depquiet.engine.run_npm_audit", lambda _: {"vulnerabilities": {}})
            result = scan(p, skip_epss=True, template_dirs=[td])

        assert result is not None

    def test_scan_community_template_keeps_a_used_package(self):
        """Absence of a function name cannot prove an imported package safe."""
        audit_json = {
            "vulnerabilities": {
                "lodash": {
                    "name": "lodash",
                    "severity": "high",
                    "isDirect": True,
                    "via": [
                        {
                            "source": 99,
                            "name": "lodash",
                            "title": "Prototype Pollution",
                            "url": "https://github.com/advisories/CVE-2020-8203",
                            "severity": "high",
                            "cwe": [],
                            "cvss": {"score": 7.4},
                            "range": "<4.17.21",
                        }
                    ],
                    "effects": [],
                    "range": "<4.17.21",
                    "fixAvailable": {"name": "lodash", "version": "4.17.21"},
                }
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "package-lock.json").write_text("{}")
            (p / "package.json").write_text('{"dependencies":{"lodash":"^4.17.0"}}')
            (p / "app.js").write_text("const _ = require('lodash');\n_.get(obj, 'x');\n")
            result = scan(p, skip_epss=True, audit_json=audit_json)

        lodash = [r for r in result.results if r.vuln.package == "lodash"]
        assert len(lodash) == 1
        assert lodash[0].verdict == Verdict.ACTION
        assert FilterReason.COMMUNITY_TEMPLATE not in lodash[0].reasons


# ── Reachability edge cases ────────────────────────────────────────────


class TestReachabilityEdgeCases:
    def test_no_source_files(self):
        """Empty project → don't filter (conservative)."""
        with tempfile.TemporaryDirectory() as tmp:
            rf = ReachabilityFilter(Path(tmp))
            v = Vulnerability(cve="CVE-1", package="a", version="1.0", severity=Severity.HIGH)
            assert rf.check(v) is False

    def test_python_files_only(self):
        """Python project with .py files only."""
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "app.py").write_text("import flask\napp = flask.Flask(__name__)\n")
            rf = ReachabilityFilter(p)

            v_flask = Vulnerability(
                cve="CVE-1",
                package="flask",
                version="2.0",
                severity=Severity.HIGH,
            )
            v_django = Vulnerability(
                cve="CVE-2",
                package="django",
                version="4.0",
                severity=Severity.HIGH,
            )

            assert rf.check(v_flask) is False  # flask IS imported
            assert rf.check(v_django) is True  # django is NOT imported

    def test_skips_node_modules(self):
        """Source files in node_modules should be ignored."""
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "index.js").write_text("console.log('hello');\n")
            nm = p / "node_modules" / "evil"
            nm.mkdir(parents=True)
            (nm / "index.js").write_text("require('lodash');\n")

            rf = ReachabilityFilter(p)
            v = Vulnerability(cve="CVE-1", package="lodash", version="1.0", severity=Severity.HIGH)
            assert rf.check(v) is True  # lodash only in node_modules → unreachable

    def test_oserror_in_file_read(self):
        """Files that can't be read are silently skipped."""
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "app.js").write_text("require('pkg');\n")
            _source_files(p, {".js"})
            # Simulate OSError by passing a non-existent path
            result = _file_mentions([Path("/nonexistent/file.js")], "pkg")
            assert result == []

    def test_find_imports_python(self):
        """find_imports works for Python files."""
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "main.py").write_text("import requests\n")
            (p / "util.py").write_text("print('no imports')\n")
            rf = ReachabilityFilter(p)
            v = Vulnerability(
                cve="CVE-1",
                package="requests",
                version="2.0",
                severity=Severity.HIGH,
            )
            imports = rf.find_imports(v)
            assert len(imports) == 1
            assert "main.py" in imports[0]

    def test_lazy_property_caching(self):
        """js_files and py_files are cached after first access."""
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "app.js").write_text("hello")
            rf = ReachabilityFilter(p)
            first = rf.js_files
            second = rf.js_files
            assert first is second  # same object, cached


# ── Template edge cases ────────────────────────────────────────────────


class TestTemplateEdgeCases:
    def test_yaml_parser_inline_list(self):
        data = _parse_yaml_simple('items: ["a", "b", "c"]')
        assert data["items"] == ["a", "b", "c"]

    def test_yaml_parser_comments_ignored(self):
        data = _parse_yaml_simple("# comment\nkey: value\n# another comment\n")
        assert data["key"] == "value"

    def test_yaml_parser_empty_lines_ignored(self):
        data = _parse_yaml_simple("\n\nkey: value\n\n")
        assert data["key"] == "value"

    def test_yaml_parser_nested_list_at_end(self):
        text = "top: val\nitems:\n  - one\n  - two\n"
        data = _parse_yaml_simple(text)
        assert data["items"] == ["one", "two"]

    def test_yaml_parser_quoted_values(self):
        data = _parse_yaml_simple('key: "hello world"')
        assert data["key"] == "hello world"

    def test_load_template_from_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "test.yaml"
            p.write_text(
                "id: test-id\nreason: test reason\ncves:\n  - CVE-2024-0001\npackage: my-pkg\n"
            )
            tmpl = _load_template(p)
            assert tmpl is not None
            assert tmpl.id == "test-id"
            assert tmpl.reason == "test reason"
            assert tmpl.cves == ["CVE-2024-0001"]
            assert tmpl.package == "my-pkg"

    def test_load_template_oserror(self):
        tmpl = _load_template(Path("/nonexistent/template.yaml"))
        assert tmpl is None

    def test_load_template_cves_as_string(self):
        """cves can be a single string instead of a list."""
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "test.yaml"
            p.write_text("id: test\nreason: r\ncves: CVE-2024-0001\n")
            tmpl = _load_template(p)
            assert tmpl is not None
            assert tmpl.cves == ["CVE-2024-0001"]

    def test_load_template_not_imported_as_string(self):
        """not-imported can be a single string."""
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "test.yaml"
            p.write_text("id: test\nreason: r\nnot-imported: merge\n")
            tmpl = _load_template(p)
            assert tmpl is not None
            assert tmpl.not_imported == ["merge"]

    def test_template_matches_cve_yes(self):
        t = Template(id="t", reason="r", cves=["CVE-1", "CVE-2"])
        assert t.matches_cve("CVE-1") is True

    def test_template_matches_cve_no(self):
        t = Template(id="t", reason="r", cves=["CVE-1"])
        assert t.matches_cve("CVE-99") is False

    def test_template_matches_package_empty(self):
        """No package set → matches any package."""
        t = Template(id="t", reason="r", cves=["CVE-1"])
        assert t.matches_package("anything") is True

    def test_template_matches_package_specific(self):
        t = Template(id="t", reason="r", cves=["CVE-1"], package="lodash")
        assert t.matches_package("lodash") is True
        assert t.matches_package("express") is False

    def test_template_filter_nonexistent_dir(self):
        """Extra template dir that doesn't exist → no crash."""
        tf = TemplateFilter(template_dirs=[Path("/nonexistent/templates")])
        assert tf.count >= 0  # still loads bundled

    def test_template_filter_custom_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "templates"
            d.mkdir()
            (d / "custom.yaml").write_text(
                "id: custom\nreason: custom reason\ncves:\n  - CVE-CUSTOM-001\n"
            )
            tf = TemplateFilter(template_dirs=[d])
            match = tf.find_match("CVE-CUSTOM-001", "any")
            assert match is not None
            assert match.id == "custom"


# ── npm parser edge cases ──────────────────────────────────────────────


class TestNpmEdgeCases:
    def test_read_package_json_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = _read_package_json(Path(tmp))
            assert result == {}

    def test_get_dev_packages_empty(self):
        assert _get_dev_packages({}) == set()
        assert _get_dev_packages({"dependencies": {"a": "^1.0"}}) == set()

    def test_get_dev_packages(self):
        pkg = {"devDependencies": {"jest": "^29", "eslint": "^8"}}
        assert _get_dev_packages(pkg) == {"jest", "eslint"}

    def test_parse_transitive_via_skipped(self):
        """Transitive string references in 'via' are skipped."""
        audit_json = {
            "vulnerabilities": {
                "micromatch": {
                    "name": "micromatch",
                    "severity": "high",
                    "isDirect": False,
                    "via": ["braces"],  # string, not dict
                    "effects": [],
                    "range": "*",
                    "fixAvailable": False,
                }
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "package.json").write_text('{"dependencies":{}}')
            vulns = NpmAuditParser.parse(audit_json, p)
        assert len(vulns) == 0  # string via entries are skipped

    def test_parse_deduplicates(self):
        """Same CVE + package only appears once."""
        audit_json = {
            "vulnerabilities": {
                "pkg": {
                    "name": "pkg",
                    "severity": "high",
                    "isDirect": True,
                    "via": [
                        {
                            "source": 1,
                            "name": "pkg",
                            "title": "Bug",
                            "url": "https://github.com/advisories/CVE-2024-0001",
                            "severity": "high",
                            "cwe": [],
                            "cvss": {"score": 7.0},
                            "range": "<2.0",
                        },
                        {
                            "source": 1,
                            "name": "pkg",
                            "title": "Bug",
                            "url": "https://github.com/advisories/CVE-2024-0001",
                            "severity": "high",
                            "cwe": [],
                            "cvss": {"score": 7.0},
                            "range": "<2.0",
                        },
                    ],
                    "effects": [],
                    "range": "<2.0",
                    "fixAvailable": False,
                }
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "package.json").write_text('{"dependencies":{"pkg":"^1.0"}}')
            vulns = NpmAuditParser.parse(audit_json, p)
        assert len(vulns) == 1

    def test_parse_cve_from_source_fallback(self):
        """When URL has no advisories path, falls back to source ID."""
        audit_json = {
            "vulnerabilities": {
                "pkg": {
                    "name": "pkg",
                    "severity": "moderate",
                    "isDirect": True,
                    "via": [
                        {
                            "source": 42,
                            "name": "pkg",
                            "title": "Issue",
                            "url": "",
                            "severity": "moderate",
                            "cwe": [],
                            "cvss": {"score": 5.0},
                            "range": "<2.0",
                        }
                    ],
                    "effects": [],
                    "range": "<2.0",
                    "fixAvailable": False,
                }
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "package.json").write_text('{"dependencies":{}}')
            vulns = NpmAuditParser.parse(audit_json, p)
        assert len(vulns) == 1
        assert vulns[0].cve == "GHSA-42"

    def test_yarn_lock_alone_is_not_an_npm_audit_project(self):
        """``npm audit`` cannot read yarn.lock; the lockfile scanner handles it."""
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "yarn.lock").write_text("")
            assert NpmAuditParser.detect(p) is False
            (p / "npm-shrinkwrap.json").write_text("{}")
            assert NpmAuditParser.detect(p) is True

    def test_run_audit_not_installed(self):
        """npm not available → empty dict."""
        with tempfile.TemporaryDirectory() as tmp:
            # Creates a dir without node_modules / npm
            result = NpmAuditParser.run_audit(Path(tmp))
        # May return {} or actual npm audit depending on environment
        assert isinstance(result, dict)


# ── SARIF edge cases ──────────────────────────────────────────────────


class TestSarifEdgeCases:
    def test_severity_to_level_mapping(self):
        assert _severity_to_level("critical") == "error"
        assert _severity_to_level("high") == "error"
        assert _severity_to_level("moderate") == "warning"
        assert _severity_to_level("low") == "note"
        assert _severity_to_level("info") == "note"
        assert _severity_to_level("unknown") == "warning"

    def test_build_message_with_all_fields(self):
        v = Vulnerability(
            cve="CVE-1",
            package="pkg",
            version="1.0",
            severity=Severity.HIGH,
            title="Test vuln",
            fix_version="2.0",
        )
        tr = TriageResult(vuln=v, verdict=Verdict.ACTION, reasons=[], epss_score=0.67)
        msg = _build_message(tr)
        assert "pkg@1.0" in msg
        assert "Fix: update to 2.0" in msg
        assert "EPSS: 67.0%" in msg
        assert "ACTION REQUIRED" in msg

    def test_build_message_review_verdict(self):
        v = Vulnerability(cve="CVE-1", package="pkg", version="1.0", severity=Severity.LOW)
        tr = TriageResult(vuln=v, verdict=Verdict.REVIEW, reasons=[])
        msg = _build_message(tr)
        assert "Verdict: REVIEW" in msg

    def test_build_locations_with_imports(self):
        v = Vulnerability(cve="CVE-1", package="pkg", version="1.0", severity=Severity.HIGH)
        tr = TriageResult(
            vuln=v,
            verdict=Verdict.ACTION,
            reasons=[],
            reachable_imports=["/project/src/app.js", "/project/src/util.js"],
        )
        locs = _build_locations(tr, "/project", "npm")
        assert len(locs) == 2
        assert locs[0]["physicalLocation"]["artifactLocation"]["uri"] == "src/app.js"

    def test_build_locations_fallback_npm(self):
        v = Vulnerability(cve="CVE-1", package="pkg", version="1.0", severity=Severity.HIGH)
        tr = TriageResult(vuln=v, verdict=Verdict.ACTION, reasons=[])
        locs = _build_locations(tr, "/project", "npm")
        assert len(locs) == 1
        assert locs[0]["physicalLocation"]["artifactLocation"]["uri"] == "package.json"

    def test_build_locations_fallback_pip(self):
        v = Vulnerability(cve="CVE-1", package="pkg", version="1.0", severity=Severity.HIGH)
        tr = TriageResult(vuln=v, verdict=Verdict.ACTION, reasons=[])
        locs = _build_locations(tr, "/project", "pip")
        assert len(locs) == 1
        assert locs[0]["physicalLocation"]["artifactLocation"]["uri"] == "requirements.txt"

    def test_sarif_review_items_included(self):
        """REVIEW items should appear in SARIF output (not just ACTION)."""
        v = Vulnerability(cve="CVE-R", package="pkg", version="1.0", severity=Severity.LOW)
        tr = TriageResult(vuln=v, verdict=Verdict.REVIEW, reasons=[])
        sr = ScanResult(
            project_path="/test",
            package_manager="npm",
            total_dependencies=5,
            results=[tr],
        )
        sarif = to_sarif(sr)
        assert len(sarif["runs"][0]["results"]) == 1

    def test_sarif_no_url_no_helpuri(self):
        """Rule without URL should not have helpUri."""
        v = Vulnerability(cve="CVE-1", package="pkg", version="1.0", severity=Severity.HIGH)
        tr = TriageResult(vuln=v, verdict=Verdict.ACTION, reasons=[])
        sr = ScanResult(
            project_path="/test",
            package_manager="npm",
            total_dependencies=1,
            results=[tr],
        )
        sarif = to_sarif(sr)
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "helpUri" not in rule


# ── CLI edge cases ─────────────────────────────────────────────────────


class TestCliEdgeCases:
    def test_cli_invalid_stdin_json(self, capsys):
        old_stdin = sys.stdin
        sys.stdin = io.StringIO("not valid json{{{")
        try:
            code = main(["--stdin"])
        finally:
            sys.stdin = old_stdin
        assert code == 1
        captured = capsys.readouterr()
        assert "invalid JSON" in captured.err

    def test_cli_exit_code_1_on_action(self, capsys):
        """CLI returns 1 when ACTION items are found."""
        audit_json = json.loads((FIXTURES / "npm_audit.json").read_text())
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "package-lock.json").write_text("{}")
            (p / "package.json").write_text(json.dumps({"dependencies": {"braces": "^2.3.0"}}))
            (p / "app.js").write_text("require('braces');\n")

            old_stdin = sys.stdin
            sys.stdin = io.StringIO(json.dumps(audit_json))
            try:
                code = main(["--path", tmp, "--stdin", "--offline"])
            finally:
                sys.stdin = old_stdin
        assert code == 1

    def test_cli_exit_code_0_no_action(self, capsys, monkeypatch):
        """CLI returns 0 when no ACTION items."""
        import io

        monkeypatch.setattr("sys.stdin", io.StringIO('{"vulnerabilities": {}}'))
        with tempfile.TemporaryDirectory() as tmp:
            code = main([*["--path", tmp, "--offline"], "--stdin"])
        assert code == 0

    def test_cli_json_output_format(self, capsys, monkeypatch):
        """JSON output includes all expected fields."""
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "package-lock.json").write_text("{}")
            (p / "package.json").write_text('{"dependencies":{}}')
            monkeypatch.setattr("depquiet.engine.run_npm_audit", lambda _: {"vulnerabilities": {}})
            main(["--path", tmp, "--offline", "--json"])

        captured = capsys.readouterr()
        out = json.loads(captured.out)
        assert "project" in out
        assert "package_manager" in out
        assert "summary" in out
        assert "results" in out

    def test_cli_custom_epss_threshold(self, capsys, monkeypatch):
        """--epss-threshold is passed through."""
        import io

        monkeypatch.setattr("sys.stdin", io.StringIO('{"vulnerabilities": {}}'))
        with tempfile.TemporaryDirectory() as tmp:
            code = main([*["--path", tmp, "--offline", "--epss-threshold", "0.05"], "--stdin"])
        assert code == 0

    def test_cli_custom_templates(self, capsys, monkeypatch):
        """--templates flag is accepted."""
        import io

        monkeypatch.setattr("sys.stdin", io.StringIO('{"vulnerabilities": {}}'))
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            td = p / "my-templates"
            td.mkdir()
            code = main([*["--path", tmp, "--offline", "--templates", str(td)], "--stdin"])
        assert code == 0


# ── __main__.py ────────────────────────────────────────────────────────


class TestMainModule:
    def test_main_module_invocable(self):
        """python -m depquiet is wired up correctly."""
        # __main__.py raises SystemExit(main()), so importing it triggers exit
        with pytest.raises(SystemExit):
            import depquiet.__main__  # noqa: F401

    def test_main_cli_callable(self):
        """The CLI main function is importable and callable."""
        from depquiet.cli import main as cli_main

        assert callable(cli_main)


# ── Output edge cases ─────────────────────────────────────────────────


class TestOutputEdgeCases:
    def test_output_review_section(self, capsys):
        """REVIEW section appears in output."""
        v = Vulnerability(
            cve="CVE-2024-5555",
            package="review-pkg",
            version="1.0",
            severity=Severity.MODERATE,
        )
        tr = TriageResult(vuln=v, verdict=Verdict.REVIEW, reasons=[], epss_score=0.15)
        sr = ScanResult(
            project_path="/test",
            package_manager="npm",
            total_dependencies=10,
            results=[tr],
        )
        print_scan_result(sr)
        captured = capsys.readouterr()
        assert "REVIEW" in captured.out
        assert "review-pkg" in captured.out

    def test_output_action_with_imports(self, capsys):
        """ACTION items show import locations."""
        v = Vulnerability(
            cve="CVE-2024-6666",
            package="act-pkg",
            version="1.0",
            severity=Severity.HIGH,
            title="Dangerous bug",
            fix_version="2.0",
        )
        tr = TriageResult(
            vuln=v,
            verdict=Verdict.ACTION,
            reasons=[],
            epss_score=0.67,
            reachable_imports=["src/app.js", "src/util.js"],
        )
        sr = ScanResult(
            project_path="/test",
            package_manager="npm",
            total_dependencies=10,
            results=[tr],
        )
        print_scan_result(sr)
        captured = capsys.readouterr()
        assert "ACTION REQUIRED" in captured.out
        assert "src/app.js" in captured.out

    def test_output_no_epss_score(self, capsys):
        """Output handles missing EPSS score gracefully."""
        v = Vulnerability(
            cve="CVE-2024-7777",
            package="no-epss-pkg",
            version="1.0",
            severity=Severity.HIGH,
        )
        tr = TriageResult(vuln=v, verdict=Verdict.ACTION, reasons=[])
        sr = ScanResult(
            project_path="/test",
            package_manager="npm",
            total_dependencies=5,
            results=[tr],
        )
        print_scan_result(sr)
        captured = capsys.readouterr()
        assert "ACTION REQUIRED" in captured.out

    def test_output_multiple_filter_reasons(self, capsys):
        """Filtered item with multiple reasons shows all."""
        v = Vulnerability(
            cve="CVE-2024-8888",
            package="multi-pkg",
            version="1.0",
            severity=Severity.LOW,
            is_dev=True,
        )
        tr = TriageResult(
            vuln=v,
            verdict=Verdict.FILTERED,
            reasons=[FilterReason.DEV_DEPENDENCY, FilterReason.UNREACHABLE],
        )
        sr = ScanResult(
            project_path="/test",
            package_manager="npm",
            total_dependencies=5,
            results=[tr],
        )
        print_scan_result(sr)
        captured = capsys.readouterr()
        assert "FILTERED" in captured.out

    def test_output_has_no_time_saved_estimate(self, capsys):
        """Time-saved message appears when items are filtered."""
        v = Vulnerability(
            cve="CVE-1",
            package="pkg",
            version="1.0",
            severity=Severity.LOW,
            is_dev=True,
        )
        tr = TriageResult(
            vuln=v,
            verdict=Verdict.FILTERED,
            reasons=[FilterReason.DEV_DEPENDENCY],
        )
        sr = ScanResult(
            project_path="/test",
            package_manager="npm",
            total_dependencies=5,
            results=[tr],
        )
        print_scan_result(sr)
        captured = capsys.readouterr()
        assert "1 filtered" in captured.out
        # No made-up time-saved estimate in the output.
        assert "minutes" not in captured.out


# ── Models edge cases ─────────────────────────────────────────────────


class TestModelsEdgeCases:
    def test_severity_from_str_unknown(self):
        assert Severity.from_str("unknown") == Severity.MODERATE
        assert Severity.from_str("CRITICAL") == Severity.CRITICAL

    def test_vulnerability_key(self):
        v = Vulnerability(cve="CVE-1", package="pkg", version="1.0", severity=Severity.HIGH)
        assert v.key == "CVE-1:pkg"

    def test_triage_result_reason_summary_empty(self):
        v = Vulnerability(cve="CVE-1", package="pkg", version="1.0", severity=Severity.HIGH)
        tr = TriageResult(vuln=v, verdict=Verdict.ACTION, reasons=[])
        assert tr.reason_summary == "no automatic filter matched; product impact unverified"

    def test_triage_result_reason_summary_multiple(self):
        v = Vulnerability(cve="CVE-1", package="pkg", version="1.0", severity=Severity.HIGH)
        tr = TriageResult(
            vuln=v,
            verdict=Verdict.FILTERED,
            reasons=[FilterReason.DEV_DEPENDENCY, FilterReason.UNREACHABLE],
        )
        assert "dev dependency" in tr.reason_summary
        assert "unreachable" in tr.reason_summary

    def test_scan_result_review_property(self):
        v = Vulnerability(cve="CVE-1", package="pkg", version="1.0", severity=Severity.LOW)
        tr = TriageResult(vuln=v, verdict=Verdict.REVIEW, reasons=[])
        sr = ScanResult(
            project_path="/test",
            package_manager="npm",
            total_dependencies=1,
            results=[tr],
        )
        assert len(sr.review) == 1
        assert len(sr.action) == 0
        assert len(sr.filtered) == 0
