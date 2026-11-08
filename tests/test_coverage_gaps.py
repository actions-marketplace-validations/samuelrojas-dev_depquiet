"""Tests targeting the 20 remaining uncovered lines to push coverage to 99%+.

Each test class maps to one source file and documents which lines it covers.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from depquiet.models import Severity, TriageResult, Verdict, Vulnerability


def _vuln(**kw) -> Vulnerability:  # type: ignore[no-untyped-def]
    defaults = {
        "cve": "CVE-2023-0001",
        "package": "requests",
        "version": "1.0.0",
        "severity": Severity.HIGH,
    }
    defaults.update(kw)
    return Vulnerability(**defaults)


# ── cli.py lines 100-101 ────────────────────────────────────────────


class TestCliEpssThresholdSysArgv:
    """Cover the branch where main() is called without argv (real CLI path)
    and --epss-threshold is detected in sys.argv."""

    def test_epss_threshold_via_sys_argv(self, tmp_path: Path) -> None:
        """cli.py:100-101 — --epss-threshold detected in sys.argv."""
        (tmp_path / "package-lock.json").write_text("{}")
        fake_argv = ["depquiet", "--path", str(tmp_path), "--offline", "--epss-threshold", "0.05"]
        with (
            patch.object(sys, "argv", fake_argv),
            patch("depquiet.engine.run_npm_audit", return_value={"vulnerabilities": {}}),
        ):
            from depquiet.cli import main

            code = main()  # no argv param → uses sys.argv
        assert code == 0


# ── config.py lines 96-98, 102-104 ──────────────────────────────────


class TestConfigParseErrors:
    """Cover error handling in _parse_config."""

    def test_unreadable_config_file(self, tmp_path: Path) -> None:
        """config.py:96-98 — OSError reading config → warning + empty Config."""
        from depquiet.config import _parse_config

        config_path = tmp_path / ".depquiet.yaml"
        config_path.write_text("epss_threshold: 0.05")
        # Mock read_text to raise OSError
        with patch.object(Path, "read_text", side_effect=OSError("Permission denied")):
            cfg = _parse_config(config_path, tmp_path)
        assert cfg.epss_threshold == 0.1  # default (error path)

    def test_invalid_yaml_config(self, tmp_path: Path) -> None:
        """config.py:102-104 — broken YAML → warning + empty Config."""
        from depquiet.config import _parse_config

        config_path = tmp_path / ".depquiet.yaml"
        config_path.write_text("valid file content")
        # Mock the YAML parser to raise
        with patch("depquiet.config._parse_yaml_simple", side_effect=ValueError("bad yaml")):
            cfg = _parse_config(config_path, tmp_path)
        assert cfg.epss_threshold == 0.1  # default (error path)


# ── reachability.py lines 106-107, 147, 184-185 ─────────────────────


class TestReachabilityOSErrors:
    """Cover OSError branches and edge cases in reachability filter."""

    def test_py_imports_package_unreadable_file(self) -> None:
        """reachability.py:106-107 — OSError reading a .py file."""
        from depquiet.filters.reachability import _py_imports_package

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "app.py"
            p.write_text("import requests\n")
            # Mock read_text to raise OSError (chmod doesn't work as root)
            with patch.object(Path, "read_text", side_effect=OSError("Permission denied")):
                result = _py_imports_package([p], "requests")
            assert result is False  # can't read → skip

    def test_vulnerable_functions_no_source_files(self) -> None:
        """reachability.py:147 — vulnerable_functions with no source files."""
        from depquiet.filters.reachability import ReachabilityFilter

        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "README.md").write_text("# hello\n")
            rf = ReachabilityFilter(project)
            v = _vuln(vulnerable_functions=["dangerous_func"])
            # No source files → return False (can't determine, don't filter)
            assert rf.check(v) is False

    def test_find_imports_unreadable_python_file(self) -> None:
        """reachability.py:184-185 — OSError in find_imports for Python."""
        from depquiet.filters.reachability import ReachabilityFilter

        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            p = project / "app.py"
            p.write_text("import requests\n")
            rf = ReachabilityFilter(project)
            # Patch read_text on just the py_files to raise OSError
            orig_read_text = Path.read_text

            def flaky_read(self_path, *a, **kw):  # type: ignore[no-untyped-def]
                if self_path.suffix == ".py":
                    raise OSError("Permission denied")
                return orig_read_text(self_path, *a, **kw)

            with patch.object(Path, "read_text", flaky_read):
                imports = rf.find_imports(_vuln(package="requests"))
            assert imports == []  # skipped due to OSError


# ── output.py line 28 ───────────────────────────────────────────────


class TestOutputTTYColors:
    """Cover the TTY color code path."""

    def test_color_output_on_tty(self) -> None:
        """output.py:28 — ANSI codes emitted when stdout is a TTY."""
        from depquiet.output import _c

        with patch.object(sys.stdout, "isatty", return_value=True):
            result = _c("\033[31m", "hello")
            assert "\033[31m" in result
            assert "hello" in result
            assert "\033[0m" in result  # reset code


# ── dependabot.py line 111 ──────────────────────────────────────────


class TestDependabotScan:
    """Cover the scan() no-op method."""

    def test_scan_returns_empty(self, tmp_path: Path) -> None:
        """dependabot.py:111 — scan() is a no-op returning []."""
        from depquiet.parsers.dependabot import DependabotParser

        result = DependabotParser.scan(tmp_path)
        assert result == []


# ── npm.py lines 70-71 ──────────────────────────────────────────────


class TestNpmRunAuditErrors:
    """Cover exception branches in NpmAuditParser.run_audit."""

    def test_run_audit_timeout(self, tmp_path: Path) -> None:
        """npm.py:70-71 — TimeoutExpired → empty dict."""
        from depquiet.parsers.npm import NpmAuditParser

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("npm", 120)):
            result = NpmAuditParser.run_audit(tmp_path)
        assert result == {}

    def test_run_audit_invalid_json(self, tmp_path: Path) -> None:
        """npm.py:70-71 — JSONDecodeError → empty dict."""
        from depquiet.parsers.npm import NpmAuditParser

        mock_result = MagicMock()
        mock_result.stdout = "not valid json {"
        with patch("subprocess.run", return_value=mock_result):
            result = NpmAuditParser.run_audit(tmp_path)
        assert result == {}

    def test_run_audit_success_with_output(self, tmp_path: Path) -> None:
        """npm.py:69 — success path with valid JSON."""
        from depquiet.parsers.npm import NpmAuditParser

        mock_result = MagicMock()
        mock_result.stdout = '{"vulnerabilities": {}}'
        with patch("subprocess.run", return_value=mock_result):
            result = NpmAuditParser.run_audit(tmp_path)
        assert result == {"vulnerabilities": {}}


# ── pip.py line 53 ──────────────────────────────────────────────────


class TestPipRunAudit:
    """Cover success and empty paths in PipAuditParser.run_audit."""

    def test_run_audit_success_with_output(self, tmp_path: Path) -> None:
        """pip.py:53 — success path with valid stdout."""
        from depquiet.parsers.pip import PipAuditParser

        mock_result = MagicMock()
        mock_result.stdout = '{"dependencies": []}'
        with patch("subprocess.run", return_value=mock_result):
            result = PipAuditParser.run_audit(tmp_path)
        assert result == {"dependencies": []}

    def test_run_audit_empty_stdout(self, tmp_path: Path) -> None:
        """pip.py:53 — empty stdout → empty dict."""
        from depquiet.parsers.pip import PipAuditParser

        mock_result = MagicMock()
        mock_result.stdout = ""
        with patch("subprocess.run", return_value=mock_result):
            result = PipAuditParser.run_audit(tmp_path)
        assert result == {}


# ── sarif.py lines 129-130 ──────────────────────────────────────────


class TestSarifRelativePathFallback:
    """Cover ValueError in _build_locations when path isn't relative."""

    def test_import_path_not_relative_to_project(self) -> None:
        """sarif.py:129-130 — ValueError → use raw import path."""
        from depquiet.sarif import _build_locations

        tr = TriageResult(
            vuln=_vuln(),
            verdict=Verdict.ACTION,
            reasons=[],
            reachable_imports=["/other/location/app.js"],
        )
        locs = _build_locations(tr, "/project", "npm")
        assert len(locs) == 1
        assert locs[0]["physicalLocation"]["artifactLocation"]["uri"] == "/other/location/app.js"
