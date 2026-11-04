"""A scanner that can't run must never look like "no vulnerabilities".

Before v0.30.1: with pip-audit not installed, ``depquiet`` in a Python project
printed "No vulnerabilities found"; so did a failed ``npm audit`` or an OSV.dev
network error. pip-audit also audited depquiet's own environment instead of
the project.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from depquiet.cli import main
from depquiet.engine import scan
from depquiet.models import Severity, Vulnerability
from depquiet.scanners import ScanError, lock_pins, run_npm_audit, run_pip_audit

UV_LOCK = """version = 1
[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "django" }]

[[package]]
name = "django"
version = "4.2.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "torch"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "torch"
version = "2.0.0+cpu"
source = { registry = "https://download.pytorch.org/whl/cpu" }
"""


def _py_project(tmp: Path) -> Path:
    (tmp / "pyproject.toml").write_text('[project]\nname = "app"\ndependencies = ["django"]\n')
    (tmp / "uv.lock").write_text(UV_LOCK)
    (tmp / "app.py").write_text("import django\n")
    return tmp


class TestNotInstalled:
    def test_pip_audit_missing_offline_is_not_clean(self, tmp_path: Path) -> None:
        _py_project(tmp_path)
        with patch("depquiet.scanners.shutil.which", return_value=None):
            result = scan(tmp_path, skip_epss=True)
        assert result.scanned is False
        assert "pip-audit is not installed" in result.note

    def test_cli_exit_code_2(self, tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
        _py_project(tmp_path)
        with patch("depquiet.scanners.shutil.which", return_value=None):
            code = main(["--path", str(tmp_path), "--offline"])
        assert code == 2
        captured = capsys.readouterr()
        assert "No vulnerabilities found" not in captured.out
        assert "pip-audit" in captured.err

    def test_falls_back_to_osv_and_says_so(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("django>=4\n")
        found = [
            Vulnerability(cve="CVE-1", package="django", version="4.2", severity=Severity.HIGH)
        ]
        with (
            patch("depquiet.scanners.shutil.which", return_value=None),
            patch("depquiet.engine.OsvScanner.scan_checked", return_value=found),
            patch("depquiet.engine.EpssFilter.lookup"),
        ):
            result = scan(tmp_path, skip_epss=False)
        assert result.package_manager == "osv"
        assert "pip-audit is not installed" in result.note
        assert "OSV.dev instead" in result.note
        assert len(result.results) == 1

    def test_npm_missing(self, tmp_path: Path) -> None:
        with (
            patch("depquiet.scanners.shutil.which", return_value=None),
            pytest.raises(ScanError, match="npm is not installed"),
        ):
            run_npm_audit(tmp_path)


class TestScannerErrors:
    def _completed(self, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=[], returncode=1, stdout=stdout, stderr=stderr)

    def test_npm_error_object(self, tmp_path: Path) -> None:
        err = json.dumps(
            {"error": {"code": "ENOLOCK", "summary": "This command requires a lockfile"}}
        )
        with (
            patch("depquiet.scanners.shutil.which", return_value="/usr/bin/npm"),
            patch("depquiet.scanners.subprocess.run", return_value=self._completed(err)),
            pytest.raises(ScanError, match="requires a lockfile"),
        ):
            run_npm_audit(tmp_path)

    def test_npm_garbage(self, tmp_path: Path) -> None:
        with (
            patch("depquiet.scanners.shutil.which", return_value="/usr/bin/npm"),
            patch("depquiet.scanners.subprocess.run", return_value=self._completed("<html>")),
            pytest.raises(ScanError, match="invalid JSON"),
        ):
            run_npm_audit(tmp_path)

    def test_npm_audit_failure_in_scan_is_not_clean(self, tmp_path: Path) -> None:
        (tmp_path / "package-lock.json").write_text('{"packages": {}}')
        err = json.dumps({"error": {"summary": "network timeout"}})
        with (
            patch("depquiet.scanners.shutil.which", return_value="/usr/bin/npm"),
            patch("depquiet.scanners.subprocess.run", return_value=self._completed(err)),
            patch("depquiet.engine.OsvScanner.scan_checked", side_effect=ScanError("offline")),
        ):
            result = scan(tmp_path, skip_epss=False)
        assert result.scanned is False
        assert "network timeout" in result.note
        assert "OSV.dev fallback failed too" in result.note

    def test_osv_network_failure_is_not_clean(self, tmp_path: Path) -> None:
        (tmp_path / "Cargo.lock").write_text('[[package]]\nname = "x"\nversion = "1.0.0"\n')
        with patch("depquiet.parsers.osv.query_osv_batch", side_effect=OSError("unreachable")):
            result = scan(tmp_path, skip_epss=False)
        assert result.scanned is False
        assert "OSV.dev" in result.note


class TestPipAuditTarget:
    def test_lock_pins_dedupes_platform_variants(self, tmp_path: Path) -> None:
        (tmp_path / "uv.lock").write_text(UV_LOCK)
        pins, dropped = lock_pins(tmp_path / "uv.lock")
        assert pins == ["django==4.2.0", "torch==2.0.0"]
        assert dropped == ["torch==2.0.0+cpu"]

    def test_audits_lockfile_not_environment(self, tmp_path: Path) -> None:
        _py_project(tmp_path)
        seen: dict[str, object] = {}

        def fake_run(cmd, **kw):  # type: ignore[no-untyped-def]
            seen["cmd"] = cmd
            req = Path(cmd[cmd.index("-r") + 1])
            seen["req"] = req.read_text()
            out = Path(cmd[cmd.index("-o") + 1])
            out.write_text(json.dumps({"dependencies": []}))
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with (
            patch("depquiet.scanners.shutil.which", return_value="/usr/bin/pip-audit"),
            patch("depquiet.scanners.subprocess.run", side_effect=fake_run),
        ):
            data = run_pip_audit(tmp_path)
        assert data == {"dependencies": []}
        assert "--no-deps" in seen["cmd"]  # type: ignore[operator]
        assert "--disable-pip" in seen["cmd"]  # type: ignore[operator]
        assert "django==4.2.0" in str(seen["req"])

    def test_requirements_txt(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("django>=4\n")

        def fake_run(cmd, **kw):  # type: ignore[no-untyped-def]
            assert cmd[1:3] == ["-r", str(tmp_path / "requirements.txt")]
            Path(cmd[cmd.index("-o") + 1]).write_text(json.dumps({"dependencies": []}))
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with (
            patch("depquiet.scanners.shutil.which", return_value="/usr/bin/pip-audit"),
            patch("depquiet.scanners.subprocess.run", side_effect=fake_run),
        ):
            assert run_pip_audit(tmp_path) == {"dependencies": []}

    def test_pip_audit_error_raises(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("django>=4\n")
        failed = subprocess.CompletedProcess([], 1, "", "ResolutionImpossible: no matching dist")
        with (
            patch("depquiet.scanners.shutil.which", return_value="/usr/bin/pip-audit"),
            patch("depquiet.scanners.subprocess.run", return_value=failed),
            pytest.raises(ScanError, match="ResolutionImpossible"),
        ):
            run_pip_audit(tmp_path)


class TestOsvPythonLocks:
    def test_uv_lock_packages_for_osv(self, tmp_path: Path) -> None:
        from depquiet.parsers.osv import parse_lockfiles

        (tmp_path / "uv.lock").write_text(UV_LOCK)
        pkgs = parse_lockfiles(tmp_path)
        assert ("django", "4.2.0", "PyPI") in pkgs
        assert ("torch", "2.0.0+cpu", "PyPI") in pkgs  # OSV can take every variant

    def test_poetry_lock_packages_for_osv(self, tmp_path: Path) -> None:
        from depquiet.parsers.osv import parse_lockfiles

        (tmp_path / "poetry.lock").write_text('[[package]]\nname = "Jinja2"\nversion = "3.1.2"\n')
        assert ("jinja2", "3.1.2", "PyPI") in parse_lockfiles(tmp_path)
