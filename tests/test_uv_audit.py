"""``uv audit`` output as an input, and as the scanner for uv projects.

uv 0.13 ships ``uv audit``. It reports packages and versions but not how a
package is reached, and includes development groups by default. The fixture
is a real run on saleor/saleor (``uv audit --frozen --output-format json``,
2026-11-11, descriptions shortened): 16 findings, the same as pip-audit.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

import depquiet.engine as engine
from depquiet.engine import scan
from depquiet.fix import apply_fixes
from depquiet.models import FilterReason, Verdict
from depquiet.parsers.uv import UvAuditParser, adverse_note, is_uv_audit
from depquiet.scanners import ScanError, run_uv_audit

FIXTURE = Path(__file__).parent / "fixtures" / "uv_audit_saleor.json"


def _report() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _registry(name: str, version: str, *deps: str) -> str:
    listed = ", ".join(f'{{ name = "{d}" }}' for d in deps)
    return (
        f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
        + (f"dependencies = [{listed}]\n" if deps else "")
        + "\n"
    )


def _saleor_like(tmp_path: Path) -> Path:
    """oauthlib in production, filelock only under pre-commit in the dev group."""
    _write(
        tmp_path / "pyproject.toml",
        '[project]\nname = "shop"\nversion = "0"\ndependencies = ["oauthlib"]\n'
        '[dependency-groups]\ndev = ["pre-commit"]\n',
    )
    _write(
        tmp_path / "uv.lock",
        'version = 1\n\n[[package]]\nname = "shop"\nversion = "0"\nsource = { editable = "." }\n'
        'dependencies = [{ name = "oauthlib" }]\n\n'
        '[package.dev-dependencies]\ndev = [{ name = "pre-commit" }]\n\n'
        + _registry("oauthlib", "4.0.0")
        + _registry("pre-commit", "4.0.0", "filelock")
        + _registry("filelock", "3.32.7"),
    )
    _write(tmp_path / "shop/auth.py", "import oauthlib\n")
    return tmp_path


def test_real_report_parses() -> None:
    report = _report()
    assert is_uv_audit(report)
    vulns = UvAuditParser.parse(report, Path("."))
    assert len(vulns) == 16
    oauth = next(v for v in vulns if v.package == "oauthlib")
    assert (oauth.cve, oauth.version, oauth.fix_version) == (
        "GHSA-3jp2-3mrg-2vxc",
        "4.0.0",
        "4.0.1",
    )
    assert oauth.url.startswith("https://github.com/oauthlib/")
    assert adverse_note(report) == (
        "uv audit also flags packages with an adverse status: rsa (archived)."
    )


@pytest.mark.parametrize(
    "report",
    [
        {"vulnerabilities": [], "summary": {}},
        {"schema": {"version": "preview"}, "vulnerabilities": {}},
        {"dependencies": [], "schema": {"version": 1}},
        {"schema": {"version": "1"}, "vulnerabilities": [{"id": "x"}]},
    ],
)
def test_other_reports_are_not_uv(report: dict[str, Any]) -> None:
    assert not is_uv_audit(report)


def test_duplicate_aliases_are_reported_once() -> None:
    finding = {"dependency": {"name": "a", "version": "1"}, "aliases": ["CVE-1"]}
    report = {
        "schema": {"version": "preview"},
        "vulnerabilities": [{**finding, "id": "GHSA-1"}, {**finding, "id": "PYSEC-1"}],
    }
    assert [v.cve for v in UvAuditParser.parse(report, Path("."))] == ["GHSA-1"]


def test_piped_uv_audit_is_triaged(tmp_path: Path) -> None:
    result = scan(_saleor_like(tmp_path), audit_json=_report(), skip_epss=True)
    assert result.package_manager == "uv"
    by_package: dict[str, set[Verdict]] = {}
    for finding in result.results:
        by_package.setdefault(finding.vuln.package, set()).add(finding.verdict)
    assert by_package["oauthlib"] == {Verdict.ACTION}
    assert by_package["filelock"] == {Verdict.FILTERED}
    filelock = next(r for r in result.results if r.vuln.package == "filelock")
    assert FilterReason.DEV_DEPENDENCY in filelock.reasons
    assert filelock.introduced_by == ["pre-commit"]
    assert "rsa (archived)" in result.note


def _completed(stdout: str, code: int = 1) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], code, stdout, "")


def test_runner_reads_the_lock_as_written(tmp_path: Path) -> None:
    _saleor_like(tmp_path)
    calls: list[list[str]] = []

    def fake(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return _completed(FIXTURE.read_text(encoding="utf-8"))

    with (
        patch("depquiet.scanners.shutil.which", return_value="/usr/bin/uv"),
        patch("depquiet.scanners.subprocess.run", side_effect=fake),
    ):
        report = run_uv_audit(tmp_path)
    assert report["summary"]["vulnerabilities"] == 16
    [cmd] = calls
    assert cmd[1:3] == ["audit", "--frozen"]
    assert "--no-dev" not in cmd and "json" in cmd


@pytest.mark.parametrize(
    ("which", "lock", "stdout", "message"),
    [
        (None, True, "", "uv is not installed"),
        ("/usr/bin/uv", False, "", "needs a uv.lock"),
        ("/usr/bin/uv", True, "error: Request failed", "uv audit failed"),
    ],
)
def test_runner_errors(
    tmp_path: Path, which: str | None, lock: bool, stdout: str, message: str
) -> None:
    if lock:
        _saleor_like(tmp_path)
    with (
        patch("depquiet.scanners.shutil.which", return_value=which),
        patch("depquiet.scanners.subprocess.run", return_value=_completed(stdout, 2)),
        pytest.raises(ScanError, match=message),
    ):
        run_uv_audit(tmp_path)


def test_uv_audit_stands_in_when_pip_audit_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _saleor_like(tmp_path)
    monkeypatch.setattr(
        engine.shutil, "which", lambda name: "/usr/bin/uv" if name == "uv" else None
    )
    monkeypatch.setattr(
        engine,
        "run_pip_audit",
        lambda p: (_ for _ in ()).throw(ScanError("pip-audit is not installed")),
    )
    monkeypatch.setattr(engine, "run_uv_audit", lambda p: _report())
    result = scan(project, skip_epss=True)
    assert result.scanned and result.package_manager == "uv"
    assert "Audited uv.lock with uv audit instead." in result.note
    assert len(result.results) == 16


def test_pip_audit_still_wins_when_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Existing users keep the scanner, and the finding ids, they had."""
    project = _saleor_like(tmp_path)
    monkeypatch.setattr(engine.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(engine, "run_pip_audit", lambda p: {"dependencies": []})
    monkeypatch.setattr(engine, "run_uv_audit", lambda p: pytest.fail("uv audit must not run"))
    assert scan(project, skip_epss=True).package_manager == "pip"


def test_explicit_uv_scanner_and_fix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = _saleor_like(tmp_path)
    monkeypatch.setattr(engine, "run_uv_audit", lambda p: _report())
    result = scan(project, skip_epss=True, scanner="uv")
    assert result.package_manager == "uv"
    fixes = apply_fixes(result, project, dry_run=True)
    assert any(
        f.message == "Would run: uv lock --upgrade-package oauthlib==4.0.1" for f in fixes.fixed
    )


def test_header_counts_vulnerable_packages_not_audited_ones(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """saleor: uv audited 231 packages; 4 of them have alerts."""
    from depquiet.output import print_scan_result

    print_scan_result(scan(_saleor_like(tmp_path), audit_json=_report(), skip_epss=True))
    assert "(4 vulnerable packages)" in capsys.readouterr().out
