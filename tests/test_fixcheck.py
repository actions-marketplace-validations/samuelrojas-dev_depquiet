"""``--check-fixes``: uv's resolver says whether each suggested fix installs.

The resolver messages below are uv 0.13.7's real output on saleor/saleor
(2026-11-11): oauthlib 4.0.1 is newer than saleor's ``exclude-newer-package``
cut-off, and opentelemetry-api 1.45.1 conflicts with the pinned
opentelemetry-semantic-conventions; filelock 4.2.1 resolves.
"""

# ruff: noqa: E501  (uv resolver messages are kept verbatim)
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from depquiet.engine import scan
from depquiet.fixcheck import _explain, check_fixes, fix_targets
from depquiet.models import Verdict

FIXTURE = Path(__file__).parent / "fixtures" / "uv_audit_saleor.json"

OAUTHLIB = """\
Using CPython 3.12.3 interpreter at: /usr/bin/python3.12
error: No solution found when resolving dependencies for split (markers: python_full_version == '3.12.*')
  cause: Because there is no version of oauthlib==4.0.1 and your project depends on oauthlib==4.0.1, we can conclude that your project's requirements are unsatisfiable.

hint: `oauthlib` was filtered by `exclude-newer-package` to only include packages uploaded before 2026-09-28T06:02:00Z. The requested version, v4.0.1, was published at 2026-10-31T09:52:56.206Z. Consider removing the setting or updating it to a later date.
"""
OTEL = """\
error: No solution found when resolving dependencies for split (markers: python_full_version == '3.12.*')
  cause: Because opentelemetry-semantic-conventions==0.58b0 depends on opentelemetry-api==1.37.0 and your project depends on opentelemetry-api==1.45.1, we can conclude that opentelemetry-semantic-conventions==0.58b0 and your project are incompatible.
         And because your project depends on opentelemetry-semantic-conventions>=0.58b0,<0.59, we can conclude that your project's requirements are unsatisfiable.
"""
RESOLVED = "Resolved 232 packages in 1.44s\nUpdate filelock v3.32.7 -> v4.2.1\n"


def _registry(name: str, *deps: str) -> str:
    listed = ", ".join(f'{{ name = "{d}" }}' for d in deps)
    return (
        f'[[package]]\nname = "{name}"\nversion = "1.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
        + (f"dependencies = [{listed}]\n" if deps else "")
        + "\n"
    )


def _project(tmp_path: Path) -> Path:
    """saleor's shape: two production packages, filelock/setuptools via dev tools."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "shop"\nversion = "0"\n'
        'dependencies = ["oauthlib", "opentelemetry-api"]\n'
        '[dependency-groups]\ndev = ["pre-commit"]\n',
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text(
        'version = 1\n\n[[package]]\nname = "shop"\nversion = "0"\nsource = { editable = "." }\n'
        'dependencies = [{ name = "oauthlib" }, { name = "opentelemetry-api" }]\n\n'
        '[package.dev-dependencies]\ndev = [{ name = "pre-commit" }]\n\n'
        + _registry("oauthlib")
        + _registry("opentelemetry-api")
        + _registry("pre-commit", "filelock", "setuptools")
        + _registry("filelock")
        + _registry("setuptools"),
        encoding="utf-8",
    )
    (tmp_path / "shop.py").write_text("import oauthlib\nimport opentelemetry\n", encoding="utf-8")
    return tmp_path


def _fake_uv(calls: list[list[str]], *, filelock_shown: bool = False):
    def run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        spec = cmd[cmd.index("--upgrade-package") + 1]
        if spec.startswith("oauthlib"):
            return subprocess.CompletedProcess(cmd, 1, "", OAUTHLIB)
        if spec.startswith("opentelemetry-api"):
            return subprocess.CompletedProcess(cmd, 1, "", OTEL)
        return subprocess.CompletedProcess(cmd, 0, "", RESOLVED)

    return run


def _scan(project: Path):
    report = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return scan(project, audit_json=report, skip_epss=True)


def test_targets_are_shown_alerts_with_their_highest_fix(tmp_path: Path) -> None:
    result = _scan(_project(tmp_path))
    targets = fix_targets(result)
    # filelock is filtered (pre-commit only) and so not checked.
    assert targets == {"oauthlib": "4.0.1", "opentelemetry-api": "1.45.1"}


def test_highest_fix_version_wins(tmp_path: Path) -> None:
    result = _scan(_project(tmp_path))
    for finding in result.results:
        finding.verdict = Verdict.ACTION
    # filelock alerts are fixed in 4.0.9 and 4.2.1: one upgrade to 4.2.1 covers both.
    assert fix_targets(result)["filelock"] == "4.2.1"


def test_resolver_answers_are_attached(tmp_path: Path) -> None:
    project = _project(tmp_path)
    result = _scan(project)
    calls: list[list[str]] = []
    with (
        patch("depquiet.fixcheck.shutil.which", return_value="/usr/bin/uv"),
        patch("depquiet.fixcheck.subprocess.run", side_effect=_fake_uv(calls)),
    ):
        checks, note = check_fixes(result, project)
    assert note == ""
    assert all(c[1:4] == ["lock", "--dry-run", "--upgrade-package"] for c in calls)
    oauth, otel = checks["oauthlib"], checks["opentelemetry-api"]
    assert oauth.status == otel.status == "blocked"
    assert oauth.detail.startswith("`oauthlib` was filtered by `exclude-newer-package`")
    assert otel.detail.startswith("Because opentelemetry-semantic-conventions==0.58b0 depends")
    assert oauth.command == "uv lock --upgrade-package oauthlib==4.0.1"
    shown = [r for r in result.results if r.vuln.package == "oauthlib"]
    assert shown and all(r.fix_check is oauth for r in shown)
    assert all(r.fix_check is None for r in result.results if r.vuln.package == "filelock")


def test_resolving_upgrade(tmp_path: Path) -> None:
    project = _project(tmp_path)
    result = _scan(project)
    for finding in result.results:
        finding.verdict = Verdict.ACTION
    with (
        patch("depquiet.fixcheck.shutil.which", return_value="/usr/bin/uv"),
        patch("depquiet.fixcheck.subprocess.run", side_effect=_fake_uv([])),
    ):
        checks, _ = check_fixes(result, project)
    assert checks["filelock"].status == "resolves"
    assert checks["filelock"].detail == "v3.32.7 -> v4.2.1"


@pytest.mark.parametrize(
    ("which", "lock", "message"),
    [(None, True, "needs uv on PATH"), ("/usr/bin/uv", False, "projects with a uv.lock")],
)
def test_missing_uv_or_lock(tmp_path: Path, which: str | None, lock: bool, message: str) -> None:
    project = _project(tmp_path)
    result = _scan(project)
    if not lock:
        (project / "uv.lock").unlink()
    with patch("depquiet.fixcheck.shutil.which", return_value=which):
        checks, note = check_fixes(result, project)
    assert checks == {} and message in note


def test_other_failures_are_errors_not_blocks(tmp_path: Path) -> None:
    project = _project(tmp_path)
    result = _scan(project)

    def offline(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            cmd, 2, "", "error: Failed to fetch: `https://pypi.org/simple/oauthlib/`\n"
        )

    with (
        patch("depquiet.fixcheck.shutil.which", return_value="/usr/bin/uv"),
        patch("depquiet.fixcheck.subprocess.run", side_effect=offline),
    ):
        checks, _ = check_fixes(result, project)
    assert {c.status for c in checks.values()} == {"error"}
    assert "Failed to fetch" in checks["oauthlib"].detail


def test_explain_keeps_continuation_lines() -> None:
    text = _explain(OTEL)
    assert "And because your project depends on opentelemetry-semantic-conventions" in text
    assert "Using CPython" not in _explain(OAUTHLIB)


def test_cli_json_includes_the_fix_check(tmp_path: Path, monkeypatch, capsys) -> None:
    import sys

    from depquiet.cli import main

    project = _project(tmp_path)
    monkeypatch.setattr(sys, "stdin", open(FIXTURE, encoding="utf-8"))  # noqa: SIM115
    with (
        patch("depquiet.fixcheck.shutil.which", return_value="/usr/bin/uv"),
        patch("depquiet.fixcheck.subprocess.run", side_effect=_fake_uv([])),
        patch("depquiet.engine.EpssFilter.lookup", lambda self, cves: None),
    ):
        main(["--path", str(project), "--stdin", "--check-fixes", "--json"])
    report = json.loads(capsys.readouterr().out)
    checks = {r["package"]: r["fix_check"]["status"] for r in report["results"] if "fix_check" in r}
    assert checks == {"oauthlib": "blocked", "opentelemetry-api": "blocked"}
