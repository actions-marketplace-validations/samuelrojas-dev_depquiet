"""A project with npm and Python dependencies is scanned for both in one run.

Half of the public projects measured for 0.33 (saleor, open-webui, redash,
pretix, gradio, jupyterhub...) declare both. Until 0.35 a default run scanned
the first ecosystem found and only named the other in a note, so a clean npm
report said nothing about the Python side.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import depquiet.engine as engine
from depquiet.engine import scan
from depquiet.finding_identity import report_contexts, report_for_scan
from depquiet.fix import apply_fixes
from depquiet.models import FilterReason, Severity, Verdict, Vulnerability
from depquiet.scanners import ScanError


def _json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _project(tmp_path: Path) -> Path:
    _json(
        tmp_path / "package.json",
        {"dependencies": {"web-lib": "1"}, "devDependencies": {"bundler": "1"}},
    )
    _json(
        tmp_path / "package-lock.json",
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"web-lib": "1"}, "devDependencies": {"bundler": "1"}},
                "node_modules/web-lib": {"version": "1.0.0"},
                "node_modules/bundler": {"version": "1.0.0", "dev": True},
            },
        },
    )
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "svc"\ndependencies = ["api-lib"]\n'
        '[dependency-groups]\ndev = ["linter"]\n',
        encoding="utf-8",
    )
    (tmp_path / "web.js").write_text("require('web-lib')\n", encoding="utf-8")
    (tmp_path / "svc.py").write_text("import api_lib\n", encoding="utf-8")
    return tmp_path


def _vuln(package: str, cve: str) -> Vulnerability:
    return Vulnerability(
        cve=cve,
        package=package,
        version="1.0.0",
        severity=Severity.HIGH,
        title="Synthetic",
        fix_version="2.0.0",
        is_direct=True,
    )


REPORTS = {
    "npm": [_vuln("web-lib", "GHSA-web"), _vuln("bundler", "GHSA-bundler")],
    "pip": [_vuln("api-lib", "PYSEC-api"), _vuln("linter", "PYSEC-linter")],
}


@pytest.fixture
def scanners(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    seen: list[str] = []

    def fake(pm: str, project: Path, *, offline: bool):
        seen.append(pm)
        if isinstance(REPORTS.get(pm), ScanError):
            raise REPORTS[pm]  # type: ignore[misc]
        return [_vuln(v.package, v.cve) for v in REPORTS[pm]], pm, ""

    monkeypatch.setattr(engine, "_run_scanner", fake)
    return seen


def test_both_ecosystems_are_scanned_and_triaged_on_their_own_graph(
    tmp_path: Path, scanners: list[str]
) -> None:
    result = scan(_project(tmp_path), skip_epss=True)
    assert scanners == ["npm", "pip"]
    assert result.scanned and result.package_manager == "npm+pip"
    assert result.note == ""
    verdicts = {r.vuln.package: (r.vuln.package_manager, r.verdict) for r in result.results}
    assert verdicts == {
        "web-lib": ("npm", Verdict.ACTION),
        "bundler": ("npm", Verdict.FILTERED),
        "api-lib": ("pip", Verdict.ACTION),
        "linter": ("pip", Verdict.FILTERED),
    }
    linter = next(r for r in result.results if r.vuln.package == "linter")
    assert FilterReason.DEV_DEPENDENCY in linter.reasons


def test_finding_identities_match_a_single_ecosystem_scan(
    tmp_path: Path, scanners: list[str]
) -> None:
    """A baseline made with ``--scanner pip`` still matches the merged report."""
    project = _project(tmp_path)
    merged = report_for_scan(scan(project, skip_epss=True))
    alone = report_for_scan(scan(project, skip_epss=True, scanner="pip"))
    merged_ids = {c.context_id for c, _ in report_contexts(merged, project_id="p")}
    alone_ids = {c.context_id for c, _ in report_contexts(alone, project_id="p")}
    assert alone_ids and alone_ids <= merged_ids


def test_one_ecosystem_failing_is_named_and_the_other_is_kept(
    tmp_path: Path, scanners: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(REPORTS, "pip", ScanError("pip-audit is not installed."))
    result = scan(_project(tmp_path), skip_epss=True)
    assert result.scanned and result.package_manager == "npm"
    assert result.note.startswith("Python dependencies were not scanned:")
    assert "pip-audit is not installed" in result.note
    assert {r.vuln.package for r in result.results} == {"web-lib", "bundler"}


def test_nothing_scanned_when_every_ecosystem_fails(
    tmp_path: Path, scanners: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(REPORTS, "npm", ScanError("npm is not installed."))
    monkeypatch.setitem(REPORTS, "pip", ScanError("pip-audit is not installed."))
    result = scan(_project(tmp_path), skip_epss=True)
    assert not result.scanned
    assert "npm dependencies were not scanned" in result.note
    assert "Python dependencies were not scanned" in result.note


def test_single_ecosystem_project_is_unchanged(tmp_path: Path, scanners: list[str]) -> None:
    project = _project(tmp_path)
    (project / "pyproject.toml").unlink()
    result = scan(project, skip_epss=True)
    assert scanners == ["npm"]
    assert result.package_manager == "npm"
    assert all(r.vuln.package_manager == "" for r in result.results)


def test_pnpm_and_python(tmp_path: Path, scanners: list[str], monkeypatch) -> None:
    project = _project(tmp_path)
    (project / "package-lock.json").unlink()
    (project / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    monkeypatch.setitem(REPORTS, "pnpm", REPORTS["npm"])
    result = scan(project, skip_epss=True)
    assert scanners == ["pnpm", "pip"]
    assert result.package_manager == "pnpm+pip"


def test_fix_uses_each_findings_package_manager(tmp_path: Path, scanners: list[str]) -> None:
    result = scan(_project(tmp_path), skip_epss=True)
    report = apply_fixes(result, tmp_path, dry_run=True)
    commands = {f.package: f.message for f in report.fixed}
    assert "npm install web-lib@2.0.0" in commands["web-lib"]
    assert "pip install api-lib==2.0.0" in commands["api-lib"]


def test_json_report_names_each_findings_package_manager(
    tmp_path: Path, scanners: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    from depquiet.cli import _print_json
    from depquiet.finding_identity import report_contexts

    _print_json(scan(_project(tmp_path), skip_epss=True))
    report = json.loads(capsys.readouterr().out)
    assert report["package_manager"] == "npm+pip"
    assert {row["package"]: row["package_manager"] for row in report["results"]} == {
        "web-lib": "npm",
        "bundler": "npm",
        "api-lib": "pip",
        "linter": "pip",
    }
    # Baselines and diffs read this JSON back.
    assert len(report_contexts(report, project_id="p")) == 4
