"""Regressions for incomplete scans and shared production dependency paths."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from depquiet.cli import main
from depquiet.engine import scan
from depquiet.models import FilterReason, Verdict
from depquiet.scanners import ScanError


def _sbom(count: int = 1) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "name": f"library-{i}",
                "version": "1.0.0",
                "purl": f"pkg:npm/library-{i}@1.0.0",
            }
            for i in range(count)
        ],
    }


def _audit(package: str) -> dict:
    return {
        "vulnerabilities": {
            package: {
                "severity": "high",
                "isDirect": True,
                "via": [
                    {
                        "source": 123,
                        "title": "Regression finding",
                        "url": "https://github.com/advisories/GHSA-regression-finding",
                    }
                ],
            }
        }
    }


@pytest.mark.parametrize("failure", [OSError("network unavailable"), ScanError("lookup failed")])
def test_sbom_query_failure_is_not_a_clean_scan(tmp_path: Path, failure: Exception) -> None:
    with patch("depquiet.engine.query_osv_batch", side_effect=failure):
        result = scan(tmp_path, audit_json=_sbom())
    assert result.scanned is False
    assert result.note


@pytest.mark.parametrize("offline", [False, True])
def test_cli_sbom_unscanned_exits_two(tmp_path: Path, capsys, offline: bool) -> None:
    sbom = tmp_path / "bom.json"
    sbom.write_text(json.dumps(_sbom()), encoding="utf-8")
    args = ["--path", str(tmp_path), "--from-sbom", str(sbom)]
    if offline:
        args.append("--offline")
    with patch("depquiet.engine.query_osv_batch", side_effect=ScanError("network unavailable")):
        assert main(args) == 2
    output = capsys.readouterr()
    assert "nothing scanned" in output.err
    assert "No vulnerabilities found" not in output.out


def test_sbom_with_embedded_vulnerabilities_works_offline(tmp_path: Path) -> None:
    bom = _sbom()
    bom["components"][0]["bom-ref"] = "library"
    bom["vulnerabilities"] = [{"id": "GHSA-regression-finding", "affects": [{"ref": "library"}]}]
    with patch("depquiet.engine.query_osv_batch") as query:
        result = scan(tmp_path, audit_json=bom, skip_epss=True)
    query.assert_not_called()
    assert result.scanned is True
    assert len(result.results) == 1


def test_sbom_inventory_empty_is_not_scanned(tmp_path: Path) -> None:
    assert scan(tmp_path, audit_json=_sbom(0)).scanned is False


def test_large_sbom_queries_all_packages_in_batches(tmp_path: Path) -> None:
    def query(packages):
        return {"results": [{} for _ in packages]}

    with patch("depquiet.engine.query_osv_batch", side_effect=query) as mocked:
        result = scan(tmp_path, audit_json=_sbom(1001))
    assert result.scanned is True
    assert [len(call.args[0]) for call in mocked.call_args_list] == [1000, 1]


def test_npm_report_is_not_read_as_pip_in_a_python_project(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname="app"\n', encoding="utf-8")
    result = scan(tmp_path, audit_json=_audit("express"), skip_epss=True)
    assert result.package_manager == "npm"
    assert [tr.vuln.package for tr in result.results] == ["express"]


def test_pip_report_is_read_in_npm_project(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    report = {"dependencies": [{"name": "django", "version": "4.2", "vulns": [{"id": "CVE-X"}]}]}
    result = scan(tmp_path, audit_json=report, skip_epss=True)
    assert result.package_manager == "pip"
    assert len(result.results) == 1


def test_unknown_json_is_not_a_clean_scan(tmp_path: Path) -> None:
    result = scan(tmp_path, audit_json={"error": "scanner failed"}, skip_epss=True)
    assert result.scanned is False
    assert "unrecognized" in result.note


@pytest.mark.parametrize("shared_with_prod", [True, False])
def test_development_filter_accounts_for_all_roots(tmp_path: Path, shared_with_prod: bool) -> None:
    package = {
        "dependencies": {"express": "4.19.2"} if shared_with_prod else {},
        "devDependencies": {"qs": "6.11.0"},
    }
    (tmp_path / "package.json").write_text(json.dumps(package), encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": package,
                    "node_modules/express": {"dependencies": {"qs": "6.11.0"}},
                    "node_modules/qs": {"version": "6.11.0"},
                },
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "app.js").write_text("require('express'); require('qs');\n", encoding="utf-8")
    tr = scan(tmp_path, audit_json=_audit("qs"), skip_epss=True).results[0]
    if shared_with_prod:
        assert tr.verdict == Verdict.ACTION
        assert FilterReason.DEV_DEPENDENCY not in tr.reasons
    else:
        assert FilterReason.DEV_DEPENDENCY in tr.reasons
