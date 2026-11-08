"""JSON consumers receive one report when license analysis is enabled."""

import json
from io import StringIO
from unittest.mock import patch

import pytest

from depquiet.cli import main
from depquiet.fix import print_fix_report
from depquiet.models import ScanResult, Severity, TriageResult, Verdict, Vulnerability


@pytest.mark.parametrize("license_id", ["MIT", "GPL-3.0-only"])
@pytest.mark.parametrize("has_vulnerability", [False, True])
def test_license_json_preserves_scan_and_license_findings(
    tmp_path, capsys, license_id, has_vulnerability
):
    (tmp_path / "package.json").write_text('{"dependencies":{"example":"1.0.0"}}')
    package = tmp_path / "node_modules" / "example"
    package.mkdir(parents=True)
    (package / "package.json").write_text(
        json.dumps({"name": "example", "version": "1.0.0", "license": license_id})
    )
    results = []
    if has_vulnerability:
        results.append(
            TriageResult(
                Vulnerability("CVE-2026-12345", "example", "1.0.0", Severity.HIGH),
                Verdict.ACTION,
            )
        )
    scan = ScanResult(str(tmp_path), "npm", 1, results)
    with patch("depquiet.cli.scan", return_value=scan):
        status = main(["--path", str(tmp_path), "--json", "--license", "--offline"])

    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["total"] == int(has_vulnerability)
    assert report["summary"]["action"] == int(has_vulnerability)
    assert report["license"]["total"] == 1
    has_license_issue = license_id != "MIT"
    assert len(report["license"]["issues"]) == int(has_license_issue)
    if has_license_issue:
        assert report["license"]["issues"][0]["package"] == "example"
    assert status == int(has_vulnerability or has_license_issue)


def test_json_without_license_keeps_existing_scan_shape(tmp_path, capsys):
    scan = ScanResult(str(tmp_path), "npm", 0, [])
    with patch("depquiet.cli.scan", return_value=scan):
        status = main(["--path", str(tmp_path), "--json", "--offline"])
    report = json.loads(capsys.readouterr().out)
    assert status == 0
    assert report["summary"]["total"] == 0
    assert "license" not in report


def test_trivy_stdin_preserves_local_npm_license_scan(tmp_path, capsys):
    (tmp_path / "package.json").write_text('{"dependencies":{"gpl-thing":"1.0.0"}}')
    (tmp_path / "package-lock.json").write_text("{}")
    package = tmp_path / "node_modules" / "gpl-thing"
    package.mkdir(parents=True)
    (package / "package.json").write_text(
        json.dumps({"name": "gpl-thing", "version": "1.0.0", "license": "GPL-3.0-only"})
    )
    with patch("sys.stdin", StringIO('{"Results":[]}')):
        status = main(["--path", str(tmp_path), "--stdin", "--json", "--license", "--offline"])
    report = json.loads(capsys.readouterr().out)
    assert status == 1
    assert report["license"]["package_manager"] == "npm"
    assert report["license"]["total"] == 1
    assert report["license"]["issues"][0]["package"] == "gpl-thing"


def test_sbom_input_preserves_python_fix_command_in_dry_run(tmp_path):
    manifest = '[project]\nname="app"\ndependencies=["urllib3==1.26.0"]\n'
    (tmp_path / "pyproject.toml").write_text(manifest)
    (tmp_path / "app.py").write_text("import urllib3\n")
    sbom = tmp_path / "bom.json"
    sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {
                        "bom-ref": "urllib3",
                        "type": "library",
                        "name": "urllib3",
                        "version": "1.26.0",
                        "purl": "pkg:pypi/urllib3@1.26.0",
                    }
                ],
                "vulnerabilities": [
                    {
                        "id": "CVE-2026-99999",
                        "ratings": [{"severity": "high"}],
                        "affects": [
                            {
                                "ref": "urllib3",
                                "versions": [{"version": "2.0.7", "status": "unaffected"}],
                            }
                        ],
                    }
                ],
            }
        )
    )
    with (
        patch("depquiet.fix.subprocess.run") as run_command,
        patch("depquiet.cli.print_fix_report", wraps=print_fix_report) as printed_report,
    ):
        status = main(["--path", str(tmp_path), "--from-sbom", str(sbom), "--dry-run", "--offline"])
    assert status == 0
    report = printed_report.call_args.args[0]
    assert len(report.fixed) == 1
    assert report.fixed[0].message == "Would run: pip install urllib3==2.0.7"
    assert (tmp_path / "pyproject.toml").read_text() == manifest
    run_command.assert_not_called()
