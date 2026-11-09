"""End-to-end scoped scanning, explicit baseline creation and instance diffs."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path

import pytest

from depquiet.cli import main

SCOPE = "example/service"
LOCATION = "node_modules/fixture-lib"
NESTED = "node_modules/parent/node_modules/fixture-lib"


@pytest.fixture
def project(tmp_path: Path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"fixture-lib": "1.0.0"}}))
    (tmp_path / "app.js").write_text("require('fixture-lib');\n")
    return tmp_path


def _lock(project: Path, nodes: dict[str, str]):
    packages = {"": {"dependencies": {"fixture-lib": "1.0.0"}}}
    packages.update({node: {"version": version} for node, version in nodes.items()})
    (project / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": packages}), encoding="utf-8"
    )


def _audit(nodes: list[str]):
    return {
        "vulnerabilities": {
            "fixture-lib": {
                "severity": "high",
                "isDirect": True,
                "nodes": nodes,
                "via": [
                    {
                        "title": "Synthetic instance context",
                        "range": "<3.0.0",
                        "url": "https://example.invalid/advisories/SYNTHETIC-INSTANCE",
                    }
                ],
            }
        }
    }


def _scan(project, monkeypatch, capsys, *, nodes=None, scope=SCOPE, baseline=None, extra=()):
    nodes = [LOCATION] if nodes is None else nodes
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_audit(nodes))))
    args = ["--path", str(project), "--stdin", "--offline", "--json"]
    if scope is not None:
        args += ["--project-id", scope]
    if baseline is not None:
        args += ["--baseline", str(baseline)]
    code = main([*args, *extra])
    output = capsys.readouterr()
    return code, json.loads(output.out) if output.out else None, output.err


def _create(project, monkeypatch, capsys):
    _lock(project, {LOCATION: "1.0.0"})
    code, report, _ = _scan(project, monkeypatch, capsys)
    assert code == 1 and report["project_id"] == SCOPE
    source = project / "before.json"
    raw = (json.dumps(report, indent=2) + "\n").encode("utf-8")
    source.write_bytes(raw)
    baseline = project / "accepted.json"
    assert (
        main(
            [
                "baseline",
                "create",
                str(source),
                "-o",
                str(baseline),
                "--reason",
                "Fixture risk acceptance",
                "--author",
                "Synthetic author",
            ]
        )
        == 0
    )
    output = capsys.readouterr()
    assert output.out == ""
    document = json.loads(baseline.read_text(encoding="utf-8"))
    assert document["baseline_schema_version"] == 2
    assert document["project_id"] == SCOPE
    assert document["source_scan_sha256"] == hashlib.sha256(raw).hexdigest()
    assert document["source_scan_hash_kind"] == "file_bytes"
    assert len(document["accepted"]) == 1
    return source, baseline


def test_scoped_baseline_suppresses_known_context_and_records_acceptance(
    project, monkeypatch, capsys
):
    _, baseline = _create(project, monkeypatch, capsys)
    code, report, _ = _scan(project, monkeypatch, capsys, baseline=baseline)
    assert code == 0
    [row] = report["results"]
    assert row["verdict"] == "filtered"
    [decision] = [change for change in row["decision_trace"] if change["source"] == "baseline"]
    assert decision["rule_id"].startswith("baseline:v2:")
    assert decision["author"] == "Synthetic author"
    assert "Fixture risk acceptance" in decision["reason"]
    assert row["assessment"]["status"] == "under_investigation"


@pytest.mark.parametrize("change", ["version", "location"])
def test_new_instance_survives_acceptance_and_triggers_diff_gate(
    project, monkeypatch, capsys, change
):
    source, baseline = _create(project, monkeypatch, capsys)
    nodes = {LOCATION: "2.0.0"} if change == "version" else {LOCATION: "1.0.0", NESTED: "1.0.0"}
    _lock(project, nodes)
    code, report, _ = _scan(project, monkeypatch, capsys, nodes=list(nodes), baseline=baseline)
    assert code == 1 and report["results"][0]["verdict"] == "action"
    head = project / "after.json"
    head.write_text(json.dumps(report), encoding="utf-8")
    assert main(["diff", str(source), str(head), "--json", "--fail-on-new"]) == 1
    difference = json.loads(capsys.readouterr().out)
    assert difference["identity_mode"] == "instances"
    assert len(difference["new"]) == 1
    assert difference["new"][0]["instance_id"]
    assert difference["new"][0]["version"] == ("2.0.0" if change == "version" else "1.0.0")
    assert difference["new"][0]["location"] == (LOCATION if change == "version" else NESTED)


def test_partial_resolution_cannot_inherit_acceptance(project, monkeypatch, capsys):
    _, baseline = _create(project, monkeypatch, capsys)
    code, report, _ = _scan(
        project, monkeypatch, capsys, nodes=[LOCATION, NESTED], baseline=baseline
    )
    assert code == 1
    [row] = report["results"]
    assert row["component_resolution_complete"] is False
    assert row["verdict"] == "action"


def test_trivy_literal_versions_in_npm_project_compare_without_becoming_acceptances(
    project, monkeypatch, capsys
):
    _lock(project, {LOCATION: "1.0.0"})
    reports = []
    for version in ("1.0.0", "2.0.0"):
        trivy = {
            "Results": [
                {
                    "Class": "lang-pkgs",
                    "Type": "npm",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "SYNTHETIC-TRIVY-INSTANCE",
                            "PkgName": "fixture-lib",
                            "InstalledVersion": version,
                            "Severity": "HIGH",
                        }
                    ],
                }
            ]
        }
        monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(trivy)))
        assert (
            main(["--path", str(project), "--stdin", "--offline", "--project-id", SCOPE, "--json"])
            == 1
        )
        report = json.loads(capsys.readouterr().out)
        assert report["package_manager"] == "npm"
        assert report["results"][0]["version_kind"] == "reported"
        path = project / f"trivy-{version}.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        reports.append(path)

    assert main(["diff", *map(str, reports), "--json", "--fail-on-new"]) == 1
    difference = json.loads(capsys.readouterr().out)
    assert difference["identity_mode"] == "instances"
    assert difference["new"][0]["version"] == "2.0.0"
    assert difference["new"][0]["identity_kind"] == "reported"
    assert "instance_id" not in difference["new"][0]
    accepted = project / "trivy-baseline.json"
    assert main(["baseline", "create", str(reports[0]), "-o", str(accepted)]) == 0
    capsys.readouterr()
    document = json.loads(accepted.read_text(encoding="utf-8"))
    assert document["accepted"] == []
    assert len(document["unaccepted"]) == 1


@pytest.mark.parametrize("scope", [None, "example/other"])
def test_wrong_or_missing_scope_fails_before_output_artifacts(project, monkeypatch, capsys, scope):
    _, baseline = _create(project, monkeypatch, capsys)
    summary = project / "summary.md"
    summary.write_bytes(b"existing summary")
    code, report, error = _scan(
        project,
        monkeypatch,
        capsys,
        baseline=baseline,
        scope=scope,
        extra=["--summary", str(summary)],
    )
    assert code == 2 and report is None
    assert "scope" in error or "project" in error
    assert summary.read_bytes() == b"existing summary"


def test_config_scope_and_explicit_cli_override(project, monkeypatch, capsys):
    _lock(project, {LOCATION: "1.0.0"})
    (project / ".depquiet.yaml").write_text("project_id: example/from-config\n", encoding="utf-8")
    _, report, _ = _scan(project, monkeypatch, capsys, scope=None)
    assert report["project_id"] == "example/from-config"
    _, report, _ = _scan(
        project, monkeypatch, capsys, scope=None, extra=["--project-id=example/from-cli"]
    )
    assert report["project_id"] == "example/from-cli"


@pytest.mark.parametrize("source", [{"results": []}, {"scanned": False, "results": []}])
def test_creation_rejects_unverified_completion_without_overwriting(project, capsys, source):
    scan = project / "source.json"
    scan.write_text(json.dumps(source), encoding="utf-8")
    output = project / "baseline.json"
    output.write_bytes(b"previous acceptance document")
    assert main(["baseline", "create", str(scan), "--project-id", SCOPE, "-o", str(output)]) == 2
    assert capsys.readouterr().out == ""
    assert output.read_bytes() == b"previous acceptance document"


def test_creation_cannot_replace_its_source_scan(project, monkeypatch, capsys):
    source, _ = _create(project, monkeypatch, capsys)
    before = source.read_bytes()
    assert main(["baseline", "create", str(source), "-o", str(source)]) == 2
    assert source.read_bytes() == before
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("scope", ["", " bad-scope", "bad\nscope"])
def test_invalid_explicit_scope_fails_before_scanning(project, monkeypatch, capsys, scope):
    def unexpected_scan(*args, **kwargs):
        raise AssertionError("invalid project scope must fail before running a scanner")

    monkeypatch.setattr("depquiet.cli.scan", unexpected_scan)
    assert main(["--path", str(project), "--project-id", scope, "--json"]) == 2
    output = capsys.readouterr()
    assert output.out == "" and "scope" in output.err


def test_empty_config_scope_does_not_silently_fall_back_to_legacy(project, monkeypatch, capsys):
    (project / ".depquiet.yaml").write_text("project_id: ''\n", encoding="utf-8")

    def unexpected_scan(*args, **kwargs):
        raise AssertionError("invalid config scope must fail before running a scanner")

    monkeypatch.setattr("depquiet.cli.scan", unexpected_scan)
    assert main(["--path", str(project), "--json"]) == 2
    output = capsys.readouterr()
    assert output.out == "" and "project" in output.err
