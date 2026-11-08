"""Offline harness tests using invented audit data and temporary local Git repos.

These are synthetic tests of the reviewed-reference mechanism, not real cases.
"""

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "reviewed_reference_harness", ROOT / "benchmarks/reference/run_reviewed.py"
)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)


def _git(source, *args):
    result = subprocess.run(
        [
            "git",
            "-C",
            str(source),
            "-c",
            "user.name=Synthetic test author",
            "-c",
            "user.email=synthetic@example.invalid",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")


@pytest.fixture
def reviewed_context(tmp_path):
    source = tmp_path / "source checkout"
    source.mkdir()
    _git(source, "init")
    _write_json(
        source / "package.json",
        {
            "name": "synthetic-harness-test",
            "version": "1.0.0",
            "dependencies": {"fixture-runtime": "1.0.0", "fixture-unselected": "1.0.0"},
            "scripts": {"postinstall": "this invented command must never be executed"},
        },
    )
    (source / "app.js").write_text("const runtime = require('fixture-runtime');\nruntime.call();\n")
    (source / ".gitignore").write_text("*.ignored\n")
    vendored = source / "node_modules/ignored-source/file.js"
    vendored.parent.mkdir(parents=True)
    vendored.write_text("require('fixture-unselected');\n")
    _git(source, "add", ".")
    _git(source, "commit", "-m", "Synthetic harness source; no real advisory evidence")
    commit = _git(source, "rev-parse", "HEAD")
    # Ignored files must not leak into the source snapshot or usage evidence.
    (source / "cache.ignored").write_text("ignored checkout content")
    fixture_root = tmp_path / "fixture repository"
    fixture_dir = fixture_root / "benchmarks/fixtures/synthetic-harness-test"
    audit_path = fixture_dir / "audit.json"
    vulns = {}
    for package, advisory in [
        ("fixture-runtime", "SYNTHETIC-KEEP"),
        ("fixture-unselected", "SYNTHETIC-OTHER"),
    ]:
        vulns[package] = {
            "severity": "high",
            "isDirect": True,
            "via": [
                {
                    "name": package,
                    "title": "Invented test advisory",
                    "url": f"https://example.invalid/advisories/{advisory}",
                    "range": "1.0.0",
                }
            ],
        }
    _write_json(audit_path, {"auditReportVersion": 2, "vulnerabilities": vulns})
    overlay_path = fixture_dir / "package-lock.json"
    _write_json(
        overlay_path,
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"fixture-runtime": "1.0.0", "fixture-unselected": "1.0.0"}},
                "node_modules/fixture-runtime": {"version": "1.0.0"},
                "node_modules/fixture-unselected": {"version": "1.0.0"},
            },
        },
    )
    spec = {
        "schema_version": 1,
        "kind": "upstream_reference",
        "project": "synthetic/local-harness-test",
        "source": {"repository": "synthetic/local-tests", "commit": commit},
        "audit": {
            "path": audit_path.relative_to(fixture_root).as_posix(),
            "sha256": hashlib.sha256(audit_path.read_bytes()).hexdigest(),
        },
        "overlay_files": [
            {
                "path": overlay_path.relative_to(fixture_root).as_posix(),
                "target": "package-lock.json",
                "sha256": hashlib.sha256(overlay_path.read_bytes()).hexdigest(),
            }
        ],
        "selection": [
            {"package": "fixture-runtime", "version": "1.0.0", "advisory": "SYNTHETIC-KEEP"}
        ],
    }
    snapshot = tmp_path / "synthetic-test.snapshot.json"
    _write_json(snapshot, spec)
    return {
        "source": source,
        "fixture_root": fixture_root,
        "audit": audit_path,
        "overlay": overlay_path,
        "snapshot": snapshot,
        "spec": spec,
        "directory": tmp_path,
    }


def _run(context):
    _write_json(context["snapshot"], context["spec"])
    return HARNESS.run_snapshot(
        context["snapshot"], context["source"], repo_root=context["fixture_root"]
    )


def test_clean_pinned_source_and_frozen_overlay_produce_stable_evidence(
    reviewed_context, monkeypatch
):
    original_scan = HARNESS.scan
    seen = []

    def inspect_scan(project, **kwargs):
        assert not (project / ".git").exists()
        assert not (project / "node_modules").exists()
        assert not (project / "cache.ignored").exists()
        assert (project / "package-lock.json").read_bytes() == reviewed_context[
            "overlay"
        ].read_bytes()
        assert kwargs["skip_epss"] is True
        assert kwargs["audit_json"]["auditReportVersion"] == 2
        seen.append(True)
        return original_scan(project, **kwargs)

    monkeypatch.setattr(HARNESS, "scan", inspect_scan)
    report = _run(reviewed_context)
    assert _run(reviewed_context) == report
    assert len(seen) == 2
    assert report["scanned"] is True
    assert report["project"] == reviewed_context["spec"]["project"]
    assert (
        report["snapshot_sha256"]
        == hashlib.sha256(reviewed_context["snapshot"].read_bytes()).hexdigest()
    )
    assert report["reference_context"]["source"] == reviewed_context["spec"]["source"]
    assert report["reference_context"]["audit"] == reviewed_context["spec"]["audit"]
    assert report["evaluation_scope"]["selected_result_rows"] == 1
    assert report["evaluation_scope"]["unselected_result_rows"] == 1
    assert report["evaluation_scope"]["full_scan_summary"]["total"] == 2
    assert report["summary"]["total"] == 1
    finding = report["results"][0]
    assert finding["version"] == "1.0.0"
    assert finding["evidence"]["import_sites"] == ["app.js"]
    assert "assessment" in finding and "decision_trace" in finding
    assert str(reviewed_context["source"]) not in json.dumps(report)
    assert "depquiet-upstream-reference-" not in json.dumps(report)
    assert not (reviewed_context["source"] / "package-lock.json").exists()
    assert _git(reviewed_context["source"], "status", "--porcelain", "--untracked-files=all") == ""


def test_default_scope_keeps_full_audit(reviewed_context):
    del reviewed_context["spec"]["selection"]
    report = _run(reviewed_context)
    assert report["evaluation_scope"]["type"] == "full_frozen_audit"
    assert report["evaluation_scope"]["unselected_result_rows"] == 0
    assert report["summary"]["total"] == 2


def test_selection_is_static_and_not_a_verdict_filter(reviewed_context, monkeypatch):
    original_scan = HARNESS.scan

    def filtered_scan(*args, **kwargs):
        result = original_scan(*args, **kwargs)
        for item in result.results:
            item.verdict = type(item.verdict).FILTERED
        return result

    first = _run(reviewed_context)
    monkeypatch.setattr(HARNESS, "scan", filtered_scan)
    second = _run(reviewed_context)
    assert first["evaluation_scope"]["selection"] == second["evaluation_scope"]["selection"]
    assert [item["cve"] for item in first["results"]] == [item["cve"] for item in second["results"]]
    assert second["results"][0]["verdict"] == "filtered"


def test_missing_selected_case_stays_absent_and_fails_evaluator_gate(reviewed_context):
    reviewed_context["spec"]["selection"][0]["advisory"] = "SYNTHETIC-MISSING"
    report = _run(reviewed_context)
    assert report["results"] == []
    assert report["evaluation_scope"]["full_scan_summary"]["total"] == 2
    label = {
        **reviewed_context["spec"]["selection"][0],
        "project": report["project"],
        "snapshot_sha256": report["snapshot_sha256"],
        "label": "retain",
        "reason": "Invented missing-case test, not real evidence",
        "provenance": {"kind": "synthetic", "source": "this test", "reviewer": "test author"},
    }
    label_path = reviewed_context["directory"] / "labels.json"
    report_path = reviewed_context["directory"] / "report.json"
    _write_json(label_path, {"schema_version": 1, "cases": [label]})
    _write_json(report_path, report)
    process = subprocess.run(
        [
            sys.executable,
            str(ROOT / "benchmarks/evaluate.py"),
            "--labels",
            str(label_path),
            "--scan",
            str(report_path),
            "--json",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
    )
    assert process.returncode == 1, process.stderr
    assert "missing_cases" in json.loads(process.stdout)["gate_failures"]


@pytest.mark.parametrize("change", ["revision", "tracked", "staged", "untracked"])
def test_source_revision_and_clean_worktree_are_required(reviewed_context, change):
    if change == "revision":
        reviewed_context["spec"]["source"]["commit"] = "0" * 40
    elif change in {"tracked", "staged"}:
        (reviewed_context["source"] / "app.js").write_text("tampered source\n")
        if change == "staged":
            _git(reviewed_context["source"], "add", "app.js")
    else:
        (reviewed_context["source"] / "untracked.js").write_text("unexpected context")
    with pytest.raises(ValueError, match=r"HEAD mismatch|dirty"):
        _run(reviewed_context)


@pytest.mark.parametrize("artifact", ["audit", "overlay"])
def test_tampered_frozen_artifact_hash_is_rejected(reviewed_context, artifact):
    reviewed_context[artifact].write_bytes(b"{}\n")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        _run(reviewed_context)


@pytest.mark.parametrize("escape", ["audit", "overlay_source", "overlay_target"])
def test_artifact_and_target_path_escapes_are_rejected(reviewed_context, escape):
    if escape == "audit":
        reviewed_context["spec"]["audit"]["path"] = "benchmarks/fixtures/../../outside.json"
    elif escape == "overlay_source":
        reviewed_context["spec"]["overlay_files"][0]["path"] = str(reviewed_context["audit"])
    else:
        reviewed_context["spec"]["overlay_files"][0]["target"] = "../outside.json"
    with pytest.raises(ValueError, match="safe repository-relative"):
        _run(reviewed_context)


def test_incomplete_scan_is_never_marked_complete(reviewed_context, monkeypatch, capsys):
    original_scan = HARNESS.scan

    def incomplete(*args, **kwargs):
        result = original_scan(*args, **kwargs)
        result.scanned = False
        result.note = "Synthetic incomplete-scan test"
        return result

    monkeypatch.setattr(HARNESS, "scan", incomplete)
    assert (
        HARNESS.main(
            [
                "--snapshot",
                str(reviewed_context["snapshot"]),
                "--source-dir",
                str(reviewed_context["source"]),
            ],
            repo_root=reviewed_context["fixture_root"],
        )
        == 1
    )
    report = json.loads(capsys.readouterr().out)
    assert report["scanned"] is False
    assert report["note"] == "Synthetic incomplete-scan test"


def test_invalid_context_cli_exits_two(reviewed_context, capsys):
    reviewed_context["spec"]["source"]["commit"] = "bad-revision"
    _write_json(reviewed_context["snapshot"], reviewed_context["spec"])
    assert (
        HARNESS.main(
            [
                "--snapshot",
                str(reviewed_context["snapshot"]),
                "--source-dir",
                str(reviewed_context["source"]),
            ],
            repo_root=reviewed_context["fixture_root"],
        )
        == 2
    )
    assert "full 40-character" in capsys.readouterr().err


def test_source_paths_colliding_on_windows_are_rejected(tmp_path, monkeypatch):
    tree = (
        b"\0".join(
            [
                f"100644 blob {'1' * 40}\tFile.js".encode(),
                f"100644 blob {'2' * 40}\tfile.js".encode(),
            ]
        )
        + b"\0"
    )
    monkeypatch.setattr(HARNESS, "_git", lambda *args, **kwargs: tree)
    with pytest.raises(ValueError, match="collide on Windows"):
        HARNESS._materialize(tmp_path, "0" * 40, tmp_path / "output")


def test_overlay_paths_colliding_on_windows_are_rejected(reviewed_context):
    overlay = reviewed_context["spec"]["overlay_files"][0]
    reviewed_context["spec"]["overlay_files"].append({**overlay, "target": "PACKAGE-LOCK.JSON"})
    with pytest.raises(ValueError, match="duplicates"):
        _run(reviewed_context)


@pytest.fixture
def python_reviewed_context(reviewed_context):
    """A fictional Python distribution with an unrelated imported module name."""
    source = reviewed_context["source"]
    (source / "package.json").unlink()
    (source / "app.js").unlink()
    (source / "requirements.txt").write_text("fixture-distribution-with-alias==1.0.0\n")
    (source / "app.py").write_text("import host_only_module\n")
    _git(source, "add", "--all")
    _git(source, "commit", "-m", "Synthetic Python alias context")
    spec = reviewed_context["spec"]
    spec["source"]["commit"] = _git(source, "rev-parse", "HEAD")
    _write_json(
        reviewed_context["audit"],
        {
            "dependencies": [
                {
                    "name": "fixture-distribution-with-alias",
                    "version": "1.0.0",
                    "vulns": [
                        {
                            "id": "SYNTHETIC-PYTHON-ALIAS",
                            "fix_versions": [],
                            "description": "Invented harness-only advisory",
                        }
                    ],
                }
            ],
        },
    )
    spec["audit"]["sha256"] = hashlib.sha256(reviewed_context["audit"].read_bytes()).hexdigest()
    spec["overlay_files"] = []
    spec["selection"] = [
        {
            "package": "fixture-distribution-with-alias",
            "version": "1.0.0",
            "advisory": "SYNTHETIC-PYTHON-ALIAS",
        }
    ]
    return reviewed_context


def test_host_python_aliases_do_not_change_frozen_report_and_are_restored(
    python_reviewed_context, monkeypatch
):
    pynames = HARNESS.pynames
    monkeypatch.setattr(pynames, "_running_environment", lambda: {})
    baseline = _run(python_reviewed_context)

    def unrelated_host_metadata():
        return {"fixture-distribution-with-alias": frozenset({"host_only_module"})}

    monkeypatch.setattr(pynames, "_running_environment", unrelated_host_metadata)
    assert "host_only_module" in pynames.import_candidates("fixture-distribution-with-alias")
    isolated = _run(python_reviewed_context)
    assert isolated == baseline
    assert isolated["results"][0]["evidence"]["usage"] != "observed"
    assert isolated["results"][0]["evidence"]["import_sites"] == []
    assert isolated["reference_context"]["host_python_metadata_excluded"] is True
    assert pynames._running_environment is unrelated_host_metadata
    assert "host_only_module" in pynames.import_candidates("fixture-distribution-with-alias")


def test_host_python_metadata_is_restored_when_scan_raises(python_reviewed_context, monkeypatch):
    def injected_host_metadata():
        return {"fixture-distribution-with-alias": frozenset({"host_only_module"})}

    monkeypatch.setattr(HARNESS.pynames, "_running_environment", injected_host_metadata)

    def failed_scan(*args, **kwargs):
        assert HARNESS.pynames._running_environment() == {}
        raise RuntimeError("Synthetic scan exception")

    monkeypatch.setattr(HARNESS, "scan", failed_scan)
    with pytest.raises(RuntimeError, match="Synthetic scan exception"):
        _run(python_reviewed_context)
    assert HARNESS.pynames._running_environment is injected_host_metadata
    assert "host_only_module" in HARNESS.pynames.import_candidates(
        "fixture-distribution-with-alias"
    )


def test_committed_project_python_metadata_remains_part_of_frozen_input(
    python_reviewed_context, monkeypatch
):
    source = python_reviewed_context["source"]
    metadata = source / ".venv/Lib/site-packages/fixture_distribution_with_alias-1.0.0.dist-info"
    metadata.mkdir(parents=True)
    (metadata / "METADATA").write_text("Name: fixture-distribution-with-alias\nVersion: 1.0.0\n")
    (metadata / "top_level.txt").write_text("host_only_module\n")
    _git(source, "add", "--force", ".venv")
    _git(source, "commit", "-m", "Version synthetic project distribution metadata")
    python_reviewed_context["spec"]["source"]["commit"] = _git(source, "rev-parse", "HEAD")
    monkeypatch.setattr(HARNESS.pynames, "_running_environment", lambda: {})
    report = _run(python_reviewed_context)
    assert report["results"][0]["evidence"]["usage"] == "observed"
    assert report["results"][0]["evidence"]["import_sites"] == ["app.py"]
    assert report["reference_context"]["host_python_metadata_excluded"] is True
