"""Run the reference harness/evaluator as real CLIs, entirely offline."""

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EVALUATOR = ROOT / "benchmarks" / "evaluate.py"
REFERENCE = ROOT / "benchmarks" / "reference"


def _run(*args):
    return subprocess.run(
        [sys.executable, *map(str, args)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
    )


@pytest.fixture
def evaluation_inputs(tmp_path):
    snapshot = tmp_path / "snapshot.json"
    snapshot.write_bytes(b'{"kind":"synthetic","project":"synthetic/evaluator-tests"}\n')
    digest = hashlib.sha256(snapshot.read_bytes()).hexdigest()
    cases = []
    results = []
    for label, verdict in [("retain", "action"), ("filter", "filtered"), ("unknown", "review")]:
        cases.append(
            {
                "project": "synthetic/evaluator-tests",
                "snapshot_sha256": digest,
                "package": f"fixture-{label}",
                "version": "1.0.0",
                "advisory": f"SYNTHETIC-{label.upper()}",
                "label": label,
                "reason": f"Invented {label} case for evaluator contract testing only.",
                "provenance": {
                    "kind": "synthetic",
                    "source": "this unit test; no real vulnerability evidence",
                    "reviewer": "synthetic test author",
                },
            }
        )
        results.append(
            {
                "package": f"fixture-{label}",
                "version": "1.0.0",
                "cve": f"SYNTHETIC-{label.upper()}",
                "verdict": verdict,
            }
        )
    return {
        "directory": tmp_path,
        "snapshot": snapshot,
        "labels": {"schema_version": 1, "cases": cases},
        "scan": {
            "project": "synthetic/evaluator-tests",
            "snapshot_sha256": digest,
            "scanned": True,
            "results": results,
        },
    }


def _evaluate(inputs, *extra, snapshot=False):
    labels_path = inputs["directory"] / "labels.json"
    scan_path = inputs["directory"] / "scan.json"
    labels_path.write_text(json.dumps(inputs["labels"]), encoding="utf-8")
    scan_path.write_text(json.dumps(inputs["scan"]), encoding="utf-8")
    args = [EVALUATOR, "--labels", labels_path, "--scan", scan_path, "--json", *extra]
    if snapshot:
        args.extend(["--snapshot", inputs["snapshot"]])
    process = _run(*args)
    return process, json.loads(process.stdout)


def test_controlled_harness_runs_snapshot_and_evaluates_its_actual_hash(tmp_path):
    scan = tmp_path / "controlled report.json"
    process = _run(REFERENCE / "run.py", "--output", scan)
    assert process.returncode == 0, process.stderr
    report = json.loads(scan.read_text(encoding="utf-8"))
    assert report["scanned"] is True
    assert (
        report["snapshot_sha256"]
        == hashlib.sha256((REFERENCE / "synthetic.snapshot.json").read_bytes()).hexdigest()
    )
    process = _run(
        EVALUATOR,
        "--labels",
        REFERENCE / "synthetic.labels.json",
        "--scan",
        scan,
        "--snapshot",
        REFERENCE / "synthetic.snapshot.json",
        "--json",
    )
    assert process.returncode == 0, process.stdout + process.stderr
    evaluation = json.loads(process.stdout)
    assert evaluation["scope"] == {"synthetic_cases": 2, "reviewed_cases": 0}
    assert evaluation["counts"]["false_dismissals"] == 0
    assert evaluation["counts"]["correct_dismissals"] == 1
    assert evaluation["counts"]["matched_unique_cases"] == 2
    assert evaluation["rates"]["false_dismissals"]["denominator"] == 1
    assert "not a real-world accuracy estimate" in evaluation["interpretation"]


@pytest.mark.parametrize(
    ("index", "metric"), [(0, "false_dismissals"), (2, "uncertain_dismissals")]
)
def test_discarding_retain_or_unknown_cases_fails_safety_gate(evaluation_inputs, index, metric):
    evaluation_inputs["scan"]["results"][index]["verdict"] = "filtered"
    process, report = _evaluate(evaluation_inputs)
    assert process.returncode == 1
    assert report["gate_passed"] is False
    assert report["counts"][metric] == 1
    assert report["rates"][metric]["numerator"] == 1
    assert report["rates"][metric]["denominator"] == 1
    assert metric in report["gate_failures"]


@pytest.mark.parametrize("verdict", ["action", "review"])
def test_retaining_filter_opportunities_is_not_a_safety_failure(evaluation_inputs, verdict):
    evaluation_inputs["scan"]["results"][1]["verdict"] = verdict
    process, report = _evaluate(evaluation_inputs)
    assert process.returncode == 0
    assert report["counts"]["retained_opportunities"] == 1
    assert report["rates"]["retained_opportunities"]["denominator"] == 1


@pytest.mark.parametrize("problem", ["missing_cases", "duplicate_results", "unlabelled_results"])
def test_missing_duplicate_and_unlabelled_results_cannot_improve_gate(evaluation_inputs, problem):
    rows = evaluation_inputs["scan"]["results"]
    if problem == "missing_cases":
        rows.pop(0)
    elif problem == "duplicate_results":
        rows.append(copy.deepcopy(rows[0]))
    else:
        rows.append({**rows[0], "cve": "SYNTHETIC-NO-REFERENCE"})
    process, report = _evaluate(evaluation_inputs)
    assert process.returncode == 1
    assert report["counts"][problem] == 1
    assert problem in report["gate_failures"]
    if problem in {"missing_cases", "duplicate_results"}:
        assert report["rates"]["false_dismissals"]["denominator"] == 0
        assert report["rates"]["false_dismissals"]["fraction"] is None
        assert report["by_label"]["retain"]["reference_cases"] == 1
    if problem == "duplicate_results":
        assert report["counts"]["duplicate_extra_rows"] == 1


@pytest.mark.parametrize("scanned", [False, None])
def test_incomplete_or_legacy_scan_fails_even_with_matching_alerts(evaluation_inputs, scanned):
    if scanned is None:
        del evaluation_inputs["scan"]["scanned"]
    else:
        evaluation_inputs["scan"]["scanned"] = scanned
    process, report = _evaluate(evaluation_inputs)
    assert process.returncode == 1
    assert "incomplete_scan" in report["gate_failures"]


def test_version_identity_is_exact_and_mismatches_are_visible(evaluation_inputs):
    evaluation_inputs["scan"]["results"][0]["version"] = "2.0.0"
    process, report = _evaluate(evaluation_inputs)
    assert process.returncode == 1
    assert report["counts"]["missing_cases"] == 1
    assert report["counts"]["unlabelled_results"] == 1


def test_supplied_snapshot_bytes_bind_a_plain_cli_report(evaluation_inputs):
    del evaluation_inputs["scan"]["snapshot_sha256"]
    evaluation_inputs["scan"]["project"] = "/local/path/to/project"
    process, report = _evaluate(
        evaluation_inputs, "--project", "synthetic/evaluator-tests", snapshot=True
    )
    assert process.returncode == 0
    assert report["snapshot_binding"] == "snapshot_bytes"
    assert report["report_project"] == "/local/path/to/project"


@pytest.mark.parametrize(
    "problem",
    [
        "duplicate_label",
        "missing_reviewer",
        "invalid_label",
        "invalid_verdict",
        "invalid_scanned",
        "conflicting_hash",
        "missing_hash",
        "other_project",
    ],
)
def test_ambiguous_or_invalid_inputs_exit_two(evaluation_inputs, problem):
    labels, scan = evaluation_inputs["labels"], evaluation_inputs["scan"]
    if problem == "duplicate_label":
        labels["cases"].append(copy.deepcopy(labels["cases"][0]))
    elif problem == "missing_reviewer":
        del labels["cases"][0]["provenance"]["reviewer"]
    elif problem == "invalid_label":
        labels["cases"][0]["label"] = "looks-safe"
    elif problem == "invalid_verdict":
        scan["results"][0]["verdict"] = "discard"
    elif problem == "invalid_scanned":
        scan["scanned"] = "true"
    elif problem == "conflicting_hash":
        scan["snapshot_sha256"] = "0" * 64
    elif problem == "missing_hash":
        del scan["snapshot_sha256"]
    elif problem == "other_project":
        scan["project"] = "different/project"
    process, report = _evaluate(evaluation_inputs, snapshot=problem == "conflicting_hash")
    assert process.returncode == 2
    assert report["status"] == "invalid"
    assert report["error"]


def test_malformed_json_is_invalid_not_a_passing_empty_scan(tmp_path):
    bad = tmp_path / "broken.json"
    bad.write_text("{", encoding="utf-8")
    process = _run(EVALUATOR, "--labels", bad, "--scan", bad, "--json")
    assert process.returncode == 2
    assert json.loads(process.stdout)["status"] == "invalid"


def test_duplicate_json_keys_do_not_silently_replace_reference_truth(tmp_path):
    bad = tmp_path / "ambiguous.json"
    bad.write_text('{"schema_version":1,"cases":[],"cases":[]}', encoding="utf-8")
    process = _run(EVALUATOR, "--labels", bad, "--scan", bad, "--json")
    assert process.returncode == 2
    assert "duplicate JSON key" in json.loads(process.stdout)["error"]


def test_harness_rejects_snapshot_paths_outside_its_temporary_project(tmp_path):
    snapshot = tmp_path / "unsafe.snapshot.json"
    snapshot.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "synthetic",
                "project": "test",
                "files": {"../escape": "x"},
                "audit_json": {},
            }
        ),
        encoding="utf-8",
    )
    process = _run(REFERENCE / "run.py", "--snapshot", snapshot)
    assert process.returncode == 2
    assert "invalid snapshot file" in process.stderr
