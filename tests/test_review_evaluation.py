"""Review metadata must not manufacture reference truth or passing coverage.

All people, decisions and evidence references in this file are synthetic test
data. The tests run the public evaluator/review CLIs without network access.
"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EVALUATOR = ROOT / "benchmarks" / "evaluate.py"
REVIEWS = ROOT / "benchmarks" / "reviews.py"


def _run(*arguments):
    return subprocess.run(
        [sys.executable, *map(str, arguments)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
    )


def _write_json(path: Path, value):
    path.write_bytes((json.dumps(value, indent=2) + "\n").encode("utf-8"))


@pytest.fixture
def inputs(tmp_path):
    snapshot = tmp_path / "snapshot.json"
    snapshot.write_bytes(b'{"kind":"synthetic","project":"synthetic/review-workflow"}\n')
    digest = hashlib.sha256(snapshot.read_bytes()).hexdigest()
    labels = {"schema_version": 1, "cases": []}
    scan = {
        "project": "synthetic/review-workflow",
        "snapshot_sha256": digest,
        "scanned": True,
        "results": [],
    }
    for index, (label, verdict) in enumerate(
        [("retain", "action"), ("filter", "filtered"), ("unknown", "review")]
    ):
        labels["cases"].append(
            {
                "id": f"synthetic-review-case-{index}",
                "project": scan["project"],
                "snapshot_sha256": digest,
                "package": f"synthetic-package-{index}",
                "version": "1.0.0",
                "advisory": f"SYNTHETIC-REVIEW-{index}",
                "label": label,
                "reason": "Invented decision for review-workflow contract testing only.",
                "provenance": {
                    "kind": "synthetic",
                    "source": "this test; no real source or advisory evidence",
                    "reviewer": "synthetic fixture author",
                },
            }
        )
        scan["results"].append(
            {
                "package": f"synthetic-package-{index}",
                "version": "1.0.0",
                "cve": f"SYNTHETIC-REVIEW-{index}",
                "verdict": verdict,
            }
        )
    labels_path = tmp_path / "labels.json"
    scan_path = tmp_path / "scan.json"
    _write_json(labels_path, labels)
    _write_json(scan_path, scan)
    return {
        "snapshot": snapshot,
        "labels": labels,
        "scan": scan,
        "labels_path": labels_path,
        "scan_path": scan_path,
        "reviews_path": tmp_path / "reviews.json",
    }


def _bundle(inputs):
    process = _run(
        REVIEWS,
        "init",
        "--labels",
        inputs["labels_path"],
        "--output",
        inputs["reviews_path"],
    )
    assert process.returncode == 0, process.stdout + process.stderr
    return json.loads(inputs["reviews_path"].read_text(encoding="utf-8"))


def _submit(
    record,
    *,
    decision,
    kind="human",
    relationship="founder",
    actor_id="synthetic-reviewer",
    label_seen=False,
    result_seen=False,
):
    record.update(
        status="submitted",
        actor={"kind": kind, "id": actor_id, "relationship": relationship},
        exposure={"reference_label_seen": label_seen, "depquiet_result_seen": result_seen},
        decision=decision,
        reason="Synthetic review rationale; this is not an actual human adjudication.",
        reviewed_sources=["synthetic://fixture-source"],
        limitations=["No real reviewer, project, installation or deployment was observed."],
        submitted_at="2026-11-09T12:00:00+00:00",
    )


def _all_submitted(inputs, bundle, **kwargs):
    decisions = {case["id"]: case["label"] for case in inputs["labels"]["cases"]}
    for record in bundle["reviews"]:
        _submit(record, decision=decisions[record["case_id"]], **kwargs)


def _evaluate(inputs, bundle=None, *extra):
    _write_json(inputs["scan_path"], inputs["scan"])
    arguments = [
        EVALUATOR,
        "--labels",
        inputs["labels_path"],
        "--scan",
        inputs["scan_path"],
        "--snapshot",
        inputs["snapshot"],
        "--json",
        *extra,
    ]
    if bundle is not None:
        _write_json(inputs["reviews_path"], bundle)
        arguments.extend(["--reviews", inputs["reviews_path"]])
    paths = [inputs[name] for name in ("snapshot", "labels_path", "scan_path", "reviews_path")]
    before = {path: path.read_bytes() for path in paths if path.exists()}
    process = _run(*arguments)
    assert all(path.read_bytes() == content for path, content in before.items())
    assert process.stdout, process.stderr
    return process, json.loads(process.stdout)


def test_absent_reviews_preserve_existing_gate_without_claiming_human_coverage(inputs):
    process, report = _evaluate(inputs)
    assert process.returncode == 0, process.stdout + process.stderr
    assert report["evaluation_basis"] == "proposed_labels"
    assert report["counts"]["correct_dismissals"] == 1
    assert report["counts"]["matched_unique_cases"] == 3
    coverage = report["review_coverage"]
    assert coverage["counts"]["reference_cases"] == 3
    assert coverage["counts"]["pending_cases"] == 3
    assert coverage["counts"]["declared_human_reviewed_cases"] == 0
    assert coverage["coverage"]["denominator"] == 3
    assert coverage["gate"]["declared_human_coverage_complete"] is False
    audit = report["human_review_audit"]
    assert audit["counts"]["matched_unique_human_cases"] == 0
    assert audit["rates"]["dismissals"]["denominator"] == 0
    assert audit["rates"]["dismissals"]["fraction"] is None


def test_reviewed_provenance_and_free_human_flags_do_not_count_as_review_records(inputs):
    for case in inputs["labels"]["cases"]:
        case["provenance"].update(kind="reviewed", human_reviewed=True)
    inputs["labels"]["review_status"] = "human_approved"
    _write_json(inputs["labels_path"], inputs["labels"])
    process, report = _evaluate(inputs)
    assert process.returncode == 0
    assert report["scope"]["reviewed_cases"] == 3
    assert report["review_coverage"]["counts"]["declared_human_reviewed_cases"] == 0


def test_required_human_review_fails_without_records(inputs):
    process, report = _evaluate(inputs, None, "--require-human-review")
    assert process.returncode == 1
    assert "human_review_coverage" in report["gate_failures"]
    assert report["counts"]["false_dismissals"] == 0


def test_valid_pending_bundle_is_not_a_completed_human_review(inputs):
    bundle = _bundle(inputs)
    process, report = _evaluate(inputs, bundle)
    assert process.returncode == 0
    assert report["review_coverage"]["counts"]["pending_records"] == 3
    assert report["review_coverage"]["counts"]["declared_human_reviewed_cases"] == 0
    process, report = _evaluate(inputs, bundle, "--require-human-review")
    assert process.returncode == 1
    assert "human_review_coverage" in report["gate_failures"]


def test_completed_founder_records_satisfy_declared_human_but_not_external_coverage(inputs):
    original = inputs["labels_path"].read_bytes()
    bundle = _bundle(inputs)
    _all_submitted(inputs, bundle)
    process, report = _evaluate(inputs, bundle, "--require-human-review")
    assert process.returncode == 0, process.stdout + process.stderr
    coverage = report["review_coverage"]
    assert coverage["counts"]["declared_human_reviewed_cases"] == 3
    assert coverage["counts"]["declared_external_reviewed_cases"] == 0
    assert coverage["gate"]["declared_human_coverage_complete"] is True
    process, report = _evaluate(inputs, bundle, "--require-unexposed-external-review")
    assert process.returncode == 1
    assert "unexposed_external_review_coverage" in report["gate_failures"]
    assert inputs["labels_path"].read_bytes() == original


@pytest.mark.parametrize(
    ("kind", "relationship", "label_seen", "result_seen"),
    [
        ("agent", "external", False, False),
        ("human", "collaborator", False, False),
        ("human", "external", True, False),
        ("human", "external", False, True),
    ],
)
def test_role_or_exposure_cannot_manufacture_unexposed_external_coverage(
    inputs, kind, relationship, label_seen, result_seen
):
    bundle = _bundle(inputs)
    _all_submitted(
        inputs,
        bundle,
        kind=kind,
        relationship=relationship,
        label_seen=label_seen,
        result_seen=result_seen,
    )
    process, report = _evaluate(inputs, bundle, "--require-unexposed-external-review")
    assert process.returncode == 1
    assert "unexposed_external_review_coverage" in report["gate_failures"]
    assert report["review_coverage"]["counts"]["declared_unexposed_external_cases"] == 0
    assert report["review_coverage"]["counts"]["declared_human_reviewed_cases"] == (
        0 if kind == "agent" else 3
    )


def test_complete_declared_external_records_can_pass_the_explicit_coverage_gate(inputs):
    bundle = _bundle(inputs)
    _all_submitted(inputs, bundle, relationship="external")
    process, report = _evaluate(
        inputs, bundle, "--require-human-review", "--require-unexposed-external-review"
    )
    assert process.returncode == 0, process.stdout + process.stderr
    coverage = report["review_coverage"]
    assert coverage["counts"]["declared_unexposed_external_cases"] == 3
    assert coverage["gate"]["declared_unexposed_external_coverage_complete"] is True
    assert report["evaluation_basis"] == "proposed_labels"


def test_partial_reviews_keep_the_full_reference_denominator(inputs):
    bundle = _bundle(inputs)
    _submit(bundle["reviews"][0], decision="retain", relationship="external")
    process, report = _evaluate(inputs, bundle, "--require-human-review")
    assert process.returncode == 1
    coverage = report["review_coverage"]
    assert coverage["counts"]["reference_cases"] == 3
    assert coverage["counts"]["declared_human_reviewed_cases"] == 1
    assert coverage["counts"]["pending_cases"] == 2
    assert coverage["coverage"]["numerator"] == 1
    assert coverage["coverage"]["denominator"] == 3
    assert coverage["coverage"]["fraction"] == pytest.approx(1 / 3)


def test_disagreement_is_unknown_and_cannot_allow_a_proposed_filter_dismissal(inputs):
    original = inputs["labels_path"].read_bytes()
    bundle = _bundle(inputs)
    _all_submitted(inputs, bundle, relationship="external")
    contrary = copy.deepcopy(bundle["reviews"][1])
    contrary["record_id"] = "synthetic-contrary-review"
    _submit(
        contrary, decision="retain", actor_id="synthetic-second-reviewer", relationship="external"
    )
    bundle["reviews"].append(contrary)
    process, report = _evaluate(inputs, bundle, "--require-human-review")
    assert process.returncode == 1
    assert "human_review_dismissals" in report["gate_failures"]
    assert "human_review_coverage" in report["gate_failures"]
    assert report["counts"]["correct_dismissals"] == 1
    coverage = report["review_coverage"]
    assert coverage["counts"]["disputed_cases"] == 1
    case = next(item for item in coverage["cases"] if item["case_id"] == contrary["case_id"])
    assert case["status"] == "disputed"
    assert case["human_consensus"] == "unknown"
    assert inputs["labels_path"].read_bytes() == original


@pytest.mark.parametrize(
    ("index", "failure"), [(0, "false_dismissals"), (2, "uncertain_dismissals")]
)
def test_human_filter_record_cannot_weaken_a_proposed_retain_or_unknown(inputs, index, failure):
    bundle = _bundle(inputs)
    _submit(bundle["reviews"][index], decision="filter", relationship="external")
    inputs["scan"]["results"][index]["verdict"] = "filtered"
    process, report = _evaluate(inputs, bundle)
    assert process.returncode == 1
    assert failure in report["gate_failures"]
    assert report["counts"][failure] == 1
    assert report["evaluation_basis"] == "proposed_labels"
    assert report["review_coverage"]["counts"]["proposal_disagreements"] == 1


@pytest.mark.parametrize("decision", ["retain", "unknown"])
def test_human_retention_audit_strengthens_the_proposed_filter_gate(inputs, decision):
    bundle = _bundle(inputs)
    _submit(bundle["reviews"][1], decision=decision, relationship="external")
    process, report = _evaluate(inputs, bundle)
    assert process.returncode == 1
    assert report["counts"]["correct_dismissals"] == 1
    assert "human_review_dismissals" in report["gate_failures"]
    audit = report["human_review_audit"]
    assert audit["counts"]["matched_unique_human_cases"] == 1
    assert audit["counts"]["matched_retention_or_unknown_cases"] == 1
    assert audit["rates"]["dismissals"]["numerator"] == 1
    assert audit["rates"]["dismissals"]["denominator"] == 1
    assert audit["rates"]["dismissals"]["fraction"] == 1
    assert len(audit["details"]["dismissals"]) == 1


def test_human_filter_consensus_is_not_the_denominator_for_retention_safety(inputs):
    bundle = _bundle(inputs)
    _submit(bundle["reviews"][1], decision="filter", relationship="external")
    process, report = _evaluate(inputs, bundle)
    assert process.returncode == 0
    audit = report["human_review_audit"]
    assert audit["counts"]["matched_unique_human_cases"] == 1
    assert audit["counts"]["matched_retention_or_unknown_cases"] == 0
    assert audit["rates"]["dismissals"]["denominator"] == 0
    assert audit["rates"]["dismissals"]["fraction"] is None


@pytest.mark.parametrize("problem", ["missing", "duplicate"])
def test_absent_or_ambiguous_scan_rows_are_not_scored_against_human_decisions(inputs, problem):
    bundle = _bundle(inputs)
    _submit(bundle["reviews"][0], decision="retain", relationship="external")
    if problem == "missing":
        inputs["scan"]["results"].pop(0)
    else:
        inputs["scan"]["results"].append(copy.deepcopy(inputs["scan"]["results"][0]))
    process, report = _evaluate(inputs, bundle)
    assert process.returncode == 1
    assert ("missing_cases" if problem == "missing" else "duplicate_results") in report[
        "gate_failures"
    ]
    assert report["review_coverage"]["counts"]["declared_human_reviewed_cases"] == 1
    assert report["human_review_audit"]["counts"]["matched_unique_human_cases"] == 0
    assert report["human_review_audit"]["rates"]["dismissals"]["denominator"] == 0
    assert report["human_review_audit"]["rates"]["dismissals"]["fraction"] is None


@pytest.mark.parametrize(
    "problem", ["project", "snapshot", "identity", "missing_submission_reason"]
)
def test_foreign_or_incomplete_submissions_are_invalid_inputs(inputs, problem):
    bundle = _bundle(inputs)
    record = bundle["reviews"][0]
    if problem == "project":
        record["project"] = "synthetic/another-project"
    elif problem == "snapshot":
        record["snapshot_sha256"] = "0" * 64
    elif problem == "identity":
        record["version"] = "2.0.0"
    else:
        _submit(record, decision="retain")
        record["reason"] = ""
    process, report = _evaluate(inputs, bundle)
    assert process.returncode == 2
    assert report["status"] == "invalid"
    assert report["error"]


def test_changed_label_file_bytes_invalidate_existing_review_bindings(inputs):
    bundle = _bundle(inputs)
    inputs["labels_path"].write_bytes(inputs["labels_path"].read_bytes() + b" \n")
    process, report = _evaluate(inputs, bundle)
    assert process.returncode == 2
    assert report["status"] == "invalid"


@pytest.mark.parametrize("problem", ["duplicate_json_key", "nonfinite_constant"])
def test_review_json_is_strict_before_evaluation(inputs, problem):
    bundle = _bundle(inputs)
    raw = json.dumps(bundle)
    if problem == "duplicate_json_key":
        raw = raw.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1', 1)
    else:
        raw = raw[:-1] + ', "synthetic_invalid_number": NaN}'
    inputs["reviews_path"].write_text(raw, encoding="utf-8")
    process = _run(
        EVALUATOR,
        "--labels",
        inputs["labels_path"],
        "--scan",
        inputs["scan_path"],
        "--reviews",
        inputs["reviews_path"],
        "--json",
    )
    assert process.returncode == 2
    assert json.loads(process.stdout)["status"] == "invalid"


def test_missing_review_file_is_an_invalid_input_not_missing_coverage(inputs):
    process = _run(
        EVALUATOR,
        "--labels",
        inputs["labels_path"],
        "--scan",
        inputs["scan_path"],
        "--reviews",
        inputs["reviews_path"],
        "--json",
    )
    assert process.returncode == 2
    assert json.loads(process.stdout)["status"] == "invalid"
