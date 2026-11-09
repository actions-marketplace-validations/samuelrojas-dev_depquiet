"""Review declarations cannot become unaudited human-validation claims."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from benchmarks.reviews import (
    InvalidReviewInput,
    create_review_bundle,
    main,
    read_document,
    summarize_reviews,
)

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "benchmarks" / "reviews.py"


@pytest.fixture
def inputs(tmp_path):
    labels = {
        "schema_version": 1,
        "cases": [
            {
                "id": f"case-{index}",
                "project": "synthetic/review-contract",
                "snapshot_sha256": "a" * 64,
                "package": f"fixture-{index}",
                "version": "1.0",
                "advisory": f"SYNTHETIC-{index}",
                "label": label,
                "reason": "Invented review-record test, not a real human decision.",
                "provenance": {"kind": "synthetic", "source": "test", "reviewer": "test author"},
            }
            for index, label in enumerate(("retain", "filter", "unknown"))
        ],
    }
    path = tmp_path / "labels.json"
    path.write_text(json.dumps(labels, indent=2) + "\n", encoding="utf-8")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return labels, digest, path, tmp_path / "reviews.json"


def _submitted(
    record,
    *,
    actor="synthetic-human",
    kind="human",
    relationship="external",
    decision="retain",
    exposed=False,
):
    record = copy.deepcopy(record)
    record.update(
        status="submitted",
        decision=decision,
        reason="Invented assertion to exercise the contract; not human adjudication.",
        reviewed_sources=["synthetic://review-test/source"],
        limitations=[],
        submitted_at="2026-11-09T10:00:00+00:00",
    )
    record["actor"] = {"kind": kind, "id": actor, "relationship": relationship}
    record["exposure"] = {"reference_label_seen": exposed, "depquiet_result_seen": exposed}
    return record


def _bundle(inputs, *, submitted=False, **kwargs):
    labels, digest, _, _ = inputs
    bundle = create_review_bundle(labels, labels_sha256=digest)
    if submitted:
        bundle["reviews"] = [_submitted(record, **kwargs) for record in bundle["reviews"]]
    return bundle


def _summary(inputs, bundle):
    return summarize_reviews(inputs[0], bundle, labels_sha256=inputs[1])


def _write_reviews(inputs, bundle):
    inputs[3].write_text(json.dumps(bundle), encoding="utf-8")


def test_no_review_records_means_no_humans_even_with_freeform_label_claims(inputs):
    labels = copy.deepcopy(inputs[0])
    for case in labels["cases"]:
        case["provenance"].update(kind="reviewed", human_reviewed=True)
    labels["review_status"] = "human_approved"
    summary = summarize_reviews(labels, None)
    assert summary["counts"]["pending_cases"] == 3
    assert summary["counts"]["declared_human_reviewed_cases"] == 0
    assert summary["coverage"] == {"numerator": 0, "denominator": 3, "fraction": 0.0}
    assert not any(summary["gate"].values())
    assert {case["human_consensus"] for case in summary["cases"]} == {None}


def test_pending_bundle_binds_exact_case_and_does_not_invent_people(inputs):
    before = copy.deepcopy(inputs[0])
    bundle = _bundle(inputs)
    assert inputs[0] == before
    assert bundle["labels_sha256"] == inputs[1]
    for record, case in zip(bundle["reviews"], inputs[0]["cases"], strict=True):
        raw = json.dumps(
            case, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("utf-8")
        assert record["case_sha256"] == hashlib.sha256(raw).hexdigest()
        assert record["actor"]["id"] is None
        assert record["decision"] is record["submitted_at"] is None
    summary = _summary(inputs, bundle)
    assert summary["counts"]["pending_records"] == 3
    assert summary["counts"]["pending_cases"] == 3
    assert all(case["status"] == "pending" for case in summary["cases"])


def test_empty_bundle_and_assigned_pending_actor_do_not_reduce_pending_cases(inputs):
    bundle = _bundle(inputs)
    bundle["reviews"][0]["actor"].update(id="founder-rehearsal", relationship="founder")
    assert _summary(inputs, bundle)["counts"]["pending_cases"] == 3
    bundle["reviews"] = []
    summary = _summary(inputs, bundle)
    assert summary["counts"]["pending_records"] == 0
    assert summary["counts"]["pending_cases"] == 3
    assert summary["coverage"]["denominator"] == 3


def test_declared_humans_can_complete_coverage_without_overwriting_proposals(inputs):
    bundle = _bundle(inputs, submitted=True, decision="filter")
    before = copy.deepcopy(inputs[0])
    summary = _summary(inputs, bundle)
    assert summary["counts"]["declared_human_reviewed_cases"] == 3
    assert summary["counts"]["declared_external_reviewed_cases"] == 3
    assert summary["counts"]["declared_unexposed_external_cases"] == 3
    assert summary["counts"]["proposal_disagreements"] == 2
    assert summary["coverage"]["fraction"] == 1.0
    assert all(summary["gate"].values())
    assert inputs[0] == before
    assert "not authenticated" in summary["interpretation"]


def test_submitted_unknown_is_a_completed_review_not_a_nonaffectedness_claim(inputs):
    summary = _summary(inputs, _bundle(inputs, submitted=True, decision="unknown"))
    assert summary["gate"]["declared_human_coverage_complete"]
    assert all(case["human_consensus"] == "unknown" for case in summary["cases"])
    assert summary["counts"]["pending_cases"] == 0


def test_agent_records_never_satisfy_human_or_external_coverage(inputs):
    summary = _summary(inputs, _bundle(inputs, submitted=True, actor="agent-test", kind="agent"))
    assert summary["counts"]["submitted_agent_records"] == 3
    assert summary["counts"]["agent_reviewed_cases"] == 3
    assert summary["counts"]["declared_human_reviewed_cases"] == 0
    assert summary["counts"]["declared_external_reviewed_cases"] == 0
    assert summary["counts"]["pending_cases"] == 3
    assert not any(summary["gate"].values())


@pytest.mark.parametrize("relationship", ["founder", "collaborator", "unknown"])
def test_relationships_do_not_implicitly_become_external(inputs, relationship):
    summary = _summary(inputs, _bundle(inputs, submitted=True, relationship=relationship))
    assert summary["gate"]["declared_human_coverage_complete"]
    assert not summary["gate"]["declared_unexposed_external_coverage_complete"]


@pytest.mark.parametrize("field", ["reference_label_seen", "depquiet_result_seen"])
def test_one_declared_exposure_prevents_unexposed_external_gate(inputs, field):
    bundle = _bundle(inputs, submitted=True)
    bundle["reviews"][0]["exposure"][field] = True
    summary = _summary(inputs, bundle)
    assert summary["counts"]["declared_external_reviewed_cases"] == 3
    assert summary["counts"]["declared_unexposed_external_cases"] == 2
    assert not summary["gate"]["declared_unexposed_external_coverage_complete"]


def test_human_dispute_is_unknown_and_latest_timestamp_cannot_win(inputs):
    bundle = _bundle(inputs, submitted=True)
    alternative = _submitted(
        bundle["reviews"][0], actor="another-declared-human", decision="filter"
    )
    alternative.update(record_id="another-vote", submitted_at="2030-01-01T00:00:00Z")
    bundle["reviews"].append(alternative)
    summary = _summary(inputs, bundle)
    assert summary["coverage"]["fraction"] == 1.0
    assert summary["counts"]["disputed_cases"] == 1
    assert summary["counts"]["proposal_disagreements"] == 3
    assert not any(summary["gate"].values())
    first = summary["cases"][0]
    assert first["status"] == "disputed" and first["human_consensus"] == "unknown"
    assert len(first["human_reviewer_ids"]) == 2


def test_agent_disagreement_is_separate_from_human_consensus(inputs):
    bundle = _bundle(inputs, submitted=True)
    agent = _submitted(bundle["reviews"][0], actor="agent-1", kind="agent", decision="filter")
    agent["record_id"] = "agent-vote"
    bundle["reviews"].append(agent)
    summary = _summary(inputs, bundle)
    assert summary["counts"]["disputed_cases"] == 0
    assert summary["cases"][0]["human_consensus"] == "retain"
    assert summary["cases"][0]["agent_reviewer_ids"] == ["agent-1"]


@pytest.mark.parametrize(
    "field", ["project", "snapshot_sha256", "package", "version", "advisory", "case_sha256"]
)
def test_records_cannot_move_to_a_different_context(inputs, field):
    bundle = _bundle(inputs)
    bundle["reviews"][0][field] = "b" * 64 if field.endswith("sha256") else "foreign"
    with pytest.raises(InvalidReviewInput, match="conflicts"):
        _summary(inputs, bundle)


def test_stale_case_evidence_is_rejected_even_if_caller_passes_old_outer_hash(inputs):
    bundle = _bundle(inputs)
    inputs[0]["cases"][0]["reason"] = "Modified reference rationale"
    with pytest.raises(InvalidReviewInput, match="case_sha256"):
        _summary(inputs, bundle)


@pytest.mark.parametrize("digest", [None, "", "x", "b" * 64])
def test_present_bundle_requires_actual_matching_labels_hash(inputs, digest):
    with pytest.raises(InvalidReviewInput):
        summarize_reviews(inputs[0], _bundle(inputs), labels_sha256=digest)


def test_legacy_cases_without_ids_have_stable_context_ids(inputs):
    labels = copy.deepcopy(inputs[0])
    for case in labels["cases"]:
        del case["id"]
    one = create_review_bundle(labels, labels_sha256=inputs[1])
    two = create_review_bundle(labels, labels_sha256=inputs[1])
    assert one == two
    assert len({record["case_id"] for record in one["reviews"]}) == 3
    assert one["reviews"][0]["case_id"].startswith("case-sha256:")


@pytest.mark.parametrize("duplicate", ["id", "identity"])
def test_duplicate_reference_cases_cannot_inflate_denominator(inputs, duplicate):
    labels = copy.deepcopy(inputs[0])
    if duplicate == "id":
        labels["cases"][1]["id"] = labels["cases"][0]["id"]
    else:
        labels["cases"][1] = {**labels["cases"][0], "id": "different-id"}
    with pytest.raises(InvalidReviewInput, match="duplicate"):
        create_review_bundle(labels, labels_sha256=inputs[1])


def test_duplicate_records_are_rejected_even_for_pending_people(inputs):
    bundle = _bundle(inputs)
    bundle["reviews"].append(copy.deepcopy(bundle["reviews"][0]))
    with pytest.raises(InvalidReviewInput, match="duplicate"):
        _summary(inputs, bundle)


def test_one_reviewer_cannot_cast_two_votes_for_a_case(inputs):
    bundle = _bundle(inputs, submitted=True)
    duplicate = {**bundle["reviews"][0], "record_id": "another-record-id"}
    bundle["reviews"].append(duplicate)
    with pytest.raises(InvalidReviewInput, match="same reviewer"):
        _summary(inputs, bundle)


@pytest.mark.parametrize("field,value", [("kind", "agent"), ("relationship", "founder")])
def test_reviewer_id_cannot_change_identity_between_cases(inputs, field, value):
    bundle = _bundle(inputs, submitted=True)
    bundle["reviews"][1]["actor"][field] = value
    with pytest.raises(InvalidReviewInput, match="contradictory"):
        _summary(inputs, bundle)


@pytest.mark.parametrize(
    "field,value",
    [
        ("decision", "retain"),
        ("submitted_at", "2026-11-09T10:00:00Z"),
        ("reason", "Already judged"),
        ("reviewed_sources", ["somewhere"]),
        ("limitations", ["draft analysis"]),
    ],
)
def test_pending_cannot_hide_a_completed_decision(inputs, field, value):
    bundle = _bundle(inputs)
    bundle["reviews"][0][field] = value
    with pytest.raises(InvalidReviewInput, match="pending"):
        _summary(inputs, bundle)


@pytest.mark.parametrize(
    "field,value",
    [
        ("decision", None),
        ("decision", []),
        ("reason", ""),
        ("reviewed_sources", []),
        ("reviewed_sources", [""]),
        ("submitted_at", "2026-11-09"),
        ("submitted_at", "2026-11-09T10:00:00"),
        ("submitted_at", "not-a-date"),
    ],
)
def test_submitted_requires_a_complete_review_record(inputs, field, value):
    bundle = _bundle(inputs, submitted=True)
    bundle["reviews"][0][field] = value
    with pytest.raises(InvalidReviewInput):
        _summary(inputs, bundle)


@pytest.mark.parametrize(
    "part,field,value",
    [
        ("actor", "id", None),
        ("actor", "id", " user "),
        ("actor", "kind", []),
        ("actor", "relationship", []),
        ("exposure", "reference_label_seen", None),
        ("exposure", "depquiet_result_seen", "false"),
    ],
)
def test_truthy_or_missing_actor_exposure_values_are_not_accepted(inputs, part, field, value):
    bundle = _bundle(inputs, submitted=True)
    bundle["reviews"][0][part][field] = value
    with pytest.raises(InvalidReviewInput):
        _summary(inputs, bundle)


@pytest.mark.parametrize(
    "mutation", ["case", "record-fields", "bundle-fields", "schema", "purpose", "records"]
)
def test_foreign_or_unsupported_structures_fail_closed(inputs, mutation):
    bundle = _bundle(inputs)
    if mutation == "case":
        bundle["reviews"][0]["case_id"] = "not-a-reference-case"
    elif mutation == "record-fields":
        bundle["reviews"][0]["human_reviewed"] = True
    elif mutation == "bundle-fields":
        bundle["human_approved"] = True
    elif mutation == "schema":
        bundle["schema_version"] = True
    elif mutation == "purpose":
        bundle["purpose"] = "human_approved"
    else:
        bundle["reviews"] = {}
    with pytest.raises(InvalidReviewInput):
        _summary(inputs, bundle)


def test_cli_init_then_check_reports_pending_and_separate_requirements(inputs, capsys):
    labels, _, path, reviews = inputs
    assert main(["init", "--labels", str(path), "--output", str(reviews)]) == 0
    output = capsys.readouterr()
    assert output.out == "" and "3 pending" in output.err
    args = ["check", "--labels", str(path), "--reviews", str(reviews), "--json"]
    assert main(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["counts"]["pending_cases"] == len(labels["cases"])
    assert main([*args, "--require-human-review"]) == 1
    assert json.loads(capsys.readouterr().out)["coverage"]["numerator"] == 0
    assert main([*args, "--require-unexposed-external-review"]) == 1


def test_cli_external_gate_requires_unexposed_humans(inputs, capsys):
    _write_reviews(inputs, _bundle(inputs, submitted=True, exposed=True))
    args = ["check", "--labels", str(inputs[2]), "--reviews", str(inputs[3]), "--json"]
    assert main([*args, "--require-human-review"]) == 0
    capsys.readouterr()
    assert main([*args, "--require-unexposed-external-review"]) == 1
    capsys.readouterr()
    _write_reviews(inputs, _bundle(inputs, submitted=True))
    assert main([*args, "--require-unexposed-external-review"]) == 0


def test_cli_strict_json_rejects_duplicates_and_nonfinite(inputs):
    for raw in (b'{"schema_version":1,"schema_version":1}', b'{"value":NaN}'):
        inputs[3].write_bytes(raw)
        process = subprocess.run(
            [
                sys.executable,
                str(CLI),
                "check",
                "--labels",
                str(inputs[2]),
                "--reviews",
                str(inputs[3]),
                "--json",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=15,
        )
        assert process.returncode == 2
        assert json.loads(process.stdout)["status"] == "invalid"


def test_raw_labels_whitespace_change_invalidates_bundle(inputs, capsys):
    _write_reviews(inputs, _bundle(inputs))
    inputs[2].write_bytes(inputs[2].read_bytes() + b" ")
    assert main(["check", "--labels", str(inputs[2]), "--reviews", str(inputs[3]), "--json"]) == 2
    assert "labels hash" in json.loads(capsys.readouterr().out)["error"]


@pytest.mark.parametrize("target", ["source", "existing"])
def test_init_does_not_overwrite_source_or_existing_destination(inputs, target, capsys):
    destination = inputs[2] if target == "source" else inputs[3]
    if target == "existing":
        destination.write_bytes(b"existing review record")
    before = destination.read_bytes()
    assert main(["init", "--labels", str(inputs[2]), "--output", str(destination)]) == 2
    assert capsys.readouterr().out == ""
    assert destination.read_bytes() == before
    assert list(destination.parent.glob(".depquiet-reviews-*.tmp")) == []


def test_failed_atomic_publish_does_not_leave_partial_output(inputs, monkeypatch, capsys):
    def denied(*args, **kwargs):
        raise PermissionError("synthetic publish failure")

    monkeypatch.setattr("benchmarks.reviews.os.link", denied)
    assert main(["init", "--labels", str(inputs[2]), "--output", str(inputs[3])]) == 2
    assert capsys.readouterr().out == ""
    assert not inputs[3].exists()
    assert list(inputs[3].parent.glob(".depquiet-reviews-*.tmp")) == []


def test_strict_reader_hashes_original_bytes_once(inputs, monkeypatch):
    original = Path.read_bytes
    reads = []

    def read(path):
        reads.append(path)
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", read)
    labels, digest = read_document(inputs[2])
    assert labels == inputs[0] and digest == inputs[1]
    assert reads == [inputs[2]]


@pytest.mark.parametrize("raw", [b"\xffnot-utf8", '{"schema_version":1}'.encode("utf-16")])
def test_review_reader_requires_utf8_like_the_evaluator(inputs, raw):
    inputs[3].write_bytes(raw)
    with pytest.raises(UnicodeError):
        read_document(inputs[3])
