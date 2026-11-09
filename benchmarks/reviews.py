"""Offline, hash-bound declarations of reference-case reviews.

Records describe who a caller says reviewed a case. They do not authenticate
people, establish independence or rewrite proposed reference labels.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

LABELS = {"retain", "filter", "unknown"}
IDENTITY = ("project", "snapshot_sha256", "package", "version", "advisory")
PURPOSE = "depquiet_reference_reviews"
_RECORD_FIELDS = {
    "record_id",
    "case_id",
    *IDENTITY,
    "case_sha256",
    "status",
    "actor",
    "exposure",
    "decision",
    "reason",
    "reviewed_sources",
    "limitations",
    "submitted_at",
}
INTERPRETATION = (
    "Coverage of caller-declared review records only. Human identity, external relationship and "
    "prior exposure are not authenticated. Proposed labels remain unchanged; these counts are "
    "not independent validation, product affectedness or real-world accuracy estimates."
)


class InvalidReviewInput(ValueError):
    """Review records are malformed, ambiguous or bound to different input."""


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InvalidReviewInput(f"{name} must be an object")
    return value


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidReviewInput(f"{name} must be a nonempty string")
    return value


def _identifier(value: Any, name: str) -> str:
    text = _text(value, name)
    if text != text.strip() or any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise InvalidReviewInput(f"{name} must not contain surrounding whitespace or controls")
    return text


def _choice(value: Any, allowed: set[str], name: str) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise InvalidReviewInput(f"{name} is unsupported")


def _hash(value: Any, name: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
        raise InvalidReviewInput(f"{name} must be a SHA-256 digest")
    return value.lower()


def _fields(value: dict[str, Any], required: set[str], name: str) -> None:
    if set(value) != required:
        raise InvalidReviewInput(f"{name} has missing or unsupported fields")


def _canonical_hash(value: Any) -> str:
    try:
        raw = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("utf-8")
    except (ValueError, TypeError, UnicodeError) as exc:
        raise InvalidReviewInput(
            f"case cannot be represented as finite canonical JSON: {exc}"
        ) from exc
    return hashlib.sha256(raw).hexdigest()


def read_document(path: Path) -> tuple[dict[str, Any], str]:
    """Parse strict JSON and hash the same single byte snapshot."""
    raw = path.read_bytes()

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise InvalidReviewInput(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def nonfinite(value: str) -> Any:
        raise InvalidReviewInput(f"non-finite JSON constant: {value}")

    document = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=nonfinite)
    return _object(document, str(path)), hashlib.sha256(raw).hexdigest()


def _cases(labels: dict[str, Any]) -> dict[str, dict[str, Any]]:
    labels = _object(labels, "labels")
    if type(labels.get("schema_version")) is not int or labels["schema_version"] != 1:
        raise InvalidReviewInput("labels.schema_version must be 1")
    cases = labels.get("cases")
    if not isinstance(cases, list) or not cases:
        raise InvalidReviewInput("labels.cases must be a nonempty array")
    result = {}
    identities: set[tuple[str, ...]] = set()
    for raw in cases:
        case = _object(raw, "case")
        identity = {name: _text(case.get(name), f"case.{name}") for name in IDENTITY}
        identity["snapshot_sha256"] = _hash(identity["snapshot_sha256"], "case.snapshot_sha256")
        _choice(case.get("label"), LABELS, "case.label")
        _text(case.get("reason"), "case.reason")
        case_id = (
            _identifier(case["id"], "case.id")
            if "id" in case
            else "case-sha256:" + _canonical_hash(identity)
        )
        key = tuple(identity[name] for name in IDENTITY)
        if case_id in result or key in identities:
            raise InvalidReviewInput("duplicate case ID or reference identity")
        identities.add(key)
        result[case_id] = {
            "case_id": case_id,
            **identity,
            "case_sha256": _canonical_hash(case),
            "proposed_label": case["label"],
        }
    return result


def create_review_bundle(labels: dict[str, Any], *, labels_sha256: str) -> dict[str, Any]:
    """Prepare pending forms; no person or completed review is invented."""
    digest = _hash(labels_sha256, "labels_sha256")
    reviews = []
    for case in _cases(labels).values():
        binding = {key: value for key, value in case.items() if key != "proposed_label"}
        reviews.append(
            {
                "record_id": "review-sha256:"
                + _canonical_hash({**binding, "labels_sha256": digest}),
                **binding,
                "status": "pending",
                "actor": {"kind": "human", "id": None, "relationship": "unknown"},
                "exposure": {"reference_label_seen": None, "depquiet_result_seen": None},
                "decision": None,
                "reason": "",
                "reviewed_sources": [],
                "limitations": [],
                "submitted_at": None,
            }
        )
    return {"schema_version": 1, "purpose": PURPOSE, "labels_sha256": digest, "reviews": reviews}


def _strings(value: Any, name: str, *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value):
        raise InvalidReviewInput(f"{name} must be {'a nonempty' if nonempty else 'an'} array")
    return [_text(item, name) for item in value]


def _record(raw: Any, cases: dict[str, dict[str, Any]]) -> dict[str, Any]:
    record = _object(raw, "review")
    _fields(record, _RECORD_FIELDS, "review")
    _identifier(record["record_id"], "review.record_id")
    case_id = _identifier(record["case_id"], "review.case_id")
    if case_id not in cases:
        raise InvalidReviewInput("review refers to a foreign case ID")
    expected = cases[case_id]
    for name in (*IDENTITY, "case_sha256"):
        actual = record[name]
        if name.endswith("sha256"):
            actual = _hash(actual, f"review.{name}")
        if actual != expected[name]:
            raise InvalidReviewInput(f"review.{name} conflicts with its bound reference case")
    actor = _object(record["actor"], "review.actor")
    _fields(actor, {"kind", "id", "relationship"}, "review.actor")
    _choice(actor["kind"], {"human", "agent"}, "review.actor.kind")
    _choice(
        actor["relationship"],
        {"founder", "collaborator", "external", "unknown"},
        "review.actor.relationship",
    )
    if actor["id"] is not None:
        _identifier(actor["id"], "review.actor.id")
    exposure = _object(record["exposure"], "review.exposure")
    _fields(exposure, {"reference_label_seen", "depquiet_result_seen"}, "review.exposure")
    if any(value is not None and type(value) is not bool for value in exposure.values()):
        raise InvalidReviewInput("exposure values must be boolean or null")
    _strings(record["limitations"], "review.limitations")
    status = record["status"]
    if status == "pending":
        if (
            record["decision"] is not None
            or record["submitted_at"] is not None
            or record["reason"] != ""
            or record["reviewed_sources"] != []
            or record["limitations"] != []
        ):
            raise InvalidReviewInput(
                "pending review must not contain a completed decision or evidence"
            )
    elif status == "submitted":
        _identifier(actor["id"], "submitted actor.id")
        _choice(record["decision"], LABELS, "submitted decision")
        _text(record["reason"], "submitted reason")
        _strings(record["reviewed_sources"], "submitted reviewed_sources", nonempty=True)
        if any(type(value) is not bool for value in exposure.values()):
            raise InvalidReviewInput("submitted exposure values must be boolean")
        try:
            moment = datetime.fromisoformat(_text(record["submitted_at"], "submitted_at"))
            if moment.tzinfo is None or moment.utcoffset() is None:
                raise ValueError("timezone is required")
        except ValueError as exc:
            raise InvalidReviewInput(
                f"submitted_at must be a timezone-aware ISO timestamp: {exc}"
            ) from exc
    else:
        raise InvalidReviewInput("review.status must be pending or submitted")
    return record


def summarize_reviews(
    labels: dict[str, Any], bundle: dict[str, Any] | None, *, labels_sha256: str | None = None
) -> dict[str, Any]:
    """Summarize declared reviews without modifying proposal labels or their gate."""
    cases = _cases(labels)
    records: list[dict[str, Any]] = []
    if bundle is not None:
        bundle = _object(bundle, "reviews bundle")
        _fields(bundle, {"schema_version", "purpose", "labels_sha256", "reviews"}, "reviews bundle")
        if type(bundle["schema_version"]) is not int or bundle["schema_version"] != 1:
            raise InvalidReviewInput("reviews.schema_version must be 1")
        if bundle["purpose"] != PURPOSE:
            raise InvalidReviewInput("unsupported reviews purpose")
        digest = _hash(labels_sha256, "actual labels_sha256")
        if _hash(bundle["labels_sha256"], "reviews.labels_sha256") != digest:
            raise InvalidReviewInput("reviews labels hash conflicts with the supplied labels bytes")
        if not isinstance(bundle["reviews"], list):
            raise InvalidReviewInput("reviews must be an array")
        records = [_record(raw, cases) for raw in bundle["reviews"]]
    ids: set[str] = set()
    actor_signatures: dict[str, tuple[str, str]] = {}
    actor_cases: set[tuple[str, str]] = set()
    by_case: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        if record["record_id"] in ids:
            raise InvalidReviewInput("duplicate review record_id")
        ids.add(record["record_id"])
        actor = record["actor"]
        if actor["id"] is not None:
            signature = actor["kind"], actor["relationship"]
            if actor["id"] in actor_signatures and actor_signatures[actor["id"]] != signature:
                raise InvalidReviewInput("reviewer identity has contradictory kind or relationship")
            actor_signatures[actor["id"]] = signature
            actor_case = actor["id"], record["case_id"]
            if actor_case in actor_cases:
                raise InvalidReviewInput("same reviewer appears more than once for a case")
            actor_cases.add(actor_case)
        by_case[record["case_id"]].append(record)
    details = []
    counts = dict.fromkeys(
        (
            "reference_cases",
            "pending_cases",
            "declared_human_reviewed_cases",
            "declared_external_reviewed_cases",
            "declared_unexposed_external_cases",
            "agent_reviewed_cases",
            "disputed_cases",
            "proposal_disagreements",
            "pending_records",
            "submitted_human_records",
            "submitted_agent_records",
        ),
        0,
    )
    counts["reference_cases"] = len(cases)
    for case_id, case in cases.items():
        selected = by_case[case_id]
        humans = [
            r for r in selected if r["status"] == "submitted" and r["actor"]["kind"] == "human"
        ]
        agents = [
            r for r in selected if r["status"] == "submitted" and r["actor"]["kind"] == "agent"
        ]
        external = [r for r in humans if r["actor"]["relationship"] == "external"]
        unexposed = [r for r in external if not any(r["exposure"].values())]
        decisions = {r["decision"] for r in humans}
        disputed = len(decisions) > 1
        disagreement = any(r["decision"] != case["proposed_label"] for r in humans)
        counts["pending_cases"] += not humans
        counts["declared_human_reviewed_cases"] += bool(humans)
        counts["declared_external_reviewed_cases"] += bool(external)
        counts["declared_unexposed_external_cases"] += bool(unexposed)
        counts["agent_reviewed_cases"] += bool(agents)
        counts["disputed_cases"] += disputed
        counts["proposal_disagreements"] += disagreement
        counts["pending_records"] += sum(r["status"] == "pending" for r in selected)
        counts["submitted_human_records"] += len(humans)
        counts["submitted_agent_records"] += len(agents)
        details.append(
            {
                **{key: value for key, value in case.items() if key != "case_sha256"},
                "status": "disputed" if disputed else "human_reviewed" if humans else "pending",
                "human_consensus": "unknown" if disputed else next(iter(decisions), None),
                "human_reviewer_ids": sorted(r["actor"]["id"] for r in humans),
                "declared_external_reviewer_ids": sorted(r["actor"]["id"] for r in external),
                "agent_reviewer_ids": sorted(r["actor"]["id"] for r in agents),
                "matched_review_ids": sorted(r["record_id"] for r in selected),
                "proposal_disagreement": disagreement,
            }
        )
    return {
        "schema_version": 1,
        "interpretation": INTERPRETATION,
        "counts": counts,
        "coverage": {
            "numerator": counts["declared_human_reviewed_cases"],
            "denominator": len(cases),
            "fraction": counts["declared_human_reviewed_cases"] / len(cases),
        },
        "cases": details,
        "gate": {
            "declared_human_coverage_complete": not counts["pending_cases"]
            and not counts["disputed_cases"],
            "declared_unexposed_external_coverage_complete": (
                counts["declared_unexposed_external_cases"] == len(cases)
                and not counts["disputed_cases"]
            ),
        },
    }


def _write_new(path: Path, text: str) -> None:
    """Publish a complete same-directory file atomically, refusing replacement."""
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=".depquiet-reviews-",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(text)
        os.link(temporary, path)  # atomic create-if-absent, including concurrent creators
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Create pending review forms without overwriting files")
    init.add_argument("--labels", type=Path, required=True)
    init.add_argument("--output", type=Path, required=True)
    check = commands.add_parser(
        "check", help="Validate declared review records and report coverage"
    )
    check.add_argument("--labels", type=Path, required=True)
    check.add_argument("--reviews", type=Path, required=True)
    check.add_argument("--json", action="store_true", dest="json_output")
    check.add_argument("--require-human-review", action="store_true")
    check.add_argument("--require-unexposed-external-review", action="store_true")
    args = parser.parse_args(argv)
    try:
        labels, digest = read_document(args.labels)
        if args.command == "init":
            if args.labels.resolve() == args.output.resolve():
                raise InvalidReviewInput("review output must differ from source labels")
            bundle = create_review_bundle(labels, labels_sha256=digest)
            _write_new(
                args.output, json.dumps(bundle, indent=2, sort_keys=True, allow_nan=False) + "\n"
            )
            print(f"Prepared {len(bundle['reviews'])} pending review records.", file=sys.stderr)
            return 0
        bundle, _ = read_document(args.reviews)
        summary = summarize_reviews(labels, bundle, labels_sha256=digest)
        if args.json_output:
            print(json.dumps(summary, indent=2, sort_keys=True, allow_nan=False))
        else:
            print(INTERPRETATION)
            print(f"Declared human coverage: {summary['coverage']}")
            print(f"Counts: {summary['counts']}")
        failures = (
            args.require_human_review and not summary["gate"]["declared_human_coverage_complete"]
        ) or (
            args.require_unexposed_external_review
            and not summary["gate"]["declared_unexposed_external_coverage_complete"]
        )
        return 1 if failures else 0
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        if getattr(args, "json_output", False):
            print(json.dumps({"schema_version": 1, "status": "invalid", "error": str(exc)}))
        else:
            print(f"Invalid review input: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
