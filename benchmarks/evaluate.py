"""Evaluate versioned reference labels against one depquiet JSON report.

This checks an explicitly labelled sample, not real-world precision or recall.
It uses only the standard library and never runs scanners or accesses the network.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

if __package__:
    from .reviews import summarize_reviews
else:
    from reviews import summarize_reviews

LABELS = {"retain", "filter", "unknown"}
VERDICTS = {"action", "review", "filtered"}
IDENTITY = ("package", "version", "advisory")


class InvalidInput(ValueError):
    """The inputs do not identify an unambiguous evaluation."""


def _object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InvalidInput(f"{context} must be an object")
    return value


def _text(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidInput(f"{context} must be a non-empty string")
    return value


def _hash(value: Any, context: str) -> str:
    text = _text(value, context)
    if re.fullmatch(r"[0-9a-fA-F]{64}", text) is None:
        raise InvalidInput(f"{context} must be a SHA-256 hex digest")
    return text.lower()


def _parse(raw: bytes, path: Path) -> dict[str, Any]:
    def unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise InvalidInput(f"duplicate JSON key in {path}: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> Any:
        raise InvalidInput(f"non-finite JSON constant in {path}: {value}")

    return _object(
        json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_keys,
            parse_constant=reject_constant,
        ),
        str(path),
    )


def _read(path: Path) -> dict[str, Any]:
    return _parse(path.read_bytes(), path)


def evaluate(
    labels: dict[str, Any],
    scan: dict[str, Any],
    *,
    snapshot_sha256: str | None = None,
    project: str | None = None,
    reviews: dict[str, Any] | None = None,
    labels_sha256: str | None = None,
    require_human_review: bool = False,
    require_unexposed_external_review: bool = False,
) -> dict[str, Any]:
    """Return counts, explicit denominators and a conservative safety gate.

    ``snapshot_sha256`` must be calculated from a supplied snapshot's bytes by
    the caller. With no snapshot file, report metadata must identify the hash.
    No advisory aliases or version ranges are inferred when matching cases.
    """
    if type(labels.get("schema_version")) is not int or labels["schema_version"] != 1:
        raise InvalidInput("labels.schema_version must be 1")
    if (
        type(require_human_review) is not bool
        or type(require_unexposed_external_review) is not bool
    ):
        raise InvalidInput("review coverage requirements must be boolean")
    cases = labels.get("cases")
    if not isinstance(cases, list) or not cases:
        raise InvalidInput("labels.cases must be a non-empty array")
    report_project = _text(scan.get("project"), "scan.project")
    selected_project = _text(project, "project mapping") if project is not None else report_project
    supplied_hash = _hash(snapshot_sha256, "snapshot hash") if snapshot_sha256 else None
    report_hash = scan.get("snapshot_sha256")
    if report_hash is not None:
        report_hash = _hash(report_hash, "scan.snapshot_sha256")
    if supplied_hash is not None and report_hash is not None and supplied_hash != report_hash:
        raise InvalidInput("snapshot file conflicts with scan.snapshot_sha256")
    selected_hash = supplied_hash or report_hash
    if selected_hash is None:
        raise InvalidInput("provide --snapshot FILE or a report with snapshot_sha256 metadata")
    if "scanned" in scan and not isinstance(scan["scanned"], bool):
        raise InvalidInput("scan.scanned must be a boolean")
    rows = scan.get("results")
    if not isinstance(rows, list):
        raise InvalidInput("scan.results must be an array")

    reference: dict[tuple[str, ...], dict[str, Any]] = {}
    scope: Counter[str] = Counter()
    by_label = {
        label: {"reference_cases": 0, "matched_unique_cases": 0, "filtered": 0, "retained": 0}
        for label in sorted(LABELS)
    }
    for index, raw in enumerate(cases):
        case = _object(raw, f"case {index}")
        if _text(case.get("project"), f"case {index}.project") != selected_project:
            raise InvalidInput(f"case {index} belongs to a different project")
        if _hash(case.get("snapshot_sha256"), f"case {index}.snapshot_sha256") != selected_hash:
            raise InvalidInput(f"case {index} belongs to a different snapshot")
        label = case.get("label")
        if label not in LABELS:
            raise InvalidInput(f"case {index}.label must be retain, filter or unknown")
        _text(case.get("reason"), f"case {index}.reason")
        provenance = _object(case.get("provenance"), f"case {index}.provenance")
        kind = provenance.get("kind")
        if kind not in {"synthetic", "reviewed"}:
            raise InvalidInput(f"case {index}.provenance.kind must be synthetic or reviewed")
        for field in ("source", "reviewer"):
            _text(provenance.get(field), f"case {index}.provenance.{field}")
        key = tuple(_text(case.get(field), f"case {index}.{field}") for field in IDENTITY)
        if key in reference:
            raise InvalidInput(f"duplicate reference identity: {key}")
        reference[key] = case
        by_label[label]["reference_cases"] += 1
        scope[kind] += 1

    observed: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    for index, raw in enumerate(rows):
        row = _object(raw, f"result {index}")
        if row.get("verdict") not in VERDICTS:
            raise InvalidInput(f"result {index}.verdict must be action, review or filtered")
        key = tuple(
            _text(row.get("cve" if field == "advisory" else field), f"result {index}.{field}")
            for field in IDENTITY
        )
        observed[key].append(row)

    details: dict[str, list[dict[str, Any]]] = {
        key: []
        for key in (
            "false_dismissals",
            "uncertain_dismissals",
            "correct_dismissals",
            "retained_opportunities",
            "missing_cases",
            "duplicate_results",
            "unlabelled_results",
        )
    }
    for key, matches in observed.items():
        identity = dict(zip(IDENTITY, key, strict=True))
        if len(matches) > 1:
            details["duplicate_results"].append({**identity, "row_count": len(matches)})
        if key not in reference:
            details["unlabelled_results"].append({**identity, "row_count": len(matches)})
    for key, case in reference.items():
        matches = observed.get(key, [])
        if not matches:
            details["missing_cases"].append(case)
            continue
        if len(matches) != 1:
            continue  # Ambiguous duplicates are unscored and fail the gate below.
        label = case["label"]
        verdict = matches[0]["verdict"]
        filtered = verdict == "filtered"
        by_label[label]["matched_unique_cases"] += 1
        by_label[label]["filtered" if filtered else "retained"] += 1
        category = None
        if filtered:
            category = {
                "retain": "false_dismissals",
                "unknown": "uncertain_dismissals",
                "filter": "correct_dismissals",
            }[label]
        elif label == "filter":
            category = "retained_opportunities"
        if category:
            details[category].append({**case, "verdict": verdict})

    counts = {name: len(values) for name, values in details.items()}
    counts.update(
        reference_cases=len(reference),
        scan_rows=len(rows),
        unique_scan_identities=len(observed),
        matched_unique_cases=sum(values["matched_unique_cases"] for values in by_label.values()),
        duplicate_extra_rows=sum(max(len(values) - 1, 0) for values in observed.values()),
    )
    rates = {}
    for metric, label in (
        ("false_dismissals", "retain"),
        ("uncertain_dismissals", "unknown"),
        ("correct_dismissals", "filter"),
        ("retained_opportunities", "filter"),
    ):
        denominator = by_label[label]["matched_unique_cases"]
        rates[metric] = {
            "numerator": counts[metric],
            "denominator": denominator,
            "fraction": counts[metric] / denominator if denominator else None,
            "denominator_definition": f"uniquely matched cases labelled {label}",
        }
    failures = [
        name
        for name in (
            "false_dismissals",
            "uncertain_dismissals",
            "missing_cases",
            "duplicate_results",
            "unlabelled_results",
        )
        if counts[name]
    ]
    complete = scan.get("scanned") is True
    if not complete:
        failures.insert(0, "incomplete_scan")
    review_coverage = summarize_reviews(labels, reviews, labels_sha256=labels_sha256)
    review_coverage["labels_sha256"] = (
        _hash(labels_sha256, "labels hash") if labels_sha256 is not None else None
    )
    review_coverage["input"] = "supplied" if reviews is not None else "not_supplied"
    human_audit = _human_review_audit(review_coverage, observed)
    if human_audit["counts"]["dismissals"]:
        failures.append("human_review_dismissals")
    if require_human_review and not review_coverage["gate"]["declared_human_coverage_complete"]:
        failures.append("human_review_coverage")
    if (
        require_unexposed_external_review
        and not review_coverage["gate"]["declared_unexposed_external_coverage_complete"]
    ):
        failures.append("unexposed_external_review_coverage")
    return {
        "schema_version": 1,
        "status": "fail" if failures else "pass",
        "gate_passed": not failures,
        "gate_failures": failures,
        "project": selected_project,
        "report_project": report_project,
        "snapshot_sha256": selected_hash,
        "snapshot_binding": "snapshot_bytes" if supplied_hash else "report_metadata",
        "scanned": complete,
        "scope": {"synthetic_cases": scope["synthetic"], "reviewed_cases": scope["reviewed"]},
        "interpretation": "Labelled sample checks only; not a real-world accuracy estimate.",
        "evaluation_basis": "proposed_labels",
        "review_coverage": review_coverage,
        "human_review_audit": human_audit,
        "counts": counts,
        "by_label": by_label,
        "rates": rates,
        "details": details,
    }


def _human_review_audit(
    coverage: dict[str, Any], observed: dict[tuple[str, ...], list[dict[str, Any]]]
) -> dict[str, Any]:
    """A declared human decision can add retention constraints, never remove them."""
    matched = 0
    retention_denominator = 0
    dismissed = []
    for case in coverage["cases"]:
        if not case["human_reviewer_ids"]:
            continue
        key = tuple(case[field] for field in IDENTITY)
        matches = observed.get(key, [])
        if len(matches) != 1:
            continue
        matched += 1
        if case["human_consensus"] not in {"retain", "unknown"}:
            continue
        retention_denominator += 1
        if matches[0]["verdict"] == "filtered":
            dismissed.append({**case, "verdict": "filtered"})
    return {
        "interpretation": "Additional retention constraints from declared human records; "
        "not authenticated review or a population accuracy estimate. "
        "Proposed labels remain unchanged.",
        "counts": {
            "matched_unique_human_cases": matched,
            "matched_retention_or_unknown_cases": retention_denominator,
            "dismissals": len(dismissed),
        },
        "rates": {
            "dismissals": {
                "numerator": len(dismissed),
                "denominator": retention_denominator,
                "fraction": len(dismissed) / retention_denominator
                if retention_denominator
                else None,
                "denominator_definition": "uniquely matched cases with declared human consensus "
                "retain or unknown, including disputes",
            }
        },
        "details": {"dismissals": dismissed},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--labels", required=True, type=Path)
    parser.add_argument("--scan", required=True, type=Path)
    parser.add_argument("--snapshot", type=Path, help="Hash the exact versioned snapshot bytes")
    parser.add_argument("--project", help="Explicitly map a report path to a reference project ID")
    parser.add_argument(
        "--reviews", type=Path, help="Separate records bound to the exact labels bytes"
    )
    parser.add_argument(
        "--require-human-review",
        action="store_true",
        help="Require undisputed declared human coverage of every reference case",
    )
    parser.add_argument(
        "--require-unexposed-external-review",
        action="store_true",
        help="Require external human records declaring no prior label/result exposure",
    )
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args(argv)
    try:
        snapshot_hash = (
            hashlib.sha256(args.snapshot.read_bytes()).hexdigest() if args.snapshot else None
        )
        labels_raw = args.labels.read_bytes()
        reviews_raw = args.reviews.read_bytes() if args.reviews else None
        report = evaluate(
            _parse(labels_raw, args.labels),
            _read(args.scan),
            snapshot_sha256=snapshot_hash,
            project=args.project,
            reviews=_parse(reviews_raw, args.reviews) if reviews_raw is not None else None,
            labels_sha256=hashlib.sha256(labels_raw).hexdigest(),
            require_human_review=args.require_human_review,
            require_unexposed_external_review=args.require_unexposed_external_review,
        )
        report["review_coverage"]["review_bundle_sha256"] = (
            hashlib.sha256(reviews_raw).hexdigest() if reviews_raw is not None else None
        )
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        if args.json_output:
            print(json.dumps({"schema_version": 1, "status": "invalid", "error": str(exc)}))
        else:
            print(f"Invalid evaluation input: {exc}", file=sys.stderr)
        return 2
    if args.json_output:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"Gate: {report['status']} ({report['interpretation']})")
        print(f"Scope: {report['scope']}")
        print(f"Counts: {report['counts']}")
        print(f"Denominators: {report['by_label']}")
        print(f"Declared review coverage: {report['review_coverage']['counts']}")
        print(f"Human-record retention audit: {report['human_review_audit']['counts']}")
        if report["gate_failures"]:
            print("Failures: " + ", ".join(report["gate_failures"]))
    return 0 if report["gate_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
