"""Committed reference packets remain pending and bound to their selected cases."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "benchmarks/reference"


def test_all_committed_packets_have_zero_completed_human_decisions():
    counts = {"reference_cases": 0, "declared_human_reviewed_cases": 0, "pending_cases": 0}
    names = [
        "mealie",
        "paperless-ngx",
        "node-express-realworld",
        "node-express-boilerplate",
        "realworld-configuration",
    ]
    for name in names:
        directory = "extensions" if name == "realworld-configuration" else "real"
        process = subprocess.run(
            [
                sys.executable,
                str(ROOT / "benchmarks/reviews.py"),
                "check",
                "--labels",
                str(REFERENCE / directory / f"{name}.labels.json"),
                "--reviews",
                str(REFERENCE / "reviews" / f"{name}.pending.json"),
                "--json",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=20,
        )
        assert process.returncode == 0, process.stderr + process.stdout
        summary = json.loads(process.stdout)
        for key in counts:
            counts[key] += summary["counts"][key]
        assert summary["counts"]["submitted_human_records"] == 0
        assert summary["counts"]["submitted_agent_records"] == 0
        assert summary["gate"]["declared_human_coverage_complete"] is False
        assert summary["gate"]["declared_unexposed_external_coverage_complete"] is False
    assert counts == {
        "reference_cases": 12,
        "declared_human_reviewed_cases": 0,
        "pending_cases": 12,
    }


def test_extension_selects_two_new_identities_without_replacing_original_context():
    original_path = REFERENCE / "real/node-express-realworld.snapshot.json"
    original = json.loads(original_path.read_bytes())
    snapshot_path = REFERENCE / "extensions/realworld-configuration.snapshot.json"
    snapshot = json.loads(snapshot_path.read_bytes())
    labels = json.loads((REFERENCE / "extensions/realworld-configuration.labels.json").read_bytes())
    digest = hashlib.sha256(snapshot_path.read_bytes()).hexdigest()
    assert snapshot["project"] == original["project"]
    assert snapshot["source"] == original["source"]
    assert snapshot["audit"] == original["audit"]

    def identities(rows):
        return {tuple(row[key] for key in ("package", "version", "advisory")) for row in rows}

    assert identities(snapshot["selection"]).isdisjoint(identities(original["selection"]))
    assert identities(snapshot["selection"]) == identities(labels["cases"])
    assert len(labels["cases"]) == 2
    assert {case["label"] for case in labels["cases"]} == {"retain", "unknown"}
    assert all(case["snapshot_sha256"] == digest for case in labels["cases"])
    assert all(case["provenance"]["human_reviewed"] is False for case in labels["cases"])
