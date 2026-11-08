"""Integrity checks for the agent-reviewed upstream retention reference set.

These checks bind existing source/audit evidence; they are not human adjudication
or a test of exploitability. Upstream projects are not downloaded or executed.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

import pytest

from depquiet.parsers.npm import NpmAuditParser
from depquiet.parsers.pip import PipAuditParser

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "benchmarks/reference/real"
SNAPSHOTS = sorted(CORPUS.glob("*.snapshot.json"))


@pytest.mark.parametrize("snapshot_path", SNAPSHOTS, ids=lambda path: path.stem)
def test_upstream_cases_are_bound_to_frozen_inputs(snapshot_path: Path, tmp_path: Path) -> None:
    raw = snapshot_path.read_bytes()
    assert b"\r\n" not in raw
    snapshot = json.loads(raw)
    labels_path = snapshot_path.with_name(snapshot_path.name.replace(".snapshot.", ".labels."))
    labels = json.loads(labels_path.read_bytes())
    assert labels["review_status"] == "agent_reviewed_human_pending"
    assert snapshot["kind"] == "upstream_reference"
    assert re.fullmatch(r"[a-f0-9]{40}", snapshot["source"]["commit"])
    assert snapshot["capture"]["recaptured_for_this_corpus"] is False
    for artifact in [snapshot["audit"], *snapshot.get("overlay_files", [])]:
        data = (ROOT / artifact["path"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == artifact["sha256"]
        assert b"\r\n" not in data

    audit = json.loads((ROOT / snapshot["audit"]["path"]).read_text(encoding="utf-8"))
    parser = PipAuditParser if "dependencies" in audit else NpmAuditParser
    findings = parser.parse(audit, tmp_path)
    identities = {(v.package, v.version, v.cve) for v in findings}
    selection = {(row["package"], row["version"], row["advisory"]) for row in snapshot["selection"]}
    assert selection <= identities
    assert len(selection) == len(snapshot["selection"])
    assert selection == {
        (case["package"], case["version"], case["advisory"]) for case in labels["cases"]
    }
    for case in labels["cases"]:
        assert case["snapshot_sha256"] == hashlib.sha256(raw).hexdigest()
        assert case["project"] == snapshot["project"]
        assert case["assessment_status"] == "under_investigation"
        assert case["provenance"]["kind"] == "reviewed"
        assert case["provenance"]["human_reviewed"] is False
        assert case["provenance"]["independent_external_validation"] is False
        assert "human review pending" in case["provenance"]["reviewer"]
        assert case["version_evidence"]["installation_observed"] is False
        assert case["version_evidence"]["installed_versions"] is None
        assert case["version_evidence"]["locked_versions"]
        assert case["label"] in {"retain", "unknown"}
        assert case["reason"] and case["limitations"]
        assert case["primary_advisory"]["url"].startswith("https://")
        assert case["evidence"]
        for evidence in case["evidence"]:
            assert evidence["kind"] == "upstream_git_blob"
            assert re.fullmatch(r"[a-f0-9]{40}", evidence["git_blob"])
            assert re.fullmatch(r"[a-f0-9]{64}", evidence["content_sha256"])
            assert f"/blob/{snapshot['source']['commit']}/" in evidence["url"]
            assert evidence["observation"]
            assert "excerpt" not in evidence and "extract" not in evidence


def test_initial_upstream_scope_is_explicit_and_has_no_safe_dismissal_claims() -> None:
    assert len(SNAPSHOTS) == 4
    cases = []
    for path in CORPUS.glob("*.labels.json"):
        cases.extend(json.loads(path.read_text(encoding="utf-8"))["cases"])
    assert len(cases) == 10
    assert len({case["id"] for case in cases}) == 10
    assert Counter(case["label"] for case in cases) == {"retain": 5, "unknown": 5}
    assert all(case["label"] != "filter" for case in cases)
