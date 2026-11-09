"""Offline conformance checks against independently captured node-semver data.

Node was used only to prepare the frozen development oracle. These tests have
no Node dependency and do not execute package managers or upstream applications.
Unknown answers cannot satisfy the 41 supported stable-version comparisons.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from depquiet.npm_semver import match_npm_range

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures/npm_semver_reference.json").read_text(encoding="utf-8")
)
CASES = FIXTURE["cases"]
CASES_SHA256 = "f3115363ab7520caeb98570472d083d86c70e8e30e85ac486910277398bea070"


def _coverage(case: dict[str, Any]) -> str:
    """Classify support from oracle validity and original syntax, not our result."""
    oracle = case["oracle"]
    if oracle["valid_version"] is None or oracle["valid_range"] is None:
        return "invalid_input_unknown"
    prerelease_version = "-" in oracle["valid_version"].split("+", 1)[0]
    prerelease_range = any(
        re.search(r"[0-9]+\.[0-9]+\.[0-9]+-", token.split("+", 1)[0])
        for token in case["range"].split()
    )
    if prerelease_version or prerelease_range:
        return "valid_prerelease_unknown"
    return "supported_stable_definitive"


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_independent_node_semver_reference(case: dict[str, Any]) -> None:
    actual, reason = match_npm_range(case["version"], case["range"])
    assert isinstance(reason, str) and reason.strip()
    coverage = _coverage(case)
    if coverage == "supported_stable_definitive":
        assert case["expected"] in {"matched", "not_matched"}
        assert actual == case["expected"], reason
    else:
        assert actual == "unknown", reason
        if coverage == "invalid_input_unknown":
            assert case["expected"] == "unknown"
        else:
            assert case["expected"] in {"matched", "not_matched"}
            assert "prerelease" in reason.replace("-", "").casefold()


def test_frozen_oracle_identity_and_explicit_supported_denominators() -> None:
    oracle = FIXTURE["oracle"]
    assert FIXTURE["schema_version"] == 1
    assert oracle["package"] == "semver" and oracle["version"] == "7.8.5"
    assert oracle["primary_source"] == "https://github.com/npm/node-semver#ranges"
    assert oracle["options"] == {"loose": False, "includePrerelease": False}
    assert oracle["entrypoint_sha256"] == (
        "422bdd8b05a81e75d912b79569f8b7da5ba041dbfd98ea2029ac5ef83feb792f"
    )
    canonical = json.dumps(CASES, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    assert hashlib.sha256(canonical.encode("utf-8")).hexdigest() == CASES_SHA256
    assert oracle["cases_sha256"] == CASES_SHA256
    assert len(CASES) == len({case["id"] for case in CASES}) == 60
    required = {
        "supported_stable_definitive": 41,
        "invalid_input_unknown": 11,
        "valid_prerelease_unknown": 8,
    }
    assert Counter(_coverage(case) for case in CASES) == required
    assert {key: FIXTURE["required_coverage"][key] for key in required} == required
