"""Stable npm ranges follow the documented node-semver comparator semantics."""

from __future__ import annotations

import pytest

from depquiet.npm_semver import is_exact_npm_version, match_npm_range


@pytest.mark.parametrize(
    ("version", "range_", "expected"),
    [
        ("1.20.2", "<1.20.3", "matched"),
        ("1.20.3", "<1.20.3", "not_matched"),
        ("6.0.5", "<6.0.6", "matched"),
        ("7.0.3", "<6.0.6", "not_matched"),
        ("1.2.3", "1.2.3", "matched"),
        ("1.2.4", "=1.2.3", "not_matched"),
        ("1.2.3", ">= 1.2.3 < 2.0.0", "matched"),
        ("2.0.0", ">=1.2.3 <2.0.0", "not_matched"),
        ("2.0.0", ">=1.2.3 <=2.0.0", "matched"),
        ("2.5.0", "1.2.3 || >=2.0.0 <3.0.0", "matched"),
        ("1.2.4", "1.2.3 || >=2.0.0 <3.0.0", "not_matched"),
        ("1.9.9", "1", "matched"),
        ("2.0.0", "1.x", "not_matched"),
        ("1.2.99", "1.2.*", "matched"),
        ("1.3.0", "1.2", "not_matched"),
        ("1.99.0", ">1", "not_matched"),
        ("2.0.0", ">1", "matched"),
        ("1.3.0", ">1.2", "matched"),
        ("1.2.99", ">1.2", "not_matched"),
        ("1.2.0", "<1.2", "not_matched"),
        ("1.1.99", "<1.2", "matched"),
        ("1.2.99", "<=1.2", "matched"),
        ("1.3.0", "<=1.2", "not_matched"),
        ("1.9.9", "^1.2.3", "matched"),
        ("2.0.0", "^1.2.3", "not_matched"),
        ("0.2.99", "^0.2.3", "matched"),
        ("0.3.0", "^0.2.3", "not_matched"),
        ("0.0.3", "^0.0.3", "matched"),
        ("0.0.4", "^0.0.3", "not_matched"),
        ("0.9.9", "^0", "matched"),
        ("1.0.0", "^0.x", "not_matched"),
        ("0.0.99", "^0.0", "matched"),
        ("0.1.0", "^0.0.x", "not_matched"),
        ("1.2.99", "~1.2.3", "matched"),
        ("1.3.0", "~1.2", "not_matched"),
        ("1.9.0", "~1", "matched"),
        ("2.0.0", "~1", "not_matched"),
        ("2.3.4", "1.2.3 - 2.3.4", "matched"),
        ("2.3.5", "1.2.3 - 2.3.4", "not_matched"),
        ("2.3.99", "1.2 - 2.3", "matched"),
        ("2.4.0", "1.2 - 2.3", "not_matched"),
        ("2.9.9", "1.2.3 - 2", "matched"),
        ("3.0.0", "1.2.3 - 2", "not_matched"),
        ("0.0.0", "*", "matched"),
        ("99.0.0", "", "matched"),
        ("1.2.3+build.001", "=1.2.3+different", "matched"),
        ("v1.2.3", ">=1.0.0", "matched"),
    ],
)
def test_supported_stable_comparisons(version: str, range_: str, expected: str) -> None:
    actual, reason = match_npm_range(version, range_)
    assert actual == expected
    assert reason


@pytest.mark.parametrize(
    "range_",
    [
        "latest",
        "npm:alias@1.0.0",
        "git+https://example.invalid/repo",
        ">=1.0.0, <2.0.0",
        "!=1.2.3",
        ">=1.0.0 || not-a-range",
        "* || >=1.0.0 garbage",
        "1.x.3",
        "1.2.3-alpha.1",
        "<1.2.3-0",
        "01.2.3",
        "1.2.3\x00",
        "1.2.3\x1c",
        "<9007199254740992.0.0",
        "^9007199254740991.0.0",
        "*" * 4097,
        " || ".join(["*"] * 65),
        " ".join([">=0"] * 257),
    ],
)
def test_unsupported_or_invalid_ranges_are_unknown(range_: str) -> None:
    state, reason = match_npm_range("1.2.3", range_)
    assert state == "unknown"
    assert reason


@pytest.mark.parametrize("version", ["1.2.3-alpha.1", "1.2.3-0", "2.0.0-rc.1+build", "v0.0.1-beta"])
def test_prerelease_comparisons_stay_explicitly_unknown(version: str) -> None:
    assert is_exact_npm_version(version)
    state, reason = match_npm_range(version, "*")
    assert state == "unknown"
    assert "Prerelease" in reason


@pytest.mark.parametrize(
    "version",
    ["^1.2.3", "1.2", "1", "1.x", "01.2.3", "1.2.3-01", "1.2.3+", "file:../pkg"],
)
def test_nonexact_versions_cannot_be_coerced_into_component_versions(version: str) -> None:
    assert not is_exact_npm_version(version)
    assert match_npm_range(version, "*")[0] == "unknown"


def test_oversize_version_and_invalid_range_types_are_unknown() -> None:
    assert match_npm_range("9007199254740992.0.0", "*")[0] == "unknown"
    assert match_npm_range("1.2.3+" + "x" * 256, "*")[0] == "unknown"
    assert match_npm_range("1.2.3", None)[0] == "unknown"  # type: ignore[arg-type]
