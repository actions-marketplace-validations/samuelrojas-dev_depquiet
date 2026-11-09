"""Conservative npm range matching without a Node or third-party runtime.

The supported subset follows npm/node-semver's default range semantics for
stable versions: comparators, whitespace intersections, OR, trailing x-ranges,
caret, tilde and standalone hyphen ranges. Full build metadata is ignored for
precedence. Prerelease comparisons and unsupported grammar remain unknown;
they must never be approximated into a negative match.

Reference: https://github.com/npm/node-semver#ranges
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Literal

RangeMatch = Literal["matched", "not_matched", "unknown"]
_Version = tuple[int, int, int]
_Comparator = tuple[str, _Version]
_MAX_SAFE_INTEGER = 2**53 - 1
_NUMBER = r"(?:0|[1-9][0-9]*)"
_IDENTIFIER = r"[0-9A-Za-z-]+"
_FULL_VERSION = re.compile(
    rf"v?({_NUMBER})\.({_NUMBER})\.({_NUMBER})"
    rf"(?:-({_IDENTIFIER}(?:\.{_IDENTIFIER})*))?"
    rf"(?:\+({_IDENTIFIER}(?:\.{_IDENTIFIER})*))?\Z"
)
_PARTIAL = re.compile(
    rf"v?({_NUMBER}|[xX*])(?:\.({_NUMBER}|[xX*]))?(?:\.({_NUMBER}|[xX*]))?"
    rf"(?:\+({_IDENTIFIER}(?:\.{_IDENTIFIER})*))?\Z"
)


class _UnsupportedRange(ValueError):
    pass


@dataclass(frozen=True)
class _Partial:
    values: tuple[int | None, int | None, int | None]
    precision: int

    @property
    def lower(self) -> _Version:
        return self.values[0] or 0, self.values[1] or 0, self.values[2] or 0


def is_exact_npm_version(value: str) -> bool:
    """Recognize a full npm SemVer, including prerelease and build identifiers.

    This validates a lockfile field; it does not inspect an installation or
    coerce a range, tag, URL or partial version into a component version.
    """
    if not isinstance(value, str) or len(value) > 256:
        return False
    match = _FULL_VERSION.fullmatch(value)
    if match is None:
        return False
    if any(int(part) > _MAX_SAFE_INTEGER for part in match.groups()[:3]):
        return False
    prerelease = match.group(4)
    return not prerelease or all(
        not (part.isdigit() and len(part) > 1 and part.startswith("0"))
        for part in prerelease.split(".")
    )


def _partial(value: str) -> _Partial:
    if len(value) > 256:
        raise _UnsupportedRange("Range version is too long.")
    match = _PARTIAL.fullmatch(value)
    if match is None:
        raise _UnsupportedRange("Unsupported npm range syntax or prerelease comparator.")
    values: list[int | None] = []
    wildcard = False
    for part in match.groups()[:3]:
        if part is None or part in {"x", "X", "*"}:
            wildcard = True
            values.append(None)
        else:
            if wildcard:
                raise _UnsupportedRange("Only trailing npm range wildcards are supported.")
            number = int(part)
            if number > _MAX_SAFE_INTEGER:
                raise _UnsupportedRange("Range version exceeds npm's safe integer limit.")
            values.append(number)
    precision = sum(value is not None for value in values)
    if match.group(4) is not None and precision != 3:
        raise _UnsupportedRange("Build metadata on a partial range is unsupported.")
    return _Partial((values[0], values[1], values[2]), precision)


def _checked(values: _Version) -> _Version:
    if any(value > _MAX_SAFE_INTEGER for value in values):
        raise _UnsupportedRange("Expanded range exceeds npm's safe integer limit.")
    return values


def _next_prefix(partial: _Partial) -> _Version:
    major, minor, _ = partial.lower
    return _checked((major + 1, 0, 0) if partial.precision == 1 else (major, minor + 1, 0))


def _primitive(operator: str, partial: _Partial) -> list[_Comparator]:
    lower = partial.lower
    if partial.precision == 0:
        # npm's >* and <* denote no stable versions; other wildcard
        # comparators accept every stable version.
        return [("<", (0, 0, 0))] if operator in {">", "<"} else []
    if operator in {"", "="}:
        if partial.precision == 3:
            return [("=", lower)]
        return [(">=", lower), ("<", _next_prefix(partial))]
    if operator == ">=" or (operator == ">" and partial.precision == 3):
        return [(operator, lower)]
    if operator == ">":
        return [(">=", _next_prefix(partial))]
    if operator == "<":
        return [("<", lower)]
    if operator == "<=":
        return [("<=", lower)] if partial.precision == 3 else [("<", _next_prefix(partial))]
    raise _UnsupportedRange("Unsupported npm comparator.")


def _advanced(operator: str, partial: _Partial) -> list[_Comparator]:
    if partial.precision == 0:
        return []
    major, minor, patch = partial.lower
    if operator == "~":
        upper = (major + 1, 0, 0) if partial.precision == 1 else (major, minor + 1, 0)
    elif major > 0 or partial.precision == 1:
        upper = (major + 1, 0, 0)
    elif minor > 0 or partial.precision == 2:
        upper = (0, minor + 1, 0)
    else:
        upper = (0, 0, patch + 1)
    return [(">=", partial.lower), ("<", _checked(upper))]


def _compile_arm(arm: str) -> tuple[_Comparator, ...]:
    arm = arm.strip()
    if not arm:
        return ()
    hyphen = re.fullmatch(r"(.+?)\s+-\s+(.+)", arm)
    if hyphen is not None:
        lower, upper = _partial(hyphen[1]), _partial(hyphen[2])
        comparators: list[_Comparator] = []
        if lower.precision:
            comparators.append((">=", lower.lower))
        if upper.precision == 3:
            comparators.append(("<=", upper.lower))
        elif upper.precision:
            comparators.append(("<", _next_prefix(upper)))
        return tuple(comparators)
    # Spaces between an operator and version are supported by node-semver.
    arm = re.sub(r"([<>]=?|[=~^])\s+(?=[v0-9xX*])", r"\1", arm)
    tokens = arm.split()
    if len(tokens) > 256:
        raise _UnsupportedRange("Too many npm comparators.")
    comparators = []
    for token in tokens:
        match = re.fullmatch(r"(<=|>=|<|>|=|~|\^)?(.+)", token)
        if match is None:
            raise _UnsupportedRange("Unsupported npm range token.")
        operator = match[1] or ""
        version = _partial(match[2])
        if operator in {"~", "^"}:
            comparators.extend(_advanced(operator, version))
        else:
            comparators.extend(_primitive(operator, version))
    return tuple(comparators)


@lru_cache(maxsize=512)
def _compile_range(value: str) -> tuple[tuple[_Comparator, ...], ...]:
    if len(value) > 4096 or any(
        ord(char) > 126 or (ord(char) < 32 and char not in "\t\r\n\v\f") for char in value
    ):
        raise _UnsupportedRange("Unsupported npm range length or characters.")
    # Compile every OR branch before deciding: an invalid branch must not be
    # silently discarded because another branch happened to match.
    branches = value.split("||")
    if len(branches) > 64:
        raise _UnsupportedRange("Too many npm OR branches.")
    return tuple(_compile_arm(arm) for arm in branches)


def _compare(version: _Version, comparator: _Comparator) -> bool:
    operator, other = comparator
    if operator == "=":
        return version == other
    if operator == "<":
        return version < other
    if operator == "<=":
        return version <= other
    if operator == ">":
        return version > other
    return version >= other


def match_npm_range(version: str, advisory_range: str) -> tuple[RangeMatch, str]:
    """Return a certain stable-version match, or explicit unsupported uncertainty.

    ``matched`` and ``not_matched`` concern only the supplied version and npm
    range, not product impact, vulnerable-function execution or installation.
    """
    if not is_exact_npm_version(version):
        return "unknown", "Lockfile version is not a supported exact npm SemVer."
    if not isinstance(advisory_range, str):
        return "unknown", "Advisory range is not a string."
    match = _FULL_VERSION.fullmatch(version)
    assert match is not None
    if match.group(4) is not None:
        return "unknown", "Prerelease npm range evaluation is not supported."
    numeric: _Version = int(match[1]), int(match[2]), int(match[3])
    try:
        arms = _compile_range(advisory_range)
    except _UnsupportedRange as error:
        return "unknown", str(error)
    if any(all(_compare(numeric, comparator) for comparator in arm) for arm in arms):
        return "matched", "Resolved version satisfies the supported npm advisory range."
    return "not_matched", "Resolved version is outside the supported npm advisory range."
