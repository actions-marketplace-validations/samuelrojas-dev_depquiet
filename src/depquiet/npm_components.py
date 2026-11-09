"""Bind npm audit node locations to exact, hashed lockfile version evidence.

No node_modules content, package code, package manager or network is consulted.
Audit nodes are a package-level union: each candidate retains its own range
comparison, including negative or unsupported matches.

Format reference:
https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/
"""

from __future__ import annotations

import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from depquiet.models import ComponentEvidence
from depquiet.npm_semver import is_exact_npm_version, match_npm_range

_NAME_PART = re.compile(r"[A-Za-z0-9._~-]+\Z")


def _safe_package(name: str) -> bool:
    if not isinstance(name, str):
        return False
    parts = name.split("/")
    if len(parts) == 2 and parts[0].startswith("@"):
        parts[0] = parts[0][1:]
    elif len(parts) != 1:
        return False
    return all(part not in {".", ".."} and _NAME_PART.fullmatch(part) for part in parts)


def _safe_location(location: str) -> bool:
    return (
        bool(location)
        and not any(char in location for char in ("\\", ":"))
        and not any(ord(char) < 32 or ord(char) == 127 for char in location)
        and all(part not in {"", ".", ".."} for part in location.split("/"))
    )


def _location_package(location: str) -> str | None:
    parts = location.split("/")
    if "node_modules" not in parts:
        return None
    index = len(parts) - 1 - parts[::-1].index("node_modules")
    suffix = parts[index + 1 :]
    if len(suffix) == 1 and not suffix[0].startswith("@"):
        return suffix[0]
    if len(suffix) == 2 and suffix[0].startswith("@"):
        return "/".join(suffix)
    return None


@lru_cache(maxsize=8)
def _parse_lock(raw: bytes) -> dict[str, Any]:
    def unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    data = json.loads(raw, object_pairs_hook=unique_keys)
    if not isinstance(data, dict):
        raise ValueError("lockfile must be a JSON object")
    return data


def _legacy_locations(data: dict[str, Any]) -> dict[str, tuple[str | None, Any]]:
    dependencies = data.get("dependencies")
    if not isinstance(dependencies, dict):
        raise ValueError("v1 dependencies must be an object")
    locations: dict[str, tuple[str | None, Any]] = {}
    pending = [("", dependencies)]
    while pending:
        prefix, children = pending.pop()
        for name, info in children.items():
            if not _safe_package(name):
                continue
            location = f"{prefix}node_modules/{name}"
            locations[location] = (name, info)
            if isinstance(info, dict) and isinstance(info.get("dependencies"), dict):
                pending.append((location + "/", info["dependencies"]))
    return locations


def _load_snapshot(
    project: Path,
) -> tuple[str, str, dict[str, tuple[str | None, Any]] | None, list[str]]:
    notes: list[str] = []
    # npm gives shrinkwrap precedence; do not resolve against an ignored lock.
    lockfile = "package-lock.json"
    try:
        if (project / "npm-shrinkwrap.json").exists():
            lockfile = "npm-shrinkwrap.json"
        raw = (project / lockfile).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        data = _parse_lock(raw)
        format_version = data.get("lockfileVersion")
        if format_version is not None and (
            type(format_version) is not int or format_version not in {1, 2, 3}
        ):
            raise ValueError("unsupported lockfileVersion")
        packages = data.get("packages")
        locations: dict[str, tuple[str | None, Any]]
        if isinstance(packages, dict) and format_version != 1:
            locations = {location: (None, info) for location, info in packages.items()}
            if format_version is None:
                notes.append("Lockfile format version is missing; using its explicit packages map.")
        elif format_version == 1:
            locations = _legacy_locations(data)
        else:
            raise ValueError("a supported packages map or v1 dependency tree is missing")
    except (OSError, ValueError, RecursionError) as error:
        return (
            lockfile,
            "",
            None,
            [f"Npm component evidence is unknown: could not read {lockfile} ({error})."],
        )
    return lockfile, digest, locations, notes


class NpmComponentResolver:
    """One immutable lockfile snapshot shared by every advisory in a report."""

    def __init__(self, project: Path):
        self._snapshot = _load_snapshot(project)

    def resolve(
        self, package: str, nodes: list[str], advisory_range: str
    ) -> tuple[list[ComponentEvidence], list[str]]:
        lockfile, digest, locations, notes = self._snapshot
        if locations is None:
            return [], list(notes)
        return _resolve_locations(
            package, nodes, advisory_range, lockfile, digest, locations, notes
        )


def resolve_npm_components(
    project: Path, package: str, nodes: list[str], advisory_range: str
) -> tuple[list[ComponentEvidence], list[str]]:
    """Resolve the reported nodes against a freshly captured lockfile snapshot.

    Parsers should reuse :class:`NpmComponentResolver` for the full report, so
    a concurrent lockfile edit cannot mix revisions between advisory records.
    """
    return NpmComponentResolver(project).resolve(package, nodes, advisory_range)


def _resolve_locations(
    package: str,
    nodes: list[str],
    advisory_range: str,
    lockfile: str,
    digest: str,
    locations: dict[str, tuple[str | None, Any]],
    initial_notes: list[str],
) -> tuple[list[ComponentEvidence], list[str]]:
    notes = list(initial_notes)
    candidates: list[ComponentEvidence] = []
    if not _safe_package(package):
        return [], [
            *notes,
            "Npm component evidence is unknown: package name is unsupported or unsafe.",
        ]
    if not isinstance(nodes, list) or not nodes:
        return [], [
            *notes,
            "No npm audit node locations were supplied; no locations were inferred.",
        ]

    seen: set[str] = set()
    for node in nodes:
        if not isinstance(node, str) or not _safe_location(node):
            notes.append(f"Npm audit node {node!r} is not a safe relative lockfile location.")
            continue
        if node in seen:
            notes.append(
                f"Duplicate npm audit node {node!r} was included once in component evidence."
            )
            continue
        seen.add(node)
        record = locations.get(node)
        if record is None:
            notes.append(f"Npm audit node {node!r} is absent from {lockfile}; version is unknown.")
            continue
        legacy_name, info = record
        if not isinstance(info, dict):
            notes.append(f"Npm audit node {node!r} has a malformed lockfile descriptor.")
            continue
        if "link" in info and not isinstance(info["link"], bool):
            notes.append(f"Npm audit node {node!r} has a malformed link flag in {lockfile}.")
            continue
        if info.get("link"):
            notes.append(f"Npm audit node {node!r} is a link; no target version was inferred.")
            continue
        path_name = _location_package(node)
        if "node_modules" in node.split("/") and (
            path_name is None or not _safe_package(path_name)
        ):
            notes.append(f"Npm audit node {node!r} is not a package-root lockfile location.")
            continue
        explicit_name = info.get("name", legacy_name)
        if explicit_name is not None:
            if not isinstance(explicit_name, str) or explicit_name != package:
                notes.append(f"Npm audit node {node!r} has a conflicting lockfile package name.")
                continue
        elif path_name != package:
            notes.append(f"Npm audit node {node!r} cannot be identified as package {package!r}.")
            continue
        version = info.get("version")
        if not isinstance(version, str) or not is_exact_npm_version(version):
            notes.append(f"Npm audit node {node!r} has no exact SemVer version in {lockfile}.")
            continue
        if isinstance(advisory_range, str) and advisory_range.strip():
            state, reason = match_npm_range(version, advisory_range)
        else:
            state, reason = (
                "unknown",
                "No string advisory range was supplied; association is unknown.",
            )
        candidates.append(
            ComponentEvidence(
                ecosystem="npm",
                package=package,
                version=version,
                location=node,
                lockfile=lockfile,
                lockfile_sha256=digest,
                range_match=state,
                reason=reason,
            )
        )
        if state == "unknown":
            notes.append(f"Range association for npm audit node {node!r} is unknown: {reason}")
    versions = {candidate.version for candidate in candidates}
    if len(versions) > 1:
        notes.append(
            f"Multiple locked versions of {package!r} remain separate at their reported locations; "
            "runtime installation was not observed."
        )
    return candidates, notes
