"""Npm audit node evidence preserves lockfile versions, locations and uncertainty."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from depquiet import npm_components
from depquiet.npm_components import NpmComponentResolver, resolve_npm_components


def _lock(project: Path, packages: dict, version: int = 3) -> Path:
    path = project / "package-lock.json"
    path.write_text(
        json.dumps({"lockfileVersion": version, "packages": packages}), encoding="utf-8"
    )
    return path


@pytest.mark.parametrize("lock_version", [2, 3])
def test_body_parser_candidates_keep_distinct_versions_and_same_version_locations(
    tmp_path: Path, lock_version: int
) -> None:
    # The first two version contexts occur in the frozen realworld fixture.
    packages = {
        "": {},
        "node_modules/body-parser": {"version": "1.20.2"},
        "node_modules/express/node_modules/body-parser": {"version": "1.20.1"},
        "node_modules/other/node_modules/body-parser": {"version": "1.20.2"},
    }
    path = _lock(tmp_path, packages, lock_version)
    nodes = list(packages)[1:]
    candidates, notes = resolve_npm_components(tmp_path, "body-parser", nodes, "<1.20.3")
    assert [(c.location, c.version, c.range_match) for c in candidates] == [
        (nodes[0], "1.20.2", "matched"),
        (nodes[1], "1.20.1", "matched"),
        (nodes[2], "1.20.2", "matched"),
    ]
    assert len({c.instance_id for c in candidates}) == 3
    assert all(
        c.lockfile_sha256 == hashlib.sha256(path.read_bytes()).hexdigest() for c in candidates
    )
    assert all(c.ecosystem == "npm" and c.lockfile == "package-lock.json" for c in candidates)
    assert any("Multiple locked versions" in note for note in notes)
    assert all("installed" not in candidate.to_dict() for candidate in candidates)


def test_cross_spawn_node_union_does_not_assign_every_version_to_each_advisory(
    tmp_path: Path,
) -> None:
    nodes = ["node_modules/cross-spawn", "node_modules/sane/node_modules/cross-spawn"]
    _lock(tmp_path, {nodes[0]: {"version": "7.0.3"}, nodes[1]: {"version": "6.0.5"}})
    candidates, _ = resolve_npm_components(tmp_path, "cross-spawn", nodes, "<6.0.6")
    assert [(c.version, c.range_match) for c in candidates] == [
        ("7.0.3", "not_matched"),
        ("6.0.5", "matched"),
    ]


def test_lockfile_is_evidence_and_node_modules_is_not_inspected(tmp_path: Path) -> None:
    node = "node_modules/example"
    _lock(tmp_path, {node: {"version": "1.0.0"}})
    runtime = tmp_path / node
    runtime.mkdir(parents=True)
    (runtime / "package.json").write_text('{"name":"example","version":"9.0.0"}')
    candidates, _ = resolve_npm_components(tmp_path, "example", [node], "<2.0.0")
    assert candidates[0].version == "1.0.0"


def test_resolver_snapshots_one_read_and_hash_for_every_advisory(
    tmp_path: Path, monkeypatch
) -> None:
    node = "node_modules/example"
    path = _lock(tmp_path, {node: {"version": "1.0.0"}})
    original_read = Path.read_bytes
    original_sha = hashlib.sha256
    reads = 0
    hashes = 0

    def read(file: Path) -> bytes:
        nonlocal reads
        if file == path:
            reads += 1
        return original_read(file)

    def sha(data: bytes):
        nonlocal hashes
        hashes += 1
        return original_sha(data)

    monkeypatch.setattr(Path, "read_bytes", read)
    monkeypatch.setattr(npm_components, "hashlib", SimpleNamespace(sha256=sha))
    resolver = NpmComponentResolver(tmp_path)
    first, _ = resolver.resolve("example", [node], "<2.0.0")
    _lock(tmp_path, {node: {"version": "3.0.0"}})
    second, _ = resolver.resolve("example", [node], ">=3.0.0")
    assert (reads, hashes) == (1, 1)
    assert first[0].version == second[0].version == "1.0.0"
    assert first[0].lockfile_sha256 == second[0].lockfile_sha256
    assert second[0].range_match == "not_matched"
    newer, _ = NpmComponentResolver(tmp_path).resolve("example", [node], ">=3.0.0")
    assert (reads, hashes) == (2, 2)
    assert newer[0].version == "3.0.0"
    assert newer[0].lockfile_sha256 != first[0].lockfile_sha256


def test_failed_snapshot_does_not_switch_to_a_newly_created_lockfile(tmp_path: Path) -> None:
    resolver = NpmComponentResolver(tmp_path)
    _lock(tmp_path, {"node_modules/example": {"version": "1.0.0"}})
    candidates, notes = resolver.resolve("example", ["node_modules/example"], "*")
    assert candidates == [] and any("could not read" in note for note in notes)
    assert NpmComponentResolver(tmp_path).resolve("example", ["node_modules/example"], "*")[0]


def test_v1_hierarchy_resolves_precise_nested_nodes(tmp_path: Path) -> None:
    data = {
        "lockfileVersion": 1,
        "dependencies": {
            "example": {"version": "1.0.0"},
            "parent": {"version": "2.0.0", "dependencies": {"example": {"version": "3.0.0"}}},
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(data))
    nodes = ["node_modules/example", "node_modules/parent/node_modules/example"]
    candidates, _ = resolve_npm_components(tmp_path, "example", nodes, "<2.0.0")
    assert [(c.location, c.version, c.range_match) for c in candidates] == [
        (nodes[0], "1.0.0", "matched"),
        (nodes[1], "3.0.0", "not_matched"),
    ]


def test_packages_map_takes_precedence_over_legacy_dependencies(tmp_path: Path) -> None:
    data = {
        "lockfileVersion": 2,
        "packages": {"node_modules/example": {"version": "1.0.0"}},
        "dependencies": {"example": {"version": "9.0.0"}},
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(data))
    candidates, _ = resolve_npm_components(tmp_path, "example", ["node_modules/example"], "*")
    assert candidates[0].version == "1.0.0"


def test_scoped_names_and_explicit_alias_names_are_preserved(tmp_path: Path) -> None:
    node = "node_modules/parent/node_modules/@scope/example"
    _lock(
        tmp_path,
        {node: {"version": "1.2.3"}, "node_modules/alias": {"name": "example", "version": "2.0.0"}},
    )
    scoped, _ = resolve_npm_components(tmp_path, "@scope/example", [node], "^1.0.0")
    alias, _ = resolve_npm_components(tmp_path, "example", ["node_modules/alias"], "*")
    assert scoped[0].package == "@scope/example" and scoped[0].location == node
    assert alias[0].package == "example" and alias[0].location == "node_modules/alias"


def test_unknown_node_does_not_fall_back_to_another_matching_package(tmp_path: Path) -> None:
    _lock(tmp_path, {"node_modules/example": {"version": "1.0.0"}})
    candidates, notes = resolve_npm_components(
        tmp_path, "example", ["node_modules/other/node_modules/example"], "*"
    )
    assert candidates == [] and any("absent" in note for note in notes)


@pytest.mark.parametrize(
    "node",
    [
        "/node_modules/example",
        "../node_modules/example",
        "./node_modules/example",
        "node_modules//example",
        "node_modules\\example",
        "C:/node_modules/example",
        "node_modules/example\x00",
    ],
)
def test_unsafe_audit_nodes_remain_unresolved(tmp_path: Path, node: str) -> None:
    _lock(tmp_path, {"node_modules/example": {"version": "1.0.0"}})
    candidates, notes = resolve_npm_components(tmp_path, "example", [node], "*")
    assert candidates == [] and any("safe relative" in note for note in notes)


@pytest.mark.parametrize(
    "descriptor",
    [
        None,
        {"version": "^1.2.3"},
        {"version": "file:../example"},
        {"version": 123},
        {"name": "different", "version": "1.2.3"},
        {"link": True},
        {"link": "false", "version": "1.2.3"},
    ],
)
def test_unverified_descriptors_produce_notes_without_component_versions(
    tmp_path: Path, descriptor
) -> None:
    _lock(tmp_path, {"node_modules/example": descriptor})
    candidates, notes = resolve_npm_components(tmp_path, "example", ["node_modules/example"], "*")
    assert candidates == [] and notes


def test_partial_resolution_preserves_valid_candidate_and_unresolved_notes(tmp_path: Path) -> None:
    _lock(tmp_path, {"node_modules/example": {"version": "1.0.0"}})
    candidates, notes = resolve_npm_components(
        tmp_path, "example", ["node_modules/example", "node_modules/missing"], "<2.0.0"
    )
    assert len(candidates) == 1
    assert any("node_modules/missing" in note for note in notes)


@pytest.mark.parametrize("range_", ["latest", "<1.2.3-0", "", None])
def test_unknown_ranges_keep_exact_candidates(tmp_path: Path, range_) -> None:
    _lock(tmp_path, {"node_modules/example": {"version": "1.0.0"}})
    candidates, notes = resolve_npm_components(
        tmp_path, "example", ["node_modules/example"], range_
    )
    assert candidates[0].version == "1.0.0" and candidates[0].range_match == "unknown"
    assert any("unknown" in note for note in notes)


def test_exact_prerelease_stays_candidate_with_unknown_range_comparison(tmp_path: Path) -> None:
    _lock(tmp_path, {"node_modules/example": {"version": "1.2.3-beta.1+build"}})
    candidates, notes = resolve_npm_components(tmp_path, "example", ["node_modules/example"], "*")
    assert candidates[0].version == "1.2.3-beta.1+build"
    assert candidates[0].range_match == "unknown" and notes


def test_duplicate_nodes_are_deduplicated_with_a_note(tmp_path: Path) -> None:
    _lock(tmp_path, {"node_modules/example": {"version": "1.0.0"}})
    candidates, notes = resolve_npm_components(
        tmp_path, "example", ["node_modules/example", "node_modules/example"], "*"
    )
    assert len(candidates) == 1 and any("Duplicate" in note for note in notes)


@pytest.mark.parametrize(
    "raw", [b"not json", b"[]", b'{"packages":{},"packages":{}}', b'{"lockfileVersion":4}']
)
def test_malformed_or_unsupported_lockfiles_are_explicitly_unknown(
    tmp_path: Path, raw: bytes
) -> None:
    (tmp_path / "package-lock.json").write_bytes(raw)
    candidates, notes = resolve_npm_components(tmp_path, "example", ["node_modules/example"], "*")
    assert candidates == [] and any("could not read" in note for note in notes)


def test_absent_lockfile_does_not_infer_a_resolved_version(tmp_path: Path) -> None:
    candidates, notes = resolve_npm_components(tmp_path, "example", ["node_modules/example"], "<2")
    assert candidates == [] and any("package-lock.json" in note for note in notes)


def test_empty_nodes_do_not_search_the_lockfile_for_unreported_instances(tmp_path: Path) -> None:
    _lock(tmp_path, {"node_modules/example": {"version": "1.0.0"}})
    candidates, notes = resolve_npm_components(tmp_path, "example", [], "*")
    assert candidates == [] and any("No npm audit node" in note for note in notes)


def test_shrinkwrap_has_npm_precedence_without_fallback_to_package_lock(tmp_path: Path) -> None:
    _lock(tmp_path, {"node_modules/example": {"version": "1.0.0"}})
    shrinkwrap = tmp_path / "npm-shrinkwrap.json"
    shrinkwrap.write_text(
        json.dumps(
            {"lockfileVersion": 3, "packages": {"node_modules/example": {"version": "2.0.0"}}}
        )
    )
    candidates, _ = resolve_npm_components(tmp_path, "example", ["node_modules/example"], "*")
    assert candidates[0].version == "2.0.0" and candidates[0].lockfile == "npm-shrinkwrap.json"
    shrinkwrap.write_text("not json")
    candidates, notes = resolve_npm_components(tmp_path, "example", ["node_modules/example"], "*")
    assert candidates == [] and any("npm-shrinkwrap.json" in note for note in notes)
