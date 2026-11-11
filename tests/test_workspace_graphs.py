"""Workspace graph coverage must not borrow another member's declarations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from depquiet.depgraph import DependencyGraph


def _json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _npm(root: Path, members: Any = None) -> None:
    _json(root / "package.json", {"name": "root", "workspaces": members or ["packages/*"]})


def test_npm_local_direct_production_and_commands_do_not_bleed(tmp_path: Path) -> None:
    _json(
        tmp_path / "package.json",
        {
            "name": "root",
            "workspaces": ["packages/*"],
            "devDependencies": {"fixture-lib": "1"},
            "scripts": {"test": "root-bin"},
        },
    )
    _json(
        tmp_path / "packages/service/package.json",
        {
            "name": "service",
            "dependencies": {"fixture-lib": "1"},
            "scripts": {"start": "service-bin"},
        },
    )
    _json(tmp_path / "examples/demo/package.json", {"dependencies": {"unrelated": "1"}})
    _json(
        tmp_path / "package-lock.json",
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"devDependencies": {"root-only": "1"}},
                "node_modules/fixture-lib": {
                    "version": "1.0.0",
                    "bin": {"service-bin": "cli.js", "root-bin": "cli.js"},
                },
            },
        },
    )
    graph = DependencyGraph.from_project(tmp_path)
    root = graph.workspace_graphs["."]
    service = graph.workspace_graphs["packages/service"]
    assert root.direct == service.direct == {"fixture-lib"}
    assert root.is_dev_only(["fixture-lib"])
    assert not service.is_dev_only(["fixture-lib"])
    assert "root-bin" not in service.commands
    assert "service-bin" not in root.commands
    assert "root-only" not in graph.direct
    assert "unrelated" not in graph.direct
    assert service.scope_path == "packages/service"
    assert "packages/service/package.json" in service.sources
    assert root.coverage_complete and service.coverage_complete


def test_deep_glob_members_do_not_use_legacy_depth_limit(tmp_path: Path) -> None:
    _npm(tmp_path, ["packages/**/service"])
    member = "packages/a/b/c/d/e/service"
    _json(tmp_path / member / "package.json", {"name": "deep", "dependencies": {"deep-dep": "1"}})
    graph = DependencyGraph.from_project(tmp_path)
    assert set(graph.workspace_graphs) == {".", member}
    assert graph.workspace_graphs[member].direct == {"deep-dep"}
    assert graph.coverage_complete


def test_npm_object_workspaces_and_scoped_dependencies(tmp_path: Path) -> None:
    _npm(tmp_path, {"packages": ["services/*"]})
    _json(
        tmp_path / "services/api/package.json", {"name": "api", "dependencies": {"@org/tool": "1"}}
    )
    graph = DependencyGraph.from_project(tmp_path)
    assert graph.workspace_graphs["services/api"].direct == {"@org/tool"}
    assert graph.coverage_complete


def test_only_local_root_manifests_are_loaded(tmp_path: Path) -> None:
    _npm(tmp_path)
    _json(tmp_path / "packages/api/package.json", {"dependencies": {"own": "1"}})
    _json(tmp_path / "packages/api/src/example/package.json", {"dependencies": {"nested": "1"}})
    graph = DependencyGraph.from_project(tmp_path)
    assert graph.workspace_graphs["packages/api"].direct == {"own"}
    assert "nested" not in graph.direct


def test_uv_members_exclude_and_local_directness(tmp_path: Path) -> None:
    _text(
        tmp_path / "pyproject.toml",
        '[project]\nname="root"\ndependencies=["root-dep"]\n[tool.uv.workspace]\nmembers=["packages/*"]\nexclude=["packages/excluded"]\n',
    )
    _text(tmp_path / "packages/a/pyproject.toml", '[project]\nname="a"\ndependencies=["prod-a"]\n')
    _text(
        tmp_path / "packages/b/pyproject.toml",
        '[project]\nname="b"\n[dependency-groups]\ndev=["dev-b"]\n',
    )
    _text(
        tmp_path / "packages/excluded/pyproject.toml",
        '[project]\nname="excluded"\ndependencies=["excluded-dep"]\n',
    )
    _text(
        tmp_path / "uv.lock",
        'version=1\n[[package]]\nname="root"\nsource={virtual="."}\ndependencies=[{name="root-dep"}]\n[[package]]\nname="a"\nsource={editable="packages/a"}\ndependencies=[{name="prod-a"}]\n[[package]]\nname="b"\nsource={editable="packages/b"}\n[package.dev-dependencies]\ndev=[{name="dev-b"}]\n[[package]]\nname="root-dep"\nversion="1.0"\n[[package]]\nname="prod-a"\nversion="1.0"\n[[package]]\nname="dev-b"\nversion="1.0"\n',
    )
    graph = DependencyGraph.from_project(tmp_path)
    assert set(graph.workspace_graphs) == {".", "packages/a", "packages/b"}
    assert graph.workspace_graphs["."].direct == {"root-dep"}
    assert graph.workspace_graphs["packages/a"].direct == {"prod-a"}
    assert graph.workspace_graphs["packages/b"].direct == {"dev-b"}
    assert graph.workspace_graphs["packages/b"].is_dev_only(["dev-b"])
    assert "excluded-dep" not in graph.direct
    assert graph.coverage_complete


def test_workspace_references_contribute_edges_not_foreign_direct_deps(tmp_path: Path) -> None:
    _npm(tmp_path)
    _json(tmp_path / "packages/a/package.json", {"name": "a", "dependencies": {"b": "*"}})
    _json(tmp_path / "packages/b/package.json", {"name": "b", "dependencies": {"leaf": "1"}})
    graph = DependencyGraph.from_project(tmp_path)
    a = graph.workspace_graphs["packages/a"]
    assert a.direct == {"b"}
    assert a.direct_ancestors("leaf") == {"b"}
    assert graph.workspace_graphs["packages/b"].direct == {"leaf"}


def test_member_development_tools_are_not_exported_to_consumers(tmp_path: Path) -> None:
    _npm(tmp_path)
    _json(tmp_path / "packages/a/package.json", {"name": "a", "dependencies": {"b": "*"}})
    _json(
        tmp_path / "packages/b/package.json",
        {
            "name": "b",
            "dependencies": {"leaf": "1"},
            "devDependencies": {"dev-tool": "1"},
        },
    )
    graph = DependencyGraph.from_project(tmp_path)
    assert graph.workspace_graphs["packages/a"].direct_ancestors("leaf") == {"b"}
    assert graph.workspace_graphs["packages/a"].directness("dev-tool") == "unknown"
    assert graph.workspace_graphs["packages/b"].is_dev_only(["dev-tool"])


def test_duplicate_workspace_names_reach_both_members_dependencies(tmp_path: Path) -> None:
    _npm(tmp_path)
    for member in ("a", "b"):
        _json(
            tmp_path / f"packages/{member}/package.json",
            {
                "name": "same",
                "dependencies": {f"leaf-{member}": "1"},
            },
        )
    _json(tmp_path / "packages/user/package.json", {"name": "user", "dependencies": {"same": "1"}})
    graph = DependencyGraph.from_project(tmp_path)
    assert graph.coverage_complete
    user = graph.workspace_graphs["packages/user"]
    # The shared name is one node carrying both members' production edges.
    assert user.direct_ancestors("leaf-a") == {"same"}
    assert user.direct_ancestors("leaf-b") == {"same"}


def test_shared_lock_edges_and_bins_are_pruned_to_own_closure(tmp_path: Path) -> None:
    _npm(tmp_path)
    for member, dependency in [("a", "parent-a"), ("b", "parent-b")]:
        _json(
            tmp_path / f"packages/{member}/package.json",
            {"name": member, "dependencies": {dependency: "1"}},
        )
    _json(
        tmp_path / "package-lock.json",
        {
            "packages": {
                "node_modules/parent-a": {"version": "1", "dependencies": {"leaf-a": "1"}},
                "node_modules/parent-b": {"version": "1", "dependencies": {"leaf-b": "1"}},
                "node_modules/leaf-a": {"version": "1", "bin": {"a-cli": "cli"}},
                "node_modules/leaf-b": {"version": "1", "bin": {"b-cli": "cli"}},
            }
        },
    )
    graph = DependencyGraph.from_project(tmp_path)
    a = graph.workspace_graphs["packages/a"]
    assert a.edges == {"parent-a": {"leaf-a"}}
    assert a.direct_ancestors("leaf-b") == set()
    assert a.bins == {"a-cli": {"leaf-a"}}
    assert a.coverage_complete


def test_multiple_lock_versions_union_their_edges(tmp_path: Path) -> None:
    _npm(tmp_path)
    _json(tmp_path / "packages/a/package.json", {"dependencies": {"shared": "1"}})
    _json(tmp_path / "packages/b/package.json", {"dependencies": {"other": "1"}})
    _json(
        tmp_path / "package-lock.json",
        {
            "packages": {
                "node_modules/shared": {"version": "1.0.0", "dependencies": {"old-leaf": "1"}},
                "node_modules/other/node_modules/shared": {
                    "version": "2.0.0",
                    "dependencies": {"new-leaf": "1"},
                },
                "node_modules/other": {"version": "1.0.0", "dependencies": {"shared": "2"}},
                "node_modules/old-leaf": {"version": "1.0.0"},
                "node_modules/new-leaf": {"version": "1.0.0"},
            }
        },
    )
    graph = DependencyGraph.from_project(tmp_path)
    assert graph.coverage_complete
    # Which copy a member installs is not modelled: each sees both versions'
    # dependencies, a superset that cannot hide a path.
    for member, root in (("packages/a", "shared"), ("packages/b", "other")):
        local = graph.workspace_graphs[member]
        assert local.direct_ancestors("old-leaf") == {root}
        assert local.direct_ancestors("new-leaf") == {root}


@pytest.mark.parametrize(
    "pattern", ["../outside", "/absolute", "C:/absolute", "packages/[ab]", "packages/**x", ""]
)
def test_unsupported_or_escaping_patterns_are_observable(tmp_path: Path, pattern: str) -> None:
    _npm(tmp_path, [pattern])
    graph = DependencyGraph.from_project(tmp_path)
    assert not graph.coverage_complete
    assert any("pattern" in note for note in graph.coverage_observations)


@pytest.mark.parametrize("members", ["packages/*", {"bad": []}, [1]])
def test_malformed_npm_declaration_abstains(tmp_path: Path, members: Any) -> None:
    _npm(tmp_path, members)
    graph = DependencyGraph.from_project(tmp_path)
    assert not graph.coverage_complete
    assert set(graph.workspace_graphs) == {"."}


def test_missing_member_and_missing_manifest_are_observable(tmp_path: Path) -> None:
    _npm(tmp_path, ["packages/missing", "packages/empty"])
    (tmp_path / "packages/empty").mkdir(parents=True)
    graph = DependencyGraph.from_project(tmp_path)
    assert not graph.coverage_complete
    assert any("missing" in note for note in graph.coverage_observations)
    assert "packages/empty" in graph.workspace_graphs
    assert not graph.workspace_graphs["packages/empty"].coverage_complete


@pytest.mark.parametrize("manifest", [[], {"dependencies": ["bad"]}, {"scripts": []}])
def test_malformed_member_manifest_is_incomplete(tmp_path: Path, manifest: Any) -> None:
    _npm(tmp_path)
    _json(tmp_path / "packages/api/package.json", manifest)
    graph = DependencyGraph.from_project(tmp_path)
    assert not graph.coverage_complete
    assert any("packages/api/package.json" in note for note in graph.coverage_observations)


def test_member_read_error_remains_visible(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _npm(tmp_path)
    target = tmp_path / "packages/api/package.json"
    _json(target, {"devDependencies": {"dev-lib": "1"}})
    original = Path.read_text

    def read(path: Path, *args: Any, **kwargs: Any) -> str:
        if path == target:
            raise PermissionError("blocked fixture")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    graph = DependencyGraph.from_project(tmp_path)
    assert not graph.workspace_graphs["packages/api"].coverage_complete
    assert not graph.is_dev_only(["dev-lib"])
    assert any("packages/api/package.json" in note for note in graph.coverage_observations)


def test_workspace_enumeration_error_abstains(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _npm(tmp_path)
    parent = tmp_path / "packages"
    _json(parent / "api/package.json", {})
    original = Path.iterdir

    def iterdir(path: Path) -> Any:
        if path == parent:
            raise PermissionError("blocked directory")
        return original(path)

    monkeypatch.setattr(Path, "iterdir", iterdir)
    graph = DependencyGraph.from_project(tmp_path)
    assert not graph.coverage_complete
    assert any("packages" in note and "enumerate" in note for note in graph.coverage_observations)


def test_workspace_symlink_escape_is_not_followed(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    _npm(root)
    outside = tmp_path / "outside"
    _json(outside / "package.json", {"dependencies": {"outside-dep": "1"}})
    (root / "packages").mkdir()
    try:
        (root / "packages/link").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("host does not permit directory symlinks")
    graph = DependencyGraph.from_project(root)
    assert not graph.coverage_complete
    assert "outside-dep" not in graph.direct
    assert any("symlink" in note for note in graph.coverage_observations)


def test_workspace_resolution_loop_is_recorded_not_raised(tmp_path: Path, monkeypatch) -> None:
    _npm(tmp_path)
    target = tmp_path / "packages/loop"
    _json(target / "package.json", {"dependencies": {"unread": "1"}})
    original = Path.resolve

    def resolve(path, *args, **kwargs):
        if path == target:
            raise RuntimeError("synthetic symlink loop")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", resolve)
    graph = DependencyGraph.from_project(tmp_path)
    assert not graph.coverage_complete
    assert "unread" not in graph.direct
    assert any("loop" in note for note in graph.coverage_observations)


def test_legacy_malformed_source_marks_coverage_incomplete(tmp_path: Path) -> None:
    _json(tmp_path / "package.json", {"devDependencies": {"dev-lib": "1"}})
    _text(tmp_path / "package-lock.json", "{bad-json")
    graph = DependencyGraph.from_project(tmp_path)
    assert not graph.coverage_complete
    assert not graph.is_dev_only(["dev-lib"])
    assert any("package-lock.json" in note for note in graph.coverage_observations)


def test_legacy_cross_ecosystem_name_collision_is_uncertain(tmp_path: Path) -> None:
    _text(tmp_path / "pyproject.toml", '[project]\nname="service"\ndependencies=["fixture-lib"]\n')
    _json(tmp_path / "examples/demo/package.json", {"devDependencies": {"fixture_lib": "1"}})
    graph = DependencyGraph.from_project(tmp_path)
    assert graph.coverage_complete
    # One node for both packages: the production declaration wins.
    assert not graph.is_dev_only(["fixture_lib"])
    # A report known to be npm-only reads npm manifests alone.
    assert DependencyGraph.from_project(tmp_path, ecosystem="npm").is_dev_only(["fixture_lib"])
    assert not DependencyGraph.from_project(tmp_path, ecosystem="python").is_dev_only(
        ["fixture-lib"]
    )


def test_no_workspace_keeps_legacy_nested_manifest_loading(tmp_path: Path) -> None:
    _json(tmp_path / "api/package.json", {"dependencies": {"nested": "1"}})
    graph = DependencyGraph.from_project(tmp_path)
    assert graph.workspace_graphs == {}
    assert graph.direct == {"nested"}
    assert graph.sources == ["api/package.json"]
