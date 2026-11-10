"""Dependency graph: which packages are direct, and what pulls in the rest.

Import-level reachability only makes sense for *direct* dependencies. A
transitive dependency is almost never imported by the application itself:
an Express app imports ``express``, never ``path-to-regexp`` or ``qs``, yet
Express calls both on every request. Treating "not imported" as "unreachable"
for those packages silently dismisses real, exploitable vulnerabilities.

So the reachability filter needs two facts the scanners do not reliably give
us (most scanner formats either omit directness or hard-code it):

1. **Is the package direct?** Taken from the project's own manifests and
   lockfiles, never from the scanner.
2. **For a transitive package, which direct dependencies pull it in?**
   Taken from lockfiles that record dependency edges.

When either fact is unknown the caller must not filter on reachability.
Being unable to prove a package is unused is not evidence that it is.

Supported sources:

========================  ==================  ==================
Ecosystem                 Direct deps         Edges
========================  ==================  ==================
npm                       package.json /      package-lock.json,
                          package-lock root   yarn.lock (v1/berry)
Python                    uv.lock roots,      uv.lock, poetry.lock,
                          pyproject.toml,     requirements.txt
                          Pipfile,            ``# via`` comments
                          requirements.in,    (pip-compile)
                          requirements.txt*
Rust                      Cargo.lock roots    Cargo.lock
Ruby                      Gemfile.lock        Gemfile.lock
PHP                       composer.json       composer.lock
.NET                      packages.lock.json  packages.lock.json
Dart                      pubspec.lock        (none)
Go                        go.mod              (none)
Java (Maven)              pom.xml             (none)
========================  ==================  ==================

Commands the project runs (``package.json`` scripts, ``Procfile``,
``Dockerfile*``) are recorded too: a dependency invoked as a command, like
``pm2 start``, is in use even though nothing imports it.

\\* A requirements.txt where *every* line is pinned with ``==`` and that has no
``# via`` annotations is indistinguishable from ``pip freeze`` output, which
lists transitive packages as if they were direct. Such files are not used as
a source of direct dependencies.
"""

from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

Directness = Literal["direct", "transitive", "unknown"]

_SKIP_DIRS = {"node_modules", ".git", "vendor", "target", ".venv", "venv", "dist", "build"}


def _norm(name: str) -> str:
    """Case-insensitive key. Package names in every supported ecosystem
    compare case-insensitively in practice (npm forbids uppercase, PyPI,
    NuGet and Composer are case-insensitive)."""
    return name.strip().lower()


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def _keys(name: str) -> set[str]:
    """Both lookup forms of a name: plain (npm, Cargo, ...) and PEP 503 (Python)."""
    return {_norm(name), _pep503(name)}


@dataclass
class DependencyGraph:
    """Direct dependencies plus parent -> child edges, keyed by normalized name."""

    direct: set[str] = field(default_factory=set)
    # Subset of ``direct`` declared for production in at least one manifest.
    # direct - prod_direct = dev-only (devDependencies, require-dev, Pipfile
    # dev-packages, Poetry dev groups).
    prod_direct: set[str] = field(default_factory=set)
    edges: dict[str, set[str]] = field(default_factory=dict)
    # Packages the lockfiles say are transitive even without edges
    # (pubspec.lock, go.mod ``// indirect``, NuGet "Transitive").
    known_transitive: set[str] = field(default_factory=set)
    # True once any manifest listing direct dependencies was read.
    has_manifest: bool = False
    sources: list[str] = field(default_factory=list)
    # normalized key -> name as written in the manifest
    display: dict[str, str] = field(default_factory=dict)
    # Executables each package installs (lockfile ``bin``): command -> packages.
    bins: dict[str, set[str]] = field(default_factory=dict)
    # Words appearing in commands the project runs: package.json scripts,
    # Procfile, Dockerfiles. A dependency run as a command is in use even if
    # nothing imports it (pm2, cross-env, next, ...).
    commands: set[str] = field(default_factory=set)
    coverage_complete: bool = True
    coverage_observations: list[str] = field(default_factory=list)
    scope_path: str = "."
    workspace_graphs: dict[str, DependencyGraph] = field(default_factory=dict)
    _ecosystems: dict[str, set[str]] = field(default_factory=dict, repr=False)

    # -- construction -----------------------------------------------------

    def add_direct(self, name: str, *, python: bool = False, dev: bool = False) -> None:
        if name:
            key = _pep503(name) if python else _norm(name)
            self.direct.add(key)
            self.display.setdefault(key, name.strip())
            if not dev:
                self.prod_direct.add(key)

    def add_edge(self, parent: str, child: str) -> None:
        if parent and child and _norm(parent) != _norm(child):
            self.edges.setdefault(_norm(parent), set()).add(_norm(child))

    def merge(self, other: DependencyGraph) -> None:
        self.direct |= other.direct
        self.prod_direct |= other.prod_direct
        self.known_transitive |= other.known_transitive
        for parent, children in other.edges.items():
            self.edges.setdefault(parent, set()).update(children)
        self.has_manifest = self.has_manifest or other.has_manifest
        self.sources.extend(other.sources)
        for key, name in other.display.items():
            self.display.setdefault(key, name)
        for cmd, pkgs in other.bins.items():
            self.bins.setdefault(cmd, set()).update(pkgs)
        self.commands |= other.commands
        self.coverage_complete = self.coverage_complete and other.coverage_complete
        self.coverage_observations.extend(other.coverage_observations)
        for name, ecosystems in other._ecosystems.items():
            self._ecosystems.setdefault(name, set()).update(ecosystems)
            if len(self._ecosystems[name]) > 1:
                _incomplete(self, f"{name}: dependency name occurs in multiple ecosystems")

    # -- queries ----------------------------------------------------------

    def directness(self, package: str) -> Directness:
        """Classify a package as direct, transitive or unknown."""
        if _norm(package) in self.direct or _pep503(package) in self.direct:
            # _pep503 only matches entries that came from Python manifests,
            # since only those are stored in that form.
            return "direct"
        if _norm(package) in self.known_transitive:
            return "transitive"
        if not self.has_manifest:
            return "unknown"
        # A manifest lists every direct dependency of its ecosystem, but we
        # don't know the package's ecosystem. If some edge points at it, it is
        # certainly transitive; otherwise it is either transitive or belongs to
        # an ecosystem whose manifest we didn't read.
        keys = _keys(package)
        if any(keys & children for children in self.edges.values()):
            return "transitive"
        return "unknown"

    def is_executed(self, package: str) -> bool:
        """True when a command the project runs invokes one of the package's executables.

        Uses the executables recorded in the lockfile, plus the package's own
        name (``@scope/tool`` -> ``tool``), the usual binary name, for
        lockfiles that don't record them. A spurious match only makes depquiet
        filter less.
        """
        if not self.commands:
            return False
        keys = _keys(package)
        names = {cmd for cmd, pkgs in self.bins.items() if pkgs & keys}
        names.add(package.rsplit("/", 1)[-1].lower())
        return bool(names & self.commands)

    def is_dev_only(self, names: list[str]) -> bool:
        """True when every name is a direct dependency declared as dev-only.

        A package declared both as a dependency and a devDependency (or in a
        second manifest as a regular dependency) counts as production.
        """
        if not self.coverage_complete:
            return False
        keys = [_keys(n) for n in names]
        return bool(keys) and all(k & self.direct and not k & self.prod_direct for k in keys)

    def direct_ancestors(self, package: str) -> set[str]:
        """Direct dependencies whose dependency closure contains ``package``.

        Returns an empty set when no path from a direct dependency is known.
        Names are returned as written in the manifest.
        """
        parents: dict[str, set[str]] = {}
        for parent, children in self.edges.items():
            for child in children:
                parents.setdefault(child, set()).add(parent)

        found: set[str] = set()
        seen = set(_keys(package))
        queue = deque(seen)
        while queue:
            node = queue.popleft()
            for parent in parents.get(node, ()):
                if parent in seen:
                    continue
                seen.add(parent)
                if parent in self.direct:
                    found.add(self.display.get(parent, parent))
                queue.append(parent)
        return found

    # -- loading ----------------------------------------------------------

    @classmethod
    def from_project(cls, project: Path) -> DependencyGraph:
        """Build the graph from every supported manifest/lockfile in ``project``.

        Unreadable, malformed or ambiguous inputs leave recorded incomplete
        coverage. They cannot justify development-only or absence decisions.
        Declared npm/uv members have local graphs; other layouts retain the
        bounded legacy discovery with explicit error reporting.
        """
        from depquiet.workspaces import discover_workspaces

        project = project.resolve()
        graph = cls()
        try:
            if not project.is_dir():
                graph.coverage_complete = False
                graph.coverage_observations.append(
                    ".: project directory is missing or inaccessible"
                )
                return graph
        except OSError as exc:
            graph.coverage_complete = False
            graph.coverage_observations.append(f".: inspect project directory: {exc}")
            return graph
        discovery = discover_workspaces(project)
        if discovery.declared:
            return _workspace_graph(project, discovery.members, discovery.observations)
        graph = _load_scope(project, project, recursive=True)
        for note in discovery.observations:
            _incomplete(graph, note)
        return graph


def _incomplete(graph: DependencyGraph, note: str) -> None:
    graph.coverage_complete = False
    if note not in graph.coverage_observations:
        graph.coverage_observations.append(note)


def _load_scope(
    scope: Path,
    project: Path,
    *,
    recursive: bool,
    skip: set[Path] | None = None,
    locks_edges_only: bool = False,
) -> DependencyGraph:
    graph = DependencyGraph(scope_path=scope.relative_to(project).as_posix())
    for path in _iter_files(
        scope,
        max_depth=3 if recursive else 0,
        on_error=lambda path, error: _incomplete(
            graph,
            f"{path.relative_to(project).as_posix()}: enumerate/inspect graph source: {error}",
        ),
    ):
        if skip and path in skip:
            continue
        _merge_source(
            graph, path, project, edges_only=locks_edges_only and path.name in _WORKSPACE_LOCKS
        )
    if graph.has_manifest:
        from depquiet.pynames import IMPLICIT_PLUGINS

        for parent, plugins in IMPLICIT_PLUGINS.items():
            if parent in graph.direct or any(
                parent in children for children in graph.edges.values()
            ):
                for plugin in plugins:
                    graph.add_edge(parent, plugin)
    return graph


def _merge_source(
    graph: DependencyGraph, path: Path, project: Path, *, edges_only: bool = False
) -> None:
    loader = _LOADERS.get(path.name)
    if loader is None and path.name.startswith("requirements") and path.suffix == ".txt":
        loader = _load_requirements_txt
    if loader is None and path.name.startswith("Dockerfile."):
        loader = _load_commands_file
    if loader is None:
        return
    try:
        part = loader(path)
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        RecursionError,
        ET.ParseError,
    ) as exc:
        _incomplete(
            graph, f"{path.relative_to(project).as_posix()}: read/parse graph source: {exc}"
        )
        return
    if part is not None:
        if edges_only:
            part.direct.clear()
            part.prod_direct.clear()
            part.has_manifest = False
            part.commands.clear()
        part.sources.append(path.relative_to(project).as_posix())
        namespace = _source_ecosystem(path.name)
        if namespace:
            names = part.direct | part.known_transitive | set(part.edges)
            names |= {name for children in part.edges.values() for name in children}
            for name in names:
                for key in _keys(name):
                    part._ecosystems.setdefault(key, set()).add(namespace)
        graph.merge(part)


_WORKSPACE_LOCKS = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "uv.lock"}


def _source_ecosystem(filename: str) -> str:
    if filename in {"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock"}:
        return "npm"
    if filename in {
        "pyproject.toml",
        "uv.lock",
        "poetry.lock",
        "Pipfile",
        "requirements.in",
    } or filename.startswith("requirements"):
        return "python"
    return {
        "Cargo.lock": "rust",
        "Gemfile.lock": "ruby",
        "composer.json": "php",
        "composer.lock": "php",
        "packages.lock.json": "dotnet",
        "pubspec.lock": "dart",
        "go.mod": "go",
        "pom.xml": "maven",
    }.get(filename, "")


def _lock_inventory(path: Path) -> tuple[set[str], set[str]]:
    """Return names and collisions that a name-only graph cannot attribute."""
    identities: dict[str, set[str]] = {}

    def record(name: str, info: dict[str, Any]) -> None:
        if name:
            identity = json.dumps(
                {key: info.get(key) for key in ("version", "source", "dependencies", "requires")},
                sort_keys=True,
            )
            identities.setdefault(
                _pep503(name) if path.name == "uv.lock" else _norm(name), set()
            ).add(identity)

    text = path.read_text(encoding="utf-8")
    if path.name == "uv.lock":
        for package in tomllib.loads(text).get("package", []):
            record(package["name"], package)
    elif path.name in {"package-lock.json", "npm-shrinkwrap.json"}:
        data = json.loads(text)
        packages = data.get("packages")
        if isinstance(packages, dict) and packages:
            for location, info in packages.items():
                if location:
                    record(info.get("name") or _npm_name_from_key(location), info)
        else:

            def walk(dependencies: dict[str, Any]) -> None:
                for name, info in dependencies.items():
                    record(name, info)
                    walk(info.get("dependencies") or {})

            walk(data.get("dependencies") or {})
    return set(identities), {name for name, versions in identities.items() if len(versions) > 1}


def _workspace_graph(
    project: Path, members: dict[str, set[str]], observations: list[str]
) -> DependencyGraph:
    aggregate = DependencyGraph()
    shared = DependencyGraph()
    files = _iter_files(
        project,
        max_depth=0,
        on_error=lambda path, error: _incomplete(
            shared, f"{path.relative_to(project).as_posix()}: inspect shared lock: {error}"
        ),
    )
    shared_paths = {path for path in files if path.name in _WORKSPACE_LOCKS}
    if any(path.name == "npm-shrinkwrap.json" for path in shared_paths):
        selected = {path for path in shared_paths if path.name != "package-lock.json"}
    else:
        selected = shared_paths
    inventory: set[str] = set()
    ambiguous: set[str] = set()
    for path in sorted(selected):
        _merge_source(shared, path, project, edges_only=True)
        try:
            names, collisions = _lock_inventory(path)
            inventory |= names
            ambiguous |= collisions
        except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
            _incomplete(shared, f"{path.name}: inspect lock resolution: {exc}")
    scopes: dict[str, DependencyGraph] = {}
    owners: dict[str, str] = {}
    for member in sorted(members):
        scope = project / member
        local = _load_scope(
            scope, project, recursive=False, skip=shared_paths, locks_edges_only=True
        )
        for note in observations:
            _incomplete(local, note)
        # Workspace package names connect references to another declared
        # member, while its dependencies remain transitive in this scope.
        for filename in members[member]:
            try:
                text = (scope / filename).read_text(encoding="utf-8")
                data = json.loads(text) if filename == "package.json" else tomllib.loads(text)
                name = (
                    data.get("name")
                    if filename == "package.json"
                    else (data.get("project") or {}).get("name")
                )
                if isinstance(name, str) and name:
                    key = _norm(name) if filename == "package.json" else _pep503(name)
                    if key in owners and owners[key] != member:
                        _incomplete(shared, f"{key}: duplicate workspace package names")
                    owners[key] = member
                    inventory.add(key)
                    # A member's development tools are not its exported
                    # production dependencies when another member uses it.
                    for child in local.prod_direct:
                        shared.add_edge(key, child)
            except (OSError, ValueError, TypeError, AttributeError) as exc:
                _incomplete(local, f"{member}/{filename}: read workspace manifest: {exc}")
        scopes[member] = local
    for local in scopes.values():
        local.merge(shared)
        closure = set(local.direct)
        pending = deque(closure)
        while pending:
            for child in local.edges.get(pending.popleft(), set()):
                if child not in closure:
                    closure.add(child)
                    pending.append(child)
        conflicts = closure & ambiguous
        if conflicts:
            _incomplete(
                local,
                "shared lock has ambiguous dependency versions/resolution: "
                + ", ".join(sorted(conflicts)),
            )
        if inventory:
            unresolved = {
                child
                for parent in closure
                for child in local.edges.get(parent, set())
                if child not in inventory and child not in local.direct
            }
            if unresolved:
                _incomplete(
                    local,
                    "shared lock has unresolved dependency edges: " + ", ".join(sorted(unresolved)),
                )
        local.edges = {
            parent: children & closure
            for parent, children in local.edges.items()
            if parent in closure
        }
        local.known_transitive = (local.known_transitive & closure) | (closure - local.direct)
        local.bins = {
            command: packages & closure
            for command, packages in local.bins.items()
            if packages & closure
        }
        aggregate.merge(local)
    aggregate.workspace_graphs = scopes
    return aggregate


def _iter_files(
    project: Path,
    max_depth: int = 3,
    *,
    on_error: Callable[[Path, OSError], None] | None = None,
) -> list[Path]:
    """Manifest files up to ``max_depth`` levels deep (monorepos), skipping vendored dirs."""
    out: list[Path] = []

    def walk(d: Path, depth: int) -> None:
        try:
            entries = sorted(d.iterdir())
        except OSError as exc:
            if on_error:
                on_error(d, exc)
            return
        for e in entries:
            try:
                if e.is_symlink() or not e.resolve().is_relative_to(project.resolve()):
                    if on_error:
                        on_error(e, OSError("symlink or graph source escapes project"))
                    continue
                if e.is_dir():
                    if (
                        depth < max_depth
                        and e.name not in _SKIP_DIRS
                        and not e.name.startswith(".")
                    ):
                        walk(e, depth + 1)
                elif e.is_file():
                    out.append(e)
            except (OSError, RuntimeError) as exc:
                if on_error:
                    on_error(e, exc if isinstance(exc, OSError) else OSError(str(exc)))

    walk(project, 0)
    return out


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------

_NPM_DEP_KEYS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


def _load_package_json(path: Path) -> DependencyGraph:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("package.json must be an object")
    g = DependencyGraph(has_manifest=True)
    for key in _NPM_DEP_KEYS:
        dependencies = data.get(key, {})
        if not isinstance(dependencies, dict) or not all(
            isinstance(name, str) and isinstance(spec, str) for name, spec in dependencies.items()
        ):
            raise ValueError(f"package.json {key} must be a dependency object")
        for name in dependencies:
            g.add_direct(name, dev=key == "devDependencies")
    scripts = data.get("scripts", {})
    if not isinstance(scripts, dict):
        raise ValueError("package.json scripts must be an object")
    for script in scripts.values():
        if isinstance(script, str):
            g.commands |= _command_words(script)
    return g


_WORD = re.compile(r"[A-Za-z0-9@._/-]+")


def _command_words(text: str) -> set[str]:
    """Words of a shell command line, plus the basename of path-like words
    (``./node_modules/.bin/pm2`` -> ``pm2``)."""
    words: set[str] = set()
    for w in _WORD.findall(text):
        words.add(w.lower())
        words.add(w.rsplit("/", 1)[-1].lower())
    return words


def _load_commands_file(path: Path) -> DependencyGraph:
    """Procfile / Dockerfile: only contributes command words."""
    g = DependencyGraph()
    g.commands = _command_words(path.read_text(encoding="utf-8", errors="replace"))
    return g


def _npm_name_from_key(key: str) -> str:
    return key.rsplit("node_modules/", 1)[-1]


def _load_package_lock(path: Path) -> DependencyGraph:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("npm lock must be an object")
    g = DependencyGraph()
    packages: dict[str, Any] = data.get("packages") or {}
    if not isinstance(packages, dict):
        raise ValueError("npm lock packages must be an object")
    if packages:
        root = packages.get("") or {}
        if not isinstance(root, dict):
            raise ValueError("npm lock root must be an object")
        if root:
            g.has_manifest = True
            for key in _NPM_DEP_KEYS:
                for name in root.get(key) or {}:
                    g.add_direct(name, dev=key == "devDependencies")
        for key, info in packages.items():
            if not isinstance(info, dict):
                raise ValueError("npm lock package entries must be objects")
            if not key:
                continue
            parent = info.get("name") or _npm_name_from_key(key)
            bin_field = info.get("bin")
            if isinstance(bin_field, dict):
                for cmd in bin_field:
                    g.bins.setdefault(cmd.lower(), set()).add(_norm(parent))
            elif isinstance(bin_field, str):
                cmd = parent.rsplit("/", 1)[-1].lower()
                g.bins.setdefault(cmd, set()).add(_norm(parent))
            for dep_key in ("dependencies", "optionalDependencies", "peerDependencies"):
                dependencies = info.get(dep_key) or {}
                if not isinstance(dependencies, dict):
                    raise ValueError(f"npm lock {dep_key} must be an object")
                for child in dependencies:
                    g.add_edge(parent, child)
        return g

    # lockfileVersion 1: nested "dependencies" with "requires"
    def walk(deps: dict[str, Any]) -> None:
        if not isinstance(deps, dict):
            raise ValueError("npm lock dependencies must be an object")
        for name, info in deps.items():
            if not isinstance(info, dict):
                raise ValueError("npm lock dependency entries must be objects")
            for child in info.get("requires") or {}:
                g.add_edge(name, child)
            walk(info.get("dependencies") or {})

    walk(data.get("dependencies") or {})
    return g


_YARN_DEP_SECTIONS = ("dependencies", "optionalDependencies", "peerDependencies")
_YARN_HEADER = re.compile(r'^"?(@?[^@"\s,]+)@')


def _load_yarn_lock(path: Path) -> DependencyGraph:
    """yarn.lock v1 and berry: headers at column 0, deps indented under ``dependencies:``."""
    g = DependencyGraph()
    current: str | None = None
    in_deps = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if indent == 0:
            m = _YARN_HEADER.match(line)
            current = m.group(1) if m else None
            in_deps = False
        elif indent == 2:
            in_deps = line.rstrip(":") in _YARN_DEP_SECTIONS
        elif indent >= 4 and in_deps and current:
            name = line.split(":", 1)[0] if ":" in line.split(" ", 1)[0] else line.split(" ", 1)[0]
            g.add_edge(current, name.strip('"'))
    return g


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------

_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _req_name(spec: str) -> str:
    m = _REQ_NAME.match(spec)
    return m.group(1) if m else ""


def _is_group_include(spec: object, groups: dict[str, object]) -> bool:
    """A PEP 735 ``{include-group = "name"}`` entry naming a group that exists.

    Every dependency group is development-only and each one is read on its
    own, so an include adds no package that is not already recorded.
    """
    return (
        isinstance(spec, dict)
        and set(spec) == {"include-group"}
        and isinstance(spec["include-group"], str)
        and spec["include-group"] in groups
    )


def _load_pyproject(path: Path) -> DependencyGraph | None:
    """PEP 621, PEP 735 dependency groups and Poetry.

    Extras (optional-dependencies) ship to users, so they count as production.
    PEP 735 groups and Poetry dev/group dependencies are development-only.
    """
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    entries: list[tuple[str, bool]] = []  # (name, dev)
    project = data.get("project") or {}
    if not isinstance(project, dict):
        raise ValueError("pyproject project must be a table")
    dependencies = project.get("dependencies", [])
    if not isinstance(dependencies, list) or not all(
        isinstance(spec, str) for spec in dependencies
    ):
        raise ValueError("pyproject dependencies must be a string array")
    optional = project.get("optional-dependencies") or {}
    groups = data.get("dependency-groups") or {}
    if not isinstance(optional, dict) or not isinstance(groups, dict):
        raise ValueError("pyproject dependency groups must be tables")
    for group in optional.values():
        if not isinstance(group, list) or not all(isinstance(spec, str) for spec in group):
            raise ValueError("pyproject optional-dependencies entry is malformed")
    for group in groups.values():
        if not isinstance(group, list) or not all(
            isinstance(spec, str) or _is_group_include(spec, groups) for spec in group
        ):
            raise ValueError("pyproject dependency group is malformed or uses unsupported includes")
    entries += [(_req_name(s), False) for s in project.get("dependencies") or []]
    for group in (project.get("optional-dependencies") or {}).values():
        entries += [(_req_name(s), False) for s in group]
    for group in (data.get("dependency-groups") or {}).values():
        entries += [(_req_name(s), True) for s in group if isinstance(s, str)]
    poetry = (data.get("tool") or {}).get("poetry") or {}
    entries += [(n, False) for n in poetry.get("dependencies") or {}]
    entries += [(n, True) for n in poetry.get("dev-dependencies") or {}]
    for grp in (poetry.get("group") or {}).values():
        entries += [(n, True) for n in (grp or {}).get("dependencies") or {}]
    entries = [(n, dev) for n, dev in entries if n and n.lower() != "python"]
    if not entries:
        return DependencyGraph(has_manifest=True) if project else None
    g = DependencyGraph(has_manifest=True)
    for n, dev in entries:
        g.add_direct(n, python=True, dev=dev)
    return g


def _load_pipfile(path: Path) -> DependencyGraph:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    g = DependencyGraph(has_manifest=True)
    for section in ("packages", "dev-packages"):
        for name in data.get(section) or {}:
            g.add_direct(name, python=True, dev=section == "dev-packages")
    return g


def _load_requirements_in(path: Path) -> DependencyGraph:
    g = DependencyGraph(has_manifest=True)
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line and not line.startswith("-"):
            g.add_direct(_req_name(line), python=True)
    return g


def _load_requirements_txt(path: Path) -> DependencyGraph | None:
    """requirements.txt, with pip-compile ``# via`` annotations when present."""
    lines = path.read_text(encoding="utf-8").splitlines()
    reqs: list[str] = []
    via: dict[str, list[str]] = {}
    current: str | None = None
    collecting = False
    for raw in lines:
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            comment = stripped.lstrip("#").strip()
            if current and comment.startswith("via"):
                rest = comment[3:].strip()
                collecting = not rest
                if rest:
                    via.setdefault(current, []).append(rest)
            elif current and collecting and comment:
                via.setdefault(current, []).append(comment)
            continue
        if stripped.startswith("-"):
            current, collecting = None, False
            continue
        spec = stripped.split(" #", 1)[0].strip()
        current = _req_name(spec)
        collecting = False
        if current:
            reqs.append(spec)
            via.setdefault(current, [])

    if not reqs:
        return None

    g = DependencyGraph()
    annotated = any(via.values())
    if annotated:
        g.has_manifest = True
        for name, parents in via.items():
            for p in parents:
                if p.startswith("-r") or p.startswith("-c") or p.endswith((".in", ".toml", ".cfg")):
                    g.add_direct(name, python=True)
                else:
                    g.add_edge(_pep503(_req_name(p)), _pep503(name))
        return g

    if all("==" in r for r in reqs):
        # Looks like `pip freeze`: directness unknown. Contribute nothing.
        return None

    g.has_manifest = True
    for r in reqs:
        g.add_direct(_req_name(r), python=True)
    return g


def _uv_names(entries: object) -> list[str]:
    return [e["name"] for e in entries or [] if isinstance(e, dict) and e.get("name")]  # type: ignore[attr-defined]


def _load_uv_lock(path: Path) -> DependencyGraph:
    """uv.lock: every package lists its dependencies; workspace roots are direct.

    Roots are the packages whose ``source`` is the project itself
    (``virtual`` or ``editable``). Their ``dependencies`` and
    ``optional-dependencies`` (extras) ship to users; ``dev-dependencies``
    (PEP 735 groups) are development-only.
    """
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    g = DependencyGraph()
    for pkg in data.get("package") or []:
        name = pkg.get("name", "")
        source = pkg.get("source") or {}
        prod = _uv_names(pkg.get("dependencies"))
        for extra in (pkg.get("optional-dependencies") or {}).values():
            prod += _uv_names(extra)
        dev: list[str] = []
        for group in (pkg.get("dev-dependencies") or {}).values():
            dev += _uv_names(group)
        if "virtual" in source or "editable" in source:
            g.has_manifest = True
            for d in prod:
                g.add_direct(d, python=True)
            for d in dev:
                g.add_direct(d, python=True, dev=True)
        for d in prod + dev:
            g.add_edge(_pep503(name), _pep503(d))
    return g


def _load_poetry_lock(path: Path) -> DependencyGraph:
    """poetry.lock: edges only. Direct dependencies come from pyproject.toml."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    g = DependencyGraph()
    for pkg in data.get("package") or []:
        for dep in pkg.get("dependencies") or {}:
            g.add_edge(_pep503(pkg.get("name", "")), _pep503(dep))
    return g


# ---------------------------------------------------------------------------
# Rust, Ruby, PHP, .NET, Dart, Go, Maven
# ---------------------------------------------------------------------------


def _load_cargo_lock(path: Path) -> DependencyGraph:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    g = DependencyGraph()
    for pkg in data.get("package") or []:
        name = pkg.get("name", "")
        deps = [d.split(" ", 1)[0] for d in pkg.get("dependencies") or []]
        if "source" not in pkg:  # local workspace crate: its deps are direct
            g.has_manifest = True
            for d in deps:
                g.add_direct(d)
        for d in deps:
            g.add_edge(name, d)
    return g


_GEM_LINE = re.compile(r"^(\s*)([A-Za-z0-9_.-]+)(?:\s|!|$)")


def _load_gemfile_lock(path: Path) -> DependencyGraph:
    g = DependencyGraph()
    section = ""
    in_specs = False
    current: str | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw and not raw.startswith(" "):
            section = raw.strip()
            in_specs = False
            continue
        if raw.strip() == "specs:":
            in_specs = True
            continue
        m = _GEM_LINE.match(raw)
        if not m:
            continue
        indent, name = len(m.group(1)), m.group(2)
        if section == "DEPENDENCIES" and indent == 2:
            g.has_manifest = True
            g.add_direct(name)
        elif in_specs and indent == 4:
            current = name
        elif in_specs and indent == 6 and current:
            g.add_edge(current, name)
    return g


def _composer_real(name: str) -> bool:
    return "/" in name  # skips "php", "ext-json", "lib-icu"


def _load_composer_json(path: Path) -> DependencyGraph:
    data = json.loads(path.read_text(encoding="utf-8"))
    g = DependencyGraph(has_manifest=True)
    for key in ("require", "require-dev"):
        for name in data.get(key) or {}:
            if _composer_real(name):
                g.add_direct(name, dev=key == "require-dev")
    return g


def _load_composer_lock(path: Path) -> DependencyGraph:
    data = json.loads(path.read_text(encoding="utf-8"))
    g = DependencyGraph()
    for key in ("packages", "packages-dev"):
        for pkg in data.get(key) or []:
            for child in pkg.get("require") or {}:
                if _composer_real(child):
                    g.add_edge(pkg.get("name", ""), child)
    return g


def _load_nuget_lock(path: Path) -> DependencyGraph:
    data = json.loads(path.read_text(encoding="utf-8"))
    g = DependencyGraph()
    for framework in (data.get("dependencies") or {}).values():
        for name, info in (framework or {}).items():
            kind = (info or {}).get("type", "")
            if kind == "Direct":
                g.has_manifest = True
                g.add_direct(name)
            elif kind == "Transitive":
                g.known_transitive.add(_norm(name))
            for child in (info or {}).get("dependencies") or {}:
                g.add_edge(name, child)
    return g


def _load_pubspec_lock(path: Path) -> DependencyGraph:
    g = DependencyGraph()
    current: str | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        if re.match(r"^  [A-Za-z0-9_]+:\s*$", raw):
            current = raw.strip().rstrip(":")
            continue
        m = re.match(r'^    dependency:\s*"?([^"]+)"?', raw)
        if m and current:
            kind = m.group(1).strip()
            if kind.startswith("direct"):
                g.has_manifest = True
                g.add_direct(current)
            elif kind == "transitive":
                g.known_transitive.add(_norm(current))
    return g


def _load_go_mod(path: Path) -> DependencyGraph:
    g = DependencyGraph(has_manifest=True)
    in_block = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require "):
            line = line[len("require ") :]
        elif not in_block:
            continue
        if not line or line.startswith("//"):
            continue
        module = line.split()[0]
        if "// indirect" in line:
            g.known_transitive.add(_norm(module))
        else:
            g.add_direct(module)
    return g


def _load_pom(path: Path) -> DependencyGraph:
    root = ET.parse(path).getroot()
    ns = root.tag.split("}", 1)[0] + "}" if root.tag.startswith("{") else ""
    g = DependencyGraph(has_manifest=True)
    for dep in root.iter(f"{ns}dependency"):
        group = dep.findtext(f"{ns}groupId") or ""
        artifact = dep.findtext(f"{ns}artifactId") or ""
        if group and artifact:
            g.add_direct(f"{group}:{artifact}")
    return g


_LOADERS: dict[str, Any] = {
    "package.json": _load_package_json,
    "package-lock.json": _load_package_lock,
    "npm-shrinkwrap.json": _load_package_lock,
    "yarn.lock": _load_yarn_lock,
    "pyproject.toml": _load_pyproject,
    "Pipfile": _load_pipfile,
    "requirements.in": _load_requirements_in,
    "uv.lock": _load_uv_lock,
    "poetry.lock": _load_poetry_lock,
    "Cargo.lock": _load_cargo_lock,
    "Gemfile.lock": _load_gemfile_lock,
    "composer.json": _load_composer_json,
    "composer.lock": _load_composer_lock,
    "packages.lock.json": _load_nuget_lock,
    "pubspec.lock": _load_pubspec_lock,
    "go.mod": _load_go_mod,
    "pom.xml": _load_pom,
    "Procfile": _load_commands_file,
    "Dockerfile": _load_commands_file,
}
