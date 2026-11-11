"""Bounded, read-only discovery of explicitly declared npm and uv members."""

from __future__ import annotations

import fnmatch
import json
import stat
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_MAX_PATTERNS = 128
_MAX_DIRECTORIES = 20000
_MAX_MEMBERS = 4096


@dataclass
class WorkspaceDiscovery:
    declared: bool = False
    members: dict[str, set[str]] = field(default_factory=lambda: {".": set()})
    observations: list[str] = field(default_factory=list)


def _patterns(raw: Any, label: str, result: WorkspaceDiscovery) -> list[str]:
    if not isinstance(raw, list) or len(raw) > _MAX_PATTERNS:
        result.observations.append(f"{label}: expected at most {_MAX_PATTERNS} relative patterns")
        return []
    valid: list[str] = []
    for pattern in raw:
        if isinstance(pattern, str):
            # ``./packages/*`` is ``packages/*``, and ``.`` names the root
            # project, which is always a scope of its own.
            while pattern.startswith("./"):
                pattern = pattern[2:]
            if pattern == ".":
                continue
        if (
            not isinstance(pattern, str)
            or not pattern
            or len(pattern) > 512
            or any(ord(char) < 32 for char in pattern)
            or any(char in pattern for char in "\\:![]{}()")
            or pattern.startswith("/")
            or any(part in {"", ".", ".."} for part in pattern.split("/"))
            or len(pattern.split("/")) > 64
            or any("**" in part and part != "**" for part in pattern.split("/"))
        ):
            result.observations.append(
                f"{label}: unsupported or unsafe workspace pattern {pattern!r}"
            )
        else:
            valid.append(pattern)
    return valid


def _expand(root: Path, pattern: str, observations: list[str]) -> set[str]:
    parts = pattern.split("/")
    matches: set[str] = set()
    visited: set[tuple[Path, int]] = set()

    def directories(path: Path) -> list[Path]:
        try:
            entries = sorted(path.iterdir())
        except OSError as exc:
            observations.append(f"{path.relative_to(root).as_posix()}: enumerate workspace: {exc}")
            return []
        out: list[Path] = []
        for entry in entries:
            try:
                metadata = entry.lstat()
                if stat.S_ISLNK(metadata.st_mode):
                    # Do not follow even in-tree links: they can alias members
                    # and make the same sources belong to multiple scopes.
                    out.append(entry)
                elif stat.S_ISDIR(metadata.st_mode):
                    out.append(entry)
            except OSError as exc:
                observations.append(
                    f"{entry.relative_to(root).as_posix()}: inspect workspace: {exc}"
                )
        return out

    def walk(path: Path, index: int) -> None:
        if len(path.relative_to(root).parts) > 128:
            observations.append(f"{pattern!r}: workspace directory depth limit exceeded")
            return
        marker = (path, index)
        if marker in visited:
            return
        if len(visited) >= _MAX_DIRECTORIES:
            if not any("directory limit" in note for note in observations):
                observations.append(f"{pattern!r}: workspace directory limit exceeded")
            return
        visited.add(marker)
        try:
            resolved = path.resolve(strict=True)
            if path.is_symlink() or not resolved.is_relative_to(root) or resolved != path:
                observations.append(
                    f"{path.relative_to(root).as_posix()}: workspace symlink or escape"
                )
                return
        except (OSError, RuntimeError) as exc:
            observations.append(f"{path.relative_to(root).as_posix()}: resolve workspace: {exc}")
            return
        if index == len(parts):
            matches.add(path.relative_to(root).as_posix())
            return
        token = parts[index]
        if token == "**":
            walk(path, index + 1)
        for child in directories(path):
            if token == "**":
                if child.name in {".git", "node_modules", ".venv", "venv"}:
                    observations.append(
                        f"{child.relative_to(root).as_posix()}: workspace traversal excluded"
                    )
                    continue
                walk(child, index)
            elif fnmatch.fnmatchcase(child.name, token):
                walk(child, index + 1)

    walk(root, 0)
    return matches


def discover_workspaces(project: Path) -> WorkspaceDiscovery:
    """Discover declarations, preserving every unsupported/unreadable boundary."""
    root = project.resolve()
    result = WorkspaceDiscovery()
    declarations: list[tuple[str, list[str], list[str]]] = []
    for filename in ("package.json", "pyproject.toml"):
        path = root / filename
        try:
            text = path.read_text(encoding="utf-8")
            data = json.loads(text) if filename == "package.json" else tomllib.loads(text)
            if not isinstance(data, dict):
                raise ValueError("manifest must be an object")
            if filename == "package.json" and "workspaces" in data:
                result.declared = True
                raw = data["workspaces"]
                if isinstance(raw, dict):
                    raw = raw.get("packages")
                declarations.append((filename, _patterns(raw, filename, result), []))
            if filename == "pyproject.toml":
                workspace = (data.get("tool") or {}).get("uv", {}).get("workspace")
                if workspace is not None:
                    result.declared = True
                    if not isinstance(workspace, dict):
                        raise ValueError("tool.uv.workspace must be a table")
                    members = _patterns(workspace.get("members", []), filename, result)
                    excludes = _patterns(workspace.get("exclude", []), filename, result)
                    declarations.append((filename, members, excludes))
        except FileNotFoundError:
            continue
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            result.observations.append(f"{filename}: read workspace declaration: {exc}")
    for filename, members, excludes in declarations:
        result.members["."].add(filename)
        excluded: set[str] = set()
        for pattern in excludes:
            excluded |= _expand(root, pattern, result.observations)
        for pattern in members:
            matches = _expand(root, pattern, result.observations)
            if not matches:
                result.observations.append(
                    f"{filename}: workspace pattern {pattern!r} matched no directories"
                )
            for member in sorted(matches - excluded):
                if len(result.members) >= _MAX_MEMBERS and member not in result.members:
                    result.observations.append(f"{filename}: workspace member limit exceeded")
                    break
                result.members.setdefault(member, set()).add(filename)
                manifest = root / member / filename
                try:
                    if not manifest.is_file():
                        result.observations.append(
                            f"{member}/{filename}: workspace manifest missing"
                        )
                except OSError as exc:
                    result.observations.append(
                        f"{member}/{filename}: inspect workspace manifest: {exc}"
                    )
    return result
