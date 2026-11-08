"""Scan a clean, pinned local upstream checkout against frozen audit bytes.

The caller supplies --source-dir. This harness never clones repositories,
installs dependencies, runs upstream code, or makes scanner/network requests.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from depquiet import pynames
from depquiet.cli import _print_json
from depquiet.engine import scan

REPO_ROOT = Path(__file__).resolve().parents[2]
EXCLUDED = {".git", "node_modules"}
IDENTITY = ("package", "version", "advisory")


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    return value


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _json(raw: bytes) -> Any:
    def unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=unique_keys)


def _relative(value: Any, name: str) -> PurePosixPath:
    text = _text(value, name)
    path = PurePosixPath(text)
    if (
        path.is_absolute()
        or ".." in path.parts
        or not path.parts
        or "\\" in text
        or ":" in text
        or any(ord(char) < 32 for char in text)
    ):
        raise ValueError(f"{name} must be a safe repository-relative POSIX path")
    return path


def _frozen_file(spec: Any, repo_root: Path, name: str) -> tuple[dict[str, str], bytes]:
    spec = _object(spec, name)
    relative = _relative(spec.get("path"), f"{name}.path")
    if relative.parts[:2] != ("benchmarks", "fixtures"):
        raise ValueError(f"{name}.path must be within benchmarks/fixtures")
    root = repo_root.resolve(strict=True)
    fixtures = (root / "benchmarks" / "fixtures").resolve(strict=True)
    path = root.joinpath(*relative.parts).resolve(strict=True)
    if not fixtures.is_relative_to(root) or not path.is_relative_to(fixtures) or not path.is_file():
        raise ValueError(f"{name}.path escapes the repository fixture directory")
    expected = _text(spec.get("sha256"), f"{name}.sha256").lower()
    if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        raise ValueError(f"{name}.sha256 must be a SHA-256 hex digest")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError(f"{name} SHA-256 mismatch")
    return {"path": relative.as_posix(), "sha256": expected}, raw


def _git(source: Path, *args: str, data: bytes | None = None) -> bytes:
    options = ["-c", "core.fsmonitor=false", "-c", f"core.hooksPath={os.devnull}"]
    if args and args[0] == "status":
        # status may run clean/process helpers while refreshing the index. Read
        # configuration without invoking helpers, then disable every filter.
        prefixes = {
            key.rsplit(".", 1)[0]
            for key in _config_keys(source)
            if key.lower().startswith("filter.")
            and key.lower().endswith((".clean", ".smudge", ".process", ".required"))
        }
        for prefix in sorted(prefixes):
            for name, value in (
                ("clean", ""),
                ("smudge", ""),
                ("process", ""),
                ("required", "false"),
            ):
                options.extend(("-c", f"{prefix}.{name}={value}"))
    result = subprocess.run(
        ["git", *options, "-C", str(source), *args],
        input=data,
        capture_output=True,
        env={
            **os.environ,
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1",
        },
        timeout=60,
    )
    if result.returncode:
        raise ValueError(
            "git verification failed: " + result.stderr.decode("utf-8", "replace").strip()
        )
    return result.stdout


def _config_keys(source: Path) -> list[str]:
    keys = _git(source, "config", "--null", "--name-only", "--list").decode("utf-8").split("\0")
    if any("=" in key or any(ord(char) < 32 for char in key) for key in keys):
        raise ValueError("source Git config contains unsupported key characters")
    return [key for key in keys if key]


def _verify_source(source: Path, commit: str) -> None:
    # Do not permit implicit object downloads, including on older Git versions
    # that may not recognize GIT_NO_LAZY_FETCH. Ordinary shallow clones are fine.
    if any(
        key.lower() == "extensions.partialclone"
        or (key.lower().startswith("remote.") and key.lower().endswith(".promisor"))
        for key in _config_keys(source)
    ):
        raise ValueError("partial/promisor source clones are unsupported; use a complete checkout")
    top = Path(_git(source, "rev-parse", "--show-toplevel").decode("utf-8").strip()).resolve()
    if top != source:
        raise ValueError("--source-dir must name the checkout root")
    actual = _git(source, "rev-parse", "--verify", "HEAD").decode("ascii").strip().lower()
    if actual != commit:
        raise ValueError(f"source HEAD mismatch: expected {commit}, found {actual}")
    if _git(source, "status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=all"):
        raise ValueError("source checkout is dirty (tracked, staged or untracked changes)")


def _materialize(source: Path, commit: str, project: Path) -> None:
    """Copy commit blobs, never ignored worktree files or checkout filters."""
    entries: list[tuple[PurePosixPath, bytes]] = []
    portable_paths: set[str] = set()
    for record in _git(source, "ls-tree", "-r", "-z", "--full-tree", commit).split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, kind, oid = metadata.split(b" ")
        relative = _relative(raw_path.decode("utf-8"), "source tree path")
        if any(part.casefold() in EXCLUDED for part in relative.parts):
            continue
        if mode not in {b"100644", b"100755"} or kind != b"blob":
            raise ValueError(f"source contains unsupported symlink or submodule: {relative}")
        portable = relative.as_posix().casefold()
        if portable in portable_paths:
            raise ValueError(f"source contains paths that collide on Windows: {relative}")
        portable_paths.add(portable)
        entries.append((relative, oid))
    if not entries:
        raise ValueError("source commit contains no materializable project files")
    objects = _git(source, "cat-file", "--batch", data=b"".join(oid + b"\n" for _, oid in entries))
    offset = 0
    for relative, expected_oid in entries:
        end = objects.index(b"\n", offset)
        oid, kind, size = objects[offset:end].split(b" ")
        length = int(size)
        offset = end + 1
        content = objects[offset : offset + length]
        if oid != expected_oid or kind != b"blob" or len(content) != length:
            raise ValueError("git returned an incomplete or unexpected source object")
        offset += length
        if objects[offset : offset + 1] != b"\n":
            raise ValueError("git returned malformed source object data")
        offset += 1
        target = project.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)


def _stable_paths(value: Any, temporary_project: Path, project_id: str) -> Any:
    """Keep evidence paths useful without leaking temporary checkout locations."""
    if isinstance(value, dict):
        return {
            key: _stable_paths(item, temporary_project, project_id) for key, item in value.items()
        }
    if isinstance(value, list):
        return [_stable_paths(item, temporary_project, project_id) for item in value]
    if isinstance(value, str):
        for prefix in {str(temporary_project), temporary_project.as_posix()}:
            if value.startswith((prefix + "/", prefix + "\\")):
                return value[len(prefix) + 1 :].replace("\\", "/")
            value = value.replace(prefix, project_id)
    return value


def _selection(snapshot: dict[str, Any]) -> list[dict[str, str]] | None:
    if "selection" not in snapshot:
        return None
    rows = snapshot["selection"]
    if not isinstance(rows, list) or not rows:
        raise ValueError("snapshot.selection must be a non-empty array when present")
    identities: list[dict[str, str]] = []
    seen: set[tuple[str, ...]] = set()
    for index, row in enumerate(rows):
        item = _object(row, f"selection {index}")
        identity = {
            field: _text(item.get(field), f"selection {index}.{field}") for field in IDENTITY
        }
        key = tuple(identity[field] for field in IDENTITY)
        if key in seen:
            raise ValueError("snapshot.selection contains a duplicate identity")
        seen.add(key)
        identities.append(identity)
    return identities


def run_snapshot(
    snapshot_path: Path, source_dir: Path, *, repo_root: Path = REPO_ROOT
) -> dict[str, Any]:
    raw_snapshot = snapshot_path.read_bytes()
    snapshot = _object(_json(raw_snapshot), "snapshot")
    if type(snapshot.get("schema_version")) is not int or snapshot["schema_version"] != 1:
        raise ValueError("snapshot.schema_version must be 1")
    if snapshot.get("kind") != "upstream_reference":
        raise ValueError("snapshot.kind must be upstream_reference")
    project_id = _text(snapshot.get("project"), "snapshot.project")
    source_spec = _object(snapshot.get("source"), "snapshot.source")
    repository = _text(source_spec.get("repository"), "snapshot.source.repository")
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None:
        raise ValueError("snapshot.source.repository must be owner/name")
    commit = _text(source_spec.get("commit"), "snapshot.source.commit").lower()
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ValueError("snapshot.source.commit must be a full 40-character Git revision")
    source = source_dir.resolve(strict=True)
    _verify_source(source, commit)
    audit_spec, raw_audit = _frozen_file(snapshot.get("audit"), repo_root, "audit")
    audit_json = _json(raw_audit)
    if isinstance(audit_json, list):
        audit_json = {"alerts": audit_json}
    audit_json = _object(audit_json, "frozen audit JSON")
    selection = _selection(snapshot)
    overlays = snapshot.get("overlay_files", [])
    if not isinstance(overlays, list):
        raise ValueError("snapshot.overlay_files must be an array")
    frozen_overlays: list[tuple[dict[str, str], PurePosixPath, bytes]] = []
    targets: set[str] = set()
    for index, item in enumerate(overlays):
        spec, content = _frozen_file(item, repo_root, f"overlay {index}")
        target = _relative(item.get("target"), f"overlay {index}.target")
        portable_target = target.as_posix().casefold()
        if any(part.casefold() in EXCLUDED for part in target.parts) or portable_target in targets:
            raise ValueError("overlay targets cannot be excluded directories or duplicates")
        targets.add(portable_target)
        frozen_overlays.append(({**spec, "target": target.as_posix()}, target, content))
    with tempfile.TemporaryDirectory(prefix="depquiet-upstream-reference-") as directory:
        project = Path(directory)
        _materialize(source, commit, project)
        for _, target, content in frozen_overlays:
            path = project.joinpath(*target.parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        # The host interpreter is not part of the frozen input. Keep project
        # metadata from committed blobs, but exclude host-only module aliases.
        with patch.object(pynames, "_running_environment", return_value={}):
            result = scan(project, audit_json=audit_json, skip_epss=True)
        result.project_path = project_id
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            _print_json(result)
        report = _stable_paths(json.loads(output.getvalue()), project, project_id)
    full_summary = dict(report["summary"])
    full_rows = report["results"]
    if selection is not None:
        selected = {tuple(item[field] for field in IDENTITY) for item in selection}
        report["results"] = [
            item
            for item in full_rows
            if (item["package"], item["version"], item["cve"]) in selected
        ]
        rows = report["results"]
        filtered = sum(item["verdict"] == "filtered" for item in rows)
        report["summary"] = {
            "total": len(rows),
            "action": sum(item["verdict"] == "action" for item in rows),
            "review": sum(item["verdict"] == "review" for item in rows),
            "filtered": filtered,
            "filter_rate": round(filtered / len(rows) * 100, 1) if rows else 0,
        }
    report["snapshot_sha256"] = hashlib.sha256(raw_snapshot).hexdigest()
    report["reference_context"] = {
        "kind": "upstream_reference",
        "source": {"repository": repository, "commit": commit},
        "audit": audit_spec,
        "overlay_files": [spec for spec, _, _ in frozen_overlays],
        "materialization": "git_commit_blobs",
        "source_worktree_verified_clean": True,
        "host_python_metadata_excluded": True,
        "excluded_directories": sorted(EXCLUDED),
    }
    report["evaluation_scope"] = {
        "type": "selected_advisory_contexts" if selection is not None else "full_frozen_audit",
        "selection": selection,
        "selected_result_rows": len(report["results"]),
        "unselected_result_rows": len(full_rows) - len(report["results"]),
        "full_scan_summary": full_summary,
    }
    return report


def main(argv: list[str] | None = None, *, repo_root: Path = REPO_ROOT) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=(
            "Prepare the exact revision separately with git clone/checkout; "
            "no downloads are automatic."
        ),
    )
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument(
        "--source-dir", type=Path, required=True, help="Root of the clean pinned Git checkout"
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = run_snapshot(args.snapshot, args.source_dir, repo_root=repo_root)
        output = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(output, encoding="utf-8", newline="\n")
        else:
            print(output, end="")
    except (OSError, UnicodeError, ValueError, TypeError, subprocess.TimeoutExpired) as exc:
        print(f"Invalid upstream reference: {exc}", file=sys.stderr)
        return 2
    return 0 if report["scanned"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
