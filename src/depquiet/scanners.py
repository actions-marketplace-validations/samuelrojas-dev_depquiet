"""Run the scanners depquiet invokes itself, and fail loudly when they can't.

A scanner that isn't installed, can't reach its database, or returns an error
must never look like "no vulnerabilities". Each runner here returns the
scanner's report or raises :class:`ScanError`; the engine then tries the
OSV.dev fallback and, if that fails too, reports the project as not scanned.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import tomllib
from pathlib import Path
from typing import Any


class ScanError(Exception):
    """The scanner couldn't produce a report. The message says why and what to do."""


def _tail(text: str, limit: int = 300) -> str:
    text = " ".join(text.split())
    return text[-limit:] if text else "no output"


def run_npm_audit(project: Path) -> dict[str, Any]:
    if shutil.which("npm") is None:
        raise ScanError("npm is not installed or not on PATH.")
    try:
        r = subprocess.run(
            ["npm", "audit", "--json"], cwd=project, capture_output=True, text=True, timeout=180
        )
    except subprocess.TimeoutExpired as e:
        raise ScanError("npm audit timed out after 180 s.") from e
    try:
        data = json.loads(r.stdout) if r.stdout else {}
    except json.JSONDecodeError as e:
        raise ScanError(f"npm audit returned invalid JSON: {_tail(r.stderr or r.stdout)}") from e
    if not isinstance(data, dict) or "error" in data or "vulnerabilities" not in data:
        err = data.get("error") if isinstance(data, dict) else None
        summary = err.get("summary") if isinstance(err, dict) else None
        raise ScanError(f"npm audit failed: {summary or _tail(r.stderr)}")
    return data


def lock_pins(lockfile: Path) -> tuple[list[str], list[str]]:
    """``name==version`` for every registry package in a uv.lock / poetry.lock.

    Local, path and git packages are skipped (nothing to look up). When a
    lockfile pins one name to several versions (platform markers, e.g. torch
    cpu/cuda), pip-audit rejects the duplicates, so only the first is kept and
    the rest are returned as dropped.
    """
    data = tomllib.loads(lockfile.read_text(encoding="utf-8"))
    pins: dict[str, str] = {}
    dropped: list[str] = []
    for pkg in data.get("package") or []:
        source = pkg.get("source") or {}
        if any(k in source for k in ("virtual", "editable", "directory", "path", "git")):
            continue
        if source.get("type") in ("directory", "git", "file", "url"):
            continue
        name, version = pkg["name"].lower(), pkg["version"]
        if name in pins:
            if pins[name] != version:
                dropped.append(f"{name}=={version}")
            continue
        pins[name] = version
    return [f"{n}=={v}" for n, v in sorted(pins.items())], dropped


def run_pip_audit(project: Path) -> dict[str, Any]:
    """Audit the *project's* dependencies, never the environment depquiet runs in.

    uv.lock / poetry.lock: every pinned version, without resolving or installing
    (``--no-deps --disable-pip``). requirements.txt: pip-audit resolves it.
    pyproject.toml only: pip-audit resolves the local project.
    """
    if shutil.which("pip-audit") is None:
        raise ScanError("pip-audit is not installed (pip install pip-audit).")
    with tempfile.TemporaryDirectory() as tmp:
        lock = next(
            (project / n for n in ("uv.lock", "poetry.lock") if (project / n).exists()), None
        )
        if lock is not None:
            try:
                pins, _ = lock_pins(lock)
            except (ValueError, KeyError, OSError) as e:
                raise ScanError(f"could not read {lock.name}: {e}") from e
            req = Path(tmp) / "requirements.txt"
            req.write_text("\n".join(pins) + "\n")
            target = ["-r", str(req), "--no-deps", "--disable-pip"]
        elif (project / "requirements.txt").exists():
            target = ["-r", str(project / "requirements.txt")]
        elif (project / "pyproject.toml").exists():
            target = [str(project)]
        else:
            raise ScanError("no uv.lock, poetry.lock, requirements.txt or pyproject.toml to audit.")
        out = Path(tmp) / "audit.json"
        cmd = ["pip-audit", *target, "-f", "json", "--progress-spinner", "off", "-o", str(out)]
        try:
            r = subprocess.run(cmd, cwd=project, capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired as e:
            raise ScanError("pip-audit timed out after 600 s.") from e
        try:
            data = json.loads(out.read_text()) if out.exists() else None
        except json.JSONDecodeError:
            data = None
    if not isinstance(data, dict) or "dependencies" not in data:
        raise ScanError(f"pip-audit failed: {_tail(r.stderr)}")
    return data
