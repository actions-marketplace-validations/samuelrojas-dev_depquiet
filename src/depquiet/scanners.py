"""Run the scanners depquiet invokes itself, and fail loudly when they can't.

A scanner that isn't installed, can't reach its database, or returns an error
must never look like "no vulnerabilities". Each runner here returns the
scanner's report or raises :class:`ScanError`; the engine then tries the
OSV.dev fallback and, if that fails too, reports the project as not scanned.
"""

from __future__ import annotations

import json
import re
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
    project = project.resolve()
    executable = shutil.which("npm")
    if executable is None:
        raise ScanError("npm is not installed or not on PATH.")
    try:
        r = subprocess.run(
            [executable, "audit", "--json"],
            cwd=project,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
        )
    except subprocess.TimeoutExpired as e:
        raise ScanError("npm audit timed out after 180 s.") from e
    except OSError as e:
        raise ScanError(f"could not run npm audit: {e}") from e
    try:
        data = json.loads(r.stdout) if r.stdout else {}
    except json.JSONDecodeError as e:
        raise ScanError(f"npm audit returned invalid JSON: {_tail(r.stderr or r.stdout)}") from e
    if (
        r.returncode not in (0, 1)
        or not isinstance(data, dict)
        or "error" in data
        or not isinstance(data.get("vulnerabilities"), dict)
    ):
        err = data.get("error") if isinstance(data, dict) else None
        summary = err.get("summary") if isinstance(err, dict) else None
        raise ScanError(f"npm audit failed: {summary or _tail(r.stderr)}")
    return data


def run_pnpm_audit(project: Path) -> dict[str, Any]:
    project = project.resolve()
    executable = shutil.which("pnpm")
    if executable is None:
        raise ScanError("pnpm is not installed or not on PATH.")
    try:
        r = subprocess.run(
            [executable, "audit", "--json"],
            cwd=project,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
        )
    except subprocess.TimeoutExpired as e:
        raise ScanError("pnpm audit timed out after 180 s.") from e
    except OSError as e:
        raise ScanError(f"could not run pnpm audit: {e}") from e
    try:
        data = json.loads(r.stdout) if r.stdout else {}
    except json.JSONDecodeError as e:
        raise ScanError(f"pnpm audit returned invalid JSON: {_tail(r.stderr or r.stdout)}") from e
    if (
        r.returncode not in (0, 1)
        or not isinstance(data, dict)
        or "error" in data
        or not isinstance(data.get("advisories"), dict)
    ):
        err = data.get("error") if isinstance(data, dict) else None
        message = err.get("message") if isinstance(err, dict) else None
        raise ScanError(f"pnpm audit failed: {message or _tail(r.stderr)}")
    return data


def lock_pins(lockfile: Path) -> tuple[list[str], list[str]]:
    """``name==version`` for every registry package in a uv.lock / poetry.lock.

    Local, path and git packages are skipped (nothing to look up). When a
    lockfile pins one name to several versions (platform markers, e.g. torch
    cpu/cuda), pip-audit rejects the duplicates, so the first pins and additional
    variants are returned separately. Callers must audit both lists.
    """
    data = tomllib.loads(lockfile.read_text(encoding="utf-8"))
    pins: dict[str, str] = {}
    variants: list[str] = []
    seen: set[str] = set()
    for pkg in data.get("package") or []:
        source = pkg.get("source") or {}
        if any(k in source for k in ("virtual", "editable", "directory", "path", "git")):
            continue
        if source.get("type") in ("directory", "git", "file", "url"):
            continue
        name, version = re.sub(r"[-_.]+", "-", pkg["name"]).lower(), pkg["version"]
        pin = f"{name}=={version}"
        if pin in seen:
            continue
        seen.add(pin)
        if name in pins:
            variants.append(pin)
            continue
        pins[name] = version
    return [f"{n}=={v}" for n, v in sorted(pins.items())], variants


def _pin_batches(pins: list[str]) -> list[list[str]]:
    """Keep each locked version, with at most one version per name per audit."""
    batches: list[list[str]] = []
    names: list[set[str]] = []
    for pin in pins:
        name = pin.split("==", 1)[0]
        for batch, batch_names in zip(batches, names, strict=True):
            if name not in batch_names:
                batch.append(pin)
                batch_names.add(name)
                break
        else:
            batches.append([pin])
            names.append({name})
    return batches


def run_pip_audit(project: Path) -> dict[str, Any]:
    """Audit the *project's* dependencies, never the environment depquiet runs in.

    uv.lock / poetry.lock: every pinned version, without resolving or installing
    (``--no-deps --disable-pip``). requirements.txt: pip-audit resolves it.
    pyproject.toml only: pip-audit resolves the local project.
    """
    project = project.resolve()
    executable = shutil.which("pip-audit")
    if executable is None:
        raise ScanError("pip-audit is not installed (pip install pip-audit).")
    with tempfile.TemporaryDirectory() as tmp:
        targets: list[list[str]] = []
        lock = next(
            (project / n for n in ("uv.lock", "poetry.lock") if (project / n).exists()), None
        )
        if lock is not None:
            try:
                pins, variants = lock_pins(lock)
            except (ValueError, KeyError, OSError) as e:
                raise ScanError(f"could not read {lock.name}: {e}") from e
            batches = _pin_batches(pins + variants)
            if not batches:
                raise ScanError(f"found no registry packages to audit in {lock.name}.")
            for i, batch in enumerate(batches):
                req = Path(tmp) / f"requirements-{i}.txt"
                req.write_text("\n".join(batch) + "\n", encoding="utf-8")
                targets.append(["-r", str(req), "--no-deps", "--disable-pip"])
        elif (project / "requirements.txt").exists():
            targets.append(["-r", str(project / "requirements.txt")])
        elif (project / "pyproject.toml").exists():
            targets.append([str(project)])
        else:
            raise ScanError("no uv.lock, poetry.lock, requirements.txt or pyproject.toml to audit.")
        report: dict[str, Any] = {"dependencies": []}
        for i, target in enumerate(targets):
            out = Path(tmp) / f"audit-{i}.json"
            cmd = [executable, *target, "-f", "json", "--progress-spinner", "off", "-o", str(out)]
            try:
                r = subprocess.run(
                    cmd,
                    cwd=project,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=600,
                )
            except subprocess.TimeoutExpired as e:
                raise ScanError("pip-audit timed out after 600 s.") from e
            except OSError as e:
                raise ScanError(f"could not run pip-audit: {e}") from e
            try:
                data = json.loads(out.read_text(encoding="utf-8")) if out.exists() else None
            except (ValueError, OSError):
                data = None
            if (
                r.returncode not in (0, 1)
                or not isinstance(data, dict)
                or not isinstance(data.get("dependencies"), list)
            ):
                raise ScanError(f"pip-audit failed: {_tail(r.stderr)}")
            if i == 0:
                report = data
            else:
                report["dependencies"].extend(data["dependencies"])
        return report
