"""Ask uv's resolver whether each suggested fix can actually be installed.

A scanner says "update opentelemetry-api to 1.45.1". Whether that works
depends on everything else the project pins: on saleor it does not, because
saleor pins ``opentelemetry-semantic-conventions<0.59``, which requires
``opentelemetry-api==1.37.0``; and ``oauthlib 4.0.1`` is newer than saleor's own
``exclude-newer-package`` cut-off. ``uv lock --dry-run --upgrade-package
pkg==version`` answers that with uv's own resolver and writes nothing.

Opt-in (``--check-fixes``): one resolution per package, with network access
to the package index.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from depquiet.models import ScanResult, Verdict

_PYTHON_MANAGERS = {"uv", "pip"}


@dataclass
class FixCheck:
    """The resolver's answer for one package upgrade."""

    status: str  # "resolves", "blocked" or "error"
    package: str
    version: str
    detail: str = ""

    @property
    def command(self) -> str:
        return f"uv lock --upgrade-package {self.package}=={self.version}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "package": self.package,
            "version": self.version,
            "command": self.command,
            "detail": self.detail,
        }


def _version_key(version: str) -> tuple[Any, ...]:
    """Order release numbers well enough to pick the highest fix (4.2.1 > 4.0.9)."""
    parts: list[Any] = []
    for piece in re.split(r"[.+-]", version):
        parts.append((0, int(piece)) if piece.isdigit() else (1, piece))
    return tuple(parts)


def fix_targets(result: ScanResult) -> dict[str, str]:
    """Package -> the highest fixed version among its alerts still shown."""
    targets: dict[str, str] = {}
    for finding in result.results:
        manager = finding.vuln.package_manager or result.package_manager
        if finding.verdict == Verdict.FILTERED or not finding.vuln.fix_version:
            continue
        if manager not in _PYTHON_MANAGERS or finding.vuln.fix_package:
            continue
        package, version = finding.vuln.package, finding.vuln.fix_version
        if package not in targets or _version_key(version) > _version_key(targets[package]):
            targets[package] = version
    return targets


def _explain(stderr: str) -> str:
    """uv's ``hint:`` lines first (the actionable part), then its ``cause:`` lines."""
    hints: list[str] = []
    causes: list[str] = []
    current: list[str] | None = None
    for line in stderr.splitlines():
        stripped = line.strip()
        if stripped.startswith("hint:"):
            current = hints
            current.append(stripped[5:].strip())
        elif stripped.startswith("cause:"):
            current = causes
            current.append(stripped[6:].strip())
        elif current is not None and line.startswith((" ", "\t")) and stripped:
            current.append(stripped)
        else:
            current = None
    text = " ".join(hints + causes) or (stderr.strip().splitlines() or [""])[-1]
    return re.sub(r"\s+", " ", text).strip()[:500]


def check_fix(project: Path, package: str, version: str, *, timeout: int = 300) -> FixCheck:
    executable = shutil.which("uv")
    if executable is None:
        return FixCheck("error", package, version, "uv is not installed.")
    try:
        r = subprocess.run(
            [executable, "lock", "--dry-run", "--upgrade-package", f"{package}=={version}"],
            cwd=project,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return FixCheck("error", package, version, f"uv lock timed out after {timeout} s.")
    except OSError as e:
        return FixCheck("error", package, version, f"could not run uv lock: {e}")
    output = f"{r.stdout}\n{r.stderr}"
    if r.returncode == 0:
        update = re.search(rf"Update {re.escape(package)} (v\S+ -> v\S+)", output, re.I)
        return FixCheck("resolves", package, version, update.group(1) if update else "")
    status = "blocked" if "No solution found" in output else "error"
    return FixCheck(status, package, version, _explain(r.stderr or r.stdout))


def check_fixes(result: ScanResult, project: Path) -> tuple[dict[str, FixCheck], str]:
    """Check every shown alert's fix; returns (checks by package, note)."""
    targets = fix_targets(result)
    if not targets:
        return {}, ""
    if shutil.which("uv") is None:
        return {}, "--check-fixes needs uv on PATH."
    if not (project / "uv.lock").exists():
        return {}, "--check-fixes works on projects with a uv.lock."
    checks = {pkg: check_fix(project, pkg, version) for pkg, version in sorted(targets.items())}
    for finding in result.results:
        check = checks.get(finding.vuln.package)
        if check is not None and finding.verdict != Verdict.FILTERED:
            finding.fix_check = check
    return checks, ""
