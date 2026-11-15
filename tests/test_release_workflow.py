"""The release workflow's tag job: real git against a local remote, gh stubbed.

Merging the release pull request must be the only manual step, and a merge
that is not a finished release must never produce a tag.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "release.yml"


def _tag_script() -> str:
    """The tag job's script, read as text: the project has no YAML dependency."""
    source = WORKFLOW.read_text(encoding="utf-8")
    job = source.split("\n  tag:\n", 1)[1].split("\n  verify:\n", 1)[0]
    script = job.split("        run: |\n", 1)[1]
    assert all(not line.strip() or line.startswith("          ") for line in script.splitlines())
    return textwrap.dedent(script)


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    if os.name == "nt" or not shutil.which("bash"):
        pytest.skip("needs bash")
    remote = tmp_path / "remote.git"
    _git(tmp_path, "init", "-q", "--bare", str(remote))
    work = tmp_path / "work"
    (work / "src" / "depquiet").mkdir(parents=True)
    _git(work, "init", "-q", "-b", "main")
    _git(work, "config", "user.email", "t@example.com")
    _git(work, "config", "user.name", "t")
    _git(work, "remote", "add", "origin", str(remote))
    gh = tmp_path / "bin" / "gh"
    gh.parent.mkdir()
    gh.write_text(f'#!/bin/sh\necho "$@" >> "{tmp_path}/gh_calls"\n')
    gh.chmod(0o755)
    return tmp_path, work, remote


def _release(work: Path, version: str, init: str | None = None, changelog: bool = True) -> str:
    (work / "pyproject.toml").write_text(f'[project]\nname = "depquiet"\nversion = "{version}"\n')
    (work / "src" / "depquiet" / "__init__.py").write_text(f'__version__ = "{init or version}"\n')
    (work / "CHANGELOG.md").write_text(
        f"## [Unreleased]\n\n## [{version}] - 2026-11-14\n" if changelog else "## [Unreleased]\n"
    )
    _git(work, "add", "-A")
    _git(work, "commit", "-q", "-m", f"release {version}")
    _git(work, "push", "-q", "origin", "main")
    return _git(work, "rev-parse", "HEAD")


def _run(tmp_path: Path, work: Path, sha: str) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "PATH": f"{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}",
        "GITHUB_SHA": sha,
        "GH_TOKEN": "x",
    }
    return subprocess.run(
        ["bash", "-c", _tag_script()], cwd=work, env=env, capture_output=True, text=True
    )


def _gh_calls(tmp_path: Path) -> list[str]:
    path = tmp_path / "gh_calls"
    return path.read_text().splitlines() if path.exists() else []


def test_new_version_is_tagged_on_the_merged_commit_and_released(repo) -> None:
    tmp_path, work, remote = repo
    sha = _release(work, "0.46.0")
    result = _run(tmp_path, work, sha)
    assert result.returncode == 0, result.stderr
    assert _git(remote, "rev-parse", "v0.46.0") == sha
    assert _gh_calls(tmp_path) == ["workflow run release.yml --ref v0.46.0"]


def test_existing_tag_means_nothing_happens(repo) -> None:
    tmp_path, work, remote = repo
    sha = _release(work, "0.46.0")
    _git(work, "tag", "v0.46.0")
    _git(work, "push", "-q", "origin", "v0.46.0")
    # A later commit on main that also touches pyproject.toml (a dependency bump).
    (work / "pyproject.toml").write_text('[project]\nname = "depquiet"\nversion = "0.46.0"\n# x\n')
    _git(work, "commit", "-qam", "chore")
    result = _run(tmp_path, work, _git(work, "rev-parse", "HEAD"))
    assert result.returncode == 0
    assert "already exists" in result.stdout
    assert _git(remote, "rev-parse", "v0.46.0") == sha  # the tag did not move
    assert _gh_calls(tmp_path) == []


@pytest.mark.parametrize(
    ("version", "init", "changelog", "message"),
    [
        ("0.46.0", "0.45.1", True, "__init__.py does not say 0.46.0"),
        ("0.46.0", None, False, "CHANGELOG.md has no section for 0.46.0"),
        ("0.46.0.dev1", None, True, "is not X.Y.Z"),
    ],
)
def test_half_done_bump_is_never_tagged(repo, version, init, changelog, message) -> None:
    tmp_path, work, remote = repo
    sha = _release(work, version, init=init, changelog=changelog)
    result = _run(tmp_path, work, sha)
    assert result.returncode == 1
    assert message in result.stdout
    assert _git(remote, "tag", "--list") == ""
    assert _gh_calls(tmp_path) == []


def test_workflow_shape() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")
    head = source.split("\njobs:\n", 1)[0]
    # A tag pushed by hand still releases; a merge to main that changes the
    # version file starts the tag job; the tag job can start the release run.
    assert '    tags:\n      - "v*"\n' in head
    assert "    branches:\n      - main\n    paths:\n      - pyproject.toml\n" in head
    assert "  workflow_dispatch:\n" in head
    assert "\npermissions:\n  contents: read\n" in head
    tag = source.split("\n  tag:\n", 1)[1].split("\n  verify:\n", 1)[0]
    assert "if: github.ref == 'refs/heads/main' && github.event_name == 'push'" in tag
    assert "contents: write" in tag and "actions: write" in tag
    # Publishing only ever happens on a version tag, after verify.
    verify = source.split("\n  verify:\n", 1)[1].split("\n  release:\n", 1)[0]
    assert "if: startsWith(github.ref, 'refs/tags/v')" in verify
    release = source.split("\n  release:\n", 1)[1]
    assert "needs: verify" in release and "id-token: write" in release
