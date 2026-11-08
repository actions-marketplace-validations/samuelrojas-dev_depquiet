"""Synthetic local Git regressions; no upstream code or network is used."""

import importlib.util
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "isolated_reference_harness", ROOT / "benchmarks/reference/run_reviewed.py"
)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)


def _git(source, *args):
    result = subprocess.run(
        [
            "git",
            "-c",
            "user.name=Synthetic test author",
            "-c",
            "user.email=synthetic@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            f"core.hooksPath={os.devnull}",
            "-C",
            str(source),
            *args,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


@pytest.fixture
def source(tmp_path):
    root = tmp_path / "synthetic source checkout"
    root.mkdir()
    _git(root, "init")
    _git(root, "config", "core.autocrlf", "false")
    (root / ".gitattributes").write_text("*.data filter=sentinel\n", encoding="utf-8")
    (root / "payload.data").write_bytes(b"bound source bytes\n")
    (root / "helper.py").write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "Path(sys.argv[1]).write_text('filter executed', encoding='utf-8')\n"
        "if sys.argv[2] == 'process':\n"
        "    raise SystemExit(1)\n"
        "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    _git(root, "add", ".")
    _git(root, "commit", "-m", "Synthetic filter isolation fixture")
    return root


@pytest.mark.parametrize("helper_type", ["clean", "process"])
@pytest.mark.parametrize("dirty", [False, True])
def test_status_never_executes_configured_filter_helpers(source, tmp_path, helper_type, dirty):
    sentinel = tmp_path / "filter-sentinel.txt"
    command = shlex.join(
        [
            sys.executable.replace("\\", "/"),
            (source / "helper.py").as_posix(),
            sentinel.as_posix(),
            helper_type,
        ]
    )
    _git(source, "config", f"filter.sentinel.{helper_type}", command)
    _git(source, "config", "filter.sentinel.required", "true")
    payload = source / "payload.data"
    if dirty:
        payload.write_bytes(b"changed source bytes\n")
    stat = payload.stat()
    os.utime(payload, ns=(stat.st_atime_ns, stat.st_mtime_ns + 10_000_000_000))
    commit = _git(source, "rev-parse", "HEAD")
    if dirty:
        with pytest.raises(ValueError, match="source checkout is dirty"):
            HARNESS._verify_source(source, commit)
    else:
        HARNESS._verify_source(source, commit)
    assert not sentinel.exists()


def test_materialization_uses_original_commit_despite_local_replace_ref(source, tmp_path):
    original = _git(source, "rev-parse", "HEAD")
    (source / "payload.data").write_bytes(b"replacement content\n")
    _git(source, "add", ".")
    _git(source, "commit", "-m", "Synthetic replacement object")
    replacement = _git(source, "rev-parse", "HEAD")
    _git(source, "replace", original, replacement)
    output = tmp_path / "materialized"
    HARNESS._materialize(source, original, output)
    assert (output / "payload.data").read_bytes() == b"bound source bytes\n"


@pytest.mark.parametrize("config_key", ["remote.origin.promisor", "extensions.partialClone"])
def test_partial_source_clone_is_rejected_without_lazy_fetch(source, config_key):
    commit = _git(source, "rev-parse", "HEAD")
    _git(source, "config", config_key, "true" if config_key.startswith("remote.") else "origin")
    with pytest.raises(ValueError, match="partial/promisor source clones are unsupported"):
        HARNESS._verify_source(source, commit)
