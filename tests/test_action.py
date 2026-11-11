"""Exercise composite Action shell steps without scanners or GitHub requests."""

import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ACTION = Path(__file__).resolve().parents[1] / "action.yml"


def _step(name):
    source = ACTION.read_text(encoding="utf-8")
    blocks = re.split(r"(?m)^    - name: ", source)[1:]
    block = next(block for block in blocks if block.splitlines()[0] == name)
    script = block.split("      run: |\n", 1)[1]
    # A line at column zero exits the YAML block and invalidates the Action.
    assert all(not line.strip() or line.startswith("        ") for line in script.splitlines())
    return block, textwrap.dedent(script)


@pytest.fixture
def shell_env(tmp_path):
    bash = (
        str(Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "Git/bin/bash.exe")
        if os.name == "nt"
        else shutil.which("bash")
    )
    if not bash or not Path(bash).is_file():
        pytest.skip("Git Bash or bash is required for composite Action tests")
    runner = tmp_path / "runner temp"
    runner.mkdir()
    stub = tmp_path / "stub.py"
    stub.write_text(
        textwrap.dedent(
            """\
            import json, os, sys
            from pathlib import Path

            args = sys.argv[1:]
            with open(os.environ['CALLS'], 'a', encoding='utf-8') as stream:
                stream.write(json.dumps(args) + '\\n')
            if args and args[0] == 'diff':
                from depquiet.cli import diff_main
                sys.exit(diff_main(args[1:]))
            print('Warning: an expired suppression remains visible', file=sys.stderr)
            sys.stdout.write(os.environ['SCAN_JSON'])
            if '--summary' in args:
                Path(args[args.index('--summary') + 1]).write_text('scan summary\\n')
            sys.exit(int(os.environ['SCAN_EXIT']))
            """
        ),
        encoding="utf-8",
    )
    gh_stub = tmp_path / "gh_stub.py"
    gh_stub.write_text(
        "import json,os,sys\n"
        "with open(os.environ['GH_CALLS'], 'a', encoding='utf-8') as stream:\n"
        "    stream.write(json.dumps(sys.argv[1:]) + '\\n')\n",
        encoding="utf-8",
    )
    report = {
        "summary": {"total": 1, "filtered": 0, "action": 1, "review": 0},
        "results": [
            {
                "cve": "CVE-2026-12345",
                "package": "example",
                "version": "1.0.0",
                "severity": "high",
                "verdict": "action",
                "reasons": [],
            }
        ],
    }
    env = {
        **os.environ,
        "TEST_PYTHON": Path(sys.executable).as_posix(),
        "STUB_SCRIPT": stub.as_posix(),
        "GH_STUB": gh_stub.as_posix(),
        "CALLS": (tmp_path / "calls.jsonl").as_posix(),
        "GH_CALLS": (tmp_path / "gh_calls.jsonl").as_posix(),
        "RUNNER_TEMP": runner.as_posix(),
        "GITHUB_OUTPUT": (tmp_path / "outputs").as_posix(),
        "GITHUB_STEP_SUMMARY": (tmp_path / "summary.md").as_posix(),
        "GITHUB_REPOSITORY": "owner/repository",
        "PR_NUMBER": "42",
        "INPUT_PATH": "apps/client portal",
        "INPUT_EPSS_THRESHOLD": "0.1",
        "INPUT_OFFLINE": "true",
        "INPUT_FAIL_ON_ACTION": "true",
        "INPUT_FAIL_ON": "",
        "SCAN_JSON": json.dumps(report),
        "SCAN_EXIT": "1",
        "PYTHONIOENCODING": "utf-8",
    }
    return bash, env


def _run_step(name, shell_env):
    bash, env = shell_env
    _, script = _step(name)
    functions = """\
python3() { "$TEST_PYTHON" "$@"; }
depquiet() { "$TEST_PYTHON" "$STUB_SCRIPT" "$@"; }
gh() { "$TEST_PYTHON" "$GH_STUB" "$@"; }
"""
    return subprocess.run(
        [bash, "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", functions + script],
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )


def _outputs(env):
    output = Path(env["GITHUB_OUTPUT"])
    if not output.exists():
        return {}
    return dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())


@pytest.mark.parametrize(
    ("scan_exit", "fail_on_action", "fail_on", "expected"),
    [
        (0, "true", "", 0),
        (1, "true", "", 1),
        (1, "false", "", 0),
        (1, "false", "high", 1),
        (2, "false", "", 2),
    ],
)
def test_action_preserves_operational_errors_and_valid_findings(
    shell_env, scan_exit, fail_on_action, fail_on, expected
):
    _, env = shell_env
    env.update(SCAN_EXIT=str(scan_exit), INPUT_FAIL_ON_ACTION=fail_on_action, INPUT_FAIL_ON=fail_on)
    if scan_exit == 2:
        env["SCAN_JSON"] = ""
    result = _run_step("Run depquiet", shell_env)
    assert result.returncode == expected, result.stderr
    outputs = _outputs(env)
    if scan_exit == 2:
        assert "scan_file" not in outputs
    else:
        assert outputs["total"] == "1"
        assert outputs["action"] == "1"
        assert json.loads(Path(outputs["scan_file"]).read_text())["summary"]["action"] == 1
        assert "Warning:" in result.stderr


def test_action_rejects_invalid_json_instead_of_publishing_zero_counts(shell_env):
    _, env = shell_env
    env.update(SCAN_EXIT="0", SCAN_JSON='{"summary":{}}\n{"second":"document"}')
    result = _run_step("Run depquiet", shell_env)
    assert result.returncode != 0
    assert "scan_file" not in _outputs(env)


def test_action_preserves_path_arguments(shell_env):
    _, env = shell_env
    path_flags = [
        "sarif",
        "templates",
        "policy",
        "sbom",
        "from-sbom",
        "ignore",
        "baseline",
        "kev-file",
        "html",
        "vex",
    ]
    for flag in path_flags:
        env["INPUT_" + flag.upper().replace("-", "_")] = f"my files/[1] {flag}.json"
    result = _run_step("Run depquiet", shell_env)
    assert result.returncode == 1, result.stderr
    args = json.loads(Path(env["CALLS"]).read_text().splitlines()[0])
    assert args[args.index("--path") + 1] == env["INPUT_PATH"]
    for flag in path_flags:
        assert args[args.index("--" + flag) + 1] == f"my files/[1] {flag}.json"


def test_diff_and_comment_reuse_sbom_scan_after_findings_failure(shell_env, tmp_path):
    _, env = shell_env
    env["INPUT_FROM_SBOM"] = "vendor reports/dependency report.cdx.json"
    scan = _run_step("Run depquiet", shell_env)
    assert scan.returncode == 1, scan.stderr
    env["SCAN_FILE"] = _outputs(env)["scan_file"]
    base = tmp_path / "base scan.json"
    base.write_text('{"results": []}', encoding="utf-8")
    env["INPUT_DIFF_BASE"] = base.as_posix()
    diff_block, _ = _step("Run scan diff")
    assert "always()" in diff_block
    assert "steps.run.outputs.scan_file != ''" in diff_block
    diff = _run_step("Run scan diff", shell_env)
    assert diff.returncode == 0, diff.stderr
    assert _outputs(env)["new"] == "1"
    assert _outputs(env)["fixed"] == "0"
    summary = Path(env["GITHUB_STEP_SUMMARY"]).read_text(encoding="utf-8")
    assert summary.startswith("scan summary\n")
    assert "example" in summary
    comment_block, _ = _step("Post PR comment")
    assert "always()" in comment_block
    assert "steps.diff.outcome == 'success'" in comment_block
    comment = _run_step("Post PR comment", shell_env)
    assert comment.returncode == 0, comment.stderr
    calls = [json.loads(line) for line in Path(env["CALLS"]).read_text().splitlines()]
    assert len([call for call in calls if call[0] != "diff"]) == 1
    assert all(call[2] == env["SCAN_FILE"] for call in calls if call[0] == "diff")
    gh_calls = [json.loads(line) for line in Path(env["GH_CALLS"]).read_text().splitlines()]
    assert gh_calls[-1][:3] == ["pr", "comment", "42"]
    assert "example" in gh_calls[-1][-1]


def test_annotation_script_stays_inside_yaml_block():
    _step("Post PR annotations")


def test_action_forwards_the_scanner_input(shell_env):
    _, env = shell_env
    env["INPUT_SCANNER"] = "uv"
    _run_step("Run depquiet", shell_env)
    args = json.loads(Path(env["CALLS"]).read_text().splitlines()[0])
    assert args[args.index("--scanner") + 1] == "uv"


def test_action_without_scanner_input_scans_every_ecosystem(shell_env):
    _, env = shell_env
    env["INPUT_SCANNER"] = ""
    _run_step("Run depquiet", shell_env)
    args = json.loads(Path(env["CALLS"]).read_text().splitlines()[0])
    assert "--scanner" not in args


def test_install_step_uses_the_actions_own_code_and_pip_audit():
    """``@v0.35.0`` must run 0.35.0, and Python projects need their scanner."""
    block, script = _step("Install depquiet")
    assert 'pip install --disable-pip-version-check "$GITHUB_ACTION_PATH"' in script
    assert "pip install --disable-pip-version-check pip-audit" in script
    assert "INPUT_INSTALL_PIP_AUDIT: ${{ inputs.install-pip-audit }}" in block
    assert "pip install depquiet" not in script
