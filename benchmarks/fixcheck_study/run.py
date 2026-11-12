"""How many of the fixes scanners suggest can be installed as-is?

For each project: clone it, audit its uv.lock with pip-audit through depquiet,
then ask uv's resolver (``uv lock --dry-run --upgrade-package pkg==fix``)
whether each fix of an alert depquiet keeps can be installed.

``uv lock`` can execute the cloned projects' build hooks. Run this only in a
disposable virtual machine; see README.md in this folder.

    python benchmarks/fixcheck_study/run.py --out ~/study
"""

from __future__ import annotations

import argparse
import collections
import json
import subprocess
import sys
import time
from pathlib import Path

from depquiet.engine import scan
from depquiet.fixcheck import check_fixes

PROJECTS = [
    "saleor/saleor",
    "zulip/zulip",
    "mlflow/mlflow",
    "langflow-ai/langflow",
    "pallets/flask",
    "getredash/redash",
    "ArchiveBox/ArchiveBox",
    "Chainlit/chainlit",
    "wger-project/wger",
    "crewAIInc/crewAI",
    "goauthentik/authentik",
    "BerriAI/litellm",
    "pydantic/pydantic-ai",
    "open-webui/open-webui",
    "mitmproxy/mitmproxy",
    "run-llama/llama_index",
    "PrefectHQ/prefect",
    "PostHog/posthog",
]


def _clone(repo: str, dest: Path) -> str:
    if not dest.exists():
        subprocess.run(
            ["git", "clone", "-q", "--depth", "1", f"https://github.com/{repo}", str(dest)],
            check=True,
            timeout=900,
        )
    out = subprocess.run(
        ["git", "-C", str(dest), "rev-parse", "--short", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.strip()


def study(repo: str, root: Path, skip_check: bool) -> dict[str, object]:
    dest = root / "repos" / repo.replace("/", "__")
    row: dict[str, object] = {"project": repo}
    try:
        row["commit"] = _clone(repo, dest)
    except (subprocess.SubprocessError, OSError) as e:
        return {**row, "error": f"clone failed: {e}"}
    if not (dest / "uv.lock").exists():
        return {**row, "error": "no uv.lock"}
    started = time.time()
    result = scan(dest, skip_epss=True, scanner="pip")
    if not result.scanned:
        return {**row, "error": f"not scanned: {result.note}"}
    kept = [r for r in result.results if r.verdict.value != "filtered"]
    row.update(alerts=len(result.results), kept=len(kept))
    if skip_check:
        return {**row, "seconds": round(time.time() - started)}
    checks, note = check_fixes(result, dest)
    by_alert = collections.Counter(r.fix_check.status for r in kept if r.fix_check is not None)
    row.update(
        note=note,
        packages={p: c.to_dict() for p, c in checks.items()},
        packages_by_status=dict(collections.Counter(c.status for c in checks.values())),
        alerts_with_fix=sum(by_alert.values()),
        alerts_by_status=dict(by_alert),
        seconds=round(time.time() - started),
    )
    return row


def summary(rows: list[dict[str, object]]) -> str:
    lines = [
        "| Project | Commit | Alerts | Kept | Kept with a fix "
        "| Fix installs | Blocked | Could not check |",
        "|:--|:--|--:|--:|--:|--:|--:|--:|",
    ]
    total: collections.Counter[str] = collections.Counter()
    for r in rows:
        if "error" in r:
            lines.append(f"| {r['project']} | {r.get('commit', '')} | {r['error']} ||||||")
            continue
        st = r.get("alerts_by_status", {})
        assert isinstance(st, dict)
        values = [
            r["alerts"],
            r["kept"],
            r.get("alerts_with_fix", 0),
            st.get("resolves", 0),
            st.get("blocked", 0),
            st.get("error", 0),
        ]
        keys = ("alerts", "kept", "fix", "ok", "blocked", "error")
        for key, value in zip(keys, values, strict=True):
            total[key] += int(value)  # type: ignore[call-overload]
        lines.append(f"| {r['project']} | {r['commit']} | " + " | ".join(map(str, values)) + " |")
    lines.append(
        f"| **Total** | | {total['alerts']} | {total['kept']} | {total['fix']} | "
        f"{total['ok']} | {total['blocked']} | {total['error']} |"
    )
    lines.append("")
    lines.append("Blocked fixes:")
    for r in rows:
        packages = r.get("packages", {})
        assert isinstance(packages, dict)
        for check in packages.values():
            if check["status"] == "blocked":
                lines.append(f"- {r['project']}: {check['command']}: {check['detail'][:300]}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--skip-check", action="store_true", help="audit only, no uv lock")
    parser.add_argument("projects", nargs="*", default=PROJECTS)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    rows = []
    for repo in args.projects:
        print(f"== {repo}", flush=True)
        row = study(repo, args.out, args.skip_check)
        print(json.dumps({k: v for k, v in row.items() if k != "packages"}), flush=True)
        rows.append(row)
        (args.out / "results.json").write_text(json.dumps(rows, indent=1), encoding="utf-8")
        (args.out / "summary.md").write_text(summary(rows), encoding="utf-8")
    print("\n" + summary(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
