"""Materialize and scan a controlled synthetic snapshot without network access."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from depquiet.engine import scan


def run_snapshot(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    snapshot = json.loads(raw)
    if not isinstance(snapshot, dict) or snapshot.get("kind") != "synthetic":
        raise ValueError("the controlled harness only accepts explicitly synthetic snapshots")
    if type(snapshot.get("schema_version")) is not int or snapshot["schema_version"] != 1:
        raise ValueError("snapshot.schema_version must be 1")
    project_id = snapshot.get("project")
    files = snapshot.get("files")
    audit_json = snapshot.get("audit_json")
    if not isinstance(project_id, str) or not project_id.strip():
        raise ValueError("snapshot.project must identify the controlled project")
    if not isinstance(files, dict) or not files or not isinstance(audit_json, dict):
        raise ValueError("snapshot must contain files and audit_json objects")
    with tempfile.TemporaryDirectory(prefix="depquiet-reference-") as directory:
        project = Path(directory)
        for name, text in files.items():
            relative = PurePosixPath(name)
            if (
                relative.is_absolute()
                or ".." in relative.parts
                or "\\" in name
                or ":" in name
                or not relative.parts
                or not isinstance(text, str)
            ):
                raise ValueError(f"invalid snapshot file: {name}")
            target = project.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8", newline="\n")
        result = scan(project, audit_json=audit_json, skip_epss=True)
    return {
        "project": project_id,
        "snapshot_sha256": hashlib.sha256(raw).hexdigest(),
        "scanned": result.scanned,
        "package_manager": result.package_manager,
        "note": result.note,
        "summary": {
            "total": len(result.results),
            "action": len(result.action),
            "review": len(result.review),
            "filtered": len(result.filtered),
        },
        "results": [
            {
                "package": item.vuln.package,
                "version": item.vuln.version,
                "cve": item.vuln.cve,
                "verdict": item.verdict.value,
                "severity": item.vuln.severity.value,
                "reasons": [reason.value for reason in item.reasons],
            }
            for item in result.results
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--snapshot", type=Path, default=Path(__file__).with_name("synthetic.snapshot.json")
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = run_snapshot(args.snapshot)
        output = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(output, encoding="utf-8", newline="\n")
        else:
            print(output, end="")
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        print(f"Invalid synthetic snapshot: {exc}", file=sys.stderr)
        return 2
    return 0 if report["scanned"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
