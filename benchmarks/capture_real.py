"""Capture real-world benchmark fixtures with the real package manager.

The original benchmark scenarios (``fixtures/*.json``) are hand-written. They
are useful as parser tests but say nothing about real dependency trees: they
have no lockfiles, so transitive packages look unused. This script builds the
``real-*`` scenarios from what npm actually resolves and reports:

1. writes a pinned ``package.json`` and the app's source files,
2. runs ``npm install --package-lock-only --ignore-scripts`` (no code runs,
   nothing lands in node_modules),
3. runs ``npm audit --json`` against the npm registry,
4. stores the project, the audit output and capture metadata.

The captured files are committed, so ``run_benchmark.py`` stays offline and
deterministic. Re-running this script later will pick up new advisories.

``repo-*`` scenarios audit well-known public projects pinned to a commit. Their
source is *not* committed (not every project's license allows redistribution):
``run_benchmark.py`` clones the pinned commit into ``benchmarks/.cache/``. Only
files we generate are committed: npm's audit output and, for yarn projects, the
package-lock.json npm derives from their yarn.lock. npm only ever runs in an
empty directory holding copies of the manifests, never inside the clone: no
install, no lifecycle scripts, no project ``.npmrc``.

Run:  python -I benchmarks/capture_real.py
"""

from __future__ import annotations

import datetime as dt
import json
import shutil
import subprocess
from pathlib import Path

OUT = Path(__file__).resolve().parent / "fixtures"

SCENARIOS: dict[str, dict[str, object]] = {
    # Same manifest as the synthetic npm-express-app scenario, pinned to the
    # versions that were current when that scenario was written.
    "real-npm-express": {
        "package.json": {
            "name": "bench-express-app",
            "version": "1.0.0",
            "private": True,
            "dependencies": {"express": "4.18.1", "lodash": "4.17.15", "braces": "3.0.0"},
            "devDependencies": {
                "webpack-dev-middleware": "5.0.0",
                "eslint-plugin-import": "2.20.0",
                "jest-environment-jsdom": "29.0.0",
                "nodemon": "2.0.0",
            },
        },
        "sources": {
            # express is used; lodash is declared but never imported.
            "app.js": (
                'const express = require("express");\n'
                "const app = express();\n"
                'app.get("/users/:id", (req, res) => res.json({ id: req.params.id }));\n'
                "app.listen(3000);\n"
            ),
            "config.js": 'const braces = require("braces");\nmodule.exports = braces("a/{b,c}");\n',
        },
    },
}


# name -> (GitHub repo, pinned commit)
REPOS: dict[str, tuple[str, str]] = {
    "repo-hackathon-starter": (
        "sahat/hackathon-starter",
        "fb53b17c28c99e6fbcd78106930c6e9b403eb9ec",
    ),
    "repo-node-express-realworld": (
        "gothinkster/node-express-realworld-example-app",
        "30b68e1e881462b2f4164ea09ab4c4f5699c7b0b",
    ),
    "repo-node-express-boilerplate": (
        "hagopj13/node-express-boilerplate",
        "179ae84efec61b14206d0305d941daed6c6d07f9",
    ),
}

CACHE = Path(__file__).resolve().parent / ".cache"


def checkout(repo: str, commit: str) -> Path:
    """Shallow-fetch ``repo`` at ``commit`` into the cache (reused if present)."""
    dest = CACHE / f"{repo.replace('/', '__')}@{commit[:12]}"
    if (dest / ".git").exists():
        return dest
    dest.mkdir(parents=True, exist_ok=True)
    url = f"https://github.com/{repo}.git"
    for cmd in (
        ["git", "init", "-q"],
        ["git", "remote", "add", "origin", url],
        ["git", "fetch", "-q", "--depth", "1", "origin", commit],
        ["git", "checkout", "-q", "FETCH_HEAD"],
    ):
        r = subprocess.run(cmd, cwd=dest, capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            shutil.rmtree(dest, ignore_errors=True)
            raise RuntimeError(f"{' '.join(cmd)} failed for {repo}: {r.stderr.strip()}")
    return dest


def capture_repo(name: str, repo: str, commit: str) -> None:
    import tempfile

    clone = checkout(repo, commit)
    dest = OUT / name
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    with tempfile.TemporaryDirectory() as tmp:
        iso = Path(tmp)
        for manifest in ("package.json", "package-lock.json", "yarn.lock"):
            if (clone / manifest).exists():
                shutil.copy2(clone / manifest, iso / manifest)
        commands = []
        generated_lock = not (iso / "package-lock.json").exists()
        if generated_lock:
            cmd = ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit"]
            r = _run([*cmd, "--no-fund"], iso)
            if r.returncode != 0:
                raise SystemExit(f"npm lock generation failed for {name}:\n{r.stderr}")
            commands.append(" ".join(cmd) + "  # from the project's yarn.lock")
            shutil.copy2(iso / "package-lock.json", dest / "package-lock.json")
        audit = _run(["npm", "audit", "--json"], iso)
        commands.append("npm audit --json")
        audit_json = json.loads(audit.stdout)
        if "vulnerabilities" not in audit_json:
            raise SystemExit(f"npm audit returned no report for {name}:\n{audit.stdout[:500]}")
        (dest / "audit.json").write_text(json.dumps(audit_json, indent=2) + "\n")

    npm_version = _run(["npm", "--version"], OUT).stdout.strip()
    commit_date = subprocess.run(
        ["git", "log", "-1", "--format=%cs"], cwd=clone, capture_output=True, text=True
    ).stdout.strip()
    meta = {
        "repo": repo,
        "commit": commit,
        "commit_date": commit_date,
        "captured_at": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tool": f"npm {npm_version}",
        "commands": commands,
        "generated_lockfile": generated_lock,
        "vulnerable_packages": len(audit_json["vulnerabilities"]),
    }
    (dest / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    print(f"{name}: {meta['vulnerable_packages']} vulnerable packages ({repo}@{commit[:7]})")


def _run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=300)


def capture(name: str, spec: dict[str, object]) -> None:
    dest = OUT / name
    project = dest / "project"
    if dest.exists():
        shutil.rmtree(dest)
    project.mkdir(parents=True)

    (project / "package.json").write_text(json.dumps(spec["package.json"], indent=2) + "\n")
    sources = spec["sources"]
    assert isinstance(sources, dict)
    for fname, content in sources.items():
        (project / fname).write_text(content)

    lock = _run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-fund"], project)
    if lock.returncode != 0:
        raise SystemExit(f"npm install failed for {name}:\n{lock.stderr}")

    # npm audit exits 1 when it finds vulnerabilities; that's the point.
    audit = _run(["npm", "audit", "--json"], project)
    audit_json = json.loads(audit.stdout)
    if "vulnerabilities" not in audit_json:
        raise SystemExit(f"npm audit returned no report for {name}:\n{audit.stdout[:500]}")
    (dest / "audit.json").write_text(json.dumps(audit_json, indent=2) + "\n")

    npm_version = _run(["npm", "--version"], project).stdout.strip()
    meta = {
        "captured_at": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tool": f"npm {npm_version}",
        "commands": [
            "npm install --package-lock-only --ignore-scripts --no-fund",
            "npm audit --json",
        ],
        "vulnerable_packages": len(audit_json["vulnerabilities"]),
    }
    (dest / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    print(f"{name}: {meta['vulnerable_packages']} vulnerable packages ({meta['tool']})")


if __name__ == "__main__":
    import sys

    only = set(sys.argv[1:])
    for scenario, spec in SCENARIOS.items():
        if not only or scenario in only:
            capture(scenario, spec)
    for scenario, (repo, commit) in REPOS.items():
        if not only or scenario in only:
            capture_repo(scenario, repo, commit)
