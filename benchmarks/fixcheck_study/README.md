# Fix-check study

Can the fix a scanner suggests be installed as-is? For 18 uv projects, `run.py` clones the
project, audits its `uv.lock` with pip-audit through depquiet, and asks uv's resolver
(`uv lock --dry-run --upgrade-package pkg==fix`) about each alert depquiet keeps.

- `results.json`: one row per project, with every resolver message.
- `summary.md`: the table and the list of blocked fixes.

Run on 2026-11-11, at each project's head (commits in the table), Ubuntu 26.04 VM.

`uv lock` can execute the cloned projects' build hooks, so run it only in a disposable
virtual machine with no shared folders: `vm.sh` installs what it needs there and runs the
study. `python run.py --out DIR --skip-check` audits without calling `uv lock`.
