#!/usr/bin/env bash
# Run the fix-check study inside a disposable Ubuntu VM. Never on your own machine:
# `uv lock` can execute the cloned projects' build hooks.
set -euo pipefail
sudo apt-get update -q
sudo apt-get install -y -q git python3-venv
python3 -m venv "$HOME/dq"
# shellcheck disable=SC1091
. "$HOME/dq/bin/activate"
pip install -q --upgrade pip
pip install -q "$(dirname "$0")/../.." pip-audit uv
python "$(dirname "$0")/run.py" --out "$HOME/study"
echo
echo "Done. Results in ~/study/summary.md and ~/study/results.json."
echo "Serving them on port 8000; open http://localhost:8080 on your computer."
cd "$HOME/study" && python3 -m http.server 8000
