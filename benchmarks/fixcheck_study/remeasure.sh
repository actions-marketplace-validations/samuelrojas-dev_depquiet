#!/usr/bin/env bash
# Re-measure the README's headline table inside a disposable Ubuntu VM.
# Usage, in the VM:
#   git clone https://github.com/samuelrojas-dev/depquiet
#   bash depquiet/benchmarks/fixcheck_study/remeasure.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
sudo apt-get update -q
sudo apt-get install -y -q git python3-venv curl
# Fresh environments every run: a venv left by an earlier run keeps its old
# depquiet, because pip does not upgrade what is already installed.
rm -rf "$HOME/dq-old" "$HOME/dq-new"
python3 -m venv "$HOME/dq-old"
python3 -m venv "$HOME/dq-new"
"$HOME/dq-old/bin/pip" install -q --upgrade pip
"$HOME/dq-new/bin/pip" install -q --upgrade pip
# The version that measured the table, and the latest release, both from PyPI.
"$HOME/dq-old/bin/pip" install -q "depquiet==0.39.0" pip-audit
"$HOME/dq-new/bin/pip" install -q --upgrade depquiet pip-audit
LATEST=$(curl -fsS https://pypi.org/pypi/depquiet/json | python3 -c 'import json,sys; print(json.load(sys.stdin)["info"]["version"])')
NEW=$("$HOME/dq-new/bin/depquiet" --version | awk '{print $2}')
if [ "$NEW" != "$LATEST" ]; then
  echo "error: installed depquiet $NEW, but the latest on PyPI is $LATEST." >&2
  exit 1
fi
echo "Comparing depquiet 0.39.0 with $NEW (latest on PyPI)."
export PATH="$HOME/dq-new/bin:$PATH"   # pip-audit for the single shared audit
"$HOME/dq-new/bin/python" "$HERE/remeasure.py" \
  "$HOME/dq-old/bin/depquiet" "$HOME/dq-new/bin/depquiet" --out "$HOME/remeasure"
echo
echo "Done. Results in ~/remeasure/remeasure.md and ~/remeasure/remeasure.json."
echo "Serving them on port 8000; open http://localhost:8080 on your computer."
cd "$HOME/remeasure" && python3 -m http.server 8000
