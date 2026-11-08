# Reference evaluation

This directory contains **two synthetic contract examples**. Package names,
advisory identifiers, audit output and labels are invented together. They test
retention of an imported runtime package and permitted filtering of a dev-only
tool. They provide no estimate of real-world precision, recall, exploitability
or the proportion of alerts that can safely be dismissed. The existing alert
reduction benchmark is not reference truth for this evaluator.

From the repository root, run these commands without network access:

```sh
python benchmarks/reference/run.py --output synthetic-scan.json
python benchmarks/evaluate.py --labels benchmarks/reference/synthetic.labels.json --scan synthetic-scan.json --snapshot benchmarks/reference/synthetic.snapshot.json --json
```

The harness reads the exact snapshot bytes, calculates SHA-256, materializes only
its source/manifests in a temporary directory and scans the supplied audit JSON
offline. Its report uses the CLI JSON field names and adds a stable `project`
identifier and `snapshot_sha256`. No scanner, EPSS or OSV request is made. The
snapshot's audit data is also covered by its hash. Keep reference JSON files
with LF line endings; changing any snapshot byte requires updating the labels'
hash after reviewing the change.

`evaluate.py` accepts one report/project/snapshot per invocation. It also accepts
ordinary `depquiet --json` reports with `scanned: true`. Supply `--snapshot FILE`
to bind the evaluation to a versioned context file, or provide
`snapshot_sha256` from a harness that actually scanned that snapshot. If both
are supplied, their hashes must agree. Supplying a file alongside an unrelated
report does not independently prove which source the report scanned: use a
harness for that connection. `--project ID` explicitly maps a local CLI path to
a stable reference identifier; this is supplied metadata, not source attestation.

Each label requires `project`, `snapshot_sha256`, `package`, `version`,
`advisory`, `label`, `reason`, and `provenance` containing `kind`, `source` and
`reviewer`. Provenance kind is `synthetic` or `reviewed`. Package/version/advisory
matching is exact, using the report's `cve` field for the advisory; the evaluator
does not invent advisory alias or version-range equivalences. In particular,
scanner version-range strings are not silently converted into installed versions.

The JSON output exposes counts, case details, per-label reference totals and
uniquely matched totals. Every rate includes its numerator and denominator;
unmatched and duplicate cases are unscored. A zero denominator produces `null`,
not an apparent zero error rate. No aggregate accuracy metric is reported.

| Reference label and observed verdict | Count | Safety gate |
| --- | --- | --- |
| `retain` → `filtered` | `false_dismissals` | Fail |
| `unknown` → `filtered` | `uncertain_dismissals` | Fail |
| `filter` → `filtered` | `correct_dismissals` | Pass |
| `filter` → `action` or `review` | `retained_opportunities` | Pass |

Both `action` and `review` mean retained. Missing reference cases, duplicate scan
identities, unlabelled scan identities, and missing/false `scanned` fail the
gate. Duplicate reference identities, malformed data, conflicting project/hash
identities and invalid verdicts are invalid inputs. Exit codes are **0** for a
passing gate, **1** for safety/coverage regressions, and **2** for invalid inputs.
The gate enforces complete label coverage, including unknown cases; reducing
the set of observed alerts cannot make an incomplete run pass.

## Curating real cases

Use a separate versioned corpus with `kind: reviewed`; do not relabel these
synthetic examples as real evidence. Pin the upstream project revision, complete
source/manifests/lockfiles, scanner version and raw advisory input. Save a context
snapshot and hash its exact bytes, and use a harness that records that identity
when it generates the report. Preserve the review evidence alongside the label.

For each package/version/advisory identity, document what was inspected and the
deployment assumptions. A named independent reviewer should check the rationale
against the advisory's actual affected behavior and production exposure. Use
`unknown` whenever that evidence is incomplete or contested. Absence of an import
alone is not a real-world `filter` label. Review label changes separately from
engine changes and preserve reviewer, evidence source and snapshot identity.
Report synthetic and reviewed samples separately, with their explicit coverage
and denominators; this small gate does not establish population-level accuracy.
