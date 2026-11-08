# Pinned upstream reference contexts

This first set contains **10 selected advisory contexts from four real projects**:
five labelled `retain` and five `unknown`. They were curated by Codex agents with
source/advisory checks and a second evidence check; **human review and independent
external validation are pending**. `provenance.kind: reviewed` describes that
recorded process, not human approval. The labels explicitly record both limits.

| Pinned project | Cases | `retain` | `unknown` | Files |
| --- | ---: | ---: | ---: | --- |
| [Mealie](https://github.com/mealie-recipes/mealie/tree/01713b04163e9524b2665ad8089148b6d2f90233) | 4 | 2 | 2 | [snapshot](mealie.snapshot.json), [labels/evidence](mealie.labels.json) |
| [Paperless-ngx](https://github.com/paperless-ngx/paperless-ngx/tree/09d70ed7da7f56b9c197a57518fd363a1fddc3ff) | 1 | 0 | 1 | [snapshot](paperless-ngx.snapshot.json), [labels/evidence](paperless-ngx.labels.json) |
| [Node Express RealWorld](https://github.com/gothinkster/node-express-realworld-example-app/tree/30b68e1e881462b2f4164ea09ab4c4f5699c7b0b) | 2 | 2 | 0 | [snapshot](node-express-realworld.snapshot.json), [labels/evidence](node-express-realworld.labels.json) |
| [Node Express Boilerplate](https://github.com/hagopj13/node-express-boilerplate/tree/179ae84efec61b14206d0305d941daed6c6d07f9) | 3 | 1 | 2 | [snapshot](node-express-boilerplate.snapshot.json), [labels/evidence](node-express-boilerplate.labels.json) |

`retain` means the reviewed source context warrants keeping the alert visible;
it is not proof of exploitation. `unknown` means the relevant deployment or
vulnerable-feature conditions could not be established. Neither label permits a
`filtered` verdict. There are **zero `filter` labels**, so this set cannot measure
correct dismissals, a false-positive rate, or safe alert reduction. Automatic
product-impact assessments remain `under_investigation` for every case.

Each case records its rationale, limitations, primary advisory link, source
locations, Git blob IDs and SHA-256 hashes. Locked versions are distinguished
from installed versions: no installation or runtime exposure was observed.
For npm, identity preserves the parser's advisory range; separately listed
lockfile versions do not turn that range into an observed installation.

The audits were already captured on **2026-11-04** using npm 10.9.9 or pip-audit
2.10.1. They were not recaptured for this set. The boilerplate snapshot also uses
the previously captured generated npm lockfile as an explicit hashed overlay;
it is not presented as an upstream Git blob. Capture limitations, including an
unexamined duplicate Python lockfile variant outside the selected cases, remain
in snapshot metadata. This is a replay of frozen inputs, not a current
vulnerability inventory or a test of scanner freshness.

CI replays all four contexts and uploads scan/evaluation JSON. It scans the full
frozen inputs but evaluates only the selected ten identities. The other findings
have no reference labels and are explicitly outside this gate. Passing it means
only that these selected cases were present once, retained and scanned completely.
It does not establish full-project coverage or population-level accuracy.

## Reproducing a context

`../run_reviewed.py` reproduces an evaluation context from a caller-provided,
clean local Git checkout and frozen audit/overlay files. It never downloads a
repository, installs packages, runs lifecycle scripts or upstream application
code, or requests scanner/EPSS/OSV data. Prepare the checkout separately at the
exact revision recorded in the snapshot; a branch name is insufficient.

For example, prepare the RealWorld source in a separate directory, then run from
the depquiet root (Python 3.11+ and Git are required; no package install is needed):

```sh
git clone https://github.com/gothinkster/node-express-realworld-example-app.git ../depquiet-reference-realworld
git -C ../depquiet-reference-realworld checkout --detach 30b68e1e881462b2f4164ea09ab4c4f5699c7b0b
python benchmarks/reference/run_reviewed.py --snapshot benchmarks/reference/real/node-express-realworld.snapshot.json --source-dir ../depquiet-reference-realworld --output reviewed-scan.json
python benchmarks/evaluate.py --labels benchmarks/reference/real/node-express-realworld.labels.json --scan reviewed-scan.json --snapshot benchmarks/reference/real/node-express-realworld.snapshot.json --json
```

Only preparing the checkout needs network access. For another project, use its
snapshot's repository and full commit, then the corresponding files below:

```sh
python benchmarks/reference/run_reviewed.py --snapshot benchmarks/reference/real/PROJECT.snapshot.json --source-dir /path/to/clean-upstream-checkout --output reviewed-scan.json
python benchmarks/evaluate.py --labels benchmarks/reference/real/PROJECT.labels.json --scan reviewed-scan.json --snapshot benchmarks/reference/real/PROJECT.snapshot.json --json
```

Each snapshot is JSON with this contract:

```json
{
  "schema_version": 1,
  "kind": "upstream_reference",
  "project": "stable/project-id",
  "source": {"repository": "owner/name", "commit": "FULL_40_CHARACTER_COMMIT"},
  "audit": {"path": "benchmarks/fixtures/PROJECT/audit.json", "sha256": "SHA256_OF_EXACT_BYTES"},
  "overlay_files": [
    {"path": "benchmarks/fixtures/PROJECT/package-lock.json", "target": "package-lock.json", "sha256": "SHA256_OF_EXACT_BYTES"}
  ],
  "selection": [
    {"package": "package-name", "version": "EXACT_REPORTED_VERSION_OR_RANGE", "advisory": "ADVISORY_ID"}
  ]
}
```

`overlay_files` and `selection` are optional. Audit and overlay paths must resolve
inside this repository's `benchmarks/fixtures` directory, and their raw bytes
must match the recorded SHA-256. Overlay targets must remain inside the temporary
project. Hashes are not normalized for line endings. Reference and frozen fixture
files therefore need the repository's LF rules when checked out on Windows.

The harness requires `--source-dir` to be the checkout root, verifies its HEAD
against the full commit, and rejects tracked, staged and untracked changes.
During that check it disables configured Git clean/smudge/process helpers, hooks
and filesystem monitors, and avoids submodule traversal. A checkout whose clean
state depends on a content-transforming helper may be rejected; the helper is
never run. Git replacement refs and lazy object fetching are disabled, and
partial/promisor clones are rejected. Ordinary shallow clones are supported.
See the [Git options and environment reference](https://git-scm.com/docs/git).
Ignored working-tree files are not materialized. It reads committed Git blobs in
one batch, preserving exact commit content without checkout transformations or
`export-ignore` exclusions. `.git` and `node_modules` directories are excluded.
Symlinks and submodules outside those exclusions are unsupported and cause an
explicit error, rather than silently omitting their context. Repository identity
is recorded provenance supplied by the curator; offline verification establishes
the commit and content, not a remote hosting account's ownership.

Python distribution-to-import metadata from the harness interpreter is excluded
during analysis and recorded as `reference_context.host_python_metadata_excluded`.
The engine's versioned mapping/rules still apply, and any virtualenv metadata
committed in the source tree remains part of the pinned input. Installing an
unrelated package beside the harness cannot add import aliases to this replay.

The entire frozen audit is scanned offline before any projection. If `selection`
is present, the resulting report retains only those exact package/version/advisory
identities. Selection comes from the versioned snapshot, never from labels or
verdicts. Missing identities remain absent and must fail the evaluator's coverage
gate; the harness does not manufacture rows. A conservative `action`/`review`
decision cannot remove a selected row. Report `evaluation_scope` records the
selection, selected/unselected row counts and `full_scan_summary`; `summary` is
recomputed for the projected rows. Without selection, all report rows are kept.
Audit hashes and source revision always describe the full frozen input.

These selected advisory contexts do not establish full-project label coverage
or population-level accuracy. Labels apply only to their declared evaluation
scope. `unknown` remains appropriate where product impact cannot be established.
Use the exact version/range emitted by the current parser for identity matching;
do not infer installed versions from an advisory range. Any separately reviewed
installed-version evidence belongs in the case provenance, not an invented
replacement for the parser's output.

The CLI serializer supplies the report's assessment, evidence and decision trace.
Temporary materialization paths are replaced with relative paths. `scanned` is
preserved from the engine; incomplete scans cannot be presented as complete.
Exit **0** means the harness generated a complete report, not that labels passed
or that vulnerabilities are safe. Exit **1** means the scan was incomplete;
exit **2** means the snapshot, checkout or frozen artifact was invalid. Run the
separate evaluator to enforce reference safety and coverage gates. The harness
unit tests use only invented packages/advisories and temporary local Git repos;
they are synthetic mechanism tests, not reviewed upstream cases.

## Extending the labels

A human reviewer should check the pinned source, relevant advisory behavior,
dependency versions and deployment assumptions before endorsing a label. Record
their identity and rationale separately; preserve the agent review history.
Do not change a label merely to make an engine regression pass. Additional real
`filter` cases need positive evidence supporting dismissal, beyond an absent
import, and separate review. Report any new sample's coverage and limitations.
