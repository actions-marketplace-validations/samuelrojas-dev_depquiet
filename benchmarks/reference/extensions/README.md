# Configuration-context extension

This is a separate, deliberately selected pair of advisory contexts from the
already pinned Node Express RealWorld source and its frozen audit. It adds two
identities without changing the original ten labels, snapshots or audit bytes.
The extension does not add another independent project to the corpus.

| Case | Agent proposal | Observed context |
| --- | --- | --- |
| serve-static / GHSA-cm22-4g7w-348p / `<1.16.0` | `retain` | The production entry point mounts `express.static`; the redirect-template advisory warrants investigation. |
| body-parser / GHSA-v422-hmwv-36x6 / `<1.20.6` | `unknown` | The inspected parser constructions omit `limit`; the advisory requires invalid limit configuration. Completeness of runtime/deployment configuration has not been adjudicated. |

These are **agent proposals with human review pending**: one `retain`, one
`unknown`, zero `filter`. No safe-dismissal rate or human-validation result can
be calculated from this pair. A selected `unknown` case must remain visible.

The body-parser case records configuration evidence that could be useful when a
person reviews a possible dismissal. It deliberately remains `unknown`: the
entry-point constructions alone are not treated as a complete runtime or
deployment proof. It must not be promoted to `filter` merely to produce a noise
reduction number.

## Provenance and boundaries

- Source commit: `30b68e1e881462b2f4164ea09ab4c4f5699c7b0b` in
  `gothinkster/node-express-realworld-example-app`.
- The audit is the existing npm 10.9.9 capture from 2026-11-04; it was not
  recaptured. The extension snapshot hashes those same audit bytes.
- `derived_from_context` identifies the original snapshot and its SHA-256.
  The new snapshot has its own hash because its explicit selection differs.
- Labels record Git blob IDs, hashes of raw blob contents, line ranges,
  advisory URLs checked on 2026-11-09, reported ranges and lockfile candidates.
  Checkout line-ending conversions are not the content-hash authority.
- Locked versions are not observations of an installed or deployed version.
  Source, request behavior, browser interaction and effective deployment remain
  separate facts. Automatic product-impact assessments stay under investigation.
- Both contexts share one project/source/audit. They are not a random sample,
  independent observations of product performance or a population-level accuracy
  estimate. All other rows are outside this extension's evaluation, including the
  original RealWorld identities evaluated by the original snapshot.

Primary advisory conditions were checked against
[serve-static's advisory](https://github.com/advisories/GHSA-cm22-4g7w-348p) and
[body-parser's invalid-limit advisory](https://github.com/advisories/GHSA-v422-hmwv-36x6).
The latter concerns invalid configuration, which differs from the URL-encoded
parsing advisory already selected in the original corpus. Reported version
ranges remain literal identities and are not interpreted as installed versions.

## Offline replay

Prepare a clean checkout at the exact source commit separately. It must contain
the required Git objects without partial/promisor lazy fetching; an ordinary
shallow checkout is supported. The replay harness does not clone repositories,
install dependencies, run upstream code or request advisory/scanner data.

From the depquiet repository root:

```sh
python benchmarks/reference/run_reviewed.py --snapshot benchmarks/reference/extensions/realworld-configuration.snapshot.json --source-dir /path/to/pinned-clean-checkout --output configuration-scan.json
python benchmarks/evaluate.py --labels benchmarks/reference/extensions/realworld-configuration.labels.json --scan configuration-scan.json --snapshot benchmarks/reference/extensions/realworld-configuration.snapshot.json --json
```

The evaluated scope contains exactly two selected identities. The evaluator
checks retention, presence and uniqueness for those identities; passing it does
not certify the correctness of every audit row or independently approve these
proposed labels. Human records must remain pending until an actual person
provides their judgement and evidence through the review workflow.
