# Reference review workflow

This workflow records caller-declared judgements about pinned reference cases.
It never imports a human decision into proposal labels automatically. The current
real sample contains twelve selected contexts from four projects: the original
ten and a separate two-case configuration extension. All twelve human records
are pending. There are no real `filter` labels, so safe-dismissal quality and
time savings remain unmeasured.

## Start with a pending form

From the repository root, use a committed packet or prepare a separate file:

```sh
python benchmarks/reviews.py init --labels benchmarks/reference/extensions/realworld-configuration.labels.json --output my-configuration-reviews.json
python benchmarks/reviews.py check --labels benchmarks/reference/extensions/realworld-configuration.labels.json --reviews my-configuration-reviews.json --json
```

`init` reads the labels once, creates only pending records with no reviewer ID,
decision, evidence or timestamp, and atomically creates a new file. It refuses
existing destinations and cannot replace its source labels. Choose another output
path to preserve prior records. `check` is offline: it validates structure and
bindings, not whether a person performed a review.

Committed `.pending.json` files in `benchmarks/reference/reviews/` are templates,
not completed judgements. Copy a template for actual records. Do not fill a human
identity, decision or timestamp using automated curation.

## Record an actual judgement

Before consulting proposed labels or depquiet results where feasible, the reviewer
checks the primary advisory, exact pinned code/lockfiles and the declared context.
Public labels cannot guarantee a blind review. Record any prior exposure honestly.
Missing deployment or behaviour evidence warrants `unknown`; an absent import
alone is insufficient for a real-world `filter` decision.

After a person supplies a judgement, change only their separate record:

| Field | Required submitted value |
| --- | --- |
| `status` | `submitted` |
| `actor.kind` | `human` or `agent`, reported separately |
| `actor.id` | Stable agreed identifier; no personal email is required |
| `actor.relationship` | `founder`, `collaborator`, `external` or `unknown` |
| `exposure.reference_label_seen` | Explicit boolean |
| `exposure.depquiet_result_seen` | Explicit boolean |
| `decision` | `retain`, `filter` or `unknown` |
| `reason` | Nonempty rationale for this behaviour/context |
| `reviewed_sources` | Nonempty array of source references actually checked |
| `limitations` | Array of assumptions, missing evidence or limits |
| `submitted_at` | Supplied timezone-aware ISO timestamp |

For another reviewer of the same case, append a separate copy with a unique
`record_id` and that reviewer's metadata. Keep its case bindings intact. Duplicate
records or the same reviewer appearing twice for one case are rejected. An actor
ID cannot switch kind or project relationship within a bundle to inflate coverage.
The tool does not authenticate that IDs describe distinct people.

Agents and founder rehearsals can document useful work. They do not become
independent external validation. External relationship and exposure are declared
metadata, not verified credentials or proof of experimental blinding. Checked
source references are also supplied by the reviewer; the validator does not fetch
them or establish that their contents were read.

## Bindings and compatibility

Bundle schema version `1` has purpose `depquiet_reference_reviews`, a SHA-256 of
the exact labels file bytes and a `reviews` array. Each record binds `case_id`,
project, literal package/version/advisory, snapshot SHA-256 and a canonical hash
of the full proposed case. Existing case IDs are preferred; legacy cases without
an ID receive a deterministic identity-derived ID.

Changing labels bytes, case contents, snapshot, project or literal identity makes
an existing binding stale. Even whitespace-only labels-file edits change its byte
hash. Keep committed JSON in LF form and do not silently rebind old reviews to new
proposals. A later adjudication should create a separately reviewed version of
the labels and preserve the earlier records. Hashes detect input mismatches;
they are not signatures or source/identity authentication.

JSON keys must be unique, values finite, statuses and booleans typed correctly,
and all case bindings consistent. Foreign, malformed, duplicated or partially
completed records are invalid. A pending form has no completed decision/evidence
and never contributes to human-review coverage. Optional actor assignment does
not turn a pending form into a review.

## Evaluate scans and reviews separately

```sh
python benchmarks/evaluate.py --labels benchmarks/reference/extensions/realworld-configuration.labels.json --scan configuration-scan.json --snapshot benchmarks/reference/extensions/realworld-configuration.snapshot.json --reviews my-configuration-reviews.json --json
```

The original safety counts/rates still use `evaluation_basis: proposed_labels`.
Legacy provenance kind `reviewed` continues to mean recorded proposal provenance,
not human approval. Free-form old `human_reviewed` flags do not supply records.

The additional sections explain review coverage:

- `review_coverage` includes the complete reference denominator, declared human,
  external, unexposed-external and agent counts, pending cases/records, disputes
  and disagreements with proposals. Label bytes and the supplied review bundle
  hash are recorded by the evaluator CLI. Coverage `0 / N` describes no reviews;
  it is not a zero error rate.
- `human_review_audit` scores only uniquely matched cases with submitted human
  records. A declared `retain` or `unknown` consensus, including a dispute, adds
  a retention constraint. Filtering such a context fails the safety gate even
  if its proposal was `filter`. Missing/duplicate scan identities remain unscored
  in this audit and fail the existing inventory gate.
- A human `filter` record cannot loosen a proposed `retain` or `unknown`, rewrite
  a proposal or establish product non-affectedness. No last-write-wins rule is used.
- Conflicting human decisions produce `human_consensus: unknown` and a disputed
  case. A single submitted `unknown` is a completed uncertainty judgement;
  it still requires keeping the alert visible.

Rates include numerator, denominator and definition. No eligible human-retention
cases means a null audit fraction, never an apparent perfect error rate. Proposal
and human-record counts stay distinct. No population accuracy or safe-noise-
reduction estimate is produced.

## Optional coverage gates

```sh
python benchmarks/reviews.py check --labels benchmarks/reference/extensions/realworld-configuration.labels.json --reviews my-configuration-reviews.json --require-human-review --json
python benchmarks/evaluate.py --labels benchmarks/reference/extensions/realworld-configuration.labels.json --scan configuration-scan.json --snapshot benchmarks/reference/extensions/realworld-configuration.snapshot.json --reviews my-configuration-reviews.json --require-unexposed-external-review --json
```

`--require-human-review` requires at least one submitted human record per reference
case and no disputes. `--require-unexposed-external-review` additionally requires
each case to have an external human record declaring neither label nor result
exposure. These are coverage checks over declarations, not authenticated validation
or proof of independence. They do not require resolved product impact.

Default evaluation remains compatible with no review file or pending packets.
CI validates committed pending packets and displays their zero human coverage;
it does not require fictional completed records to pass.

Exit codes are `0` for valid `check` inputs or a passing evaluation, `1` for an
explicit coverage requirement or safety/inventory failure, and `2` for invalid
inputs. A valid pending packet passes format checking but fails a required-human
gate. Successful format validation never means a review was performed.
