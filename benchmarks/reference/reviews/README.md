# Pending review packets

These five immutable example packets cover twelve selected real advisory contexts:
the original ten plus two configuration-extension identities. Every record is
`pending`, with no reviewer ID, judgement, evidence or timestamp. There are zero
completed human reviews; the packets do not establish validation or independence.

| Packet | Bound labels | Cases |
| --- | --- | ---: |
| `mealie.pending.json` | `../real/mealie.labels.json` | 4 |
| `node-express-boilerplate.pending.json` | `../real/node-express-boilerplate.labels.json` | 3 |
| `node-express-realworld.pending.json` | `../real/node-express-realworld.labels.json` | 2 |
| `paperless-ngx.pending.json` | `../real/paperless-ngx.labels.json` | 1 |
| `realworld-configuration.pending.json` | `../extensions/realworld-configuration.labels.json` | 2 |

Keep these templates pending. Copy a packet to record actual separately supplied
reviews, preserving its label/case/snapshot bindings. The
[workflow and schema](../../../docs/reference-reviews.md) explain metadata,
disagreements and opt-in coverage gates. `check` validates declarations; it does
not authenticate people or turn proposed labels into human-adjudicated truth.
