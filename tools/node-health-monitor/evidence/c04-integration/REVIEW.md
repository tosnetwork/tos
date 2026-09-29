# C04 integrated review — scoped development acceptance

Reviewed runtime tree: `b67f67981` on `node-health-monitor`.
Consumer parent: `00eef3198abd1b7421d6b3406ace88d56d25e74c`.
Native original: `e89ca322253e1c7a7acb87d16d63f974e462158e`;
integrated native commit: `b67f67981` (clean cherry-pick, no resolution).
Authority: R4 design and work order, memo interface ruling `dd07098`,
publication budget amendment `49462b89`, serial collection amendment
`d7dff8c69980021cc883e84bb84debb49572b4a3`.

## Independent checks

- All 199 indexed source, artifact and binary files re-hashed without mismatch.
- All 142 compiled C04 catalog tuples exactly match the manifest. Histogram
  suffix expansion gives 249 unique combined tuples, within 256/2048 limits.
- Action and persistence manifest source digests and named anchors match.
- Integrated metrics/validator/native test source is byte-identical to the
  native candidate; no new native build is required to establish this identity.
- Independently executed restored native union: 35/35, natural exit 0.
- Four native compiled mutants: intended assertion red, restored build and
  control green; independent receipts and restored source hashes checked.
- Four consumer compiled mutants retained with intended assertion failures.
- Integrated fmt, all-target Clippy with warnings denied, locked contract suite
  and explicit actual-publisher pair gate each naturally exited 0. Raw logs and
  receipt are beside this report. The suite has 132 active workspace tests;
  the separately invoked pair test checks all 48 indexed pairs and the actual
  cache, HTTP edge route and collector path. No default ignored test is counted
  as execution.
- The pair/binary/consumer source hashes remained unchanged throughout these
  integrated checks. Native producer index and complete body/EOF hashes checked.

## Acceptance scope and open capabilities

Accept the C04 development implementation for bounded local action observation,
separate replay accounting, commit acknowledgement, typed progress, strict v2
consumer and finite publication contracts. Keep native-core-v1 behavior intact.
No monitoring rule activates C04 production facts from these synthetic actors.

This is not production acceptance. Native contract_valid/performance_gate flags
remain false. Provider construction cost before its return is not proven by a
post-return budget check; retain that source/performance gate for C09. Actor
ownership release does not prove drain: stopped remains null, lifecycle quality
is incomplete, and actor drain remains unverified. PQ queue, assigned duties,
vote deadlines, cohort rate, durable finality and network delivery remain
unsupported. The recorded memory boundary is 4,096,249 bytes against 4,194,304;
it is an isolated tested boundary, not a production peak measurement. Pool
failure fixtures and production DB actor/TestDb coverage do not prove hardware
power-loss durability. No business nodes, main merge or deployment authorized.

Historical test/build failures and prior drafts remain labelled as development
lineage. Final manifests and frozen schema govern this candidate.
