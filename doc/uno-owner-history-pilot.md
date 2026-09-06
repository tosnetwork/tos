# Permanent terminal-owner history comparison

The prior reservation-root pilot had only one current owner per affected page.
This comparison adds a historical refunded owner and single-key manifest for
every historical spent key, while keeping the same keys and current two-key
event. It measures existing NullifierState primitives, not a new Reserve,
identity schema, receipt protocol or authorized production migration.

## Fixture and checks

`owner-refund` constructs historical state through real reserve/refund calls,
one unique fixture owner per key. The key bytes themselves identify that owner
only in this experiment. Zero is reserved for the current event and collisions
are explicitly rejected. The used-only baseline is constructed independently.
Full `from_roots` restoration checks historical manifests against that baseline.
Each sample starts from the same immutable history; events do not accumulate
between samples. Historical construction is outside sample timers.

The new `load_reservation_state` phase measures restoration of used and owner
roots before the current reservation. Both `refund` and `owner-refund` now
include that phase. The four full-root codec phases retain their definitions
from `uno-reservation-roots-pilot.md`; owner and total-manifest restore bounds
include the per-page history through checked additions. Final assertions query
every old spent key and check every old owner remains in refunded status.

The registered self-test checks historical owner reuse with a different fresh
key, not just root equality. Replacing fixture reserve/refund with direct
used-key insertion preserves spent history but omits terminal owners; CTest
then exits 8 on that behavioral check. Restoring the fixture passes CTest.
The executable retains checked output flushing and its existing exception
boundaries; no consensus judgement or error classification changed. External
review remains pending at the milestone.

## Reproduction and source

Base `c440bc0ec` plus `owner-history-final-source.patch` in
`doc/measurements/uno-owner-history-pilot.tar.gz` identifies the measured source.
Build `measure-uno-partition-state` with `-j48`, then capture stdout and stderr
separately for each invocation:

```sh
for mode in single pages16; do
  for history in 0 1024 8192 32768 65536; do
    for scenario in refund owner-refund; do
      build/measure-uno-partition-state "$mode" "$scenario" "$history" 3 45 || exit 1
    done
  done
done
```

Twenty serial invocations passed, producing 1020 phase rows and 120 byte
breakdowns. Each of 17 phases has three samples per invocation. Byte totals
equal checked sums of used/reserved/owner BoCs, and all three samples agree.
Environment: 2026-09-06, approximately 13:51 UTC, Release clang++-21,
`-O3 -DNDEBUG`, Xeon Platinum 8455C. The archive includes environment observations,
source and mutation patches, build logs, restored CTest and raw data. No CPU
pinning, host isolation or controlled cold-cache conditions were established.

## Results at 65,536 historical keys

All sizes below are sums of independent BoCs, not deduplicated account or
CellDb sizes. The owner component includes manifests and their framing.

| Mode / history | Pending owner bytes | Pending total bytes | Refunded total bytes | Median initial full restore ms | Median pending full decode/validate ms | Median refunded full decode/validate ms |
| --- | --- | --- | --- | --- | --- | --- |
| single / spent only | 93 | 2794050 | 2793982 | 20.2124 | 38.5262 | 38.2457 |
| single / spent + terminal owners | 5368183 | 8162140 | 8162072 | 229.843 | 258.324 | 262.036 |
| pages16 / spent only | 104 | 2663159 | 2663081 | 25.5341 | 45.0001 | 40.5956 |
| pages16 / spent + terminal owners | 5171738 | 7834793 | 7834715 | 204.238 | 215.707 | 229.833 |

Historical owners remain after the current refund, so the owner byte column is
unchanged between pending and refunded cuts. Used bytes and the two current
reservations match their controls; the extra content is not extra transactions
in the current event. Median pending serialization was 28.3259 / 88.7781 ms
for single spent-only / owner-history, and 28.8189 / 68.8523 ms for pages16.

Maximum process HWM across these invocations was 99232 / 152856 KiB for the
single control/history and 99604 / 154872 KiB for pages16. It includes historical
construction, redundant fixture roots, metrics and restored arenas, not
phase-local memory or a deployed validator's requirement. The largest phase
observed in the whole run was 271.394 ms, single owner-history refunded full
decode/validate; this is neither WCET nor a full validation deadline bound.

## What this does not establish

Owner history is not a fixed-size addition: this dataset supplies direct
size and full-restore evidence for that component. It still covers only
uniformly distributed, single-key refunded manifests. It does not cover large
manifests, accumulated pending/Paid mixtures, concentration, authenticated
receipts, note reservations, Native balances/fees, account limits for a complete
schema, physical persistence, coordinator/participants or migration peaks.
Large single used dictionaries already exceed the known Native data-cell bound.
No production schema, admission limit, cost coefficient, retirement feasibility
or deadline safety margin is selected; Y-1/D-3 remain open.
