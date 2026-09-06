# Distinct-request ABI corpus pilot

Base `52136d7a8` plus archived `corpus-final.patch`. The corpus contains eight
sample IDs for each of funding/spend and 2/4/8 Actions: 48 proofs. Structural
inspection found all 48 proof byte strings different, with 112 distinct public
nullifiers for funding and 112 for spend across all shapes. Each file was
generated and verified through the real ABI, including a changed-digest negative
control. Seeds are public, deterministic and described in
`uno-d3-multishape-fixtures.md`; keys and controlled amounts remain shared.

Generation: run `export_measurement_shapes` as documented, with
`UNO_SHAPE_SAMPLE` set to each integer 1 through 8 and output directories
`build/uno-corpus-ye7uvZ/1` through `/8`. All eight commands exited 0. Invalid
sample ID 256 failed before key construction (exit 101). Restored seed-identity
unit test and the single registered C++ cost self-test passed.

Measurement command:

```sh
env RAYON_NUM_THREADS=48 build/uno/crypto/test-uno-crypto-cost \
  --measure-corpus build/uno-corpus-ye7uvZ
```

Release build on the same 192-logical-CPU host, 48 build jobs. No affinity,
cache eviction or workload isolation. The observation bracket was
2026-09-06 12:37:22–12:38:31 UTC; the end is recorded after observing completion,
not an exact process exit timestamp. One-minute load was 4.17 then 4.07.
The command exited 0 with 246 records: six first-batch rows plus twenty valid
and twenty late-failure rows per context/shape. Each batch contains eight
distinct fixture objects with independent backing buffers. All row counts,
dimensions, call counts and payload sizes were checked independently.

Valid eight-call ABI time, milliseconds (20 repetitions per row):

| Context | Actions per request | Median | Maximum |
|---|---:|---:|---:|
| Funding | 2 | 63.544015 | 81.258486 |
| Funding | 4 | 83.662339 | 94.298072 |
| Funding | 8 | 145.656906 | 150.223781 |
| Spend | 2 | 53.948531 | 59.780819 |
| Spend | 4 | 83.114822 | 87.264757 |
| Spend | 8 | 108.363566 | 151.656803 |

First batch including key construction: 2108.793938 ms total. Process HWM was
10752 KiB. The largest group has 223744 ABI payload bytes, far below a maximum
candidate working set. Corpus loading, uniqueness checking, request-list copying
and limit derivation occur outside the timed admission/ABI interval. No full
preflight or full-block timing claim follows from these rows.

## Instrument controls

- Removing the seed sample-byte contribution made the literal expected-byte
  test fail (exit 101), rather than merely comparing two calls to one function.
- Replacing distinct requests with repetitions of the first made the C++ test
  fail (exit 1); it checks visited request identities and independent expected
  totals for mixed two-/four-Action inputs.
- Copying sample 1's funding-2 file onto sample 2's in a separate corpus caused
  rejection before output (exit 2 with a duplicate-nullifier diagnostic).
  Temporarily disabling that guard let the incorrect corpus return success
  and emit 246 rows, contradicting the required rejection. The mutant's data
  are evidence of instrument failure, not performance results. The guard was
  restored before the valid measurement and final registered self-test.

Raw files, patches, logs, environment observations and public fixtures are in
`measurements/uno-d3-distinct-corpus.tar.gz`. These are manual historical mutation
experiments, not automated mutation CI. External review remains pending the
milestone under the current review cadence; no consensus judgement path or
error classification changed.

Distinct seeded witnesses are not statistically independent fresh samples on
each repetition. Groups share keys and controlled amounts; spend anchors come
from separate synthetic funding trees, not one authenticated production state.
Thus this is still not a legal chain batch or a Deposit/Withdrawal lifecycle
test. No weights, maximum verification count, input limits, safety margin,
production schema or WCET conclusion is supplied. Those remain tied to larger
working sets and the complete state/proof/execution/serialization/commit path.
