# Multi-shape funding verification pilot

Source base `0ed660836` plus the archived `shape-reader-final.patch`; the commit
carrying this report contains that change. Same local Release build and host as
the preceding component run, with `RAYON_NUM_THREADS=48`. The cost target was
built after restoring all mutations. The unrelated prediction-market edit was
not included. This pilot did not capture fresh affinity, load or kernel metadata
and is not an isolated or cold-device experiment.

Command from the repository root:

```sh
env RAYON_NUM_THREADS=48 build/uno/crypto/test-uno-crypto-cost \
  --measure-funding-shapes \
  build/uno-shapes-restored-NIw366/funding-2.bin \
  build/uno-shapes-restored-NIw366/funding-4.bin \
  build/uno-shapes-restored-NIw366/funding-8.bin
```

The command exited 0. Its 183 JSON records comprise three first-call records
and 180 measured records: three Action dimensions, three call counts, two
outcomes and ten samples. Output counts and payload arithmetic were checked
independently. Each shape uses one public output-only fixture; repeated calls
are not a legal batch of independently funded transactions.

Valid-call ABI time (milliseconds, ten samples per row):

| Actions per proof | Calls | Median | Maximum |
|---:|---:|---:|---:|
| 2 | 1 | 10.070773 | 10.747437 |
| 2 | 16 | 92.571631 | 127.414536 |
| 2 | 64 | 420.007573 | 461.916910 |
| 4 | 1 | 10.254283 | 10.380065 |
| 4 | 16 | 169.285003 | 175.309571 |
| 4 | 64 | 604.778451 | 675.512369 |
| 8 | 1 | 13.650793 | 14.793493 |
| 8 | 16 | 217.117729 | 227.255509 |
| 8 | 64 | 906.203377 | 1054.208214 |

The first two-Action call, including key construction, took 2093.320425 ms
total; subsequent shapes did not rebuild that key. Process HWM was 10752 KiB,
dominated by the shared small-fixture process, not resident distinct-batch data.
The late-failure rows are retained in full, not discarded as failed samples.

Evidence: `measurements/uno-d3-shape-reader.tar.gz` includes source identity,
final and mutant patches, build logs, three behavioral red self-tests, restored
registered CTest output and raw measurement records. Fixtures themselves are in
`measurements/uno-d3-shape-generation.tar.gz`. Removing declared-length matching,
the supported-dimension check, or the trailing-byte rejection independently
made self-test exit 1. Restoration passed the single registered cost self-test;
no full-suite result is claimed. These are manual mutation records, not an
automated mutation CI facility. Milestone review remains pending under the
current review cadence.

Proof bytes are affine in Action count for this profile, so varying Action count
separates proof-count from Action-count observations but does not independently
identify a third proof-byte coefficient. Fixed seeds, sequential order, only
output-only bundles, no distinct-batch working set and no full state/commit path
still limit interpretation. No coefficients, maximum verification count, safety
factor, input limits or production schema are installed or recommended here.
This is not a WCET result or evidence that the full synchronous validation path
fits its deadline. D-3/B3-1 and the capacity/claim-only gates remain open.

## Spend follow-up

Base `1e406f9a2` plus the archived `spend-shape-final.patch`. This follow-up uses
2/4/8 real spends, all consuming distinct notes recovered from each corresponding
funding bundle, with a 100 nanotomi fee. The observation bracket was
2026-09-06 12:28:00–12:29:07 UTC (the latter was recorded after observing process
completion, not an exact process exit timestamp). The same Release target was
rebuilt with 48 jobs; verification used `RAYON_NUM_THREADS=48`. CPU/build metadata
and start/end load are archived; one-minute load rose from 2.99 to 9.39. No
affinity, cache eviction or workload isolation was applied.

Command: `env RAYON_NUM_THREADS=48 build/uno/crypto/test-uno-crypto-cost
--measure-spend-shapes build/uno-spend-restored-eR7sfD/spend-2.bin
build/uno-spend-restored-eR7sfD/spend-4.bin
build/uno-spend-restored-eR7sfD/spend-8.bin` (one shell command).

Exit 0; all 183 records had the expected context, dimension, call count, sample
count and ABI payload size. Valid-call ABI milliseconds, ten samples per row:

| Actions / real spends | Calls | Median | Maximum |
|---:|---:|---:|---:|
| 2 | 1 | 10.248195 | 11.427614 |
| 2 | 16 | 110.275092 | 146.572783 |
| 2 | 64 | 337.677084 | 444.194017 |
| 4 | 1 | 10.349431 | 10.693228 |
| 4 | 16 | 146.183745 | 174.978032 |
| 4 | 64 | 513.339908 | 663.688010 |
| 8 | 1 | 17.504120 | 18.203118 |
| 8 | 16 | 242.343022 | 293.292514 |
| 8 | 64 | 877.154647 | 1155.363396 |

First call with key construction: 2089.691046 ms total; process HWM 10752 KiB.
The same small-fixture/repeated-request and sequential-order limitations apply;
these observations are not a controlled funding-versus-spend comparison or a
claim that later runs improved performance. No admission coefficients or limits
are inferred.

Evidence `measurements/uno-d3-spend-shapes.tar.gz` contains public fixtures,
source/base and mutation patches, build/test logs, environment observations and
raw JSON. Repeating the first output position made the distinct-input assertion
fail; choosing the current node instead of its sibling made the root comparison
fail (both exit 101). Removing the C++ balance/context check made its self-test
accept spend as funding and fail (exit 1). Restored fixture generation and the
single registered cost self-test passed. Original and restored spend fixtures
were byte-identical. This is manual evidence; external milestone review remains
pending. Independent seeds and distinct-request working sets, full lifecycle
workloads and the full synchronous validation envelope are still missing.
