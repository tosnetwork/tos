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
