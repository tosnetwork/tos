# State work outside incremental commit timers

This extends `uno-incremental-partition-pilot.md`, not the production host.
The earlier prepare/stage/write timings exclude significant state work. New
`INCREMENTAL_STATE_CSV` rows expose that work without moving it into a database
commit timer or claiming an end-to-end validation deadline.

## Boundaries

- `resolve_update_ms` starts after the baseline KV scan and before loading the
  old shard root. It includes Account unpack, full `UsedNullifiers::from_root`
  validation, absence checks, insertion, account dictionary updates and packing
  the next shard root. It includes invariant assertions in that region. Each
  of the two keys uses the current full-validation path, even when they share
  a page; this is not an incremental validated-state cache implementation.
- `serialize_ms` serializes the complete new shard state to BoC, after both
  commits, all record scans and final spent-state verification. Moving this
  before commit would warm all pages and change the earlier experiment.
- `decode_ms` reconstructs that complete BoC into a new in-memory arena. The
  decoded root must equal the committed next root and differ from the old root.
  This is not a fresh database import or authenticated checkpoint verification.

Fields after the prefix: history count, seed, pages, shape, resolve/update ms,
serialize ms, decode ms, BoC bytes and process HWM KiB. The same environment
controls, command matrix and fixture limitations as the preceding pilot apply.
RSS includes fixture and KV maps, prior work and both serialization arenas;
it is not phase-local. The clock is steady_clock. No amount arithmetic or new
exception handling/classification is introduced. No production schema changed.

## Data and source

Base `0c9b9d6c2`, plus `incremental-stages-final-source.patch` in
`doc/measurements/uno-incremental-state-stages.tar.gz`, identifies the measured
source. The later restored-source patch additionally checks output stream
failure after all timers. Do not describe this matrix as a run of that later
revision. Both patches and the successful final smoke log are archived.

The serial matrix ran around 13:28 UTC on 2026-09-06 with Release clang++-21,
`-O3 -DNDEBUG`, the same Xeon Platinum 8455C host and v2 extra_threads=0.
Observed load during the run was 3.11/2.39/2.38. There was no host isolation or
OS-cache eviction. All 48 processes passed, yielding 48 new stage rows in
addition to 96 retained/released record rows. Each scenario has three samples;
their BoC sizes agree. Seed is 91 throughout.

At 65,536 historical keys plus two inserts:

| Pages | Shape | Median resolve/update ms | Median serialize ms | Median decode ms | BoC bytes | Maximum HWM KiB |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | uniform | 381.246 | 43.9932 | 33.2874 | 2794119 | 204620 |
| 16 | uniform | 41.9777 | 46.2605 | 23.6263 | 2795665 | 202824 |
| 1 | prefix | 362.567 | 41.3900 | 26.7497 | 1729581 | 196168 |
| 16 | prefix | 349.080 | 45.2130 | 24.7181 | 1731248 | 189688 |

Across this run, individual phase maxima were 421.403, 82.8531 and 53.8559 ms,
respectively. These are observed maxima, not WCET or a sum representing one
end-to-end sample. The single-account and concentrated large-page controls
remain beyond the Native data-cell bound; their successful storage operations
do not authorize those states. The uniform update touches only two small pages,
whereas both concentrated updates revalidate the large page. This fixture
demonstrates distribution-dependent full-validation work, not a general speedup.

## Instrument checks and remaining work

Serializing the old root instead of the new root makes the registered smoke
fail the root-identity assertion (CTest exit 8). Restoring it passes. Output
failure is now checked after flushing the measurement: `/dev/full` exits 1
with a stream-state diagnostic. Removing that check returns 0 despite no
record being written; restoring the check and the normal smoke passes. Exact
mutation patches and diagnostic logs are archived. These are manual mutations,
not automatic mutation CI. External review remains pending at the milestone.

The three input limits and production schema remain unselected. Missing work
still includes bounded coordinator/participants, complete state and obligation
shapes, persistent splits/migration, authenticated ingress and proofs, and a
single full validation envelope under a real deadline. Serialization measured
after all reads is warm; this is not the required controlled cold/warm suite.
Do not combine this partial dataset with proof medians to claim deadline safety.
