# Multi-account storage import and reopen pilot

Base `23a83d6ba` plus the archived source patch. This test extends only the
snapshot test actor with an optional verifier; the original single-executor
verifier remains the default. The production host's single-account rule and
all consensus/schema definitions are unchanged.

The synthetic unsplit workchain-2 state contains either 1 or 16 ordinary Native
accounts holding raw used dictionaries. Addresses are experimental page indices;
balances, code/library and storage usage metadata are zero placeholders, as in
the preceding envelope pilot. These are not UNO participant accounts or valid
production UNO states. In particular, the 65536-key single account has 131071
data Cells, already outside the 65536 experiment control before host overhead.
Successful raw CellDb import is not account-capacity or consensus acceptance.

Each run writes a BoC, uses the production streaming CellDb actor to import it,
checks the returned root and lease, validates every page, adopts the root under
a synthetic block identity, releases the lease and checks registration. A new
actor/database instance reopens that database, validates all pages and probes
duplicate rejection and immutable fresh-key insertion. Expected page hashes
come from the source fixture. This is local root integrity, not authenticated
checkpoint acquisition. The probe's inserted keys are not committed.

The custom verifier is asserted to run three times in the import/adoption path,
then twice on reopen (including one append probe). Reopen validation therefore
includes two full scans. Root-store timing is adoption of an already imported
root, not incremental account writes or an atomic logical batch commit.

## Run

2026-09-06 12:57:32–12:58:14 UTC, serial on the 192-logical-CPU host, Release
Clang 21, 48 build jobs, two actor scheduler workers, CellDb v2, 64 MiB cache,
16 MiB streaming-parser resident budget. No affinity, cache eviction or workload
isolation. One-minute load was 3.03 to 2.69. Fresh temporary databases do not mean
cold physical storage. Source Cells, grouped keys and serialized input remain
resident, so RSS is process lifetime high water, not an importer-only bound.

For pages 1/16 and keys 1000/8000/32000/65536, run three separate processes:

```sh
env TOS_UNO_STORAGE_KEYS=32000 TOS_UNO_STORAGE_PAGES=16 \
  build/test-uno-storage-measurement --filter PartitionPersistenceStages
```

All 24 invocations exited 0, each with exactly one test and one data row. The
runner checks both instead of accepting a zero-match test command. Structural
fields and root hashes matched across all three repetitions of each pair.
All times were finite/nonnegative and RSS positive. Successful runs remove
their fresh database and input file; failures retain paths in the log.

Median times in milliseconds (three samples; not tail estimates):

| Accounts | Keys | Import request | First full lookup | Adopt root | Reopen root | Reopen validation/probe | Max HWM KiB |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1000 | 59.3127 | 8.3621 | 9.7888 | 17.4115 | 15.7819 | 27648 |
| 16 | 1000 | 37.6089 | 7.5677 | 6.0858 | 12.5937 | 13.6208 | 27648 |
| 1 | 8000 | 191.041 | 84.2426 | 9.7412 | 36.0378 | 123.298 | 38784 |
| 16 | 8000 | 203.757 | 70.5135 | 6.7906 | 39.3979 | 100.369 | 38400 |
| 1 | 32000 | 728.210 | 385.214 | 10.2056 | 101.759 | 507.512 | 88844 |
| 16 | 32000 | 603.980 | 308.245 | 8.8003 | 100.270 | 448.696 | 83872 |
| 1 | 65536 | 1315.990 | 753.870 | 8.1355 | 229.089 | 679.295 | 148892 |
| 16 | 65536 | 1262.700 | 712.785 | 9.1578 | 156.065 | 709.344 | 151144 |

At 65536 keys the single/16-account maxima are 131071/8383 data Cells; complete
snapshot Cells are 131077/131107 and BoC sizes 2794035/2795581 bytes. Dividing
data across accounts does not eliminate the full-state import/validation work.
These small, fixed-order samples cannot establish a causal performance gain.

CSV fields after `PARTITION_STORAGE_CSV`: keys, seed (91), accounts, maximum
data Cells, BoC Cells, BoC bytes, generation ms, serialization ms, import request
ms, first lookup ms, root adoption ms, reopened root ms, reopen validation/probe
ms, process HWM KiB, state hash. They do not measure incremental persistent bytes.

## Controls and scope

Removing the per-page expected hash comparison made the wrong-binding negative
control fail. Removing the actor's custom verification call made the callback
count assertion fail (0 instead of 3). Both experiments exited 1; exact patches
and diagnostics are archived. Restored smoke CTest passed, as did the original
single-account measurement and `V2ActorImportPublishesFreshReader` test.

An initial legacy regression filter incorrectly matched zero tests. Its log is
retained, not claimed as passing evidence; the corrected filter ran one test.
The new smoke CTest rejects `0 test(s) passed`: deliberately selecting a missing
test made CTest exit 8. The new test name also avoids matching the existing
`SnapshotStages` substring filter. The smoke target is in `all-tests`; resource
matrices remain manual. External milestone review is pending.

Evidence: `measurements/uno-partition-persistence-pilot.tar.gz`. This does not
close Y-1/D-3: coordinator/effects/candidate overhead, settlement reservations,
physical participant records, value conservation, incremental persistent writes,
atomic multi-account commit, authenticated network sync/GC/migration, and the
complete proof/execution/deadline envelope remain unimplemented or unmeasured.
