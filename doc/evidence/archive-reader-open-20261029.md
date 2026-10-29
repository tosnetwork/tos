# Archive reader open-failure verification

## Source and environment

Verified on 2026-10-29 with the native Linux CMake/Ninja build, Clang 21,
`Release`, and `TOS_ARCH=x86-64-v2`.

- Base: `245ac393a9b13400929857bb21faa61cfc2b4998`.
- Locally tested source: `a435797f5fbf99772f34854e928f0afd38a94d38`.
- Reachable equivalent: [`b0e2274213dbadc21e56a97ebdcd857af2c4e733`](https://github.com/tosnetwork/tos/commit/b0e2274213dbadc21e56a97ebdcd857af2c4e733).
- Both source commits have tree `b24a1577d1e79e52d053be936989d1f7758ea507`.

The verification checkout was switched to this source before rebuilding its
dependencies. Objects compiled against a different validator-options interface
were not used as final evidence. This note and its accompanying operator-wording
clarification change no production, test, or build sources.

## Native results

After configuring the native build:

```sh
cmake --build build --parallel 6 --target test-archive-prune
ctest --test-dir build -j 1 --output-on-failure -R '^(archive-prune|archive-prune-held-reader-shutdown|archive-reader-no-package-sync|archive-reader-no-package-repair|archive-reader-no-node-writes|archive-reader-open-failures)$'
```

All six CTests passed before sensitivity controls and again after restoring and
rebuilding the tested source. The final restored run took 3.62 seconds. The
existing primary deletion, held-reader shutdown, package-sync, package-repair,
and source-write guards remain green.

`archive-reader-open-failures` runs 19 deterministic scenarios:

| Scenarios | Coverage |
| --- | --- |
| 6 | Secondary/read-only readers discover normal/key/temp packages; the primary completes real pruning before the first lazy open. Repeated failures leave the slice closed, return `notready`, and do not recreate the source index. |
| 2 | The second package is absent after a successful index open; partial layout handles are released, then the same reader reads restored bytes. |
| 8 | Missing or invalid-`CURRENT` slice/global indexes fail their DB open, then recover on the same actor after the source is restored. |
| 2 | A valid empty global index returns `notready` for min/max queries; secondary catch-up also reports the absent package list safely. |
| 1 | An already-open secondary encounters a missing `CURRENT` during query-triggered and explicit catch-up, then resumes using its existing index after restoration. |

Ordering uses actor replies and filesystem operations. The catch-up scenario
expires the throttle through an actor-serialized test accessor; no sleep is
needed to create its failure window. Successful database-open counters, empty
partial state, returned bytes, and deleted-package actor retirement are checked.
The new CTest is included in `scripts/strict-build-targeted-tests.txt`.

## Failure sensitivity

The first native run at local commit
`8cb7a0bbc8c8b37a2598834ff0c90338fd29e786` passed five existing CTests but failed
the new test with `a reader never recreates a removed index`. The read-only
RocksDB default file logger had recreated the removed source directory even
though opening the DB failed. Supplying a no-op logger and disabling
`create_if_missing` fixed that failure. Restoring
`tddb/td/db/RocksDbReadOnly.cpp` from the base commit reproduces this control
against the new test.

Seven further mutations were compiled and run separately against the same native
target. Every mutation failed at the intended operation; no timeout was counted
as a passing control.

| Removed protection | Observed failure | Completed scenarios before failure |
| --- | --- | ---: |
| Secondary slice open: call `result.ensure()` before handling its error | `SIGABRT`, `Unexpected Status` at the first pruned lazy open | 0 |
| Read-only slice open: the same fatal call | `SIGABRT`, after the secondary matrix | 9 |
| Secondary global-index open: the same fatal call | `SIGABRT`, at missing-global-index startup | 6 |
| Read-only global-index open: the same fatal call | `SIGABRT`, at missing-global-index startup | 15 |
| Omit `do_close()` after the initial partial layout load fails | `SIGABRT`, explicit closed-state assertion | 3 |
| Remove the empty-manager max-seqno descriptor guard | `SIGSEGV`, at the empty global index | 4 |
| Restore fatal catch-up handling in `ArchiveSlice::before_query()` | `SIGABRT`, `archive slice index catch-up is not ready` | 18 |

Each control used its own temporary directory and disabled core dumps. Its
source mutation was restored before the next control, and its owned fixture
directory was removed. The final tracked-source diff was empty before rebuilding
and rerunning all six green CTests. No running source-node directory was changed.

## Resource and compatibility review

- New retained scalar state is one warning timestamp per slice and one per
  manager. New failure warnings are limited to one per minute for each owner.
- A read-only database holds one fixed no-op logger object instead of the default
  disk logger. Failed opens and database closure release it; retries retain no
  logger or source-file state.
- A secondary DB is owned before its fallible initial catch-up, so that failure
  releases the DB. Partial slice layouts release already-open packages and the
  index before another query retries.
- No retry actor, background retry timer, stored promise list, or retry queue was
  added. Retries occur on incoming requests. Existing archive/cache limits are
  unchanged; this change does not claim a new hard process-memory or FD ceiling.
- Primary index-open and package-open failures remain fatal. Primary writes,
  pruning, and read-only write refusals retain their existing behavior.

The upstream TON archive slice/manager at
`857b8a57a178e6ae0fe7fa86e7d81c5233de8560` were checked: they have primary-only
index opens, without these local reader branches to port a fix from.

This verification covers archive index-open errors, missing package files,
catch-up errors, and recovery without restarting the archive actor. It does not
claim repair of malformed records inside an already-open index, or change
unrelated `StateDb`/`CellDb` startup error handling. It is local native evidence;
supported-platform CI and the repository's required external review remain
separate merge gates.
