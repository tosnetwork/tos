# Archive pruning validation

Scheduler shutdown can cancel a delayed index-deletion retry. The former
`ArchiveManager::delete_package` completion called `R.ensure()` on the resulting
`Lost promise` error and aborted the process. The fix returns that error before
acknowledging physical deletion. It preserves pending deletion while a real
reader or filesystem error prevents removal.

The alleged permanent production owner was not reproduced. Ordinary TTL pruning
on the unmodified baseline removes the package and index in-process. Both
original checkpoint retention scenarios also remove their indexes and destroy
the scheduler normally when their test waits for index removal instead of
exiting early. Temporary handle copies survive pruning and are not a valid
physical-deletion oracle.

Production baseline: `994ac69cfb854fbb9d43535f81498c28993eae9c`.
Native regression source: `d1001bc7a4efc78d6fff9f012bc1197e14c4af0f`.
The C++ blobs are unchanged from the first verified fix at `c70b9ffd7`.

The test calls the production archive manager, slice, RocksDB and TD scheduler.
It covers regular/key/temp packages, open/closed slices, synchronous/asynchronous
TTL pruning, preservation of the newest package, temporary handle survival,
clean scheduler destruction and reopening in the same process. A snapshot from
the actual slice blocks index deletion, remains readable, and allows deletion
after release. A separate retained-reader shutdown case verifies cancellation
without acknowledging a successful deletion.

On a configured Linux Release build:

```sh
cmake --build build --parallel 4 --target test-archive-prune test-validator-cleanup test-validator-cleanup-worker test-validator-cleanup-statedb
ctest --test-dir build --output-on-failure --repeat until-fail:3 -R '^archive-prune'
ctest --test-dir build --output-on-failure -R '^test-validator-cleanup(-worker|-statedb)?$'
```

The exact configure flags and the mutation runner are in
`.github/workflows/archive-prune.yml`. The workflow restores the fatal assertion,
rebuilds, requires exit 134 with the retained-reader barrier and `Lost promise`,
then restores the fix, rebuilds and reruns both tests. A timeout, compile failure
or unrelated abort does not satisfy this control.

Linux x86-64 / Clang 21.1.8 results:

- Both archive CTest entries passed three times each, then both passed after
  restoring the cancellation guard.
- All three related cleanup test programs passed.
- The cancellation mutation compiled and exited 134 at the intended assertion.

Bounded failure receipt, with temporary roots and timestamps omitted:

```text
failed to destroy index ...archive.00000.index:
  IO error: lock hold by current process ...archive.00000.index/LOCK: No locks available
BARRIER: actual slice owner released; external reader held=1
Unexpected Status [Error : 0 : Lost promise] ...archive-manager.cpp at line 700
cancellation mutation exit=134
```

[Native job and logs](https://github.com/tosnetwork/tos/actions/runs/38554703325/job/115821354408).
The workflow artifact retains raw logs for 14 days. After expiry, rerun the
workflow; the committed test and mutation are the durable reproduction.

| Artifact entry | Bytes | SHA-256 |
| --- | ---: | --- |
| `archive-prune-green.log` | 859 | `47c42028cc6707bbf1e1a4b2941517b7d4371d853691c7bc75c21dafa0040a24` |
| `archive-prune-red.log` | 1420 | `ed2420a84e8c3a3ebfafc70aa791a62f8fd50316821da3fc7ad275a120465229` |
| `archive-prune-related.log` | 514 | `44d07c5e70a60217ca82bb5e314ff46510d3c8669707935ab6072cc41ddb8b30` |
| `archive-prune-restored.log` | 401 | `cedb3e46a9fa112d1b9b9a539295119196c650580c6302b3e39ff9a87eb38718` |

The original fixture was built at
`d04491e24f81ab7898c1e0abd6a8f40e6b9044eb`, without changing production code.
`test/diagnostics/stage-original-archive-prune.py` instruments its test lifecycle:
a stack scheduler, a wait for every pruned index, a normal return, and a status
printed after scheduler destruction. Production libraries use Release flags;
the large test translation unit uses `-O0 -g0`.

Both original modes passed:

```text
retention:          PACKAGES_CREATED=1 PRUNED=1 R1=0 R2=1 R3=1 LOADED=1
retention-violated: PACKAGES_CREATED=1 PRUNED=1 R1=0 R2=0 R3=0 LOADED=1
both: ORIGINAL_RETENTION_INDEXES_REMOVED=1
both: retention child after scheduler destructor: OK
```

[Original fixture run](https://github.com/tosnetwork/tos/actions/runs/38554873145).
Its existing manager probe retains its startup/alarm substitutions. The primary
TTL suite above uses the unmodified archive manager and its alarm.

To repeat, create an isolated checkout of the original commit, run the staging
script from this branch with that checkout as the current directory, configure
and build `test-consensus-cleanup-checkpoint-db`, then invoke:

```sh
build/test-consensus-cleanup-checkpoint-db --child retention test/pq-native/data/c04-pq-genesis.boc "$(mktemp -d)"
build/test-consensus-cleanup-checkpoint-db --child retention-violated test/pq-native/data/c04-pq-genesis.boc "$(mktemp -d)"
```

The mode name is inherited: each invocation prunes and destroys its scheduler
in the same process, without an `_Exit` shortcut. The formatted staging script
produces the same test source bytes as the exercised version (SHA-256
`5cbf47f7c64c2b6eef4c4a8f37ede025a95b34fb60c54c90f37a3ac622c2c996`).

Original fixture artifact entries, retained for 14 days:

| Artifact entry | Bytes | SHA-256 |
| --- | ---: | --- |
| `original-retention.log` | 18697 | `287eb2185e34bf20e89016f26a5fdbf96f57e36862cef008a77ac2ce74ad0516` |
| `original-retention-violated.log` | 18937 | `8512a05f23c6c3b29d062938df42198ef394b1a848d28c94a092a2e3c05a6dae` |

A supplementary macOS arm64 check recompiled the test and changed manager
translation unit against an existing native dependency build at
`d41eae93dbbcb2af730b4ff5015458794ef04cb1`. Its archive slice, RocksDB wrapper
and scheduler match the baseline. With the original manager object, ordinary
pruning passed and retained-reader shutdown raised SIGABRT with `Lost promise`.
Relinking the changed manager object made both return 0. This was a targeted
native relink, not a clean macOS build; Linux builds the regression target and
its production dependencies natively.

Retries remain pending while an external owner or filesystem error prevents
removal. This change does not forcibly invalidate readers, add a retry deadline,
or add durable orphan recovery. The original permanent-production-owner claim
remains unverified; this change fixes the reproduced cancellation abort.

Strict differential C++ analysis passed with CodeChecker 6.29.1 / LLVM 21.1.8
and rule-set fingerprint `73600cde7a576a01`. Both checkouts used the same Debug
configuration. Dependency preflight covered 990 HEAD and 989 BASE compilations;
the gate then analysed the affected 13 HEAD and 12 BASE compilations against the
clean merge base `994ac69cfb854fbb9d43535f81498c28993eae9c`. All 10 marked positive
controls reported. Result: **0 new blocking and 0 new advisory findings**, exit 0.

[Static analysis job](https://github.com/tosnetwork/tos/actions/runs/38554703325/job/115821354662).
Its 14-day artifact entry `archive-prune-analysis.log` is 724 bytes,
SHA-256 `29b13c21539125dd8686ed5f8e7377ad76d070fbc7a6bfed51a348ef5f9d1e3b`.

The evidence follow-up changes only workflow timing/cache/log flushing and adds
this record and the reproduction helper. Archive C++ sources, headers, the
native test and its CMake registration are byte-identical to the verified source.
