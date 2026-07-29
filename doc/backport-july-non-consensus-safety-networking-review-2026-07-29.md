# Code Review: `backport/july-non-consensus-safety-networking` (2026-07-29)

**Method:** Traced `git diff main...HEAD` (merge-base `b722ee3c3`, 40 files,
+1131/-268) by area, cross-referenced every claimed fix against the actual
upstream commit in `/home/tomi/ton-c`, built and ran the relevant test
binaries in an isolated build directory (`build-jemalloc`, not the live
`build/` used by the running node1-3 validator-engines), and confirmed the
running nodes were undisturbed throughout.

## Findings

No Critical, High, or Medium severity findings remain. The one pre-existing
Medium hardening gap and the two Low coverage gaps identified by the initial
review were fixed and verified in the same branch on 2026-07-29. Two
non-blocking Low observations remain.

*Correction (post-review verification, 2026-07-29): an earlier draft of this
report flagged `OverlayImpl::get_random_neighbour_peer` for dropping
upstream's linear-probe-with-wraparound loop. That loop was added by
`ton-c` `8bb4d7d3` and then deliberately **removed** by the very next
upstream commit touching this function, `02867cc5` ("Fix problem with
removal of selected random neighbour."), which reverted to a single random
index — confirmed via `git show 02867cc5 -- overlay/overlay-peers.cpp` and
matches current `ton-c` HEAD exactly. TOS's implementation matches
upstream's final design; there is no gap here, and restoring the loop would
undo upstream's own fix. This finding is retracted; see the comparison
matrix below.*

---

**RESOLVED MEDIUM — `crypto/smc-envelope/GenericAccount.cpp:51`,
`GenericAccount::get_init_state`.**
The raw `noexcept` API previously called throwing `CellBuilder::store_ref()`
for both code and data, so a single null ref could escape as
`CellCreateError` and terminate the process. It now delegates to
`get_init_state_checked()`, which uses `store_maybe_ref` and comprehensive
`TRY_VM` exception conversion; the raw API preserves its existing
`noexcept` signature and returns an empty cell only if checked construction
fails. Code-only and data-only `StateInit` values now work in both the raw
and checked APIs. `GenericAccountCheckedExternalMessage` directly verifies
both partial-init cases and their raw external messages, while
`GenericAccountCheckedExternalMessageCatchesCellBuilderFailure` verifies
that a maximum-depth CellBuilder failure returns an empty raw result instead
of aborting.

**LOW — `validator-engine/json-rpc-server-send.cpp:541-112` — duplicated
message-encoding logic.**
`build_external_message_cell` (via `GenericAccount::create_ext_message_checked`)
and `build_external_message_cell_by_ref` (a second, hand-rolled `CellBuilder`
implementation used only by `handle_sendQuery`) independently encode the
same `Message$_` TL-B layout. Both are currently correct and TRY_VM-safe,
but a future change to one (e.g. gas/size handling) could drift from the
other. Recommend consolidating onto one implementation.

**LOW — `toslib/test/offline.cpp:314` — cosmetic only.** Dropped `.ensure()`
before `.move_as_ok()`; `move_as_ok()` already `LOG_CHECK`s internally, so
behavior is identical.

**RESOLVED COVERAGE — DHT self-node error propagation and cache eviction.**
`test/test-dht.cpp` now creates a real ADNL/Keyring/DhtMember stack, removes
the DHT actor's registered ADNL ID, verifies that `get_self_node()` returns
an error without terminating, restores the same ID, and verifies that the
same DHT actor retries successfully. The success after failure proves that
the failed `self_node_future_` was evicted rather than permanently poisoning
the cache.

**RESOLVED COVERAGE — `OverlayImpl::del_peer()` to Plumtree cleanup.**
`Overlay.DelPeerCleansPlumtreeState` constructs an `OverlayImpl`, seeds a
deletable peer with real Plumtree state, calls the public `forget_peer()`
entry point, and verifies that both the overlay peer and its Plumtree state
are removed. This exercises the actual
`forget_peer()` → `del_peer()` → `BroadcastsPlumtree::remove_peer()` wiring,
not just the underlying Plumtree helper.

---

*Correction: an earlier draft also reported "empty-pagination loop
prevention" as not located. It is present. Upstream `9c07336d` adds, in
`TonlibClient.cpp`'s `RunEmulator` transaction-history walker: `if
(bTxes->incomplete_ && bTxes->ids_.empty()) { ...error... }`. TOS ports this
as `detail::validate_liteserver_transaction_page()`
(`toslib/toslib/ToslibClient.cpp:77-82`), called from
`RunEmulator::get_transactions()` (`ToslibClient.cpp:2236-2239`). Without
this check, a malicious or buggy LiteServer returning `incomplete_=true`
with an empty `ids_` page leaves `last_lt` at its initial value, and
`get_transactions()` recurses on `bTxes->incomplete_` (`ToslibClient.cpp:2264-2265`)
requesting the exact same page forever — an unbounded recursive pagination
loop. The check short-circuits this with a clean error before the
recursion. Confirmed as an exact functional port; see the comparison
matrix.*

## Upstream-to-TOS comparison matrix

| Item | Upstream commit | TOS files | Status | Notes |
|---|---|---|---|---|
| VM/SMC safety (`TRY_VM` for message builders) | No direct upstream analog — `json-rpc-server-send.cpp` is TOS-only | `GenericAccount.{cpp,h}`, `json-rpc-server-send.cpp` | **TOS-original, complete** | Verified: `TRY_VM`/`try_f` catches `VmError`, `VmVirtError`, `VmNoGas`, `CellCreateError`, `CellWriteError`, `std::exception`, and `catch(...)` — comprehensive. Both handlers now route through checked builders with correct `store_maybe_ref` partial-init encoding. |
| AES fix | `9c07336d` | `keys/keys.hpp` (`export_as_slice` 40→36 bytes) | **Complete, exact port** | Fixes a real bug: 4 bytes of uninitialized `SecureString` were exported, and the 40-byte export was actually un-importable (`PrivateKey::import` requires 32 bytes post-magic-strip). |
| Keyring fix | `9c07336d` | `keyring/keyring.cpp/.hpp` | **Complete, exact port** | `load_all_keys()` before `export_all_private_keys` — lazily-loaded keys no longer silently omitted. |
| validator-console fix | `9c07336d` | `validator-engine-console/validator-engine-console-query.cpp` | **Complete, exact port** | |
| Toslib LiteServer response validation | `9c07336d` + `4c92183c`-derived extensions (already on `main` pre-branch) | `ToslibClient.cpp/.h` | **Complete** | Block-id mismatch abort, 0-txn+`incomplete` rejection, `TRY_VM`-wrapped `create_ext_message_checked`, block-id validation in `blocks_getTransactions`. |
| Empty-pagination loop prevention | `9c07336d` (`RunEmulator`'s `incomplete_ && ids_.empty()` guard) | `ToslibClient.cpp:77-82` (`detail::validate_liteserver_transaction_page`), called from `RunEmulator::get_transactions` at `ToslibClient.cpp:2236` | **Complete, exact port** | Prevents an unbounded recursive pagination loop when a malicious/buggy LiteServer returns `incomplete_=true` with an empty page (see correction note above). |
| Key error propagation | `9c07336d` | `KeyStorage.cpp`, `keys/DecryptedKey.cpp/.h` | **Complete, exact port** | `encrypt()` now returns `td::Result` instead of blind `.move_as_ok()` crash on all 3 call sites. |
| External-message exception handling | No direct upstream analog | `GenericAccount.{cpp,h}`, `json-rpc-server-send.cpp`, `ToslibClient.cpp` (`deserialize_safe_boc_root`) | **TOS-original, complete** | Both JSON-RPC builders and Toslib use checked exception conversion. The raw `get_init_state()` API now delegates to the checked builder, supports partial init, and cannot terminate from a CellBuilder exception crossing `noexcept`. |
| Overlay peer removal cleanup for Plumtree state | matches upstream's existing `del_peer` wiring (present in ton-c, absent in TOS pre-branch) | `overlay/overlay-peers.cpp:47`, `test/test-overlay-peer-cleanup.cpp` | **Complete and end-to-end tested** | Confirmed via `git show main:overlay/overlay-peers.cpp`: TOS's `del_peer` never called `BroadcastsPlumtree::remove_peer` before this branch. `Overlay.DelPeerCleansPlumtreeState` now verifies the public deletion path and closes the previous coverage gap. |
| Dual-path random-node discovery | `8bb4d7d3` (superseded by `02867cc5`) | `overlay/overlay.cpp:460-481`, `overlay/overlay-peers.cpp:629-641` | **Complete, matches upstream's final design** | Dual query (neighbour + random peer) ported. `get_random_neighbour_peer` uses a single random index with no retry loop — this matches upstream's *current* code exactly; the loop `8bb4d7d3` introduced was deliberately reverted by upstream's own follow-up commit `02867cc5`, so there is nothing missing here. |
| DHT/Overlay self-node request coalescing | `9c07336d` (crash-prevention intent), but TOS's mechanism is original | `dht/dht.cpp`, `overlay/overlay.cpp`, `SharedFuture.h` (`await_shared_future`), `test/test-dht.cpp` | **Complete, justified divergence — exceeds upstream, regression tested** | Upstream's *own current* `get_self_node_coro` uses a bare `co_await future->get()`; per `coro_task.h`'s `TaskUnwrapAwaiter`, an error short-circuits the coroutine before the cache-eviction line runs — upstream permanently poisons its self-node cache on one transient failure, and 7 remaining `R.ensure()` call sites still `LOG(FATAL)`-crash on the very first such failure. TOS fixed both halves: all 7 `R.ensure()` sites now propagate errors, and the TOS-original `await_shared_future` helper evicts the cache on error before returning. The real DHT/ADNL retry test now verifies both behaviors. |
| SharedFuture failure-cache cleanup | `9d2cb8ff` (materially different design: `CoroMutex`+cancellation-propagation) | `tdactor/td/actor/SharedFuture.h` | **Complete via a different, TOS-original mechanism** | TOS kept the promise-vector design, fixed a reentrancy hazard in `get()` (swap-then-iterate), and added `await_shared_future`. Verified: 64-concurrent-waiter test confirms single underlying attempt, shared failure, eviction, and successful retry. TOS evicts on *any* error (upstream only evicts on staleness) — arguably stricter/better. Upstream's cancellation-propagation feature has no TOS equivalent, but nothing in TOS triggers it either (pre-existing, out of scope). |
| DNS length validation | `9c07336d` | `crypto/smc-envelope/ManualDns.cpp/.h` | **Complete, exact port** | `resolve_args_raw` 127/128-byte boundary. |
| Zero-length bitstrings | `9c07336d` | `crypto/common/bitstring.cpp` | **Complete, exact port** | Real UB fix: `bits_load_long` previously shifted a 64-bit value by 64 when `bits==0` (undefined behavior); `bits_load_ulong` already had the guard, `bits_load_long` didn't. |
| (Bonus, not in original scope list but ported) `PaymentChannel::SignedPromise::unpack` | `9c07336d` | `crypto/smc-envelope/PaymentChannel.cpp` | **Complete, exact port** | `prefetch_bytes`→`fetch_bytes`: previously the signature bytes were peeked, not consumed, so `cs.empty_ext()` always failed — valid signed promises could never unpack. |

Correctly treated as out-of-scope per the review instructions and not
flagged as missing: `317abd38` FullNode query redesign, FullNode LRU
256→10000, Plumtree stats file collection, CI/RocksDB test-dir changes,
consensus acceptance-rule changes.

## Test/build results

Ran in an isolated build directory (`/home/tomi/tos/build-jemalloc`) to
avoid touching the live `build/` → `build-remove-workchains-full` used by
the running node1-3 validator-engine and node0 dht-server processes:

```
cmake --build build-jemalloc --target test-smartcont test-test-scheduler test-overlay-peer-cleanup test-dht -j 32
./build-jemalloc/test-smartcont → 21/21 passed (including raw/checked partial-init and CellBuilder-failure coverage)
./build-jemalloc/test/tdactor/test-test-scheduler → 14/14 passed (incl. SharedFuture.FailedResultIsEvictedAndRetried, SharedFuture.ConcurrentWaitersShareFailureAndRetry)
./build-jemalloc/test-overlay-peer-cleanup → 2/2 passed (including Overlay.DelPeerCleansPlumtreeState)
./build-jemalloc/test-dht → passed, including missing-ADNL-ID error propagation followed by successful retry
git diff --check → clean (exit 0)
```

The final focused CTest run executed `test-smartcont`,
`test-test-scheduler`, `test-dht`, and `test-overlay-peer-cleanup` in
parallel and passed 4/4 in 12.07 seconds.

**Process note:** one sub-investigation (Toslib/Keyring/AES) built and ran
`test-cells`, `test-ed25519`, `test-toslib-offline` in the **live** `build/`
directory (`ninja -j 128`) rather than an isolated one, before the isolated
build was set up. All three validator-engine processes and the dht-server
were confirmed still running normally afterward with no crashes or notable
CPU/memory disruption (192 CPUs / 106 GB free made this low-risk in
practice), but this deviated from the "do not interfere with running local
nodes" instruction and is flagged here transparently. No files were edited,
committed, or the build dir otherwise left in a bad state; those test
binaries' pass results (11/11 `test-cells`, 5/5 `test-ed25519`, 18/18
`test-toslib-offline`) are consistent with independent re-verification of
the overlapping bitstring/AES/PaymentChannel fixes by reading the diffs
directly.

## Memory-growth assessment

No unbounded retention path was found to be **introduced** by this branch:
- `self_node_future_` (DHT and Overlay): a single `shared_ptr` slot per
  actor, replaced (not accumulated) on each new attempt, evicted on error —
  bounded. The DHT failure-then-success regression test now verifies the
  error eviction against a real ADNL actor.
- `SharedFuture::promises_`: temporary concurrent-waiter growth only;
  swapped-and-cleared every dispatch cycle (confirmed by the 64-waiter
  test).
- Plumtree per-peer state (`eager_peer_refcnt_`, `eager_peer_activity_`,
  per-slot `eager`/`pending_feedback`): this branch **closes** a pre-existing
  bounded-but-delayed leak (peer state previously survived `del_peer` until
  the next inactivity sweep) — a net improvement, not a new leak. The
  `OverlayImpl::del_peer()` wiring is now covered end-to-end.
- `ToslibClient` missing-library-fetch retries: bounded by pre-existing
  `max_smc_missing_library_fetches=8` (unrelated to this branch, still
  bounded).
- `KeyringImpl::map_`: one-time load bounded by files present on disk at
  startup.
- The `doc/*.md` changes in this diff are textual status updates to an
  **unrelated, already-resolved** investigation (workchain-0 standstill /
  `StateResolver` in-flight admission control, PRs #15/#16, `1c137fa44` — a
  different subsystem, `validator/consensus/simplex/state-resolver.cpp`, not
  touched by this branch). They don't bear on this branch's correctness.

## Final verdict

**Safe to merge.** No Critical, High, or Medium defects remain. The
pre-existing raw `GenericAccount::get_init_state` `noexcept` hazard is fixed
at the root, and the DHT self-node and Overlay peer-cleanup production paths
now have regression coverage. No unbounded-growth path was introduced, and
the two upstream-comparison concerns raised in an earlier draft of this
report (the neighbour-selection "regression" and the "missing"
empty-pagination guard) were both verified to be non-issues on closer
inspection against upstream's actual final state.

Recommended, non-blocking follow-ups:
- Consolidating the two external-message-builder implementations in
  `json-rpc-server-send.cpp` can be done later; it is not a merge blocker.
