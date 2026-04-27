# TOS Security: Threat Model and Defense Layers

## Overview

This document is the top-level security reference for the TOS codebase.
It enumerates the attack surfaces a TOS full node exposes to remote
peers, RPC clients, and operators, and maps each surface to the
defenses currently implemented in the source tree. Citations point to
exact `file:line` locations in the working tree (branch `main`) so a
maintainer or external reviewer can audit each defense without
spelunking the commit history. The document is structured to evolve as
new defenses land — sections should be extended in place rather than
rewritten.

Audience: TOS maintainers, security reviewers performing a fresh audit
or comparing against the cumulative `tos11`-`tos15` audit series, and
operators deploying validator / follower / admin nodes against a
public network.

Cumulative audit reference series (private notes, not checked into the
tree):
- `tos11` regression audit (2026-04-26) — first persistent-MPT-witness
  hot-path scan.
- `tos12` regression audit (2026-04-27) — strict witness validation,
  state-download budget RAII.
- `tos13` regression audit (2026-04-27) — `eth_getProof` no-cache safe
  helper, heavy read-only RPC limiter, `stateOverrides` strict parse.
- `tos14` regression audit (2026-04-27) — H-01 dynamic flat/MPT
  verifier, H-02 EIP-4788/EIP-2935 witness coverage, H-03 streaming
  persistent-state download.
- `tos15` regression audit (2026-04-27) — code-root keccak verification,
  AdminLocal listener fail-closed, strict call-object parser, unsafe
  API gating, libFuzzer harness gating, K-02 RPC code-root mismatch
  surfacing.

Architectural background: see
[`docs/adr/0001-streaming-cell-import-and-residency.md`](docs/adr/0001-streaming-cell-import-and-residency.md)
for the persistent-state download and DAG residency analysis that
underpins the P2P state sync defenses below.

---

## Attack Surfaces

### 1. Public JSON-RPC (read-only and admin)

**Surface.** The validator-engine exposes a JSON-RPC endpoint
(`validator-engine/json-rpc-server.cpp`). When an operator binds it to
a public interface, every method in `evm/rpc/handlers.cpp` becomes
remotely reachable. The heavy methods (`eth_call`, `eth_estimateGas`,
`eth_createAccessList`, `eth_simulateV1`, `eth_getProof`,
`debug_*`) drive silkworm or the persistent MPT witness against the
live state under the global EVM state mutex.

**Audit findings addressed.**
- `tos11` Persistent state downloader budget release.
- `tos12` `stateOverrides` strict parse, debug invariant gating.
- `tos13` H-01 `eth_getProof storageHash` no-cache safe helper, H-02
  heavy read-only RPC limiter / inflight gate, M-01 download budget
  RAII placement.
- `tos14` M-02 `AdminLocal` profile remote misconfiguration, M-03 lax
  `parse_call_object`, L-01 unsafe API leakage.
- `tos15` H-01 lazy bytecode keccak verification (RPC side), M-02
  AdminLocal listener fail-closed, M-03 strict call-object parser,
  L-01 unsafe API gating.

**Defenses.**

1. **3-state RPC profile.** The default
   `EvmRpcProfile::ValidatorMinimal` disables every heavy read-only
   RPC, `eth_getProof`, and the debug allowlist. Operators must opt in
   to `FollowerPublic` (heavy read-only at the 10M public gas cap) or
   `AdminLocal` (full caps, debug exposed if the build flag is on).
   - `evm/rpc/handlers.h:84-88` — enum definition.
   - `evm/rpc/handlers.h:94` — `set_evm_rpc_profile()` declaration.
   - `evm/rpc/handlers.cpp:228` — default `g_evm_rpc_profile`
     initialised to `ValidatorMinimal`.
   - `evm/rpc/handlers.cpp:258-302` — `apply_profile()` updates every
     profile-dependent toggle (heavy-readonly enable, getProof enable,
     debug allowlist) and resets rate buckets atomically.
   - `validator-engine/validator-engine.cpp:6001-6014` — CLI flag
     `--evm-rpc-profile=validator|follower|admin`.

2. **Per-method TokenBucket rate limiters.** Independent buckets cap
   heavy methods so a swarm cannot starve cheap reads.
   - `evm/rpc/handlers.cpp:79-94` — burst / RPS constants
     (`kCallBurst=10/5 RPS`, `kEstimateGasBurst=4/2 RPS`,
     `kMaxGetProofBurst=4`, `kMaxSimulateBurst`, …).
   - `evm/rpc/handlers.cpp:110-156` — `RateLimiter` token-bucket
     implementation.
   - `evm/rpc/handlers.cpp:157-162` — concrete buckets: `g_rpc_limiter`,
     `g_getlogs_limiter`, `g_getproof_limiter`, `g_simulate_limiter`,
     `g_call_limiter`, `g_estimate_gas_limiter`,
     `g_access_list_limiter`.

3. **AtomicConcurrencyPermit single-inflight gates.** Each heavy method
   binds a permit on entry; over-limit requests fail fast without
   pressuring the global EVM mutex.
   - `evm/rpc/handlers.cpp:172-195` — RAII permit type.
   - `evm/rpc/handlers.cpp:164-170` — counters (`g_getproof_inflight`,
     `g_simulate_inflight`, `g_readonly_evm_inflight`,
     `g_estimate_gas_inflight`, `g_access_list_inflight`,
     `g_debug_trace_inflight`).
   - `evm/rpc/handlers.cpp:1401, 1468, 1474, 1833, 3094, 4447, 5002,
     5008` — call sites.

4. **AdminLocal listener fail-closed.** The listener computes
   `is_loopback` BEFORE applying the profile, then runs a pure
   admission helper. `AdminLocal` on a non-loopback address is refused
   unless the operator passes `--allow-remote-admin-rpc` AND configures
   an API key.
   - `validator-engine/json-rpc-server.cpp:255-282` —
     `decide_listen_admission()` pure helper.
   - `validator-engine/json-rpc-server.cpp:284-369` — `listen()` order
     (loopback classification → admission → profile apply).
   - `validator-engine/json-rpc-server.h:169` — `allow_remote_admin_rpc`
     option flag.
   - `validator-engine/validator-engine.cpp:6028` —
     `--allow-remote-admin-rpc` CLI flag (no value, opt-in only).
   - `validator-engine/test-json-rpc-cache.cpp:27-185` — M-02 listener
     admission matrix.

5. **Strict call-object parser.** `eth_call`, `eth_estimateGas`,
   `eth_createAccessList`, and the per-call object inside
   `eth_simulateV1` all use the strict variant. Invalid `from` / `to` /
   hex `data` / hex gas / hex nonce surface as JSON-RPC `-32602` BEFORE
   the global EVM mutex is taken.
   - `evm/rpc/handlers.cpp:1268-` — `parse_call_object_strict()`.
   - `evm/rpc/handlers.cpp:1393, 1459, 4485, 4992` — call sites.
   - `evm/rpc/handlers.cpp:1078-` — `parse_access_list_strict()`.

6. **Strict `eth_getProof` storage-key validation.** Invalid hex storage
   keys return `-32602 invalid storage key hex` instead of being
   silently skipped.
   - `evm/rpc/handlers.cpp:3237` — `eth_getProof: invalid storage key
     length`.
   - `evm/rpc/handlers.cpp:3250` — `eth_getProof: invalid storage key
     hex`.

7. **Strict `stateOverrides` parser.** `eth_simulateV1` rejects invalid
   hex in storage slots / values / code / addresses BEFORE the EVM
   mutex.
   - `evm/rpc/handlers.cpp:3656-3759` — `invalid stateOverrides storage
     slot|value|code|account address`.

8. **K-02 code-root mismatch surfacing.** Heavy read-only RPC handlers
   that drive silkworm without binding a `WitnessFlatConsistencyContext`
   snapshot the global mismatch counter before execution and map any
   delta to `-32000 corrupt EVM code root`.
   - `evm/core/cell-state.cpp:37` — `g_code_root_hash_mismatch_count`.
   - `evm/core/cell-state.cpp:66-76` — counter accessors and reset.
   - `evm/core/state.cpp:437-448` — `EvmState::code_root_hash_mismatch_count()`.
   - Hardening grep at
     `scripts/check-evm-production-hardening.sh:337-364` enforces this
     pattern across `handle_call`, `handle_estimate_gas`,
     `handle_create_access_list`, `handle_simulate_v1`, and the
     admin-gated `handle_debug_trace_transaction`.

9. **Future per-IP rate limiter (N1).** A per-IP TokenBucket layer is
   planned in front of the per-method buckets for follower deployments.
   When that lands, follower flag guidance below should add
   `--evm-rpc-per-ip-enabled`.

### 2. P2P persistent-state download

**Surface.** A peer joins a chain by downloading a serialized
ShardState as a single Bag-of-Cells (BoC) blob from another node and
deserializing it into the local cell-DB. At production scale the BoC
is multi-GiB; a malicious peer can advertise an oversized total, drip
slow chunks, or feed corrupt data.

**Audit findings addressed.**
- `tos11` P4 — downloader memory budget released too early.
- `tos12` Medium — RAII unbroken through manager / downstream chain.
- `tos13` H-02 — heap-only 256 MiB ceiling as catch-up liveness ceiling;
  M-01 — module-boundary risk for budget API.
- `tos14` H-03 — 512 MiB processing ceiling; full BoC materialization;
  split-state OnDisk paths skipping reservation. M-01 — processing
  reservation released before resident cell tree life ends.

**Defenses.**

1. **Streaming tempfile downloader.** Persistent-state bytes land in a
   tempfile, not heap; only the in-memory branch (small states) holds
   `BudgetedBufferSlice`.
   - `validator/state-download-buffer.h:71-200` — `BudgetedBufferSlice`,
     `DownloadedPersistentState` (memory vs file variants).
   - `validator/state-download-buffer.cpp:80-95` —
     `g_persistent_state_download_bytes` accounting.

2. **`PersistentStateBudgetConfig` (post-K1, post-J2).** Single owner of
   download cap, processing cap, single-file cap, and resident cap.
   Default download cap raised to 16 GiB; processing cap raised to
   16 GiB once the streaming importer landed.
   - `validator/state-download-buffer.h:230-248` — config struct,
     `configure_persistent_state_budgets()` setter.
   - `validator/state-download-buffer.cpp:58` — `kHeapThreshold = 64
     MiB` boundary between heap and tempfile branches.
   - `validator/state-download-buffer.cpp:111-134` —
     `validate_budget_config()` rejects nonsensical caps.
   - `validator-engine/validator-engine.cpp:6052-6119` — CLI flags
     `--persistent-state-download-cap`, `--persistent-state-processing-cap`,
     `--persistent-state-single-file-cap`,
     `--persistent-state-resident-cap`.

3. **Streaming BoC importer.** OnDisk parse no longer materialises the
   full BoC into RAM. The bounded-resident streaming importer reads in
   4 MiB chunks and hands cells to the sink in topological order.
   - `crypto/vm/boc.{h,cpp}` (touched by ADR-0001) —
     `vm::std_boc_deserialize_from_file_bounded()`.
   - `validator/downloaders/download-state.cpp:122, 147, 974, 1154` —
     all OnDisk parse call sites including split-state header / part.
   - `validator/downloaders/wait-block-state.cpp:495` — zero-state
     OnDisk path drives the same importer.
   - `validator/state-download-buffer.h:319-400` — sink integration.

4. **`CellDbStreamingSink` / `StreamingCellSink` state machine.** The
   sink begin/persist/finish/abort lifecycle commits cells directly to
   the cell-DB, never holding the full DAG resident.
   - `validator/state-download-buffer.h:354-` — `CellDbStreamingSink`
     final class.
   - `validator/state-download-buffer.cpp:746-` — sink wiring contract.

5. **Processing reservation lifetime through handoff.** Reservations
   are RAII through the manager / archive-store chain so memory is
   released only after the resident cell tree is no longer needed.
   - `validator/state-download-buffer.h:212-222` —
     `PersistentStateProcessingReservation` non-copyable / non-movable
     RAII type.
   - `validator/state-download-buffer.h:257` —
     `try_reserve_persistent_state_processing_memory()`.
   - `validator/state-download-buffer.cpp:139-` — reservation release
     accounting against `g_persistent_state_processing_bytes`.
   - `validator/full-node.cpp:716` — manager-side handoff comment
     references the in-memory vs on-disk branch.

6. **mmap-backed OnDisk parse.** When the file path is taken, the
   downloader mmaps for the SHA256 hash gate (`file_hash` check), then
   the bounded importer parses the BoC. A regression that re-introduces
   `vm::std_boc_deserialize(mapped)` is caught by the hardening grep at
   `scripts/check-evm-production-hardening.sh:524-538`.

### 3. EVM consensus hot path

**Surface.** Every block carries a persistent-MPT witness. Each EVM
transaction inside the block reads the live flat-state account map and
writes back through the witness. A flat/MPT drift, a corrupt witness
node, or a bytecode mismatch at the witness leaf must fail-closed
during consensus, not produce a divergent stateRoot.

**Audit findings addressed.**
- `tos11` High — full-state scan in compute hot path; storage index
  eager materialization.
- `tos12` High/High — StrictRecursive on every account/storage witness;
  Medium — MPT mutation `CHECK` aborts.
- `tos13` H-01/H-02 — `eth_getProof storageHash` mutating helper; heavy
  read-only RPC under shared lock. M-02 — `TrustedShallow` cross-check
  not covering touched values; M-03 — unsafe API misuse.
- `tos14` H-01 — flat/MPT verifier missed dynamic touches.
- `tos15` H-01 — lazy bytecode `code_hash` not verified vs decoded
  bytecode; H-02 — EIP-4788 / EIP-2935 system calls bypassed verifier.

**Defenses.**

1. **`TrustedLazy` state load + `TrustedShallow` witness load.** The
   compute path no longer eagerly walks the full witness; the root cell
   is bound shallowly and decoding happens path-bounded on first
   touch.
   - `evm/core/cell-state.h:168-194` — `CellStateLoadMode::TrustedLazy`,
     `TrieWitnessLoadMode::TrustedShallow` enum doc-comments.
   - `evm/core/compute-phase.cpp:78-88, 209-223` — block-execution
     re-binding via `TrustedLazy + TrustedShallow`.
   - `evm/core/cell-state.cpp:1758` — lazy decode dispatch.

2. **`MptOrigin` provenance pin.** Every `MptTrie` carries an origin
   that says whether it was built in-process (full RLP cache trusted)
   or hydrated from a cell (cached RLP must be checked path-locally).
   - `evm/core/mpt-trie.h:110-165` — `MptOrigin` enum + `origin()`
     accessor.
   - `evm/core/mpt-trie.h:283-297` — `LoadedFromCell` pin contract.

3. **MPT path-local cached-RLP check.** On `LoadedFromCell` tries, the
   safe API recomputes RLP for each visited node along the access path
   instead of trusting `rlp_cache`.
   - `evm/core/mpt-trie.cpp:311-411` — `child_ref_local()` cached-RLP
     verification.
   - `evm/core/mpt-trie.cpp:463-498` — `rlp_checked_local()`
     budgeted version with `MptPathBudget::kMaxPathRlpBytes`
     ceiling.

4. **Dynamic flat ↔ MPT verifier.** Inside a transaction, every
   first-touch account / storage / code read flows through a fail-closed
   consistency hook gated by the per-tx
   `WitnessFlatConsistencyContext`.
   - `evm/core/state.h:36, 411` — context type.
   - `evm/core/cell-state.cpp:1158-1185` — context setters
     (`begin_witness_consistency_check`, `end_witness_consistency_check`,
     `consume_witness_consistency_error`).
   - `evm/core/cell-state.cpp:1131-1156` —
     `record_witness_error_if_active()` records the first divergence
     under a `noexcept` boundary.
   - `evm/core/cell-state.cpp:1259-1372` —
     `verify_account_witness_matches_flat_state()`.
   - `evm/core/cell-state.cpp:1422-` —
     `verify_storage_witness_matches_flat_state()`.
   - `evm/core/executor.cpp:522-558` — user-tx scope (begin … run …
     consume … end).

5. **`code_root` keccak verification.** When `read_code` lazily decodes
   bytecode from the witness, it computes `keccak256(decoded)` and
   compares against the requested `code_hash`. Mismatches record a
   witness error; non-empty `code_hash` decoding to empty is also
   treated as corruption.
   - `evm/core/cell-state.cpp:247-285` — lazy decode + keccak compare in
     `CellEvmState::read_code()`.
   - `evm/core/cell-state.cpp:1116-` — `keccak_code_hash()` helper.
   - `evm/core/cell-state.cpp:489-491` — `update_account_code()`
     defensive symmetric check.
   - Hardening grep enforces presence at
     `scripts/check-evm-production-hardening.sh:376-385`.

6. **EIP-4788 / EIP-2935 system calls under verifier.** Pre-tx system
   calls (Cancun beacon-roots, Pectra history-storage) execute through
   the same `WitnessFlatConsistencyContext` scope and reject the compute
   phase on mismatch instead of "continuing".
   - `evm/core/compute-phase.cpp:130-167` —
     `execute_system_transaction_with_witness()`.
   - `evm/core/compute-phase.cpp:360-410` — EIP-4788 / EIP-2935 dispatch.

7. **`MptTrie::*_safe` API.** Production callers (compute hot path,
   RPC, post-accept) use `proof_safe`, `value_at_hashed_safe`,
   `root_hash_safe`, `upsert_hashed_safe`, `erase_hashed_safe`. These
   return `td::Result` / `td::Status` instead of `CHECK`-aborting on
   corrupt witness.
   - `evm/core/mpt-trie.h:250-274` — safe API surface.
   - `evm/core/mpt-trie.cpp:1338-1349` —
     `MptTrie::value_at_hashed_safe()` with `MptPathBudget` recursion +
     RLP-byte ceiling.

8. **`MptPathBudget` recursion-depth + byte ceiling.** Every safe API
   walks under a budget that bounds nodes visited and total RLP bytes
   spent on path-local checks, preventing pathological witnesses from
   causing stack overflow or quadratic recompute.
   - `evm/core/mpt-trie.h:57-` — `MptPathBudget::kMaxPathNodes`,
     `kMaxPathRlpBytes`.
   - `evm/core/mpt-trie.cpp:756, 870, 980, 1040` — budget-checked
     descents.

### 4. Storage corruption / state-import attack surface

**Surface.** Imported state (snapshot, state-sync, archive replay) may
have arbitrary invariants violated. A bug in the consensus path, a
disk corruption event, or a malicious archive must not silently
execute on the cluster.

**Audit findings addressed.**
- `tos11` Persistent state downloader downstream lifetime.
- `tos12` Low — `TOS_EVM_TEST_INSTRUMENTATION` leakage into
  production library.
- `tos13` M-02 — `TrustedShallow` cross-check, M-03 — unsafe API
  ergonomics.
- `tos14` L-01 — unsafe API still in production namespace.
- `tos15` L-01 — `_unsafe_for_tests_only` not yet `#ifdef`-gated; K1 —
  streaming sink lifecycle.

**Defenses.**

1. **`code_root_hash_mismatch_count` metric.** A monotonic global
   counter is bumped on every code-root mismatch detected by
   `read_code` / `update_account_code`. Heavy read-only RPC handlers
   snapshot the counter before silkworm execution and surface a
   `-32000 corrupt EVM code root` error on a non-zero delta.
   - `evm/core/cell-state.cpp:37` — `g_code_root_hash_mismatch_count`
     atomic.
   - `evm/core/cell-state.cpp:63-76` — internal mirror counter and
     `reset_code_root_hash_mismatch_count_for_test()`.
   - `evm/core/state.h:239` —
     `EvmState::code_root_hash_mismatch_count()` accessor.

2. **`_unsafe_for_tests_only` APIs gated by
   `TOS_EVM_TEST_INSTRUMENTATION`.** Production builds do not define
   the macro and physically do not export the unsafe symbols.
   - `evm/CMakeLists.txt:56-59` — option default OFF.
   - `evm/CMakeLists.txt:103, 139` — test libraries opt in.
   - `evm/core/mpt-trie.h:190-231` — declarations gated.
   - `evm/core/mpt-trie.cpp:1293-1317` — definitions gated.
   - `evm/core/cell-state.cpp:26-296, 762-795` — same gating in
     `CellEvmState`.
   - Hardening grep: `scripts/check-evm-production-hardening.sh:289-326`
     uses an `awk`-based `#ifdef` tracker to flag any
     `*_unsafe_for_tests_only(` reference outside a
     `TOS_EVM_TEST_INSTRUMENTATION` block.

3. **`StreamingCellSink` begin/persist/finish/abort state machine.**
   Imported cells flow through the sink in topological order; aborting
   the sink reverses every persisted cell.
   - `validator/state-download-buffer.h:319-400`.
   - `validator/state-download-buffer.cpp:746-` — sink wiring contract.
   - Hardening grep at
     `scripts/check-evm-production-hardening.sh:524-553` requires the
     streaming importer drivers and the BoC fuzz drivers
     (`fuzz_boc_streaming_importer_round_trip`,
     `fuzz_boc_streaming_truncated_input`) to remain present.

4. **`mmap` SHA256 gate before parse.** Before the streaming importer
   touches the file, the SHA256 file-hash check rejects any
   unexpected payload.

### 5. Debug RPC

**Surface.** `debug_traceTransaction` and `debug_rebuildRpcCache` give
deep introspection / cache rewrites that production nodes must never
expose to public traffic.

**Audit findings addressed.** Pre-`tos11` historical issues
(`debug_rebuildRpcCache` and `debug_traceTransaction` defaults). Every
subsequent audit (including `tos15`) re-verifies these have not
regressed.

**Defenses.**

1. **`TOS_ENABLE_EVM_DEBUG_RPC` compile flag.** Production builds of
   `evm_workchain` MUST NOT define the macro; only the
   `evm_workchain_test_debug` test library does. Without the macro, the
   debug method declarations and dispatch entries are physically absent
   from the binary.
   - `evm/CMakeLists.txt:120, 140` — debug-test library opts in.
   - `evm/test/CMakeLists.txt:18, 28-35` — `test-evm-executor-debug`
     target uses `evm_workchain_test_debug`.
   - `evm/rpc/handlers.cpp:168, 1784, 5253, 5361, 5390, 5444, 5527,
     5556` — `#ifdef TOS_ENABLE_EVM_DEBUG_RPC` gates around the
     declarations, the dispatch, and per-method bodies.
   - Hardening grep:
     `scripts/check-evm-production-hardening.sh:74-94` enforces that
     `debug_traceTransaction` and `debug_rebuildRpcCache` dispatch
     lines are inside a `TOS_ENABLE_EVM_DEBUG_RPC` block.
   - Hardening grep:
     `scripts/check-evm-production-hardening.sh:246-251` enforces that
     the macro is never set on the production `evm_workchain` library.

2. **`TOS_EVM_DEBUG_RPC_TOKEN` runtime token.** Even when the build
   includes the methods, the runtime requires `TOS_EVM_DEBUG_RPC_TOKEN`
   env var to be set, ≥ 16 chars, and the request must match. Missing
   env var returns `-32601`; mismatch returns `-32001 unauthorized`.
   - `evm/rpc/handlers.cpp:1823-1832` — `handle_debug_trace_transaction`
     gate.
   - `evm/rpc/handlers.cpp:5253-5262` — `handle_debug_rebuild_rpc_cache`
     gate.
   - Hardening grep:
     `scripts/check-evm-production-hardening.sh:64-72` enforces both
     gates.

3. **AdminLocal profile gating at runtime.** Even compiled in, the
   debug allowlist is only honoured when the active profile is
   `AdminLocal` (`evm/rpc/handlers.cpp:294-300`).

4. **AdminLocal listener admission.** See attack surface 1 — the
   `decide_listen_admission` matrix prevents `AdminLocal` on a
   non-loopback listener without explicit override + API key.

---

## Cumulative test coverage

| Test target | Source | Coverage |
|---|---|---:|
| `test-evm-executor` | `evm/test/test-executor.cpp` | 163 tests (production build, `evm_workchain_test`) |
| `test-evm-executor-debug` | `evm/test/test-executor.cpp` against `evm_workchain_test_debug` | 164 tests (extra `#ifdef TOS_ENABLE_EVM_DEBUG_RPC` cases) |
| `test-evm-compute-purity` | `evm/test/test-evm-compute-purity.cpp` | 17 + cases — verify/apply phase separation invariants |
| `test-download-state-budget` | `test/test-download-state-budget.cpp` | 40+ cases — download / processing budget RAII, tempfile cleanup, concurrent downloads |
| `test-mpt-fuzz` | `evm/test/test-mpt-fuzz.cpp` | 13 fuzz drivers × 6 seeds × 2k iters ≈ 156k inputs (MPT safe API + BoC streaming importer) |
| `test-json-rpc-cache` | `validator-engine/test-json-rpc-cache.cpp` | M-02 listener-admission decision matrix |
| `test-mpt-libfuzzer` | `evm/test/test-mpt-libfuzzer.cpp` | Coverage-guided harness over the MPT `_safe` surface (gated by `TOS_BUILD_LIBFUZZER`) |
| `test-boc-libfuzzer` | `evm/test/test-boc-libfuzzer.cpp` | Coverage-guided harness over `std_boc_deserialize` and `std_boc_deserialize_from_file_bounded` (gated by `TOS_BUILD_LIBFUZZER`) |

LibFuzzer harness driver: `scripts/run-libfuzzer.sh` — required ≥ 1
hour daily per harness in CI; any `crash-*` file in the corpus must be
escalated to security.

Test driver guidance is recorded in `CLAUDE.md`: full-suite runs use
`cargo test --release -j 64` (do NOT cap `--test-threads=1`).

---

## Operational guidance

### Validator nodes

```text
--evm-rpc-profile=validator
--json-rpc-readonly
```

- `ValidatorMinimal` profile keeps consensus nodes out of heavy
  read-only RPC and disables `eth_getProof` / debug methods.
- The default JSON-RPC listener is loopback. If exposing to a private
  management network, also set `--json-rpc-api-key`.
- Recommended disk: archival-class SSD with headroom for the configured
  `--persistent-state-download-cap` and a few rounds of catch-up.
- Recommended RAM: peak resident during a 1 GiB persistent-state
  catch-up has been measured at ~256 MiB
  (`8ca3d30fd test: EXTCODEHASH 10k loop + 1 GiB streaming-importer
  resident-peak`); size accordingly with margin for live consensus.

### Follower / public RPC nodes

```text
--evm-rpc-profile=follower
--json-rpc-readonly
# (after N1 lands)
--evm-rpc-per-ip-enabled
```

- `FollowerPublic` enables `eth_call` / `eth_estimateGas` /
  `eth_createAccessList` / `eth_simulateV1` at the 10M public gas cap
  and re-enables `eth_getProof`. Debug methods stay disabled even if
  the build flag is on.
- Recommended deployment: behind a reverse proxy / WAF that enforces
  per-IP quotas and request-size limits. The per-method TokenBucket +
  AtomicConcurrencyPermit gates are the in-process line of defense, not
  the only one.
- Monitoring counters worth scraping:
  - `g_code_root_hash_mismatch_count` (`evm/core/cell-state.cpp:37`).
  - `g_persistent_state_download_bytes` and
    `g_persistent_state_processing_bytes`
    (`validator/state-download-buffer.cpp:80-81`).
  - Post-accept incomplete-index health (incomplete transactions /
    blocks pending in `evm/rpc/cache-db.cpp` and reconciled at
    `evm/core/post-accept.cpp:86-236`).

### Admin / debug nodes

```text
--evm-rpc-profile=admin
--json-rpc-api-key <strong key>
```

- `AdminLocal` raises the gas cap and unlocks the debug allowlist if
  the build flag is on.
- Strongly recommended: bind to `127.0.0.1` only and access via SSH
  tunnel or VPN. The listener admission helper refuses `AdminLocal` on
  a non-loopback address unless the operator passes
  `--allow-remote-admin-rpc` AND configures an API key, but the
  conservative deployment is loopback-only regardless.
- `TOS_EVM_DEBUG_RPC_TOKEN` must be set to a random ≥ 16-character
  string before debug methods will respond.

---

## Hardening regression coverage

`scripts/check-evm-production-hardening.sh` is the central
defense-in-depth tripwire. It is run in CI and locally; every rule
below catches a specific historical regression class.

| Rule range | What it catches |
|---|---|
| L22-47 (mnemonic / Hardhat keys) | Public test mnemonic / Anvil private key landing under `evm/core` or in non-devnet harness configs. |
| L49-62 (`EToSPoWGiver`) | `mine()` regression to parent-blockhash-only seed; missing replay-resistant per-success seed; metadata-hash leakage. |
| L64-94 (debug RPC) | `debug_traceTransaction` / `debug_rebuildRpcCache` exposed without `TOS_ENABLE_EVM_DEBUG_RPC` gate or `TOS_EVM_DEBUG_RPC_TOKEN` runtime check. |
| L96-111 (compute hot path) | Trie-witness check before transaction execution; cheap prevalidate before heavy witness check; no full-state stateRoot scan. |
| L113-123 (cell-codec / MPT) | `cp.new_data` schema v5 carries persistent trie witness; MPT primitives present. |
| L125-142 (`eth_simulateV1`) | Filler-block / response-bytes caps; method limiter + single-inflight + requested-gas preflight; no legacy 8192 filler cap. |
| L144-167 (state download) | Total / cumulative size validated before streaming; budget config or legacy constants present; no slice start before total verified. |
| L169-187 (`eth_getProof`) | Persistent-trie-witness proof path; default-on; no per-request trie rebuild / `kEmptyRoot` approximation. |
| L194-203 (post-accept) | Incomplete tx/block index durable + restart-hydrated; TokenManager wakes pending requests with the right size/priority. |
| L205-222 (lazy witness) | Compute hot path must not StrictRecursive-validate; uses `TrustedShallow` + path-bounded decode. |
| L224-251 (`TOS_EVM_TEST_INSTRUMENTATION` / debug build flag) | Test-only macros never default-on `PUBLIC` on `evm_workchain`. |
| L253-262 (`stateOverrides`) | Strict hex / oversize rejection messages present. |
| L264-326 (unsafe API) | Production paths never call `*_unsafe_for_tests_only` / `*_unsafe_for_execution_cache`; `_unsafe_for_tests_only` declarations physically gated by `TOS_EVM_TEST_INSTRUMENTATION`. |
| L328-364 (K-02) | Heavy read-only handlers + `handle_debug_trace_transaction` snapshot `code_root_hash_mismatch_count` before silkworm. |
| L366-385 (H-01) | `read_code` calls `keccak_code_hash` after `decode_evm_bytecode`. |
| L387-394 (`#ifndef NDEBUG`) | Strict compute invariant must use opt-in CMake option, not `NDEBUG`. |
| L396-433 (L-02 family) | RPC layer never uses unsafe MPT helpers; `eth_getProof` never silently `continue`s past invalid keys; `TOS_EVM_STRICT_COMPUTE_INVARIANTS` defaults OFF; `TOS_ALLOW_NPX_SOLC` not in CI release. |
| L455-485 (RPC profile) | Debug RPC dispatcher under `#ifdef TOS_ENABLE_EVM_DEBUG_RPC`; default `EvmRpcProfile` is `ValidatorMinimal`; the four heavy read-only methods are gated together. |
| L487-503 (M-02) | `refusing AdminLocal` listener fail-closed string and `allow_remote_admin_rpc` flag both present in `validator-engine/json-rpc-server.cpp`. |
| L505-517 (J1 strict parser) | `parse_call_object_strict` used; legacy `parse_call_object` deleted. |
| L519-553 (K1 / J2 streaming) | OnDisk persistent-state and zero-state paths drive `std_boc_deserialize_from_file_bounded`; BoC streaming and truncated-input fuzz drivers present. |
| L555-574 (libFuzzer) | `test-mpt-libfuzzer.cpp` and `test-boc-libfuzzer.cpp` exist; `TOS_BUILD_LIBFUZZER` option declared in root and test CMake. |

LibFuzzer harnesses run via `scripts/run-libfuzzer.sh` are expected to
execute at minimum 1 hour daily per harness in CI; the script gates the
build on `clang` + `-DTOS_BUILD_LIBFUZZER=ON`.

---

## Known not-implemented items

These are conscious decisions, not oversights. Each line says what is
missing, why it is acceptable today, and what would change that.

- **`vm::DataCell` → `vm::ExtCell` PATH A child-ref refactor (post-K1
  H-03).** Not needed for the current operating envelope per the L2
  empirical measurement: peak buffer-allocator delta during a 32 MiB
  realistic-density import is ~4 MiB, flat in BoC size, capped by the
  importer's `max_resident_bytes`. See
  `docs/adr/0001-streaming-cell-import-and-residency.md`. If profiling
  on a real archive node ever shows the streaming sink retaining the
  full DAG resident, revisit Path A.
- **N1 per-IP rate limiter.** Planned but not yet landed. Until it
  lands, follower deployments must rely on a reverse proxy / WAF for
  per-IP quota. The per-method TokenBucket and AtomicConcurrencyPermit
  gates remain effective even without per-IP limits, but they cap the
  whole node, not an individual abuser.
- **Multi-node testnet harness (operational).** Available; recommended
  deployment per `tos15` checklist is 4+ validators + a follower RPC +
  an adversarial client + a 7-14 day continuous run with corrupt-witness
  injection and reorg / archive-prune scenarios.
- **Third-party security audit.** Required before mainnet-with-real-
  value-assets deployment. Not yet completed. The cumulative
  `tos11`-`tos15` regression series is an internal regression check, not
  an independent audit.

---

## Reporting a vulnerability

Send private disclosure to the project security email channel published
in the repository's main `README.md`. Include:

- A reproducer (test case, malformed input, network capture) that
  fails closed on a non-vulnerable build.
- The build's commit SHA and CMake configuration (so reviewers can
  reproduce the same hardening regression rules).
- Whether the issue affects only debug-build code paths
  (`TOS_ENABLE_EVM_DEBUG_RPC=1`) or the production library.

Response SLA: triage acknowledgement within 5 business days; severity
assessment and remediation plan within 14 days for High / Critical
findings. Coordinated disclosure window negotiated case-by-case; bounty
policy is to be determined once the project enters
public-mainnet-with-real-value scope.

Do NOT file a public GitHub issue for any finding that surfaces:
- a remote DoS through the JSON-RPC profile gates,
- a witness-validation bypass (`WitnessFlatConsistencyContext` hooks,
  `MptTrie::*_safe` API, `code_root` keccak),
- a state-import path that bypasses `StreamingCellSink` lifecycle, or
- a debug-RPC unlock without `TOS_EVM_DEBUG_RPC_TOKEN`.

Such reports must go through the private channel only.

---

## References

- `tos11` regression audit (2026-04-26).
- `tos12` regression audit (2026-04-27).
- `tos13` regression audit (2026-04-27).
- `tos14` regression audit (2026-04-27).
- `tos15` regression audit (2026-04-27).
- ADR-0001: streaming cell import and DAG residency
  (`docs/adr/0001-streaming-cell-import-and-residency.md`).
- Hardening regression script (`scripts/check-evm-production-hardening.sh`).
- LibFuzzer driver script (`scripts/run-libfuzzer.sh`).
- Test concurrency guidance (`CLAUDE.md`).

Defense-by-defense file:line index (verified against branch `main` at
the time this document was written; line numbers are "best effort
locators" — function names are the durable handles):

- 3-state RPC profile: `evm/rpc/handlers.h:84-99`,
  `evm/rpc/handlers.cpp:228-302`,
  `validator-engine/validator-engine.cpp:6001-6017`.
- AdminLocal listener fail-closed:
  `validator-engine/json-rpc-server.cpp:255-369`,
  `validator-engine/json-rpc-server.h:169-189`,
  `validator-engine/test-json-rpc-cache.cpp:27-185`.
- Per-method rate limiters: `evm/rpc/handlers.cpp:79-94, 110-162`.
- AtomicConcurrencyPermit: `evm/rpc/handlers.cpp:172-195` and call
  sites at `1401, 1468, 1474, 1833, 3094, 4447, 5002, 5008`.
- Strict call-object parser: `evm/rpc/handlers.cpp:1078, 1268, 1393,
  1459, 4485, 4992`.
- Strict `eth_getProof` storage key: `evm/rpc/handlers.cpp:3237, 3250`.
- Strict `stateOverrides`: `evm/rpc/handlers.cpp:3656-3759`.
- Code-root mismatch counter: `evm/core/cell-state.cpp:37, 63-76`,
  `evm/core/state.cpp:437-448`,
  `evm/core/state.h:239`.
- `MptOrigin` + path-local checks:
  `evm/core/mpt-trie.h:57, 110-165, 250-297`,
  `evm/core/mpt-trie.cpp:311-498, 756-1349`.
- Dynamic flat/MPT verifier:
  `evm/core/cell-state.cpp:1131-1185, 1259-1372, 1422-`,
  `evm/core/executor.cpp:522-558`,
  `evm/core/compute-phase.cpp:130-167, 360-410, 438, 496-566`.
- Streaming BoC importer: `crypto/vm/boc.{h,cpp}`,
  `validator/downloaders/download-state.cpp:122, 147, 974, 1154`,
  `validator/downloaders/wait-block-state.cpp:495`,
  `validator/state-download-buffer.h:319-400`,
  `validator/state-download-buffer.cpp:746-`.
- Persistent-state budget: `validator/state-download-buffer.h:71-258`,
  `validator/state-download-buffer.cpp:58-134, 80-95, 139-`,
  `validator-engine/validator-engine.cpp:6052-6119`.
- `TOS_EVM_TEST_INSTRUMENTATION` gating: `evm/CMakeLists.txt:56-103,
  139`, `evm/core/mpt-trie.h:190-231`,
  `evm/core/mpt-trie.cpp:1293-1317`,
  `evm/core/cell-state.cpp:26-296, 762-795`.
- Debug RPC: `evm/CMakeLists.txt:120-140`,
  `evm/test/CMakeLists.txt:18-35`,
  `evm/rpc/handlers.cpp:168, 1784, 1823-1832, 5253-5262, 5361-5556`.
- Hardening script: `scripts/check-evm-production-hardening.sh:1-580`.
- LibFuzzer driver: `scripts/run-libfuzzer.sh:1-80`.
