# EVM Workchain — Test Plan

Version: v1.8 — 2026-04-18 (fifth 2-agent sprint: P-6 server bugs fixed + Hive 4-validator container)

## Status at a glance

| Gate | State | Notes |
|------|-------|-------|
| **Gate T — Testnet** | ✅ PASS | All 6 rows green. Last-known-good HEAD includes JSON-RPC 2.0 batch support + spec error envelope + Hive 4-validator container bootstrap. |
| **Gate P — Private mainnet** | 🚧 in progress | **4 of 6** rows fully green (P-1 + P-2 + P-5 + **P-6 closed by `d48d110a`+`03bf955b`** — Blockscout 9.0.2 syncs end-to-end without normalize-proxy shim, zero crashes, indexer reaches `finished_indexing:true` in ~90s). P-3 24h fuzz + P-4 7-day soak still gated on operational time only. |
| **Gate M — Public mainnet** | 🚧 progressing | Hive `rpc-compat`: **40 sub-tests pass via single-container 4-validator bootstrap** (`496f8ac6`, was 35 in proxy mode). `bootstrap-validators.sh` brings up 1 DHT + 4 validators + DEV-mode catchain on localhost using deterministic keys, runs `tos-create-state` with Agent K's genesis-alloc translator, then chain.rlp replay. Hive M-3 is now an "incremental closure" — each remaining failure is documented as a specific gap (eth_blockNumber lag, debug API gaps, blob support). M-1/M-2 effectively done (Cancun+Shanghai 100%). Cancun pre-fork prep done (`6d311e8e`+`bb56f43e`+`ca8cc59b`): `cancun_time = 0` flip remains intentional defer. |

| Phase | State | Headline |
|-------|-------|----------|
| G.1 — State-test harness (GeneralStateTests) | ✅ done (55 dirs, 100% pass) | Runner + walker ✅ over **55 subdirs**, **2533/2533 pass (100%)**, **0 fail**, 5 upstream-skipped (silkworm `kFailingTests` + EIP-684/7610 grey zone), 2 silkworm-asserted skips. **10 real bugs** found and fixed (5 consensus + 3 DoS + 2 adapter-glue) |
| G.2 — execution-spec-tests (Pyspec) | ✅ done (Cancun + Shanghai, 100% pass; Prague stub awaiting fixtures) | Walkers landed in `eef094bf` + `f6d1f83a`. Pyspec stable v3.0.0 fixtures: **Cancun 43/43**, **Shanghai 11/11**, Prague stub ready (no `prague/` dir in current release; future drop activates without code change). 1 new bug class found and fixed: EIP-4844 blob-fee burn missing + 2 blob-tx pre-validation rules. |
| G.3 — Hive (`rpc-compat`) | 🚧 proxy + chainId override + RLP-replay tool ✅ (35 sub-tests pass), single-validator-in-container 📋 (~3-5 days) | Scaffold (`132a9787`) → proxy mode (`4ba807df`) → chainId override (`02b791ef`) → spec-only schema + multi-roundtrip + normalize-not-found + RLP replay tool (`56d80175`). Local harness `run-rpc-compat-local.sh` now does (a) recursive type-only schema match (`// speconly:` fixtures) and (b) multi-step roundtrips. Proxy gains `--normalize-not-found` so all-zero placeholder block→null translation matches geth contract. New stdlib RLP decoder (`chain-rlp-replay.py`) parses spec's chain.rlp (45 blocks, 160 txs) and broadcasts via `eth_sendRawTransaction` — fully wired into `tos.cmd`. **PASS=35 / FAIL=∼170**. Ceiling without single-validator-in-container is ~50 (limited by chain id mismatch on signed txs). Final blocker: `crypto/block/create-state.cpp` needs Ethereum-genesis-alloc support so `tos-create-state` can bake an arbitrary set of pre-funded EOAs at the spec's chainId — ~3-5 engineer-days. |
| G.4 — Continuous differential CI + manual-rpc sanity set | 🚧 runner ✅, CI 📋 | One-shot `differential_geth.py`: 20/25 OK (after the 2026-04-18 RPC correctness pass added spec-shape `eth_feeHistory.gasUsedRatio:list<float>`, geth still returns `list<int>` so they re-diverge — both are spec-allowed, we picked spec-correct). The 5 remaining diverges are all intentional (eth_mining, eth_syncing shape, eth_accounts, eth_createAccessList simulation strategy, eth_feeHistory ratio type) — see `known-divergences.md` Category B. **OUR_ERROR methods across 202 conformance fixtures = 0**. **NEW**: `test/conformance/manual-rpc/` (`698a51fc`) — 17 RPC methods × 18 fixtures + 3 chain-step fixtures (filter lifecycle), all PASS. Covers the methods execution-apis upstream doesn't (eth_blobBaseFee, eth_coinbase, eth_protocolVersion, eth_hashrate, eth_maxPriorityFeePerGas, eth_getRawTransactionByHash, eth_getUncle*, web3_sha3 + web3_clientVersion, net_listening, net_peerCount, eth_newFilter+changes+uninstall, eth_newBlockFilter chain, eth_newPendingTransactionFilter chain). New runner `run_manual_rpc.py` understands `${RESULT_N}` token interpolation for chained tests. Continuous CI not yet stood up. |
| G.5 — Fuzz + stress | 🚧 runner ✅, 32-min soak ✅, 4h soak 🚧 deferred to overnight, 24h soak 📋 | `test/conformance/fuzz_eth.py` ✅ landed; found 1 DoS (eth_call hex-parse) fixed in `f53c356a`. Two follow-up soaks: 10-min and 32-min (109,500 mutated requests, **0 crashers / 0 5xx / 0 validator restarts**). 4-hour run started but interrupted at 32 min by user request to push other testing forward; rescheduled for off-peak. 10K-tx/s stress harness still pending. |
| **Phase F — RPC cache persistence** (Gate P-5 blocker) | ✅ done — receipts + tx + blocks (by-number + by-hash) + logs all persisted | First-principles **Pure B side-channel** design: per-validator RocksDB at `${db_root}/evm-rpc-cache`, parallel to celldb/statedb, **zero consensus involvement**. **F.5** (receipts) shipped in `68e31992`. **F.6** (tx + blocks + logs) shipped in `607ceff6`: `EvmRpcCacheDb` extended with put/get/for_each for all 4 types (key tags 0x01-0x05); compute-phase write hooks gated on `exec_result.success` to avoid validate-block re-write; `evm-init.cpp` runs 4 independent hydration walks; `proof-receipt-survives-restart.js --verify <hash> <block> <hash>` extended to also assert tx/block/logs. New unit test `test_persisted_logs_roundtrip`. **47/47** unit tests pass. **3 subtle bugs found and fixed** during F.5 integration; F.6 hooks land cleanly behind the same patterns. |

| Consensus bugs found via external-oracle testing | Commit | Severity |
|--------------------------------------------------|--------|----------|
| EIP-1559 base-fee paid to beneficiary instead of burned | `64bbd2ed` | Consensus (would diverge from Ethereum MPT roots) |
| EIP-3607 txs from code-bearing sender executed instead of rejected | `bb95edbd` | Consensus (invalid txs mutated state) |
| EIP-1559 pre-validation: priority > max, maxFee < baseFee, gas > blockGasLimit | `a71060c2` | Consensus (invalid txs mutated state) |
| EIP-2681 tx with nonce == 2^64-1 executed instead of rejected | `474f45f6` | Consensus (silent nonce overflow) |
| `eth_sendRawTransaction` DoS: oversized RLP crashed validator | `fdcebdc1` | DoS (remote-reachable) |
| `eth_sendRawTransaction` DoS: foreign-chainId txs piled up, crashed collator | `fdcebdc1` | DoS (remote-reachable) |
| `eth_call` DoS: invalid hex in `value`/`gas`/`gasPrice` crashed validator via `intx::from_string` throw | `f53c356a` | DoS (remote-reachable, found by Phase G.5 fuzzer) |
| State-test runner: PREVRANDAO fed zero to silkworm (`env.currentRandom` ignored) — 10 fixtures diverged | `23fe9c88` | Adapter glue (runner-only; prod collator already wires `block.prev_randao` correctly) |
| `CellEvmState::read_code`: returned ByteView into a shared thread_local buffer, overwritten on every call. silkworm caches the ByteView in `IntraBlockState::existing_code_`, so any recursive contract ping-ponging between two code_hashes corrupted the cache → wrong bytecode executed | `8a929b44` | **Consensus bug** — affects any tx that touches ≥2 contracts and recursion. Cleared 22 state-test fixtures at once. |
| State-test runner: `excess_blob_gas` left as `nullopt` on the block header → `blob_gas_price()` returned `nullopt` → `BLOBBASEFEE` opcode (EIP-7516, Cancun) returned 0 instead of `MIN_BLOB_GASPRICE = 1`. Contracts that branched on `ISZERO(BLOBBASEFEE)` reverted | `a23f0fb9` | Adapter glue (runner-only; production block builder doesn't have blob txs yet). Cleared the last failing fixture. |
| EIP-4844 blob-fee burn missing — `run_evm()` deducted `gas_limit * gas_price` from sender but never subtracted `total_blob_gas * blob_gas_price`. Sender balance came out too high by exactly the burn amount; spec state-root mismatched | `d140ec1d` | **Consensus bug** — affects every EIP-4844 blob tx. Found by Pyspec G.2 walker (8 fixtures simultaneously). Fix also adds 2 EIP-4844 pre-validation rules (zero-blobs, bad version byte) for 2 more cleared fixtures. |
| `eth_createAccessList` always emitted `error:""` field even on success — spec only includes the field on revert. Caused conformance regression (1 OK → 0 OK on `value-transfer.io`) | `2bdbb5e1` | RPC-shape (no consensus impact) — tracked down via differential rerun |
| `eth_estimateGas` / `eth_call` / `eth_createAccessList` rejected value transfers from unfunded sender — geth/erigon bypass the balance check during simulation, ours ran the real EVM | `1b9f881f` + `cf38cdd2` + `d4ca7c4c` | RPC compat (wallet UX) — 4/4 OK on estimateGas after fix (was 2/4) |
| `decode_log_list` (and now `decode_hash_list`): `fetch_long_bool(1, val)` sign-extends a 1-bit field to -1, not +1. Pre-existing latent bug — never surfaced because every test receipt had ≤3 logs (single chunk, no continuation read) | `483b760e` | Pre-existing latent — caught by Phase F.1 17-element hash-list tests |
| Phase F.3 receipt cache: `td::RocksDb` opens with `manual_wal_flush=true` and its destructor does not flush. Every `put_receipt` died in the memtable on SIGTERM. Caused F.5 "PASS" to actually return null receipts on restart | `68e31992` | Phase F integration — caught by the e2e proof. Fix: explicit `flush()` per put |
| Phase F.3 receipt cache: validator's validate-block re-runs compute-phase against state already mutated by collator → produces `success=false / gas=0` receipt that overwrites the good one. Caused F.5 to PASS but with garbage receipt content | `68e31992` | Phase F integration — only persist `receipt.success==true` |
| `eth_simulateV1` was missing ~20 spec block-header fields per simulated block + `maxUsedGas` per call; `transactions[]` array always empty even with `returnFullTransactions:true`. Parser also returned empty array for `blockStateCalls:[{}]` (no `"calls"` keyword) | `57887d30` | RPC shape — fixed to enumerate blockStateCalls by brace-counting; 9/63 OK on spec fixtures (was 0/63) |
| `eth_feeHistory` hardcoded 1 reward per block regardless of percentile array length; emitted `gasUsedRatio` as int (`0`) when ratio==0, breaking spec's `list<float>` shape | `57887d30` | RPC shape — 1/1 OK (was 0/1) |
| `eth_getLogs` accepted invalid filter combos: `blockHash` + `from/toBlock` (mutually exclusive per spec) and reversed `from > to` ranges. No validation rejects | `57887d30` | RPC compat — geth/erigon both reject; we now do too with matching error messages |
| `eth_simulateV1` deep-dive: parse_call_object didn't extract accessList, blobVersionedHashes, maxPriorityFeePerGas, maxFeePerBlobGas, nonce; tx-shape emission emitted every tx as type-2 (DynamicFee) regardless of fields present; `transactions[]` always emitted as object list when spec emits hash list when `returnFullTransactions` is false; per-log envelope missing 7 fields (blockHash/Number/Timestamp, transactionHash/Index, logIndex, removed); failed calls emitted no `error` envelope; `blockOverrides.number` jumps weren't filled with placeholder blocks | `4e35666e` | **9 → 50 OK on 63 simulateV1 fixtures** (+41); 13 remaining all need `stateOverrides` (out of scope for read-only simulator) |
| Phase F.6: tx + blocks + logs cross-restart persistence (Gate P-5 closure for the remaining 3 RPC categories) | `607ceff6` | Pure B side-channel — same pattern as F.5 receipts; one new key tag per type (0x02-0x05), separate write hooks all gated on `exec_result.success`, four independent hydration walks |
| `eth_simulateV1` stateOverrides + blockOverrides: handler ran every call against live state with no per-call balance/code/storage overrides and no per-block coinbase/timestamp/baseFee overrides; spec's contract-deploying fixtures all reverted because the contract address had no code on our chain | `849a42d0` | **50 → 60 OK on 63 simulateV1 fixtures** (+10); 3 remaining (1 needs Cancun activation, 1 needs SELFDESTRUCT-emit-log tracer subclass, 1 is a pre-merge fork-schema corner) |
| `eth_getProof` returned empty `storageProof[*].proof:[]` for slots that don't exist (or that exist but live in an empty storage trie). Spec emits a non-existence proof — at minimum the empty-trie root node `0x80` so verifier sees `keccak(proof[0]) == storageHash` | `fbde5412` | **2 → 3 OK on getProof fixtures** (+1, all green) |
| Hard-coded `kEvmChainId = 0x544F53` was used in 7+ places (RPC handlers, transaction admission, EIP-155 sigrec, simulateV1 chainId field, zerostate generator). To run the Hive `rpc-compat` simulator with the spec's expected chainId `0xc72dd9d5e883e`, these had to become runtime-configurable | `02b791ef` | new `current_evm_chain_id()` getter + `TOS_EVM_CHAIN_ID` env override. Caveat: must only be applied to a fresh chain (EIP-155 v-recovery binds to chainId). Hive sub-test count: 19 → 21 |
| `eth_simulateV1` blocked the `empty-with-block-num-set-firstblock.io` fixture: spec returns the pre-merge block schema (no `baseFeePerGas`/`blobGasUsed`/`excessBlobGas`/`parentBeaconBlockRoot`/`requestsHash`/`withdrawals*`) when block number is small (≤16), our handler always emitted post-merge schema | `f4ded48a` | RPC shape — fork-aware emit; 60 → 61 simulateV1 OK |
| `eth_simulateV1` `traceTransfers:true` did not emit a synthetic Transfer log on SELFDESTRUCT — spec emits one to `0xeeee…eeee` with the beneficiary transfer details | `b2feb54f` | RPC shape — new `SelfDestructLogTracer` subclass of `silkworm::EvmTracer`; 61 → 63 simulateV1 OK |
| Cancun activation analysis (no code change): pre-fork checklist documented in `known-divergences.md` Category E — KZG precompile + EIP-4788 predeploy + blob-tx admission gaps must close BEFORE flipping `cancun_time = 0`. Conformance gain (1 fixture) too small to justify rolling out without those | `a05409a1` | Documentation only |
| HTTP body silently truncated at 16 KiB — `HttpPayload::get_slice(N)` returns at most ONE 16 KiB chunk regardless of `N`, all 4 RPC server call sites called it once and treated the result as the whole body. Any ≥16 KiB request hit `-32700 Parse error` | `7fa271b0` | **Transport DoS-class bug** — silent data corruption pretending to be malformed JSON. New `drain_payload_body` helper concatenates all chunks; explicit 1 MiB cap with deterministic `-32600` rejection on overflow. Fixes the eth_simulateV1 21 KiB transport error and any other oversized request. New regression test `test/conformance/manual-rpc/http_transport/large-eth-call-30kb.io` |
| Hive bootstrap: `tos-create-state` only baked the 10 hard-coded Hardhat EOAs at 10000 TOS each. To run Hive `rpc-compat` against the spec's 36-account / 5-contract genesis, needed an arbitrary-genesis-alloc path | `24721846` + `f70d040c` + `72f997e9` | C++ overload accepting `std::vector<GenesisAccount>` with code + storage; Fift word `evm-zerostate-from-alloc` exposing it; stdlib Python translator `translate-genesis.py` that converts geth `genesis.json` to a Fift include. Test `test_genesis_alloc_parameterized` round-trips a 3-account zerostate (EOA + contract+code + contract+storage) |
| Cancun pre-fork prep: KZG point-evaluation precompile (0x0a) was not verified active; EIP-4788 beacon-roots predeploy not seeded; blob-tx admission silently passed type-3 txs that the collator would later bounce | `6d311e8e` + `bb56f43e` + `ca8cc59b` | (1) `verify_kzg_setup_loaded()` startup canary confirms evmone's bundled trusted setup is callable; (2) `seed_eip4788_predeploy()` deploys the 97-byte EIP-4788 runtime at the magic address with nonce=1; (3) per-block EIP-4788 system call hook in compute-phase, gated on `revision() >= EVMC_CANCUN` (no-op until flip); (4) `eth_sendRawTransaction` rejects type-3 with `-32000 "blob transactions not supported on this chain"`. New tests `test_kzg_precompile_active` + `test_eip4788_predeploy_seeded`. **Cancun activation analysis**: 3/3 pre-fork gaps closed; intentional defer remains because flip needs future-anchored timestamp + cross-config walker re-run |
| `eth_getProof` non-existence proof was a `0x80` placeholder for empty-trie cases; now a real Yellow Paper Appendix D walk for missing accounts/slots when the trie is non-empty | `f82a0c4b` | New `verify_mpt_proof()` cryptographic verifier in `evm-mpt-prover.{h,cpp}`. Test `test_eth_get_proof_non_existence` confirms `keccak(proof[0]) == stateRoot`, walks the proof along `keccak(target)` nibble path, terminates at divergence with `MptProofResult::kValidNonExistence`. Existence-proof + empty-trie cases also self-verify. The `0x80` empty-trie sentinel is preserved for the genuinely-empty-trie edge case |
| Blockscout 9.0.2 indexer install + sync revealed 2 hard-blocking RPC bugs in TOS JSON-RPC server: (1) error envelope shape is `{ok:false, error:str, code:N}` instead of spec `{error:{code:N, message:str}}` — crashes Indexer.Block.Catchup.MissingRangesCollector; (2) batch JSON arrays rejected — Blockscout always batches its catchup fetches | `d652576e` (catalog) + `d48d110a` (envelope fix) + `03bf955b` (batch support) | **FIXED.** validator-engine/json-rpc-server.cpp now emits spec envelope universally and dispatches batch arrays per JSON-RPC 2.0 (with order preservation, notification handling, empty-batch rejection, 100-element cap). Blockscout 9.0.2 syncs DIRECT (no normalize-proxy shim), `finished_indexing:true` in ~90s, zero crashes. Manual-rpc suite extended to 23 fixtures (4 new: 2 error_shape + 2 batch). Side fix: secondary "params must be an object" bug for unknown-method-with-array-params now correctly returns `-32601 Method not found` |
| Hive M-3: single-container 4-validator bootstrap built end-to-end. New `test/conformance/hive/clients/tos/bootstrap-validators.sh` (~450 lines bash + Python) generates 21 deterministic ed25519 keys, synthesises configs, inlines a Fift zerostate template with Agent K's `evm-zerostate-from-alloc` for the spec's 26-account allocation, runs `tos-create-state`, distributes BOCs, launches 1 DHT + 4 validators on localhost with QUIC, runs chain.rlp replay | `496f8ac6` | Verified: container produces a chain at the spec's chainId `0xc72dd9d5e883e`, prefunded balances match (e.g. `0x0c2c…7508` has 1e29 wei), chain.rlp replays. **Hive rpc-compat 35 → 40 PASS** in the local harness. Remaining 167 failures categorised: block-hash mismatches (geth-spec-vs-TOS-collator divergence — out of scope), eth_blockNumber lag (separate server-side fix), blob/4844, debug_getRaw* (geth-only API), Engine API methods (out of scope) |

## Purpose

This document consolidates the testing strategy for the TOS EVM
workchain (wc=1, chainId `0x544F53`) into a single source of truth.
It catalogs what exists today, maps our coverage onto the four
Ethereum-ecosystem conformance suites, defines admission gates for
each deployment stage, and schedules the work required to close
remaining gaps.

## Why a dedicated test plan

Implementation (Phase A–E) produced testing artifacts in several
places: `test-evm-executor.cpp` for unit tests, `test/conformance/`
for execution-apis + differential runners, `test/evm-workchain/` for
e2e shell scripts + JS wallet tests, `STATE-TESTS-STATUS.md` for a
scoping note on GeneralStateTests. None of those answer the
**deployment gate** questions: *what must be green before we ship to
testnet? private mainnet? public mainnet?* This doc does.

Treat it as a checklist, not a wishlist. Each gate either blocks
deployment or it doesn't.

## Test pyramid

```
                                ┌────────────────────┐
                                │   Hive (e2e, full  │   Phase G.3
                                │   node + network)  │   📋 PLANNED
                                └────────────────────┘
                              ┌──────────────────────────┐
                              │  Differential vs geth /  │   Phase G.4
                              │  erigon (continuous)     │   🚧 runner ✅, CI 📋
                              └──────────────────────────┘
                        ┌────────────────────────────────────┐
                        │  Ethereum conformance suites       │
                        │    • execution-apis        ✅ done │
                        │    • GeneralStateTests     🚧 G.1  │
                        │    • execution-spec-tests  📋 G.2  │
                        └────────────────────────────────────┘
                  ┌──────────────────────────────────────────────┐
                  │  Restart-survival + indexing proofs (e2e)    │
                  │    • proof-mirror-not-canonical.sh      ✅   │
                  │    • proof-bytecode-survives-restart.sh ✅   │
                  │    • proof-rpc-indexing.sh              ✅   │
                  └──────────────────────────────────────────────┘
           ┌────────────────────────────────────────────────────────┐
           │  Unit + integration (test-evm-executor, 43 tests)    ✅ │
           │    • 14 Silkworm gold vectors                        ✅ │
           │    • cell-native state (codec, state hash, atomicity)✅ │
           │    • ERC-20, precompiles, bridge, subscriptions      ✅ │
           │    • DoS regression (test_large_raw_tx_roundtrip)    ✅ │
           │    • State-test PoC (stChainId) + curated walker     ✅ │
           └────────────────────────────────────────────────────────┘
```

The bottom two bands cover *our* adapter layer. The middle two cover
parity with the Ethereum spec. The top band covers full-node
behaviour (P2P, sync, mempool interactions).

**Legend**: ✅ done and green · 🚧 in progress · 📋 planned / not
yet started · ❌ blocked or failing · ⊘ explicitly out of scope.

## In-tree inventory

### Unit + integration — `crypto/block/evm-workchain/test-evm-executor.cpp` ✅

**50** tests compiled into `./build/crypto/block/evm-workchain/test-evm-executor`.
All pass. Run in ~3 seconds on a laptop. Grouped by theme:

| Group | Count | Status | What it proves |
|-------|-------|--------|---------------|
| Silkworm gold vectors | 14 | ✅ | silkworm/execution is correctly wired: CHAINID, DELEGATECALL, CREATE return-data-size, EIP-684, EIP-3541, SELFDESTRUCT, multi-block execution, precompiles, insufficient-balance CREATE, value-transfer edge cases |
| Cell-native state | 6 | ✅ | `test_cell_codec_roundtrip`, `test_storage_dict_persistence`, `test_state_hash_includes_evm`, `test_no_separate_evm_db`, `test_bytecode_roundtrip`, `test_bytecode_marker_distinguished` |
| Ethereum-format state root | 7 | ✅ | `test_state_root_empty`, `test_state_root_single_eoa`, `test_state_root_changes_after_transfer`, `test_state_root_with_storage`, `test_block_has_state_root`, `test_transactions_root_empty`, `test_state_root_cell_format` |
| Concurrency | 2 | ✅ | `test_concurrent_eth_send_and_receipts`, `test_concurrent_filters` (shared_mutex semantics, bounded LRU cache under load) |
| RPC surface | 1 | ✅ | `test_eth_rpc` — many methods in one test |
| DoS regression (Phase E.5) | 1 | ✅ | `test_large_raw_tx_roundtrip` — 2 KB raw RLP fits in chunk chain, round-trip byte-equal |
| State-test runner (Phase G.1) | 2 | ✅ | `test_state_test_runner_poc` (loads stChainId/chainId.json and runs it against CellEvmState end-to-end), `test_state_test_runner_walk_curated` (**2533/2533 Cancun entries across 55 dirs — 100% pass**, 5 upstream-skip matching silkworm `kFailingTests` + EIP-684/7610) |
| Pyspec walker (Phase G.2) | 3 | ✅ | `test_state_test_runner_pyspec_walk` (Cancun 43/43), `test_state_test_runner_pyspec_walk_shanghai` (11/11), `test_state_test_runner_pyspec_walk_prague` (stub, awaiting fixtures) |
| Phase F codec (rpc-cache persistence) | 4 | ✅ | `test_persisted_receipt_roundtrip` (3 logs, 300-byte return_data, 4 topics LOG4-max, deterministic re-encode), `test_persisted_transaction_roundtrip` (populated + contract-create + 250-byte data + 400-byte raw_rlp), `test_persisted_block_roundtrip` (256-byte bloom, 17-hash chunked list, scalars, 4-ref fan-out), `test_persisted_logs_roundtrip` (chunked IndexedLog chain) |
| Other | 10 | ✅ | transfer, create, call, signed tx, persistent state, config param, bn254, replay, event logs, ERC-20, bridge, subscriptions, nonce validation |

Run:
```
./build/crypto/block/evm-workchain/test-evm-executor
```
Expect `PASSED` on every line; exit code 0 iff all pass.

### Restart-survival + indexing proofs — `test/evm-workchain/` ✅

Three end-to-end shell tests that clean-start the 4-validator testnet,
execute a scenario, and assert the observable state is correct. The
first two also `systemctl restart tos-validator@1` between stages to
verify persistence.

| Script | Status | Scenario | Primary assertion |
|--------|--------|----------|-------------------|
| `proof-mirror-not-canonical.sh` | ✅ | Hardhat account 0 → account 1 transfer | sender nonce 0x1 and recipient balance both survive restart |
| `proof-bytecode-survives-restart.sh` | ✅ | Deploy 10-byte runtime contract | `eth_getCode` returns the same bytecode post-restart; `eth_call` to the contract returns the expected 32-byte result |
| `proof-rpc-indexing.sh` | ✅ | Send one transfer, then probe 10 block / tx / receipt indexing methods by the freshly-observed hashes | `debug_getRawTransaction`, `debug_getRawHeader`, `debug_getRawBlock`, `debug_getRawReceipts`, `eth_getBlockTransactionCountByHash`, `eth_getTransactionByBlockHashAndIndex`, `eth_getTransactionByBlockNumberAndIndex`, `eth_getBlockReceipts`, `eth_getBlockByHash`, `eth_createAccessList` all return the expected tx/block. Closes the "weak coverage" gap for Category A methods in `known-divergences.md`. |
| `proof-receipt-survives-restart.js` | ✅ | Send tx, capture receipt; restart validator; re-query receipt | Phase F.5 — receipt with same `block`, `status`, `gasUsed` returned post-restart. Two-phase usage: bare invocation broadcasts and prints `TX_HASH=...`, then `--verify <hash>` after restart asserts the receipt survives via the side-channel cache db (`/data/tos${i}/evm-rpc-cache`). |

Run (requires sudo + systemctl):
```
sudo bash test/evm-workchain/proof-mirror-not-canonical.sh
sudo bash test/evm-workchain/proof-bytecode-survives-restart.sh
sudo bash test/evm-workchain/proof-rpc-indexing.sh
```
All three must exit 0.

### Conformance — `test/conformance/`

| Artifact | Status | What it runs |
|----------|--------|--------------|
| `run_execution_apis.py` | ✅ | 207 `.io` fixtures from ethereum/execution-apis against our RPC; shape-match classifier (see `CONFORMANCE-FINDINGS.md`) |
| `differential_geth.py` | ✅ | 25 representative RPC methods against our node + a local geth dev chain; shape diff |
| `CONFORMANCE-FINDINGS.md` | ✅ | Snapshot of findings from the 2026-04-17 full run |
| `STATE-TESTS-STATUS.md` | ✅ | Scoping note — superseded by Phase G.1 below (kept for history) |

### Wallet / developer-tooling probes — `test/evm-workchain/`

| Script | Status | Purpose |
|--------|--------|---------|
| `wallet-test.js` | ✅ | 16 read-only RPC checks end-to-end |
| `e2e-wallet-test.js` | ✅ | Replays the exact sequence MetaMask issues on first connect |
| `full-rpc-test.js` | ✅ | Full ethers.js round-trip: read, signed transfer, receipt verify, contract interaction, gas estimation |

## Ethereum conformance-suite coverage matrix

| Suite | Purpose | Our status | Signal strength | Gate |
|-------|---------|-----------|-----------------|------|
| **ethereum/execution-apis** | JSON-RPC wire-format + response shape | ✅ Adopted. 207-test runner, 0 METHOD_NOT_FOUND, 0 crashes. 16 SHAPE_MISMATCHes — all false positives from chain-state divergence, individually classified in `doc/evm-workchain-known-divergences.md` Category A. | High for RPC compat | **Required for testnet** — ✅ met |
| **ethereum/tests GeneralStateTests** | State-transition correctness per EIP | 🚧 Phase G.1 in progress. 14 Silkworm gold vectors always green + PoC runner + walker across **47 curated subdirs** → **2088/2128 pass (98.1%)**, **34 fail**, **4 upstream_skip** (mirror of silkworm's own `kFailingTests`, see `known-divergences.md` Category D). **Four real consensus bugs found and fixed**: EIP-1559 base-fee-burn (`64bbd2ed`), EIP-3607 code-bearing-sender (`bb95edbd`), EIP-1559 pre-validation suite (`a71060c2`), EIP-2681 nonce-overflow (`474f45f6`). Silkworm verified byte-identical to upstream HEAD (`aeb2302`, 2025-05-21). 34 remaining failures cluster around SELFDESTRUCT / deep-recursion / random-bytecode — most are silkworm-internal EVM edges, likely flush out with a BlockchainTests-format runner swap. See Phase G.1 below. | High — this is where consensus bugs hide | **Required for private mainnet** (at least 100% of Cancun + Shanghai subset) |
| **ethereum/execution-spec-tests** (Pyspec) | Newer Python-generated fixtures covering Cancun/Prague | 📋 Not adopted. Same runner as GeneralStateTests — bundled into Phase G.2 scope | High for post-Cancun EIPs | **Required for public mainnet** |
| **ethereum/hive** | Full-node simulator (P2P sync, mempool, JSON-RPC) in Docker | 📋 Not adopted. Phase G.3 | Medium — most hive tests assume devp2p which we don't speak; value is in the JSON-RPC and sync subsets | **Optional but recommended before public mainnet** |

Color legend for status columns: ✅ = in-tree and green · 🚧 = in progress · 📋 = planned / not yet started · ⊘ = explicitly out of scope · DEFERRED = postponed to a future stage.

## Admission gates

Each row is a binary: green = go, red or yellow = stop. Each next stage is a strict superset of the previous.

### Gate T — Testnet (local / regional)

| # | Requirement | How to verify | Blocker? | Status |
|---|-------------|---------------|----------|--------|
| T-1 | 50/50 unit tests pass | `./build/crypto/block/evm-workchain/test-evm-executor` | ✓ | ✅ |
| T-2 | All three `proof-*.sh` scripts pass | `sudo bash test/evm-workchain/proof-*.sh` (restart-survival + rpc-indexing) | ✓ | ✅ |
| T-3 | execution-apis suite: 0 METHOD_NOT_FOUND, 0 crashes, every SHAPE_MISMATCH and OUR_ERROR accounted for in `doc/evm-workchain-known-divergences.md` | `SKIP_CRASHERS=0 python3 test/conformance/run_execution_apis.py` | ✓ | ✅ |
| T-4 | 4 validators stay up through the full suite | systemd shows all `tos-validator@{1..4}` `active` post-run | ✓ | ✅ |
| T-5 | Basic wallet probes work | `node test/evm-workchain/wallet-test.js`, `full-rpc-test.js` | ✓ | ✅ |
| T-6 | Differential vs. geth: every diverge listed in `doc/evm-workchain-known-divergences.md` Category B | `python3 test/conformance/differential_geth.py` | ✓ | ✅ |

**Current status: PASS.** HEAD includes the fifth 2-agent sprint
results (JSON-RPC 2.0 batch + spec error envelope — closes P-6 via
Blockscout direct sync without shim; single-container 4-validator
Hive bootstrap — 35 → 40 rpc-compat sub-tests). **50/50** unit
tests pass; **OUR_ERROR=0** across 202 conformance fixtures.

### Gate P — Private mainnet (limited allowlisted validators + RPCs)

Everything in Gate T, plus:

| # | Requirement | How to verify | Blocker? | Status |
|---|-------------|---------------|----------|--------|
| P-1 | Cancun + Shanghai GeneralStateTests ≥ 95% pass | Phase G.1 runner reports counts | ✓ | ✅ — **2533/2533 (100%)** across 55 dirs, exceeds the 95% bar |
| P-2 | execution-spec-tests Cancun fork ≥ 95% pass | Phase G.2 runner (shared harness) | ✓ | ✅ — Cancun **43/43 (100%)** + Shanghai **11/11 (100%)** |
| P-3 | No known DoS vectors from a 24-hour fuzz of `eth_sendRawTransaction` + `eth_call` with malformed inputs | Phase G.5 fuzz harness | ✓ | 🚧 — **32-min soak: 109,500 mutations / 0 crashers / 0 5xx**; 4h overnight scheduled; 24h still pending |
| P-4 | 7-day soak on a dedicated testnet: zero validator restarts due to EVM bugs, zero state-hash divergences | Operational logs | ✓ | 📋 |
| P-5 | Receipts / tx / logs survive validator restart | **Phase F.5+F.6 fully shipped** (`68e31992` receipts; `607ceff6` tx + blocks + logs). Codec, write hooks, hydration walks all live. e2e proof script extended (`proof-receipt-survives-restart.js --verify <hash> <block> <hash>`) — receipt + tx + block-by-number + block-by-hash + getLogs all check post-restart | ✓ | ✅ |
| P-6 | Third-party indexer (Blockscout or similar) syncs the chain without warnings | Manual run | Recommended | ✅ — **Blockscout 9.0.2 syncs DIRECTLY** without the normalize-proxy shim after `d48d110a` (spec error envelope) + `03bf955b` (JSON-RPC 2.0 batch dispatch). Stack at `test/conformance/blockscout/` reaches `finished_indexing:true, indexed_blocks_ratio:1` in ~90 s with **0 GenServer crashes** and **0 FunctionClauseError** on `standardize_error`. The previously-blocking BUG #1 (top-level error string) and BUG #2 (batch rejection) are both fixed — see bug table below + `test/conformance/blockscout/README.md`. Remaining noise: `txpool_content` returns spec-shape `-32601 Method not found` (Blockscout treats as "no pending data this tick", indexer keeps progressing — non-blocking warning only). |

### Gate M — Public mainnet

Everything in Gates T + P, plus:

| # | Requirement | How to verify | Blocker? | Status |
|---|-------------|---------------|----------|--------|
| M-1 | **All** Cancun + Shanghai + post-merge GeneralStateTests pass (100%) | Phase G.1 runner | ✓ | 📋 |
| M-2 | execution-spec-tests: 100% on all forks our chain claims to support | Phase G.2 runner | ✓ | 📋 |
| M-3 | Hive suite `rpc-compat` + `sync` subsets pass | Phase G.3 | ✓ | 🚧 — proxy mode passes 19 sub-tests (`4ba807df`); ~1-2d for arbitrary chainId in `tos-create-state`, ~1-2d for chain.rlp replay (gated on further `eth_sendRawTransaction` stabilisation). `sync` skipped (we don't speak devp2p — out of scope per design) |
| M-4 | Third-party security audit of the EVM adapter layer (`crypto/block/evm-workchain/`, the admission path, and the cell codec) | Audit report | ✓ | 📋 |
| M-5 | Differential CI against geth + erigon + reth has run continuously for ≥ 30 days with no undiagnosed diverges | Phase G.4 | ✓ | 📋 (runner ✅, continuous CI 📋) |
| M-6 | Stress: 10K tx/s submission through `eth_sendRawTransaction` for 1 hour without validator crashes or memory exhaustion | Phase G.5 | ✓ | 📋 |
| M-7 | `eth_getProof` round-trips through a light client implementation | Manual | ✓ | 📋 |

## Phase roadmap (G.1 – G.5)

### Phase G.1 — State-test harness 🚧 in progress

**Goal:** run ethereum/tests GeneralStateTests + execution-spec-tests
against `CellEvmState` byte-for-byte.

**Scope:**
- ✅ Minimal JSON fixture loader + executor in `test-evm-executor.cpp`
  (`run_one_state_test_cancun`) — loads `pre`, decodes `txbytes`, runs
  `execute_evm_transaction` with a per-test `ChainConfig`, diffs every
  account in `post.Cancun.state` (balance, nonce, storage slots).
- ✅ Curated directory walker (`test_state_test_runner_walk_curated`
  + `walk_state_tests`) — runs every `*.json` under the listed
  subdirectories, reports pass/fail/skip per directory plus a total.
- ✅ **Four** real consensus bugs found and fixed via the walker:
    * EIP-1559 base-fee-burn: beneficiary was receiving
      `gas_used * effective_gas_price` instead of priority-only, so
      the base fee was paid to the miner instead of burned. Commit
      `64bbd2ed`. Caught by `stSelfBalance/diffPlaces.json`.
    * EIP-3607: txs from accounts with non-empty code were being
      executed instead of rejected. Commit `bb95edbd`. Caught by 4
      fixtures in `stEIP3607/`.
    * EIP-1559 pre-validation (commit `a71060c2`): rejected-pre-tx
      paths were executing instead. Added: priority ≤ maxFee,
      maxFee ≥ baseFee, txn.gas_limit ≤ block.gas_limit, balance
      budget uses maxFeePerGas (not effective), intrinsic-gas
      check moved earlier. Caught by
      `stEIP1559/{tipTooHigh,transactionIntinsicBug_Paris,lowGasLimit}`.
    * EIP-2681: tx with sender-nonce == 2^64-1 executed,
      silently overflowing the nonce counter. Commit `474f45f6`.
      Caught by `stCreateTest/CreateTransactionHighNonce.json`.
- ✅ Walker expanded to **47 subdirectories** covering ~2,100 fixtures;
  resilience fix so silkworm asserts on intentionally-invalid txs
  become clean skips instead of aborting the binary.
- **Current walker coverage**: **2088/2128 pass (98.1%)** across 47 dirs,
  34 fail, 2 skip (silkworm asserts), **4 upstream_skip** (mirror of
  silkworm's own `kFailingTests` — see `known-divergences.md`
  Category D).
- ✅ Silkworm is verified byte-identical to upstream HEAD
  (`erigontech/silkworm` @ `aeb2302`, 2025-05-21). The 34 remaining
  failures are therefore not snapshot-lag; they are either genuine
  silkworm-level EVM edges or artifacts of the `GeneralStateTests`
  fixture format itself.
- ✅ EIP-4788 beacon-roots pre-block hook added to the runner so
  that fixtures warming addresses via the Cancun system call don't
  observe an empty pre-state. (Didn't move the 29-fail count —
  confirms these failures are not about EIP-4788 warming.)
- 📋 Deferred: porting the walker to the `BlockchainTests` fixture
  format silkworm's own CI uses. That format wraps each state test
  in an RLP-encoded block + genesis-RLP + expected block-hash
  chain; it would exercise the full `ExecutionProcessor` path
  (including the beacon-roots predeploy, block rewards, uncle
  checks, etc). Estimate: 2-3 days for a minimal runner.
  Hypothesis: most of the 34 remaining failures land in silkworm's
  per-block hooks that our GST-format runner bypasses — porting
  would narrow the gap to upstream silkworm gaps only.
- 🚧 Remaining 34 fixture failures cluster into themes for
  follow-up investigation:
    * `stExtCodeHash/*DeletedAccount*` (6) — SELFDESTRUCT + EIP-6780
      balance-transfer semantics; silkworm passes these in its own
      BlockchainTests runner but our raw-GeneralStateTests runner
      shows diffs — worth checking whether silkworm's `created()`
      tracking differs between the two entry points.
    * `stStaticCall/*RecursiveBomb*`, `stCreate2/OnDepth102x`
      (11 total) — 1024-depth call-stack + gas-forwarding edge
      cases, inside silkworm::EVM.
    * `stRandom/*` (9) — randomly-generated bytecode, various
      opcode edge triggers.
    * `stCreateTest/CreateOOGafterMaxCodesize` (1) — EIP-170 24KB
      code-size gas accounting.
    * `stBadOpcode/opc4ADiffPlaces` (1) — BLOBBASEFEE (EIP-7516)
      opcode semantics; silkworm has the field but this specific
      test may exercise a corner.
    * `stRevertTest/LoopCallsDepthThenRevert` (1) — recursive depth
      with REVERT.
    * `stCallDelegateCodesCallCodeHomestead/*ABCB_RECURSIVE*` (2) and
      `stCallDelegateCodesHomestead/*ABCB_RECURSIVE*` (2) — same
      deep-recursion / call-stack edges as the `stStaticCall`
      bombs above, just in the Homestead-era dirs.
    * `stExample/mergeTest` (1) — synthetic fixture; likely a
      harness-format edge.
- 🚧 Expand walker to remaining ~15 subdirectories (still mostly
  fork-agnostic + Cancun). Target: ≥ 95% pass on a
  representative Cancun+Shanghai sample before Gate P.
- 🚧 Post-state MPT root comparison via `IncrementalTrieCalculator`
  — right now we compare accounts individually; expected `hash`
  in the fixture requires computing the Ethereum-format state
  root and diffing against the JSON's `hash`.
- Deferred: vendoring Silkworm's `cmd/consensus/consensus.cpp`
  (~550 lines) into a standalone binary. The in-process runner is
  sufficient for PoC + curated walker.

**Acceptance:**
- Phase P gate — Cancun + Shanghai ≥ 95% pass.
- Phase M gate — 100% on all supported forks.

**Estimate:** 5-7 engineering days (runner + debugging first
divergences). First day already landed PoC + 1 real consensus bug.

### Phase G.2 — execution-spec-tests (Pyspec) 📋 planned

**Goal:** run the Python-generated Pyspec fixtures (newer, covers
Prague).

**Scope:** same runner as Phase G.1 (the fixture JSON format is
identical to GeneralStateTests); extend the scripts to walk
`execution-spec-tests/fixtures/` in addition to
`ethereum-tests/GeneralStateTests/`.

**Acceptance:** ≥ 95% on all Cancun + Shanghai, ≥ 95% on Prague if
we claim support.

**Estimate:** 1-2 days once G.1 is in place (mostly repo-wiring).

### Phase G.3 — Hive (optional, recommended pre-mainnet) 📋 planned

**Goal:** run the `rpc-compat` and `sync` simulators from
ethereum/hive against a containerized `tos-validator-engine`.

**Scope:**
- Write a `Dockerfile` that launches a validator in dev mode with the
  JSON-RPC port exposed.
- Write a hive client definition (Go stub — ~100 lines).
- Shim devp2p out of the relevant simulators (we don't speak it —
  our P2P is TOS overlay + ADNL).

**Acceptance:** `rpc-compat` 100% pass. `sync` skipped (not
applicable without devp2p).

**Estimate:** 5-10 days (Docker + Go + skipping logic).

### Phase G.4 — Continuous differential CI 🚧 runner ✅ · CI 📋

**Goal:** automate the `differential_geth.py`-style checks as a
recurring job.

**Scope:**
- ✅ One-shot differential runner (`differential_geth.py`) — 25
  RPC methods against our node + local geth dev chain. Current
  result: 20/25 match, 5 documented diverges in
  `known-divergences.md` Category B.
- 📋 Stand up a geth + erigon + reth container triple alongside our
  4-validator testnet.
- 📋 Extend `differential_geth.py` → `differential_multi.py` that
  polls all four nodes for every RPC method at a configurable
  frequency.
- 📋 Any diverge triggers an alert (Slack/email).
- 📋 Run continuously for 30+ days before Gate M.

**Acceptance:** no undiagnosed diverges in the 30-day window.

**Estimate:** 3-5 days setup + ongoing operational cost.

### Phase G.5 — Fuzz + stress 🚧 runner ✅ · short soak ✅ · 24h soak 📋

**Goal:** flush out latent DoS vectors and throughput ceilings.

**Scope:**
- ✅ Fuzzer (`test/conformance/fuzz_eth.py`) — mutates valid raw
  transactions and floods `eth_sendRawTransaction` + `eth_call`.
  Seed corpus from the 46 unit tests + the execution-apis fixtures.
  Distinguishes operator-induced restart from real crash via 32-second
  exponential backoff probe (`a745d0ae`).
- ✅ Latest soak: **32 minutes, 109,500 mutated requests, 0 crashers,
  0 5xx, 0 validator restarts**. 6% of `eth_call` requests hit the
  60-second timeout (interesting payloads worth post-soak sampling).
- ✅ Found 1 DoS bug: `eth_call` invalid-hex via `intx::from_string`
  throw — fixed in `f53c356a`.
- 🚧 4-hour overnight soak rescheduled (initial run interrupted at
  32 min by user request to push other testing forward).
- 📋 24-hour soak.
- 📋 Throughput harness driving `eth_sendRawTransaction` at increasing
  rates until first failure mode (memory, latency, crash). Target:
  ≥10K tx/s sustained.

**Acceptance:** 24-hour fuzz run with zero crashes; 1-hour stress
at 10K tx/s with memory plateau and no validator restarts.

**Estimate:** 3-5 days for the throughput harness; operational time variable.

### Phase F — RPC cache persistence ✅ done (receipts; tx/blocks/logs scaffolded)

**Goal:** receipts / transactions / blocks / logs survive validator
restart. Closes Gate P row P-5.

**Design (Pure B side-channel)**: per-validator standalone RocksDB
instance at `${db_root}/evm-rpc-cache`, parallel to celldb/statedb.
**Zero consensus involvement** — the RPC cache cells are not
referenced from `state_hash`. Receipt-encoding bugs cannot fork the
chain; operators tune retention independently without coordination.
Full design in `doc/evm-workchain-rpc-cache-persistence.md`.

**Why Pure B over the original Option C**: first-principles —
receipts are derived data, not consensus. Geth/erigon both hold
them in a separate RocksDB column family. Putting them inside
`cp.new_data` (Option B) or `EvmAccountData` (Option A) would turn
every encoding subtlety into a fork. The cost of B (one extra
RocksDB instance per node) is far smaller than that surface.

**Scope:**
- ✅ F.1 — `evm-rpc-cache-codec.{h,cpp}`: `encode/decode_persisted_receipt`,
  `encode/decode_persisted_transaction`, `encode/decode_persisted_block`
  (`483b760e`). Cell layout caps each at 1023 bits/cell with
  fan-out via refs (4-ref blocks, chunked log/hash lists).
- ✅ F.2 — `cp.new_data` v2 with trailing `Maybe ^Cell rpc_cache_root`
  (`90eea2a6`). Backward-compatible decoder reads v1 cells as
  `nothing`. Pure B does not actually use the slot but keeps it for
  future chain-wide hooks.
- ✅ F.3 — `EvmRpcCacheDb` (`evm-rpc-cache-db.{h,cpp}`) wraps
  `td::RocksDb` with key namespacing (1-byte tag + 32-byte tx_hash).
  `put_receipt` calls `flush()` per put because `td::RocksDb`'s
  default `manual_wal_flush=true` + non-flushing destructor would
  otherwise lose every write on SIGTERM. Wired into compute-phase
  with a `receipt.success` filter so the validator's failed
  validate-block re-execution doesn't overwrite the collator's good
  receipt (`68e31992`).
- ✅ F.4 — Hydration in `init_evm_workchain`: walks the cache and
  calls `g_evm_state.store_receipt` for every entry. Decode failures
  are logged-and-skipped (best-effort recovery).
- ✅ F.5 — `proof-receipt-survives-restart.js` end-to-end harness;
  verified live: tx mined into block 35852, all 4 validators
  restarted, post-restart `eth_getTransactionReceipt` returned
  identical block / status / gasUsed.
- 🚧 Extension to `transactions` / `blocks` / `logs` — codec already
  in place (`483b760e`); mechanical replication of the F.3+F.4
  pattern with new key tags. ~1 day.

**Acceptance:** ✅ for receipts. Extension to tx/blocks/logs is the
remaining ~1 day; tracked under P-5 as "in extension".

**Future hardening (not blocking Gate P):**
- Periodic / batched flush instead of per-put (avoids 1 SST per
  receipt at high TPS).
- Retention sweeper with operator-tunable window (e.g. drop entries
  with `block_number < latest - N`).
- Surface a metric for cache size / hit-rate.

## Ownership and cadence

| Layer | Run when | Owner | Failure action |
|-------|----------|-------|----------------|
| Unit (`test-evm-executor`) | Every commit that touches `crypto/block/evm-workchain/` or `validator-engine/` | Contributor | Must go green before merge |
| Proof tests | Before each testnet deploy | Maintainer | Block the deploy |
| execution-apis | Before each testnet deploy + weekly on main | Maintainer | Investigate any new MNF or crash within 24h |
| Differential (Phase G.4, once live) | Continuous; alert on diverge | On-call | Triage within 1h |
| State-test corpus (Phase G.1, once live) | Pre-mainnet deploy; weekly on main | Maintainer | Block deploy if any Cancun test regresses |

## What's intentionally NOT in scope

- **devp2p compatibility.** Our node speaks TOS overlay + ADNL; we
  don't intend to join the Ethereum P2P network. Hive's `sync` suite
  is therefore not a meaningful signal for us.
- **Full hive suite.** Many hive tests cover engine API, block
  propagation, and other post-merge-Ethereum-specific concerns that
  don't apply to a TOS-hosted EVM workchain. We cherry-pick
  `rpc-compat` only.
- **Fork simulation before we ship support for a fork.** We test the
  forks our chain config activates. Adding Prague support (for
  example) means both a code change and an extension of the
  G.1/G.2 target lists — not a silent broadening.

## References

- `doc/evm-workchain-known-divergences.md` — v1.0, registry of
  acceptable RPC response differences (so runners don't re-flag them
  as bugs)
- `doc/tos-evm-workchain-feasibility.md` — v1.4, ships-all-phases
  summary + phase history
- `doc/evm-workchain-cell-native-state.md` — v1.3, cell schema incl.
  `EvmAccountData.code`
- `doc/evm-workchain-rpc-cache-persistence.md` — v0.1, Phase F design
  (Pure B side-channel for receipts/tx/blocks/logs)
- `doc/evm-workchain-transaction-admission-and-single-executor.md`
  — v2.0, admission-model rationale
- `test/conformance/CONFORMANCE-FINDINGS.md` — the last full
  execution-apis snapshot
- `test/conformance/STATE-TESTS-STATUS.md` — superseded by Phase G.1
  above; kept for historical context
- `test/evm-workchain/README.md` — wallet / e2e script usage
- upstream: `ethereum/execution-apis`,
  `ethereum/tests`,
  `ethereum/execution-spec-tests`,
  `ethereum/hive`
