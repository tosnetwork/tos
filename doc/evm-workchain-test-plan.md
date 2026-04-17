# EVM Workchain — Test Plan

Version: v1.1 — 2026-04-17 (status snapshot)

## Status at a glance

| Gate | State | Notes |
|------|-------|-------|
| **Gate T — Testnet** | ✅ PASS | All 6 rows green. Last-known-good `57bf20cb`. |
| **Gate P — Private mainnet** | 🚧 in progress | 1 of 6 rows partially green (G.1 at 97.6% on curated subset). |
| **Gate M — Public mainnet** | 📋 planned | Depends on Gates T + P + Phase G.2/G.3/G.4/G.5 + third-party audit. |

| Phase | State | Headline |
|-------|-------|----------|
| G.1 — State-test harness (GeneralStateTests) | 🚧 in progress | Runner + walker ✅ over **30 subdirs**, **1427/1458 pass (97.9%)**, **29 fail** to investigate, **4 upstream-skipped** (silkworm `kFailingTests`), **6 real consensus bugs** already found and fixed |
| G.2 — execution-spec-tests (Pyspec) | 📋 planned | Same runner as G.1; extend to new fixture dir |
| G.3 — Hive (`rpc-compat`) | 📋 planned | Dockerize validator, write hive client stub |
| G.4 — Continuous differential CI | 🚧 runner ✅, CI 📋 | One-shot `differential_geth.py` lives; continuous CI not yet stood up |
| G.5 — Fuzz + stress | 📋 planned | Harness to be written |

| Consensus bugs found via external-oracle testing | Commit | Severity |
|--------------------------------------------------|--------|----------|
| EIP-1559 base-fee paid to beneficiary instead of burned | `64bbd2ed` | Consensus (would diverge from Ethereum MPT roots) |
| EIP-3607 txs from code-bearing sender executed instead of rejected | `bb95edbd` | Consensus (invalid txs mutated state) |
| EIP-1559 pre-validation: priority > max, maxFee < baseFee, gas > blockGasLimit | `a71060c2` | Consensus (invalid txs mutated state) |
| EIP-2681 tx with nonce == 2^64-1 executed instead of rejected | `474f45f6` | Consensus (silent nonce overflow) |
| `eth_sendRawTransaction` DoS: oversized RLP crashed validator | `fdcebdc1` | DoS (remote-reachable) |
| `eth_sendRawTransaction` DoS: foreign-chainId txs piled up, crashed collator | `fdcebdc1` | DoS (remote-reachable) |

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

43 tests compiled into `./build/crypto/block/evm-workchain/test-evm-executor`.
All pass. Run in ~3 seconds on a laptop. Grouped by theme:

| Group | Count | Status | What it proves |
|-------|-------|--------|---------------|
| Silkworm gold vectors | 14 | ✅ | silkworm/execution is correctly wired: CHAINID, DELEGATECALL, CREATE return-data-size, EIP-684, EIP-3541, SELFDESTRUCT, multi-block execution, precompiles, insufficient-balance CREATE, value-transfer edge cases |
| Cell-native state | 6 | ✅ | `test_cell_codec_roundtrip`, `test_storage_dict_persistence`, `test_state_hash_includes_evm`, `test_no_separate_evm_db`, `test_bytecode_roundtrip`, `test_bytecode_marker_distinguished` |
| Ethereum-format state root | 7 | ✅ | `test_state_root_empty`, `test_state_root_single_eoa`, `test_state_root_changes_after_transfer`, `test_state_root_with_storage`, `test_block_has_state_root`, `test_transactions_root_empty`, `test_state_root_cell_format` |
| Concurrency | 2 | ✅ | `test_concurrent_eth_send_and_receipts`, `test_concurrent_filters` (shared_mutex semantics, bounded LRU cache under load) |
| RPC surface | 1 | ✅ | `test_eth_rpc` — many methods in one test |
| DoS regression (Phase E.5) | 1 | ✅ | `test_large_raw_tx_roundtrip` — 2 KB raw RLP fits in chunk chain, round-trip byte-equal |
| State-test runner (Phase G.1) | 2 | ✅ | `test_state_test_runner_poc` (loads stChainId/chainId.json and runs it against CellEvmState end-to-end), `test_state_test_runner_walk_curated` (1427/1458 Cancun entries across 30 dirs — 97.9% pass, 4 upstream-skip matching silkworm `kFailingTests`) |
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
| **ethereum/tests GeneralStateTests** | State-transition correctness per EIP | 🚧 Phase G.1 in progress. 14 Silkworm gold vectors always green + PoC runner + walker across **30 curated subdirs** → **1427/1458 pass (97.9%)**, **29 fail**, **4 upstream_skip** (mirror of silkworm's own `kFailingTests`, see `known-divergences.md` Category D). **Four real consensus bugs found and fixed**: EIP-1559 base-fee-burn (`64bbd2ed`), EIP-3607 code-bearing-sender (`bb95edbd`), EIP-1559 pre-validation suite (`a71060c2`), EIP-2681 nonce-overflow (`474f45f6`). Silkworm verified byte-identical to upstream HEAD (`aeb2302`, 2025-05-21). 29 remaining failures cluster around SELFDESTRUCT / deep-recursion / random-bytecode — most are silkworm-internal EVM edges, likely flush out with a BlockchainTests-format runner swap. See Phase G.1 below. | High — this is where consensus bugs hide | **Required for private mainnet** (at least 100% of Cancun + Shanghai subset) |
| **ethereum/execution-spec-tests** (Pyspec) | Newer Python-generated fixtures covering Cancun/Prague | 📋 Not adopted. Same runner as GeneralStateTests — bundled into Phase G.2 scope | High for post-Cancun EIPs | **Required for public mainnet** |
| **ethereum/hive** | Full-node simulator (P2P sync, mempool, JSON-RPC) in Docker | 📋 Not adopted. Phase G.3 | Medium — most hive tests assume devp2p which we don't speak; value is in the JSON-RPC and sync subsets | **Optional but recommended before public mainnet** |

Color legend for status columns: ✅ = in-tree and green · 🚧 = in progress · 📋 = planned / not yet started · ⊘ = explicitly out of scope · DEFERRED = postponed to a future stage.

## Admission gates

Each row is a binary: green = go, red or yellow = stop. Each next stage is a strict superset of the previous.

### Gate T — Testnet (local / regional)

| # | Requirement | How to verify | Blocker? | Status |
|---|-------------|---------------|----------|--------|
| T-1 | 43/43 unit tests pass | `./build/crypto/block/evm-workchain/test-evm-executor` | ✓ | ✅ |
| T-2 | All three `proof-*.sh` scripts pass | `sudo bash test/evm-workchain/proof-*.sh` (restart-survival + rpc-indexing) | ✓ | ✅ |
| T-3 | execution-apis suite: 0 METHOD_NOT_FOUND, 0 crashes, every SHAPE_MISMATCH and OUR_ERROR accounted for in `doc/evm-workchain-known-divergences.md` | `SKIP_CRASHERS=0 python3 test/conformance/run_execution_apis.py` | ✓ | ✅ |
| T-4 | 4 validators stay up through the full suite | systemd shows all `tos-validator@{1..4}` `active` post-run | ✓ | ✅ |
| T-5 | Basic wallet probes work | `node test/evm-workchain/wallet-test.js`, `full-rpc-test.js` | ✓ | ✅ |
| T-6 | Differential vs. geth: every diverge listed in `doc/evm-workchain-known-divergences.md` Category B | `python3 test/conformance/differential_geth.py` | ✓ | ✅ |

**Current status: PASS.** Commit `64bbd2ed` is the last-known-good
(includes the EIP-1559 base-fee-burn fix).

### Gate P — Private mainnet (limited allowlisted validators + RPCs)

Everything in Gate T, plus:

| # | Requirement | How to verify | Blocker? | Status |
|---|-------------|---------------|----------|--------|
| P-1 | Cancun + Shanghai GeneralStateTests ≥ 95% pass | Phase G.1 runner reports counts | ✓ | 🚧 currently 97.9% on curated subset (1427/1458 across 30 dirs; 4 upstream-skip matching silkworm `kFailingTests`); need to expand walker to remaining dirs + investigate 29 SELFDESTRUCT / deep-recursion failures |
| P-2 | execution-spec-tests Cancun fork ≥ 95% pass | Phase G.2 runner (shared harness) | ✓ | 📋 |
| P-3 | No known DoS vectors from a 24-hour fuzz of `eth_sendRawTransaction` + `eth_call` with malformed inputs | Phase G.5 fuzz harness | ✓ | 📋 |
| P-4 | 7-day soak on a dedicated testnet: zero validator restarts due to EVM bugs, zero state-hash divergences | Operational logs | ✓ | 📋 |
| P-5 | Receipts / tx / logs survive validator restart | Currently RAM-only LRUs; needs Phase F (RPC-cache extraction) | ✓ | 📋 |
| P-6 | Third-party indexer (Blockscout or similar) syncs the chain without warnings | Manual run | Recommended | 📋 |

### Gate M — Public mainnet

Everything in Gates T + P, plus:

| # | Requirement | How to verify | Blocker? | Status |
|---|-------------|---------------|----------|--------|
| M-1 | **All** Cancun + Shanghai + post-merge GeneralStateTests pass (100%) | Phase G.1 runner | ✓ | 📋 |
| M-2 | execution-spec-tests: 100% on all forks our chain claims to support | Phase G.2 runner | ✓ | 📋 |
| M-3 | Hive suite `rpc-compat` + `sync` subsets pass | Phase G.3 | ✓ | 📋 |
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
- ✅ Walker expanded to **30 subdirectories** covering ~1,500 fixtures;
  resilience fix so silkworm asserts on intentionally-invalid txs
  become clean skips instead of aborting the binary.
- **Current walker coverage**: **1427/1458 pass (97.9%)** across 30 dirs,
  29 fail, 2 skip (silkworm asserts), **4 upstream_skip** (mirror of
  silkworm's own `kFailingTests` — see `known-divergences.md`
  Category D).
- ✅ Silkworm is verified byte-identical to upstream HEAD
  (`erigontech/silkworm` @ `aeb2302`, 2025-05-21). The 29 remaining
  failures are therefore not snapshot-lag; they are genuine
  silkworm-level gaps or our runner's GeneralStateTests-format
  handling divergences from silkworm's BlockchainTests-format runner.
- 🚧 Remaining 29 fixture failures cluster into themes for
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
- 🚧 Expand walker to remaining ~20 subdirectories (still mostly
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

### Phase G.5 — Fuzz + stress 📋 planned

**Goal:** flush out latent DoS vectors and throughput ceilings.

**Scope:**
- A fuzzer that mutates valid raw transactions and floods
  `eth_sendRawTransaction` + `eth_call`. Seed corpus from the 41 unit
  tests + the execution-apis fixtures.
- A throughput harness that drives `eth_sendRawTransaction` at
  increasing rates until first failure mode (memory, latency,
  crash). Target: ≥10K tx/s sustained.

**Acceptance:** 24-hour fuzz run with zero crashes; 1-hour stress
at 10K tx/s with memory plateau and no validator restarts.

**Estimate:** 3-5 days for the harness; operational time variable.

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
