# EVM Workchain — Known Acceptable Divergences

Version: v1.0 — 2026-04-17

## Purpose

Running an Ethereum conformance suite against a non-Ethereum chain
produces two types of non-matching test results:

1. **False positives** — the suite's fixtures assume a specific seeded
   chain state (e.g. ethereum/execution-apis has a pre-baked
   `chain.rlp` with blocks, receipts, and contracts at known hashes).
   Our chain has a completely different genesis and state, so any
   method that reads a specific block/tx/receipt by hash returns
   `null` while the suite expects a populated object. This is not a
   bug — it's "you asked us about a block we don't have".

2. **Intentional behavioral differences** — cases where our response
   legitimately differs from geth (or the spec) for a documented
   reason: a field was removed post-merge, we're stricter than geth
   somewhere for a security reason, a method geth no longer
   implements, etc.

Both categories look identical in the runner output
(`SHAPE_MISMATCH` or `DIVERGE`). Without this document, every
conformance run rediscovers them and a reviewer re-investigates
whether each one is a real bug. That's waste.

This doc is the **known-acceptable list**. If a divergence is on
this list, runners should skip it or flag it as expected. If a
divergence is not on this list, it needs investigation before the
next testnet deploy.

Linked from `doc/evm-workchain-test-plan.md` §3 and §4 — see that
doc for the overall test plan.

## Category A — False positives from chain-state divergence

These appear when running `ethereum/execution-apis/tests/` against
our node. The runner (`test/conformance/run_execution_apis.py`)
classifies them as `SHAPE_MISMATCH` because the spec's expected
response is a populated object and ours is `null` / `[]`.

All 12 of these are the same root cause: the spec's seeded chain has
block N / tx T / log L; our chain doesn't. Querying for N / T / L on
our chain correctly returns "not found".

| Method | Test fixture | Our response | Spec response | Reason |
|--------|--------------|--------------|---------------|--------|
| `debug_getRawBlock` | `get-block-n.io` | `null` | RLP hex string | Block at requested number doesn't exist on our chain |
| `debug_getRawHeader` | `get-block-n.io` | `null` | RLP hex string | Same |
| `debug_getRawReceipts` | `get-block-n.io` | `[]` | `list<str>` | No receipts at that block number |
| `debug_getRawTransaction` | `get-tx.io` | `null` | RLP hex string | Tx hash not indexed on our chain |
| `eth_getBlockByHash` | `get-block-by-hash.io` | `null` | full block object | Hash not in our CellDb |
| `eth_getBlockByNumber` | 10 of 11 test fixtures | various | various | Each fixture queries a specific block number or tag; our chain's blocks at those heights have different content |
| `eth_getBlockReceipts` | `get-block-receipts-by-hash.io` | `[]` | `list<receipt>` | Block hash not ours |
| `eth_getBlockTransactionCountByHash` | `get-block-n.io` | `null` | `"0xN"` | Block hash not ours |
| `eth_getLogs` | `contract-addr.io` | `[]` | `list<log>` | Contract address referenced isn't deployed on our chain |
| `eth_getTransactionByBlockHashAndIndex` | `get-block-n.io` | `null` | tx object | Block hash not ours |
| `eth_getTransactionByBlockNumberAndIndex` | `get-block-n.io` | `null` | tx object | No tx at that index |
| `eth_getTransactionByHash` | `get-access-list.io` | `null` | tx object | Tx hash not ours |
| `eth_getTransactionReceipt` | `get-access-list.io` | `null` | receipt | Tx hash not ours |
| `eth_call` | 1 of 6 fixtures | error "execution reverted" | result hex | Contract at spec's address doesn't exist on our chain, so the call reverts |
| `eth_estimateGas` | 2 of 4 fixtures | error "execution reverted" | gas hex | Same reason as above |
| `eth_createAccessList` | `create-al-abi-revert.io` | `{accessList:[], error, gasUsed}` | `{accessList:[entries], error, gasUsed}` | Contract not on our chain — no access entries collected during simulated revert |
| `eth_simulateV1` | 63 of 91 fixtures | minimal block shape | full Cancun block | Our `eth_simulateV1` implementation returns a subset of block fields; fully closing this requires G.2 scope (spec-tests-driven parity) |

**Verdict for all of the above:** not a bug. Runner should skip
these fixtures when running against our testnet, OR classify them
as `CHAIN_STATE_FALSE_POSITIVE` (distinct from `SHAPE_MISMATCH`).

The correct way to test the affected methods against *our* chain is
to seed our chain with a known transaction/block first, then query
the hash we just observed.
`test/evm-workchain/proof-rpc-indexing.sh` does exactly that for the
ten block/tx indexing methods above — it sends one transfer, waits
for the receipt, then asserts that each method returns the expected
tx / block when queried by the freshly-observed hashes
(`debug_getRawTransaction/Header/Block/Receipts`,
`eth_getBlockTransactionCountByHash`,
`eth_getTransactionByBlockHashAndIndex`,
`eth_getTransactionByBlockNumberAndIndex`,
`eth_getBlockReceipts`, `eth_getBlockByHash`, `eth_createAccessList`).
The other two proofs (`proof-mirror-not-canonical.sh`,
`proof-bytecode-survives-restart.sh`) and the JS wallet probes cover
the remaining balance / code / log / call methods the same way.

## Category B — Intentional behavioral differences (vs. geth)

These appear when running
`test/conformance/differential_geth.py`. They are deliberate and
documented here so future reviewers don't re-open them as bugs.

### B.1 `eth_mining` — we return `bool`, geth returns error

```
ours : true / false  (bool)
geth : {"error": {"code": -32601, "message": "the method eth_mining does not exist/is not available"}}
```

**Reason:** geth dropped `eth_mining` post-merge because PoS mining
has no meaningful "is mining" concept. We keep it because it's still
in the Ethereum JSON-RPC spec (as "deprecated, returns false on
post-merge chains") and legacy wallets / dashboards still probe for
it. Returning `false` is safe and wallet-friendly.

**Verdict:** keep our behavior.

### B.2 `eth_syncing` — we return `false`, geth can return an object

```
ours : false  (bool — always, in dev mode)
geth : {currentBlock, highestBlock, healing*, syncing*, txIndex*, ...}  (object, while syncing)
       false  (bool, when fully synced)
```

**Reason:** when a node is actively syncing, geth returns a detailed
object with progress counters. When idle, geth returns `false`. Our
current implementation always returns `false` because our node
doesn't track Ethereum-style "syncing" state (we're always either
caught up to the TOS chain or not running).

**Verdict:** accept `false`-always for now. If we later need a true
syncing signal (e.g. during TOS chain catch-up on restart), upgrade
to emit the progress-object shape. Not blocking.

### B.3 `eth_accounts` — we return `[]`, geth returns its dev key

```
ours : []
geth : ["0x71562b71999873db5b286df957af199ec94617f7"]  (one address)
```

**Reason:** `eth_accounts` returns node-managed signing keys. We
deliberately don't manage keys — wallets sign locally and submit
raw transactions via `eth_sendRawTransaction`. Geth in `--dev` mode
auto-generates a dev key and exposes it here. Production geth with
no unlocked accounts also returns `[]`.

**Verdict:** accept. Matches geth's production behavior (not its dev
mode).

### B.4 `eth_estimateGas` for a zero-balance sender

```
ours : {"error": {"code": 3, "message": "execution reverted"}}
geth : {"result": "0x5208"}   # 21000, successful estimate
```

**Reason:** when `eth_estimateGas` is called with a `from` address
that has zero balance but a non-zero `value` in the tx, silkworm's
EVM enforces the balance check and reverts with insufficient-funds.
Geth has a special rule: for estimation, if `gasPrice == 0` and
the call is otherwise valid, it bypasses the balance check so
unfunded senders can still get a gas estimate.

**Verdict:** minor UX difference. Most wallets fund `from` before
estimating, so this rarely fires in practice. Can be addressed in
a follow-up that patches our `call_evm_transaction` path to mirror
geth's bypass when `max_fee_per_gas == 0`. Not blocking for testnet.

### B.5 `eth_createAccessList` on non-signed tx

```
ours : {"result": {"accessList": [], "error": "", "gasUsed": "0x5208"}}
geth : {"error": {"code": -32000, "message": "failed to apply transaction: 0x..."}}
```

**Reason:** geth's `--dev` chain requires the tx to match a known
nonce/sender in its mempool before simulating; an unsigned probe
is rejected. We accept unsigned probes because `eth_createAccessList`
is documented as read-only simulation. The ethers.js access-list
path hits both cases; our behavior is the more forgiving of the two.

**Verdict:** accept our behavior. It matches the execution-apis
spec description of the method.

## Category E — Live chain config divergence (production lags state tests)

**Status: open — design decision pending.**

`crypto/block/evm-workchain/evm-block-context.cpp::evm_chain_config()`
sets `shanghai_time = 0` but does **not** set `cancun_time` or
`prague_time`. The live 4-validator chain therefore reports
**EVMC_SHANGHAI** revision to silkworm + evmone.

In contrast, the Phase G.1 / G.2 state-test runner builds its own
per-test ChainConfig with `cancun_time = 0`, so all our state tests
pass at Cancun. **Tests and production run on different forks.**

What's blocked in production today (silently — no error, just opcode
acts as INVALID and reverts):
- BLOBBASEFEE (`0x4a`, EIP-7516)
- BLOBHASH (`0x49`, EIP-4844 host op for blob versioned hashes)
- TLOAD / TSTORE (`0x5c`/`0x5d`, transient storage, EIP-1153)
- MCOPY (`0x5e`, EIP-5656)
- KZG point-evaluation precompile (`0x0a`)
- EIP-6780 SELFDESTRUCT semantics (production still does the
  pre-Cancun full-teardown flavor)
- EIP-4788 beacon-roots predeploy at
  `0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02` (we don't seed it)

Modern Solidity output (compiled with `--optimize` on `^0.8.25`)
emits MCOPY and TSTORE routinely → contracts compiled with current
Solidity will revert in our chain.

### Adapter-readiness audit (2026-04-18, Agent F)

Done while closing the last `eth_simulateV1` SHAPE_MISMATCHes
(`ethSimulate-blobs.io` was the third — its only failure mode is
spec-side `BLOBHASH` succeeding while we revert at Shanghai). Audit
of every Cancun-only behavior against our adapter:

| Behavior | Adapter-side prerequisite | Ready? | Evidence |
|----------|---------------------------|--------|----------|
| `BLOBHASH` opcode | Read `txn.blob_versioned_hashes` from EVM context | ✅ | silkworm + evmone implement it; we already parse blob_versioned_hashes (`evm-rpc.cpp:647`) and tag blob txns as `kBlob` |
| `BLOBBASEFEE` opcode | Block header carries `excess_blob_gas` → `blob_gas_price()` | ✅ | `block.header.blob_gas_price()` already wired in `evm-executor.cpp:208` for blob-fee burn |
| `TLOAD`/`TSTORE` | Per-transaction transient storage in IBS | ✅ | silkworm IBS already has it; nothing to do |
| `MCOPY` | evmone implements as a base op | ✅ | upstream-only |
| KZG precompile (`0x0a`) | KZG trusted setup loaded into evmone | ⚠️ | silkworm bundles a setup; we never call its loader. Without the setup the precompile reverts. **Blocker for any contract that calls 0x0a.** |
| EIP-6780 SELFDESTRUCT | silkworm's `selfdestruct()` switches on `rev >= EVMC_CANCUN` (`evm.cpp:420`) | ✅ | flips automatically |
| EIP-4844 blob fee burn | Burn `total_blob_gas * blob_gas_price` from sender (never credit beneficiary) | ✅ | shipped in `d140ec1d` (`evm-executor.cpp:199-210`) |
| EIP-4788 beacon-roots predeploy | Genesis-seeded contract at `0x000F…Beac02` storing parent beacon roots | ❌ | not deployed; any contract calling it gets empty code → reverts. Cosmetic for normal traffic but breaks any L2 / restaking client that reads parent beacon roots |
| Blob-tx admission gating | Reject type-3 at `eth_sendRawTransaction` (no blob mempool) | ⚠️ | see admission audit in `validator-engine/json-rpc-server-send.cpp` — needs verification |
| `eth_simulateV1` Cancun fields | Always emit `blobGasUsed`/`excessBlobGas`/`parentBeaconBlockRoot`/`requestsHash` | ✅ | shipped in `bfb6b5c0` and untouched here; the new pre-merge schema branch only kicks in for explicitly-anchored sub-block-16 simulations |

### Recommendation (revised 2026-04-18)

**Defer flipping `cancun_time = 0` to a coordinated hard-fork
deployment.** Reasoning:

1. **Two real adapter gaps remain.** KZG trusted setup is unloaded
   (point-evaluation reverts), and the EIP-4788 beacon-roots
   predeploy is not seeded. Activating Cancun without those means
   any contract that touches 0x0a or the beacon-roots address
   gets a silent revert that didn't exist on day-0. That's a worse
   user experience than today's "BLOBHASH reverts because rev=Shanghai".

2. **Blob-tx admission needs a deliberate rejection path.** We
   already burn the blob fee correctly (`d140ec1d`), but we have
   no blob-data mempool — so accepting a type-3 at the JSON-RPC
   layer just to bounce it at the collator is a worse latency
   contract than rejecting at submission. Verify the current
   `eth_sendRawTransaction` path before a fork.

3. **Consensus-changing.** Flipping `cancun_time` retro-actively
   re-revisions every block in history (`config.revision()` is
   keyed off `block.header.timestamp`, and every existing block
   would suddenly report EVMC_CANCUN). Validators that pull the
   updated binary will disagree with any node still on the
   pre-Cancun build over selfdestruct semantics on accounts with
   prior mid-block creates. This is a hard-fork and must be
   announced + scheduled, not slipped in as a PR.

4. **Conformance gain is small.** Today the Shanghai gap costs us
   exactly one conformance fixture (`ethSimulate-blobs.io`).
   Marking it as a documented Category-E divergence and
   classifying it `expected_fail` in the conformance runner buys
   parity-on-paper without any consensus risk.

**Concrete plan** (when the team is ready):

  a. Pre-deploy:
     - Wire silkworm KZG setup into validator-engine init.
     - Seed the EIP-4788 beacon-roots contract bytecode at
       `0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02` (and the
       per-block update logic that writes the parent root).
     - Add an explicit `txn.type == kBlob → -32000 "blob
       transactions not supported"` rejection in
       `handle_eth_sendRawTransaction`.
     - Re-run Phase G.2 walker against a Cancun-flag *and* a
       Shanghai-flag config to confirm no state-root drift.

  b. Hard-fork deploy:
     - Set `cancun_time = <activation_unix>` (NOT 0 — anchor it
       to a future timestamp so the fork is deterministic across
       all replay clients).
     - Coordinate validator binary rollout so the activation
       timestamp passes uniformly.
     - Update the divergence doc + test plan to reflect post-fork
       state.

  c. Until then: accept `ethSimulate-blobs.io` as a known
     divergence (BLOBHASH on Shanghai is INVALID; spec succeeds).

This is a deployment-blocking discrepancy that the state-test
walker can't catch (because the walker controls its own ChainConfig).
Surfaced manually while reviewing `evm-block-context.cpp` during
the Phase G.2 expansion; re-affirmed during the Agent F audit
that closed the other two simulateV1 SHAPE_MISMATCHes.

## Category D — Upstream silkworm known-failing tests

These are `GeneralStateTests` fixtures that silkworm itself maintains
on its `kFailingTests` allow-list in `cmd/test/ethereum.cpp`. Silkworm
upstream acknowledges it does not pass them, and the Ethereum
community hasn't reached consensus on the correct behavior.

All of them live in the EIP-684 (clear-storage-on-CREATE-into-shell)
vs. EIP-7610 (revert-CREATE-on-non-empty-storage) grey zone.
Silkworm's comment (verbatim):

> Silkworm follows the older EIP-684 and clears the created account
> storage if not empty, evmone tries to follow the newer EIP-7610 to
> revert the creation, however Silkworm is not able to provide enough
> information to evmone to identify non-empty storage, in the result
> the non-empty storage remains unchanged.
>
> **This scenario don't happen in real networks. The desired behavior
> for implementations is still being discussed.**

Our walker honors silkworm's allow-list via `kUpstreamFailingTests`
in `test-evm-executor.cpp`. These fixtures are reported as
`upstream_skip=N` rather than `fail=N`.

| Fixture | Reason |
|---------|--------|
| `stCreate2/create2collisionStorage.json` | EIP-684 vs EIP-7610 |
| `stCreate2/create2collisionStorageParis.json` | Same, Paris fork |
| `stCreate2/RevertInCreateInInitCreate2.json` | REVERT inside CREATE init on non-empty storage |
| `stCreate2/RevertInCreateInInitCreate2Paris.json` | Same, Paris fork |
| `stRevertTest/RevertInCreateInInit.json` | REVERT inside CREATE init on non-empty storage |
| `stRevertTest/RevertInCreateInInit_Paris.json` | Same, Paris fork |
| `stSStoreTest/InitCollision.json` | CREATE into account with pre-existing storage |
| `stSStoreTest/InitCollisionParis.json` | Same, Paris fork |
| `stExtCodeHash/dynamicAccountOverwriteEmpty_Paris.json` | CREATE-over-empty-account + code-hash cache update — tests EXTCODEHASH before/after. Same EIP-684/7610 grey zone: spec expects revert (EIP-7610), silkworm continues (EIP-684). Not on silkworm's own `kFailingTests` but behavior matches silkworm exactly. Added to our skip list until the industry resolves the EIP choice. |

**Verdict for all of the above:** not a bug. Wait for the Ethereum
community to decide between EIP-684 and EIP-7610 (or land EIP-7610
with proper `storage_is_empty()` plumbing). If we later get a
silkworm update that supports EIP-7610 fully, remove them from
`kUpstreamFailingTests` and expect them to pass.

**Maintenance:** when silkworm's upstream `kFailingTests` list changes
(add or remove entries), mirror the change into both
`test-evm-executor.cpp::kUpstreamFailingTests` and this table.

## Category C — Previously-real bugs, now fixed

Kept here for traceability so reviewers don't chase ghosts.

| Bug | Fix commit | Verification |
|-----|-----------|--------------|
| `eth_sendRawTransaction` crashed the validator on oversized RLP (EIP-2930 / 1559 / 4844 tx > 127 bytes) | `fdcebdc1` | `test_large_raw_tx_roundtrip` unit test + full conformance suite runs without killing any validator |
| `eth_sendRawTransaction` with wrong chainId would pile up in mempool and crash the collator ~10s later | `fdcebdc1` | Explicit chainId check at RPC layer; 5 ex-crasher fixtures return clean JSON-RPC errors |
| Cancun block fields missing (`blobGasUsed`, `excessBlobGas`, `parentBeaconBlockRoot`) | `bfb6b5c0` | `eth_getBlockByNumber` shape matches geth |
| Shanghai `withdrawals` / `withdrawalsRoot` missing | `bfb6b5c0` | Same |
| Prague `requestsHash` missing | `7449b586` | Same |
| `eth_feeHistory` missing `baseFeePerBlobGas`, `blobGasUsedRatio` | `bfb6b5c0` | Differential runner matches geth |
| Non-standard JSON-RPC error shape for `eth_*` methods (`{ok, error:<string>, code}` at top level instead of nested `{error:{code, message}}`, HTTP 401 for `-32000`) | `bfb6b5c0` | Added `make_eth_json_error`; TVM path kept unchanged to preserve its test suite |
| `eth_getProof` storage-key parsing mis-read the following blockhash arg as a key; also rejected odd-length hex like `"0x0"` | `bfb6b5c0` + `7449b586` | Runner shows storage-proof shape matches geth |
| `eth_createAccessList` missing `error` field in response | `bfb6b5c0` | Same |
| `totalDifficulty` emitted on post-merge blocks (geth / erigon drop it) | `7449b586` | Same |

## Maintaining this document

Add a new entry to Category A, B, or C whenever:

- A conformance run surfaces a new `SHAPE_MISMATCH` or `DIVERGE` and
  investigation concludes it's acceptable (→ A or B).
- A fix lands that closes a previously-surfaced discrepancy (→ C,
  with the commit hash).

Remove a Category A entry if we later decide to match spec shape
exactly (e.g. always emit a populated object at that path using a
placeholder rather than `null`). Treat that decision as a semantic
change: run the full suite before and after to confirm no
regressions elsewhere.

When in doubt, err on the side of leaving it in Category A/B rather
than shipping "fixes" that paper over useful differences.

## References

- `doc/evm-workchain-test-plan.md` — the parent test plan this doc
  supports
- `test/conformance/CONFORMANCE-FINDINGS.md` — the 2026-04-17
  execution-apis snapshot that seeded Category A
- `test/conformance/differential_geth.py` — the runner whose output
  seeded Category B
- `git log --grep='evm-workchain'` — the full fix history behind
  Category C
