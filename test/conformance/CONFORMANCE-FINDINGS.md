# execution-apis Conformance — Findings (2026-04-17)

Ran `ethereum/execution-apis/tests/` (207 `.io` files) against `127.0.0.1:8011`
on a live 4-validator testnet (chainId `0x544f53`). See
`run_execution_apis.py` for the runner; it classifies each response
structurally because we can't value-match the spec's seeded chain state
against ours.

## Headline

- **0 `METHOD_NOT_FOUND`** across all 207 tests — every RPC method the
  spec exercises is wired up on our node. That's a strong baseline.
- **1 critical stability bug**: `eth_sendRawTransaction` with **any** of
  the five spec raw-tx payloads kills `tos-validator@1`
  (`systemctl` exit code 1, no stderr, no FATAL in thread logs). The
  runner skips these by default (`SKIP_CRASHERS=0` to disable).
- **17 methods report `SHAPE_MISMATCH`** on at least one test. Most are
  false positives (`ours=null` when we have no such block/tx — spec
  expected a full object because it pre-seeded its chain). Real schema
  skews are in the "Genuine schema gaps" section below.
- **2 methods report `OUR_ERROR`**: `eth_call` and `eth_estimateGas`,
  both "execution reverted" — the spec expected a reverting call to
  return `result: "0x..."` with the revert data, not an error code.

## Pass / fail matrix

```
METHOD                                             OK  MM  MNF  OUR_ERR  SPEC_ERR  BOTH_ERR  OTHER
debug_getRawBlock                                   0   2    0        0         1         0      0
debug_getRawHeader                                  0   2    0        0         1         0      0
debug_getRawReceipts                                1   1    0        0         1         0      0
debug_getRawTransaction                             0   1    0        0         0         1      0
eth_blobBaseFee                                     1   0    0        0         0         0      0
eth_blockNumber                                     1   0    0        0         0         0      0
eth_call                                            3   0    0        1         2         0      0
eth_chainId                                         1   0    0        0         0         0      0
eth_createAccessList                                1   3    0        0         0         0      0
eth_estimateGas                                     2   0    0        2         2         0      0
eth_feeHistory                                      0   1    0        0         0         0      0
eth_getBalance                                      3   0    0        0         0         0      0
eth_getBlockByHash                                  2   1    0        0         0         0      0
eth_getBlockByNumber                                0  11    0        0         0         0      0
eth_getBlockReceipts                                2   6    0        0         0         0      0
eth_getBlockTransactionCountByHash                  0   2    0        0         0         0      0
eth_getBlockTransactionCountByNumber                2   0    0        0         0         0      0
eth_getCode                                         3   0    0        0         0         0      0
eth_getLogs                                         0   6    0        0         3         0      0
eth_getProof                                        1   2    0        0         0         0      0
eth_getStorageAt                                    2   0    0        0         2         0      0
eth_getStorageValues                                0   0    0        0         0         0      4
eth_getTransactionByBlockHashAndIndex               0   1    0        0         0         0      0
eth_getTransactionByBlockNumberAndIndex             0   1    0        0         0         0      0
eth_getTransactionByHash                            2   7    0        0         0         0      0
eth_getTransactionCount                             3   0    0        0         0         0      0
eth_getTransactionReceipt                           2   7    0        0         0         0      0
eth_sendRawTransaction                              0   0    0        0         0         0      5  ← all SKIPPED_CRASHER
eth_simulateV1                                      0  63    0        0        27         0      1
eth_syncing                                         1   0    0        0         0         0      0
net_version                                         1   0    0        0         0         0      0
testing_buildBlockV1                                0   0    0        0         0         0      3  ← spec-only, not ours
```

Total: 202 tests (after skipping 5 crashers), 0 METHOD_NOT_FOUND.

## Critical: `eth_sendRawTransaction` crashes the validator

Reproducer (after validator@1 is up):

```
curl -sS http://127.0.0.1:8011 -X POST -H 'Content-Type: application/json' -d @- <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":[
"0x01f8cc870c72dd9d5e883e028405763f5883015f90947dcd17433742f4c0ca53122ab541d0ba67fc27df8083010203f85bf859947dcd17433742f4c0ca53122ab541d0ba67fc27dff842a00000000000000000000000000000000000000000000000000000000000000000a0010000000000000000000000000000000000000000000000000000000000000080a0f9dc42e8bab0a70132fb8399cf03cf38e1c12cc47f736d19e6e7728356d97db3a053daf342acd24da15073f5dac02bec0501a0716165984aab2df9694882b91fac"
]}
EOF
```

This is a well-formed EIP-2930 access-list tx with the spec's chainId
`0xc72dd9d5e883e` (not ours). Expected behavior is a polite reject
(chainId mismatch, or nonce gap, or underfunded sender). Observed
behavior: HTTP response closes mid-write, process exits with
status=1/FAILURE ~1 second later, systemd auto-restart kicks in.

No `FATAL` / `CHECK failed` line appears in the thread logs, so the
crash is either `std::terminate()` from an uncaught exception or
`std::exit(1)` from somewhere deep in the ext-msg pool / collator /
silkworm chain validator. All five `eth_sendRawTransaction` .io files
(legacy, EIP-1559, EIP-2930, dynamic-fee, blob) reproduce the crash.

This is a **DoS vector** against anyone who submits a tx with a
chainId other than our own. Must be fixed before any external-facing
deployment.

## Genuine schema gaps

### `eth_getBlockByNumber` / `eth_getBlockByHash` — Cancun / Prague fields missing

Our block response lacks:
- `blobGasUsed`
- `excessBlobGas`
- `parentBeaconBlockRoot`
- `withdrawals` / `withdrawalsRoot` (not tested here but implied)
- `requestsHash` (Prague)

These are optional on pre-Cancun blocks per the OpenRPC schema, but
block-explorer / indexer code often assumes they're always present.
Decision needed: add as always-`"0x0"` / `null`, or keep omitted.

### `eth_feeHistory` — EIP-4844 blob fee fields missing

Our response:
`{baseFeePerGas, gasUsedRatio, oldestBlock, reward}`

Spec adds: `baseFeePerBlobGas`, `blobGasUsedRatio`.

Since we don't do blobs, returning `["0x0", "0x0", …]` arrays matching
`baseFeePerGas` length is trivial and keeps clients happy.

### `eth_createAccessList` — missing `error` field on revert

Spec: `{accessList, error, gasUsed}` when the simulation reverts.
Ours: `{accessList, gasUsed}`.

Add `error:"revert reason"` (or empty string) on non-success.

### `eth_getProof` — `storageProof` element shape

When no storage keys are requested, spec returns `storageProof: []`.
When keys *are* requested, each element should be
`{key, proof:list<str>, value}`. Our shape matches when present, but
one test emits `proof:list[]` (empty, because we have no proof bytes).
Likely our MPT-proof engine returns an empty proof for non-existent
slots — spec wants `list<string>` even when empty.

### `eth_call` / `eth_estimateGas` — revert handling

When a call reverts, the spec returns `{"result":"0xrevert_data"}`
or the eth_estimateGas-specific error format with
`data:"0x..."`. Ours returns a plain error with message
`"execution reverted"`. MetaMask / ethers depend on the `data` field
to show "Transaction will fail because…" UX.

### `gasUsedRatio` element type

Our `eth_feeHistory` returns `gasUsedRatio: [0, 0, …]` (integers);
spec returns floats `[0.0, 0.0, …]`. One-byte fix in the formatter.

### `eth_simulateV1` — returns minimal object

Our result is a list of `{baseFeePerGas, calls, hash, number, timestamp}`;
spec's block object is the full execution-apis block shape (13+ fields).
`eth_simulateV1` responses are supposed to be indistinguishable from
real block RPC responses. Gap is large — fix after the easier items.

## False positives (not our bugs)

Everything where `ours=null` and the spec returned a populated object
is because the spec's test chain has that block/hash/tx and ours
doesn't. These include all `eth_getTransactionByHash`,
`eth_getTransactionReceipt`, `debug_getRawTransaction`,
`eth_getTransactionByBlock*`, `eth_getBlockByHash`, most
`eth_getBlockByNumber` (values diverge), etc. If we replayed the spec's
`chain.rlp` / `genesis.json` on our chain we could do value-match; for
now, shape-match is enough to confirm the method works.

## Methods we don't implement (and probably shouldn't)

- `testing_buildBlockV1` — part of the `testing_*` namespace defined by
  the execution-apis suite for test-harness usage. Not a real
  Ethereum RPC method. Safe to leave unsupported.
- `eth_getStorageValues` — non-standard, ethers proposal. Optional.

## Rerun

```
cd /home/tomi/evm-workchain/test/conformance
python3 run_execution_apis.py        # skips crashers by default
SKIP_CRASHERS=0 python3 run_execution_apis.py   # full suite, crashes node
```

## Update 2026-04-18 — sendRawTransaction crashers fixed; differential vs geth

Re-ran with `SKIP_CRASHERS=0`: the four prior validator-killing payloads
now reject cleanly with `invalid chain id` (`f53c356a` invalid-hex/DoS
hardening + `fdcebdc1` chunked-RLP + chainId reject). The fifth
(`send-blob-tx.io`) still times out on submit but does not crash.

`createAccessList` regression on `value-transfer.io` (was the 1 OK,
now SHAPE_MISMATCH) traced to `bfb6b5c0` always-emitting `error:""` on
success — the spec only includes the field on revert. Fixed in the
followup commit; binary restart deferred to after the in-flight 4h
fuzz soak.

**G.4 differential vs local geth** (`differential_geth.py`, 25 methods):
20/25 OK, 5 minor divergences:
- `eth_mining` — geth dropped (-32601), ours returns `false`. We're
  more spec-compliant; leave alone.
- `eth_syncing` — geth returns rich sync-stats object, ours returns
  bool `false`. Both are spec-allowed; geth's shape is the modern
  convention but our minimal shape is fine for explorers.
- `eth_accounts` — geth returns one dev-mode account, ours returns
  empty array (we never manage user keys). Working as intended.
- `eth_estimateGas` for value transfer from an unfunded sender
  (`{from:0x...01, to:0x...02, value:0x1}`) — geth returns gas estimate,
  ours rejects `execution reverted`. Geth bypasses balance enforcement
  during estimation; we run the real EVM. Real wallet UX gap, not
  consensus. Worth fixing in a follow-up by inflating sender balance
  during the simulation only.
- `eth_createAccessList` for the same payload — same `0x...01` →
  `0x...02` value-transfer case; both diverge differently from each
  other and from spec. Mostly subsumed by the estimateGas fix above.
