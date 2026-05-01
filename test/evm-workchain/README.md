# EVM Workchain — RPC integration test scripts

Six Node.js scripts for validating Ethereum JSON-RPC compatibility against a
running TOS EVM workchain (`wc=1`) node. Cover the read-only wallet probe
sequence, MetaMask connection probe, end-to-end signed transactions,
TOS-native state-commitment / receipt-rebuild invariants, and the
no-MPT regime checks.

## Prerequisites

```bash
# 1. A running EVM workchain node (see doc/Validator-Local.md §"EVM Workchain (Workchain 1)")
# 2. Node.js 18+ (uses the built-in fetch API)
# 3. For scripts that send signed transactions: ethers v6
npm install ethers
```

The local 3-node testnet from `scripts/setup-testnet.sh` exposes one
JSON-RPC endpoint per validator:

| Validator | RPC URL |
|----|----|
| `tos1` | `http://127.0.0.1:8011` |
| `tos2` | `http://127.0.0.1:8012` |
| `tos3` | `http://127.0.0.1:8013` |

Port allocation: `setup-testnet.sh:240` computes `JSONRPC_PORT=8010+i` for
validator `i` and adds `--json-rpc-address 127.0.0.1:$JSONRPC_PORT` to each
`tos-validator@i` systemd unit.

## Scripts

| Script | What it tests | Tx writes? | Default RPC | Deps | Devnet flag |
|--------|--------------|-----------|------|------|-----|
| `wallet-test.js` | 16 read-only RPC checks (chainId, blockNumber, gasPrice, balance, code, storage, fee history, filters, …) | No | `8011` | — | — |
| `e2e-wallet-test.js` | The exact RPC sequence MetaMask issues during initial connection (14 checks). Falls back to raw RPC if ethers not installed | No | `8011` | optional ethers | — |
| `full-rpc-test.js` | Full ethers.js end-to-end: chain identity, balance read, signed transfer, receipt, recipient verification, contract interaction, gas estimation | **Yes** | `8011` | ethers (required) | required |
| `native-receipt-log-rebuild-test.js` | Two-phase invariant: (pass-1) send tx + capture receipt/logs; (pass-2) re-fetch after receipt-cache rebuild and assert byte-equal canonical reconstruction | **Yes** | `8011` | ethers (required) | required |
| `native-state-root-test.js` | TOS-native state-commitment invariants: `stateRoot` is the cell hash, never the Ethereum empty-trie constant; deterministic across re-reads | No | `8011` | — | — |
| `no-mpt-rpc-test.js` | Verify the no-MPT regime: `eth_getProof` is unconditionally rejected (`-32601`) on every shape; `tos_evmChainInfo` advertises `mpt=false` | No | `8011` | — | — |

The `Devnet flag` column means the script bails out unless the build was
configured with `-DTOS_DEVNET_ALLOW_TEST_EVM_ACCOUNTS=ON` and the env var
`TOS_DEVNET_ALLOW_TEST_EVM_ACCOUNTS=1` is set when running. Those scripts
sign transactions with the canonical Hardhat fixture key
`0xac09…ff80` (account `#0`, listed in `doc/Validator-Local.md:633`); without
the build flag the address has no balance.

## Usage

```bash
# Read-only suite against tos1
node test/evm-workchain/wallet-test.js     http://127.0.0.1:8011
node test/evm-workchain/e2e-wallet-test.js http://127.0.0.1:8011
node test/evm-workchain/native-state-root-test.js
node test/evm-workchain/no-mpt-rpc-test.js

# Tx-writing suite (requires devnet build + env)
TOS_DEVNET_ALLOW_TEST_EVM_ACCOUNTS=1 node test/evm-workchain/full-rpc-test.js
TOS_DEVNET_ALLOW_TEST_EVM_ACCOUNTS=1 node test/evm-workchain/native-receipt-log-rebuild-test.js

# Re-target a different validator
node test/evm-workchain/wallet-test.js http://127.0.0.1:8012
```

`native-receipt-log-rebuild-test.js` also accepts an optional
`TOS_REBUILD_CHECK='{"txHash":"0x…","blockNumber":"0x…","logCount":N}'` env
var to skip pass-1 and verify a previously-captured fixture against a
post-restart cache state.

## Expected results (live local 3-node testnet)

```
$ node wallet-test.js http://127.0.0.1:8011
  ✓ chainId is 0x544f53
  ✓ blockNumber is a hex number
  ✓ net_version is 5525331
  ✓ web3_clientVersion is evm-workchain/0.1.0
  ✓ … 16 checks total
  Results: 15 passed, 1 failed
  (the 1 failure is a stale assertion expecting gasPrice = 1 gwei
   but our impl correctly returns base+priority = 2 gwei)

$ node e2e-wallet-test.js http://127.0.0.1:8011
  Results: 14/14 passed
  MetaMask probe sequence: all checks passed.

$ TOS_DEVNET_ALLOW_TEST_EVM_ACCOUNTS=1 node full-rpc-test.js
  ✓ chainId is 5525331
  ✓ devnet fixture account #0 balance > 0
  ✓ devnet fixture account #0 nonce >= 0
  ✓ gasPrice > 0
  ✓ blockNumber >= 0
  ✓ block has hash
  ✓ block has stateRoot
  ✓ devnet fixture account #1 balance >= 10000
  ✓ eth_call to 0x00 returns "0x"
  ✓ estimateGas for transfer ~ 21000
  ✓ eth_getCode for zero address is "0x"
  ✓ signed transfer landed in block
  Results: 12/12 passed
```

## What changed since the early Phase-B README

The previous version of this README listed three "known limitations". All
three have been resolved in subsequent commits; capturing the current state:

1. **`wc=1` collator assignment.** Earlier versions only collated `wc=-1`
   and `wc=0` so writes had no block to land in. Today every validator
   spawned by `setup-testnet.sh` collates **all four** chains
   (`wc=-1` masterchain, `wc=0` TOS, `wc=1` EVM, `wc=2` UNO)
   simultaneously — the allowlist is open in
   `validator/impl/collator.cpp:160`, and `tostester` symlinks all four
   zerostates into each node's `static/` dir
   (`test/tostester/src/tostester/zerostate.py:557`).
   `eth_sendRawTransaction` now lands in a real block.
2. **JSON-RPC 2.0 batch requests.** Batch is fully supported; the cap is
   `kJsonRpcMaxBatchSize = 100` (`validator-engine/json-rpc-server.cpp:867`)
   matching what ethers `BatchProvider`, web3.js `BatchRequest`, and
   Blockscout catch-up settle on. Oversize batches return `-32600` with
   message `"Batch too large: max 100 requests, got N"`. The
   `batchMaxCount: 1` workaround in `full-rpc-test.js:37` is now belt-and-
   suspenders, not a requirement.
3. **RPC method coverage.** The handler table now dispatches **64** unique
   methods across the `eth_`, `net_`, `web3_`, `debug_`, and `tos_`
   namespaces (`evm/rpc/handlers.cpp`). Highlights beyond the original
   29-method set:
   - `eth_getBlockReceipts`, `eth_blobBaseFee`, `eth_createAccessList`,
     `eth_simulateV1`, `eth_getProof` (rejected — see below),
     `eth_getRawTransactionBy*`, `eth_getUncle*` (always empty by design),
     `eth_subscribe` / `eth_unsubscribe` / `eth_getSubscription`,
     `eth_getFilterLogs`, `eth_getBlockTransactionCountBy*`,
     `eth_getTransactionByBlock*AndIndex`, `eth_protocolVersion`,
     `eth_coinbase`, `eth_hashrate`.
   - `net_listening`, `net_peerCount`; `web3_sha3`.
   - `debug_traceTransaction` and `debug_rebuildRpcCache` are gated by
     `-DTOS_ENABLE_EVM_DEBUG_RPC=ON`. `debug_getRawTransaction`,
     `debug_getRawHeader`, `debug_getRawBlock`, `debug_getRawReceipts`,
     `debug_rpcCacheHealth` are always available.
   - `tos_evmChainInfo` — TOS-specific introspection
     (chainId / workchain / `mpt:false` / `stateCommitment:tos-native-cell-hash`).

## Permanently unsupported methods

| Method | Code | Reason |
|----|----|----|
| `eth_getProof` | `-32601` | TOS EVM uses TOS-native state commitments (cell hashes), not Ethereum MPT proofs. Verified by `no-mpt-rpc-test.js`. |
| `eth_sign` / `eth_signTransaction` / `eth_sendTransaction` | `-32601` | The node holds no user keys. Wallets sign locally and submit via `eth_sendRawTransaction`. |

## Build flags affecting these tests

| CMake option | Default | Effect |
|----|----|----|
| `TOS_DEVNET_ALLOW_TEST_EVM_ACCOUNTS` | `OFF` | Seeds the 10 standard Hardhat fixture accounts (`m/44'/60'/0'/0/N` from `test test test … junk`) at zerostate. Required for any tx-writing script. Production builds must NOT set this. |
| `TOS_ENABLE_EVM_DEBUG_RPC` | `OFF` | Enables `debug_traceTransaction` and `debug_rebuildRpcCache`. Independent of the devnet account seeding. |

## Related infrastructure

- **Setup**: `scripts/setup-testnet.sh` (3-node systemd cluster, all 4
  chains live), `scripts/testnet-ctl.sh` (start/stop/logs).
- **Dev configs to drop into client projects**: `doc/evm-workchain-dev/foundry.toml`,
  `doc/evm-workchain-dev/hardhat.config.js`.
- **Heavier conformance**: `test/conformance/` carries
  `differential_geth.py`, `fuzz_eth.py`, the `hive` runner, and the
  Blockscout pipeline — those depend on the wc=1 collator producing real
  blocks (now true) and on the devnet build flag.
- **Known divergences from upstream EVM**: `doc/evm-workchain-known-divergences.md`.
