# EVM Workchain — RPC integration test scripts

Three test scripts for validating Ethereum JSON-RPC compatibility against a running TOS EVM workchain node.

## Prerequisites

```bash
# 1. A running EVM workchain node (see doc/Validator-Local.md to set up)
# 2. Node.js 18+ (uses the built-in fetch API)
# 3. For full-rpc-test.js only: ethers.js
npm install ethers
```

## Scripts

| Script | What it tests | Tx writes? | Deps |
|--------|--------------|-----------|------|
| `wallet-test.js` | 16 read-only RPC checks (chainId, blockNumber, gasPrice, balance, code, storage, fee history, filters, ...) | No | — |
| `e2e-wallet-test.js` | The exact RPC sequence MetaMask issues during initial connection (14 checks). Falls back to raw RPC if ethers not available | No | optional ethers |
| `full-rpc-test.js` | Full ethers.js end-to-end: chain identity, balance read, signed transfer, receipt, recipient verification, contract interaction, gas estimation. Requires a wc=1 collator producing blocks | **Yes** | ethers (required) |

## Usage

```bash
# Default RPC URL is http://127.0.0.1:8011 — pass another to override
node test/evm-workchain/wallet-test.js
node test/evm-workchain/wallet-test.js http://127.0.0.1:8012

node test/evm-workchain/e2e-wallet-test.js
node test/evm-workchain/full-rpc-test.js
```

## Expected results (live local 4-node testnet)

```
$ node wallet-test.js
  ✓ chainId is 0x544f53
  ✓ blockNumber is a hex number
  ✓ net_version is 5525331
  ✓ web3_clientVersion is evm-workchain/0.1.0
  ✓ ... 16 checks total
  Results: 15 passed, 1 failed
  (the 1 failure is a stale assertion expecting gasPrice = 1 gwei
   but our impl correctly returns base+priority = 2 gwei)

$ node e2e-wallet-test.js
  Results: 14/14 passed
  MetaMask probe sequence: all checks passed.

$ node full-rpc-test.js
  ✓ chainId is 5525331
  ✓ Hardhat #0 balance == 10000 TOS
  ✓ Hardhat #0 nonce >= 0
  ✓ gasPrice > 0
  ✓ blockNumber >= 0
  ✓ block has hash
  ✓ block has stateRoot
  ✓ Hardhat #1 balance >= 10000
  ✓ eth_call to 0x00 returns "0x"
  ✓ estimateGas for transfer ~ 21000
  ✓ eth_getCode for zero address is "0x"
  ✗ signed transfer  ← KNOWN LIMITATION (see below)
  Results: 11 passed, 1 failed
```

## Known limitations

### `full-rpc-test.js` signed transfer fails

**Symptom:** `eth_sendRawTransaction` returns:
```
cannot apply external message to current state :
cannot load block (1,8000000000000000,0): not in db
```

**Cause:** The wc=1 chain genesis block is registered in ConfigParam 12 (via `add-evm-workchain` in `gen-zerostate.fif`) and `evmstate1.boc` is shipped to each validator's `static/` directory. However, no validator is actually running the **wc=1 collator** — the local 4-node testnet only assigns validators to masterchain (`wc=-1`) and basechain (`wc=0`) collation by default.

**Effect:**
- ✅ All read-only RPC works (queries hit `global_evm_state()` directly)
- ✅ Pre-funded test account balances are visible
- ❌ Writes (`eth_sendRawTransaction`) cannot land in a block

**Resolution path:** Add validator-side wc=1 shard assignment. This requires either:
1. Election system support for assigning validators to wc=1 shards (production path), or
2. A local-testnet override that auto-assigns all validators to all registered workchains (dev path).

Tracked as the next milestone after this commit.

### ethers.js batch requests rejected

The current JSON-RPC server returns `422 Unprocessable Entity / "Batch requests are not supported"` for ethers.js's default batched requests. Workaround in `full-rpc-test.js`: pass `{ batchMaxCount: 1, staticNetwork: ... }` to the provider. Real fix is to implement batch support in `validator-engine/json-rpc-server.cpp`.
