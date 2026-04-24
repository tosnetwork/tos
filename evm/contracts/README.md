# EToS PoW Giver Solidity Contract

## Overview

`EToSPoWGiver.sol` is the eTOS Proof-of-Work distribution contract deployed on the TOS wc=1 EVM workchain at genesis. It mirrors the logic of TOS `pow-testgiver-code.fc` (TVM/FunC) but implemented in Solidity for the EVM environment.

10 instances are deployed at genesis, each pre-funded with 10 M eTOS. Miners submit keccak-256 PoW solutions to claim 2 eTOS rewards. Difficulty auto-adjusts toward a 12-second solve interval.

See `doc/Mining-Design.md` §"eTOS Mining (wc=1 EVM)" for the full specification.

## Genesis Deployment Addresses

Each giver occupies a deterministic EVM address in the range `0x1000000000000000000000000000000000000001` through `0x100000000000000000000000000000000000000a`:

| Giver | Address |
|---|---|
| 1 | `0x1000000000000000000000000000000000000001` |
| 2 | `0x1000000000000000000000000000000000000002` |
| 3 | `0x1000000000000000000000000000000000000003` |
| 4 | `0x1000000000000000000000000000000000000004` |
| 5 | `0x1000000000000000000000000000000000000005` |
| 6 | `0x1000000000000000000000000000000000000006` |
| 7 | `0x1000000000000000000000000000000000000007` |
| 8 | `0x1000000000000000000000000000000000000008` |
| 9 | `0x1000000000000000000000000000000000000009` |
| 10 | `0x100000000000000000000000000000000000000a` |

Address scheme: `0x10...0N` where N = 1..10 (0x01..0x0a). These addresses are in a range that cannot conflict with standard EVM precompiles (0x01–0x0a) because the prefix `0x10...0` (with 18 zero bytes) is distinct from the precompile range `0x00...0001` through `0x00...000a`.

## Genesis Parameters

| Parameter | Value | Notes |
|---|---|---|
| Balance per giver | 10,000,000 eTOS | = 10_000_000 × 10^18 wei |
| `seed` (slot 0) | `0xdead0N...00` | Per-giver, N = 01..0a in hex |
| `target` (slot 1) | 2^222 | ~1.8e10 hashes/solve at 1.5 GH/s × 12s |
| `lastSuccess` (slot 2) | 0 | Genesis timestamp |
| `targetDelta` (slot 3) | 12 | Seconds between solves |
| `reward` (slot 4) | 2e18 | 2 eTOS in wei |
| `minCpl` (slot 5) | 192 | log2 of minimum target = 2^192 |
| `maxCpl` (slot 6) | 228 | log2 of maximum target = 2^228 |

### Difficulty interpretation

The contract's `target` is the 256-bit keccak hash threshold. A hash `h` is valid iff `uint256(h) < target`. Difficulty in "complexity bits" N means target = 2^(256-N):

| minCpl=192 | target ≥ 2^192 | → max complexity = 64 bits (hardest) |
| maxCpl=228 | target ≤ 2^228 | → min complexity = 28 bits (easiest) |
| initial    | target = 2^222 | → ~34 complexity bits at genesis |

This maps to the Mining-Design.md calibration: `init_cpl = 34` complexity bits at launch (5-10 GPU miners at ~1.5 GH/s).

### Solidity storage layout

Each variable occupies its own 32-byte slot (no packing), making genesis seeding predictable:

| Slot | Variable | Type | Genesis value |
|---|---|---|---|
| 0 | `seed` | `bytes32` | `0xdead0N` + 29 zero bytes |
| 1 | `target` | `uint256` | `0x0000000040...00` (= 2^222) |
| 2 | `lastSuccess` | `uint256` | `0` |
| 3 | `targetDelta` | `uint256` | `0x0c` (= 12) |
| 4 | `reward` | `uint256` | `0x1bc16d674ec80000` (= 2e18) |
| 5 | `minCpl` | `uint256` | `0xc0` (= 192) |
| 6 | `maxCpl` | `uint256` | `0xe4` (= 228) |

## Compilation

### Prerequisites

- Solidity compiler `solc` version 0.8.26 or later.

The binary can be obtained from:
- `solc-bin`: https://github.com/ethereum/solc-bin
- Via `py-solc-x`: `pip install py-solc-x && python3 -c "import solcx; solcx.install_solc('0.8.26')"`
- Package managers: `apt install solc` (Ubuntu), `brew install solc` (macOS)

### Build commands

```bash
# From the evm/contracts/ directory:

# Creation bytecode (for deploy via CREATE, used in tests):
solc --bin --optimize --optimize-runs 200 EToSPoWGiver.sol -o build/

# Runtime bytecode (for genesis seeding via evm-zerostate-from-alloc):
solc --bin-runtime --optimize --optimize-runs 200 EToSPoWGiver.sol -o build_runtime/

# ABI (for miner client integration):
solc --abi --optimize EToSPoWGiver.sol -o build_abi/
```

The compiled runtime bytecode is embedded in `crypto/smartcont/etos-pow-givers.fif` as a hex string constant. If you recompile `EToSPoWGiver.sol`, update the hex literal in `etos-pow-givers.fif` accordingly.

## Genesis Integration

The Fift script `crypto/smartcont/etos-pow-givers.fif` is included by both:

- `crypto/smartcont/gen-zerostate.fif` (mainnet)
- `crypto/smartcont/gen-zerostate-test.fif` (testnet)

It calls the C++ Fift word `evm-zerostate-from-alloc` (registered in `crypto/block/create-state.cpp`) with a 10-entry tuple, each a 5-tuple `(addr, balance, nonce, code, storage)`.

To regenerate the zerostate after contract changes:

```bash
# Recompile
cd /path/to/tos/evm/contracts
solc --bin-runtime --optimize --optimize-runs 200 EToSPoWGiver.sol -o build_runtime/
BYTECODE=$(cat build_runtime/EToSPoWGiver.bin-runtime)

# Update the hex literal in etos-pow-givers.fif:
#   Replace the long string on the line starting '"6080...' with "NEW_BYTECODE" x>B

# Regenerate zerostate
mkdir /tmp/test-genesis && cd /tmp/test-genesis
/path/to/tos/build/crypto/create-state \
  -I /path/to/tos/crypto/fift/lib:/path/to/tos/crypto/smartcont \
  /path/to/tos/crypto/smartcont/gen-zerostate.fif
```

## Miner Client Integration

eTOS reuses standard Ethereum PoW miner software (ethminer, T-Rex, lolMiner) via a stratum adapter. See Task #13 `release-etos-config.yml` for the miner configuration bundle.

### Quick start (ethminer)

```bash
# Point ethminer at the TOS RPC endpoint via stratum adapter:
./stratum-adapter.py --rpc http://<tos-node>:8545 --port 4444 &
ethminer -P stratum://YOUR_ADDRESS@127.0.0.1:4444
```

### Contract ABI (abbreviated)

```json
{
  "mine(uint256 nonce, address whom, uint32 expire, bytes16 rseed, bytes32 rdata1, bytes32 rdata2)": "Submit PoW solution",
  "getMiningParams()": "Returns (seed, target, targetDelta, reward, minCpl, maxCpl, balance)",
  "currentTarget()": "Current 256-bit difficulty target",
  "currentSeed()": "Current anti-replay seed (bytes32)"
}
```

### PoW hash format

```
h = keccak256(abi.encode(
    uint32(0x706f7754),  // "powT" magic
    nonce,               // uint256
    whom,                // address
    expire,              // uint32
    rseed,               // bytes16 (must equal bytes16(currentSeed()))
    rdata1               // bytes32 (must equal rdata2)
))
require(uint256(h) < currentTarget())
```

The seed rotation happens inside `mine()`: `seed = blockhash(block.number - 1)`. Miners must poll `currentSeed()` before each attempt.

### Polling

Miners should poll `getMiningParams()` once per TOS block (~400ms Simplex cadence) to detect seed rotation. The `nextSolveExpected()` view gives the next expected solve timestamp.

## Security Notes

- The `require(ok, "transfer failed")` in `mine()` means failed ETH sends revert the entire tx; miners must use EOA addresses or contracts that accept ETH.
- The `require(address(this).balance >= reward)` check prevents double-spends when the giver runs dry.
- The difficulty clamp `[2^minCpl, 2^maxCpl]` prevents both hash-dust attacks (too easy) and permanent lock-out (too hard) from adversarial mining pace.
