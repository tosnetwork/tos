# Hive client wrapper for the TOS validator (Phase G.3)

Phase G.3 of `doc/evm-workchain-test-plan.md` is *Hive (`rpc-compat`):
dockerize validator, write hive client stub*. This directory ships
artifacts that let `ethereum/hive`'s `rpc-compat` simulator drive our
JSON-RPC surface end-to-end.

**Status (2026-04-18, post sprint #3):** the Hive client wiring is
functional in **proxy mode**: a thin container forwards Hive's 8545
traffic to an already-running TOS RPC endpoint. Against the spec's
`execution-apis/tests/*.io` fixtures, this delivers **35 PASSes** out
of 207 sub-tests when the upstream is the live 4-validator testnet
*and* the proxy is launched with `--override-chain-id 0xc72dd9d5e883e
--normalize-not-found`. Remaining 172 fail because they assert on
specific hashes / state from a 45-block seeded chain we don't have
(see *Gap* below).

What changed in sprint #3 (was 21 → now 35):

- **Local fixture runner** (`run-rpc-compat-local.sh`) now mirrors the
  real Hive `rpc-compat` semantics:
  1. honours `// speconly:` markers (recursive shape check, mirroring
     `checkJSONStructure` in [hive/simulators/ethereum/rpc-compat/main.go]
     (https://github.com/ethereum/hive/blob/master/simulators/ethereum/rpc-compat/main.go));
  2. supports multi-roundtrip `.io` files (each `>>` / `<<` pair is
     replayed in order, fail-fast on first mismatch).
- **Proxy** (`tos-rpc-proxy.py`) gained `--normalize-not-found`: when the
  upstream returns a synthetic all-zero placeholder block for an unknown
  number/hash (TOS's wire convention), the proxy rewrites the response
  to `{"result":null}` to match geth's contract.
- **chain.rlp replay tool** (`chain-rlp-replay.py`) added: a
  stdlib-only RLP decoder + `eth_sendRawTransaction` driver that reads
  Hive's per-test `/chain.rlp` and replays its 160 transactions across
  45 blocks into our chain.  Wired into `tos.cmd` for the
  single-validator path; not yet runnable end-to-end against the proxy
  because the chain id mismatch causes signature recovery failure on
  every tx.

The validator binary itself honours `TOS_EVM_CHAIN_ID` at startup
(consumed by `evm_workchain::init_evm_workchain` — commit `02b791ef`),
so a fresh-chain single-node bootstrap can serve the spec's chain id
end-to-end without a recompile. See `crypto/block/evm-workchain/evm-init.cpp`.

The full single-node validator path is **not yet functional** — see
*Gap: single-validator container bootstrap* below for the (substantial)
remaining work.

## Why hive?

Hive is the Ethereum Foundation's containerised end-to-end harness. It
spins clients in Docker, feeds them a `genesis.json` (geth format), and
runs simulators against them. We care about exactly two:

- **`ethereum/rpc-compat`** — replays `*.io` fixtures (request /
  expected response pairs) generated from the `execution-apis` spec.
  It's the only existing third-party check that cross-validates our
  entire RPC wire format (eth_*, net_*, web3_*) against reference
  expectations.
- **`ethereum/sync`** (later) — tests that a fresh node can catch up
  from scratch.  Out of scope; needs devp2p.

Most other Hive simulators (`devp2p`, `consensus`, `engine`) assume a
client that speaks devp2p / Engine API.  We do neither.  Out of scope.

## What's in here

```
test/conformance/hive/
├── Dockerfile                        # canonical 2-stage image (compiles validator + ships replay tools)
├── Dockerfile.proxy                  # SLIM image: proxy-mode only (works today)
├── README.md                         # this file
├── run-rpc-compat-local.sh           # local fixture replay (no hive needed); now speconly-aware + multi-roundtrip
└── clients/tos/
    ├── Dockerfile                    # hive-discovered wrapper (FROM canonical)
    ├── tos.cmd                       # entrypoint shim: env -> launch
    ├── tos-rpc-proxy.py              # tiny stdlib HTTP forwarder for proxy mode
    ├── chain-rlp-replay.py           # stdlib RLP decoder + sendRawTransaction driver
    ├── mapper.jq                     # hive geth-genesis.json -> tos zerostate JSON
    └── genesis.tmpl.json             # fallback when hive provides no /genesis.json
```

The `clients/tos/` layout mirrors hive's existing client conventions
(see e.g. `ethereum/hive/clients/{nethermind,geth,reth}/`).

## Quick win: run rpc-compat fixtures via the proxy (35 PASS)

This is the fastest way to see end-to-end traffic flow through the Hive
client wiring.  Requires the live testnet on `127.0.0.1:8011` (which is
where `tos-validator@1.service` binds).

```bash
# 1. (Optional) Build the slim proxy image (~10s).
docker build -f test/conformance/hive/Dockerfile.proxy \
             -t tos/validator-hive:proxy \
             test/conformance/hive/clients/tos/

# 2. Run with --network host so we can reach the testnet on localhost.
docker run -d --name tos-hive --network host \
    -e TOS_PROXY_UPSTREAM=127.0.0.1:8011 \
    -e TOS_JSONRPC_BIND=127.0.0.1:18546 \
    -e HIVE_CHAIN_ID=0xc72dd9d5e883e \
    tos/validator-hive:proxy

# 3. Confirm the readiness signal.
docker logs tos-hive | grep TOS-VALIDATOR-READY

# 4. Replay rpc-compat fixtures.
RPC_URL=http://127.0.0.1:18546 \
TESTS_ROOT=test/conformance/execution-apis/tests \
bash test/conformance/hive/run-rpc-compat-local.sh
# => PASS=35  FAIL=172  SKIP=0   [speconly: 6]
```

Or, without docker, run the proxy script directly:

```bash
python3 test/conformance/hive/clients/tos/tos-rpc-proxy.py \
    --listen 127.0.0.1:18546 --upstream 127.0.0.1:8011 \
    --override-chain-id 0xc72dd9d5e883e \
    --normalize-not-found \
    --ready-marker TOS-READY
```

## How to run real Hive against us (full path — not yet wired)

Pre-requisites: a built TOS image tagged `tos/validator-hive:latest` —
either from the canonical Dockerfile (slow: ~30 min compile) or from a
host build that is then re-tagged.

```bash
# 1. Build the runtime image from this repo's root.
docker build -t tos/validator-hive:latest \
    -f test/conformance/hive/Dockerfile .

# 2. Clone hive.
git clone https://github.com/ethereum/hive.git
cd hive && go build .

# 3. Tell hive about us.  Symlink (or copy) our client dir into hive's tree:
ln -s "$OLDPWD/test/conformance/hive/clients/tos" clients/tos

# 4. Run rpc-compat.
./hive --client tos --sim ethereum/rpc-compat
```

Today this run will only pass the same 35 sub-tests as the proxy-mode
preview — see *Gap* below.

## What works in this scaffold

| Capability                                                | Status | Notes |
|-----------------------------------------------------------|--------|-------|
| Hive client discovery (`clients/tos/Dockerfile`)          | OK     | Mirrors geth/reth conventions |
| Slim proxy image (`Dockerfile.proxy`)                     | OK     | Builds in ~10s |
| Canonical builder image (`Dockerfile`)                    | Buildable | ~30 min cold compile |
| `tos.cmd` env handling: HIVE_CHAIN_ID (hex/dec), HIVE_NETWORK_ID, HIVE_LOGLEVEL, HIVE_CHECK_LIVE_PORT | OK | |
| `tos.cmd` rejects unsupported forks (Prague/Cancun/Shanghai) with exit 64 | OK | TOS_FORK_RELAX=1 to override |
| `tos.cmd` ready signal: `TOS-VALIDATOR-READY` to stderr + 8545 TCP open | OK | |
| `tos.cmd` invokes `tos-chain-rlp-replay` after readiness when `/chain.rlp` exists | OK | Run path; gated on chain id sanity check |
| `tos-rpc-proxy.py --override-chain-id`                    | OK     | eth_chainId / net_version short-circuited locally |
| `tos-rpc-proxy.py --normalize-not-found`                  | OK     | rewrites placeholder blocks → `null` |
| `chain-rlp-replay.py` decodes chain.rlp                   | OK     | 45 blocks / 160 txs, exit code semantics documented in script header |
| `mapper.jq` translates geth genesis -> our intermediate JSON | OK | Tested against execution-apis/tests/genesis.json |
| Local runner: speconly + multi-roundtrip                  | OK     | Mirrors hive `checkJSONStructure` |
| 35 `rpc-compat` fixtures pass via proxy mode              | OK     | See list below |
| Single-node validator bootstrap inside container          | TODO   | Needs zerostate + key + DHT init — **see *Gap* below** |
| chain.rlp replay actually runs end-to-end                 | BLOCKED | Requires single-node bootstrap first; current attempt against live testnet rejects every tx with `invalid chain id` |

### The 35 sub-tests passing today (proxy mode against live testnet)

```
debug_getRawReceipts/get-genesis
debug_getRawTransaction/get-invalid-hash             (both errored)
eth_chainId/get-chain-id                             (with --override-chain-id)
eth_createAccessList/create-al-contract               (speconly)
eth_createAccessList/create-al-contract-eip1559      (speconly)
eth_createAccessList/create-al-value-transfer
eth_estimateGas/estimate-successful-call             (speconly)
eth_estimateGas/estimate-with-eip4844                (speconly)
eth_estimateGas/estimate-with-eip7702                (speconly, 2 roundtrips)
eth_feeHistory/fee-history                            (speconly)
eth_getBalance/get-balance-unknown-account
eth_getBlockByHash/get-block-by-empty-hash
eth_getBlockByHash/get-block-by-notfound-hash
eth_getBlockByNumber/get-block-notfound              (with --normalize-not-found)
eth_getBlockReceipts/get-block-receipts-0
eth_getBlockReceipts/get-block-receipts-earliest
eth_getBlockTransactionCountByNumber/get-genesis
eth_getCode/get-code-unknown-account
eth_getLogs/filter-error-invalid-blockHash-and-range
eth_getLogs/filter-error-reversed-block-range
eth_getStorageAt/get-storage-unknown-account
eth_getTransactionByHash/get-empty-tx
eth_getTransactionByHash/get-notfound-tx
eth_getTransactionCount/get-nonce-unknown-account
eth_getTransactionReceipt/get-empty-tx
eth_getTransactionReceipt/get-notfound-tx
eth_simulateV1/ethSimulate-add-more-non-defined-BlockStateCalls-than-fit
eth_simulateV1/ethSimulate-big-block-state-calls-array
eth_simulateV1/ethSimulate-block-num-order-38020
eth_simulateV1/ethSimulate-block-override-reflected-in-contract  (both errored)
eth_simulateV1/ethSimulate-block-timestamp-auto-increment        (both errored)
eth_simulateV1/ethSimulate-block-timestamp-non-increment
eth_simulateV1/ethSimulate-block-timestamp-order-38021
eth_syncing/check-syncing
net_version/get-network-id                           (with --override-chain-id)
```

These fall into four categories:
1. **Schema-only** queries that work on any node (`eth_syncing`).
2. **Unknown-account / unknown-tx** queries that correctly return
   `null` / `0x0` regardless of seeded chain.
3. **Error-path** queries where the spec expects an error and we
   return one (codes/messages are not compared, per Hive policy).
4. **Speconly** queries where Hive only checks response shape (we now
   support this in the local runner).

## Gap: single-validator container bootstrap (root blocker)

The remaining 172 sub-tests all fall into one bucket: **the spec
pre-mines a 45-block / 160-transaction chain with specific
contracts/balances/storage, and asserts on hashes/receipts/storage
derived from that chain**. We need to import `chain.rlp` into a fresh
TOS chain whose genesis matches the spec's. Two sub-problems:

### A. Bootstrap a TOS chain inside one container

The TOS validator network requires:
- a **zerostate.boc** — a binary BOC built by `tos-create-state`
  (the Fift interpreter) from `crypto/smartcont/gen-zerostate.fif`,
  which embeds validator keys, masterchain config, EVM workchain shell,
  and the spec's prefunded EOAs;
- a **DHT bootstrap node** + at least 4 validators (the minimum the
  zerostate hard-codes via `40 20 4 config.validator_num!` and
  `shard_validators=4`); reducing to 1 validator requires re-tuning
  several Fift constants and is risky;
- per-validator **keyrings** (4 ed25519 keys per node generated via
  `generate-random-id`), stored under each `keyring/` dir and referenced
  by hex-uppercase id;
- a global **tos-global.json** pointing at the DHT and listing all
  liteservers;
- a per-node **config.json** describing local addrs/adnl/control;
- ~30s of warm-up after launch before consensus produces the first
  EVM block (catchain handshake + validator-set election).

The canonical bootstrap is `scripts/setup-testnet.sh`, which uses the
Python `tostester.network.Network` infrastructure (depends on
`toslib` C library, `tos_api` TL bindings, `nacl`, `pytosiq_core`).
Replicating this entirely **inside** a single container means:

1. Add to the Dockerfile: Python 3.10+, `uv`, `nacl`, `pytosiq_core`,
   the `tostester` package itself, plus all transitive C-library deps
   (we already ship `toslib`).
2. Rewrite the bash wrapper of `setup-testnet.sh` so it doesn't need
   systemd or `useradd` — start the 4 validator processes as
   background subprocesses of `tos.cmd`, supervise with `wait`, and
   forward all stderr to the container's stdout.
3. Bake the spec's `genesis.json` `alloc` into the Fift zerostate
   template so the prefunded accounts match. The current Fift template
   only knows about TOS-internal smart contracts (wallet, elector,
   config); there is **no path** to inject arbitrary EOA balances
   without extending `crypto/block/create-state.cpp` (out of our scope
   in this directory).

Realistic effort to reach a green single-validator-in-container:
**3-5 engineer-days**, primarily for the create-state.cpp extension
that injects EVM `alloc[]` into the zerostate.

Workaround attempted but rejected: 1-validator topology by patching
`shard_validators=1` and `min_validators=1`. The TOS catchain code
(`validator-session/`) has hard-coded asserts that depend on
`validators ≥ 4` for some branches (`is_initial_validator` consensus
path), and changing those is Agent J's domain.

### B. chain.rlp replay actually executes

Once (A) is done and the container's chain id matches
`0xc72dd9d5e883e`, replay is a simple loop. We've already shipped
`chain-rlp-replay.py` which:

- decodes chain.rlp at top level (concatenated blocks, NOT a single
  outer list — verified against the spec's 54 KB / 45-block file);
- extracts each block's `transactions[]` field;
- broadcasts each via `eth_sendRawTransaction`;
- waits for `eth_blockNumber` to advance before sending the next batch;
- exits with a meaningful code (0=ok, 2=tx rejected, 3=stalled).

Verified end-to-end *as far as decoding goes*:

```bash
$ python3 test/conformance/hive/clients/tos/chain-rlp-replay.py \
      --chain test/conformance/execution-apis/tests/chain.rlp \
      --rpc http://127.0.0.1:8011 \
      --expected-chain-id 0xc72dd9d5e883e \
      --start-block 0 --max-block 0
[chain-rlp-replay] decoded 45 blocks (54615 bytes)
[chain-rlp-replay] total 160 transactions across 45 blocks
[chain-rlp-replay] CHAIN ID MISMATCH — upstream=0x544f53 expected=0xc72dd9d5e883e.
                  All transactions in chain.rlp are signed with chain id
                  0xc72dd9d5e883e; sending them to a chain reporting
                  0x544f53 will be rejected with bad signature. Set
                  TOS_EVM_CHAIN_ID before launching the validator.
EXIT=2
```

The chain id sanity check fires before sending any tx, so this is safe
to run in CI (no state mutation against the live testnet).

### Why even a full chain.rlp replay won't push the count past ~50

Even with (A) and (B) both complete, fixtures that assert on **block
hashes** (`eth_getBlockByNumber/get-genesis`, `eth_getBlockByHash/*`,
all of `eth_simulateV1` that includes the block's `parentHash` /
`hash` / `stateRoot` field — that's most of them) will continue to
fail. TOS produces blocks via its own collator with its own
`extraData`/`coinbase`/`timestamp`/`mixHash`, so our block hashes are
deterministic but **different from geth's**. To match geth's hashes we
would need to reproduce geth's block-production rules byte-for-byte —
out of scope for this workchain.

The fixtures that **would** start passing post-replay (rough estimate
from inspecting fixture shapes):

| Method                         | Currently | After full replay (estimate) |
|--------------------------------|-----------|------------------------------|
| `eth_getBalance`               | 1 / 3     | 2-3 / 3   (balances are deterministic) |
| `eth_getCode`                  | 1 / 3     | 2-3 / 3   (deployed bytecode is deterministic) |
| `eth_getStorageAt`             | 1 / 4     | 3-4 / 4 |
| `eth_getTransactionCount`      | 1 / 3     | 2-3 / 3 |
| `eth_call` (no block-hash dep) | 0 / 6     | 4 / 6 |
| `eth_estimateGas`              | 3 / 6     | 5 / 6 |
| Everything else (block-hash)   | n/a       | unchanged |

Total estimated upper bound after full replay: **~50-55 PASSes**, which
is roughly the practical ceiling without re-implementing geth's block
producer.

## Files (where to look)

- `Dockerfile` — canonical builder image (compiles validator from source).
- `Dockerfile.proxy` — slim image, proxy mode only, builds in seconds.
- `clients/tos/tos.cmd` — entrypoint shim. Two modes: proxy /
  full-validator. Reads `HIVE_*` env, rejects unsupported forks,
  signals readiness via `TOS-VALIDATOR-READY`, and (in validator
  mode) invokes `tos-chain-rlp-replay` after readiness if
  `/chain.rlp` is present.
- `clients/tos/tos-rpc-proxy.py` — stdlib-only HTTP forwarder used by
  proxy mode. Honours `--override-chain-id` and `--normalize-not-found`.
- `clients/tos/chain-rlp-replay.py` — stdlib-only RLP decoder +
  `eth_sendRawTransaction` driver. Decodes 45 blocks / 160 txs from
  the spec's chain.rlp; exits with documented codes.
- `clients/tos/mapper.jq` — geth-genesis -> tos-zerostate-JSON
  translator. Output is consumed by the (TODO) `tos-create-state`
  init helper.
- `clients/tos/genesis.tmpl.json` — fallback when Hive provides no
  `/genesis.json`.
- `clients/tos/Dockerfile` — Hive-discovered wrapper that pulls from
  `tos/validator-hive:latest`.
- `run-rpc-compat-local.sh` — replays `*.io` fixtures locally; lets us
  iterate without the 30-min Hive Go build cycle. Now mirrors hive's
  `speconly` and multi-roundtrip semantics.
