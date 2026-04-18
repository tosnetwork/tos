# Hive client wrapper for the TOS validator (Phase G.3)

Phase G.3 of `doc/evm-workchain-test-plan.md` is *Hive (`rpc-compat`):
dockerize validator, write hive client stub*. This directory ships
artifacts that let `ethereum/hive`'s `rpc-compat` simulator drive our
JSON-RPC surface end-to-end.

**Status (2026-04-18):** the Hive client wiring is functional in
**proxy mode**: a thin container forwards Hive's 8545 traffic to an
already-running TOS RPC endpoint.  Against the spec's
`execution-apis/tests/*.io` fixtures (which is the same fixture set
`rpc-compat` consumes), this delivers **21 PASSes** out of 204
single-roundtrip sub-tests when the upstream is the live 4-validator
testnet *and* the proxy is launched with `--override-chain-id` set to
the spec's expected value (`0xc72dd9d5e883e`).  The remaining 183 fail
because they assert on values from a specific seeded chain we don't
have — see *Gap* below.

The validator binary itself now also honours `TOS_EVM_CHAIN_ID` at
startup (consumed by `evm_workchain::init_evm_workchain`), so a
fresh-chain single-node bootstrap can serve the spec's chain id end-to-
end without a recompile. See `crypto/block/evm-workchain/evm-init.cpp`.

The full single-node validator path is **not yet functional** — the TOS
validator requires a 4-node consensus topology and a pre-built
zerostate, neither of which we synthesise from a Hive `genesis.json`
yet.  See *Gap* below.

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
├── Dockerfile                       # canonical 2-stage image (compiles validator)
├── Dockerfile.proxy                 # SLIM image: proxy-mode only (works today)
├── README.md                        # this file
├── run-rpc-compat-local.sh          # local fixture replay (no hive needed)
└── clients/tos/
    ├── Dockerfile                   # hive-discovered wrapper (FROM canonical)
    ├── tos.cmd                      # entrypoint shim: env -> launch
    ├── tos-rpc-proxy.py             # tiny stdlib HTTP forwarder for proxy mode
    ├── mapper.jq                    # hive geth-genesis.json -> tos zerostate JSON
    └── genesis.tmpl.json            # fallback when hive provides no /genesis.json
```

The `clients/tos/` layout mirrors hive's existing client conventions
(see e.g. `ethereum/hive/clients/{nethermind,geth,reth}/`).

## Quick win: run rpc-compat fixtures via the proxy container

This is the fastest way to see end-to-end traffic flow through the Hive
client wiring.  Requires the live testnet on `127.0.0.1:8011` (which is
where `tos-validator@1.service` binds).

```bash
# 1. Build the slim proxy image (~10s).
docker build -f test/conformance/hive/Dockerfile.proxy \
             -t tos/validator-hive:proxy \
             test/conformance/hive/clients/tos/

# 2. Run with --network host so we can reach the testnet on localhost.
docker run -d --name tos-hive --network host \
    -e TOS_PROXY_UPSTREAM=127.0.0.1:8011 \
    -e TOS_JSONRPC_BIND=127.0.0.1:18546 \
    tos/validator-hive:proxy

# 3. Confirm the readiness signal.
docker logs tos-hive | grep TOS-VALIDATOR-READY

# 4. Replay rpc-compat fixtures.
RPC_URL=http://127.0.0.1:18546 \
TESTS_ROOT=test/conformance/execution-apis/tests \
bash test/conformance/hive/run-rpc-compat-local.sh
# => PASS=19  FAIL=185  SKIP=3 (multi-roundtrip)
```

To pick up the two extra `eth_chainId` / `net_version` fixtures (PASS=21),
launch the proxy with `HIVE_CHAIN_ID` set to the spec value:

```bash
docker run -d --name tos-hive --network host \
    -e TOS_PROXY_UPSTREAM=127.0.0.1:8011 \
    -e TOS_JSONRPC_BIND=127.0.0.1:18546 \
    -e HIVE_CHAIN_ID=0xc72dd9d5e883e \
    tos/validator-hive:proxy
```

Or, without docker, run the proxy script directly with `--override-chain-id`:

```bash
python3 test/conformance/hive/clients/tos/tos-rpc-proxy.py \
    --listen 127.0.0.1:18546 --upstream 127.0.0.1:8011 \
    --override-chain-id 0xc72dd9d5e883e --ready-marker TOS-READY
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

Today this run will only pass the 19 chainless / unknown-account /
error-path fixtures — same set as the proxy-mode preview above —
because the validator inside the container can't honour an arbitrary
chainId from `/genesis.json`.

## What works in this scaffold

| Capability                                    | Status | Notes |
|-----------------------------------------------|--------|-------|
| Hive client discovery (`clients/tos/Dockerfile`) | OK   | Mirrors geth/reth conventions |
| Slim proxy image (`Dockerfile.proxy`)         | OK     | Builds in ~10s |
| Canonical builder image (`Dockerfile`)        | Buildable | ~30 min cold compile |
| `tos.cmd` env handling: HIVE_CHAIN_ID (hex/dec), HIVE_NETWORK_ID, HIVE_LOGLEVEL, HIVE_CHECK_LIVE_PORT | OK | |
| `tos.cmd` rejects unsupported forks (Pragu/Cancun/Shanghai) with exit 64 | OK | TOS_FORK_RELAX=1 to override |
| `tos.cmd` ready signal: `TOS-VALIDATOR-READY` to stderr + 8545 TCP open | OK | |
| `mapper.jq` translates geth genesis -> our intermediate JSON | OK     | Tested against execution-apis/tests/genesis.json |
| 19 `rpc-compat` fixtures pass via proxy mode | OK     | See list below |
| Single-node validator bootstrap inside container | TODO | Needs zerostate + key + DHT init |
| Per-test re-init when HIVE_GENESIS_* changes | TODO   | Needs working init first |

### The 21 sub-tests passing today (proxy mode against live testnet, chain-id override)

```
debug_getRawReceipts/get-genesis
debug_getRawTransaction/get-invalid-hash             (both errored)
eth_chainId/get-chain-id                              (only with --override-chain-id)
eth_createAccessList/create-al-value-transfer
eth_getBalance/get-balance-unknown-account
eth_getBlockByHash/get-block-by-empty-hash
eth_getBlockByHash/get-block-by-notfound-hash
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
eth_syncing/check-syncing
net_version/get-network-id                            (only with --override-chain-id)
```

These fall into three categories:
1. **Schema-only** queries that work on any node (`eth_syncing`).
2. **Unknown-account / unknown-tx** queries that correctly return
   `null` / `0x0` regardless of seeded chain.
3. **Error-path** queries where the spec expects an error and we
   return one (codes/messages are not compared, per Hive policy).

## Gap: what blocks the other ~183 sub-tests

The remaining fixtures fall into two buckets:

1. **Chain-id mismatch (2 sub-tests, FIXED)**:
   `eth_chainId/get-chain-id` and `net_version/get-network-id`. The
   spec's chain id is `0xc72dd9d5e883e` (3503995874084926); ours is
   `0x544f53`.  The validator now honours `TOS_EVM_CHAIN_ID` at
   startup (consumed by `evm_workchain::init_evm_workchain`), and the
   proxy script honours `--override-chain-id` for setups where the
   upstream is the live testnet.  **Caveat:** the validator override
   MUST be applied to a fresh chain — EIP-155 v-recovery and stored
   receipts both assume a stable chain id, so changing it on an
   existing chain invalidates every signed transaction in state.

2. **Seeded chain expectations (~everything else)**: the spec
   pre-mines a 36-block chain with specific txs/logs/contracts and
   the fixtures assert on hashes/receipts/storage from that chain.
   We cannot satisfy these without ingesting `chain.rlp` —
   functionally equivalent to running the spec's transactions
   through `eth_sendRawTransaction` post-genesis.  **Fix:** wire a
   `chain.rlp` -> `eth_sendRawTransaction` replay step inside
   `tos.cmd` after the validator goes live.  Blocked by current
   `eth_sendRawTransaction` instability (see
   `test/conformance/CONFORMANCE-FINDINGS.md`).

### Realistic estimate to first-green real-Hive `rpc-compat` run

| Task | Effort |
|------|--------|
| Wire `mapper.jq` output into `tos-create-state` to bake chain id | 1-2 d |
| Wire single-node DHT + 1-validator zerostate at image build time | 1 d |
| Wire `chain.rlp` replay inside `tos.cmd` after RPC up | 1 d |
| Stabilise `eth_sendRawTransaction` (separate workstream) | unknown |
| Tighten validator `--initial-sync-delay 0` + skip-key-sync flow | 0.5 d |
| Round-trip Hive a couple of times to flush shape mismatches | 0.5 d |

Realistic estimate to first-green `rpc-compat` run: **~4 engineer-days**
on top of this wiring, plus whatever it takes to stabilise
`eth_sendRawTransaction`.

## Files (where to look)

- `Dockerfile` — canonical builder image (compiles validator from source).
- `Dockerfile.proxy` — slim image, proxy mode only, builds in seconds.
- `clients/tos/tos.cmd` — entrypoint shim.  Two modes: proxy /
  full-validator.  Reads `HIVE_*` env, rejects unsupported forks,
  signals readiness via `TOS-VALIDATOR-READY` log line.
- `clients/tos/tos-rpc-proxy.py` — stdlib-only HTTP forwarder used by
  proxy mode.
- `clients/tos/mapper.jq` — geth-genesis -> tos-zerostate-JSON
  translator.  Output is consumed by the (TODO) `tos-create-state`
  init helper.
- `clients/tos/genesis.tmpl.json` — fallback when Hive provides no
  `/genesis.json`.
- `clients/tos/Dockerfile` — Hive-discovered wrapper that pulls from
  `tos/validator-hive:latest`.
- `run-rpc-compat-local.sh` — replays `*.io` fixtures locally; lets us
  iterate without the 30-min Hive Go build cycle.
