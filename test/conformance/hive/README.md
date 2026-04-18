# Hive client scaffold for the TOS validator (Phase G.3)

Phase G.3 of `doc/evm-workchain-test-plan.md` is *Hive (`rpc-compat`):
dockerize validator, write hive client stub*. This directory is the
starting point — it produces the artifacts hive needs to launch us as a
client. **It does not run hive.** The simulator must still be invoked by
hand against the resulting image (see *How to run* below).

## Why hive?

Hive is the Ethereum Foundation's containerised end-to-end harness. It
spins clients in Docker, feeds them genesis files, and runs simulators
against them. We care about exactly two of its simulators:

- **`ethereum/rpc-compat`** — exercises every JSON-RPC method against a
  fresh node. This is the only existing third-party check that
  cross-validates our entire RPC surface (eth_*, net_*, web3_*) against
  reference fixtures. Phase G.1/G.2 cover state-transition correctness,
  but not the wire-format / parameter-shape contract that wallets and
  block explorers rely on.
- **`ethereum/sync`** (later) — tests that a fresh node can catch up
  from scratch. Optional for mainnet admission; deferred to Phase G.5+.

Most other hive simulators (`devp2p`, `consensus`, `engine`) assume a
client that speaks devp2p / Engine API. We do neither. Those suites are
**out of scope** for G.3.

## What's in here

```
test/conformance/hive/
├── Dockerfile                       # canonical 2-stage image, exposes :8545
├── README.md                        # this file
└── clients/tos/
    ├── Dockerfile                   # hive-discovered wrapper (FROM canonical)
    ├── tos.cmd                      # entrypoint shim: reads HIVE_* env, launches engine
    ├── mapper.jq                    # hive genesis.json -> tos zerostate seed (STUB)
    └── genesis.tmpl.json            # fallback genesis when hive provides none
```

The `clients/tos/` layout mirrors hive's existing client conventions
(see e.g. `ethereum/hive/clients/{nethermind,geth,reth}/`).

## How to run hive against us (once everything is wired)

Pre-requisites: a built TOS image tagged `tos/validator-hive:latest` —
either from this Dockerfile (slow: 30 min compile inside the container)
or from a host build that is then re-tagged.

```bash
# 1. Build the runtime image from this repo's root.
docker build -t tos/validator-hive:latest \
    -f test/conformance/hive/Dockerfile .

# 2. Clone hive.
git clone https://github.com/ethereum/hive.git
cd hive && go build .

# 3. Tell hive about us. Symlink (or copy) our client dir into hive's tree:
ln -s "$OLDPWD/test/conformance/hive/clients/tos" clients/tos

# 4. Run the rpc-compat simulator.
./hive --client tos --sim ethereum/rpc-compat
```

Results land in `hive/workspace/logs/` as a JSON summary plus per-test
container logs.

## What's still missing (TODOs before rpc-compat will pass)

| Gap | Where | Effort |
|-----|-------|--------|
| `mapper.jq` does not yet drive `tos-create-state` to produce a real binary zerostate; the JSON it emits is passed through but never consumed. | `clients/tos/mapper.jq` + new init helper | 1-2 d |
| `tos.cmd` writes a stub `config.json` and empty `tos-global.json`. The validator will bind 8545 but never produce a tip; only chainless RPCs (`eth_chainId`, `web3_clientVersion`, `net_version`) will answer. A real init step must run `tos-genkey`, `tos-create-state`, and emit a working pair of configs. | `clients/tos/tos.cmd` | 1 d |
| **devp2p shim**: hive's `rpc-compat` injects test transactions via `eth_sendRawTransaction`, so devp2p is *not* required for this simulator — but its `sync` and `consensus` simulators are. Out of scope for G.3. | n/a | DEFERRED |
| Engine API (`engine_*`) is not implemented. `rpc-compat` skips it for non-merge clients, but if hive auto-detects a merge config it will probe; we'd need to return well-formed `METHOD_NOT_FOUND`. | validator JSON-RPC layer | 0.5 d |
| Hive's per-test genesis re-init: hive tears the container down between tests. Our zerostate generation is slow (~10 s); we should bake a deterministic single-validator zerostate at image-build time and only re-init when `HIVE_GENESIS_*` actually differs. | `Dockerfile` + `tos.cmd` cache logic | 0.5 d |
| Wrapper `clients/tos/Dockerfile` references `tos/validator-hive:latest` which hive does not auto-build. Either change hive's invocation to `--docker.buildargs` with a wider context, or document the manual pre-build step (current approach). | `clients/tos/Dockerfile` | 0.25 d |

Realistic estimate to first-green `rpc-compat` run: **~4 engineer-days**
on top of this scaffold (mapper + real init + a couple of round-trips
with hive to flush out shape mismatches).
