# Four-node local PQ network

`scripts/setup-testnet.sh` installs four PQ validators and a separate DHT,
then deploys the shielded pool compiled from this checkout. Consensus uses
ML-DSA-44, ConfigParam 8 is version 18, and ConfigParam 34 contains exactly
the four newly generated PQ identities. No classical validator is installed.

## Initialize

```bash
sudo ./scripts/setup-testnet.sh --build --clean
./scripts/testnet-ctl.sh status
./scripts/testnet-ctl.sh check
```

`--build` builds the native tools and pool generator. Without it, existing
build outputs must be present. `--clean` **deletes all contents of `/data`**,
including the previous keys, databases, wallets and pool state. Without
`--clean`, an existing network is refused before stopping its services.
The installer starts the services and verifies the actual deployment.

This is a local development chain with a funded development wallet and a
**development pool verifying key**. It is not a release Genesis or a pool for
real funds. The initial validator set lasts 30 days; reset the local chain
before expiry or implement the election lifecycle for a longer deployment.

## Services and configuration

| Service | Database | JSON-RPC |
| --- | --- | --- |
| `tos-pq-dht` | `/data/testnet/node0` | — |
| `tos-pq-validator@1` | `/data/testnet/node1` | `127.0.0.1:8011` |
| `tos-pq-validator@2` | `/data/testnet/node2` | `127.0.0.1:8012` |
| `tos-pq-validator@3` | `/data/testnet/node3` | `127.0.0.1:8013` |
| `tos-pq-validator@4` | `/data/testnet/node4` | `127.0.0.1:8014` |

All five units start automatically at boot. Each validator can be restarted
independently, for example `sudo systemctl restart tos-pq-validator@4`.
`testnet-ctl.sh` also supports `start`, `stop`, `restart` and `logs 1..4`.

The exported public configurations are `/data/configs/node-1.json` through
`node-4.json`, the corresponding `node-N-lite.json` files, and `global.json`.
Exact ADNL, lite and console ports are in `/data/testnet-ports.json`.
PQ seeds, keyrings and the development wallet stay in protected directories;
exporting the configuration does not export private keys.

## Shielded pool

`/data/shielded-pool/pool.json` records the address and compiled code/data
identity. `deployment.json` records the observed active account, code hash
and initial getter results. The installer funds the pool with 100 test TOS;
the reserve floor is 50 TOS. It checks both empty roots, zero liability and
that the actual balance covers liability plus reserve.

`testnet-ctl.sh check` verifies increasing common full block IDs on all four
nodes, live version 18, the four provisioned PQ identities, and the pool's
reserve/backing getters. `deploy-pool` resumes an interrupted deployment;
it checks an existing account before sending another deployment.
Pool proofs and withdrawals use the matching development parameters from
`tools/shielded-pool-circuit`; deployment does not claim a withdrawal test.
