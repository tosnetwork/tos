# Local PQ network

`scripts/setup-testnet.sh` installs four PQ validators, two observers and a separate DHT,
then deploys the shielded pool compiled from this checkout. Consensus uses
ML-DSA-44, ConfigParam 8 is version 16, and ConfigParam 34 contains exactly
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
before expiry or use the explicit election rehearsal described below.

## Startup checklist after a reset

A full reset of the local development network, in order:

1. `sudo ./scripts/setup-testnet.sh --clean --rotate` (add `--build` after source
   changes). With `--rotate` it deploys and authorizes the candidate
   controllers and only then starts `tos-pq-elections`; see the next section.
   Do not edit `scripts/setup-testnet.sh` while it runs: bash reads the script
   as it executes, and a changed file makes it run the wrong lines.
2. `./scripts/testnet-ctl.sh status` and `./scripts/testnet-ctl.sh check`: every
   service active, seven nodes on one full block ID.
3. Bootstrap random transfers in a quiet interval of the election service (see
   `scripts/README-local-pq-testnet.md`), then
   `sudo systemctl enable --now tos-pq-transfers`.
4. Confirm the first election: four `stake_accepted` events in
   `sudo journalctl -u tos-pq-elections`, then a new
   `/data/elections/activation-*.json` after the set switches.
5. Rebind health monitoring to the new zero-state (see "Health MCP after a chain
   reset"). Restarting the old monitoring units is not enough; their network ID
   belongs to the previous chain.
6. Watch disk use for the first two hours (next section).

## Disk retention

On this chain a validator writes about 1.4 GB per hour and an observer about
0.4 GB per hour. With the node defaults, block files and archives are kept for
`state-ttl + archive-ttl` = 8 days and retired consensus databases are never
deleted. The local network then needs more than 600 GB and fills a typical
development disk in 3–4 days. The session statistics file needs nothing: the
node rotates it to a single `.old` copy at 256 MiB.

The local unit templates therefore pass:

| Option | Effect |
| --- | --- |
| `--state-ttl 3600` | states may be garbage collected after one hour |
| `--archive-ttl 7200` | archived blocks are kept two hours beyond that |
| `--enable-validator-consensus-cleanup` | retired validator consensus databases are deleted once the GC floor proves them obsolete. The engine marks this option as acceptance-only and off by default; on this development network it is deliberately on. |

A local `ExecStart` override, such as a health-monitoring drop-in, replaces the
template's command line. It must carry the same three options. Verify with
`systemctl show tos-pq-validator@1 -p ExecStart`.

**Garbage collection needs key blocks.** The GC floor advances only while it
is behind the last key block, the last validator-set rotation and the
persistent-state serializer, and only for states older than `state-ttl`. The
serializer walks every masterchain block and normally keeps up. It pauses only
when a key block starts a new 2^17 s (about 36.4 h) period
(`ValidatorManager::is_persistent_state`). Then it waits a random 0–6 h before
writing that persistent state, and the floor cannot pass it in the meantime.

On this network, with a key block every ten-minute election, the floor runs
about `state-ttl` (one hour) behind the head. Usage levels off after the first
few hours: about 29 GB for the seven nodes, measured on 2026-10-06. Expect a
temporary rise of up to six hours of growth, about 7 GB/h, when a persistent
state falls due.

Elections and set changes produce the key blocks. A network whose elections
fail keeps only its Genesis key block and never collects anything, whatever the
TTLs are. The validator logs then show
`VALCLEANUP pass gc_seqno=0 … reserved=0` indefinitely. If `/data` keeps
growing:

- check that elections still complete;
- check that `last_known_key_block_ago` in the node log stays below a few
  election periods;
- check that `VALCLEANUP pass` reports a `gc_seqno` about one hour behind the
  head.

**Short retention removes the early key blocks.** A toslib client that starts
from the zero state proves its way forward through every key block since
Genesis. Once those blocks are collected, every newly started client fails
with `LITE_SERVER_NOTREADY: block handle not in db`. The local drivers
therefore load their lite-client configs through
`local_pq_testnet.lite_config()`, which starts the proof chain at the latest
key block read from a local node. A client started with an unmodified
`/data/configs/node-*-lite.json` fails in the same way. A production client
takes a recent `init_block` from its global config instead.

## Controller funding before election rehearsal

`--rotate` selects a ten-minute development election profile and adds candidate
node 7. The election driver alternates the four-member sets 1/2/3/7 and 1/2/3/4.
This is different from the default 30-day bootstrap profile above.

A controller forwards a stake to the Elector only within an explicit, root-signed
operating authorization (controller action kind 4). A newly deployed controller
has none: `operating_state` reads all zero, and every relay is refused with exit
180. A plain balance transfer does not create an authorization.

`setup-testnet.sh --rotate` therefore runs `scripts/local-pq-fund-controllers.py`
after the network is deployed and **before** it starts `tos-pq-elections`. For
each candidate controller (nodes 1, 2, 3, 4 and 7) the tool:

1. deploys the controller's birth StateInit if the account has no code;
2. reads `controller_state` (authority epoch and root nonce) and
   `operating_state`;
3. renews the authorization when it is missing, expires within seven days, or
   when its funds or allowance have fallen below 25 % of their target. Renewing
   means:
   - encode the kind 4 payload;
   - sign it with `/usr/local/bin/tos-pq-controller fund-operations` using the
     development root seed `/data/elections/keys/root-<i>.seed`;
   - send it from the Genesis wallet, which becomes the bound payer;
4. waits for the root nonce to advance and reads `operating_state` back.
   Recorded funds must equal the old funds plus the deposit exactly, and every
   other field must equal what was signed. Otherwise it stops, and it never
   resends blindly;
5. tops up ordinary capital so the balance covers the recorded funds plus the
   storage floor plus a 20 TOS margin.

The contract **adds** a deposit to the recorded funds and **replaces** every
other field. The tool therefore deposits only the deficit
`funds_target - funds`, which is zero when only the expiry or the allowance
needs renewing, and resets the allowance to its target. It never withdraws
funds above the target.

Defaults: 50,000 TOS funds and allowance targets, 20 TOS per-request limit,
10 TOS floor, 30-day sponsorship. On this profile nodes 1, 2 and 3 relay a stake
every ten-minute round, at about 6.44 TOS each, which is about 930 TOS per
controller per day. The targets therefore outlast the sponsorship. These are
local development values, not production fee estimates. The Python payload encoder is byte-for-byte equal
(same cell hash) to `contracts::validator_controller::operating_funding_payload`.

The tool is idempotent: a healthy controller gets no transaction. Check or
renew authorizations on a running network during a quiet interval. The
election service exclusively owns the Genesis wallet while it runs, so the
tool refuses to send anything while the service is active. Stop it first and
always restart it afterwards:

```bash
sudo env PYTHONPATH=test/tostester/src:scripts .venv/bin/python \
  scripts/local-pq-fund-controllers.py --check     # report only
sudo systemctl stop tos-pq-elections
sudo env PYTHONPATH=test/tostester/src:scripts .venv/bin/python \
  scripts/local-pq-fund-controllers.py             # renew where needed
sudo systemctl start tos-pq-elections
```

Each relay consumes part of the allowance and funds, and the authorization
expires after 30 days. A network that runs longer must re-run the tool before
then. `--check` shows what is left and whether a renewal is due. The development root seeds are
deterministic fixtures and must never control real funds.

### Diagnose a missing stake confirmation

| Observation | Check and response |
| --- | --- |
| Controller has balance but refuses forwarding | Read the explicit operating authorization, expiry, allowance and per-request limit; ordinary transfers do not authorize spending. |
| `operating_state` reads all zero or expired | The controller has no operating authorization. Run `scripts/local-pq-fund-controllers.py` with the election service stopped. |
| Controller rejects with exit 180 | This is a shared relay guard code, not a unique diagnosis. Inspect the request and exact transaction; check balance against recorded funds plus floor, as well as the other relay preconditions. |
| Pool receives a native bounce after forwarding | Decode the controller compute/action failure and pool bounce transaction. Confirm where principal returned before retrying. A bounce is not an elector acceptance. |
| Election driver reports a confirmation timeout | The driver waits for business receipts and may miss a controller rejection/bounce. Pause automatic submission, inspect raw transactions and getters, and do not infer that the stake is lost or accepted. |
| Re-running the driver adds more faucet capital | It funds pools before submission; a retry can add another deposit even when the previous principal returned. Reconcile balances and accepted stake separately. |

Do not disable contract guards to make deployment succeed. Correct missing
initialization or insufficient capital first; investigate unexpected failures
against the exact deployed code hash.

### Verify an actual election, not just submission

- Match the deployed elector/controller/pool code identities to the intended
  build and frozen artifacts.
- Check successful elector receipts for all intended query IDs and the actual
  participant list/accepted amounts.
- Wait for Config34 to activate the intended four-member set. Acceptance alone
  does not prove selection or activation.
- Run `scripts/testnet-ctl.sh check` and verify a common full block ID across
  validators and observers after activation.
- For the local rotation rehearsal, run:

  ```bash
  sudo env PYTHONPATH=test/tostester/src:scripts .venv/bin/python \
    scripts/check-local-pq-relays.py --output /data/elections/relay-verification.json
  ```

  This checks retained traces after the transition grace period, including the
  new member and exclusion of the retired member from current first-hop sets.
- Inspect restarts, compute/action failures and balance/allowance consumption.
  A reserved operating-budget debit is not necessarily the actual gas spent.
- After a bounded rehearsal, stop further automated staking with
  `sudo systemctl disable --now tos-pq-elections`. This leaves node services
  running. Continuing recurring elections requires monitoring and replenishing
  the finite authorized budget; it is not an unattended recovery guarantee.

One successful election does not validate the later unfreeze/withdrawal cycle,
all failure recovery paths, or production costs. Validate those separately.

## Health MCP after a chain reset

A reset creates a new zero-state root and new node process identities. Rebind
monitoring to that root; do not reuse an old manager/query database or report
old retained evidence as current health.

- Start the nodes with their approved `--health-node-id` aliases,
  `--health-core-metrics`, `--health-native-core-v3`, and numeric-loopback
  `--exporter-address` listeners. The initial `/health-snapshot` may be
  unavailable until the scheduled metrics owner has populated its cache.
- Bind each health edge to the running node PID and the new network ID.
  Configure collectors, native pollers and manager/query inventories with
  that same ID. Create separate private control, evidence and query databases.
- Build `tos-observability` with the `mcp` feature. Use a private Unix MCP
  socket, separate operator/service credentials and bounded run grants.
  A listening socket alone is not verification: initialize MCP, discover the
  six tools, read fresh node snapshots, check their network/PID/time/evidence,
  and revoke each observation grant after use. Never print run tokens.
- Apply CPU/memory/storage limits to monitoring services, and validate mTLS
  certificate expiry before enabling continuous collection. See the
  [health deployment guide](../tools/node-health-monitor/deploy/README.md).
- Read `coverage.missing_fields`, per-component quality and incident details.
  `partial` means usable but incomplete coverage, not necessarily a node
  failure; `ok` is not a blanket health verdict. `CACHE_MISS` is missing
  evidence, not a healthy zero. In the current projection, process coverage
  can lack `host_pressure`, `cgroup_effective` and `fd_usage`; native-derived
  chain/consensus/storage responses can inherit `shard_consensus_progress`
  gaps. Storage durability limitations must be read separately.
- Compare samples across the election boundary: new validators should begin
  participating, retired validators should stop current duties, and all nodes
  should continue following the same chain. Short memory samples do not prove
  the absence of a leak or replace a complete trend window.

### Rebinding the local health stack

The local stack lives in `~/.local/state/tos-local-health/<first 12 hex of the
network ID>/`. It has 31 user units (`tos-local-health-*`) and seven system
units (`tos-local-health-edge-<i>`, bound to the validator's PID). To rebind it
after a reset:

1. Take the network ID from the **new** chain:
   `sudo jq -r .zerostate_root /data/network.json`. It must equal the
   `payload.network_id` that a node reports at
   `http://127.0.0.1:901<i>/health-snapshot`. Read it only after
   `setup-testnet.sh` has finished: a value read before the reset belongs to
   the previous chain. The symptom is an edge logging
   `native sample refused: native v3 identity or generation mismatch` every
   minute, with every MCP snapshot at `CACHE_MISS`.
2. Stop the user units and the edges. Create the new directory with copies of
   `bin/`, `pki/`, `config/` and `observe.py`, and empty `control/`,
   `evidence/`, `query/` and `sockets/`, so that no old database is reused.
   Replace the old network ID and directory name in the copied `config/*` and
   in all 38 unit files.
3. `daemon-reload` both managers, start the units, wait about three minutes,
   then run `observe.py` from the new directory. Expected: all seven nodes
   answer, observers `ok` and validators `partial` with the known gaps listed
   above. `host` and `telemetry` answer `CACHE_MISS` on this deployment: no
   collector feeds them, and they did not before the reset either.

The validator restart in a reset stops the edges (`BindsTo=`). Start them again
after `setup-testnet.sh`, even when the network ID does not change.

Keep node health collection running independently of the bounded election
submission driver. Resetting the chain again requires repeating this binding
procedure, not merely restarting the previous monitoring units.

## Services and configuration

| Service | Database | JSON-RPC |
| --- | --- | --- |
| `tos-pq-dht` | `/data/testnet/node0` | — |
| `tos-pq-validator@1` | `/data/testnet/node1` | `127.0.0.1:8011` |
| `tos-pq-validator@2` | `/data/testnet/node2` | `127.0.0.1:8012` |
| `tos-pq-validator@3` | `/data/testnet/node3` | `127.0.0.1:8013` |
| `tos-pq-validator@4` | `/data/testnet/node4` | `127.0.0.1:8014` |
| `tos-pq-observer@5` | `/data/testnet/node5` | `127.0.0.1:8015` |
| `tos-pq-observer@6` | `/data/testnet/node6` | `127.0.0.1:8016` |
| `tos-pq-validator@7` (`--rotate` only) | `/data/testnet/node7` | `127.0.0.1:8017` |

Installed node units are enabled to start automatically at boot. Each validator can be restarted
independently, for example `sudo systemctl restart tos-pq-validator@4`.
`testnet-ctl.sh` also supports `start`, `stop`, `restart` and `logs 1..4`.

The exported public configurations are `/data/configs/node-1.json` through
`node-6.json` (also node 7 with `--rotate`), the corresponding `node-N-lite.json` files, and `global.json`.
Exact ADNL, lite and console ports are in `/data/testnet-ports.json`.
PQ seeds, keyrings and the development wallet stay in protected directories;
exporting the configuration does not export private keys.

## Shielded pool

`/data/shielded-pool/pool.json` records the address and compiled code/data
identity. `deployment.json` records the observed active account, code hash
and initial getter results. The installer funds the pool with 100 test TOS;
the reserve floor is 50 TOS. It checks both empty roots, zero liability and
that the actual balance covers liability plus reserve.

`testnet-ctl.sh check` verifies increasing common full block IDs across the local
nodes, live version 16, the four provisioned PQ identities, and the pool's
reserve/backing getters. `deploy-pool` resumes an interrupted deployment;
it checks an existing account before sending another deployment.
Pool proofs and withdrawals use the matching development parameters from
`tools/shielded-pool-circuit`; deployment does not claim a withdrawal test.
