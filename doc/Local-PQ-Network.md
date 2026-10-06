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
`state-ttl + archive-ttl` = 8 days, retired consensus databases are never
deleted, and the session statistics file is never rotated. The local network
then needs more than 600 GB and fills a typical development disk in 3–4 days.

The local unit templates therefore pass:

| Option | Effect |
| --- | --- |
| `--state-ttl 3600` | states may be garbage collected after one hour |
| `--archive-ttl 7200` | archived blocks are kept two hours beyond that |
| `--enable-validator-consensus-cleanup` | retired validator consensus databases are deleted once the GC floor proves them obsolete. The engine marks this option as acceptance-only and off by default; on this development network it is deliberately on. |

`setup-testnet.sh` also installs `/etc/logrotate.d/tos-local-session-logs`,
which rotates each node's `session-logs` daily or above 500 MB and keeps three
compressed copies.

A local `ExecStart` override, such as a health-monitoring drop-in, replaces the
template's command line. It must carry the same three options. Verify with
`systemctl show tos-pq-validator@1 -p ExecStart`.

**Garbage collection needs key blocks and a persistent state.** The GC floor
only advances behind the last key block, a validator-set rotation and the last
persistent state, and only for states older than `state-ttl`. A persistent
state is written only at the first key block after each 2^17 s (about 36.4 h)
boundary of Unix time (`ValidatorManager::is_persistent_state`). So on a new
network nothing is collected until it has crossed such a boundary, which takes
up to about 36 hours. Plan for roughly that many hours of full growth, about
7 GB/h for the seven nodes, before usage levels off.

Elections and set changes produce the key blocks. A network whose elections
fail keeps only its Genesis key block and never collects anything, whatever the
TTLs are. The validator logs then show
`VALCLEANUP pass gc_seqno=0 … reserved=0` indefinitely. If `/data` keeps
growing past the first boundary:

- check that elections still complete;
- check that `last_known_key_block_ago` in the node log stays below a few
  election periods;
- check that `VALCLEANUP pass` reports a non-zero `gc_seqno`.

## Controller funding and continuous elections

`--rotate` selects a ten-minute development election profile and adds candidate
node 7. The election driver alternates the four-member sets 1/2/3/7 and 1/2/3/4.
This is different from the default 30-day bootstrap profile above. Keep elections
running on a persistent development network; a bounded rehearsal's shutdown is
not the default and can prevent the key-block progression needed for retention.

A controller needs a root-signed kind-4 operating authorization before forwarding
a stake. A new controller has zero allowance and expiry. A plain balance transfer
does not authorize spending; exit 180 is a shared guard code, not a unique diagnosis.

`setup-testnet.sh --rotate` runs `local-pq-fund-controllers.py` after deployment
and before starting the election service. Setup and the steady-state driver use
the same helper in `local_pq_funding.py`; the driver rechecks selected candidates
before each new round. For all five candidate controllers it:

1. verifies the explicit disposable network and controller birth/code/authority
   identity, deploying the exact StateInit when necessary;
2. reads current authority, operating state and Config20/24 fee parameters;
3. calculates the authorized automatic grant and a 30-day target, renewing at
   the 25% threshold or on missing/mismatched policy;
4. deposits only the deficit, signs using `/usr/local/bin/tos-pq-controller`,
   and confirms the actual controller transaction and exact state transition;
5. separately tops up ordinary capital to funds plus storage floor plus margin.

Defaults are a 30-day funds/allowance target computed as `4320 * current_grant`,
a 20 TOS per-request cap, 10 TOS floor, 20 TOS capital margin and 30-day
sponsorship. They are development policy, not fixed production fees. A policy
renewal can deposit zero; kind 4 adds the deposit to existing funds but replaces
the allowance and policy. Its signature expires after 600 seconds, independently
of sponsorship expiry. Unsupported prices or caps cause a visible failure.

Read-only checks do not require stopping healthy elections:

```bash
sudo env PYTHONPATH=test/tostester/src:scripts .venv/bin/python \
  scripts/local-pq-fund-controllers.py --check
sudo env PYTHONPATH=test/tostester/src:scripts .venv/bin/python \
  scripts/check-local-pq-elections.py
```

`--check` reports a renewal need without signing or writing. The service normally
renews automatically; a manual write requires exclusive ownership of the faucet.
Do not run setup/traffic bootstraps concurrently with the election service.
Any maintenance stop must be followed by a checked restart, not left unnoticed.

The sender records its exact signed request before broadcasting. A restart
reuses the same wallet seqno and reconciles the destination transaction. Per-node
intent records prevent repeated funding of a partially completed round. Do not
delete `faucet-journal/`, `candidate-intent-*.json` or `submitted.json` to force a
retry: first reconcile the saved request and chain state. Unknown outcomes and
deterministic refusals require attention rather than blind new payments.

The development root seeds in `/data/elections/keys/` are deterministic fixtures
and must never control real funds. This automation is not production root custody.

### Diagnose a missing stake confirmation

| Observation | Check and response |
| --- | --- |
| Controller has balance but refuses forwarding | Read the explicit operating authorization, expiry, allowance and per-request limit; ordinary transfers do not authorize spending. |
| `operating_state` reads all zero or expired | The controller has no operating authorization. Run `scripts/local-pq-fund-controllers.py` with the election service stopped. |
| Controller rejects with exit 180 | This is a shared relay guard code, not a unique diagnosis. Inspect the request and exact transaction; check balance against recorded funds plus floor, as well as the other relay preconditions. |
| Pool receives a native bounce after forwarding | Decode the controller compute/action failure and pool bounce transaction. Confirm where principal returned before retrying. A bounce is not an elector acceptance. |
| Election driver reports a confirmation timeout | The signed intent remains unresolved. Inspect the complete transaction path and retained journal; do not infer acceptance or send a new payment. |
| A restart appears to repeat funding | Check that the installed snapshot contains this repair, and preserve the journal. Reconcile exact transaction identities and balances; do not delete records to bypass duplicate protection. |

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
- For a persistent network, keep the election service and its health check
  active. Use `scripts/check-local-pq-elections.py` to surface stale heartbeat,
  expired Config34 and low operating runway. A deliberately bounded disposable
  rehearsal may be stopped, but leaving validators running without continued
  elections is not a safe default retention policy.

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

Keep node health collection running independently of the election
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


### Installed privacy generator independence

The installed traffic generator embeds both the pool gas-ceiling source and the
development verifying-key fixture. Installation validates its `resources`
response under `ProtectHome=true` with source/build roots inaccessible, before
publishing the new snapshot. A failed check preserves the previous `current`.
The existing ELF, symlink and Python search-path checks remain mandatory.

Rebuild the generator after either embedded source changes. When installing without
`--build`, existing artifacts must still match the checkout's exact resource bytes. A successful
resource check or locally generated proof is not on-chain privacy acceptance.
Confirm deposit, transfer and withdrawal through the installed service and its
cross-node checks. See [the repair record](local-pq-network-defects-20261006.md)
for the tested revisions and outstanding acceptance gates.
