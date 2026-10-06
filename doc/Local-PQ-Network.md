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

## Controller funding before election rehearsal

`--rotate` selects a ten-minute development election profile and adds candidate
node 7. The election driver alternates the four-member sets 1/2/3/7 and 1/2/3/4.
This is different from the default 30-day bootstrap profile above.

**The current setup/election scripts do not initialize the controller's explicit
operating authorization.** `setup-testnet.sh --rotate` attempts to start
`tos-pq-elections`; arrange a service start hold before invoking it, and keep
that hold until the following initialization is complete. Starting the chain
or deploying the controller is not sufficient to authorize stake forwarding.
A plain balance transfer does not set the operating allowance.

For each candidate controller:

1. Deploy the current controller code and its exact birth StateInit, with the
   matching code admission in the chain configuration. Retain the birth witness.
   The local development fixtures are generated under `/data/elections/`;
   deterministic fixture keys must never be used for production funds.
2. Read `controller_state` to obtain the current authority epoch and root nonce.
   Do not assume both remain zero after an earlier initialization attempt.
3. Have the operator explicitly choose the deposit, spending allowance,
   per-request limit, storage floor, funding wallet and sponsorship expiry.
   Encode and root-sign action kind 4 using the current SDK/tool:

   ```bash
   cargo build --manifest-path tosctl/src/Cargo.toml -p contracts --locked \
     --example controller_operating_payload
   cmake --build build --target tos-pq-controller

   PAYLOAD_BOC_B64=$(tosctl/src/target/debug/examples/controller_operating_payload \
     "$PAYER" "$DEPOSIT" "$ALLOWANCE" "$PER_REQUEST_LIMIT" \
     "$STORAGE_FLOOR" "$SPONSORSHIP_EXPIRES")
   build/crypto/tos-pq-controller fund-operations \
     "$ROOT_SEED_FILE" "$GLOBAL_ID" "$CONTROLLER_HEX" "$EPOCH" "$NONCE" \
     "$AUTHORIZATION_VALID_UNTIL" "$PAYLOAD_BOC_B64"
   ```

   All amounts are decimal nano-TOS. `CONTROLLER_HEX` is the 256-bit account ID
   without the workchain prefix. The authorization expiry must be in the future
   and no more than 3,600 seconds ahead; it is separate from sponsorship expiry.
   These commands only encode/sign: submit the returned body as an internal
   message from the exact bound `PAYER` wallet, with the deposit plus the current
   required processing fees. Keep the seed private and execute the signer as its
   file owner; do not loosen key permissions to work around a signing error.
4. Read back `operating_state`: funds, allowance, per-request limit, storage
   floor, sponsorship expiry and payer. Verify transaction compute/action
   success and the updated root nonce. A wallet send confirmation alone does
   not prove controller acceptance. Re-read state before retrying; do not
   blindly repeat a deposit after a timeout.
5. Check the account's actual balance **after deployment and funding fees**.
   Before accepting a relay, the controller requires pre-message capital to
   cover its recorded operating funds **plus** the storage floor. Leave a
   separate margin for deployment/storage charges. Depositing exactly 10 TOS
   as initial capital while configuring a 10 TOS floor is insufficient once
   any fees have been charged. Also verify that the unexpired allowance,
   per-request limit and funds cover the current automatic processing budget.
6. Only then release the election service hold and submit a stake. Record the
   query ID and watch the complete pool/controller/elector transaction path.

A tested local setup used an 80 TOS operating deposit, 60 TOS allowance,
20 TOS per-request limit, 10 TOS floor and one-day sponsorship, with a 100 TOS
funding message. A further 20 TOS ordinary capital top-up was needed after the
initial 10 TOS controller deployment. These are **development examples**, not
production fee estimates or mandatory defaults. An ordinary top-up supplies
balance margin; it does not increase the authorized allowance. Size both from
the current chain fee configuration and monitor them independently. Operating
capital belongs to the validator operator; pool principal and unrelated
receipts must not be treated as an operating budget.

### Diagnose a missing stake confirmation

| Observation | Check and response |
| --- | --- |
| Controller has balance but refuses forwarding | Read the explicit operating authorization, expiry, allowance and per-request limit; ordinary transfers do not authorize spending. |
| Controller rejects with exit 180 | This is a shared relay guard code, not a unique diagnosis. Inspect the request and exact transaction; check balance against recorded funds plus floor, as well as the other relay preconditions. |
| Pool receives a native bounce after forwarding | Decode the controller compute/action failure and pool bounce transaction. Confirm where principal returned before retrying. A bounce is not an elector acceptance. |
| Election driver reports a confirmation timeout | The current driver waits for business receipts and may miss a controller rejection/bounce. Pause automatic submission, inspect raw transactions and getters, and do not infer that the stake is lost or accepted. |
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
