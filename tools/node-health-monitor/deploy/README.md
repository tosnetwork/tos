# Deployment status

These assets are development/review inputs, not an accepted production package.
The existing edge unit requires an operator approval marker. No process in this
package installs, stops or restarts a validator. Effective cgroup, filesystem,
network and failure-domain isolation must be measured on the approved hosts.

## Independent rule authority

`health-state CONFIG_JSON` runs on M. Its control and evidence SQLite databases
must be different files (including symlink/hardlink aliases), in already-created
operator-owned directories. Dedicated bounded writer threads own the respective
connections. Both databases bind a network ID and reject reuse by another network. The five-second control timer precedes queued work; an entire rule
round, incident changes, outbox and evaluation sequence commit together. A full
or unavailable evidence database cannot borrow the control writer. Cached state
and metrics become unavailable if evaluation fails or is over 15 seconds old.
Ingest and state/metrics have independent admission limits; process heartbeat
does not wait for either database. This is not proof against host-wide exhaustion.

`config/health-state.development.json` enables only management reachability and
expected-source availability. Its all-zero network ID and quotas are placeholders,
not discovered production facts. The 22-rule catalog is implemented in Rust, but
most native/host/witness facts still lack real adapters. Do not populate them with
inferred consensus success. Bind a new immutable inventory revision when changing
configuration. Removed active targets remain visible as unknown after restart.

`health-probe CONFIG_JSON` polls the fixed edge heartbeat on a 15-second schedule
and forwards a typed `edge_probe/reachable` fact to M using separate credentials.
This measures the management endpoint only. A malformed/auth-failed response is
unknown. Missed timer ticks are skipped; this process never polls native metrics.
The internal `FactFrame` is a closed fact DTO, not the complete R4 SourceEnvelope.

`health-collector` is a separate archival path. It polls the C02 typed
`/v1/edge/snapshot` and posts that same validated body to
`/v1/manager/snapshot-evidence`; M validates the node/network/epochs again,
then returns references only after each immutable evidence row commits. A
partially committed request returns no accepted receipt; replay deduplicates
the committed rows without changing their original receipt time. This path
does **not** feed the live rule engine or turn unsupported/unknown source
status into a healthy fact. The current C02 snapshot contract admits only
available, timestamped partial sources; unavailable sources are absent and
remain unknown in the rule inventory. Evidence v1 cannot archive a missing
observation timestamp, so such a source is refused rather than invented.

A configured notification receiver must return JSON with `accepted: true`, the
same `idempotency_key`, and the same SHA-256 `payload_hash`. Notification keys are network-scoped hashes; the payload includes the node/scope/rule identity. A plain HTTP 2xx is
insufficient to delete an outbox entry. The production sender requires fixed HTTPS,
private CA and client identity; redirects and proxy settings are disabled. A valid
receiver receipt proves that receiver accepted the payload, not human delivery.

## Fixed mTLS ingress

`health-ingress CONFIG_JSON` is a separately bounded HTTP/1.1 TLS reverse proxy.
It verifies private-CA client certificates, expiry and an explicit leaf SHA-256
allowlist, then authorizes a fixed method/path by role. Certificate rotation needs
an updated reviewed allowlist; never disable verification to rotate. The server
private key must be an owner-only regular file. Authorization is forwarded only
to the configured numeric loopback upstream, never a caller-selected address.

Roles are `edge_reader`, `edge_watchdog`, `manager_ingest`, `manager_reader`, and
`pipeline_sender`. They expose only their listed cache/ingest/heartbeat paths;
control/grant/query routes are not exposed. Query strings, Origin, wrong Host,
unapproved methods, oversized bodies and responses fail closed. The ingress has
bounded TLS/header/request deadlines and per-peer/global rate budgets. A rate token
is reserved for heartbeat traffic; the global TLS connection pool is still shared.
Use an independently restricted observer listener/network path before claiming
complete heartbeat admission isolation under handshake floods. Example files do
not provision firewall rules or establish sole native scrape ownership.

## Independent observer and rule transport

`health-watchdog` now has two clocks: a 45-second process-heartbeat deadline and a
100-second rule-pipeline deadline. `pipeline_listen` is a numeric loopback endpoint;
put its `/v1/watchdog/pipeline` behind a `pipeline_sender` ingress on O. Configure
`pipeline_token_file` and `monitor_id`. It accepts firing Watchdog notifications
for its own monitor only, with canonical decimal evaluation sequence. Repeated
sequences and retired epochs cannot renew either deadline. Epoch retirement is
bounded; exhaustion fails closed rather than forgetting replay protection.

`prometheus/rules.yml` reads persisted incident state. PromQL source disappearance
and Alertmanager resolved webhooks do not close incidents. The Watchdog rule
carries the completed evaluation sequence and monitor epoch through Alertmanager.
`prometheus/alertmanager.example.yml` repeats that heartbeat every 30 seconds and
uses a distinct mTLS identity/token. Change the monitor identity consistently.
The pinned Prometheus binary must run with `--rules.alert.resend-delay=15s`;
`prometheus/runtime-flags.json` freezes this required argv and the matching
Alertmanager route intervals for deployment review and the isolated runtime test.
its one-minute default delayed fresh Watchdog annotations to about 90 seconds
in the isolated chain despite Alertmanager's 30-second repeat. The 15-second
resend aligns with the already fixed 15-second group interval; it does not
change O's independent 45/100-second deadlines.
The independent observer must reside outside V and M's failure domains.

The pinned Prometheus 3.9.1 `promtool check rules` and `promtool test rules`,
plus Alertmanager 0.34.1 `amtool check-config`, passed in the isolated C03
worktree; hashes and raw logs are indexed under C03 evidence. These static
tool checks do not establish the running three-process notification chain.
The C03 runtime test uses only isolated monitoring binaries, loopback endpoints
and disposable test identities; it does not start a business node. The rule
manifest distinguishes implemented reachability/telemetry predicates,
synthetic-only PQ input, and pending C04/C05/C08 adapters.
The observer's external notifier is still an HTTP acknowledgement boundary, not a
verified human-delivery receipt. The real notification chain, runtime version pins,
rotation, source adapters and 72-hour acceptance remain required.


## Initial native PQ source

For an isolated development setup, pass an approved alias with validator-engine
`--health-node-id NODE`, use a loopback exporter address, and opt in to PQ hooks
with `--health-core-metrics`. The exporter derives its network identity from the
configured zero-state root bytes, encoded as lowercase hex. Configure that same
identity in edge, the native poller and the immutable manager inventory.

The typed endpoint reads the completed native generation without collecting.
An owner metrics request waits at most two seconds; an overdue child still holds
the real collection lease and its late result is discarded. No metrics or typed
request can bypass the fixed minimum refresh interval.

The development native poll/state examples add only PQ signing failure facts.
Duties, storage, host and witness facts are still absent, and performance/host
acceptance remains not_run. Do not treat a reachable endpoint or zero observed PQ
failures as proof of healthy consensus.

## Native facts, judgement and the six-tool sample

`health-native-poll CONFIG_JSON` reads the typed `/v1/edge/snapshot` every 15
seconds with the edge-reader identity and posts a `native_core` FactFrame to
`/v1/manager/facts` with the separate manager-ingest identity
(`manager_identity_file`). The facts are derived deterministically from the
native record (`health-core::native_facts`): chain progress age (v3 anchors,
else the finalized masterchain slot), local execution failures, oldest pending
action, PQ signing failures, storage ack failures/usability and session stop
pending. A fact the sample cannot support stays absent and the frame is marked
incomplete; legitimate refusals are never failures. The derived facts are posted
under their own source id `native_facts` (source epoch suffixed with the
catalog version) with exactly the eight catalog facts; the same tick also posts
one-fact frames for `native_chain` (applied/served gap, only when the node
serves lite state), `diagnostic` (publisher drops), `native_gauges` (QUIC
backlog from two fixed OpenMetrics lines) and `process_facts` (anonymous
memory growth over 15 minutes). A catalog change must bump `CATALOG_VERSION` and the
inventory revision; it never rewrites an archived generation.

The manager ingress that aggregates many lanes sets `rate_per_second` /
`burst` in its ingress config (defaults 1 / 4 are the node-entry contract).

`scripts/judge-validator-health.py` reads M's rule state and the latest
archived native snapshot per node and prints one verdict record (healthy,
degraded, unhealthy, unknown) with the archive parent hashes as evidence IDs.
Run it from a timer with `--journal`; exit status 3 means at least one node is
unhealthy. `scripts/sample-validator-health-tools.py` issues one short grant on
the private control socket and reads a node through the six MCP tools.

Derived source epochs carry the deriving run's identity
(`…:facts-v2:<start-ms>-<pid>`, `…:witness-v1:<run>`): a restarted poller or
comparer re-derives with fresh in-memory state and would otherwise collide
with its own earlier frames under the same generation and quarantine the
source. A restart is therefore a new epoch; the archived snapshot epochs are
untouched.

## External witness, receiver, AI availability and the storage gauge

`health-witness-compare CONFIG_JSON` (unit `local-judge/nhm-local-witness-compare.service`)
reads M's archived `native-core-v3` chain anchors read-only every 15 seconds
and compares each node against the observers: the same masterchain seqno with
a different root hash is a fork; lagging every fresh observer head by more than
`lag_blocks` is isolation; being ahead of the observers is not a fault. The
result is posted as the `observer_disagreement` fact under source `witness`,
bound to the node's current native epoch. Without a fresh anchor from the node
and from at least one observer no fact is posted, so the rule stays unknown
rather than good. It never contacts a node, an edge or a model.

`scripts/local-notification-receiver.py` (unit `nhm-local-receiver.service`)
is an independent HTTPS receiver for M's outbox: bearer token, payload hash
echoed as the receipt M verifies, every delivery appended to a private journal.
M's `receiver` config points at it; the doctor's `notification_receiver` gate
reads M's last accepted receipt.

The `ai_optional` availability fact for the `monitor` node is posted by the
**minute** judgement run (`--ai-fact-url`, `--ai-fact-token-file`,
`--ai-fact-state`, `--ai-fact-journal`, `--ai-fact-max-age 900`): `1` while
the last line of the model journal is an accepted explanation younger than
the maximum age, `0` otherwise; epoch and generation persist in the state
file and there is exactly one writer. Source ttls are bounded at 180 s by
the catalog, so a fact posted only by the ten-minute model turn would expire
between turns (it did, and read as unknown for seven minutes in ten). A silent
model lane therefore opens `ai_unavailable` on the `monitor` target instead
of vanishing; the deterministic verdict never depends on it.

The engine records `rocksdb.is-write-stopped` after every synchronous commit
into a process-wide storage health (`td::storage_health`), the exporter
publishes `tos_health_storage_write_stopped` (0/1), `_total` and
`commits_observed_total`, and the poller turns the gauge into the
`rocksdb_write_stopped` fact of the `native_gauges` frame. On an engine without
the gauge the frame is incomplete, the rule is unknown and
`telemetry_unavailable` says so; nothing is assumed good.

## Key blocks: the `native_key_block` source

Persistent states and state garbage collection follow key blocks, and a key
block exists only when the configuration changes (in practice: when elections
rotate the validator set). The validator manager therefore publishes the last
known key block (`chain.key_block = {seqno, unix_seconds}`, null before one
is resolved) with the v3 chain anchor; the poller derives `key_block_age_ms`
(observation clock minus the key block's own clock) into its own one-fact
source `native_key_block`, and the rule `key_block_stale` (Above threshold)
says how long the chain has gone without a checkpoint. A publisher without
the field is accepted and yields no fact, never zero. The development
inventory binds the rule at one hour (revision `development-native-facts-7`);
a production threshold follows the election period plus margin.

Any change to the v3 anchor is a change to the **edge's** contract too: the
edge parses the native record with the same strict types and answers 503
until it is rebuilt and recreated. On 2026-09-30 the rebuilt network came up
with every edge refusing for four minutes for exactly this reason. An edge is
also bound to the **network id** it was started with: after a rebuild, every
edge must be recreated with the new zero-state root (read it from the
network's own file, never from a constant in a script), or it refuses every
native sample. The refusal reason is now logged by the edge once a minute.

## Node state: duties, real queues and the storage position

The v3 payload carries a `node_state` section the validator manager refreshes
once per second (null until the first refresh, dropped when unrefreshed for
30 s), and the three coverage fields `local_duties`, `queue_state` and
`storage_state` disappear when it is present; the snapshot's coverage then
reads `complete`. Each part is its own one-frame source in the poller:

- `native_duties` (`duty_member`, `duty_windows_missed`): membership is
  whether the manager runs any validator group; the duty denominator is the
  collator schedule's own leader-window assignment
  (`is_expected_collator`), and a missed window is one that neither started
  nor ended for a protocol reason (superseded by a newer window while the
  parent resolved, or suppressed because finality was behind). Rule
  `duty_missed` (Increase) is bound for validators only; observers are never
  assigned and report zero.
- `native_queues` (`queue_depth`, `queue_oldest_ms`): the manager's three real
  waiter queues (`wait_block_data_`, `wait_state_` incl. preliminary waits,
  `shard_client_waiters_`), counted in the same one-second sweep that checks
  their timers; each waiter now records its creation time. Rule `queue_stall`
  (Above) fires on the oldest unfinished wait. The PQ signer still has no
  queue and none is invented.
- `native_storage` (`disk_used_permille`, `state_gc_lag_blocks`): `statvfs`
  of the database root once per second, and the applied seqno minus the
  garbage-collection seqno (the persistent-state seqno is published beside
  it). Rules `storage_space_low` (Above 900 ‰) and `state_gc_lag` (Above a
  block count; GC trails by `state_ttl` plus at most one key-block interval on
  a healthy network).

All of it is a handful of relaxed atomics in the engine; nothing scans the
database or reads private material. The edge, collector, query broker and
poller all parse the section with strict types, so every one of them must be
rebuilt and redeployed with the engine.

## The rotating development network

`setup-testnet.sh --clean --rotate` creates the network with a bootstrap
validator set valid for 600 s, stage-A elections every 600 s
(`tos-pq-elections.service`, rosters 1,2,3,7 and 1,2,3,4 alternating) and a
fifth validator node 7. Every election is a configuration change and hence a
key block about every ten minutes; the first persistent state follows the
first key block after a 2^17 s boundary, after which restarts stop replaying
from genesis and garbage collection runs. Monitoring covers node 7 like the
others (edge, ingress, probe, collector, poller, `judge-nodes.json` for the
judgement's node list); the election service restarts nothing itself, but a
node restart during its RPC turn makes it exit and it has `Restart=no`, so
check it after any node restart.

## Rolling an engine on a network without persistent state

Before the rotating rebuild the development network had produced no key
block since genesis (validator set fixed for 30 days, nothing changed the
config), so no persistent state existed and **every node restart replayed
the chain from genesis** (about 6 blocks/s here against about 2.5 blocks/s
produced), and validator memory grew about 1.4 GiB/h with nothing collected.
The rules below still hold on any network without a recent persistent state:

1. One node at a time. Restart a validator only while the chain is live and
   all four validators are at the head; move on only after the restarted node
   is back at the head. Two validators replaying at once halts the chain
   (three of four are needed), as happened on 2026-09-30 13:50 UTC when a
   rollout treated "ready" as "at the head".
2. Stop the node's edge first, restart, wait for a `native-core-v3` snapshot,
   then recreate the edge bound to the new PID.
3. While a node replays, the monitor reports it honestly: applied/served gap
   and initialization facts move, `observer_disagreement` sees it lagging the
   observers, and the verdict is degraded or unhealthy. That is the correct
   reading, not noise.
4. Do not compare performance profiles by restarting a node on this network;
   toggle the edge instead (see `perf/CC-ONE-HOUR-GATE.md`).

## Bounded evidence retention

An evidence database that can only grow eventually reaches its quota, refuses
ingest and leaves the monitor blind. `health-state` therefore accepts two
optional keys, both decimal-string milliseconds between one hour and ninety
days; absent keys keep the store unbounded exactly as before:

```json
"evidence_retention_ms": "604800000",
"witness_retention_ms": "2592000000"
```

The single evidence writer runs one bounded pass every five minutes (at most
16 pages of 512 scanned rows or one second per pass) and one extra pass after
a write is refused for space, then retries that write once. A pass deletes
ordinary observations whose `record.received_at_ms` is older than the window
and historical witness rows whose receipt `first_received_at` is older than
the witness window. It never deletes a row younger than two hours (the fixed
floor keeps the query service's retained parents and fixed-watermark grants
valid), never the newest eight rows of a (node, scope, source) or witness
endpoint, never anything in `quarantined`, `witness_quarantined`,
`witness_current_activation`, `database_identity` or any control-database
table. Incidents and the outbox live in the control database and are not
touched. Sequence numbers are never reused and no VACUUM runs; a passive WAL
checkpoint follows each pass.

Deleting a row also removes the unique-identity witness that refused a replay
of that record, so each pass commits a per-source seal (the highest deleted
generation) in the same transaction. A later insert at or below that seal is
refused with `EVIDENCE_EXPIRED` (a diagnostic batch is acknowledged as a
duplicate) rather than minting a fresh sequence number for old evidence.
Records without a canonical generation are never deleted. Seals are small and
are kept for the life of the database.

The query service revalidates every retained parent on each projection and
blocks all manager queries when one is missing. Set the evidence window at or
above the longest period a query row may stay resident in Q; the two-hour
floor is a minimum, not that guarantee.

The state endpoint reports `retention` (configured windows, pass counts, rows
deleted, last pass age and error, oldest retained receipt), `inventory` (the
bound revision and rule bindings), `quarantined_sources` and `notification`
(receiver configured, last accepted delivery receipt in this process). The
metrics endpoint adds `tos_health_evidence_retention_*` counters and ages.

## Production doctor

`scripts/doctor.py` prints one table of gates, each `pass`, `fail` or
`not_run`, and exits 1 when any gate fails (2 on a usage error). It reads only
the manager state endpoint (`--manager-state-url` with
`--manager-read-token-file`, or a saved copy via `--manager-state-file`), the
evidence database read-only (`--evidence-db`) and a receipts file
(`--evidence-file`, see `config/doctor-evidence.example.json`) for gates that
are established outside the running process. It never prints `pass` without a
concrete check; what it cannot establish is `not_run`.

Live gates: `manager_state`, `rule_inputs_usable` (every inventory rule on
every node evaluated with a non-unknown input), `no_quarantined_sources`
(live list and the durable quarantine tables), `evidence_retention`
(configured, last pass within twice its period, no error),
`notification_receiver` (configured and an accepted delivery within 24 hours,
live or by receipt) and `ai_lane` (`ai_unavailable` bound and not active;
`not_run` when unbound). Receipt gates: `physical_separation`,
`performance_round_a` to `_f`, `soak_72h`, `token_rotation`,
`cert_rotation`, `rollback_drill`. A `pass` receipt is honoured only with a
valid RFC 3339 `at` younger than `--receipt-max-age-days` (default 90) and an
evidence path that exists (`--no-check-evidence-paths` relaxes the latter).
