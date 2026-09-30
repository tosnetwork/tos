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
not discovered production facts. The 18-rule catalog is implemented in Rust, but
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
backlog from two fixed OpenMetrics lines) and `process` (anonymous memory
growth over 15 minutes). A catalog change must bump `CATALOG_VERSION` and the
inventory revision; it never rewrites an archived generation.

The manager ingress that aggregates many lanes sets `rate_per_second` /
`burst` in its ingress config (defaults 1 / 4 are the node-entry contract).

`scripts/judge-validator-health.py` reads M's rule state and the latest
archived native snapshot per node and prints one verdict record (healthy,
degraded, unhealthy, unknown) with the archive parent hashes as evidence IDs.
Run it from a timer with `--journal`; exit status 3 means at least one node is
unhealthy. `scripts/sample-validator-health-tools.py` issues one short grant on
the private control socket and reads a node through the six MCP tools.
