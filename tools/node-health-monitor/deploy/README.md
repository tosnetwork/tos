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
The independent observer must reside outside V and M's failure domains.

The Prometheus rules and example Alertmanager configuration have NOT passed a real
promtool/Alertmanager run in this environment: no binaries are installed and the
release download failed. Run `promtool test rules tests/fixtures/rule_test.yml`
from `tools/node-health-monitor` after installing the reviewed, pinned runtime.
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
