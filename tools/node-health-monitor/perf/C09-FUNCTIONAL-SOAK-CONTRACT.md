# C09 private QueryService functional soak witness — review candidate

Base: `node-health-monitor@afdd738eadc62cd6d3960aa86c475816a96d8555`.
Branch: `nhm/c09-functional-soak-starbridge`. This branch contains only this
contract, `scripts/sample-query-functional.py`, and its offline test. It is
not deployed, scheduled, or counted toward the running 72-hour gate.

## Instrument and cadence

The script is a **one-shot** instrument. An operator-owned timer may invoke it
at most once per 300-second wall-clock slot; its private append-only JSONL lock
refuses a second invocation in the same slot or less than 300 seconds of
same-boot `CLOCK_BOOTTIME` after the previous sample. It selects one of the six approved
nodes in round-robin order. One control grant permits exactly that node and
`node` scope for a four-minute window. One persistent private MCP connection
initializes protocol `2025-06-18` and calls `tos_get_node_snapshot` with only
`process`, `max_age_seconds=180`, and the grant's fixed `as_of` time. The script
requires one process component and one derived evidence record, looks up the
one original `process` parent by ID in the **same Q-configured M database**,
recomputes its original hash, and checks node, process epoch, full process
payload, positive PID, valid clock, and parent age in `[0, 180000]` ms.

Every twelfth slot, the same grant also queries `consensus` and requires
`CACHE_MISS`, unknown coverage, null data, and no evidence. A second grant
permits a different node; its separate MCP connection queries the primary
node and requires `OUT_OF_SCOPE` with the same unknown/no-evidence envelope.
Both grants are revoked regardless of the outcome. A negative-control failure
is a failed sample, not a skipped control. No external model, AURA process,
public TCP endpoint, native node, collector, M write, or service restart is
used.

## Pinned boundaries

| Boundary | Fixed limit |
| --- | --- |
| Cadence | One sample per 300-second slot; hourly negative controls |
| Connections | Private control UDS and private MCP UDS only; two grants and two MCP sessions maximum |
| Tokens | Operator and service tokens read from same-UID regular files with no group/other access, `O_NOFOLLOW`; never logged or written to a handoff file |
| Binding | Running systemd Q PID, exact executable SHA-256 and command-line M/control/MCP paths must match operator arguments |
| Deadlines | Control connection 3 s; MCP connection/request 5 s; entire functional phase 22 s; cleanup has independent bounded control attempts |
| Bytes | 4096-byte control response and request, 32768-byte MCP/parent response, 1024-byte JSONL sample |
| Log | Same-UID private directory and 0600 non-linked regular file; exclusive nonblocking lock, `fsync` per record, 4 MiB hard cap; only status/category/phase/elapsed/node slot/count, no token, payload or evidence ID |
| Ledger | Operator freezes starting grant count, grant-body bytes and attempt count. Refuse new grants if growth exceeds 1024 grants, 32 MiB grant bodies or 3072 attempts |

At exactly five-minute cadence a 72-hour window creates at most 864 primary
grants and 72 second negative-control grants, or 936 total. It makes at most
1008 process/consensus/scope tool calls combined. The 1024-grant limit leaves
room for scheduling margin but never interprets unrelated grants as this
instrument's own. Q ledger byte growth is monitored independently from the
4 MiB witness log cap; SQLite page/WAL size is reported separately by the
operator's existing resource sampler.

Once a grant response contains a valid run ID it is registered for cleanup
before its token is used. A 200 response that cannot be decoded records an
unknown grant side effect and fails cleanup confirmation. On timeout or any
other failure the script cancels the functional alarm, tries every known
revoke through a new bounded control connection, and marks the sample failed
if any revoke is not acknowledged. An unconfirmed grant must be inspected by
the operator; grant expiry is not reported as a successful revoke.

## Review and acceptance boundary

Offline tests cover exact parent/payload/age rejection, source hash mismatch,
negative-envelope validation, malformed grant cleanup registration, and
ledger budget refusal. Before scheduling, independently review interface
facts and run an isolated Q/M socket integration with disposable databases,
including a fault-injected query timeout and revoke acknowledgement. A live
read-only dry run is **not** part of this branch's implementation. Deployment,
timer wiring, and interpretation of a new 72-hour window remain separate
operator decisions. This witness supplements the existing one-minute
projection sampler; it does not by itself satisfy C09 A–F performance,
rotation/restore, or 72-hour acceptance.
