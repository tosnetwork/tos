# C09 private QueryService functional soak witness — review candidate

Base: `node-health-monitor@afdd738eadc62cd6d3960aa86c475816a96d8555`.
Branch: `nhm/c09-functional-soak-starbridge`. This branch contains only this
contract, `scripts/sample-query-functional.py`, and its offline test. It is
not deployed, scheduled, or counted toward the running 72-hour gate.

## Instrument and cadence

The script is a **one-shot** instrument. An operator-owned timer may invoke it
at most once per 300-second wall-clock slot; its private append-only JSONL lock
refuses a second invocation in the same slot or less than 300 seconds of
same-boot `CLOCK_BOOTTIME` after the previous sample. A persisted slot
highwater also refuses wall-clock rollback, including repeated attempts after
a logged rollback failure. The private 0600 JSONL record holds `boot_id` and
`boottime_ns` to distinguish reboot from same-boot spacing; these metadata
stay in the private witness log. It selects one of the six approved
nodes in round-robin order. One control grant permits exactly that node and
`node` scope for a four-minute window. One persistent private MCP connection
initializes protocol `2025-06-18` and calls `tos_get_node_snapshot` with only
`process`, `max_age_seconds=180`, and the grant's fixed `as_of` time. The script
requires one process component and one derived evidence record, looks up the
one original `process` parent by ID in the **same Q-configured M database**,
recomputes its original hash, and checks node, process epoch, full process
payload, positive PID, valid clock, and parent age in `[0, 180000]` ms. It also
requires the running Q process to hold the exact Q ledger inode, Q's durable
M cursor to identify the currently opened M inode/network, and Q's retained
origin binding to contain the exact M parent sequence and serialized body. The
same Q snapshot reads the grant's frozen Q and M watermarks from its durable
body, and requires the selected Q evidence and retained M parent sequences to
be no greater than those respective grant watermarks.
The M lookup uses that retained sequence against `observations.store_seq`
(`INTEGER PRIMARY KEY`) and checks the resulting hash and quarantine tuple;
it does not scan historical M rows by content hash.

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
| Binding | Running systemd Q PID, exact executable SHA-256, command-line M/Q/control/MCP paths, Q's open ledger inode, M cursor device/inode/network, and exact retained parent bytes must match |
| Grant expiry | Q's returned `expires_in_seconds` must be exactly its existing 200-second maximum; the witness cannot request an extension |
| Deadlines | Control connection and each revoke 3 s; MCP connection/each request 5 s; SQLite busy 0.5 s; functional phase 22 s, then at most two independently bounded revoke attempts (6 s) and the durable revocation read |
| Bytes | 4096-byte request/control response, 32768-byte MCP/parent response, 1024-byte JSONL sample |
| Log | Same-UID private directory and 0600 non-linked regular file; exclusive nonblocking lock, `fsync` per record, 4 MiB hard cap; only status/category/phase/elapsed/node slot/count, no token, payload or evidence ID |
| Ledger | Before any isolated socket test, freeze a 0600 baseline file containing Q device/inode, starting grant count/body bytes/attempts, Q binary SHA and the three exact caps; pin that file's SHA-256 in invocation. Refuse new grants if growth exceeds 1024 grants, 32 MiB grant bodies or 3072 attempts |

Preflight reserves the entire next slot's worst-case cost before issuing any
grant: one or two grant rows, 32768 bytes per row (Q's `encoded` limit), and
one or three attempts. Concurrent unrelated writers can still consume the
reserved budget after preflight; this instrument is not a global quota
enforcer. Such growth is a separate Q ledger gate, not evidence of successful
functional sampling.

At exactly five-minute cadence a 72-hour window creates at most 864 primary
grants and 72 second negative-control grants, or 936 total. It makes at most
1008 process/consensus/scope tool calls combined. The 1024-grant limit leaves
room for scheduling margin but never interprets unrelated grants as this
instrument's own. Q ledger byte growth is monitored independently from the
4 MiB witness log cap; SQLite page/WAL size is reported separately by the
operator's existing resource sampler.

The baseline JSON has exactly `schema_version=1`, `q_device`, `q_inode`,
`grants`, `grant_body_bytes`, `attempts`, `query_sha256`,
`max_new_grants=1024`, `max_new_grant_body_bytes=33554432`, and
`max_new_attempts=3072`. Its exact bytes are pinned by
`--expected-baseline-sha256`; it cannot be silently refreshed between samples.
The baseline and Q file identity must both survive every sample. A replaced Q
database or lower ledger count is an explicit failure.

Each JSONL row separately records `fixed_grant_query_status` and
`projection_head_status`. The latter is a separate, read-only private control
probe: `lagging` does not erase a successful fixed-grant query, while an
unavailable head probe fails the overall sample and retains the independent
query result. The existing one-minute projection sampler is still authoritative
for its own continuous head-status series.

Once a grant response contains a valid run ID it is registered for cleanup
before its token is used. A 200 response that cannot be decoded records an
unknown grant side effect and fails cleanup confirmation; so does a grant
transport timeout, disconnect, or non-200 response that may have occurred
after Q committed a grant. On timeout or any
other failure the script cancels the functional alarm, tries every known
revoke through a new bounded control connection, and marks the sample failed
if any revoke is not acknowledged. An unconfirmed grant must be inspected by
the operator; grant expiry is not reported as a successful revoke. Even after
the control endpoint acknowledges revocation, the witness requires every
known run ID to have `revoked=1` in the same pinned Q ledger inode.

## Review and acceptance boundary

Offline tests cover exact parent/payload/age rejection, source hash mismatch,
grant-frozen W, Q retained-binding and M inode rejection, negative-envelope
validation, malformed grant cleanup registration, frozen baseline digest,
reserved ledger budget, durable revocation, slot rollback, and the whole-run
timeout at the head probe. A real Unix-socket fault test commits an issued row
to a disposable SQLite database then drops the grant response; the witness
records `cleanup_unconfirmed` rather than a clean failure. An isolated one-shot
control on 2026-09-30 used a disposable
private M/Q directory, six archived process source envelopes refreshed only
inside that disposable M, a separate Q process with generated private tokens,
and a frozen empty Q baseline. The actual private control/MCP sockets passed
one hourly-slot run (process, unknown consensus, cross-run denial): 2 grants,
2 durable revocations, 335 ms. A fault-injected process-query timeout returned
failure and left its one durable grant revoked. No live Q/M database was
written. An independent source review remains required before scheduling. A live
read-only dry run is **not** part of this branch's implementation. Deployment,
timer wiring, and interpretation of a new 72-hour window remain separate
operator decisions. This witness supplements the existing one-minute
projection sampler; it does not by itself satisfy C09 A–F performance,
rotation/restore, or 72-hour acceptance.
