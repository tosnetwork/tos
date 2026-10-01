# C06 isolated candidate — supervisor review required

Base: `35ba59c111dd74518e6e661bcd1984598d493907`.
Branch: `nhm/c06-native-diagnostics`; checkpoint `b3f5c725cd44decc385ed765d713e8c3dfb91ab2` plus the delivery correction commit containing this file.
No main merge, production acceptance, performance gate, or 72-hour soak is claimed.

The native action hook copies only three fixed enum scalars after CORE updates.
Diagnostic delivery defaults off. Enabled sampling precedes allocation of a
source sequence; source sequence allocation precedes transport admission. Full
or contended delivery therefore leaves observable sequence gaps. Late lower
sequences across relay batches remain admissible; an ACK's accepted-through
sequence is the maximum of that batch, not a global contiguous watermark.

Native credentials use a fixed approved Edge PID and same UID/GID handshake.
Edge startup mapping pins node, native PID/UID/GID, and the existing publisher's
32-lowercase-hex process epoch. The private pathname socket is mode 0600 under a
same-owner private directory. Neither side registers the first sender. A restart
requires explicit remapping. Deployment must coordinate those approved PIDs and
read the actual native publisher epoch; the standalone bridge's known epoch is
fixture evidence, not the actual validator startup/deployment protocol.

Edge has one pending flight and bounded queue, age, retries, JSON, and encrypted
TCP writes. The rate counts handshake, TLS records, HTTP headers and retries at
the socket writer; it excludes TCP/IP retransmission, DNS and NIC overhead.
There is no diagnostic spool. M uses a distinct diagnostic credential and the
existing evidence writer. Hash conflicts quarantine the immutable native
identity. A whole batch transaction commits before ACK. Caller timeout retains
its lease until writer completion. The 32 slot limit is an upper bound: the
4 MiB predecode reservation and8 MiB total budget can refuse earlier.

Records remain unanchored partial evidence. Source-reported wall time never
establishes clock validity. Unknown observed time projects as null; the stored
scalar0 is a compatibility sentinel. Unattached per-record dropped/parse counters
are required nullable fields and remain null; measured zero remains string "0".
The per-process diagnostic status has independent measured counters and reasons.

## Evidence and limits

`raw/index.json` indexes captured artifacts and SHA-256 hashes. Source before and
after indices, native binary hashes, per-control natural exits, compiled mutant
patch/source hashes and restored results are included. `metric-manifest.json`
records249 existing + 7 label-free tuples = 256 without changing the 256 profile
limit. `resource-profile.json` records fixed ownership and transport caps.
The existing C04 budget control includes the 32768-byte response reserve while
preserving the 512 KiB catalog-layout and4 MiB total-publication assertions.

The Rust workspace union passed 191 tests. Its indexed source differs from the
final fixture only in binary-hash logging and the finite SQL-trigger cleanup
bound (55 seconds). The final three integration controls bind that exact fixture
source; all production source and maximum 128-row/nullability controls are
unchanged across those receipts.

The relevant controls cover native disabled/sampled/full/contention/exhaustion,
real credential/epoch datagrams, full/dead socket, source catalog invariants,
existing action/publisher regressions, actual IPC→relay→mTLS→M rows, HTTP
refusals, conflict quarantine/reopen, SQLite page and WAL quota, atomic prefix
rollback, nullable query projection, max 128 rows and actual 256 KiB JSON, caller
deadline ownership, and independent native/Edge/M subprocess lifecycle.
Native build receipts bind the frozen source hashes and executable hashes;
the native build stamp precedes this delivery commit. An integrated exact-SHA
build remains the supervisor’s responsibility. Test-job peak RSS and elapsed
time are build/control resource observations, not production measurements.

The lifecycle fixture exercises production ActionObservation and IPC plus real
health-edge/health-state children; it does not establish actual validator
consensus liveness. Its terminal outputs and EOF/exit are logged by the final
Rust union. Actual validators, C09 operations, CI and performance remain open.

Historical failed controls remain captured: catalog null-label segfault; status
reserve classified as catalog storage; insufficient 16 KiB row bound; missing
coverage/nullability; WAL-vs-page quota wrong branch; premature SQL BUSY instead
of a writer deadline; too-short trigger drain (3 seconds and later 30 seconds under load); and excessive Edge polling.
Only restored final receipts support the delivered candidate.

## Additive shared-file integration map

Lighthouse owns integration. Apply checkpoint and delivery correction together;
reconcile shared files rather than replacing its newer source.

- `manager.rs`: optional diagnostic config/token/node allowlist, budget/status,
  diagnostic-only route and command on the existing writer.
- `durable.rs`: diagnostic insertion wrapper with existing WAL budget gate.
- `ingress.rs`: diagnostic-only certificate role; separate path/body/ACK bounds;
  read-role diagnostic status route. PipelineSender retains its existing scope.
- `edge.rs`, `lib.rs`, `bin/health-edge.rs`: independent status and optional relay.
- core `wire.rs`, `contracts.rs`: additive catalog8 and batch validation/content ID;
  original catalog7 interoperability fixture remains supported.
- core `evidence.rs`, `query_output.rs`: unknown observed-time sentinel/projection,
  diagnostic phase DTO, required nullable counter fields. Preserve Lighthouse's
  newer PaginationDto success argument when reconciling test call sites.
- `generate-contracts.py` and eight schemas: targeted additive patch path
  `--diagnostics-only`; preserve frozen C04 native-v2 definitions. Preserve the
  supervisor's central c8bc native/process binding correction during integration.

Supervisor must verify the exact integrated SHA and ledger independently. The
standalone stage can be reviewed without starting or changing shared local nodes.
