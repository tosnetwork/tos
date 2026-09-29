# C07/C08 reconciliation (development scope)

Baseline: `35ba59c111dd74518e6e661bcd1984598d493907` (C05 scoped acceptance). Starbridge's reviewed C06 candidate was cherry-picked into the implementation branch as `900bcb894` and `1f1c634ef`; the combined source still requires exact integrated review. C09 local-node lifecycle belongs to the supervisor. This document records gaps, not acceptance.

| Contract | Existing implementation | C07/C08 closure work |
| --- | --- | --- |
| Six cache-only tools | `health-core/query.rs` and typed `query_output.rs`; actual HTTP router tests | Preserve source/scope/window/W behavior; test MCP and HTTP parity and error semantics |
| 256-bit grant token | Random token and SHA-256 digest in `Grant`; 200-second in-process TTL | Durable grant/call/byte/delivered-ID ledger with conservative restart handling; broker-only control socket; service credential remains separate |
| Evidence and watermark | Baseline 8 MiB bounded in-memory `EvidenceStore`; read-only QueryService | SQLite WAL/FULL write-through, exact restoration, active-grant W pinning, and a narrow read-only projection of M's archived `process` source now exist. M original sequence and query-package sequence are separate; original M body/hash is retained and checked on query-ledger restart, and derived evidence names its parent and converter version. A bounded broker-side 15-second refresh detects quarantine of retained M parents, durably revokes active grants and refuses new grants; the detection interval is not instantaneous and no query handler reads M. Native/cgroup/diagnostic/other M adapters and production source claims remain open. |
| Per-run limits | 16 calls, 16 KiB input, 32 KiB response, 128 KiB returned bytes in HTTP service | Atomic durable accounting including MCP structured/text duplicate bytes, two child requests, 5-second tool deadline and 180-second run deadline |
| Pagination | Event/change queries now sort by `(store_seq,evidence_id)` and return bounded pages with a standard HMAC-SHA256 cursor bound to principal/run/tool/filters/window/W/key/expiry | Core event/change pages and actual HTTP event pages, fixed-W late-row exclusion, RFC 4231 HMAC, tamper/filter/cross-run/principal/tool/expiry/lexeme negatives, and durable ledger restart continuation pass in isolated tests. Change-history HTTP pagination and intended mutation sensitivity remain to be reviewed; not a C08 acceptance. |
| MCP | Exact `rmcp` 3.5.0 is now an opt-in Cargo feature; six published schemas use the existing HTTP QueryService; private Unix transport binds one durable grant to one connection and refuses replay. SDK-level calls and a real Unix same-connection flow pass in isolated tests. | Preserve the token-hidden transport admission, then close full protocol/session/cancellation, whole-run and AURA client compatibility gates; no production endpoint is enabled. |
| C07 fixed package | `Broker` queue/cooldown skeleton; no package or model wiring | Immutable bounded package at M watermark, delivered-ID validation, English diagnosis schema and conservative evidence/basis checks |
| AURA/provider | Pinned commit `1000f119d38f4c4656ced0ae883c90f6f7610890`, disabled | Inspect exact source/config and isolate tools/egress; owner model/private endpoint choice pending, so no external API or actual provider-pass claim |
| Zero upstream | QueryService has no upstream client | Counter-based storm/miss/depth/redirect/replay controls with actual V/O request counters; no on-demand refresh |

Implementation sequence: (1) durable grant and evidence ledger with crash/restart negatives; (2) broker-only control and shared HTTP/MCP service with exact SDK/protocol; (3) fixed evidence package and offline broker validation/cancellation; (4) isolated AURA and provider tests only after explicit owner choice. Preserve historical scoped C00–C05 claims; neither this plan nor unit tests promote production capabilities.

Checkpoint note: `tos-observability` now requires a private ledger DB and Unix control socket. An optional ninth argument (after a cache JSONL path or `-`) configures M's retained evidence DB. The broker-only grant operation imports eligible archived process observations from one bounded read-only M transaction before fixing the query-package W; no query handler reads M or calls V/O/Prometheus. The process still uses an 8 MiB clone-on-insert candidate to commit SQLite before publishing a cache row; measure or replace this copy before any production cost claim. The old in-memory-only router remains solely for existing isolated tests. This is a process-only development adapter, not C08 acceptance or a complete M evidence/query integration.

C06 integration boundary: the process projection scans only M rows declared as
`source='process'`, so a full population of diagnostic archives cannot consume
its 4096-row/8 MiB cap or revoke unrelated process runs. Diagnostic phases are
persisted by M, but source-reported wall time (when present) lacks a verified
clock basis; genuinely unknown time remains `observed_at=null`. The six-tool event
window is defined over trustworthy observed time, so it
explicitly returns `CAPABILITY_UNSUPPORTED` for the C06 diagnostic source or
kind. It does not substitute M receipt time or the compatibility zero sentinel
for an observation. A separately approved time-basis contract and a retained
parent adapter would be required for diagnostic event-window success.
For direct C06 typed projection, unverified diagnostic clock quality emits
`uncertain` (never `valid` or a claimed proven-invalid clock); a truly absent
source observation emits `observed_at=null`. Other sources with known invalid
clock still emit `invalid`. Neither form makes a diagnostic event selectable by
the observed-time window.

Control socket follow-up: admission is now limited to eight connections before
task spawn; permits last through response transmission and a five-second
connection deadline bounds idle/header/slow clients. Real Unix-socket tests
exercise eight idle holders, ninth refusal, expiry/recovery, and an overlapping
slow request. This is a C08 connection-budget control, not Unix peer identity
or production broker isolation; deployment must enforce dedicated ownership
and credentials separately.
The scoped test's natural-exit-0 raw log is
`/home/tomi/nhm-c07c08-build/edge-epoch-proof/control-socket.log`
(SHA-256 `af4f7286500b9721aca7dcf229b9c906f458b83c62e920de2915ef99690d7806`);
source `tos-observability.rs` SHA-256 is
`6fd00293b04e2a4ac988d161269dcec9821666b2f1b126cf18f8ee89b1d6d93e`.

MCP transport correction: the first draft exposed `run_token` in every
model-visible tool schema; the supervisor's retained red control and
`C08-MCP-REVIEW-HOLD.md` document that failure. The current draft restores the
six published input schemas verbatim and rejects a token supplied as a tool
argument. Service authorization, run ID and the opaque token are admitted in
private Unix HTTP headers, validated against the active grant, then claimed
once in the durable ledger. The bridge holds the token only in connection-owned
server state, rechecks the grant on each call through the original HTTP route,
and another connection cannot claim the same run even after ledger reopen.
Only one HTTP connection may carry a run; disconnect fails closed and requires
a new grant. That strict transport profile still needs AURA client compatibility
and disconnect/cancel/timeout controls before C08 acceptance. The MCP result
contains only one charged JSON text representation, not a second uncharged
structured copy. Feature `mcp` and production enablement remain off by default.

Watermark retention follow-up: while any durable grant is active, an evidence
insert that would evict a row at or before its fixed W is refused before the
SQLite commit and before the in-memory candidate replaces the current store.
The restart/revoke test confirms the original page remains visible across
reopen and eviction resumes only after revoke. This is a fail-closed 8 MiB
cache policy, not an increase in retention. The later cursor slice adds
event/change pagination in the isolated query service, while M's main
EvidenceDb import, MCP and whole-run accounting remain open C08 items.
The focused 16 HTTP + 3 ledger test raw log is
`/home/tomi/nhm-c07c08-build/edge-epoch-proof/query-pinning.log`
(SHA-256 `e4a25bc34af84c4e6655e9c3d38493b209fa617e1e112f93f5b4ed334a494157`);
strict workspace clippy/fmt/diff checks also exited 0.
