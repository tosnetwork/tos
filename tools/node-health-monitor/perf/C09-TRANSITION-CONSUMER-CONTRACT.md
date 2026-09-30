# C09 projection transition consumer — isolated upgrade candidate

This branch starts from the frozen functional sampler at
`nhm/c09-functional-soak-starbridge@7f9b82b4e3d166152d1086b8624afada4e0065e1`.
It changes only a **future** consumer source and tests. It has not replaced
`/home/tomi/nhm-supervision/c09-local/runtime/functional/sample-query-functional.py`,
its `SCRIPT.sha256`, the running Q binary, or any active timer. The current
manifest intentionally still pins the running consumer, so copying this
candidate script alone would fail the unit's checksum preflight.

The isolated Lighthouse producer `nhm/c09-anchor-integration@4050107cc`
(`observability.rs` SHA-256
`8a2f5f08d4e0945dde8078c05b077f6fabf8f5be8ea7ffb63e9e84113677e3bc`)
emits `projection_status="transition"` only when before/after Data+Q samples
differ while the M head and M version are available. Conflict takes precedence.
The response is JSON `schema_version=1` with HTTP 503,
`manager_conflicted=false`, boolean `caught_up_at_last_import` from the after
sample, decimal `query_watermark`, decimal/null after-cursor
`cursor_global_m_seq`, decimal M-head `source_global_m_seq`, decimal/null
`lag_global_m_seq` (null if cursor absent or source below cursor), and
boolean/null `source_identity_match` (null if cursor absent). A transition can
carry `caught_up_at_last_import=true`; that flag is not a current-head proof.

The candidate consumer validates that shape and returns the distinct head
status `transition`. It marks the overall sample failed with
`error_kind=projection_transition` while retaining the independently measured
`fixed_grant_query_status`. It never maps transition to `caught_up` or to a
passing sample. The same unavailable/failure rule now covers the other
schema-valid head statuses besides `caught_up` and `lagging`, closing a
pre-existing path where a later fixed-grant success could mask a 503 head.
Existing cleanup/revocation and `.inflight` failure latch
remain in force. Invalid transition/200, conflicted transition, missing M
head, malformed counters, inconsistent lag, and false `caught_up` all fail.

Before any coordinated Q upgrade, review the exact producer and consumer
commits, exercise the real private HTTP handler during an import overlap,
freeze a new consumer script SHA and unit manifest in the 0700 runtime
directory, and decide whether the active functional/Q-aware 72-hour window
must restart. This candidate does not authorize a live Q or sampler change,
and does not establish C09 acceptance.
