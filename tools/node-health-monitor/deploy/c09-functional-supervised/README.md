# C09 supervised functional sampler — prepared, not installed

These are candidate **user** systemd units. The owner controls installation and
enablement. No unit in this directory has been copied to the user manager or
enabled by this branch. The service executes a checksum-pinned Python copy in
`/home/tomi/nhm-supervision/c09-local/runtime/functional-soak/`, outside the
disposable Git worktree, against the existing private local Q/M sockets. It
does not launch or restart QueryService, collectors, business nodes, or a model
API.

## Private runtime setup and ownership

The dedicated `functional-soak/` directory is owned by `tomi:tomi` and mode
0700. It currently contains mode-0500 copies of the exact candidate sampler
and stop-receipt scripts, a mode-0400 `SCRIPT.sha256` manifest, and a mode-0600
copy of the pinned one-shot Q baseline. Both script hashes in the manifest
match the frozen files; `ExecStartPre` checks them before either unit runs.
The manifest in this candidate is the installation source and must be copied
byte-for-byte to that runtime directory before enablement. If source changes,
review the successor and install its scripts and manifest together while the
functional timer is stopped; never update a running window in place.

Before owner-controlled enablement, check `stat -c '%a %U:%G %n'` on the
directory and four frozen files, run `sha256sum --check` against the **runtime**
`SCRIPT.sha256`, and verify the baseline digest
`25c0458888a275bcf9568bc1fc53d914e9d5a3901932b0840444d99a3ea3382f`.
If rebuilding the directory, use a same-UID mode-0700 directory, copy the
reviewed scripts as mode 0500, manifest as 0400, and baseline as 0600; fsync
each file and the directory. Refuse to overwrite an existing sample log,
review receipt, `.inflight`, or stop receipt. The operator and service must run
under the same UID. The operator/service token files remain in the existing
private runtime `config/` directory; token values are never copied here.

The 72-hour `samples.private.jsonl`, `review.private.json`, its `.inflight`
marker, and `stop-receipt.private.json` live only in this runtime directory.
The sampler creates sample log and marker mode 0600; an operator creates any
review receipt mode 0600. Do not put these files or their contents in Git.

## Exact schedule and limits

`nhm-c09-functional.timer` starts after five minutes, then at least five
minutes after the preceding service becomes inactive. The script additionally
requires a new wall-clock slot and at least 300 seconds of same-boot
`CLOCK_BOOTTIME`. Every twelfth wall slot includes the bounded unknown
consensus and cross-run denial controls. The candidate first successful
fixed-grant sample must finish by **2026-09-30 06:55:00 UTC**. Before that
first pass, the script reserves the full 35-second service deadline and
refuses a grant when it can no longer meet the cutoff. The candidate
`nhm-c09-functional-stop.timer` ends at **2026-10-03 07:10:00 UTC**: at least
72 hours plus 15 minutes after the latest allowed first pass. The script
refuses to start a grant within 45 seconds of that end. A service timeout
leaves the durable inflight marker for operator review.

The supervisor extended the active Q-aware stop timer to
**2026-10-03 07:10 UTC** as `nhm-c09-q-soak-stop-v2.timer`; the old 01:10
timer is inactive and `nhm-c09-soak.timer` remains active. Recheck these
three unit states immediately before owner-controlled functional enablement.
If source review or installation misses
the 06:55 first-pass cutoff, move both proposed ends and review new pins;
do not start a late or shortened window under these units.

The existing pinned private baseline is
`evidence/c09-functional-live-one-shot-20260930T014805Z/baseline.private.json`
(SHA-256 `25c0458888a275bcf9568bc1fc53d914e9d5a3901932b0840444d99a3ea3382f`).
It records Q ledger device/inode, binary SHA, 24 initial grants, 18,003 grant
body bytes, and 72 attempts. The authorized one-shot consumed one grant and
one attempt, so the same baseline counts it toward the fixed growth limits.
Before the owner enables the timer, Q identity and source checksum must still
match the pinned files. The script refuses growth above 1,024 grants, 32 MiB
grant bodies, or 3,072 attempts from that baseline, reserving the next slot's
worst-case cost before issuing a grant.

The private sample log directory is the dedicated runtime `functional-soak/`
directory (same UID, mode 0700). Each JSONL row is
at most 1,024 bytes; the file stops at 4 MiB. A full 72 hours at five-minute
cadence has at most 864 ticks and 936 grants including hourly controls, before
accounting for the already-used one-shot or any unrelated Q activity. The
script's functional alarm is 22 seconds, each control/revoke call 3 seconds,
each MCP call 5 seconds, and SQLite busy timeout 0.5 seconds. Token values,
run IDs, evidence IDs, and process payload never enter the log or journal.
The owner must verify this directory is same-UID mode 0700 before enablement.
A wrong mode makes the script refuse before any grant.

## Failure latch and alert

Before the first grant POST, the script fsyncs
`samples.private.jsonl.inflight` and its parent directory. It removes that
marker only after a `pass` sample is fsynced and every grant is durably
`revoked=1`. A crash, failed sample, unconfirmed cleanup, failed log append,
or source/baseline mismatch therefore prevents the next tick from issuing a
grant. A previous JSONL row with `status != pass` or
`cleanup_confirmed != true` also latches. A latched tick exits nonzero without
appending another sample, preserving the failed row and slot highwater.

`nhm-c09-functional.service` has `Restart=no`. A nonzero exit leaves the unit
failed and triggers `nhm-c09-functional-alert.service`, which writes one
fixed, token-free error message to the **local journal**. The service stdout
contains only the bounded instrument result/category. No external paging is
configured in this candidate; the owner must inspect the failed unit, private
sample log, Q ledger, and any inflight marker. Repeated timer activations, if
systemd performs them, remain fail-closed and cannot create grants.

An existing `.inflight` is checked before any review receipt. No receipt can
remove it or allow the next tick to issue a grant. For an orphaned marker,
the operator procedure is:

1. Keep the functional timer stopped. In the same private 0700 directory,
   preserve byte-for-byte mode-0600 copies of the marker and JSONL log;
   record each SHA-256, device/inode, marker slot and boot ID, and the last
   complete log row. Do not truncate or rewrite either source artifact.
2. Verify the running Q process still uses the pinned binary and the exact Q
   ledger device/inode from the frozen baseline. Inspect that Q ledger
   read-only, including all `query_grants` rows that could have been created
   by the interrupted sample and their `run_id`, `boot_id`, `expires_ms`, and
   `revoked` columns. Include the unknown-after-POST case even if no run ID
   reached the sampler. If the ledger was replaced, the candidate set is
   uncertain, or its time namespace/boot identity is unclear, keep the
   marker and timer stopped.
3. For each possibly live candidate, use the private operator control socket
   to revoke by run ID, then confirm `revoked=1` in the same durable Q ledger.
   Alternatively, with the timer still stopped, confirm every such row is
   expired against the matching Linux `CLOCK_BOOTTIME` domain and the fixed
   200-second service expiry. A successful HTTP reply alone is insufficient.
   Keep token values, run IDs and grant bodies out of public logs and notes.
4. Only after all candidates are accounted for, manually remove the original
   `.inflight` and fsync its private parent directory. Retain the archived
   bytes and hashes. Do not enable a timer that retries while the marker
   exists. If no sample row was written, also require the next wall slot to
   exceed the archived marker slot; the script cannot recover that highwater
   from a removed marker.

To release a previous failed JSONL row after the marker procedure, the
operator creates a same-UID, mode-0600 `review.private.json` with exactly:

```json
{
  "schema_version": 1,
  "failed_row_sha256": "SHA256_OF_EXACT_FAILED_JSON_LINE_WITHOUT_NEWLINE",
  "slot_highwater": 0,
  "reviewer": "operator-id",
  "reviewed_at_utc": "2026-09-30T00:00:00Z"
}
```

`slot_highwater` must equal the failed row's highwater, and the review time
must follow that row's `wall_utc`. A valid acknowledgement does not clear an
inflight marker. The next sample records the acknowledgement file SHA-256,
preserves the row highwater, and will not reuse the same review file for a
later failure. Editing, rotating, or truncating the sample log is not the
reset procedure.

## Review boundary

At 2026-10-03 07:10:00 UTC the separate stop timer calls a service that stops
both the functional timer and functional service, then writes a private,
single-write `stop-receipt.private.json` after checking they are no longer
active. That receipt records the configured window end, actual UTC receipt
time, timer/service states, Q ledger device/inode and baseline identity match,
sample-log byte count/SHA-256, first recorded and first successful sample
times, the first-pass cutoff, the calculated wall-clock end, same-boot
`CLOCK_BOOTTIME` elapsed nanoseconds, whether the 72-hour-plus-one-tick
monotonic bound was met, last row digest/status/highwater,
and marker presence/digest. It excludes token values, run IDs, grant bodies,
and sample payloads. A missing receipt or active timer/service is a
stop-control failure. The receipt does not prove uninterrupted coverage,
Q-aware overlap, or C09 acceptance; those require independent evidence. If a
grant was interrupted, the marker stays for the manual procedure above.

The source is pinned by the runtime `SCRIPT.sha256` and checked by
`ExecStartPre`; the binary SHA and baseline SHA are pinned again by the
sampler arguments. The candidate unit files, both scripts, latch and stop
receipt tests, and an isolated disposable Q/M control must pass source review
before the owner installs or enables either timer. Enablement is the owner's
separate action. This work does not claim C09 or 72-hour acceptance.
