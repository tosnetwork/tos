# C09 supervised functional sampler — prepared, not installed

These are candidate **user** systemd units. The owner controls installation and
enablement. No unit in this directory has been copied to the user manager or
enabled by this branch. The service executes the checked Python source from
this separate worktree against the existing private local Q/M sockets; it does
not launch or restart QueryService, collectors, business nodes, or a model API.

## Exact schedule and limits

`nhm-c09-functional.timer` starts after five minutes, then at least five
minutes after the preceding service becomes inactive. The script additionally
requires a new wall-clock slot and at least 300 seconds of same-boot
`CLOCK_BOOTTIME`. Every twelfth wall slot includes the bounded unknown
consensus and cross-run denial controls. `nhm-c09-functional-stop.timer`
stops the sampler timer at **2026-10-03 01:10:00 UTC**, the existing Q-aware
window stop. The script itself refuses to start a grant within 45 seconds of
that boundary. The service has a 35-second systemd timeout; a timeout leaves
the durable inflight marker for operator review.

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

The private sample log directory is
`evidence/c09-functional-supervised/` (same UID, mode 0700). Each JSONL row is
at most 1,024 bytes; the file stops at 4 MiB. A full 72 hours at five-minute
cadence has at most 864 ticks and 936 grants including hourly controls, before
accounting for the already-used one-shot or any unrelated Q activity. The
script's functional alarm is 22 seconds, each control/revoke call 3 seconds,
each MCP call 5 seconds, and SQLite busy timeout 0.5 seconds. Token values,
run IDs, evidence IDs, and process payload never enter the log or journal.
Git does not preserve directory modes: the owner must verify this directory
is same-UID mode 0700 before installation. A wrong mode makes the script
refuse before any grant.

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

The source is pinned by `SCRIPT.sha256` and checked by `ExecStartPre`; the
binary SHA and baseline SHA are pinned again by the script arguments. The
candidate unit files, source, latch tests, and an isolated disposable Q/M
control must pass source review before the owner installs or enables either
timer. Enablement is the owner's separate action. This work does not claim
C09 or 72-hour acceptance.
