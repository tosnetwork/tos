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

After investigation, the operator must verify that any uncertain grant is
revoked or expired. To release a previous failed JSONL row or inflight marker,
the operator creates a same-UID, mode-0600
`review.private.json` in that directory with exactly:

```json
{
  "schema_version": 1,
  "failed_row_sha256": "SHA256_OF_EXACT_PREVIOUS_JSON_LINE_WITHOUT_NEWLINE_OR_NULL",
  "inflight_sha256": "SHA256_OF_EXACT_INFLIGHT_FILE_OR_NULL",
  "slot_highwater": 0,
  "reviewer": "operator-id",
  "reviewed_at_utc": "2026-09-30T00:00:00Z"
}
```

`slot_highwater` must equal the maximum of the preceding row's highwater and
the inflight marker's slot. The review time must follow each present row's
`wall_utc` and marker's `created_at_utc`. A valid acknowledgement removes and
fsyncs the old marker before a new grant. The next sample records the
acknowledgement file SHA-256, preserves the highwater, and will not reuse the
same review file for a later failure. Manually deleting the marker or editing,
rotating, or truncating the sample log is not the reset procedure.

## Review boundary

The source is pinned by `SCRIPT.sha256` and checked by `ExecStartPre`; the
binary SHA and baseline SHA are pinned again by the script arguments. The
candidate unit files, source, latch tests, and an isolated disposable Q/M
control must pass source review before the owner installs or enables either
timer. Enablement is the owner's separate action. This work does not claim
C09 or 72-hour acceptance.
