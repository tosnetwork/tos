# Streaming import admission and cancellation

The actor admits an import only when the larger of its file-size ratio and the
checked CellDb encoding-plus-rollback bound fits the per-import spool cap. The
bound is computed from a bounded BoC header probe, before sidecar creation, GC
pause, worker creation, full parsing or database writes. It is no longer clamped
to the cap. Per-record and shared-process limits remain in force.

This is intentionally conservative resource admission, not proof that every
rejected file would consume that much disk. It may reject a file whose actual
encoding fits. Neither the nominal 48 GiB cap nor the previous approximate
24 GiB failure discussion is a measured usable snapshot capacity. This change
does not raise those defaults or establish production UNO state scalability.

Each downloader supplies its shared sticky cancellation flag to all three
actor-import request paths. Abort (including timeout) and actor teardown set the
flag. CellDb shares it with the worker and checks it between commit batches;
shutdown also sets the same flag. A retry after cancellation requires a fresh
token. Existing queued-action re-entry checks cancellation before starting work.
An abandoned import therefore relinquishes its single-worker slot after reaching
a cooperative checkpoint, and existing rollback/release logic handles failure.
This cannot interrupt an operating-system read blocked inside the kernel; no
fixed cancellation latency is claimed.

The actor regression uses a valid small file with a cap one byte below the
computed bound, verifies zero parser callback invocations and no imported root,
then admits at the exact bound. It parks the actual worker at a cancellation
checkpoint with a condition variable, signals only the request token, verifies
failure and absence of the root, and successfully retries on the same CellDb
actor with a fresh token. The instrumentation itself always returns false; it
does not implement cancellation for the code under test. This is a deterministic
worker-stall test, not a slow-device benchmark or a downloader-network timeout
integration test.

Both mutations were demonstrated red: restoring the old reservation clamp
accepts the valid bound-minus-one fixture, and removing the request-to-worker
token assignment accepts the deliberately cancelled import. In each case the
test fails on the success/error disposition, not on diagnostic wording. Both
mutations were restored before final regression testing.
