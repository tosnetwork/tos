# C09 real-source epoch reconciliation (scoped candidate)

The pre-change local C09 read returned `/v1/edge/snapshot` 503 on all six
nodes: the native publisher uses an independent 32-hex publisher epoch, while
the proc/cgroup collector uses `boot_id:pid:start_ticks`. Equality between
those raw strings was a false C02 synthetic-fixture assumption. The original
six-503 evidence remains with the C09 supervisor; it is not a passing run.

The scheduled native sampler now captures, both before and after its exact
paired `/metrics` and `/health-snapshot` reads, the configured PID's proc
epoch, executable path/device/inode identity and ownership of the configured
loopback listening socket. Reads of proc socket tables are bounded to 4 MiB;
FD enumeration is capped at 8,192 and each probe at one second. Any missing,
ambiguous or changed identity refuses publication without retry. The cached
snapshot carries a separate `native_process_binding`; the native envelope
retains its original publisher epoch. HTTP handlers perform cache-only binding
and source-age checks, never proc or native source I/O. The binding asserts
local process/socket association, not consensus correctness or production
acceptance.

Synthetic contract/ingress/archive fixtures explicitly use two epoch
namespaces and a marked synthetic binding. Actual typed sampler and C++ pair
tests use a process-owned local listener. Wrong PID, missing binding, invalid
listener, closed listener, mixed epoch and pre-publication pair mismatches are
negative controls. The actual routed snapshot is validated against the closed
edge schema. Production six-node rerun belongs to the C09 supervisor; this
candidate alone does not replace that real-source evidence.

Build and checks used `CARGO_TARGET_DIR=/home/tomi/nhm-c07c08-build`,
`--locked`, and `-j2`. Frozen raw logs and binary hashes are indexed in the
successor review receipt after final completion.
