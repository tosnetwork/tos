# X02 native-log offline cut (2026-09-25)

Fixed implementation commit: `747f515881e624d08b6d0ce53dc9a1e39ec859a0`.

The Stage A validators are subprocesses whose stderr is streamed into each
`nodeN/log`; the `validator-N` journald units are empty. This cut adds a
separate `validator_stderr_file` evidence format. It binds the child PID and
start ticks, executable SHA, DB cwd device/inode, stderr pipe inode, harness
PID and start ticks, harness-held pipe and log-file descriptor, log path and
device/inode, exact byte offsets, prefix and segment SHA, and paired wall and
monotonic read times. Native finalized markers retain full BlockIdExt and
their original UTC event time; file offsets are not presented as journald
cursors. Same-generation truncation, changed prefix, cursor replay, path or
inode alias, and missing pipe/DB writer identity fail closed. A deliberate
restart is not accepted by this first X02 slice; it requires separate sealed
generation handling. The directed-isolation run itself must not restart a
validator.

Source SHA-256:

- `scripts/x02_fault_evidence.py`: `546de3c5546b4a8015be0c14c8dbbbbdf99a06dc0fc600a06e043ed5adc578e2`
- `test/pq-native/test_x02_native_log.py`: `fdcf9de0e346993bdbf77d2762df1273f41d64a81977f46478542ff146bd51cc`

At this exact tree, `python3 -m unittest discover -s test/pq-native -p
'test_x02*.py' -q` exited 0 with 48/48 tests. `git diff --check` and
`python3 -m py_compile` exited 0. Tests include a real local child stderr pipe
and harness log FD; a marker emitted before a synthetic cut but read after
the cut retains its earlier event time. These tests do not start a validator
network and do not demonstrate actual `tc` rule hits or drops.

Remaining before X02 live evidence: freeze a policy from the four real Stage A
PIDs/UDP socket tuples and their source/binary hashes; retain pre/post-RPC
native-log segments; independently review the native-file verifier and its
cut-time mutants; then run one serial four-node directed 100% isolation with
the raw bidirectional `tc` counters, full per-height IDs, RPC completion
times, and fault/recovery windows. Partial packet loss remains separate. X02
is OPEN.
