# Structural admission measurement scope

`measure-uno-input-admission` is an opt-in benchmark, not a consensus entry.
It constructs an ordinary balanced DAG from seed 91, with a distinct 256-bit
leaf payload per index. The two measured stages are the low-level union walker
and a fresh detached candidate admission session over the same resident source.
There is one logical candidate root and no Native inbox. Configuration identity
is a fixture, not an authenticated configuration or production input limit.

Each size runs in a fresh process; twenty repetitions reuse the source DAG.
The first sample is process-first admission, not disk-cold. The detached graph
is rebuilt on every sample. RSS is Linux process high-water RSS, not isolated
stage RSS. No OS caches are dropped. Graph generation, retained source storage,
and other process overhead are outside the stage timers but included in RSS.

The self-test checks a hand-counted three-cell/512-bit graph, exact admission,
one-cell-over CandidateInvalid and zero downstream calls. Replacing the actual
candidate cell bound with UINT64_MAX made it fail with exit 1; restoring it
passed. Logs: build/wave4-input-mutation.log and wave4-input-restored.log.
An additional checked-counter overflow test ensures the instrument does not
silently wrap its own counters; its mutation evidence is recorded with results.

The unchecked-add mutation also exited 1; restored self-test passed. A separate
anchor self-test fails when the real window eviction is removed, then passes
after restoration. `--anchors` performs 1200 successive finish/encode/decode
steps with a fixture capacity of 100 and opaque unique roots, checking old-root
eviction and round-trip height. These are anchor codec operations, not valid
note-tree commitments or full UNO blocks. The capacity is an experiment input,
not a newly selected production value. RSS remains process high-water RSS.

No commitment construction, inbox localization or semantic decoding, state
authentication, proof checking, engine execution, serialization, account wrapper
or CellDb commit is represented by these two timers. Summing this graph's bits
cannot determine how many logical proofs a shared graph may reference. Those
require independent semantic occurrence budgets and a real wire/profile.
