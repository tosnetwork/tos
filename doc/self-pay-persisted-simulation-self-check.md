# Persisted self-pay simulation author self-check

This increment supplies the missing checkpoint boundary for mobile confirmation:
the existing session already delegates locking and durable state to native code.
An uncommitted simulation next-state cannot be consumed as a fee preview.

Applicable checklist areas: UP, RB, CC, PS, PA, AP, TE, BC, DC and RH. This is a
project-specific adapter, with no upstream counterpart. Consensus, VM execution,
cryptographic checks, contract formats and economic rules are unchanged; their
existing engine is invoked, not forked. No signature or broadcast is produced.

The new public C function is declared in `persisted.h`, implemented in
`persisted.cpp` and called by the real-library ctypes test. A caller search finds
no phone caller yet. Existing persisted read/verify wrappers remain on the old
runner path with unchanged arguments and error codes. Swift packaging already
exports this header. Platform compilation and phone source pins remain pending.

The new wrapper has no initialization flag. The shared runner uses its original
private directory/file validation, same exclusive nonblocking checkpoint lock,
existing marker/state requirements, bounded prior-state read, temporary file
fsync, atomic rename and directory fsync. Acquisition and simulation both run
under that lock; the exact signed BOC is passed only to the local simulator, not
to acquisition or the callback. Every acquired part remains untrusted until the
one-shot simulation authenticates it. Negative results publish nothing. On a
successful tagged result the checkpoint is durably committed before result bytes
or size are exposed. The result remains a local estimate, not an authenticated
balance cache entry, receipt or permission to release a pending authorization.

Simulation preserves its -1 through -6 error domain. The new wrapper assigns
persistence -7 and busy -8; ordinary reads retain persistence -6 and busy -5.
Acquisition failures map to -2, including invalid acquisition request profiles.
Invalid callback/message interface arguments are -1. Storage errors after rename
can leave the checkpoint advanced but return no estimate; callers must retry
from the current checkpoint rather than restore an older one.

Resource lifetime is unchanged: existing RAII descriptors and lock are released
on every path. Per-call material, output and next-state vectors are destroyed at
return. Simulation result storage caps at 2 MiB, message at 1 MiB, prior/next
state at 1 MiB. Acquisition retains its decreasing aggregate 64 MiB input budget,
16 MiB account/config caps and bounded query/fragment count. Caller result and
internal answer coexist, and verification may copy material; these are not RSS
measurements. No long-lived container, actor, timer, queue, thread, socket or
production file category is added. Existing checkpoint files remain fixed in
number and bounded in size. Phone concurrency/RSS and physical durability gates
remain pending; the callback still owns transport timeout/cancellation.

Actual native tests enroll using authenticated public basechain material, then
simulate its exact signed message. They check message hash/local-estimate status,
lock contention inside the callback, checkpoint presence, transport/bad-proof/
stale-proof refusal, empty message, distinct busy error, commit failure and lost
enrolled state. The existing filesystem shim also injects a directory fsync
failure after rename and requires -7 with zero output. Neither test enrollment nor
fixture signing is phone signing. Runtime directories use temporary private paths
and automatic cleanup; no secrets or bulk logs are committed.

Four compiled source controls remove the checkpoint lock, final directory fsync,
failure output clearing and the enrolled-missing-state refusal. Each designated
assertion fails; source is then restored and all 20 relevant CTests pass. The
first control harness selected a nonunique memset and stopped safely after
restoration; another missing-state variant failed earlier at first enrollment.
The corrected variants isolate the intended guards. These harness attempts and
their actual outputs are retained in the companion memo index, not hidden.

CMake registers both positive and filesystem-fault tests. The relevant Python
workflow builds the filesystem shim and selects both tests along with acquisition
and execution regressions. The workflow guard and ten condition tests pass.
Hosted CI, Apple exports and the new phone call are not claimed yet. The current
tree includes main `e26db394f`; this adapter does not alter that integration.
No manual two-build static analysis was requested or claimed. Review of the exact
new head and third-party/final release gates remain separate requirements.
