# Response to the fed3ca84e UNO audit

The external audit was read in full. Its coverage is static review of the
listed files, not compilation, fuzzing, dynamic verification or an audit of
the complete product. Its 21 confirmed properties are not targets for changes.
This response records a partial disposition, not security or activation sign-off.

## Addressed

H-1: the verifier cache now stores only successful immutable verifiers.
Construction is serialized; subsequent successful reads avoid the mutex.
A failed construction returns the existing local key-error status for that
call and leaves initialization retryable. A constructor unwind also cannot
permanently poison the initialization lock, which protects no partial key.
Tests cover one failed construction followed by the real fixed-key constructor,
reuse of the resulting key, unwind recovery and concurrent initialization.
Restoring error caching made the recovery test fail on the second construction.
No circuit selection, VK binding or local-error/invalid-bundle mapping changed.

M-1: dev/release profiles explicitly use unwind; an abort-strategy build is
rejected by a compile-time guard. An explicit `cargo rustc -- -C panic=abort`
failed at that guard. Removing the guard allowed the same build to succeed;
the guard was restored and a normal release library rebuilt afterward.
Strictly, abort does not unwind across the ABI: it terminates the process and
defeats recoverable-panic containment. OOM/abort/invalid pointers remain outside
the containment guarantee, as documented before this change.

M-5: ABI.md now explicitly says v0 has no KEM field and is not the hybrid
profile or durable transaction format. A changed hybrid request contract needs
an ABI version change and regenerated integration fixtures. This does not
automatically invalidate independent primitive/VK reference vectors; those
remain valid evidence for their original, narrower scope.

## M-3: not reproduced; underlying API already checks the fork

`vm::dict::LabelParser` defaults to `chk_all` in `crypto/vm/dict.h`.
Its constructor calls `validate_ext(max_label_len)` in `crypto/vm/dict.cpp`.
For a fork, that rejects anything other than exactly two references and
exactly the unconsumed label bits. `skip_label()` then removes those bits.
Thus `validate_state_dictionary` already receives a zero-bit, two-ref fork.

The new test verifies valid two-leaf lookup/count and rejects zero, one or
three refs and trailing bits, without changing the implementation. Temporarily
passing `chk_none` to the parser made the malformed-fork control fail. The
default was restored with no source diff. No redundant fork guard was added.

## Still open

- H-2 is confirmed as a queued-message liveness risk. Fatal rejection prevents
  miscrediting but does not drain the message. Pre-activation queued messages
  and potential sender-filter failures must be handled, not assumed away by
  rollout instructions. The masterchain-origin path is not claimed verified
  here. Define and version the collate/validate rule, including imported value,
  forwarding/bounce fees, non-bounceable messages, queue removal and InMsg/OutMsg
  evidence, before implementation. Silently discarding value or removing
  `fatal_error` alone is not a fix. This stays activation-blocking.
- M-2: the policy checks are indeed after execution. Add a bounded preflight
  with a defined candidate resource metric; do not equate serialized BoC bytes
  with the engine's existing `wire_bytes` without defining that contract.
  The Counter engine reports eight payload bytes, not the BoC container size.
  Keep post-execution accounting checks as well. No fix is claimed yet.
- M-4: zero settlement principal and shared Rust/C++ vectors remain to be
  addressed together, preserving zero-valued protocol dummy notes separately.
- L-1/L-2 remain follow-ups; L-3/L-4 remain bounded performance observations.
  No accounting transition or invariant was changed in this pass.

## Dynamic evidence for this disposition

Rust release tests: 26 passed, one opt-in measurement ignored. FFI recovery and
panic tests are included. State-container tests: 16 passed. Logs are
`build/uno-audit-crypto-regression.log`, `build/uno-audit-key-cache-mutation.log`,
`build/uno-audit-panic-abort.log`, `build/uno-audit-panic-guard-mutation.log`,
`build/uno-audit-fork-before.log`, `build/uno-audit-fork-mutation.log`, and
`build/uno-audit-state-regression.log`. All deliberate mutations were restored.
These tests do not expand the external audit's reviewed coverage.
