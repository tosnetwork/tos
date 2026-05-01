# Slice 6 Author Guide

Slice 6 gives contract authors four bounded actor-style tools without
changing the public-address account model:

- `@stdlib/time` for masterchain-seqno scheduled actions.
- `@stdlib/supervision` for monitors, links, child registries, restart
  intensity, and escalation records.
- `@stdlib/capability` for public grants with sender-bound or
  signature-bound proof.
- `@stdlib/safe-payments` for value dispatch with bounce-on-action-fail,
  excess refunds, and retained-balance checks.
- `@stdlib/delivery` for canonical delivery ids, dead-letter records,
  and BackPressure advice validation while production emission remains
  gated.

Rules for production contracts:

- Treat masterchain seqno as the only trusted Slice 6 scheduling time
  base. Use `blockchain.currentMcSeqno()` / `currentMcSeqno()`, which read
  TVM `PREVMCBLOCKS`; never use `blockchain.now()` or caller-provided
  `msg.now` for `*McSeqno` capability or scheduler fields. Unix time is
  still appropriate for ordinary wall-clock business logic. Use
  `Slice6WallClockBudget` / `slice6WallClockBudget(...)` for bounded
  application durations measured in seconds; do not reuse
  `Slice6TimerBudget.maxFutureHorizonBlocks` for wall-clock periods.
- Declare a finite timer, monitor, supervisor, dead-letter, and
  capability budget before storing entries.
- Dead-letter records must be funded with a concrete escrow coin amount.
  The stdlib rejects records below `Slice6DeadLetterBudget.minRecordEscrowCoins`;
  do not pass a caller-supplied boolean as a substitute for paid storage.
  The compatibility default is intentionally tiny for tests; production
  manifests must set this to a rent-backed per-record amount.
- Use `save({ ...storage, changedField: value })` for storage updates and
  `save(storage)` for pure state transitions. Spread preserves unchanged
  fields while evaluating the base storage value once.
- In `@deploy`, `storage` is intentionally unavailable because c4 may be
  empty, but `contract.getAddress()` is safe and supported: it reads TVM
  `MYADDR`, not contract data.
- For sparse state machines, use `@implicit_protocol_for(Message, State)`
  for one intentionally implicit known-opcode/wrong-state path, or
  `@implicit_protocol_default;` when every missing pair should use the
  synthesized Protocol path. Keep an explicit `@unknown_*` policy for
  unknown opcodes; it is a separate axis.
- Use `slice6RefundExcess*` when accepting `in.valueCoins >= required`,
  and use `slice6SendCoins*` / `slice6RequireMinimumBalanceAfterPayout`
  for payouts instead of raw `SEND_MODE_REGULAR`.
- Keep `extra_flags` bit 3 disabled unless a later synchronized
  validator amendment activates it.
- Do not use public bearer secrets. Capability handles are public ids;
  authorization must be sender-bound, signature-bound, stateful, or
  single-use.
- Size every capability registry dimension explicitly:
  active grants, revoked handles, revocation epochs, consumed nonces,
  and tracked handle-use counters. `maxUses` is enforced by the
  registry; consumed nonces and use counters are bounded storage, not
  free append-only logs.
- Populate `Slice6CapabilityUseContext` with the target's replay
  domain, the current delegation depth, and any argument values covered
  by `argumentBounds`. These fields are checked at runtime, not merely
  displayed in the wallet hash. `replayDomain = 0` is the unrestricted
  domain and should be used only for intentionally portable grants;
  production deployments should use a deployment-specific domain such as
  a contract-address hash or manifest constant.
- Keep capability argument bounds small. `@stdlib/capability` caps
  `argumentBounds` at `SLICE6_CAPABILITY_MAX_ARGUMENT_BOUNDS` and
  records `argumentBoundCount` in the hashed constraints so a grant
  cannot hide thousands of bounds behind one capability check.
- Use `requireCapabilityWithSignature(...)` for pubkey-bound grants.
  Plain `requireCapability(...)` rejects `grantee == null` /
  `granteePubkey != null` grants so an author cannot accidentally create
  an any-sender pubkey capability without verifying a signature. A grant
  with both `grantee` and `granteePubkey` has AND semantics only when
  the contract calls the signature path; the plain path enforces the
  sender address but does not verify the pubkey signature.
- Treat `revokeHandle(handle, 0)` as permanent revocation. Repeating a
  revocation may only extend the revocation horizon; it must not shorten
  or undo an earlier revocation. `setMinEpoch(...)` is also monotonic:
  lowering the minimum epoch is rejected. `setMinEpoch(issuer, null, N)`
  is a wildcard issuer epoch and revokes address-bound grants as well as
  pubkey-bound grants whose `revocationEpoch < N`.
- Treat `one_for_all` and `rest_for_one` as best-effort non-atomic
  recovery sequences. Each child recovery is a separate transaction.
  Prefer `Slice6SupervisorState.recordChildRestartOutcome(...)` when an
  outgoing escalation dispatch depends on the restart result. It reports
  `escalationStarted` only on the false -> true transition of
  `finalFailure`, preventing duplicate dispatch after the circuit is
  already open. `recordChildRestart(...)` remains as a bool wrapper.
  `emitEscalation()` marks `finalFailure`; it does not send an outgoing
  message. Callers must dispatch their escalation or dead-letter action
  explicitly after observing the flag.

`Cell<T>` is a typed cell reference. `T.toCell()` produces a `Cell<T>`,
`cell.beginParse()` plus `T.fromSlice(...)` parses an untyped cell, and
`Cell<T>.load()` materializes the typed value. The `lazy` keyword is used
by dispatch lowering for inbound bodies; nested cells inside user code can
be parsed directly with `T.fromSlice(cell.beginParse())`.

The examples in `examples/slice6/` are intentionally small and
compile-only. They show the approved shapes without pretending to be
full production services.
