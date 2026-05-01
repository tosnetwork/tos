# Slice 6 Audit Checklist

## Scheduler

- All scheduled messages use `sendAfterBlocks` or `sendAtMcSeqno`.
- The time source is trusted masterchain seqno, not caller-controlled
  message fields, and not `blockchain.now()`. Contract code uses
  `blockchain.currentMcSeqno()` or a protocol-provided seqno.
- `expire_after_blocks` is nonzero and horizon bounded.
- Escrow depletion has an explicit force-expiry path.
- Cancellation authority is explicit and not inherited by a deleted
  sender or dead-letter address unless configured that way.

## Delivery and Dead Letter

- Every persistent delivery-failure record has a payer.
- Dead-letter storage has finite record, bit, ref, and retention bounds.
- Record insertion uses a concrete escrow coin amount and checks
  `minRecordEscrowCoins`; a boolean "funded" flag is not sufficient.
- Record insertion rejects cells whose measured bit/ref counts exceed
  the storage field width before narrowing to `uint16` / `uint8`.
- Diagnostic cells are depth-prechecked before `calculateSize`, so an
  attacker cannot force an expensive traversal of a cell tree that could
  never fit the configured record-depth budget.
- `minRecordEscrowCoins` is nonzero; a direct struct literal cannot
  disable the escrow floor.
- Full-sink behavior rejects or counts drops; it never creates a free
  unbounded record.
- Production BackPressure emission remains runtime-gated until the
  activation review is complete.

## Monitors and Links

- `OP_MONITOR_DOWN` is used for monitor notifications, not `OP_ERROR`.
- Monitor registration and link registration are explicit and distinct.
- Diagnostics fit declared bit/ref/depth budgets.
- Observer failure does not affect the observed actor unless an explicit
  link policy says so.

## Supervision

- Restart windows, maximum restarts, cooldown, gas budget, and value
  budget are declared.
- `one_for_all` and `rest_for_one` are documented as best-effort and
  non-atomic.
- Partial recovery records include recovered child count and escalation
  target.
- Restart storms open a circuit breaker instead of amplifying messages.
- Crash notifications while a circuit is already open do not extend the
  cooldown indefinitely.
- Supervisor-level restart helpers set final-failure escalation when a
  child restart cannot be funded or exceeds the restart window.
- Contracts that dispatch escalation messages use
  `recordChildRestartOutcome(...)` and gate the dispatch on
  `escalationStarted`, not merely on `recordChildRestart(...) == false`.
- Gas/value budget exhaustion may open the circuit before consuming a
  restart-count slot; this is an intentional funding guard and should be
  tested separately from restart-storm exhaustion.
- `emitEscalation` / `finalFailure` is a state flag; the contract still
  sends any escalation or dead-letter message explicitly.

## Capability

- Capability constraints are hashed with `CapabilityConstraintsV1`.
- `validFromMcSeqno`, `expiresAtMcSeqno`, revocation expiry, and
  `Slice6CapabilityUseContext.currentMcSeqno` are masterchain seqnos,
  never Unix timestamps.
- Wallet or SDK display includes target, selector, max value, validity
  window, max uses, grantee or signer, counterparty, replay domain,
  delegated depth, and argument bounds.
- A grant is sender-bound, signature-bound, stateful, or single-use.
- Pubkey-bound grants use `requireCapabilityWithSignature(...)`; plain
  `requireCapability(...)` is not accepted as a signature check.
- Dual-bound grants (`grantee` and `granteePubkey`) are sender-checked by
  the plain path and sender+signature checked only by the signature path.
- Reusable public bearer tokens are rejected.
- Revoked-handle, epoch, consumed-nonce, and handle-use maps have finite
  bounds and full-set behavior is reject-until-compacted.
- Argument-bound maps have a fixed small bound and the hashed
  constraints include `argumentBoundCount`.
- `maxUses` is enforced by registry state, not only displayed in the
  hashed constraints.
- Revocation is monotonic: zero means permanent, and repeated revocation
  may extend but not shorten the revocation horizon.
- Minimum revocation epochs are monotonic and cannot be lowered.
- A wildcard issuer epoch (`grantee = null`) revokes address-bound grants
  too, so compromised issuer batches do not require one entry per
  grantee.
- Replay domain, delegation depth, and argument bounds are populated in
  `Slice6CapabilityUseContext` and enforced at runtime.
- `replayDomain = 0` is intentionally unrestricted; production contracts
  use a deployment-specific replay domain.

## Value Dispatch

- Payouts use `@stdlib/safe-payments` helpers or explicitly include
  `SEND_MODE_BOUNCE_ON_ACTION_FAIL`.
- Funding receivers refund `in.valueCoins - required` or require exact
  value.
- Long-lived contracts call `slice6RequireMinimumBalanceAfterPayout` or
  reserve a retained balance before sending partial payouts.
