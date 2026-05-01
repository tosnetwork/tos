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
- Full-sink behavior rejects or counts drops; it never creates a free
  unbounded record.
- Production BackPressure emission remains gated until the activation
  review is complete.

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

## Capability

- Capability constraints are hashed with `CapabilityConstraintsV1`.
- `validFromMcSeqno`, `expiresAtMcSeqno`, revocation expiry, and
  `Slice6CapabilityUseContext.currentMcSeqno` are masterchain seqnos,
  never Unix timestamps.
- Wallet or SDK display includes target, selector, max value, validity
  window, max uses, grantee or signer, counterparty, and delegated depth.
- A grant is sender-bound, signature-bound, stateful, or single-use.
- Reusable public bearer tokens are rejected.
- Revoked-handle, epoch, consumed-nonce, and handle-use maps have finite
  bounds and full-set behavior is reject-until-compacted.
- `maxUses` is enforced by registry state, not only displayed in the
  hashed constraints.
- Revocation is monotonic: zero means permanent, and repeated revocation
  may extend but not shorten the revocation horizon.

## Value Dispatch

- Payouts use `@stdlib/safe-payments` helpers or explicitly include
  `SEND_MODE_BOUNCE_ON_ACTION_FAIL`.
- Funding receivers refund `in.valueCoins - required` or require exact
  value.
- Long-lived contracts call `slice6RequireMinimumBalanceAfterPayout` or
  reserve a retained balance before sending partial payouts.
