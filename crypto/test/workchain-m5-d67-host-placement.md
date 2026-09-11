# D67 host placement proposal

Specification: `0301d7fdb5676510` (memo commit `eec5f8e0`). This is a
placement proposal for confirmation, not an implemented or frozen codec.

Confirmed by the coordinator in memo `dcbcd28c`, specification
`c7da55fddeee326e`: the placement is now frozen, but the codec is not implemented
by this document. Enforce both Withdrawal identity uniqueness and created_lt
uniqueness regardless of dictionary key choice, and independently enumerate
the stored open count. Introduce authenticated closure inspection together
with this representation; do not retire the structural guard before the
replacement check exists. The historical proposal below is retained as the
basis of the decision.

## Authenticated location

Place the bounded set of open Withdrawal records inside the withdrawing
account's confidential state, persisted through its Native account data and
ShardAccounts commitment. Do not put it in coordinator state, an external
side table, or a process-local replay map.

Use a new versioned account-state constructor. The existing deposits layout
has identity, crypto, pending dictionary and lifecycle references: with a
nonempty pending dictionary these already occupy four cell references. Simply
adding a fifth reference is not representable.

Proposed shape: retain identity, crypto and pending at the root; replace the
root lifecycle reference in the NEW constructor with a mandatory account
control envelope. That envelope contains the existing lifecycle and a bounded
Withdrawal dictionary keyed by the canonical Withdrawal identity supplied by
B. Any stored open count must equal dictionary cardinality, independently
enumerated during validation. Record fields and Attempt identity remain B's
codec responsibility. No tag number, count width or configuration default is
selected by this proposal.

This realizes the explicit future tag migration noted at
`workchain-confidential-state.h` beside `system_pending`; it does not reinterpret
the existing lifecycle tags or insert obligations into the pending dictionary.
Old constructors retain their current encoding and represent no Withdrawal
records. Migration must be explicit and authenticated, never silently rewrite
an old record while decoding it.

## Host constraints to implement after confirmation

- Read `K_withdrawal` from authenticated configuration, with no local default.
  A missing value cannot admit a Withdrawal profile. The initial value is not
  frozen by D67 and is not chosen here.
- Enforce the cap on the resulting open-record set with checked arithmetic;
  unknown or malformed records must not be treated as empty.
- Keep only unresolved records, not permanent per-payout history. The exact
  terminal removal transition must follow B's mutually exclusive terminal
  state invariants; this proposal does not invent it.
- Closure must inspect this authenticated set and reject an open obligation.
  The M3 structural no-obligation premise expires when this representation is
  introduced; coordinate the owned expiry inventory with B, not weaken it.
- For the D66 no-pending assertion, compare the full authenticated account to
  pending slice over affected accounts, including both receipt kinds and both
  counts. Comparing a proposed effects list is insufficient. Withdrawal
  records must not consume or impersonate receipt slots.

## Independent interface work

B can define Withdrawal wire/context, Withdrawal/Attempt identities and record
fields without waiting for this envelope's final encoding. The host first
needs the canonical wire/context and identity inputs for the metered statement
path, then record encoding for persistence. None of these interfaces is
assumed delivered by `48dca2c42`. No independent accounting prediction was
read to prepare this proposal.

## Evidence and limits

Inspected `WorkchainConfidentialAccount` and both existing account constructors
in `block.tlb`; verified the specification SHA-256 locally. Only this document
is added: no production code, schema, guard criterion, or D59 default changes.
This is not a live test, an implemented migration, or a completed M5 claim.
