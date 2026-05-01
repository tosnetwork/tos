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
- Treat `one_for_all` and `rest_for_one` as best-effort non-atomic
  recovery sequences. Each child recovery is a separate transaction.

`Cell<T>` is a typed cell reference. `T.toCell()` produces a `Cell<T>`,
`cell.beginParse()` plus `T.fromSlice(...)` parses an untyped cell, and
`Cell<T>.load()` materializes the typed value. The `lazy` keyword is used
by dispatch lowering for inbound bodies; nested cells inside user code can
be parsed directly with `T.fromSlice(cell.beginParse())`.

The examples in `examples/slice6/` are intentionally small and
compile-only. They show the approved shapes without pretending to be
full production services.
