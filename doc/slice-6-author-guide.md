# Slice 6 Author Guide

Slice 6 gives contract authors four bounded actor-style tools without
changing the public-address account model:

- `@stdlib/time` for masterchain-seqno scheduled actions.
- `@stdlib/supervision` for monitors, links, child registries, restart
  intensity, and escalation records.
- `@stdlib/capability` for public grants with sender-bound or
  signature-bound proof.
- `@stdlib/delivery` for canonical delivery ids, dead-letter records,
  and BackPressure advice validation while production emission remains
  gated.

Rules for production contracts:

- Treat masterchain seqno as the only trusted Slice 6 scheduling time
  base. Never schedule from caller-provided `msg.now`.
- Declare a finite timer, monitor, supervisor, dead-letter, and
  capability budget before storing entries.
- Keep `extra_flags` bit 3 disabled unless a later synchronized
  validator amendment activates it.
- Do not use public bearer secrets. Capability handles are public ids;
  authorization must be sender-bound, signature-bound, stateful, or
  single-use.
- Treat `one_for_all` and `rest_for_one` as best-effort non-atomic
  recovery sequences. Each child recovery is a separate transaction.

The examples in `examples/slice6/` are intentionally small and
compile-only. They show the approved shapes without pretending to be
full production services.
