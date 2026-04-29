# TOS Actor-Layer Implementation Roadmap

## 0. Scope and references

This document sequences the implementation of the actor-model
strengthening directions defined in [`doc/actor.md`](actor.md) and the
language execution path defined in [`doc/tol.md`](tol.md). It is a
coordination document; it does not re-derive the design choices made
in those two files.

The roadmap covers:

- the **first six-month vertical slice** in concrete week-by-week
  detail;
- the **subsequent slices** through Year 3 in high-level form;
- the **out-of-scope list** at each phase, so that scope creep is
  visible early;
- the **cross-team dependencies and risks** specific to the actor
  layer.

## 1. Premise: actor.md and tol.md are paired, not parallel

The two source documents are not independent work streams.

- `actor.md` defines protocol-level directions (§5.1 supervision,
  §5.2 time, §5.3 structured errors, §5.6 request/reply, ... ).
- `tol.md` defines the language execution path that lets contract
  authors use those directions (Q1 envelope, Q2 syntax,
  Q3 stdlib, Q4 static analysis).

By construction, **`tol.md` Q1 is the language surface of
`actor.md` §5.3 + §5.6**. `tol.md` Q2 is the language surface of
`actor.md` §5.5 + §6.5. `tol.md` Q4 carries §5.5 and §5.6 static
analysis. Year 2 and Year 3 in `tol.md` map onto §5.9, §6.5,
§5.1, §5.2, §5.4 in `actor.md`.

Both documents independently arrived at the same first-priority
item: **structured errors plus request/reply correlation**. This is
the substrate every higher-level direction depends on, and it is
therefore the right first vertical slice.

## 2. The first vertical slice: structured errors + request/reply + envelope

The first slice cuts through every layer of the stack in one
project: protocol → TVM → Tol compiler → stdlib → reference
contract → tests → docs. It implements `actor.md` §5.3 + §5.6 and
`tol.md` Q1 as a single deliverable.

### Why this slice, and not another

- **Not §5.1 (supervision) first.** Supervisors with no
  structured error format have nothing to discriminate on; they
  can only blanket-restart, which is unsafe in a financial
  setting.
- **Not §5.4 (capability addressing) first.** Research-grade work
  before bread-and-butter substrate exists leaves the team
  designing in a vacuum, with nothing to dogfood.
- **Not Q2 (`contract` / `receive` / `message`) first.** Without a
  locked envelope, op-code, query_id, and error format, the
  language baking those choices into syntax has to walk back
  shipped contracts when the protocol layer evolves.
- **Not Q3 (domain stdlib) first.** The recurring pain in the
  current stdlib is exactly query_id and error plumbing.
  Standardizing the stdlib before the envelope is locked
  guarantees a rewrite later.

This slice is the only cut that simultaneously unblocks every
upper-layer direction in `actor.md` and every upper-layer
deliverable in `tol.md`.

## 3. Pre-work: `doc/tos-message-policy.md`

Before any implementation begins, a short policy document fixes the
cross-cutting decisions that all three subsystems (protocol, TVM,
Tol) need to agree on. This is the "cross-cutting resource
semantics" item from `actor.md` §7 prioritization.

**Target length:** roughly ten pages, written in 1–2 weeks.

**It locks:**

- Wire-level envelope structure: opcode, `query_id`, `reply_to`,
  optional fields, extension reservations.
- `query_id` namespace, uniqueness, and replay rules across
  shards and across reorgs.
- Error class encoding, including the **transient vs. permanent**
  distinction (`actor.md` §5.3).
- Account lifecycle states (uninit, active, frozen, deleted) and
  the rules for what happens to scheduled or in-flight messages
  in each state.
- Bounce-message budgeting: who pays, how much is reserved at
  send time, what happens on under-funding.
- Upgrade and migration policy for already-deployed contracts
  using older message conventions.
- Compatibility rules with TEP-style standards already in use
  (jetton, NFT, wallet, etc.).

**Why it must precede implementation.** Without this document, the
three implementing subsystems will independently invent slightly
inconsistent assumptions and the integration phase will burn
weeks on reconciliation. The cost of writing it once, with all
parties present, is one to two weeks.

## 4. The six-month first slice in detail

The plan below is by week number, not calendar date. Stage gates
are sequential: a stage cannot start before the prior stage has
delivered its deliverables.

### Stage 0 — Policy lock (week 1–2)

**Owners.** Protocol architect, TVM lead, Tol compiler lead, one
contract-team representative.

**Deliverables.**

- `doc/tos-message-policy.md` published and approved by all four
  owner roles.
- A documented annotation of the existing wire surface against
  which Slice 1 will be built: both `int_msg_info$0` constructors
  in `crypto/block/block.tlb:126,135` (`CommonMsgInfo` and
  `CommonMsgInfoRelaxed`), the v12
  `new_bounce_body#fffffffe` constructor at `block.tlb:170-175`,
  and the application-layer body shape
  `opcode:uint32 query_id:uint64 payload:...` defined in
  `tos-message-policy.md` §3.1. Slice 1 introduces no new TL-B
  constructor — this deliverable is a reference document, not a
  schema change.
- A short list of TEP-compatibility commitments (which existing
  standards must keep working bit-for-bit).

**Exit criterion.** All four owners sign off; no open
inconsistencies between the document and the existing TVM and
contract surfaces.

### Stage 1 — Protocol-touching work, no wire-format change (week 3–8)

**Owners.** Protocol team, TVM team.

Slice 1 is purely an envelope-discipline and Tol-stdlib release;
**no new TVM opcode and no new bounce-body constructor** are
introduced (`tos-message-policy.md` §8.1). Application-tier
errors travel as a body-level `OP_ERROR` reply on top of the
existing v12 bounce body, not inside it. Putting `error_class`
into the bounce body itself is a schema bump (new
`new_bounce_body_v2` constructor + global-version gate +
synchronized `extra_flags` mask widening), explicitly deferred
until a future slice (`tos-message-policy.md` §5.4).

**Deliverables.**

- Lift the three hard-coded `extra_flags` magic literals
  (`crypto/block/transaction.cpp:2948`,
  `crypto/block/transaction.cpp:3632`,
  `tol/send-message-api.cpp:307-342`) into named constants
  (`EXTRA_FLAGS_NEW_BOUNCE = 1`,
  `EXTRA_FLAGS_FULL_BOUNCE_BODY = 2`,
  `EXTRA_FLAGS_RICH_BOUNCE = 3`,
  `EXTRA_FLAGS_VALID_MASK = 3`). The mask itself stays at `& 3`;
  reservation of bits 2 and 3 is documentary only
  (`tos-message-policy.md` §3.4 / §10.1).
- Reserve the `OP_ERROR = 0x00010001` opcode in the TOS
  internal-opcode registry (`tos-message-policy.md` §5.2). The
  body shape
  `(query_id, original_op, error_class, error_code, diagnostic)`
  is application-layer and lives in the Tol stdlib (Stage 2),
  not in TL-B.
- Conformance fixtures: a small fixture set of (input message,
  expected protocol behaviour) pairs covering at minimum:
  normal delivery; out-of-gas (`exit_code = -3`); frozen
  recipient with no StateInit (`bounced_by_phase = 0`,
  `exit_code = -1`); frozen recipient with mismatched StateInit
  (`exit_code = -2`); compute-phase exception (`bounced_by_phase
  = 1`); action-phase failure (`bounced_by_phase = 2`); an
  inbound message with `extra_flags = 0b0100` rejected by the
  `& 3` mask (`tos-message-policy.md` §10.1). Each fixture
  asserts the §6.2 conditional-bounce predicates: bounce only
  emitted when inbound `bounce=true` AND remaining value covers
  `fwd_fee` (`crypto/block/transaction.cpp:921 / :3522 /
  :3608`).

**Exit criterion.** The existing TVM test suite still passes
unchanged (no schema regressions); the named-constants refactor
is checked in with the synchronized-constants hardening grep
described in `tos-message-policy.md` §3.4; conformance fixtures
are checked into the repository.

### Stage 2 — Tol compiler support (week 9–14)

**Owners.** Tol compiler team.

**Deliverables.**

- An `Envelope` struct in the Tol standard library with
  auto-derived pack/unpack code matching the Stage 0 TL-B schema.
- A structured `Error` type in Tol, with a `throw` form that
  emits a properly classified bounce instead of a flat error
  code.
- A new compiler pass under `tol/pipe-check-*.cpp` that warns
  when a `query_id`-bearing inbound message is handled without
  the `query_id` being either propagated to a reply or
  explicitly disclaimed. This is the smallest piece of §5.6
  static analysis that is actionable today.
- Compiler integration with the Stage 1 conformance fixtures so
  that compiled contracts can be replayed against them.

**Exit criterion.** A Tol contract written against the new
envelope compiles, deploys to a local test net, and round-trips
the conformance fixtures with no manual op-code plumbing.

**What is explicitly not in this stage.** The `contract`,
`receive(...)`, and `message` keywords (those are Q2 / second
slice). Stage 2 ships only the envelope struct, the error type,
and the static check — not the high-level syntax sugar.

### Stage 3 — Reference contract migration (week 15–20)

**Owners.** Contract team, with Tol compiler team support.

The migration order is the audit-driven recommendation from
`tos-message-policy.md` §10.1 (smallest delta first so the
playbook accumulates confidence before the largest contract):

**Deliverables.**

1. **`jetton-minter`** — smallest, paired with `jetton-wallet`,
   estimated ~45 LOC touched. Establishes the basic
   `Envelope` + `OP_ERROR` rewrite pattern.
2. **`jetton-wallet`** — ~80 LOC; first contract that exercises
   the bounce-handler delta (`onBouncedMessage` parsing the
   v12 bounce body's `original_body` for the original opcode).
3. **`wallet-v5`** — ~110 LOC, ~16 distinct error codes that
   need classifying into `error_class` values from
   `tos-message-policy.md` §5.3. Last because the error
   classification has the most discretion and benefits from
   what the first two contracts teach.

A migration playbook captured from doing the three rewrites:
what parts of the old code disappear, what compiler errors come
up most often, what the bytecode-size delta looks like, and what
the `error_class` mapping convention is for hand-rolled error
codes.

**Exit criterion.** All three reference contracts deploy and
pass their existing test suites unchanged; bytecode-size delta
is recorded for each (against the §10.1 ≤ 15% budget); the
migration playbook is checked in under `doc/`.

### Stage 4 — Conformance, fuzzing, gas regression (week 21–24)

**Owners.** QA, with protocol team support.

**Deliverables.**

- Conformance test suite extended to cover the migrated
  reference contracts as black-box senders / receivers.
- Property-based fuzzing of envelope encoding/decoding:
  arbitrary in-bounds messages must round-trip; arbitrary
  out-of-bounds messages must be rejected with a documented
  error class.
- Gas-regression dashboard: the migrated contracts' gas costs are
  tracked against their pre-migration baselines, and any
  regression beyond a documented threshold (recommend 10%) is a
  blocker for slice acceptance.

**Exit criterion.** No outstanding fuzz crashes; gas regressions
are within budget or have a documented justification.

### Stage 5 — Migration documentation and external RFC (week 25–26)

**Owners.** Documentation, with the architects from Stage 0.

**Deliverables.**

- **Internal migration playbook** — extends the Stage 3
  playbook into a publishable contract-author guide. Lives at
  `doc/tos-message-envelope-migration.md` (the file is created
  in this stage; do not confuse it with the policy itself at
  `doc/tos-message-policy.md`). Contents: how an existing
  TEP-style contract (jetton, NFT, wallet-vN) upgrades to the
  Slice 1 `Envelope` library and the `OP_ERROR` reply
  convention, with concrete diffs lifted from the three
  Stage 3 rewrites. No wire-format changes are described — this
  is purely a developer-experience migration.
- **External RFC** announcing the `Envelope`, `Error`, and
  `OP_ERROR` conventions; the `0xfffffffe` collision caveat
  (`tos-message-policy.md` §3.2); and the §8.1 commitment that
  Slice 1 ships zero wire-format changes. The RFC has no
  "activation height" because there is nothing to activate at
  the protocol layer; what activates per-contract is the opt-in
  three-step path in `tos-message-policy.md` §8.2.
- Changelog and release-notes entries.

**Exit criterion.** Migration playbook reviewed by an external
contract author; RFC posted; release notes attached to the slice
release tag.

## 5. First-slice deliverables checklist

By end of week 26, the following must all be true:

- [ ] `doc/tos-message-policy.md` exists and is approved by all
      four §12 owners.
- [ ] `doc/tos-message-envelope-migration.md` exists (Stage 5
      contract-author migration playbook).
- [ ] The two `extra_flags & 3` magic literals in
      `crypto/block/transaction.cpp:2948,3632` and the
      `BounceMode` literals in `tol/send-message-api.cpp:307-342`
      are replaced by named constants
      (`EXTRA_FLAGS_NEW_BOUNCE / _FULL_BOUNCE_BODY /
      _RICH_BOUNCE / _VALID_MASK`); the synchronized-constants
      hardening grep is wired in.
- [ ] The Tol standard library exposes `Envelope` and `Error`
      types with auto-derived serializers, the
      `disclaim_query_id()` builtin, and the `OP_ERROR` reply
      helper.
- [ ] `tol/pipe-check-query-id-propagation.cpp` enforces
      `query_id` propagation at Tol compile time, injected
      between `pipeline_check_serialized_fields()` (line 83)
      and `G.error_collector = nullptr;` (line 102) per
      `tos-message-policy.md` §4.4.
- [ ] All three reference contracts (jetton-minter →
      jetton-wallet → wallet-v5) are rewritten in Tol against
      the new `Envelope` library and continue to pass their
      pre-migration test suites; bytecode-size delta is within
      the §10.1 ≤ 15% budget for each.
- [ ] Conformance fixtures (Stage 1) and BoC / Envelope fuzzing
      (Stage 4) run in CI.
- [ ] Gas regressions are documented and within budget.
- [ ] An external RFC has been published with the
      §8.1 zero-wire-change commitment explicitly called out.

If any one of these is missing, the slice is not done. Slipping
the boundary creates exactly the cross-layer inconsistency this
slice is designed to prevent.

## 6. Subsequent slices

The following are sequenced but described at a coarser grain
because their detail will follow from what the first slice teaches.

### Slice 2 — Q2 syntax, weeks 27–52 (six months)

Deliver `tol.md` Q2: `contract`, `receive(...)`, `message`
keywords, and the early form of state-aware dispatch (`receive(...)
on State`). The envelope from Slice 1 is the wire format these
keywords compile to; nothing in the wire format changes.

This slice also begins the first of the §5.5 static-analysis
features: exhaustiveness checking of `receive` handlers. Full
exhaustiveness checking lands in Slice 3.

### Slice 3 — Q3 + Q4, weeks 53–78 (six months)

Deliver `tol.md` Q3 (domain stdlib: jetton, NFT, ownable, wallet,
multisig) and Q4 (full §5.5 exhaustiveness, scaffolding CLI,
test harness, "TVM model for Solidity developers" guide). The
official reference contracts migrated in Slice 1 are now rewritten
again, this time using the Slice 2 high-level syntax and the
Slice 3 stdlib. The double-migration is intentional: it forces the
team to feel the cost of each abstraction layer separately.

### Slice 4 — §5.9 + §6.5, Year 2 H1

Deliver bounded postponement (`actor.md` §5.9) and trait-based
behaviour patterns (§6.5). These are language-and-stdlib slices
with limited protocol exposure.

### Slice 5 — second-wave stdlib, Year 2 H2

Auction, DAO/governance, oracle, and payment-channel templates,
each one preceded by a short design note. Cross-language ABI is
frozen at the end of this slice.

### Slice 6 — Year 3 protocol-heavy items

`actor.md` §5.1 (supervision) and §5.2 (time primitive) become
implementable once Slices 1–4 are in production. §5.4 (capability
addressing) remains research-only until a public design document
is approved.

## 7. Out of scope at each phase

| Phase | Out of scope |
|---|---|
| Slice 1 | high-level Tol syntax (`contract` / `receive`); supervision; scheduled messages; capability handles; new domain stdlib |
| Slice 2 | exhaustiveness for state machines (still informal); domain stdlib; behaviour traits |
| Slice 3 | supervision; scheduled messages; capability handles |
| Slice 4 | supervision; scheduled messages |
| Slice 5 | capability handles |
| Slice 6 | none of the above (all unblocked) |

A phase boundary is the right place to say no. Pulling Slice 4
work into Slice 1 is exactly the failure mode this roadmap is
designed to prevent.

## 8. Cross-team dependencies and risks

| Risk | Mitigation |
|---|---|
| Stage 0 policy doc gets weak sign-off and reopens during implementation. | Stage 0 has explicit owners and a single approval gate; no Stage 1 work begins until sign-off is recorded in the document. |
| TVM v12 full-bounces work conflicts with Slice 1 envelope. | Stage 1 explicitly aligns with the existing v12 work rather than competing with it; the TVM lead is one of the four Stage 0 owners. |
| Slice 1 ships only an envelope, with no high-level syntax, and contract authors find it underwhelming. | Slice 1 is positioned in external communication as a substrate release, not a developer-experience release. The DX win lands in Slice 2. |
| The migrated reference contracts in Stage 3 expose envelope-design defects that force a Stage 1 rewrite. | This is acceptable cost. Better to find the defects in Stage 3 than after external contracts depend on the format. The 26-week budget includes a notional two-week return path to Stage 1 if needed. |
| Slice 2 starts before Slice 1 has actually shipped externally. | Slice 2 design work can begin in parallel, but Slice 2 implementation requires a Slice 1 release tag. The roadmap is written with sequential implementation gates. |
| Tol compiler team is the bottleneck across multiple slices. | Stages 2 and 3 of Slice 1 are scheduled non-overlapping with Slice 2 design discussion; subsequent slices reuse the Stage 2 patterns rather than re-deriving them. |

## 9. Success criteria per slice

| Slice | Pass / fail criterion |
|---|---|
| Slice 1 | All ten checklist items in §5 are checked. |
| Slice 2 | At least one new official reference contract is written from scratch using `contract` / `receive(...)` / `message`, deploys, and passes its test suite. |
| Slice 3 | A new contract author can produce a working Jetton or NFT in under one hour using `tol new`, the stdlib, and the documentation. |
| Slice 4 | Bounded postponement is used by at least one shipped contract; traits cover at least three official reference contracts without bytecode regression beyond the Slice 1 budget. |
| Slice 5 | The second-wave stdlib is used by at least three external production contracts. |
| Slice 6 | Supervision, scheduled messages, and structured errors are in production on at least one workchain and used by at least one official system contract. |

## 10. Closing framing

The TOS actor layer is not a research project. The protocol shape
is fixed by `actor.md`, the language path is fixed by `tol.md`,
and the work that turns those documents into shipped behavior is
sequenced here.

The single most important property of this roadmap is that the
**first slice cuts through all layers**. Half-slices that ship a
protocol change without language support, or a language feature
without protocol support, are the historical failure mode of
multi-layer systems. The 26-week first slice exists to avoid that
mode. Every later slice depends on it.

The right first action is to start writing
`doc/tos-message-policy.md`.

## 11. Revision notes

### r1 (post-policy-v5 alignment)

A four-document consistency review against
`doc/tos-message-policy.md` v5, `doc/actor.md`, and `doc/tol.md`
caught five places where this roadmap was inconsistent with the
locked policy. The original sequencing and stage budgets are
unchanged; r1 only corrects deliverable wording so the four
documents agree on what Slice 1 actually ships.

- **Stage 0** — "TL-B schema draft for the new envelope and
  bounce body" replaced with "annotation of the existing wire
  surface". Slice 1 introduces no new TL-B constructor; the
  Stage 0 deliverable is a reference document over the existing
  v12 schema (`policy.md` §8.1).
- **Stage 1** — "TVM bounce-action format updated to carry the
  structured error payload" replaced with the application-tier
  `OP_ERROR` reply on top of the existing v12 bounce body. The
  Stage 1 deliverable list now matches the
  `policy.md` §10.1 implementable subset: lift the
  `extra_flags` magic literals into named constants, reserve
  the `OP_ERROR` opcode in the TOS registry, ship the
  conformance fixtures (including the §6.2 conditional-bounce
  predicates and the `extra_flags=0b0100` rejection case).
  Putting `error_class` into the bounce body remains future
  work, gated by a new `new_bounce_body_v2` constructor and
  global-version bump per `policy.md` §5.4.
- **Stage 3** — Two-contract recommendation (wallet-v5 +
  simplest jetton wallet) replaced with the canonical
  three-contract list from `policy.md` §10.1: jetton-minter →
  jetton-wallet → wallet-v5. Order is smallest-delta-first so
  the migration playbook accumulates confidence before the
  largest contract.
- **Stage 5 deliverables** — The `doc/tos-message-migration.md`
  filename was overloaded against the policy doc itself; the
  Stage 5 contract-author guide is now
  `doc/tos-message-envelope-migration.md`. The external RFC
  no longer references an "activation height" because there
  is nothing to activate at the protocol layer in Slice 1.
- **§5 checklist** — Items aligned with the corrected stage
  deliverables: "TL-B envelope schema" and "TVM bounce format
  carries structured errors" replaced with the named-constants
  refactor + synchronized-constants hardening grep, plus the
  `OP_ERROR` opcode reservation. The reference-contract item
  is updated to require all three migrations within the §10.1
  ≤ 15% bytecode-overhead budget.

No stage week ranges, owners, or success criteria changed.
