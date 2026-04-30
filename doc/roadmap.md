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

### Stage 0 — Policy lock (week 1–2) ✅ Completed 2026-04-29

**Status.** ✅ Completed 2026-04-29 — `tos-message-policy.md` v6
approved by single-signer (`gtosnetwork-dotcom`) per §12; all four
audit-derived open questions resolved with evidence; wire-surface
annotation in §2.1 covers both `int_msg_info$0` constructors and
the v12 bounce body. Slice 1 implementation unblocked.

**Owners.** Protocol architect, TVM lead, Tol compiler lead, one
contract-team representative.

**Deliverables.**

- `doc/tos-message-policy.md` published and approved by the
  authorized owner of record (single-signer model per
  `tos-message-policy.md` §12; v6 onwards).
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

**Exit criterion.** Authorized owner signs off (`policy.md` §12);
no open inconsistencies between the document and the existing
TVM and contract surfaces.

### Stage 1 — Protocol-touching work, no wire-format change (week 3–8) ✅ Completed 2026-04-29

**Status.** ✅ Completed 2026-04-29 — see `actor-layer` branch
commits `d92d4fa12..40f69bec9` (13 conformance fixtures + 4
pre-existing emulator tests pass: `17 test(s) passed`). Magic
literals lifted into named constants in `tol/extra-flags-constants.h`;
synchronized-constants hardening grep enforced via
`Slice1ExtraFlagsFixtures.F3_3_synchronized_constants_self_check`;
`OP_ERROR = 0x00010001` reserved in
`crypto/smartcont/tol-stdlib/common.tol` and mirrored in
`crypto/smartcont/tol-stdlib/envelope.tlb`. Wire format unchanged;
§8.1 commitments preserved.

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

### Stage 2 — Tol compiler support (week 9–14) ✅ Completed 2026-04-29

**Status.** ✅ Completed 2026-04-29 — three deliverables landed
in parallel on `actor-layer`:

- **S2-A check pass body** (commit `73e3f117d`): replaced the
  TODO(slice-1) skeleton with a full AST visitor that detects
  `lazy <Struct>.fromSlice(in.body)` envelope binding,
  `createMessage<TBody>` reply emission, and
  `disclaim_query_id()` opt-out, then emits `Error::warning(...)`
  diagnostics referencing policy v6 §4.4.
- **S2-B tol-tester cases** (commit `13ae8cc89`): four `.tol`
  test files under `tol-tester/tests/`
  (`query-id-{propagation-positive,propagation-missing,disclaim,no-envelope}.tol`)
  exercising the four expected behaviours of the check pass.
- **S2-C end-to-end round-trip** (commit `d8debf814`): a minimal
  `crypto/smartcont/echo-envelope.tol` contract that uses the
  new Envelope library + an `emulator/test/slice-1-stage-2-roundtrip-fixture.cpp`
  asserting the inbound `query_id` is propagated verbatim to
  the outbound reply. Closes the Stage 2 exit criterion (a Tol
  contract that compiles and round-trips the Stage 1 conformance
  fixtures).

Test surface as of close: **19/19 emulator fixtures pass**
(F1×7 + F2×3 + F3×3 + F1.aux + Stage 2 round-trip×2 + 4
pre-existing emulator-tests cases) and **553/553 tol-tester
cases pass** (549 pre-existing + 4 S2-B cases).

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

### Stage 3 — Reference contract migration (week 15–20) ✅ Complete

**Status.** ✅ Complete as of 2026-04-30 — all three reference
contracts have Tol migrations on `actor-layer`: Stage 3.1
`jetton-minter` (commit `af809de44`), Stage 3.2 `jetton-wallet`,
and Stage 3.3 `wallet-v5`. The migrations preserve the FunC
reference contracts, record §5.3 error-class tables in the Tol file
headers, and meet the §10.1 bytecode budget:
`jetton-minter` **FunC 11 cells / Tol 9 cells / ratio 0.82**;
`jetton-wallet` **FunC 17 cells / Tol 10 cells / ratio 0.59**;
`wallet-v5` **FunC 20 cells / Tol 22 cells / ratio 1.10**.
Follow-up Tol compiler ergonomics exposed by the minter migration
also landed on `actor-layer` (commit `bf09e60fd`): const / enum
`struct(...)` opcode tags, const / string `@method_id`, bounced
ignore policy, and manual-parse `query_id` propagation analysis.
A later ergonomics fix (commit `02197a2c0`) allows auto-unpack of
tail-position `slice` fields, so stdlib `Envelope.fromSlice(...)`
now parses `Envelope.payload: slice` directly instead of requiring
a local `RemainingBitsAndRefs` surrogate.

**Owners.** Contract team, with Tol compiler team support.

The migration order is the audit-driven recommendation from
`tos-message-policy.md` §10.1 (smallest delta first so the
playbook accumulates confidence before the largest contract):

**Deliverables.**

1. ✅ **`jetton-minter`** — completed 2026-04-30 in
   `crypto/smartcont/jetton-minter.tol` with three tol-tester
   cases (`jetton-minter-{positive,auth-fail,unknown-opcode}.tol`).
   Establishes the basic `Envelope` + `OP_ERROR` rewrite pattern
   and the first bytecode-delta measurement.
2. ✅ **`jetton-wallet`** — completed 2026-04-30 in
   `crypto/smartcont/jetton-wallet.tol` with three tol-tester
   files (`jetton-wallet-{positive,auth-fail,protocol-fail}.tol`).
   First migration that exercises the bounce-handler delta
   (`onBouncedMessage` parsing the bounced-body prefix and
   original opcode). Bytecode delta: FunC 17 cells / Tol 10
   cells / ratio 0.59.
3. ✅ **`wallet-v5`** — completed 2026-04-30 in
   `crypto/smartcont/wallet-v5.tol` with three tol-tester files
   (`wallet-v5-{positive,error-map,protocol-fail}.tol`). Preserves
   wallet-v5's signed external/internal request bodies and C5
   action-list validation per policy §9.3 while classifying all
   FunC throw sites into §5.3 `error_class` values. Bytecode delta:
   FunC 20 cells / Tol 22 cells / ratio 1.10.

A migration playbook captured from doing the three rewrites:
what parts of the old code disappear, what compiler errors come
up most often, what the bytecode-size delta looks like, and what
the `error_class` mapping convention is for hand-rolled error
codes. The first playbook fragment is now embedded in the
`jetton-minter.tol`, `jetton-wallet.tol`, and `wallet-v5.tol`
headers; the standalone Stage 5 document can now be written from
the completed migration examples.

**Exit criterion.** All three reference contracts deploy and
pass their focused Tol migration tests plus the existing emulator
suite; bytecode-size delta is recorded for each against the
§10.1 ≤ 15% budget. The standalone migration playbook remains the
Stage 5 documentation deliverable.

### Stage 4 — Conformance, fuzzing, gas regression (week 21–24) 🚧 In progress

**Status.** 🚧 In progress as of 2026-04-30. Slice 1 conformance
fixtures exist (`emulator/test/slice-1-*-fixtures.cpp`, now 15
cases) and the Slice 1 CI gate is wired: it compiles the migrated
Tol reference contracts, runs full `tol-tester`, runs the Slice 1
emulator fixtures through `test-emulator`, runs a deterministic
Envelope / `OP_ERROR` fuzz smoke in Tol, and runs deterministic
BoC / Envelope fuzz smoke through the emulator fixture suite.
The focused Tol gas-regression gate now exists, but final
pre-migration FunC black-box gas baselines are not yet available.
The deterministic Envelope fuzz now exercises the real stdlib
`Envelope.fromSlice(...)` path after commit `02197a2c0`, including
tail-position `slice` auto-unpack coverage.

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

### Stage 5 — Migration documentation and external RFC (week 25–26) 🚧 In progress

**Status.** 🚧 In progress as of 2026-04-30. The internal
contract-author migration playbook exists at
`doc/tos-message-envelope-migration.md`, drafted from the three
Stage 3 reference migrations in commit `6d9520348`. The external
RFC, changelog, and release notes have not been published.

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

By end of week 26, the following must all be true. Status as of
2026-04-30 noted inline; commit references are on the `actor-layer`
branch.

- [x] `doc/tos-message-policy.md` exists and is approved by the
      §12 authorized owner. *(v6, single-signer
      `gtosnetwork-dotcom`, 2026-04-29; commit `ea5869adf` then
      v6 governance refinement in `063f44f4b`.)*
- [x] `doc/tos-message-envelope-migration.md` exists (Stage 5
      contract-author migration playbook). *(Drafted 2026-04-30
      from the three Stage 3 migrations in commit `6d9520348`;
      external RFC and release notes remain pending.)*
- [x] The two `extra_flags & 3` magic literals in
      `crypto/block/transaction.cpp:2948,3632` and the
      `BounceMode` literals in `tol/send-message-api.cpp:307-342`
      are replaced by named constants
      (`EXTRA_FLAGS_NEW_BOUNCE / _FULL_BOUNCE_BODY /
      _RICH_BOUNCE / _VALID_MASK`); the synchronized-constants
      hardening grep is wired in. *(commits `156e92247`
      Tol-IR side, `9541d022e` transaction.cpp annotations,
      `83c01c672` Tol-stdlib mirror in `common.tol`; F3.3
      hardening grep in `slice-1-extra-flags-fixtures.cpp`
      passes.)*
- [x] The Tol standard library exposes `Envelope` and `Error`
      types with auto-derived serializers, the
      `disclaim_query_id()` builtin, and the `OP_ERROR` reply
      helper. *(commits `83c01c672` `common.tol` types,
      `f48a11533` `disclaim_query_id` builtin stub,
      `402f944a3` `envelope.tlb` reference doc. Compiler support
      for direct `Envelope.fromSlice(...)` on
      `payload: slice` landed in `02197a2c0`, with positive and
      negative tol-tester coverage for tail-position `slice` fields.)*
- [x] `tol/pipe-check-query-id-propagation.cpp` enforces
      `query_id` propagation at Tol compile time, injected
      between `pipeline_check_serialized_fields()` (line 83)
      and `G.error_collector = nullptr;` (line 102) per
      `tos-message-policy.md` §4.4. *(Skeleton at correct band
      in `d92d4fa12`; full visitor body in `73e3f117d`; four
      tol-tester cases in `13ae8cc89` validate positive /
      missing / disclaim / no-envelope behaviours. Manual-parse
      propagation coverage added in `bf09e60fd`.)*
- [x] All three reference contracts (jetton-minter →
      jetton-wallet → wallet-v5) are rewritten in Tol against
      the new `Envelope` library and continue to pass their
      pre-migration test suites; bytecode-size delta is within
      the §10.1 ≤ 15% budget for each. *(Stage 3 complete:
      `jetton-minter` completed in `af809de44` with FunC 11
      cells / Tol 9 cells / ratio 0.82; `jetton-wallet`
      completed with FunC 17 cells / Tol 10 cells / ratio 0.59;
      `wallet-v5` completed with FunC 20 cells / Tol 22 cells /
      ratio 1.10.)*
- [x] Conformance fixtures (Stage 1) and BoC / Envelope fuzzing
      (Stage 4) run in CI. *(Stage 1 fixtures exist and pass
      locally — `slice-1-{account-state,failure-phase,extra-flags}-fixtures.cpp`,
      13 cases, commits `5e7c21bc7`, `33b30ccc5`, `69b275817`,
      registered into `test-emulator` in `dd3acfc83` + linker
      fix `40f69bec9`. CI integration added in
      `.github/workflows/slice-1-conformance.yml`, with
      `slice-1-envelope-fuzz-smoke.tol` covering deterministic
      stdlib `Envelope.fromSlice(...)` / `OP_ERROR` fuzz and
      `slice-1-boc-envelope-fuzz-fixture.cpp` covering deterministic
      BoC / Envelope fuzz inside `test-emulator`.)*
- [x] Gas regressions are documented and within budget.
      *(Stage 4 — closed 2026-04-30 by the FunC↔Tol parity harness
      in
      [`emulator/test/slice-1-stage-4-gas-parity-fixture.cpp`](../emulator/test/slice-1-stage-4-gas-parity-fixture.cpp),
      schema v2 dual baselines in
      [`doc/slice-1-gas-baselines.json`](slice-1-gas-baselines.json),
      and the widened
      [`scripts/check-slice-1-gas.py`](../scripts/check-slice-1-gas.py)
      gate. Closure spec from
      [`doc/slice-1-gas-gap.md`](slice-1-gas-gap.md) §4 fully met;
      see that file's §7 closure note for the per-contract ratios
      and the per-contract `func_vs_tol_ratio_threshold` policy
      (1.15 for jetton-minter / jetton-wallet, 1.35 for wallet-v5
      because of its +10% bytecode growth). The `slice-1-gas-gap.md`
      file is preserved as a historical record but is no longer
      load-bearing for this checkbox.)*
- [x] An external RFC has been published with the
      §8.1 zero-wire-change commitment explicitly called out.
      *(Published 2026-04-30 at
      [`doc/slice-1-rfc.md`](slice-1-rfc.md); commit `83eb22e71`.)*

**Progress as of 2026-04-30:** 9 of 9 checked — Slice 1 is
**complete on the §5 deliverables checklist**. Stage 3 has all 3
reference-contract migrations complete (`jetton-minter`,
`jetton-wallet`, `wallet-v5`); the Stage 5 internal migration
playbook is in tree; the Stage 5 external RFC was published at
[`doc/slice-1-rfc.md`](slice-1-rfc.md); Stage 4 CI conformance and
fuzzing is wired; the former Tol workaround for
`Envelope.payload: slice` is resolved in `02197a2c0`; the focused
tol-tester suite now covers 571 cases. The Stage 4 gas-parity gap
that was the last remaining blocker is closed by the FunC↔Tol
parity harness in
[`emulator/test/slice-1-stage-4-gas-parity-fixture.cpp`](../emulator/test/slice-1-stage-4-gas-parity-fixture.cpp)
plus the widened
[`scripts/check-slice-1-gas.py`](../scripts/check-slice-1-gas.py)
gate; the historical
[`doc/slice-1-gas-gap.md`](slice-1-gas-gap.md) record retains the
§4 closure-spec walkthrough.

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

**Status.** 🚧 In progress as of 2026-04-30. The Slice 2 syntax
policy input exists at `doc/tos-language-syntax-policy.md`
(Draft v3, post-v2-security-review). Stages 0–7 have landed on
`actor-layer`; the compiler implementation commits are Stage 1
(`081f05d3c`), Stage 2 (`cc6656ce9`), Stage 3
(`aeafe7906` merged via `8e6b3a3f8`), Stage 4
(`f697390d3` merged via `4ed03f313`), Stage 5 (`21b3f8a03`
merged via `6f188fdcf`), Stage 6 (`c7d9448eb` merged via
`b962f7254`), and Stage 7 (`2e01919ee` merged via
`c6bb72fc2`). Stage 8 is in progress: `jetton-minter` was
re-migrated in `38856e950`, and `jetton-wallet` was re-migrated
in `bd851ebb4`; `wallet-v5` remains. The current regression
suite reports 616/616 tol-tester pass, 24/24 test-emulator pass,
and the FunC↔Tol gas-parity gate green for all three Slice 1
reference contracts.

**Implementation stages.**

1. ✅ **Stage 0 — syntax policy RFC / implementation input.**
   `doc/tos-language-syntax-policy.md` exists and has been
   revised through v3 after the security-review closure pass.
   It locks the Stage 1 subset against §3.1 / §3.2 / §4.1 /
   §6.1 / §10.1 for implementation on `actor-layer`.
2. ✅ **Stage 1 — minimum `contract` / `receive` parser +
   lowering.** Completed 2026-04-30 in commit `081f05d3c`.
   Ships lexer tokens `contract` / `receive` / `storage`,
   AST nodes for contract declarations and receive blocks,
   parser support for
   `contract X { storage: S; receive(msg: T)+ }`, explicit
   rejection of the deferred Slice 2 features, a new
   `tol/pipe-lower-contract.cpp` pass that synthesizes the
   simple no-state/no-`@deploy` `onInternalMessage` dispatcher,
   32-bit receive opcode-prefix enforcement, and five new
   `tol-tester/tests/contract-*.tol` cases. Verification at
   close: `tol` target builds, `576/576` tol-tester cases pass,
   `24 test(s) passed` in `test-emulator`, Slice 1 gas gate
   remains green, and `git diff --check` is clean.
3. ✅ **Stage 2 — states / `become` / `keep_state` /
   reachability.** Completed 2026-04-30 in commit `cc6656ce9`.
   Ships parser support for `states:`, `@initial state`,
   `receive(...) on State`, `become`, and `keep_state`; a new
   `tol/pipe-check-state-reachability.cpp` pass for declared
   states, initial-state singleton, receiver state clauses,
   tail-position transition discipline, hidden `__state`
   namespace protection, and reachability from `@initial`; and
   state-aware lowering that synthesizes an internal state enum
   plus `__<Contract>StateData` wrapper while leaving the user
   storage struct unchanged. Adds seven `contract-state-*.tol`
   tol-tester cases. Verification at close: `tol` target builds,
   `583/583` tol-tester cases pass, `24 test(s) passed` in
   `test-emulator`, Slice 1 gas gate remains green, and
   `git diff --check` is clean.
4. ✅ **Stage 3 — `@on` + field-scoping / taint analysis.**
   Completed 2026-04-30 in commit `aeafe7906` (worktree
   contribution) merged to `actor-layer` as `8e6b3a3f8`. Adds
   `@on(State1, State2)` annotation parsing on storage struct
   fields, a new `tol/pipe-check-field-scoping.cpp` pass
   (registered between `pipe-check-state-reachability` and
   `pipe-lower-contract`) with taint propagation across local
   aliases, tuple/pattern destructure, free-function passthrough
   rejection (conservative Stage 3 approximation), and the
   explicit c4-serialization-escape check. Adds 7
   `contract-on-*.tol` tol-tester cases (1 positive, 6 negative).
5. ✅ **Stage 4 — `@deploy` + unknown-opcode modes.**
   Completed 2026-04-30 in commit `f697390d3` (worktree
   contribution) merged to `actor-layer` as `4ed03f313`. Adds
   parser/lowering support for `@deploy receive(...)`,
   `@unknown_throw(N)`, `@unknown_silent_drop`, and
   `receive(msg: UnknownOpcode)`; enforces the deploy-specific
   restrictions around `@disclaim_query_id`, state clauses,
   multiple deploy receivers, and `become`/`keep_state`; and
   injects the initial state tag for state-bearing deploy saves.
   Adds 11 `contract-deploy-*` / `contract-unknown-*`
   tol-tester cases.
6. ✅ **Stage 5 — get functions + `method_id` collision
   detector.** Completed 2026-04-30 in commit `21b3f8a03`
   (worktree contribution) merged to `actor-layer` as
   `6f188fdcf`. Adds `get fun X(): T { ... }` inside contract
   blocks, parser fix at `tol/ast-from-tokens.cpp:1712` (now
   accepts `@method_id` on contract `get fun`), auto-derived
   `method_id` via `crc16(name) | 0x10000`, per-contract
   collision detector at `tol/pipe-generate-fif-output.cpp:255-261`
   covering both auto-derived and `@method_id`-pinned IDs, and
   read-only `get fun` body enforcement. Adds 5
   `contract-getfun-*.tol` tol-tester cases.
7. ✅ **Stage 6 — `receive_external` + `require`
   auto-numbering.** Completed 2026-04-30 in commit `c7d9448eb`
   (worktree contribution) merged to `actor-layer` as
   `b962f7254`. Adds `receive_external(...)` parsing/lowering,
   external-only opcode-prefix and duplicate-opcode checks, the
   `onExternalMessage(inMsgBody: slice)` entrypoint, and
   `require(...)` auto-numbering grouped per contract and
   `ErrorClass` while preserving the 3-arg pass-through form for
   pinned legacy exit codes. Adds 7 `contract-external-*` /
   `contract-require-*` tol-tester cases.
8. ✅ **Stage 7 — per-receiver `disclaim_query_id` rewrite.**
   Completed 2026-04-30 in commit `2e01919ee` (worktree
   contribution) merged to `actor-layer` as `c6bb72fc2`.
   Closes the codex security review v2 HIGH defect on §3.2.1.
   Introduces the synthetic `ast_receiver_scope_marker` AST kind
   emitted by `tol/pipe-lower-contract.cpp` around each lowered
   receive-branch body; rewrites
   `tol/pipe-check-query-id-propagation.cpp` to maintain a stack
   of per-scope `ScopeRecord`s so receiver A's
   `@disclaim_query_id` no longer silences receiver B. Adds
   parser support for `@disclaim_query_id` on `receive(...)`
   blocks. Adds 3 `contract-disclaim-*.tol` tol-tester cases.
9. 🚧 **Stage 8 — dogfood remigration of jetton-minter /
   jetton-wallet / wallet-v5.** In progress. `jetton-minter`
   was re-migrated to `contract` / `receive` / contract-local
   `get fun` syntax in commit `38856e950` (Stage 8a), preserving
   the hand-packed outbound body shapes and `@unknown_throw(0xffff)`
   legacy unknown-opcode behavior. `jetton-wallet` was re-migrated
   in commit `bd851ebb4` (Stage 8b): the three internal receive
   paths now use `@disclaim_query_id receive(...)`, the getter is
   contract-local, bounced-message handling keeps its file-scope raw
   c4 helper, and the lowering no longer emits an unreachable
   trailing `return` after terminal unknown-opcode tails. `wallet-v5`
   remains the final Stage 8 reference-contract migration.

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
| Slice 1 | All nine checklist items in §5 are checked. |
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

## 11. Known unscheduled work and cross-Slice blockers

This section makes the gaps in §6 explicit so they are not silently
forgotten between slices. Every entry below is something the
implementation cannot rely on existing — either no slice owns it,
or the slice that nominally owns it is missing prerequisite design
work.

This section is updated as items move from "unscheduled" to
"scheduled in Slice N"; do not delete entries when they land —
move them to a "Closed" subsection at the bottom of §11 with a
pointer to the slice and PR that resolved them.

### 11.1 `actor.md` sections not yet scheduled in any slice

The Slice 1–6 plan in §6 covers `actor.md` §5.1, §5.2, §5.3, §5.4,
§5.5, §5.6, §5.9, and §6.5. The remaining seven directions are
unscheduled at the time of writing:

| `actor.md` § | Content | Downstream impact | Recommended placement |
|---|---|---|---|
| §5.7 | Cross-shard delivery SLA + dead-letter handling | Blocks `error_class = 5` (back-pressure) emission (`policy.md` §5.3); blocks Slice 4 `§5.9` postponement design (postpone-expiry semantics depend on undeliverable definition); blocks Slice 6 supervision (failure-class taxonomy) | Pre-design RFC during Slice 1 Stage 4–5; protocol implementation slot inserted between Slice 4 and Slice 5 |
| §5.8 | Actor-level observability | Operational debuggability blocker once supervised contracts exist; off-chain indexer surface usable independently of on-chain protocol work | Off-chain part: pulled forward to Slice 3 (alongside `tol new` scaffolding). On-chain hooks: bundled into Slice 6. |
| §6.1 | Release handling and upgrade discipline | TOS already has `SETCODE`-style behaviour replacement; the missing part is operational discipline (compatibility windows, rollback, state-migration proofs). Becomes load-bearing the moment Slice 6 ships supervision-driven restarts. | Pre-design during Slice 4–5; production rollout adjacent to Slice 6. |
| §6.2 | Application boundaries / lifecycle (validator subsystem, workchain, system-contract package) | Without this, every multi-subsystem upgrade is hand-coordinated. Compounds with §6.1. | Same window as §6.1. |
| §6.3 | Monitors versus links (one-way observation vs bidirectional failure) | Slice 6's nominal scope only lists §5.1; without §6.3 the supervision design has only a single coarse `supervisor` field. | **Promote into Slice 6 scope explicitly** — current §6 row reads `§5.1 + §5.2 + §5.4` but needs to read `§5.1 + §5.2 + §5.4 + §6.3 + §6.4 + §6.6`. |
| §6.4 | Restart intensity / circuit breakers | Same — supervision without restart-intensity limits is a message-amplification attack surface. | Promote into Slice 6 scope. |
| §6.6 | Crash reports / `sys`-style diagnostics | "Let it crash" is unsafe without classified, bounded crash reports. | Promote into Slice 6 scope. |

`§6.3 / §6.4 / §6.6` should be folded into §6's Slice 6 row in a
later revision rather than continuing to live in this gap table.
The table here is the holding pen until that update lands.

### 11.2 Per-Slice blockers

Each downstream slice has at least one blocker that is not yet
resolved. None invalidates the §6 sequencing; all must be cleared
before the corresponding slice can start.

**Slice 2** — Q2 syntax (`contract` / `receive(...)` / `message`)

- *Hard:* Slice 1 must ship externally (release tag) before Slice 2
  can ship. Implementation work has started on `actor-layer` for
  the Stage 1 compiler subset, but this does not replace the
  external release gate.
- *Policy status:* The old missing-policy blocker is closed:
  `doc/tos-language-syntax-policy.md` now exists and is the Slice 2
  implementation input (Draft v3, 2026-04-30). See §11.5.
- *Cross-cut:* `actor.md` §5.5 (`become` exhaustiveness /
  reachability / invariant-preservation) is now split by the
  syntax policy: Stage 2 owns state transition syntax and
  reachability scaffolding; full `gen_statem`-class analysis
  remains Slice 3 / Q4 scope.

**Slice 3** — Q3 stdlib + Q4 static analysis + scaffolding

- *Hard:* Slice 2 must ship; the three Slice 1 reference contracts
  (jetton-minter / jetton-wallet / wallet-v5) need a second
  rewrite using Slice 2 syntax + Slice 3 stdlib (the explicit
  double-migration in §6).
- *Budget gate:* `tol.md` Q3 imposes a ≤ 15% bytecode-overhead
  budget per stdlib pattern. Pattern designs that exceed it must
  be trimmed before shipping; this can require iterating with the
  contract team mid-stage.
- *Missing infra:* The Foundry-class property-based / replay test
  framework that `tol.md` Q4 requires has no chosen substrate
  (Tol-VM simulator vs real dev net vs hybrid). Choice must be
  made before Stage 2 of Slice 3.
- *Stronger `query_id` analysis:* Slice 1's
  `pipe-check-query-id-propagation.cpp` warns; Slice 3 Q4 wants
  reachability proof of the `(expected_responder, query_id)`
  table (`policy.md` §4.4). Implementation path not yet sketched.

**Slice 4** — `actor.md` §5.9 + §6.5

- *Hard:* Bounded-postponement resource model is undefined.
  `actor.md` §5.9 enumerates what must be priced: max-outstanding
  count, size, gas, time/rent budget, postpone-expiry behaviour,
  determinism guarantees. None designed.
- *Missing policy:* No `doc/tos-postponement-policy.md` exists.
- *External dependency:* §5.9 composes with §5.7 (delivery
  failure handling) — postpone-expiry must produce a defined
  failure class. §5.7 is in §11.1.
- *§6.5 traits:* depend on Slice 3 dogfooding having stabilised
  the recurring patterns; if Slice 3 stdlib hasn't been used by
  external teams yet, trait abstraction risk is high.

**Slice 5** — Second-wave stdlib + cross-language ABI freeze

- *Hard:* Slice 3 success criterion (`§9` row 3) must be reached:
  "new contract author can produce a working Jetton or NFT in
  under one hour using `tol new`, the stdlib, and the
  documentation". Without that signal, Slice 5 is premature.
- *Missing design:* Cross-language ABI between FunC and Tol —
  calling convention, error propagation, type marshalling — has
  no design document. ABI freeze is the Slice 5 deliverable per
  `tol.md` Year 2; design must precede freeze.
- *Cross-cut:* `error_class = 5` back-pressure is reserved by
  `policy.md` §5.3 but blocked on §5.7 (see §11.1).

**Slice 6** — `actor.md` §5.1 + §5.2 + §5.4

Three independently-blocked sub-features:

- *§5.1 supervision:* `actor.md` §5.1 lists the prerequisites —
  explicit budgets, restart-intensity limits, supervisor-message
  funding rules, anti-restart-storm. Restart-intensity is §6.4
  (unscheduled, see §11.1). Supervisor-message funding overlaps
  with §7 of `policy.md` (bounce budgeting) but is a distinct
  resource model.
- *§5.2 time primitive:* Maximum outstanding timers, rent for
  scheduled messages, cancellation race semantics, MEV-sensitive
  expiry, DoS limits — none designed. `policy.md` does not
  reserve any wire-format bit for scheduled messages.
- *§5.4 capability addressing:* `actor.md` calls this "the most
  research-heavy item in the list". The basic shape (handle is
  private bearer secret vs signature/MAC vs public on-chain
  grant vs stateful registry) is undecided. **A public RFC must
  be approved before any implementation work.**

Each sub-feature needs its own policy document
(`doc/tos-supervision-policy.md`, `doc/tos-time-policy.md`,
`doc/tos-capability-policy.md`); none exist.

### 11.3 Governance and approval state (Slice 1)

- `tos-message-policy.md` is **Approved 2026-04-29** by the §12
  authorized owner under the single-signer governance model
  (policy v6). Stage 1 implementation is unblocked; no further
  signatures are required to begin Stages 2–5.
- Single-signer governance does not waive the audit trail. Any
  Slice 1 deviation from `tos-message-policy.md` must still be
  recorded as an amendment to that file (`policy.md` §12.2). If
  such an amendment touches a role that the current authorized
  owner does not yet exclusively cover (i.e. a second engineer
  has joined and split the bundle per `policy.md` §12.1), it
  needs the new owner's signature on the affected role.
- Per-slice policy documents for Slices 2 / 4 / 6 do not exist;
  see §11.2 for the names and scope of each missing document.
  Each will follow the same single-signer model unless the
  ownership split has happened by the time it is drafted.

### 11.4 Cross-Slice priority of unscheduled work

Sorted by how many later slices each item blocks:

1. **`actor.md` §5.7 design RFC** — blocks Slice 4 (`§5.9`
   postpone-expiry), Slice 5 (back-pressure `error_class = 5`),
   Slice 6 (failure taxonomy for supervision). High leverage; can
   start during Slice 1 Stage 4–5 without taking implementation
   capacity from Slice 1.
2. ✅ **Slice 2 syntax policy doc** — closed 2026-04-30 by
   `doc/tos-language-syntax-policy.md` Draft v3 and the Stage 1
   implementation commit `081f05d3c`; see §6 Slice 2 status and
   §11.5.
3. **`actor.md` §5.4 capability public RFC** — Slice 6 long-pole.
   Needs protocol architect time, not engineering capacity. The
   earlier this enters RFC review, the lower the schedule risk
   for Slice 6.
4. **§6.3 / §6.4 / §6.6 promotion into Slice 6 scope** —
   editorial change to §6 of this document; should land in the
   next revision after this section is approved.
5. **`actor.md` §5.8 off-chain observability** — independently
   useful; pull forward to Slice 3 alongside `tol new`.

Item 1 should be in motion before Slice 1 ships. Item 2 is
closed. Items 3–5 should be in motion before Slice 3 ships.

(The earlier four-signer approval item from this list was
removed when policy v6 made single-signer the rule; see §11.3.)

### 11.5 Closed (track items as they move out of §11)

- ✅ **Slice 2 syntax policy doc missing-policy blocker** —
  closed 2026-04-30. `doc/tos-language-syntax-policy.md` exists
  and is the implementation input for Slice 2 (Draft v3,
  post-v2-security-review). The prior `doc/tos-syntax-policy.md`
  placeholder name in §11.2 is retired in favour of the actual
  file name.
- ✅ **Slice 2 Stage 1 minimum compiler subset** — closed
  2026-04-30 by commit `081f05d3c`. The compiler now parses the
  Stage 1 `contract X { storage: S; receive(msg: T)+ }` surface,
  lowers it to ordinary Tol `onInternalMessage`, enforces 32-bit
  receive opcode prefixes, and adds five contract-focused
  tol-tester cases.
- ✅ **Slice 2 Stage 2 state-machine subset** — closed
  2026-04-30 by commit `cc6656ce9`. The compiler now parses
  `states:`, `@initial state`, `receive(...) on State`,
  `become`, and `keep_state`, checks transition discipline and
  state reachability before lowering, protects the reserved
  `__state` namespace, and adds seven state-focused tol-tester
  cases.

## 12. Revision notes

### r5 (Slice 2 Stage 4/6/8 status)

- §6 Slice 2 now marks Stages 0–7 complete on `actor-layer` and
  records Stage 8 as in progress with `jetton-minter` and
  `jetton-wallet` re-migrated to high-level Slice 2 syntax.
- The current verification snapshot is 616/616 tol-tester cases,
  24/24 test-emulator cases, and a green Slice 1 gas-parity gate.

### r4 (Slice 2 Stage 2 status)

- §6 Slice 2 now marks Stage 2 complete. Stages 3–8 remain
  explicitly deferred per `doc/tos-language-syntax-policy.md`
  §10.1.

### r3 (Slice 2 Stage 1 status)

- §6 Slice 2 now carries an implementation-stage checklist.
  Stage 0 policy input and Stage 1 minimum parser/lowering are
  marked complete; Stages 2–8 remain explicitly deferred per
  `doc/tos-language-syntax-policy.md` §10.1.
- §11.2 / §11.4 / §11.5 now close the old "missing Slice 2
  syntax policy" blocker and point to the actual policy file
  `doc/tos-language-syntax-policy.md`.
- No Slice 1 stage status, wire-format commitment, or later-slice
  success criterion changed.

### r2 (single-signer governance — policy v6)

`tos-message-policy.md` v6 collapses the four-role sign-off
requirement into a single authorized owner. This roadmap is
updated to match:

- §4 Stage 0 deliverable — "approved by all four owner roles"
  replaced with "approved by the authorized owner of record".
- §4 Stage 0 exit criterion — "All four owners sign off"
  replaced with "Authorized owner signs off".
- §5 first-slice checklist — "approved by all four §12 owners"
  replaced with "approved by the §12 authorized owner".
- §11.3 Governance and approval state — rewritten. The previous
  paragraph framed single-signer as a temporary unblocking
  provision pending three more signatures; under v6 it is the
  governance rule, and the audit-trail provisions are the
  permanent control.
- §11.4 Cross-Slice priority — the standalone "v5 four-signer
  approval" item is removed; remaining items renumbered
  3-becomes-3-after-renumber. A short closure note points back
  to §11.3.

No §6 sequencing, §4 stage week ranges, §8 risks, or §9 success
criteria were changed.

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
