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
- **Not Q2 (`contract` / `receive` / opcode-bearing structs) first.** Without a
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

**What is explicitly not in this stage.** The `contract` /
`receive(...)` syntax and opcode-bearing contract message surface
(those are Q2 / second slice). Stage 2 ships only the envelope struct,
the error type, and the static check — not the high-level syntax sugar.

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

### Stage 4 — Conformance, fuzzing, gas regression (week 21–24) ✅ Complete

**Status.** ✅ Complete as of 2026-04-30. Slice 1 conformance
fixtures exist (`emulator/test/slice-1-*-fixtures.cpp`) and the
Slice 1 CI gate is wired: it compiles the migrated Tol reference
contracts, runs full `tol-tester`, runs the Slice 1 emulator fixtures
through `test-emulator`, runs deterministic Envelope / `OP_ERROR`
fuzz smoke in Tol, and runs deterministic BoC / Envelope fuzz smoke
through the emulator fixture suite. The deterministic Envelope fuzz
exercises the real stdlib `Envelope.fromSlice(...)` path after commit
`02197a2c0`, including tail-position `slice` auto-unpack coverage.
The former gas-regression gap is closed by the FunC↔Tol parity harness
and schema v2 dual baselines referenced in §5.

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

### Stage 5 — Migration documentation and external RFC (week 25–26) ✅ Complete

**Status.** ✅ Complete as of 2026-04-30. The internal
contract-author migration playbook exists at
`doc/tos-message-envelope-migration.md`, drafted from the three
Stage 3 reference migrations in commit `6d9520348`. The external RFC
has been published at `doc/slice-1-rfc.md` with the §8.1
zero-wire-change commitment explicitly called out. Release-note
integration is release-management work and no longer blocks Slice 1
acceptance.

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
- Changelog and release-note pointers handed to release management.

**Exit criterion.** Migration playbook exists, external RFC is posted,
and release-management follow-up is recorded outside the implementation
gate.

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
      the external RFC is published at `doc/slice-1-rfc.md`;
      release-note integration is release-management work.)*
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

### Slice 2 — Q2 syntax, weeks 27–52 (six months) ✅ Complete

Deliver `tol.md` Q2 as locked by `doc/tos-language-syntax-policy.md`
v3: `contract`, `receive(...)`, opcode-bearing `struct (0xNN)` message
types, and the early form of state-aware dispatch (`receive(...) on
State`). The envelope from Slice 1 is the wire discipline these
constructs preserve; nothing in the wire format changes.

This slice also begins the first of the §5.5 static-analysis
features: exhaustiveness checking of `receive` handlers. Full
exhaustiveness checking lands in Slice 3.

**Status.** ✅ Complete as of 2026-04-30. The Slice 2 syntax
policy input exists at `doc/tos-language-syntax-policy.md`
(Draft v3, post-v2-security-review). Stages 0–8 and the
post-Stage 8 query-id hardening have landed on `actor-layer`; the
compiler implementation commits are Stage 1
(`081f05d3c`), Stage 2 (`cc6656ce9`), Stage 3
(`aeafe7906` merged via `8e6b3a3f8`), Stage 4
(`f697390d3` merged via `4ed03f313`), Stage 5 (`21b3f8a03`
merged via `6f188fdcf`), Stage 6 (`c7d9448eb` merged via
`b962f7254`), and Stage 7 (`2e01919ee` merged via
`c6bb72fc2`). Stage 8 re-migrated all three Slice 1 reference
contracts to Slice 2 syntax: `jetton-minter` in `38856e950`,
`jetton-wallet` in `bd851ebb4`, and `wallet-v5` in `621e7c514`.
Post-Stage 8 query-id dispatch hardening landed in `71fe23f53`:
the 32-bit opcode is now the only contract-wide dispatch field,
while `queryId` is discovered per matched receiver scope. The
current regression suite reports 617/617 tol-tester pass, 24/24
test-emulator pass, and the FunC↔Tol gas-parity gate green for all
three Slice 1 reference contracts.

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
9. ✅ **Stage 8 — dogfood remigration of jetton-minter /
   jetton-wallet / wallet-v5.** Completed 2026-04-30.
   `jetton-minter`
   was re-migrated to `contract` / `receive` / contract-local
   `get fun` syntax in commit `38856e950` (Stage 8a), preserving
   the hand-packed outbound body shapes and `@unknown_throw(0xffff)`
   legacy unknown-opcode behavior. `jetton-wallet` was re-migrated
   in commit `bd851ebb4` (Stage 8b): the three internal receive
   paths now use `@disclaim_query_id receive(...)`, the getter is
   contract-local, bounced-message handling keeps its file-scope raw
   c4 helper, and the lowering no longer emits an unreachable
   trailing `return` after terminal unknown-opcode tails. `wallet-v5`
   was re-migrated in commit `621e7c514` (Stage 8c): it now uses
   contract-level `@unknown_silent_drop`, contract-level
   `@on_bounced_policy("manual")`, typed internal prefix carriers,
   `receive_external(...)`, `receive_external(msg: UnknownOpcode)`,
   and contract-local `get fun` methods while preserving the
   wallet-v5 signed-body parsing and short unknown-opcode return
   path.
10. ✅ **Post-Stage 8 hardening — receiver-local `queryId`
    dispatch semantics.** Completed 2026-04-30 in commit
    `71fe23f53`. Removes the common pre-dispatch `queryId` load
    from `tol/pipe-lower-contract.cpp`, treats the 32-bit opcode as
    the only contract-wide dispatch field, and tightens
    `tol/pipe-check-query-id-propagation.cpp` so receiver scopes do
    not inherit any function-level query-id source. Adds
    `contract-mixed-queryid-nonquery-positive.tol` to prove that a
    query/reply receiver and a non-query receiver can coexist in the
    same contract without a contract-wide query-id preflight.

### Slice 3 — Q3 + Q4, weeks 53–78 (six months) ✅ Complete

Deliver `tol.md` Q3 (domain stdlib: jetton, NFT, ownable, wallet,
multisig) and Q4 (full §5.5 exhaustiveness, stronger request/reply
correlation analysis, scaffolding CLI, replay/property harness, and
"TVM model for Solidity developers" documentation). The Slice 2
reference contracts are already written in high-level `contract` /
`receive(...)` syntax; Slice 3 rewrites them again only where doing so
dogfoods the new stdlib patterns without changing wire bytes or
breaking the gas budget.

**Status.** ✅ Complete as of 2026-04-30. The Slice 3 policy RFC and
stage plan live at
[`doc/tos-slice-3-policy.md`](tos-slice-3-policy.md) and are approved.
The machine-readable Stage 0 baseline capture lives at
[`doc/slice-3-reference-baselines.json`](slice-3-reference-baselines.json).
The deterministic replay/property substrate is now checked in via
`doc/slice-3-replay-fixture-schema.json`,
`emulator/test/slice-3-replay-fixtures/jetton-minter-stage1.json`,
`emulator/test/slice-3-replay-fixture.cpp`, and
`scripts/check-slice-3-replay-fixtures.py`. Stage 2 stabilized
`@stdlib/ownable`, `@stdlib/jetton`, `@stdlib/nft`, `@stdlib/wallet`,
`@stdlib/multisig`, shared `@stdlib/slice3-common`, and the pattern
manifest format. Stage 3 moved the official Jetton master/wallet
references onto `@stdlib/jetton` compatibility wrappers where
wire-compatible, added direct stdlib tests and manifest detail, and
kept the regenerated Jetton Tol BoCs byte-for-byte identical to the
Stage 0 baseline. Stage 4 added the NFT TEP-62 / royalty helper surface
and fixture-level wire-shape coverage for mint, deploy, transfer,
ownership replies, static-data replies, royalties, authorization
failure, unknown opcode mapping, and bounced-message detection.
Stage 5 moved wallet-v5 helper logic into `@stdlib/wallet` wrappers
without changing the raw signed internal/external body model, and added
`@stdlib/multisig` signer/threshold/replay/action validation helpers
with focused tests. Stage 6 added `tol new --pattern
jetton|nft|wallet|multisig`, generated project artifacts, scaffold
verification, and the task-oriented Slice 3 docs. Stage 7 added
receive-exhaustiveness warnings and manifest-backed reply-correlation
hardening. Stage 8 added generated Jetton/NFT example projects, release
notes, a compatibility matrix, an audit checklist, an external-author
trial record, and `scripts/check-slice-3-release-package.py`. A
repo-side Jetton surrogate trial passed in about 9 minutes and produced
two documentation fixes. The maintainer accepted that surrogate as the
Slice 3 release gate on 2026-04-30.

**Stage plan.**

1. ✅ **Stage 0 — policy and baseline lock.** Approved
   `doc/tos-slice-3-policy.md`, captured current Slice 2
   reference-contract bytecode/gas/opcode/method-id/error-code
   baselines in `doc/slice-3-reference-baselines.json`, and fixed the
   first two vertical stdlib targets: Jetton first, NFT second.
2. ✅ **Stage 1 — deterministic property/replay harness.** Completed
   2026-04-30. Defines the replay fixture schema, uses the approved
   hybrid `tol-tester` + `test-emulator` substrate, adds a
   `jetton-minter` replay fixture plus a deterministic
   `splitmix64-unknown-opcode` negative generator, and wires the
   harness into CI.
3. ✅ **Stage 2 — stdlib foundation and package shape.** Completed
   2026-04-30. Adds stable package imports for `ownable`, `jetton`,
   `nft`, `wallet`, and `multisig`; shared `slice3-common` helpers for
   raw replies, `OP_ERROR` body construction, and pending-reply key
   hashing; a pattern-manifest schema plus initial manifests; and a
   minimal ownable helper with focused tol-tester coverage.
4. ✅ **Stage 3 — Jetton vertical slice.** Completed 2026-04-30. Ships
   Jetton master/wallet helpers in `@stdlib/jetton`, migrates the Slice
   2 `jetton-minter.tol` and `jetton-wallet.tol` helper surface to
   compatibility wrappers over the stdlib, expands the Jetton manifest,
   and adds focused stdlib coverage for state-init/address derivation,
   TEP-74 body construction, duplicate `query_id` determinism, and
   error-code mapping. The Stage 0 BoC hashes and sizes are unchanged.
5. ✅ **Stage 4 — NFT vertical slice.** Completed 2026-04-30. Ships
   NFT collection/item helpers in `@stdlib/nft`, including TEP-62 /
   royalty opcode constants, collection mint body construction,
   item state-init/address derivation, raw transfer/deploy/reply
   builders, bounce-flag detection, and item/collection error mapping.
   Focused stdlib coverage checks mint, transfer, ownership query
   replies, collection/item linkage, bounced-message detection, unknown
   opcode mapping, and authorization failures against manual builders.
6. ✅ **Stage 5 — wallet and multisig vertical slice.** Completed
   2026-04-30. `@stdlib/wallet` owns wallet-v5 constants, storage
   packing, raw signed-body parsing, extension-action body construction,
   C5 action-list validation, and error mapping; `wallet-v5.tol` keeps
   compatibility wrappers and preserves raw signed internal/external body
   processing with the Stage 0 wallet-v5 Tol BoC hash unchanged.
   `@stdlib/multisig` adds signer-set, duplicate-signer, threshold,
   pending-proposal replay, expiry, action-list validation, and
   error-mapping helpers with focused coverage.
7. ✅ **Stage 6 — `tol new` scaffolding and documentation.** Completed
   2026-04-30. `tol new --pattern jetton|nft|wallet|multisig` generates
   source, a smoke test, replay/deploy stubs, a manifest, and
   observability JSON artifacts; `scripts/check-slice-3-scaffold.py`
   verifies all generated patterns. Added task-oriented Tol, Jetton,
   NFT, wallet/multisig, and TVM-for-Solidity docs.
8. ✅ **Stage 7 — Q4 static-analysis hardening.** Completed
   2026-04-30. Added `pipe-check-receive-exhaustiveness.cpp` warning
   coverage for implicit unknown-opcode policy and state/message cells
   that fall to the synthesized state guard. Added
   `pipe-check-slice3-reply-correlation.cpp`, manifest-backed
   `Slice3PendingReplyTable.reserve/consume/ignoreDuplicate` helpers,
   and tests for spoofed responders, duplicate replies, raw-key warning
   mode, and direct table-access compile errors.
9. ✅ **Stage 8 — external author trial and release package.**
   Completed 2026-04-30. Added generated
   Jetton/NFT author-trial examples under `examples/slice3/`, release
   notes, compatibility matrix, audit checklist, external-author trial
   record, and `scripts/check-slice-3-release-package.py`. A Jetton
   surrogate trial passed in about 9 minutes and fixed two doc gaps.
   The maintainer accepted the surrogate as the release gate.

### Slice 4 — §5.9 + §6.5, Year 2 H1

Deliver bounded postponement (`actor.md` §5.9) and trait-based
behaviour patterns (§6.5). These are language-and-stdlib slices
with limited protocol exposure.

**Status.** ✅ Complete 2026-04-30. Stage 0 policy work has
landed in [`doc/tos-postponement-policy.md`](tos-postponement-policy.md)
and [`doc/tos-slice-4-policy.md`](tos-slice-4-policy.md), with the
initial behaviour-manifest schema at
[`doc/slice-4-behaviour-manifest-schema.json`](slice-4-behaviour-manifest-schema.json).
Draft v1.1 closes the first security-review findings on schema
constraints, callback failure semantics, zero-capacity queues, optional
`query_id` replay keys, and cell-depth budgeting. Stage 1 has landed the
`@stdlib/postponement` helper surface and focused tol-tester coverage.
Stage 2 has landed compiler hardening for direct queue internals,
external-message enqueue attempts, missing enqueue budgets, and raw-map
bypass warnings. Stage 3 has landed the first official postponed
reference contract, an auction-style example that queues too-early bids
and drains them after opening. Stage 4 has added check-only behaviour
manifests and validation without changing generated Fift. Stage 5
extends that trait coverage to Jetton wallet, NFT item, and Multisig
helper surfaces with no Tol source or BoC changes. Stage 6 has landed
the release-package surrogate: `tol new` emits behaviour-conformance
metadata, Slice 4 author docs and release notes are checked in, generated
Slice 4 scaffold examples live under `examples/slice4/`, and
`scripts/check-slice-4-release-package.py` validates the package.

**Stage plan.**

1. ✅ **Stage 0 — policy and resource-model lock.** Completed
   2026-04-30. Defines bounded postponement as explicit contract
   storage, not protocol-mailbox scanning; fixes required budgets
   (`maxItems`, per-body size, total footprint, age, drain bound);
   keeps `ErrorClass.BackPressure` reserved until `actor.md` §5.7; and
   defines trait/behaviour manifests as check-only compiler inputs.
2. ✅ **Stage 1 — `@stdlib/postponement` foundation.** Completed
   2026-04-30. Adds `crypto/smartcont/tol-stdlib/postponement.tol`
   with `PostponementBudget`, bounded `PostponedItem` /
   `PostponedQueue` storage, enqueue, duplicate-key detection, FIFO
   drain, expiry cleanup, explicit drop, and accounting helpers. Focused
   coverage in `tol-tester/tests/slice4-postponement-stdlib-positive.tol`
   exercises queue full, duplicate `query_id`, optional `query_id`
   without an author key, explicit author idempotency keys, oversized
   bodies, cell-depth budget, expiry, FIFO drain, callback throw
   preservation, and explicit drop.
3. ✅ **Stage 2 — postponement compiler hardening.** Completed
   2026-04-30.

   - ✅ Added `tol/pipe-check-postponement.cpp`, wired in the resolved
     AST/type-checking band before codegen.
   - ✅ Error mode: rejects direct access to private `PostponedQueue`
     maps and direct writes to queue accounting fields.
   - ✅ Error mode: rejects `enqueue`-style calls from
     `onExternalMessage`.
   - ✅ Error mode: enqueue helpers require the explicit budget argument;
     missing-budget tests fail at call-arity checking.
   - ✅ Warning mode: flags raw `map<*, PostponedItem>` mutators that
     bypass the stdlib helper.
   - ✅ Negative tol-tester cases: direct-internal-write, external
     enqueue, missing-budget.
   - ✅ Positive/warning tol-tester cases: raw-map legacy warning plus
     Stage 1 valid stdlib usage.
   - ✅ Exit criterion: targeted hardening tests prove bounded queues
     cannot be bypassed through ordinary Tol field access or raw
     external-message paths.

4. ✅ **Stage 3 — first postponed reference contract.** Completed
   2026-04-30.

   - ✅ Added `examples/slice4/postponed-auction.tol`, an
     auction-style reference that queues too-early bids in
     `PostponedQueue`, opens the auction, and drains queued bids.
   - ✅ Replay/tol-tester fixture: early message enqueue.
   - ✅ Replay/tol-tester fixture: state transition that unlocks
     drain.
   - ✅ Replay/tol-tester fixture: FIFO drain after state transition.
   - ✅ Replay/tol-tester fixture: expiry before drain.
   - ✅ Replay/tol-tester fixture: queue full.
   - ✅ Replay/tol-tester fixture: duplicate `query_id`.
   - ✅ Replay/tol-tester fixture: malformed body rejected before
     storage mutation.
   - ✅ Recorded focused gas baseline in
     `doc/slice-4-reference-baselines.json`; a handwritten raw-map
     equivalent is explicitly not used because Stage 2 now warns on
     that bypass pattern.
   - ✅ Exit criterion: bounded postponement used by one shipped
     reference contract; no existing BoC hash regressed.

5. ✅ **Stage 4 — behaviour manifest foundation.** Completed
   2026-04-30.

   - ✅ Added `request_server` behaviour manifest under
     `doc/slice4-behaviours/`.
   - ✅ Added `state_machine` behaviour manifest.
   - ✅ Added `postponing_state_machine` behaviour manifest.
   - ✅ Added `scripts/check-slice-4-behaviour-manifests.py`, a
     check-only validator that validates ordinary Tol source against a
     selected manifest without rewriting source or generated Fift.
   - ✅ Warning mode for raw code contracts; error mode for
     stdlib/generated contracts.
   - ✅ Tests: validator compares generated Fift hash before/after and
     checks no behaviour/trait/vtable marker leaks into generated code.
   - ✅ Tests: postponed auction conforms; a non-conforming temporary
     contract passes in raw warning mode and fails in generated error
     mode.
   - ✅ Exit criterion: callback/message/postponement shape is proved
     for the Stage 3 reference while preserving bytecode.

6. ✅ **Stage 5 — trait coverage for three official patterns.**
   Completed 2026-04-30.

   - ✅ Added behaviour manifest for Jetton wallet helper coverage
     (`doc/slice4-behaviours/jetton_wallet.json`).
   - ✅ Added behaviour manifest for NFT item helper coverage
     (`doc/slice4-behaviours/nft_item.json`).
   - ✅ Added behaviour manifest for multisig helper coverage
     (`doc/slice4-behaviours/multisig.json`).
   - ✅ Verified BoC impact is none: this stage changes JSON manifests,
     scaffold metadata, and the read-only validator only; no Tol
     contract or stdlib source changes.
   - ✅ Extended existing scaffold manifests so generated Jetton/NFT
     examples declare behaviour conformance.
   - ✅ Added conformance checks for all three patterns to
     `scripts/check-slice-4-behaviour-manifests.py`.
   - ✅ Exit criterion: traits cover three official Slice 3 patterns
     without bytecode regression beyond Slice 1 budget.

7. ✅ **Stage 6 — tooling, docs, and release surrogate.**
   Completed 2026-04-30.

   - ✅ Extend `tol new` output with behaviour-manifest declarations
     where applicable.
   - ✅ Add author documentation for bounded postponement usage.
   - ✅ Add author documentation for behaviour conformance and
     manifest selection.
   - ✅ Add `scripts/check-slice-4-release-package.py` (validates
     docs, manifests, generated examples, and focused tests).
   - ✅ Add generated contract examples under `examples/slice4/`.
   - ✅ Run repo-side author surrogate trial (or record human trial
     if available); acceptance criterion mirrors Slice 3 surrogate
     gate.
   - ✅ Update roadmap and release notes with Slice 4 completion
     record.
   - ✅ Exit criterion: a contract author can generate or inspect a
     behaviour manifest and run bounded-postponement tests without
     reading compiler source.

### Slice 5 — second-wave stdlib, Year 2 H2

Auction, DAO/governance, oracle, and payment-channel templates,
each one preceded by a short design note. Cross-language ABI is
frozen at the end of this slice.

**Status.** 🚧 Stage 1 complete, Stage 2 active, 2026-04-30. The implementation
input candidates are [`doc/tos-slice-5-policy.md`](tos-slice-5-policy.md),
[`doc/slice-5-func-tol-abi.md`](slice-5-func-tol-abi.md), and
[`doc/slice-5-abi-manifest-schema.json`](slice-5-abi-manifest-schema.json).
The first Stage 0 security-review findings are addressed and Draft v1.1
is accepted as the implementation input. Stage 1 has landed the
dependency-free ABI manifest validator and a FunC/Tol golden fixture
pair; second-wave helper implementation is now unblocked.

**Stage plan.**

1. ✅ **Stage 0 — policy and ABI freeze input.** Drafted
   2026-04-30; approved as Draft v1.1 implementation input.

   - ✅ Draft Slice 5 policy RFC and stage plan.
   - ✅ Draft FunC<->Tol ABI freeze boundary.
   - ✅ Draft Slice 5 ABI manifest schema.
   - ✅ Update roadmap status and dependencies.
   - ✅ Address first Stage 0 security-review findings: payment-channel
     signature material, constrained ABI types, optional-query layout,
     manual/raw fixtures, schema revision discipline, method-id and
     error-code reserved ranges, DAO action policy, and oracle reporter
     lifecycle.
   - ✅ Security review and approval.
   - ✅ Exit criterion: ABI boundary and stage plan are approved.

2. ✅ **Stage 1 — ABI manifest validator and interop harness.**

   - ✅ Add `scripts/check-slice-5-abi-manifests.py`.
   - ✅ Add one FunC-produced and one Tol-produced fixture that
     serialize the same body/cell shape and compare the result.
   - ✅ Validate opcode width, getter stack order, error-code ranges,
     `queryId` policy, cell-field encodings, and compatibility
     exceptions.
   - ✅ Wire into release-package checks without changing bytecode.

3. 🚧 **Stage 2 — auction package.**

   - ⬜ Add `@stdlib/auction`.
   - ⬜ Migrate or wrap `examples/slice4/postponed-auction.tol`
     through the package where budget permits.
   - ⬜ Add ABI/behaviour manifests, replay coverage, scaffold output,
     and tests for bid, too-early bid, close, settle, refund/excess,
     duplicate `queryId`, stale close, low bid, and malformed body.

4. ⬜ **Stage 3 — DAO / governance package.**

   - ⬜ Add `@stdlib/governance`.
   - ⬜ Add proposal, vote, quorum/threshold, cancel/expire, execute,
     and action-list validation helpers.
   - ⬜ Add tests for duplicate vote, unauthorized proposer, quorum
     boundary, threshold boundary, expired proposal, malformed action
     list, replayed execution, and unknown opcode.

5. ⬜ **Stage 4 — oracle package.**

   - ⬜ Add `@stdlib/oracle`.
   - ⬜ Add reporter-set authorization, round ids, freshness windows,
     quorum/median aggregation, duplicate report rejection, and stale
     data handling.
   - ⬜ Add tests for unauthorized reporter, duplicate reporter,
     insufficient quorum, stale round, outlier handling, replayed round
     id, and unknown opcode.

6. ⬜ **Stage 5 — payment-channel package.**

   - ⬜ Add `@stdlib/payment-channel`.
   - ⬜ Add signed state updates, monotonic sequence numbers,
     cooperative close, challenge close, settlement, and body builders.
   - ⬜ Add tests for signature failure, seqno replay, wrong channel id,
     stale challenge, premature settlement, duplicate close, and
     malformed state body.

7. ⬜ **Stage 6 — scaffolding, docs, and release candidate.**

   - ⬜ Extend `tol new --pattern` for auction, governance, oracle, and
     payment-channel.
   - ⬜ Generate examples, ABI manifests, behaviour manifests, replay
     stubs, deploy stubs, opcode maps, method-id maps, and error-code
     maps.
   - ⬜ Add contract-author docs, audit checklists, and
     `scripts/check-slice-5-release-package.py`.

8. ⬜ **Stage 7 — ABI freeze sign-off and external adoption.**

   - ⬜ Freeze the ABI manifest schema.
   - ⬜ Record canonical ABI manifest hashes for second-wave packages.
   - ⬜ Record at least three external production contracts using the
     second-wave stdlib, or explicitly mark Slice 5 as
     release-candidate-only until those deployments exist.

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
| Slice 3 | supervision; scheduled messages; capability handles; bounded postponement; trait / behaviour syntax; new wire surface |
| Slice 4 | supervision; scheduled messages |
| Slice 5 | capability handles; protocol delivery SLA / dead-letter handling; protocol back-pressure emission; supervision; scheduled messages |
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
| Slice 2 | The three Slice 1 reference contracts are re-migrated using Slice 2 `contract` / `receive(...)` / `struct (0xNN)` syntax, deploy, preserve wire compatibility, and pass the full regression suite. |
| Slice 3 | A new contract author can produce a working Jetton or NFT in under one hour using `tol new`, the stdlib, replay fixtures, and the documentation. Accepted completion record: the 2026-04-30 Stage 8 Jetton surrogate trial completed in about 9 minutes and was accepted by the maintainer as the release gate. |
| Slice 4 | Bounded postponement is used by at least one shipped contract; traits cover at least three official reference contracts without bytecode regression beyond the Slice 1 budget. Accepted completion record: the 2026-04-30 repo-side release-package surrogate generated Jetton/NFT/Multisig examples and passed `scripts/check-slice-4-release-package.py`. |
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

The right next action is Slice 5 Stage 0 security review: approve or
revise the second-wave stdlib target boundaries and the FunC<->Tol ABI
freeze plan before adding auction, DAO/governance, oracle, or
payment-channel templates. The `actor.md` §5.7 delivery-SLA RFC should
run in parallel because it still blocks protocol-level back-pressure and
later supervision semantics, but Slice 4's contract-level bounded
postponement is complete without that dependency.

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
| §5.7 | Cross-shard delivery SLA + dead-letter handling | Blocks `error_class = 5` (back-pressure) emission (`policy.md` §5.3), protocol-level delivery-failure semantics, and Slice 6 supervision failure taxonomy. It no longer blocks Slice 4's contract-level bounded postponement because Slice 4 uses explicit expiry/drop semantics and keeps `ErrorClass.BackPressure` reserved. | Pre-design RFC before any back-pressure or supervision implementation; protocol implementation slot adjacent to Slice 5 / before Slice 6. |
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

**Slice 2** — Q2 syntax (`contract` / `receive(...)` / opcode-bearing structs)

- *Implementation status:* Closed on `actor-layer`. Stages 0–8 plus
  receiver-local `queryId` hardening have landed; see §6 Slice 2.
  External release tagging is release-management work and no longer an
  implementation blocker for starting Slice 3 planning.
- *Policy status:* The old missing-policy blocker is closed:
  `doc/tos-language-syntax-policy.md` exists and was implemented as the
  Slice 2 input (Draft v3, 2026-04-30). See §11.5.
- *Cross-cut:* `actor.md` §5.5 (`become` exhaustiveness /
  reachability / invariant-preservation) is still split by policy:
  Slice 2 delivered state transition syntax and reachability
  scaffolding; full per-state receive exhaustiveness remains Slice 3 /
  Q4 scope.

**Slice 3** — Q3 stdlib + Q4 static analysis + scaffolding

- *Hard:* Slice 2 implementation is complete on `actor-layer`; Slice 3
  Stage 0 is complete. The next rewrite is not "to Slice 2 syntax"
  anymore; it is a stdlib dogfood rewrite on top of existing Slice 2
  syntax, gated by `doc/slice-3-reference-baselines.json`.
- *Budget gate:* `tol.md` Q3 imposes a ≤ 15% bytecode-overhead
  budget per stdlib pattern. Pattern designs that exceed it must
  be trimmed before shipping; this can require iterating with the
  contract team mid-stage. Stage 2 has only helper/package foundation;
  the first production budget comparison resumes in Stage 3 Jetton.
- *Replay/property substrate:* Closed in Slice 3 Stage 1. The approved
  hybrid substrate now has a schema, JSON fixture directory, runner
  script, CI wiring, and first `jetton-minter` emulator replay fixture
  with a deterministic negative generator.
- *Stronger `query_id` analysis:* Closed in Slice 3 Stage 7.
  The implementation is stdlib-manifest-backed checking of the
  `(expected_responder, query_id)` table, with optional
  `expected_reply_opcode` discrimination and warning-first mode for raw
  code.
- *External author trial:* Closed in Slice 3 Stage 8. The Jetton
  surrogate trial passed in about 9 minutes and was accepted by the
  maintainer as the Slice 3 release gate.

**Slice 4** — `actor.md` §5.9 + §6.5

- *Status:* Complete on `actor-layer`. Stage 0 inputs are approved and
  the implementation has landed through Stage 6.
- *Resource model:* The bounded-postponement resource model prices
  max-outstanding count, per-body size, total storage footprint, age,
  explicit drain bounds, duplicate handling, and observed expiry.
- *External dependency:* §5.9 still composes with §5.7 (delivery
  failure handling). Slice 4 avoids depending on §5.7 by keeping
  `ErrorClass.BackPressure` reserved and using explicit contract-level
  expiry/error handling.
- *§6.5 traits:* Traits ship as check-only behaviour manifests over
  existing stdlib/reference patterns, not as bytecode-visible dynamic
  dispatch.

**Slice 5** — Second-wave stdlib + cross-language ABI freeze

- *Status:* Stage 0 draft exists. Slice 3 and Slice 4 prerequisites are
  complete; the next blocker is security review of the Slice 5 policy
  and ABI boundary.
- *ABI design:* Cross-language ABI between FunC and Tol now has a draft
  boundary document and manifest schema. Stage 1 must prove it with a
  mixed FunC/Tol interop fixture before template implementation begins.
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
- Per-slice policy documents: Slice 2 exists at
  `doc/tos-language-syntax-policy.md`; Slice 3 is approved at
  `doc/tos-slice-3-policy.md`; Slice 4 is complete under
  `doc/tos-postponement-policy.md` and `doc/tos-slice-4-policy.md`.
  Slice 6 policy documents do not exist; see §11.2 for the names and
  scope of each missing document. Each will follow the same
  single-signer model unless the ownership split has happened by the
  time it is drafted.

### 11.4 Cross-Slice priority of unscheduled work

Sorted by how many later slices each item blocks:

1. **`actor.md` §5.7 design RFC** — no longer blocks Slice 4's bounded
   contract-level postponement, but still blocks protocol-level delivery
   failure semantics, Slice 5 back-pressure `error_class = 5`, and
   Slice 6 failure taxonomy for supervision.
2. ✅ **Slice 2 syntax policy doc** — closed 2026-04-30 by
   `doc/tos-language-syntax-policy.md` Draft v3 and the Stage 1
   implementation commit `081f05d3c`; see §6 Slice 2 status and
   §11.5.
3. ✅ **Slice 3 Stage 1 replay harness** — closed 2026-04-30. The
   deterministic replay/property substrate is checked in and CI-wired;
   stdlib pattern implementation can start.
4. **`actor.md` §5.4 capability public RFC** — Slice 6 long-pole.
   Needs protocol architect time, not engineering capacity. The
   earlier this enters RFC review, the lower the schedule risk
   for Slice 6.
5. **§6.3 / §6.4 / §6.6 promotion into Slice 6 scope** —
   editorial change to §6 of this document; should land in the
   next revision after this section is approved.
6. ✅ **`actor.md` §5.8 off-chain observability placement** —
   pulled into Slice 3 Stage 6 in `doc/tos-slice-3-policy.md` as
   generated manifests, opcode maps, method-id maps, error-code maps,
   and replay traces.

Item 1 remains the next protocol-design dependency. Slice 4 avoids
blocking on it by keeping back-pressure emission out of scope, but §5.7
still needs a design RFC before any protocol-level delivery
failure semantics or `ErrorClass.BackPressure` activation. Items 2, 3,
and 6 are closed. Items 4–5 should be in motion before Slice 6 design
starts.

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
- ✅ **Slice 2 full implementation** — closed 2026-04-30. Stages
  3–8 plus receiver-local `queryId` hardening landed on
  `actor-layer`; the Slice 2 status block in §6 records the stage
  commits and current verification snapshot.
- ✅ **Slice 3 Stage 0 policy/baseline gate** — closed
  2026-04-30. `doc/tos-slice-3-policy.md` is approved and
  `doc/slice-3-reference-baselines.json` captures the three Slice 2
  reference-contract bytecode/gas/opcode/method-id/error-code and
  wallet-v5 external-body baselines. Implementation remains gated on
  the Stage 1 replay/property harness before stdlib pattern work starts.
- ✅ **Slice 3 Stage 1 deterministic replay/property harness** —
  closed 2026-04-30. The schema
  `doc/slice-3-replay-fixture-schema.json`, first fixture
  `emulator/test/slice-3-replay-fixtures/jetton-minter-stage1.json`,
  runner `scripts/check-slice-3-replay-fixtures.py`, and emulator
  fixture `emulator/test/slice-3-replay-fixture.cpp` are checked in and
  CI-wired. The first deterministic negative generator is
  `splitmix64-unknown-opcode`.
- ✅ **Slice 3 Stage 2 stdlib foundation** — closed 2026-04-30.
  Stable imports now exist for `@stdlib/ownable`, `@stdlib/jetton`,
  `@stdlib/nft`, `@stdlib/wallet`, and `@stdlib/multisig`, with shared
  helpers in `@stdlib/slice3-common`. Pattern manifests live under
  `crypto/smartcont/tol-stdlib/manifests/`, and the minimal ownable
  helper has focused tol-tester coverage.
- ✅ **Slice 3 Stage 3 Jetton vertical slice** — closed 2026-04-30.
  `@stdlib/jetton` now provides the shared Jetton opcode constants,
  state-init/address helpers, raw TEP-74 body builders, basechain guard,
  and minter/wallet error mapping. The official `jetton-minter.tol` and
  `jetton-wallet.tol` references dogfood those helpers through
  compatibility wrappers while preserving the Stage 0 Tol BoC hashes and
  sizes exactly.
- ✅ **Slice 3 Stage 4 NFT vertical slice** — closed 2026-04-30.
  `@stdlib/nft` now provides TEP-62 / royalty opcode constants,
  collection mint body construction, item state-init/address helpers,
  raw transfer/deploy/reply builders, bounce-flag detection, and
  item/collection error mapping. Coverage is fixture-level because the
  repo has legacy FunC and JS NFT shapes but no official Tol NFT
  reference contract to migrate byte-for-byte.
- ✅ **Slice 3 Stage 5 wallet and multisig vertical slice** — closed
  2026-04-30. `@stdlib/wallet` owns wallet-v5 raw signed-body parsing,
  extension-action builders, C5 action-chain validation, storage packing,
  and error mapping while `wallet-v5.tol` preserves its external/internal
  body shape through compatibility wrappers and keeps the Stage 0 Tol BoC
  hash unchanged. `@stdlib/multisig` adds signer-set, duplicate-signer,
  threshold, proposal-replay, expiry, action validation, and error-mapping
  helpers.
- ✅ **Slice 3 Stage 6 `tol new` scaffolding and documentation** —
  closed 2026-04-30. The `tol` CLI now supports
  `tol new --pattern jetton|nft|wallet|multisig`, generating source,
  smoke tests, replay/deploy stubs, manifests, opcode maps, method-id
  maps, error-code maps, and replay traces. The scaffold checker and
  task-oriented Slice 3 docs are checked in.
- ✅ **Slice 3 Stage 7 Q4 static-analysis hardening** — closed
  2026-04-30. Added receive-exhaustiveness warnings, manifest-backed
  reply-correlation checking, and `Slice3PendingReplyTable`
  reserve/consume/ignore helpers with spoofed-responder and
  duplicate-reply tests.
- ✅ **Slice 3 Stage 8 external-author trial/release package** —
  closed 2026-04-30. Generated Jetton/NFT
  author-trial examples, release notes, compatibility matrix, audit
  checklist, and the release-package checker are checked in. A Jetton
  surrogate trial passed in about 9 minutes and produced the checked-in
  docs fixes for `ErrorClass` and custom Jetton error-code examples. The
  maintainer accepted the surrogate as the Slice 3 release gate.
- ✅ **Slice 4 full implementation** — closed 2026-04-30. Stages 0–6
  landed on `actor-layer`: bounded postponement stdlib, compiler
  hardening, postponed-auction reference, check-only behaviour
  manifests, three-pattern trait coverage, generated examples, author
  docs, and `scripts/check-slice-4-release-package.py`.
- ✅ **Slice 5 Stage 0 policy / ABI freeze input** — closed
  2026-04-30. `doc/tos-slice-5-policy.md`,
  `doc/slice-5-func-tol-abi.md`, and
  `doc/slice-5-abi-manifest-schema.json` define the second-wave stdlib
  stage plan and FunC<->Tol ABI freeze boundary; Draft v1.1 is the
  approved implementation input.
- ✅ **Slice 5 Stage 1 ABI manifest validator** — closed 2026-04-30.
  `scripts/check-slice-5-abi-manifests.py` validates constrained ABI
  types, query-id layout, reserved getter/error ranges, manual/raw
  fixture requirements, Ed25519 signing-input declarations, and the
  FunC/Tol golden fixture pair under `doc/slice5-abi-fixtures/`.

## 12. Revision notes

### r24 (Slice 5 Stage 1 ABI validator)

- §6 Slice 5 now marks Stage 0 approved, Stage 1 complete, and Stage 2
  active.
- Added the dependency-free Slice 5 ABI manifest validator, the first
  mixed FunC/Tol ABI manifest, canonical golden fixtures, and the
  checker runbook.

### r23 (Slice 5 Stage 0 review fixes)

- Closed the first Slice 5 Stage 0 review findings on signature
  material, ABI type constraints, optional-query layout, manual/raw
  fixture requirements, schema revision discipline, method-id and
  error-code reserved ranges, DAO action-list policy, and oracle
  reporter lifecycle.

### r22 (Slice 5 Stage 0 draft)

- §6 Slice 5 now has a Stage 0-7 implementation plan.
- Added the Slice 5 policy RFC, FunC<->Tol ABI freeze draft, and ABI
  manifest schema as review input.
- Updated §7 and §11 to make clear that Slice 5 does not implement
  capability handles, scheduled messages, supervision, or protocol
  back-pressure.

### r21 (Slice 4 post-review hardening)

- Closed the post-implementation Slice 4 review findings for
  postponed-auction FIFO drain pinning, indirect external-message
  postponement, legacy BackPressure manifest documentation, and
  comment-safe behaviour-manifest parsing.

### r20 (Slice 4 complete)

- §6 Slice 4 now marks Stage 6 and Slice 4 complete.
- Recorded the repo-side Slice 4 release-package surrogate as the
  accepted completion record.
- Updated §9, §11.2, §11.3, §11.4, and §11.5 to reflect that Slice 4 no
  longer waits on the §5.7 delivery-SLA RFC for contract-level bounded
  postponement.

### r19 (Slice 3 complete)

- §6 Slice 3 now marks Stage 8 and Slice 3 complete.
- Recorded the 2026-04-30 maintainer decision accepting the Jetton
  surrogate trial as the Slice 3 release gate.
- Updated release notes, audit checklist, and trial record to remove the
  human-trial blocker.

### r18 (Slice 3 Stage 8 release package surrogate)

- §6 Slice 3 initially marked the Stage 8 repo-side surrogate complete
  while treating the real external-author trial as a separate gate; r19
  supersedes this by accepting the surrogate as the release gate.
- Added Jetton/NFT generated author-trial example projects under
  `examples/slice3/`.
- Added release notes, compatibility matrix, audit checklist,
  external-author trial record, and
  `scripts/check-slice-3-release-package.py`.
- Recorded a Jetton surrogate trial that completed in about 9 minutes
  and fixed the `ErrorClass` / custom Jetton error-code documentation
  gaps.

### r17 (Slice 3 Stage 7 static-analysis hardening)

- §6 Slice 3 now marks Stage 7 complete and Stage 8 active.
- Added receive-exhaustiveness warnings before contract lowering.
- Added manifest-backed reply-correlation checks and
  `Slice3PendingReplyTable` helpers/tests.

### r16 (Slice 3 Stage 6 scaffolding and docs)

- §6 Slice 3 now marks Stage 6 complete and Stage 7 active.
- Added `tol new --pattern` scaffolding for Jetton, NFT, wallet, and
  multisig projects plus `scripts/check-slice-3-scaffold.py`.
- Added task-oriented Slice 3 author docs and recorded generated
  observability artifacts as the Stage 6 off-chain surface.

### r15 (Slice 3 Stage 5 wallet and multisig stdlib)

- §6 Slice 3 now marks Stage 5 complete and Stage 6 active.
- `@stdlib/wallet` owns the wallet-v5 helper surface while preserving
  raw signed body processing in the reference wallet.
- `@stdlib/multisig` now has signer/threshold/replay/action helpers and
  focused tests; §11.5 records the stage as closed.

### r14 (Slice 3 Stage 4 NFT stdlib)

- §6 Slice 3 now marks Stage 4 complete and Stage 5 active.
- `@stdlib/nft` owns the NFT helper surface and manifest detail for
  TEP-62 transfer, ownership, static-data, royalty, and collection mint
  shapes.
- §11.5 now records the NFT vertical slice as closed with focused
  fixture-level wire-shape coverage.

### r13 (Slice 3 Stage 3 Jetton stdlib)

- §6 Slice 3 now marks Stage 3 complete and Stage 4 active.
- `@stdlib/jetton` owns the shared Jetton helper surface and manifest
  details used by the official minter/wallet references.
- §11.5 now records that the Jetton vertical slice is closed with
  byte-for-byte unchanged Tol BoCs against the Stage 0 baseline.

### r12 (Slice 3 Stage 2 stdlib foundation)

- §6 Slice 3 now marks Stage 2 complete and Stage 3 active.
- Added stable Slice 3 stdlib import names, shared helper foundation,
  initial pattern manifests, and minimal ownable helper coverage.
- §11.2 / §11.5 now record that package-shape work is closed; production
  budget comparisons resume with the Stage 3 Jetton vertical slice.

### r11 (Slice 3 Stage 1 replay harness)

- §6 Slice 3 now marks Stage 1 complete and Stage 2 active.
- Added the deterministic replay fixture schema, first `jetton-minter`
  replay fixture, runner script, and emulator replay fixture.
- §11.2 / §11.4 / §11.5 now close the replay/property substrate blocker
  before stdlib foundation work begins.

### r10 (Slice 3 Stage 0 approved)

- `doc/tos-slice-3-policy.md` is now approved as the Slice 3 Stage 0
  implementation input.
- Added `doc/slice-3-reference-baselines.json`, the machine-readable
  baseline for the three Slice 2 reference contracts before Slice 3
  stdlib rewrites.
- §6 Slice 3 marks Stage 0 complete and Stage 1
  deterministic replay/property harness as the active next gate.

### r9 (Slice 3 RFC and stage plan)

- Added `doc/tos-slice-3-policy.md` as the Slice 3 Draft v1 RFC and
  stage plan, including a built-in deep self-review.
- §6 Slice 3 now lists Stages 0–8: policy/baseline lock,
  deterministic replay harness, stdlib foundation, Jetton, NFT,
  wallet/multisig, `tol new` + docs, Q4 static analysis, and external
  author trial.
- §4 Stage 4/5 Slice 1 headings are now aligned with the §5 checklist:
  both are complete as of 2026-04-30.
- §9 no longer describes Slice 2 success in terms of a `message`
  keyword; Slice 2 uses opcode-bearing `struct (0xNN)` types.
- §11.2 / §11.4 / §11.5 now treat Slice 3's replay harness and stronger
  query-id analysis as scheduled Slice 3 work instead of unsketched
  blockers.

### r8 (Slice 2 complete)

- §6 Slice 2 now marks the full Slice 2 implementation complete:
  Stages 0–8 plus the receiver-local `queryId` hardening have
  landed on `actor-layer`.

### r7 (Slice 2 queryId dispatch hardening)

- §6 Slice 2 compiler lowering now treats the 32-bit opcode as the
  only contract-wide dispatch field. `queryId` is discovered inside
  each receiver scope from the matched typed body; the common
  pre-dispatch query-id load has been removed.
- The current verification snapshot is 617/617 tol-tester cases,
  24/24 test-emulator cases, and a green Slice 1 FunC↔Tol
  gas-parity gate.

### r6 (Slice 2 Stage 8 complete)

- §6 Slice 2 now marks Stage 8 complete: `jetton-minter`,
  `jetton-wallet`, and `wallet-v5` are all re-migrated to the
  high-level Slice 2 syntax on `actor-layer`.
- The verification snapshot at Stage 8 close was 616/616 tol-tester
  cases, 24/24 test-emulator cases, and a green Slice 1
  FunC↔Tol gas-parity gate.

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
