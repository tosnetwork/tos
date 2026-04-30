# TOS Slice 3 Policy RFC

Domain stdlib, scaffolding, replay testing, and Q4 static analysis.

## 0. Status, scope, and references

**Status.** Approved 2026-04-30 by the authorized owner of record.
This is the Slice 3 Stage 0 implementation input.

Slice 3 implements the `tol.md` Q3 + Q4 work on top of the completed
Slice 1 message envelope and completed Slice 2 contract syntax. The
goal is not a new wire format. The goal is to make the already shipped
Tol actor vocabulary usable by ordinary contract authors through
audited domain libraries, scaffolding, replay/property tests, and the
next static-analysis layer.

References:

- `doc/roadmap.md` section 6, Slice 3.
- `doc/tol.md` Q3 and Q4.
- `doc/actor.md` section 5.5 (`become` / state machines), section
  5.6 (request/reply correlation), and section 5.8 (observability).
- `doc/tos-message-policy.md` v6, especially sections 3, 4, 5, 8.1,
  and 9.3.
- `doc/tos-language-syntax-policy.md` v3, especially sections 3.2,
  3.4, 3.8, 6.1, 7, 8, 9, and 10.1.
- Current Slice 2 reference contracts:
  `crypto/smartcont/jetton-minter.tol`,
  `crypto/smartcont/jetton-wallet.tol`, and
  `crypto/smartcont/wallet-v5.tol`.

## 1. Ground facts carried into Slice 3

Slice 1 is complete. The `Envelope`, `Error`, `OP_ERROR`, bounce
policy, `query_id` propagation warning, conformance fixtures, fuzz
smoke, gas gate, migration guide, and external RFC exist.

Slice 2 is complete. The compiler parses and lowers `contract`,
`storage:`, `receive`, `states:`, `@initial state`, `@on`, `become`,
`keep_state`, `@deploy`, unknown-opcode modes, `receive_external`,
contract-local `get fun`, `require`, and receiver-local
`@disclaim_query_id`. The reference contracts have been re-migrated
to Slice 2 syntax.

Slice 2 deliberately did not add a `message` keyword. Opcode-bearing
types continue to be normal Tol structs with a declared 32-bit prefix,
for example `struct (0xf8a7ea5) Transfer { ... }`. Slice 3 stdlib and
scaffolding MUST use that spelling unless a later language RFC changes
it.

External messages are not part of the Slice 1 internal `Envelope`
contract. `receive_external` can be wire-compatible with wallet-vN
external bodies, but Slice 3 must prove that with dedicated
wallet-style fixtures rather than inheriting `tos-message-policy.md`
section 8.1 automatically.

## 2. First-principles constraints

1. **No new wire surface.** Slice 3 introduces no TL-B constructor, no
   TVM opcode, no bounce-body format, and no `extra_flags` mask
   widening. Any stdlib helper must lower to existing Slice 1 / Slice 2
   behaviour.
2. **Dogfood before abstraction.** A stdlib pattern is accepted only
   after at least one official reference contract uses it and the
   resulting bytecode/gas deltas are measured.
3. **Stdlib patterns are not traits.** Slice 3 may extract concrete
   helpers and templates. First-class behaviour traits remain Slice 4
   / Year 2 work.
4. **Escape hatches stay available.** Reference migrations may keep raw
   cell builders, raw external-body parsers, and direct TVM helpers
   where wire compatibility or gas requires them.
5. **Budget is a release gate.** A pattern whose generated/reference
   implementation exceeds the handwritten equivalent by more than 15%
   in bytecode cells or measured gas fails the stage unless the
   exception is explicitly approved in the stage record.
6. **Replayability is part of the feature.** A domain stdlib pattern
   without deterministic replay fixtures is not shipped, because the
   library user cannot distinguish a compiler bug from a contract bug.
7. **Static analysis must stay conservative.** False positives may be
   introduced in warning mode when the analysis is new. False negatives
   that bless a known spoofing, replay, state-corruption, or
   wire-compatibility bug are blockers.

## 3. Non-goals

Slice 3 does not implement supervision, scheduled messages,
capability addressing, bounded postponement, trait-based behaviours,
sum-type storage, cross-language ABI freeze, external-message protocol
changes, or a Solidity-compatibility layer.

Slice 3 does not promise that all existing FunC reference contracts
disappear. FunC remains the low-level system-contract language. Slice 3
proves that ordinary Jetton, NFT, wallet, ownable, and multisig
patterns can be authored in Tol without losing the wire and gas
properties that made the original references acceptable.

## 4. Stage plan

### Stage 0 - Policy and baseline lock

Deliverables:

- This RFC approved as the Slice 3 implementation input.
- Current Slice 2 reference-contract bytecode, gas, opcode, method-id,
  error-code, and external-body baselines captured in a machine-readable
  file under `doc/`. The Stage 0 baseline file is
  `doc/slice-3-reference-baselines.json`.
- A decision record naming the first two vertical stdlib targets. The
  approved order is Jetton first, NFT second, because Jetton already has
  two migrated references and exercises both master/wallet interaction
  and bounce paths.

Exit criterion: complete as of 2026-04-30. The stdlib implementation
does not begin until Stage 1's deterministic replay/property harness is
checked in.

### Stage 1 - Deterministic property/replay harness

Deliverables:

- A replay fixture format for Tol contracts that records initial c4,
  inbound message body, sender/value flags, expected c4 delta, expected
  outbound bodies, exit behaviour, and gas/cell metrics.
- A runner that can execute these fixtures through the local compiled
  contract path used by `tol-tester` and `test-emulator`.
- Property-style generators for in-bounds and out-of-bounds
  `Envelope`, Jetton, NFT, and wallet message bodies. Generators must be
  deterministic under a recorded seed.
- CI integration that keeps the existing Slice 1/2 test counts intact
  and adds Slice 3 fixtures without replacing older fixtures.

Design choice: use a hybrid substrate. Keep fast deterministic
contract-level checks in `tol-tester`, but use emulator replay for
message/value/bounce/gas assertions. Do not require a live devnet for
the Stage 1 gate.

Implementation status: complete as of 2026-04-30. The replay schema
is checked in at `doc/slice-3-replay-fixture-schema.json`; the first
fixture is
`emulator/test/slice-3-replay-fixtures/jetton-minter-stage1.json`;
`scripts/check-slice-3-replay-fixtures.py` is the CI entrypoint; and
`emulator/test/slice-3-replay-fixture.cpp` replays the fixture against
the compiled Slice 2 `jetton-minter.tol` BoC through `test-emulator`.
The first deterministic negative generator is
`splitmix64-unknown-opcode`, with its seed and case count recorded in
the fixture.

Exit criterion: at least one existing Slice 2 reference contract has a
checked-in replay fixture and one deterministic negative generator.

### Stage 2 - Stdlib foundation and package shape

Deliverables:

- Package layout under `crypto/smartcont/tol-stdlib/` for:
  `ownable`, `jetton`, `nft`, `wallet`, and `multisig`.
- Import names and file naming rules stabilized before pattern code is
  added. Import churn after Stage 2 is a breaking change.
- Shared helper modules for:
  ownership checks, two-step ownership transfer, raw reply builders,
  `OP_ERROR` construction, error-code documentation, query/reply table
  storage, and replay-test assertions.
- A generated manifest format for each stdlib pattern containing
  opcode prefixes, get-method ids, auto-numbered `require` codes, public
  error codes, storage fields, and known wire-compatibility exceptions.

Implementation status: complete as of 2026-04-30. The stable import
names are `@stdlib/ownable`, `@stdlib/jetton`, `@stdlib/nft`,
`@stdlib/wallet`, and `@stdlib/multisig`, with shared Slice 3 helpers
in `@stdlib/slice3-common`. The manifest schema is
`doc/slice-3-pattern-manifest-schema.json`, and the first manifest set
lives under `crypto/smartcont/tol-stdlib/manifests/`. The minimal
ownable helper exports `Ownable`, `OwnableTransfer`, explicit
authorization error codes, owner checks, and two-step pending-owner
acceptance. Focused coverage is in
`tol-tester/tests/slice3-ownable-positive.tol` and
`tol-tester/tests/slice3-stdlib-layout.tol`.

Exit criterion: a minimal `ownable` helper is used by a focused test
contract, passes replay tests, and stays within the 15% budget.

### Stage 3 - Jetton vertical slice

Deliverables:

- Jetton master and wallet helper modules conforming to the existing
  Jetton wire format.
- A Jetton sample generated from the stdlib pattern, plus a migration of
  the official `jetton-minter.tol` and `jetton-wallet.tol` references to
  use the helpers where that does not change wire bytes or exceed the
  budget.
- Replay/property fixtures for transfer, internal transfer, burn,
  burn-notification, excesses, authorization failures, unknown opcode,
  bounce handling, and duplicate/replayed `query_id` cases.
- A per-helper gas and bytecode report comparing raw Slice 2 reference
  code with the stdlib form.

Exit criterion: Jetton master and wallet pass the existing Slice 1/2
tests plus new replay fixtures, preserve TEP wire bodies bit-for-bit,
and stay within budget.

Implementation status: complete as of 2026-04-30. `@stdlib/jetton`
now owns the shared Jetton opcode constants, wallet state-init/address
helpers, raw TEP-74 body builders, basechain guard, and minter/wallet
error mapping helpers. `crypto/smartcont/jetton-minter.tol` and
`crypto/smartcont/jetton-wallet.tol` keep their old helper names as
compatibility wrappers for existing tests while dogfooding the stdlib
implementation underneath. The direct stdlib coverage is
`tol-tester/tests/slice3-jetton-stdlib-positive.tol`; the legacy
Jetton suites still pass. The regenerated Tol BoCs match the Stage 0
baseline exactly:
`jetton-minter-tol.boc` stays `483` bytes with SHA-256
`ec48d61cee436991b6248c58631e86d7241b9fe487ca3250859ad28cb363823c`;
`jetton-wallet-tol.boc` stays `740` bytes with SHA-256
`7448e96820d6656b57e9c7e27411197e624f48efe4b9dcf4fae1efb13d86b798`.

### Stage 4 - NFT vertical slice

Deliverables:

- NFT collection and item helper modules conforming to the existing NFT
  wire format.
- Official NFT reference contracts or fixtures written in Slice 2 syntax
  and then rewritten to the Slice 3 stdlib form.
- Replay/property coverage for mint, transfer, ownership query,
  collection/item linkage, unknown opcode, bounced transfer, and
  authorization failures.
- Gas/bytecode budget report.

Exit criterion: a generated NFT collection/item pair deploys, handles
the canonical message set, and preserves wire-compatible bodies.

Implementation status: complete as of 2026-04-30. `@stdlib/nft` now
exports the TEP-62 / royalty opcode constants, transfer and reply body
structs, collection mint body helper, item state-init/address helpers,
raw transfer / deploy / ownership-assigned / excesses /
static-data-report / royalty-report builders, bounce-flag helper, and
item/collection error mapping. Focused coverage is
`tol-tester/tests/slice3-nft-stdlib-positive.tol`, which checks mint,
deploy, transfer, ownership-assigned, excesses, static-data report,
royalty report, collection/item address linkage, authorization failure,
unknown-opcode mapping, and bounced-message flag detection against
manual builders. There is no pre-existing official Tol NFT reference
under `crypto/smartcont/` to migrate byte-for-byte in this stage; the
wire-compatibility comparison is therefore fixture-level against the
local legacy FunC and JS wrapper shapes.

### Stage 5 - Wallet and multisig vertical slice

Deliverables:

- Wallet helpers for signed external bodies, seqno checks, wallet-id
  checks, action-list validation, and extension-action parsing.
- A wallet-v5 migration that keeps the raw signed-body shape and does
  not force wallet-v5 through the internal `query_id` preflight model.
- Multisig helpers for signer-set storage, threshold checks, proposal
  replay protection, and action execution.
- Replay/property fixtures for signature failure, seqno replay, expired
  request, invalid C5/action list, extension authorization, multisig
  duplicate signer, and threshold boundary cases.

Exit criterion: wallet-v5 remains wire-compatible for both internal and
external bodies, and multisig has at least one executable generated
contract with replay fixtures.

Implementation status: complete as of 2026-04-30 for the Stage 5
minimum helper slice. `@stdlib/wallet` now owns wallet-v5 constants,
storage packing, raw signed-body prefix/header parsing, extension-action
body construction, C5 `action_send_msg` chain validation, and error
mapping. `crypto/smartcont/wallet-v5.tol` keeps its old helper names as
compatibility wrappers and still processes signed internal/external
bodies as raw slices, so the wallet-v5 external body shape is not routed
through the Slice 1 internal envelope. `@stdlib/multisig` now owns
signer-set insertion/lookup, duplicate-signer rejection, threshold
checks, pending-proposal replay checks, expiry checks, action-list
validation through the wallet action-chain helper, and multisig error
mapping. Focused coverage is in
`tol-tester/tests/slice3-wallet-stdlib-positive.tol` and
`tol-tester/tests/slice3-multisig-stdlib-positive.tol`, while the
existing wallet-v5 tests continue to pass. The regenerated wallet-v5 Tol
BoC remains at the Stage 0 baseline: `815` bytes with SHA-256
`9e8aa8c3e12150389381647bb836ee084ea561f69b33a06c407717a1495c9b03`.

### Stage 6 - `tol new` scaffolding and documentation

Deliverables:

- `tol new --pattern jetton`, `tol new --pattern nft`,
  `tol new --pattern wallet`, and `tol new --pattern multisig`.
- Generated source, tests, replay fixtures, deploy skeleton, and pattern
  manifest for each supported pattern.
- Task-oriented docs:
  "Writing TOS contracts in Tol", Jetton walkthrough, NFT walkthrough,
  wallet/multisig walkthrough, and "TVM model for Solidity developers".
- Off-chain observability artifacts from `actor.md` section 5.8 that do
  not require protocol hooks: opcode maps, method-id maps, error-code
  maps, replay traces, and generated manifests consumable by indexers and
  explorers.

Exit criterion: a new author can create, build, test, and inspect a
Jetton or NFT project from `tol new` without hand-writing opcode,
method-id, or error-code tables.

Implementation status: complete as of 2026-04-30 for the repo-side
scaffold package. `tol new --pattern jetton|nft|wallet|multisig`
generates source, a smoke test, replay/deploy stubs, a manifest, and
off-chain observability artifacts (`opcodes.json`, `method-ids.json`,
`error-codes.json`, and `replay-trace.json`). The verification entrypoint
is `scripts/check-slice-3-scaffold.py`, which generates all four
patterns into a temporary directory, runs `tol --check-only` on each
source file, executes the generated tol-tester smoke tests, and validates
the JSON artifacts. Task-oriented docs are
`doc/slice-3-writing-tol-contracts.md`,
`doc/slice-3-jetton-walkthrough.md`,
`doc/slice-3-nft-walkthrough.md`,
`doc/slice-3-wallet-multisig-walkthrough.md`, and
`doc/slice-3-tvm-model-for-solidity-developers.md`.

### Stage 7 - Q4 static-analysis hardening

Deliverables:

- `pipe-check-receive-exhaustiveness.cpp`: for each state and each
  declared internal receive domain, report whether a message is handled,
  explicitly ignored, explicitly thrown, or accepted by an unknown-mode
  catch-all. Unknown catch-alls are permitted only when they are visible
  in the source.
- Stronger request/reply correlation checking for stdlib send-with-reply
  patterns. The table key is `(expected_responder, query_id)`, with
  `expected_reply_opcode` as an optional discriminator inside that key,
  matching `tos-message-policy.md` section 4.3.
- Duplicate-reply and replay handling rules for the stdlib table: a
  consumed reply is removed or marked consumed before user-visible side
  effects; duplicate replies are rejected or ignored according to the
  pattern manifest.
- Warning-first mode for legacy/raw code, error mode for stdlib helpers
  whose manifest declares a reply-producing API.

Non-goal: protocol timeouts. Without the future scheduled-message/time
primitive, Slice 3 can provide explicit sweep/expiry helpers but cannot
guarantee delivery deadlines.

Exit criterion: the Jetton/NFT/wallet/multisig replay suites include at
least one spoofed-responder test and one duplicate-reply test, and the
new checker catches the unsafe variant.

Implementation status: complete as of 2026-04-30 for the repo-side
static-analysis hardening package. `tol/pipe-check-receive-exhaustiveness.cpp`
runs before contract lowering and warns on implicit unknown-opcode
policy plus state/message cells that fall through to the synthesized
state guard. `tol/pipe-check-slice3-reply-correlation.cpp` runs after
query-id propagation and rejects direct user access to
`Slice3PendingReplyTable.entries`, forcing manifest-backed reply APIs
through `Slice3PendingReplyTable.reserve(...)`, `.consume(...)`, or
`.ignoreDuplicate(...)`. The stdlib table key is
`(expected_responder, query_id)` with optional `expected_reply_opcode`;
`consume(...)` deletes the pending reply before returning it, so spoofed
responders and duplicate replies hit the same rejected missing-key path.
Raw `slice3PendingReplyKeyHash(...)` construction remains warning-only
for legacy code.

### Stage 8 - External author trial and release package

Deliverables:

- At least one contract author who did not implement the compiler uses
  `tol new` plus the Slice 3 stdlib to build a Jetton or NFT in under
  one hour.
- Release notes covering supported patterns, budget numbers, known
  escape hatches, and unsupported protocol features.
- Compatibility matrix for Slice 1, Slice 2, and Slice 3 contracts.
- Final audit checklist signed off before the release branch is cut.

Exit criterion: Slice 3 success criterion in `roadmap.md` section 9 is
met by a real author trial, not by a maintainer demo.

## 5. Required review gates

Every Slice 3 implementation stage must answer these questions before
merge:

- Does this stage change any TL-B schema, TVM opcode, bounce body, or
  `extra_flags` mask? The expected answer is no.
- Does every generated opcode-bearing body use a declared 32-bit struct
  prefix?
- Are external wallet bodies tested separately from internal
  `Envelope` bodies?
- Are bytecode and gas deltas recorded against the Stage 0 baseline?
- Does the pattern manifest list opcodes, get-method ids, error codes,
  storage fields, and wire exceptions?
- Are replay fixtures deterministic under a recorded seed?
- Does the query/reply path bind both responder address and `query_id`,
  not `query_id` alone?
- Does the implementation avoid introducing trait or behaviour syntax
  before Slice 4?

## 6. Deep self-review of this RFC

The review below is part of approved v1. It records defects found while
writing the RFC and the corrective rule now present in the text.

| ID | Severity | Finding | Resolution in this RFC |
|---|---|---|---|
| R1 | HIGH | The older roadmap text still named a `message` keyword for Slice 2, but Slice 2 v3 explicitly made `struct (0xNN)` canonical and put `message` out of scope. Building Slice 3 around `message` would generate syntax the compiler does not own. | Sections 1 and 4 require opcode-bearing `struct (0xNN)` types and prohibit stdlib/scaffolding from assuming `message`. |
| R2 | HIGH | The Slice 2 syntax policy still said Slice 3 would re-migrate the Slice 1 references to Slice 2 syntax, but that already happened in Slice 2 Stage 8. If left uncorrected, Slice 3 could count already-completed syntax migrations as stdlib dogfood. | Sections 1, 3, and Stages 3-5 define the new work as a stdlib rewrite on top of the existing Slice 2 references. |
| R3 | HIGH | Wallet-v5 signed external bodies cannot be forced through the internal `Envelope` / `query_id` model without breaking wire compatibility. | Sections 1 and Stage 5 require separate external-body fixtures and raw signed-body preservation. |
| R4 | HIGH | A Foundry-class property framework is too large to leave as an implicit prerequisite. Without a staged substrate choice, Slice 3 could block after stdlib code exists but before it can be trusted. | Stage 1 chooses a hybrid `tol-tester` plus emulator replay substrate and makes the fixture format the first implementation gate. |
| R5 | HIGH | Stronger `query_id` analysis can easily become unsound if it matches only by `query_id` or treats all replies as the same opcode. | Stage 7 binds correlation to `(expected_responder, query_id)` and makes `expected_reply_opcode` an optional discriminator inside that key. |
| R6 | MEDIUM | Trait-like behaviour design is tempting when writing a domain stdlib, but `tol.md` places traits in Year 2 after dogfooding. | Section 2 and the review gates forbid Slice 3 from adding trait/behaviour syntax. |
| R7 | MEDIUM | A one-size wallet stdlib can hide wallet-v5-specific validation such as C5 action-list checks, signature mode, extensions, and seqno replay. | Stage 5 names wallet-v5-specific helpers and replay cases instead of pretending wallet is a generic internal-message actor. |
| R8 | MEDIUM | The static analysis plan could make raw legacy code fail immediately, blocking migration. | Stage 7 uses warning-first mode for raw code and error mode only for stdlib APIs with explicit manifests. |
| R9 | LOW | Off-chain observability was recommended for Slice 3 in the roadmap gap table but absent from the coarse Slice 3 paragraph. | Stage 6 adds generated manifests, opcode maps, method-id maps, error-code maps, and replay traces as off-chain observability artifacts. |

Open issues intentionally left for implementation design:

- The concrete representation of the stdlib query/reply pending table.
- The first external author used for the Stage 8 trial.

None of these open issues changes the security or wire-compatibility
contract of this RFC.
