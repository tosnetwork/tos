# TOS Slice 5 Policy RFC

Second-wave stdlib and FunC<->Tol ABI freeze.

## 0. Status, scope, and references

**Status.** Draft v1.1, 2026-04-30. This is the Slice 5 Stage 0
implementation-input candidate after the first security-review fixes.
It is not yet an approved release gate.

Slice 5 implements the `tol.md` Year 2 H2 work on top of completed
Slices 1-4. Its job is to ship the second-wave stdlib patterns and to
freeze the binary interface by which legacy FunC contracts and new Tol
contracts call, parse, and audit each other.

References:

- `doc/tol.md` section 5, Year-2 directions.
- `doc/actor.md` section 6.5, behaviour patterns.
- `doc/roadmap.md` section 6, Slice 5.
- `doc/tos-message-policy.md`.
- `doc/tos-language-syntax-policy.md`.
- `doc/tos-slice-3-policy.md`.
- `doc/tos-slice-4-policy.md`.
- `doc/slice-5-func-tol-abi.md`.
- `doc/slice-5-abi-manifest-schema.json`.

## 1. Ground facts carried into Slice 5

Slice 1 is complete. The message envelope, `OP_ERROR`, `ErrorClass`,
request/reply correlation baseline, conformance fixtures, gas gates, and
migration documentation are part of the compatibility floor.

Slice 2 is complete. Tol has contract syntax, typed `receive(...)`,
state machines, `@deploy`, unknown-opcode policies, `receive_external`,
contract-local getters, `require`, and receiver-local query-id handling.

Slice 3 is complete. The first-wave stdlib packages are stable:
`@stdlib/ownable`, `@stdlib/jetton`, `@stdlib/nft`, `@stdlib/wallet`,
and `@stdlib/multisig`. `tol new` exists, generated manifests exist,
and replay/release-package checks exist.

Slice 4 is complete. Bounded postponement exists as explicit storage,
compiler hardening rejects unsafe postponement paths, and behaviour
manifests provide check-only conformance without changing bytecode.

Therefore Slice 5 must not re-open syntax, wire format, or protocol
mailbox semantics. Its risk is different: a second-wave stdlib package
can accidentally become a de facto ABI without a stable manifest,
interop test, or rollback story.

## 2. First-principles constraints

1. **ABI before templates.** Auction, governance, oracle, and
   payment-channel helpers must not ship before their message bodies,
   get-method stack shapes, error codes, and cell encodings can be
   expressed in an ABI manifest.
2. **Interop is on-chain ABI, not source compatibility.** FunC and Tol
   do not need the same syntax. They need identical message bodies,
   getter method ids, stack result ordering, cell encodings, and error
   conventions at the TVM boundary.
3. **No new protocol surface.** Slice 5 introduces no TL-B constructor,
   TVM opcode, bounce-body format, `extra_flags` widening, protocol
   scheduled wakeup, protocol mailbox scan, or capability handle.
4. **No hidden time.** Templates with deadlines or challenge windows use
   ordinary chain time checks and explicit inbound messages. Native
   scheduled messages remain Slice 6.
5. **No `ErrorClass.BackPressure` activation.** Back-pressure remains
   reserved until `actor.md` section 5.7 delivery-SLA semantics are
   approved. Existing legacy classifications must be manifest exceptions.
6. **Dogfood before abstraction.** A helper is accepted only when it is
   used by a focused example or reference contract, has replay/property
   coverage, and has gas/bytecode budget recorded.
7. **External adoption is the release gate.** A repo-side surrogate can
   prove the release package, but Slice 5 is not complete until at least
   three external production contracts use the second-wave stdlib.

## 3. Non-goals

Slice 5 does not implement supervision, scheduled messages, capability
addressing, protocol delivery SLA, protocol-level back-pressure, system
release handling, validator application lifecycle, or FunC language
changes.

Slice 5 does not convert FunC contracts to Tol automatically. The ABI
freeze gives both languages a shared boundary; it is not a source-level
transpiler or macro system.

Slice 5 does not claim oracle truth, DAO governance legitimacy, or
payment-channel dispute finality beyond what the contract code checks.
The stdlib can enforce quorum, signatures, freshness, replay keys, and
state transitions; it cannot make off-chain facts true.

## 4. ABI freeze boundary

The ABI freeze is defined in `doc/slice-5-func-tol-abi.md` and becomes
machine-readable through `doc/slice-5-abi-manifest-schema.json`.

The frozen boundary includes:

- inbound and outbound internal message body layout;
- external message body layout where a pattern exposes external entry
  points;
- opcode prefixes and `queryId` position;
- getter method ids, argument stack order, and result stack order;
- public error-code and `ErrorClass` mapping;
- cell encodings used as state-init, payload, proof, or action data;
- manifest-recorded wire-compatibility exceptions.

The frozen boundary does not include:

- helper function names that are not exported through a manifest;
- local variable names, comments, or source layout;
- optimizer-internal stack temporaries;
- exact generated Fift text where the resulting BoC and ABI-visible
  behavior are unchanged.

## 5. Second-wave package boundaries

### Auction

The auction package covers bid validation, bid postponement where
needed, close/settle transitions, refund/excess body builders, and
manifested get methods. It must build on Slice 4 bounded postponement
where a bid is valid but too early. It must not introduce protocol
timers; close and expiry are explicit messages or getter-observable
state.

### DAO / governance

The governance package covers proposal creation, vote recording,
threshold/quorum checks, duplicate-vote rejection, execution action-list
validation, and optional timelock checks. It must not pretend to be
protocol governance. It is a contract-level pattern for application
governance.

Governance action lists must be policy-typed. The default Slice 5
governance helper admits `SendMsg`-style actions only when the proposal
policy explicitly allows the target address, value range, and send mode.
`SetCode`, `SetData`, reserve-currency, or library/code-change actions
are disallowed by default. If Stage 3 enables any code or data
replacement action, the proposal must include the expected code/data
hash and the ABI manifest must record that action class as an explicit
exception.

### Oracle

The oracle package covers reporter-set authorization, round ids,
freshness windows, quorum/median aggregation, duplicate report
rejection, and stale-data errors. It must not emit
`ErrorClass.BackPressure` for congestion and must not claim that quorum
proves off-chain truth.

Every oracle example must choose and manifest one reporter-set lifecycle:
fixed at deploy, admin-managed, or governance-managed. Dynamic reporter
changes must define whether they apply immediately or from the next
round. In-flight rounds must be evaluated against the reporter snapshot
declared for that round, not against a mutable set with ambiguous
history.

### Payment channel

The payment-channel package covers channel id derivation, signed state
updates, monotonic sequence numbers, cooperative close, challenge close,
settlement, replay rejection, and action/body builders. Challenge
windows are explicit time checks; there is no scheduled wakeup until
Slice 6.

Signed channel states must use Ed25519 over the canonical state cell
hash (`cell.hash()`) unless a later policy revision approves a checked
`raw_bits` encoding. Stage 5 starts with the `cell_hash` form so FunC and
Tol sign the same 256-bit value.

## 6. Stage plan

### Stage 0 - Policy and ABI freeze input

Deliverables:

- This RFC.
- `doc/slice-5-func-tol-abi.md`, defining the ABI freeze boundary and
  compatibility rules.
- `doc/slice-5-abi-manifest-schema.json`, defining the machine-readable
  ABI manifest shape for Slice 5 packages.
- `doc/roadmap.md` updated with Slice 5 stages and current status.

Exit criterion: security review signs off the ABI boundary and the
stage plan. No second-wave helper implementation begins before this
gate is approved.

### Stage 1 - ABI manifest validator and interop harness

Deliverables:

- Add `scripts/check-slice-5-abi-manifests.py`.
- Add at least one FunC-produced and one Tol-produced ABI fixture that
  serialize the same body/cell shape and compare the result.
- Validate opcode width, getter method ids, error-code ranges,
  `queryId` policy, optional-query presence indicators, signing inputs,
  cell-field encodings, raw/manual fixtures, and wire-compatibility
  exceptions against the schema.
- Add CI/release-package wiring without changing contract bytecode.

Exit criterion: a mixed FunC/Tol fixture proves that the ABI manifest is
not just documentation. The schema is revision-controlled after this
stage: later schema edits require a policy revision note and revalidation
of earlier Slice 5 manifests.

### Stage 2 - Auction package

Deliverables:

- Add `@stdlib/auction`.
- Migrate or wrap `examples/slice4/postponed-auction.tol` through the
  package where this stays within budget.
- Add ABI manifest, behaviour manifest, replay fixtures, and focused
  tests for bid, too-early bid, close, settle, refund/excess, duplicate
  `queryId`, stale close, low bid, and malformed body.

Exit criterion: the auction example uses the package and preserves the
Slice 4 postponement security properties.

### Stage 3 - DAO / governance package

Deliverables:

- Add `@stdlib/governance`.
- Add a focused governance example with proposal, vote, cancel/expire,
  execute, and action-list validation paths.
- Add tests for duplicate vote, unauthorized proposer, quorum boundary,
  threshold boundary, expired proposal, malformed action list, replayed
  execution, and unknown opcode.

Exit criterion: governance helpers ship with ABI manifest and replay
coverage and do not claim protocol governance authority.

### Stage 4 - Oracle package

Deliverables:

- Add `@stdlib/oracle`.
- Add a focused oracle example with reporter authorization, round
  updates, quorum/median aggregation, and freshness checks.
- Add tests for unauthorized reporter, duplicate reporter, insufficient
  quorum, stale round, outlier handling, replayed round id, and unknown
  opcode.

Exit criterion: oracle helpers make freshness/quorum guarantees explicit
and do not encode off-chain truth assumptions as protocol facts.

### Stage 5 - Payment-channel package

Deliverables:

- Add `@stdlib/payment-channel`.
- Add a focused two-party payment-channel example with signed state
  updates, monotonic sequence numbers, cooperative close, challenge
  close, and settlement.
- Add tests for signature failure, seqno replay, wrong channel id,
  stale challenge, premature settlement, duplicate close, and malformed
  state body.

Exit criterion: channel helpers are ABI-manifested and do not require
native scheduled messages.

### Stage 6 - Scaffolding, docs, and release candidate

Deliverables:

- Extend `tol new --pattern` for auction, governance, oracle, and
  payment-channel.
- Generate examples, ABI manifests, behaviour manifests, replay stubs,
  deploy stubs, opcode maps, method-id maps, and error-code maps.
- Add contract-author docs and audit checklists.
- Add `scripts/check-slice-5-release-package.py`.

Exit criterion: a repo-side author surrogate can generate and test at
least two second-wave patterns without reading compiler source.

### Stage 7 - ABI freeze sign-off and external adoption

Deliverables:

- Freeze the ABI manifest schema.
- Record ABI hashes or canonical manifest hashes for all second-wave
  packages.
- Record external production adoption for at least three contracts, or
  explicitly mark Slice 5 as release-candidate-only until those
  deployments exist.

Exit criterion: the roadmap Slice 5 success criterion is satisfied:
the second-wave stdlib is used by at least three external production
contracts.

## 7. Acceptance criteria

Slice 5 is complete only when:

- auction, governance, oracle, and payment-channel packages exist under
  stable `@stdlib/...` import names;
- each package has an ABI manifest, behaviour manifest, examples,
  replay/property coverage, docs, and gas/bytecode budget record;
- the FunC<->Tol ABI freeze document and schema are approved;
- no Slice 1, 2, 3, or 4 compatibility gate regresses;
- no new protocol wire surface is introduced;
- at least three external production contracts use the second-wave
  stdlib.

## 8. Security review focus for Slice 5

Reviewers should treat these as blocker-class surfaces:

- ABI manifests that omit a body field, getter stack result, error code,
  or wire-compatibility exception;
- a Tol helper that serializes a body differently than the FunC fixture
  it claims to interoperate with;
- auction funds becoming stuck because close/refund paths depend on
  unpriced queue drain or hidden time;
- governance double voting, action-list injection, replayed execution,
  ambiguous quorum/threshold semantics, or unsafe `SetCode` / `SetData`
  action-list permissions;
- oracle stale data, duplicate reporters, unauthorized reporters,
  unbounded report sets, ambiguous reporter-set lifecycle, or hidden
  truth assumptions;
- payment-channel signature replay, sequence rollback, premature
  settlement, challenge-window ambiguity, channel-id collision, or
  cross-language disagreement about signed bytes;
- any use of `ErrorClass.BackPressure` as active semantics before
  `actor.md` section 5.7 is approved.

## 9. Open questions

1. Which production contracts will count toward the three-contract
   external adoption gate.
2. Whether the ABI manifest hash should be included in generated
   artifacts only, or also exposed through an optional get method.
3. Whether Stage 5 payment-channel helpers should support only two-party
   channels in Slice 5 or leave a constrained extension point for
   multi-party channels.
