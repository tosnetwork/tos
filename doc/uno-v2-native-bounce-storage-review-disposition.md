# Native bounce storage review disposition

Base: `807173ffe`. Transcript:
`~/memo/reviews/uno-v2-native-bounce-storage-review.txt`.
This extraction shares pricing-closure measurement, not full disposal or live
admission. The Native walker and fee formula remain unchanged.

## F1: clear the rejected phase (fixed, defensive)

The measurement-error return now resets bounce_phase like the other early
failure returns. This is defensive cleanup, not an independently witnessed
production path. With canonical builder references, optional currency absence
handled explicitly and default unlimited counters, the new Status branch has
no demonstrated Native wire trigger. The library null-span negative does not
prove that branch or its reset. No such claim is made.

## F2: failure source is not a single policy choice (disputed framing)

A host-assembled null required reference is a local invariant failure, not a
reason to vote against a valid candidate. CandidateInvalid, LocalUnavailable
and ConfigInvalid must still be selected by source at the admitted boundary;
the generic measurement Result does not encode that distinction by itself.
There is no new choice to classify *all* measurement failures one way.

The future batch disposal caller must use the pure components, not call the
ordinary prepare_bounce_phase and interpret its bool as a disposal decision.
That separation was already required by the design. Retaining the ordinary
bool contract does not authorize the future caller to reuse it as classification.
Production source-aware admission remains incomplete and activation-blocking.

## F3: reachable evidence (fixed scope and additional tests)

The helper directly witnesses optional absence versus a null actual body root.
The latter is a library contract test, not a valid serialized Native message.
The ordinary tests additionally cover versions 12/13/16 with extra-currency-v2
off/on and a real extra-currency dictionary. Explicit case expectations cover
one 22-bit currency cell versus zero. Nonzero bit/cell prices make the counted
case cost exactly 123 against value 123; one higher lump price yields nofunds.
The uncounted cases return 23 or 22 while preserving the extra currency.
Balances, output count and ok/nofunds are checked independently of diagnostics.

The first fixture used BitArray<32>(0), which selects the pointer constructor,
not the numeric template: an isolated compiler AST confirms NullToPointer and
the `const unsigned char *` overload. The fixture now uses explicit zero().
Its initial crash is retained as a fixture failure, not mutation evidence.

## F4: the inherited NoVm walker is not recoverable

Documentation is fixed; live protection remains deferred.

Source inspection confirms load_cell_nothrow can discard a failed load result,
leaving an empty slice whose later special_type access hits a fatal null Ref.
The helper's earlier propagation wording was too strong. Its contract now
requires authentication, resource admission and full materialization/validation
before a batch call; root is_loaded() is insufficient for descendants. It adds
no catch and promises no recovery from the inherited walker. A raw database or
partly virtualized closure must not be wired directly into this helper.
This is a documented prerequisite, not a claim that typed live admission has
already implemented it. No recoverable-loader or bounded-walker claim is made.

## Optional root contract

The batch caller must derive absence from the decoded authenticated
CurrencyCollection, not accept a proposer-supplied optional hint or silently
treat a missing required root as an empty dictionary. Preserving the Native
null-as-empty representation does not require a new owner monetary policy.

The reviewer ran positive filters and a nonexistent-filter control; the latter
exits zero without executing tests. Our control runner therefore also checks
the expected `Running test` marker. Manual controls, successful builds and
source/binary hashes belong in the evidence artifact, not a claim of recurring
mutation CI. M1 and wrong-destination disposal remain incomplete.

## Restored verification

All six rebuilt controls exit 1 after their expected test starts: currency
inclusion, optional absence, shared-root deduplication, actual body-root error,
the Native caller's currency/version switch, and its forwarding-price input.
Each mutation was restored. The final build and all five CTest targets
(workchain-block, workchain-admission, vm, cells, smartcont) pass, as does a
standalone include check using the actual test compilation flags. Raw logs,
substitutions and hashes are in
`measurements/uno-v2-native-bounce-storage-evidence.json`.
