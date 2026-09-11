# M5 encoding handoff

Branch: `agent/uno-m5-encoding`, worktree `/home/tomi/tos-m2`.
Specification: memo main `01a82572`, SHA256 prefix `aaac1f54cce57364`.
The newer user messages, especially the D69 corrections, supersede older prose.
A owns host integration and ABI inventory; B owns TL-B and encoding. Never hash
or import A's WIP. A's committed `0f799c88e` was merged as `66505f935`.

## Preserved work and evidence

- `48dca2c42`: D64 review, proof tests and the original frozen symbolic prediction.
- `0e8fbbc12`: D66 applicability addendum and earlier interface proposal.
- `76a317394`: initial Withdrawal wire/context/record codec. Its free Attempt
  sequence was wrong and is superseded by the next commit.
- `ccc24052e`: one Attempt per Withdrawal, no attempt sequence/counter; bounded
  control envelope, ID Add semantics, independent created_lt uniqueness,
  enumerated count and nonempty control closure check. Six codec tests passed;
  isolated LT/count/closure check removals each exited 1. The existing three
  M3 wallet vectors passed their unchanged field and candidate-hash assertions.
- `475214710`, `9be4f9c67`: frozen D68 shortfall prediction and English-reference
  correction. Do not rewrite these or the older prediction to fit observations.
- `fc55a5590`: WIP D69 origin codec, V2 primitive ABI and complete schema-3
  account-envelope codec. No node call site is installed by this commit.

Executed on the fc55a5590 contents:

    cargo test --locked --offline --lib system_encryption
    # cwd uno/crypto: 7 passed, 0 failed (debug)
    cmake --build /home/tomi/uno-m3-refund-assert-build --target test-workchain-withdrawal-codec -j2
    ctest --test-dir /home/tomi/uno-m3-refund-assert-build -R '^test-workchain-withdrawal-codec$' --output-on-failure
    # 1 CTest target passed; direct executable: 9 tests passed

The tests cover all three origin roundtrips, zero/truncated sequence rejection,
actual C++ canonical origin bytes consumed by Rust V2, unchanged D33 fixed
ciphertext, distinct new-member transcripts, schema-3 full-root roundtrip,
4-root-reference framing, old/new decoder rejection without implicit migration,
account binding and malformed control. Two identical sweep attributions with
sequences 41/42 produce different receipt IDs AND different commitment/handle;
old ciphertext verification under the second request returns VERIFY=3.
These are codec/primitive results, not successful host issuance/settlement.

Local logs: `/tmp/d69-rust-tests.log`, `/tmp/d69-codec-build.log`.
Logs are convenient, not required inputs to reproduce the committed tests.

## Callable APIs and representation

`crypto/block/workchain-system-origin.h`:

- `WorkchainSystemOrigin` variant: Deposit, Settlement, Sweep; tags 0/1/2.
- `encode/decode_workchain_system_origin` and `derive_workchain_system_receipt_id`.
- `encode_workchain_system_origin_transcript`: exact canonical bytes, 41/115.
- `encode/decode_workchain_system_receipt`: new tagged receipt; old receipt
  constructors and Deposit identity derivation remain unchanged.
- Sweep attribution stores type 2, src workchain/address, account_id, uint256
  value and return_failed. Host must enforce D62 eligibility, not trust encoding.

`crypto/block/workchain-withdrawal-account.h`:

- `encode/decode_workchain_withdrawal_account(value/root, authenticated_limit)`.
- `WorkchainWithdrawalAccount` holds `account`, authenticated `control`, and
  `origin_pending`. The legacy system receipts in `account.system_pending` and
  new `origin_pending` share ONE capacity of four and ONE Add-only dictionary.
- `account.schema_version` is 3. Component validation reuses an internal schema-2
  projection that is never installed; input decoding accepts only the new root.
- Both account and control expose lifecycle; their encodings must agree.
- Existing generic account/ReplayInput decoders have NOT been expanded. A must
  dispatch the new tags to their dedicated APIs and perform explicit migration.

Rust `SystemEncryptionRequestV2` / generated C header: abi_version 2, domain,
receipt_id, recipient, amount, origin[115], origin_bytes. Tail bytes zero.
`uno_crypto_system_encrypt_v2` / `uno_crypto_system_verify_v2` are additive;
Deposit delegates to unchanged v1 transcript. New source labels differ. See
`uno/crypto/ABI.md` for exact byte order and host provenance obligations.
The ABI does not independently parse/authenticate TL-B attribution or its ID.

## Exact next steps

1. COMPLETED after the handoff commit: run
   `python3 crypto/test/workchain-d69-sequence-controls.py --repo /home/tomi/tos-m2 --build /home/tomi/uno-m3-refund-assert-build`.
   Deposit, Settlement and Sweep each exited 1 at `missing.is_error()` after
   removing only the required-sequence check. The initial ccache argument-order
   tool failure was corrected; it was not counted as a mutation result.
2. Add/run removal controls for the new complete-account combined system count,
   account binding and dictionary Add checks as appropriate. Do not claim the
   nine passing tests alone prove these checks detect their targeted changes.
3. COMPLETED after fc55a5590: rebuild `test-workchain-confidential-execution`,
   run its `--filter M3WalletRequests`. FormalVectorFields passed (one named
   test covers all three existing vectors). No vectors or expectations changed.
4. Give A the committed interfaces above. A must add the V2 metering entry and
   register changed Rust files/new ABI test call sites in its owned
   `crypto/test/workchain-crypto-abi-boundary.json` BEFORE any node caller is wired.
   B has not changed that file or claimed the guard green.
5. A must wire the schema-3 root/control into actual host account access, closure,
   COLLECT (both system views) and Failed custody dispatch. The standalone
   nonempty-control predicate is not evidence that the node calls it.
6. Coordinate replacement of the expired M3 no-obligation guard with the
   authenticated-set check. Do not merely delete/update the guard to turn green.
   State-loader inventory also needs an explicit review of the new codec paths;
   source-aware error classification remains the caller's responsibility.
7. Continue D62/D63 real host behavior controls and cross-check actual accounting
   against frozen predictions only after predictions have been committed.

## Boundaries and traps

- No full regression, new host activation, custody Failed acceptance, counter
  installation, no-pending host behavior or complete closure integration is
  claimed by fc55a5590. The source set is WIP despite focused tests passing.
- Deposit transcript and existing vectors MUST NOT be regenerated to fit code.
- Do not weaken coordinator `info.bounced` rejection. Failed/late bounce belongs
  to a separate custody authenticated entry. Use actual incoming envelope.msg
  CellRepr hash, never payout hash or original created_lt as message identity.
- Shared deposit_sequence uses checked increment and same-batch staged state.
  Failed issuance or no-receipt dust MUST NOT install increment. Two constructors
  reading the same batch-old value do not establish sequencing. Pending ID
  collision checks remain mandatory even with a counter and domain separation.
- consumed_return_cost is actual reserve SPENT, capped by original_reserve,
  not total actual return loss c when c>b. Shortfall is an event-derived amount,
  not a persistent payable claim or an operating-budget subsidy.
- K_withdrawal, return reserve and settlement window have no local defaults.
  The latter is not a delivery/safety bound. D68 freezing conditions still apply.
- Do not read A's expected accounting outputs before freezing new predictions.
  Independence is behavioral; coordinator-relayed outputs are not B observations.
- Communication to A repeatedly fails at localhost:42881. Do not retry the same
  message. Coordinator relays; `/tmp/uno-m5-codec-handoff.txt` is only a local
  convenience and older than this committed handoff until explicitly updated.

## Ordered queue item 1: complete account codec delivery

The full-root API was already committed in fc55a5590; it is not awaiting
implementation. `block/workchain-withdrawal-account.h` exports
`encode_workchain_withdrawal_account(value, authenticated_limit)` and
`decode_workchain_withdrawal_account(root, authenticated_limit)`, returning
`WorkchainWithdrawalAccount { account, control, origin_pending }`.
Generic old-account decoding is intentionally not widened. Host dispatch,
explicit migration authorization and calling the closure check remain A's work.

The focused account test now simultaneously installs user, legacy Deposit and
new-origin receipts into the same root. It passes and checks that the retained
legacy Deposit cell hash is unchanged. Combined legacy/new system capacity is
four. Isolated removal of the combined-capacity check and record-account binding
check each exits 1 at the corresponding assertion. Reproduce with:

    python3 crypto/test/workchain-withdrawal-account-controls.py --repo /home/tomi/tos-m2 --build /home/tomi/uno-m3-refund-assert-build

These complete the two new-account checks previously listed under next step 2;
they do not replace the already committed control ID/LT/count/closure checks or
claim actual node invocation of the full-root decoder.

## Ordered queue item 2: identical sweep attributions

Already implemented in fc55a5590 and rerun after queue item 1:

    /home/tomi/uno-m3-refund-assert-build/crypto/test-workchain-withdrawal-codec --filter IdenticalSweepAttributionUsesDistinctIssuedSequences
    # Test_SystemOrigin_IdenticalSweepAttributionUsesDistinctIssuedSequences: PASS; 1 test passed

The test copies the entire sweep attribution, including src, account_id,
value and return_failed. Only issued sequence changes from 41 to 42. It compares
all encoded attribution bytes (after the root kind and sequence), then checks
distinct receipt IDs, distinct commitment bytes and distinct handle bytes via
actual Rust V2 calls. Verifying the first ciphertext against the second request
returns VERIFY=3. Zero sequence is separately rejected by the origin codec;
its isolated check-removal control was recorded in 8683606c8.

This is the exact identical-entry derivation case, not merely a codec
roundtrip. It is still not a host sweep or atomic counter-installation test;
those are distinct obligations in queue items 3 and 4.

## Ordered queue item 3: actual sequencing producer not yet present

Read-only inspection of A's committed tree `2353777c7` (not WIP) found the
only issuance counter install in `workchain-deposit-transition.h:81`.
`workchain-deposit-admission.h:80` calls the checked helper; the helper at
`workchain-coordinator-state.h:131` rejects UINT64_MAX before increment.
The new `associate_workchain_withdrawal_return` explicitly performs read-only
association: no receipt issuance, counter advance or W/P release.

Consequently three-source same-batch sequencing cannot yet be tested against
actual host producers. This item is NOT complete. When A commits those producers,
feed their actual before/after coordinator and pending roots into controls for:
(1) chained staged counters, (2) two competing successors of the same old value,
and (3) failure/no-receipt paths publishing an increment. Do not substitute a
hand-built synthetic counter trace and call it three-source host evidence.
Queue item 4 (real D62/D63 integration) likewise remains pending, not skipped
or declared covered. No A implementation or prediction fixture was modified.

Queue item 5 was already frozen separately in `475214710` (English-reference
follow-up `9be4f9c67`), before these queue instructions. Both invariant equations
hold algebraically in the deficient Failed branch; it is not an actual host
observation. Do not duplicate or rewrite that prediction while waiting for
items 3/4. The earlier specification SHA remains its evidence provenance.

## D51 arrival trigger for the pending sequencing controls

`test-workchain-system-sequence-expiry` is now in default CTest. It inventories
counter/allocator syntax units over explicit Native/account roots plus the named
test-scope registered Native adapter. Initial reachability is 221 files, printed
on every run; exceeding 442 requires scope review. Current installation is the
Deposit successor only; serialization and read references are explicitly pinned.

Default CTest passed in 1.65 seconds. New reachable-file writer, same-file writer
and changed existing writer each trigger the expiry action. Unrelated adjacent
fields and disconnected files do not. In an isolated script variant, disabling
the inventory comparison exits 1 at the new-writer control. No production source
was mutated for these controls.

This is a lexical/static arrival trigger, not three-source sequencing evidence.
New reads conservatively require review too. Aliases, indirect writes/runtime
coupling and separately linked units outside named roots are not inferred.
When it expires, install real host controls for staged increments, competing
successors and failure/no-receipt nonpublication before accepting another writer;
do not merely refresh the baseline. Actual D62/D63 remains deferred as directed.

The effective queue's D68 item is complete: see
`doc/uno-m5-d68-d51-applicability.md` for the current specification hash and
explicit algebra checking both equations. The earlier frozen prediction is
unchanged. This is not a report of host execution or fee measurements.

## Executable successor handoff

See `doc/uno-m5-sequence-handoff.md` for the six exact host test contracts,
fixture provenance, committed-state assertions and mutation failure points.
`workchain-system-sequence-handoff.py --build BUILD_DIRECTORY` fails closed
when successor tests are missing or disabled. Current run exits 1 listing all
six missing tests; this is readiness evidence, not host sequencing evidence.
The default expiry diagnostic now points to that procedure. Its scanning scope
and predicate are unchanged. Only B's sequence premise expires on a new issuer;
A's prepare guard remains until its separate Native prepare evidence exists.
Specification: memo 19d0446e / SHA256 prefix 71968ef2afb0d917.

## D70 symbolic extension

`doc/uno-m5-d70-accounting-addendum.md` reserves issuance compute as
`g = checked(base_compute * u)` with no local billing-unit value. It covers
funded Paid/Failed and sweep book/physical deltas symbolically and names the
future observation slice, execution paths and omission controls. The old
slot-only synthetic sweep predicate is not D70 coverage. Routing of the new
compute component versus D63's old all-fee-to-coordinator wording, and the
`s < m <= s+g` no-positive-receipt branch, remain explicit questions. No actual
host execution or complete D70 branch coverage is claimed. Earlier frozen
prediction files are unchanged. Spec prefix: f900bb4b043c82e2.

## D71 resolves D70's two open accounting questions

See `doc/uno-m5-d71-accounting-addendum.md` (spec b01d284b511b1607).
The no-receipt threshold is now s+g; that entire band sends m to coordinator,
with no issuance, issuance compute revenue or sequence increment. Funded
issuance sends s to coordinator and g to fees_collected. Successful type-2
sweep therefore increases D60 slack by s, not s+g. Both conservation equations
hold symbolically in funded and no-receipt Paid/Failed branches. No billing-unit
number was chosen. Prior files retain their original evidence versions; the
D70 questions are resolved by this new addendum, not by rewriting them.

## D73 phase prerequisite review

`doc/uno-m5-d73-phase-handoff.md` records the paired prepare/queue prerequisite,
strictly later authenticated absence, and truthful rather than earliest removal
height, with seven concrete Native controls. Current codec allows equality
between removal and opened heights; D73 does not. That difference is reported
for integration, not silently changed in this documentation task. The codec
cannot attest queue presence/absence. Source spec: 3b4413b390f43969.

## D74 late bounce with an unevaluated open record

D73 handoff control 8 now requires real paired prepare, phase 1 and a matching
bounce arriving strictly after the checked deadline while no owner has touched
the account. The bounce must use the outside-window path without W/P release
or reserve top-up. Legitimate late-return issuance is observed separately and
must not be mistaken for reserve use. Replacing the height test with record-open
status is the prescribed isolated mutation. Owner-triggered Paid evaluation is
a separate observed event. Spec prefix 1df942bd8a8dae0b; prospective contract only.

## Independent D61 recheck

`doc/uno-m5-d61-independent-recheck.md` records direct B runs on A's committed
293fc152a: D61 CTest 1/1, five Native selectors green, isolated old-helper red
at the custody 270 assertion. Actual serialized custody debit and nonempty
outbound message are checked. Eight consumer files versus A's seven unique
listed files: only the M5 accounting assertion test was omitted from prose;
it was already changed and now executed. Construction-isolation was inventoried
but not run in this selection. No full M5 or full regression claim.

## External review scope draft

`doc/uno-d34-external-review-scope-draft.md` separately names SEND/COLLECT,
registration Schnorr, closure DLEQ, Withdrawal amount derivation and prepare
pending prohibition, and D33/D69 verification plus actual host callers. It
preserves the proof-system soundness premise and handle-redundancy distinction.
It is not an audit or commissioning action. Current D34/D44 still say no further
external audit while spec line 67 recommends budgeting one; the draft reports
that governance inconsistency rather than silently changing the decision.

## Independent D64 implementation recheck

`doc/uno-m5-d64-implementation-recheck.md` binds six requested checks to original
5f628635d source lines, with a full 8x6 matrix/target table and six ordered ranges.
Independent isolated tests pass 2/2; witness-index and range-object mutations each
exit 101, restoration passes. The original T>Vmax gate is historical and was
removed by 15c34b205. No authenticated tariff lookup or actual Withdrawal host
caller exists in that original commit; f is bound separately but its source
cannot be certified there. The runnable review script and expectation module
are committed; no production or A-owned code is changed.

## Withdrawal fee admission: control 9

The phase/acceptance handoff now specifies a proof-valid underpriced Withdrawal
(f=f_required-1) and an independently generated floor-priced positive case.
It distinguishes kernel proof validity, host admission refusal, and validator
rejection of claimed successful underpriced execution. Two future default CTest
names and a host-comparison removal control are specified; no current execution
is claimed. Billing inputs must come from explicit authenticated test policy,
not proof-work units. Implementing A must supply actual admission diagnostics
and authenticated before/after artifacts before closing this item.

## WITHDRAWAL-PREPARE acceptance handoff

`doc/uno-m5-withdrawal-prepare-handoff.md` specifies nine real Native contracts
and exact future CTest names. The dedicated Python runner currently exits 1,
WITHDRAWAL-PREPARE_NOT_READY, listing all nine missing targets. Disabled/skipped
execution, absent observation markers and test/tool failures cannot pass.
Mocked runner-only controls exercised disabled, skipped, missing marker, failed
test and successful execution reports; these validate the runner, not Native
behavior. Each actual target must implement the documented positive, isolated
mutation and restoration evidence before emitting its marker.

The cap test separates owner-touch settlement from prepare: settlement may add
backed pending, while the prepare event must preserve the complete pending cut.
No A file, production source, CMake registration or frozen prediction was changed.
Specification: 45b20d8f6678edeb. Return to read-only review after delivery; a
committed prepare integration triggers B's independent shadow-build review.

## Outstanding parameter freezes after funded Failed review

Owner confirmation following `d08348b31`: successful live execution does not
freeze protocol parameters. Keep these open through the specification's §12.1
freeze process; explicit implementation-test inputs are not deployment defaults.

| Parameter | Status / boundary |
|---|---|
| `failed.issuance_billing_units` (D70) | Not frozen. The reviewed fixture explicitly encoded 4; with authenticated test base 2 it produced g=8. Neither 4 nor 8 is a frozen protocol constant. Billing units remain distinct from proof-work units. |
| Withdrawal `f_state` | Not frozen; explicit test configuration only, no local default. |
| `max_bounce_cost` | Not frozen; reserve must match authenticated configuration. Apply D68's pricing-change margin criteria, not a universal network-cost guarantee. |
| `payout_settlement_blocks` | Not frozen; explicit policy, not a finite delivery bound or safety guarantee. |
| `K_withdrawal` (D67) | Initial value likewise remains separately conditional on freezing; do not infer it from test fixtures or from this list's other entries. |

The observed base=2 is the fixture's authenticated tariff input, not a newly
frozen base. This checklist grants no production activation, guard retirement,
or full Failed-contract acceptance. The independent review remains retrospective;
full three-site validator refusal behavior remains unestablished by that review.

## Current limitation-to-obligation index

See [limits tracking](uno-m5-limits-tracking.md) for the baseline-bound inventory,
existing handoff mappings, additional pending real-host gates and explicit
non-M5 boundaries. D62/D63 are now the eight mandatory BUCKET-SWEEP items;
validator unknown injection, phase/Paid/late paths and remaining acceptance
boundaries have their own fail-closed runner. No historical prediction or
review result has been rewritten as later execution evidence.
