# B's M5 limitations: current obligation map

Inventory baseline `2c78106f1`, 2026-09-11. Normative reference supplied by owner:
memo `86e775a9`, SHA256 prefix `1f756b55faf2820c`. This is a current tracking
addendum, not a revision of any pre-observation prediction or retrospective report.

Scope: B's 24 `doc/uno-m5*.md` files at that baseline, plus
`uno-d34-external-review-scope-draft.md`. Inventory includes source hashes and
line-indexed scope/pending phrases in `measurements/uno-m5-limits-tracking/`.
This is a targeted scope-statement scan and follow-up of their named boundaries,
not a semantic proof that every possible synonym has been found. Not scanned:
M3/M4 historical documents, A-owned documents, memo's other documents, arbitrary
non-Markdown materials or Git history. No new whole-specification audit is claimed.

A historical "this run did not prove X" must remain true even when a later test
proves X. Its current implementation obligation is mapped below. Methodological
limits (retrospective evidence, shared dependencies, lexical aliases) are not
unimplemented features and cannot honestly be erased by a new green marker.

## Existing executable obligations

Run the existing named readiness runners against the intended integrated build.
Missing real adapters/tests, markers or execution remain failure; an earlier
successful isolated review does not close a larger contract.

| Source documents / uncovered property | Current tracker |
| --- | --- |
| `accounting-criteria`, `d70-accounting-addendum`, `d71-accounting-addendum`: D62 lineage/one return/governance/closure, D63 physical move and S/C routing | BUCKET-SWEEP eight items, `workchain-bucket-sweep-handoff.py` |
| `d64-review`, `d64-implementation-recheck`, `withdrawal-codec-interface-proposal`, `d61-independent-recheck`: actual wire/statement dispatch, authorized amounts, reserve record, full pending cut, Native publication | WITHDRAWAL-PREPARE nine items, `workchain-withdrawal-prepare-handoff.py`; debit/overflow/no-pending/record/enqueue must execute the actual verifier caller, not just constructor |
| `prepare-independent-review`: q/b record-copy links, not just conservation; `d76-independent-review`: original isolated budget probe | PREPARE debit/record compares each authorized/stored field independently; principal-budget probe subsequently registered in default CTest, documented in `principal-budget-default` (historical "not default" is superseded, not false at its original date) |
| `fee-admission-independent-review`, `d73-phase-handoff` control 9: proof-valid underpricing in actual producer AND validator | PREPARE fee-admission and existing `workchain-withdrawal-fee-handoff.py`; prior host-input red is real evidence but does not silently satisfy all candidate/publication subcases |
| `sequence-handoff`, `encoding-handoff`: three-source shared staged counter, competing issuers, aborted/no issuance paths | `workchain-system-sequence-handoff.py` six mandatory successors; current expiry guard cannot retire merely by reporting red |
| `withdrawal-failed-handoff`, `failed-independent-review`: actual return sources, authentic fee changes, threshold, full refusal behavior, publication, full decryption | WITHDRAWAL-FAILED twelve mandatory items, `workchain-withdrawal-failed-handoff.py`; old three refusal bodies matching is not three-path execution |
| `d68-shortfall-prediction`, `d68-d51-applicability`, `d70/d71-accounting-addendum`: shortfall and no-issuance | FAILED shortfall/remainder, real value/fee branches, not synthetic algebra |
| `statement-guard-callee-probe`: account-file side effect is not Native pending-state evidence | PREPARE no-pending/oracle-control on complete authenticated cuts; file-probe evidence remains limited |
| `d64-symbolic-prediction`, `d66-prediction-addendum`, `d68-shortfall-prediction`: predictions not observations | PREPARE, FAILED and BUCKET component oracles plus Paid/late tasks below. Observed numbers must never overwrite the predictions |

Names in this table abbreviate `doc/uno-m5-<name>.md` unless otherwise explicit.
No stored sum/internal codec equality substitutes for comparing to authorization.
Known later x/q/b/f anchor reviews remain valid within their stated snapshots.

## Additional fail-closed obligations

Run `python3 crypto/test/workchain-m5-remaining-handoff.py --build <build>`.
Each suffix below names `test-workchain-m5-remaining-<suffix>` and must print
`M5-REMAINING_OBSERVED:<full-name>` only after real controls and restoration.
These are missing-work gates, not claims that the named tests currently exist.
All must have independent oracle-disable controls that fail when their expected
named red disappears; generic nonzero or earlier setup failure is insufficient.

| Suffix / origin | Real fixture, observation cut, path and required red |
| --- | --- |
| `phase-transition` / `d73-phase-handoff` controls 1–7 | Actual paired prepare and authenticated queue snapshots; run actual 0→1 transition and validator reconstruction. Observe queue/message/height and W phase at committed cut. Orphan record, still-present payout, wrong root/height and equal/earlier height rejected at named `PHASE_QUEUE_BINDING`/`PHASE_STRICT_HEIGHT`; later truthful absence accepted. Remove each check and require its named red. Codec >= alone cannot discharge strict host height. |
| `paid-lazy` / symbolic predictions, D74 | Genuine phase-1 record, deadline passes without action: no physical change and no automatic closure. Then owner-touch performs actual Paid evaluation; observe W/P release, reserve receipt or threshold disposition, fees, sequence, Native balances. Mutate premature timer release or suppress owner-touch settlement: `PAID_TRIGGER`/`PAID_RELEASE` fails. Keep legitimate settlement pending separate from prepare's no-pending cut and test settlement-before-cap through PREPARE cap. |
| `late-return` / D68 scope, D74 control 8 | Real bounce after authenticated deadline while record still open, and another after closure; run custody entry/replay. Assert `LATE_NO_TOPUP_RELEASE` on event-local W/P and reserve, actual y-based admission or full-slot/unregistered/fee rejection into bucket. Then separate owner-touch Paid event. Mutate record-open-as-window-open or wrong account routing: named time/ownership red, not malformed proof. Record exact-deadline policy source rather than choosing one. |
| `validator-unknown` / unknown-origin review | Valid candidate/authenticated predecessor reaching real validator execution; inject raw code0 after successful execution. Observe validator boundary original-code log, count delta1, -7201 local abstention and unchanged accepted account/queue roots, independently. Remove increment only: `VALIDATOR_UNKNOWN_COUNT` fails. Mutate early acceptance/publication retaining -7201: `VALIDATOR_UNKNOWN_PUBLICATION` fails. Collator sidecars and common helper do not satisfy this item. |
| `source-classification` / unknown and Failed reviews | Independently fault candidate-owned malformed/special material versus unavailable authenticated local arena on producer and validator paths, retaining provenance. Observe named classification and no erroneous acceptance; `SOURCE_CLASSIFICATION` fails when candidate/local mapping is interchanged. Include known incarnation case and unknown fallback; zero count is not proof all known classes are correct. No requirement to simulate every physical OOM/DB failure is implied. |
| `integrated-regression` / focused-review/full-build limits | Pin final merged source/build/generated ABI and run required default gates, all four original OFF refusal sites individually, actual publication/counter controls and existing handoffs. Observe exact test executions/results, not counts alone. `INTEGRATED_REQUIRED_RESULT` fails for missing/skipped/failed required execution; separately retain an existing red-control case so a no-op runner cannot pass. Do not recursively invoke this wrapper from itself. Historical tool errors are not product defects. |
| `activation-freeze` / encoding-handoff freeze list | Distinct activation readiness, NOT an implementation blocker: require owner-approved §12.1 freeze artifacts/config identities for issuance units, Withdrawal f_state, b, settlement interval and K_withdrawal; explicit fixture values are insufficient. Actual activation policy must reject missing approvals/default substitutions at `ACTIVATION_UNFROZEN`. Remove one approval or substitute a test-only config and require named refusal; restoring approvals requires owner action, not B selecting values. This remains pending until that stage. |

No A code or default test body is added here. These gates deliberately stay red
until a reviewed successor exists; they do not declare current implementation
wrong merely because independent evidence is missing.

## Legitimate non-M5 claims, with authority (not fabricated future promises)

- Capacity/hardware, cold sync and lifecycle takeover: M6, §17 M6 row / §12.1.
  Performance envelope and full growth claims are not made by M5 fixtures.
- Wallet recovery/user disclosure and public-testnet fault/rotation/migration
  program: M7, §17 M7 row / §13. This does not defer M5 consensus classification.
- D34 cryptographic/dependency audit: owner decision, NOT silently reassigned to
  M7. Coordinator explicitly retained D34 and designated the scope draft an
  unreviewed-surface register. No external review is arranged; soundness or an
  audited supply chain is not promised by passing M5. Changing that policy needs
  the owner; implementation-specific missing host links remain tracked above.
- Arbitrary-network finite delivery bound and recipient-credit guarantee from
  Paid: not a deferred deliverable at all; §11.2/D68/D74 explicitly deny these
  implications. M7 must disclose the limitation, not promise to prove the bound.
- Production hidden-total public audit / stronger D60 budget decomposition:
  existing §3.2/D60 distinguishes test-key checks from public audit and places
  stronger ledger context in M5/M6; do not claim solved. Current required event
  routing and Native balances remain M5 gates above; a new public-audit design
  is not authorized by this task.

Retrospective vs prospective, direct vs relayed, shared vs independent, lexical
vs runtime, finite fixture vs exhaustive semantics remain evidence descriptors,
not tasks that can be "completed" by renaming a test. No claim here exhausts all
fee/policy combinations: required representative reachable branches are tracked;
an exhaustive combination proof is neither an existing M5 claim nor invented M7
work. Any newly identified required reachable branch must acquire its own gate.

Delivery: runner-only protocol selftests 11/11; real B CTest inventory returns 1
and names all seven missing obligations. Isolated deletion of `validator-unknown`
and of `paid-lazy` each makes its mandatory-membership selftest fail, exit 1.
Raw results and the baseline file/line/hash inventory are in
`measurements/uno-m5-limits-tracking/`. No newly described host test was executed.
