# WITHDRAWAL-FAILED fail-closed acceptance contract

Normative baseline: memo `7a732682`, specification SHA256
`e83e56b5e8fb08d994cbaff475b2a08a8371d28da6d7c61057e82e89fa8c6179`.
This pins the supplied D35/D65/D69/D70/D71/D77 decisions, not moving memo HEAD.
Source/refusal baseline: B `4f5874cdc68bc87bd4b42f57d33ecea85646a4a4`.
Prepared without reading A's in-progress Failed implementation or observing its
publication results. Prior helper/prepare results are already known; this is
behavioral independence, not structural isolation or a new cryptographic review.
Old predictions/contracts are unchanged. This is prospective acceptance, not a
claim that any Failed host control has passed.

## Executable handoff

```
python3 crypto/test/workchain-withdrawal-failed-handoff.py --build BUILD_DIRECTORY
```

The eleven exact names below must be registered in DEFAULT CTest. Each must emit
`WITHDRAWAL-FAILED_OBSERVED:<full-ctest-name>` only after its real positive,
negative, designated-failure and restored-green observations. Missing, disabled,
duplicated or skipped tests, missing markers, failures and tool errors fail
closed. No placeholder registration, WILL_FAIL inversion, or marker-only test
qualifies. The runner itself is not registered as an expected failing test.
Readiness is separate from default-suite health while the contracts are absent.

A marker cannot prove provenance or adequate coverage: independently review its
emission site, fixture and oracle. Names alone do not establish acceptance.
For each negative record: mutant source, actual reached stage, exact diagnostic
or assertion, exit status and restored run. A compile failure, malformed fixture
or earlier rejection cannot substitute for its designated red.

## Shared real fixture, amounts and observation boundary

Use a REAL authenticated prepare predecessor: committed W control record and
actual serialized payout from the same publication, with matched custody source,
principal x, actual created_lt, destination and Attempt ID. Import a real rich
bounce through custody's independent authenticated inbox, then execute the
registered engine, reconstruct the candidate in validate-query and atomically
publish. Do not feed claimed effects to an accounting helper and call it host
acceptance. Never relax coordinator's existing `info.bounced` refusal.

Supply explicit authenticated test configuration for reserve b, slot fee s,
settlement interval, capacities, base beta and issuance BILLING units u.
No local/default freeze values; the reported seven proof-work units are NOT u.
Let g=checked(beta*u), h=checked(s+g). Use x>y>0, q>0, b>0, s>0, g>0 and distinct
amounts, with canonical keys, valid matching identity and sufficient slots.
Choose b>checked(x-y+h) for the main funded branch. The bounce envelope's actual
value is y; c=checked(x-y) is its already-paid return loss in this fixture.
Verify Native fee artifacts independently account for c; do not infer away
other value flows. Reject using an invented bounce or original payout hash as
its authenticated inbound identity. Queue phase is set by real prior events.

The main fixture emits ONE aggregate settlement receipt, m=checked(y+b),
z=checked(m-h). It is a Withdrawal-settlement origin containing Attempt ID and
one newly consumed shared deposit_sequence. If the implementation intentionally
splits principal/reserve into multiple receipts, that must be separately declared
before claiming this fixture: each actual receipt costs s+g and consumes its own
sequence. Never silently reuse one-receipt expectations for two issuances.

Observe independently decoded committed predecessor/successor: custody and
coordinator Native balances; full account-to-pending cut (user/system entries,
both counts, unrelated accounts); control records and enumerated cardinality;
R_book/N_book reconstruction; W/P; attributed fees_collected and inbound/outbound
message evidence. Decrypt installed rights using test keys. Effects are an
additional observation, not the authority for expected values. D/P structural
zeros are labeled as such, not fabricated persistent counters. Evaluate batch
boundaries, never a mixture of old/new snapshots.

For this isolated one-receipt funded event, with pre-settlement values suffixed 0:

```
gross custody inbound credit = y
R_actual1 = R_actual0 + y - s - g
R_book1   = R_book0   + y - s - g
N_book1   = N_book0   + z
P1 = P0 - x
W1 = W0 - (x+b)                    # q is NOT in W
coordinator1 = coordinator0 + s    # no other event or Native expense hidden here
attributed fees_collected delta = g
consumed reserve = c+s+g <= b
remaining reserve = b-(c+s+g)
z = x + remaining reserve
```

Every arithmetic operation is checked. Historical q/f have already been paid;
do not charge them again. Return c is already reflected in y: do not subtract c
again from y+b. Other documented Native charges must be separately observed and
paired, not silently folded into these expected values. A discrepancy is a
finding; do not update the oracle to match the implementation.

## Eleven real-host contracts

All names have prefix `test-workchain-withdrawal-failed-`.

### credit-y

Fixture/path: shared real bounce with y unequal to x, through inbox import and
atomic Failed publication. Observe actual envelope value and custody's gross
inbound event as well as final net balance. Assert `FAILED_GROSS_CREDIT_Y` and
`FAILED_R_NET`, using the separate anchors above. Mutation: substitute x for y
in producer accounting, retaining the authentic envelope. The first designated
red is either the validator's gross-value mismatch or the independent
`FAILED_GROSS_CREDIT_Y` assertion; record which actually executes. In either case
it must have passed framing/identity/phase checks. A general conservation error
alone is not evidence for the gross-y anchor.

### release

Fixture/path: successful main publication with other W records retained to
expose accidental whole-set clearing. Independently enumerate and sum W/P.
Assert `FAILED_RELEASE_P_X`, `FAILED_RELEASE_W_X_B`, `FAILED_Q_NOT_RELEASED` and
only the matched record removed. Mutate P's released x alone; W's x component
alone; W's b component alone; then inject q into W release. Each must hit its
corresponding release/component assertion (or the validator's specific release
comparison), not codec failure or an unrelated balance check. Also vary valid
x/b/q separately by rebuilding a matching authenticated prepare predecessor:
W release tracks x+b; P release tracks x; varying q changes neither release.
These are input anchors, not merely equality of two recomputed wrong totals.

### identity

Fixture/path: successful custody settlement with unselected user and system
receipts retained. Decode the installed origin; assert `FAILED_ORIGIN_ATTEMPT`
uses D69 Withdrawal settlement, the matched Attempt ID, and next shared staged
sequence; independently recompute points and receipt ID. Assert
`FAILED_SEQUENCE_ADVANCED_ONCE` and one new system slot; unrelated entries/counts
remain intact. Mutations separately use a wrong origin/Attempt with internally
consistent ciphertext, and sign/install the valid new receipt but leave the
published sequence at its old value. Fail the origin/event binding and sequence
publication assertions respectively, after successful issuance. A mismatched
ciphertext rejected by crypto earlier is not this identity control. Failed or
aborted publication must install neither receipt nor sequence increment; keep
both pending dictionaries' duplicate-ID rejection. This supplements, not replaces,
the existing multi-source sequence handoff and its staged-counter controls.

### topup

Fixture/path: main funded bounce, coordinator with independently observed
protected deposits/bucket holdings, and no unrelated operating flow. Derive
c=x-y from actual prior payout and actual bounce; observe original b and remaining
reserve. Assert `FAILED_TOPUP_SOURCE_RESERVE`: consumed reserve pays c+s+g,
coordinator has no negative topup edge, and the user's returned rights are z.
Mutation: fund c from coordinator while restoring the same user credit, retaining
valid inputs and successful publication. Fail `FAILED_NO_OPERATOR_SUBSIDY` on
event-attributed balance/transfer evidence even if conservation still holds.
Do not mislabel a resulting codec inconsistency as proof of funding isolation.
D68 shortfall cannot use operating subsidy either; this funded fixture alone
does not certify all shortfall paths.

### return-cost

Fixture/path: main settlement with nonzero distinct c, s and g, all independently
derived from Native artifacts and authenticated configuration. Assert
`FAILED_COST_RETURN`, `FAILED_COST_SLOT`, `FAILED_COST_COMPUTE`,
`FAILED_COST_TOTAL`, `FAILED_COST_ROUTING`: c+s+g is consumed from b; s goes to
coordinator operating income; g goes to event fees_collected. Proof-work charging
alone does not demonstrate collection of g. Remove each component separately
from consumption/routing while keeping the real bounce and valid installed
receipt. Require the corresponding component assertion to fail after reaching
settlement (not admission or ciphertext-format rejection). Separately route g
into coordinator instead: fee-routing assertion must fail even if all totals
match. Missing u remains NOT_READY/ConfigInvalid, never silently g=0.

### remainder

Fixture/path: funded main case plus real valid predecessors giving m=y+b at h,
in the newly affected band s<m<=h, and just above h. Main case asserts
`FAILED_RESERVE_REMAINDER`=b-(c+s+g) and installed user rights x+that remainder;
refund goes to the same owner, not another account or an unbacked available credit.
In the one-receipt convention m is the TOTAL issuance pot, not the residual
reserve after an aggregate receipt already includes it. Do not charge s/g twice.
Threshold cases assert `FAILED_NO_ISSUANCE_THRESHOLD`: m<=h means no receipt,
no sequence increment, no issuance compute charge, and all m goes to coordinator;
otherwise install m-h with costs s/g. The small-pot cases need not be funded;
use legitimate D68 inputs rather than wrapping subtraction. Mutate lost/reassigned
remainder, use threshold s instead of h, or advance sequence/charge g without
issuance. Fail the named remainder/threshold/no-issuance assertions, not earlier
setup failures. Insufficient real fixtures leave this item NOT_READY.

### phase0

Fixture/path: actual paired prepare whose phase is still 0, with a strongly
matched rich bounce at height greater than the settlement interval measured from
zero. No artificial phase-1 transition is installed. Assert
`FAILED_PHASE0_SETTLED`: successful Failed publication, matched record removed,
correct W/P release and funded refund. Mutation A computes deadline from zero;
mutation B restores the old requirement for an open phase-1 window. The former
must fail the settlement/refund assertion rather than silently take a late-return
branch; the latter must fail the positive success assertion at the specific
`funded Failed requires an open height window` refusal. Both demonstrate reached
association, not bad identity. A phase-1 companion with record still open but
height beyond the REAL deadline takes the late path without W/P release or topup
(D74); phase 0 must not accidentally weaken that height rule.

### conservation

Fixture/path: commit the real event and independently decode/decrypt all amounts.
Assert each expected value in the shared table BEFORE asserting both equations:
`R_actual1 == R_book1` and `R_actual1+P1 == D1+N_book1+W1`.
Name these `FAILED_R_ACTUAL`, `FAILED_R_BOOK`, `FAILED_N_BOOK`, `FAILED_P`,
`FAILED_W`, then `FAILED_FIRST_PAIR`/`FAILED_SECOND_PAIR`. Perturb each observed
side independently; also mutate both sides consistently (e.g. replace y by x
in both books). Component anchors must still fail in the symmetric case even
if paired equalities pass. Mutation of expected values along with production
is forbidden. Structural D=0 is labeled; unrelated pending rights remain included.

### vq-refusals

This protects OLD default behavior, not successful Failed execution. Baseline
`validator/impl/validate-query.cpp` at the pinned source has THREE occurrences
of the exact diagnostic `multi-account admission and replay are not connected`:
`validator_account_binding_custom` (return at 78-79),
`validator_account_binding_ready` (return at 85-86), and the account-binding
visitor in `ValidateQuery::check_transactions` (6714-6715). Each returns
`WorkchainExecutionFailure::LocalUnavailable`; the third flows to fatal_error.
The M3 record's fourth refusal is in collator and outside this item's three-site
scope; do not claim four-site regression coverage from this test.

Fixture/path: otherwise valid account binding with absent/default and explicitly
OFF test permit. Execute each production decision through a reachability adapter,
including the real validator visitor path for the third. Capture original and
new diagnostic bytes, typed outcome and final validator disposition; require
`FAILED_VQ_REFUSAL_CUSTOM`, `FAILED_VQ_REFUSAL_READY`, `FAILED_VQ_REFUSAL_VISITOR`.
Use controlled independent entry into each decision so the first refusal does
not hide the other two; disclose adapter boundaries, do not fake literal returns.
Mutations separately weaken/bypass each refusal and separately change its string.
The corresponding behavior/diagnostic assertion must fail; an unchanged earlier
refusal is not evidence. Source text comparison alone cannot pass this item.
If a real visitor adapter is unavailable, report NOT_READY for this item.

### onoff

Fixture/path: same authentic bounce candidate and predecessor through actual
validate-query ON, explicit OFF and default OFF. ON executes Failed publication;
OFF follows the pre-change refusal with its exact reached site identified, no
Failed engine execution, no produced transactions/accepted state, no candidate
export. Independently compare the old pinned implementation's OFF outcome.
Assert `FAILED_OFF_REFUSAL`, `FAILED_OFF_ZERO_EXECUTION`,
`FAILED_OFF_NO_PUBLICATION`; inability to construct the ON candidate is not an
OFF success. Mutation bypasses the permit while preserving all input validity;
OFF oracle must fail on the changed disposition or published artifacts. This
complements the three individually exercised refusal sites above.

### oracle-control

For each preceding designated mutation run the same authentic fixture with the
specified oracle enabled: obtain its exact named red. Then disable ONLY that
oracle in an isolated test copy, retain the mutation, and require the driver to
fail because the expected named red disappeared. A substitute earlier failure
cannot satisfy the driver. Record `FAILED_ORACLE_MISSING:<oracle-name>` and exit
status for every pair; restored source passes. Where setup relies on a component
X passing before Y is tested, independently corrupt X's input and establish that
X can actually fail. Neither a constant-green backend nor a constant-red wrapper
is acceptable. Drivers must compare failure identity, not just nonzero status.

## Status, expiry and independent follow-up

The runner must currently exit 1, HANDOFF_NOT_READY. Its own simulated CTest tests
exercise only readiness mechanics, NOT these eleven host behaviors. The suite
is not completed by A's narrower funded helper or by a reported algebraic match.
This contract includes threshold/phase-1/default-refusal boundaries beyond the
first funded phase-0 implementation; retain missing items explicitly.

B first reviews the claimed green by isolated shadow reversion at the specified
layer. A's files are not changed by this delivery. No sequence guard retirement
or baseline refresh is authorized: red means a transition obligation, not expiry
completion. Existing six/nine-item contracts retain their separate requirements.
No assertion here proves network delivery/liveness, a delay upper bound, all
shortfall/policy combinations, all validator refusals, or cryptographic soundness.

## Delivery checks

On the B source baseline above, the repository-generated CTest directory
`/tmp/b-budget-default` has none of the eleven names: the real readiness invocation
exits 1 and lists all eleven. This says nothing about A's moving worktree.
Runner-only unit controls pass 10/10 (simulated registration/execution responses).
In separate temporary copies, removing the registration gate and removing the
observation-marker/skip gate each makes those controls exit 1 at `0 != 1`.
The original runner is unchanged; raw results are in
`measurements/uno-m5-withdrawal-failed-handoff/`. No Native test was run or claimed
by this delivery, and no A implementation/guard was modified.
