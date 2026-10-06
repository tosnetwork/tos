# Wallet V5R2 implementation baseline

V5R2 is a full Wallet V5 revision with the V5R1 security and execution baseline,
plus role-bound primary/rescue authentication and the paired rescue-fee route.
A minimal receiver with a single-message execute operation is not the deliverable.
This requirement supersedes treating the rescue-loop probe as the wallet implementation.

## Authoritative code and compatibility boundary

The starting implementation is `crypto/smartcont/wallet-v5-code.fc`, with the
existing Rust/JavaScript V5R1 SDK bytecode as the immutable compatibility control.
Its current code hash is
`086a86aa9913c0ec52277adbb7e4b5695964dbb8c817ad0c305cdd345bbfac69`.
The shared `wallet-v5-action-list.fc` is extracted directly from that implementation;
the extraction produces exactly the same V5R1 code hash and frozen SDK BOC.

The R2 implementation must use that shared full action engine. It must not replace
OutList with an ad-hoc one-message operation, accept arbitrary send modes, add
classical authorization, or substitute a fee credential for wallet authority.
`rescue-v5r2-account.fc` remains a historical research receiver; its gas/lock results
are not acceptance of a complete V5R2 wallet. The complete receiver candidate has a separate
implementation and test boundary. No default template or SDK code is switched here.

Equal strictness does not mean restoring legacy bypasses that the accepted R2
security design deliberately removes. V5R1 is retained unchanged. V5R2 starts in
PQ-only mode 2 and rejects legacy v1 AUTH, legacy signed messages and unbound
extension authority. Ordinary account fields/getters and complete V5 transfer
behavior remain part of the R2 implementation, subject to those explicit
superseding authentication rules. Missing/truncated R2 AUTH never selects legacy.

## Required parity and extension matrix

| Boundary | V5R1 baseline to preserve | R2 addition / acceptance requirement |
| --- | --- | --- |
| Transfer payload | Full linked OutList; 0–255 send actions; exact cell shape | Use the shared validator and real action phase for both roles |
| Strict send policy | Every send has +2; reject bits 2/3/5 and combined 64+128 | No weaker alternate execute or recovery transfer path |
| Code/lifetime | No raw SETCODE, destruction, malformed action tail or arbitrary action | Lock/migration cannot reopen authority by deleting/redeploying the wallet |
| Authorization | Preserve strict authenticated authority and fail-closed behavior | Owner v6 supersedes classical compatibility: ML-DSA/SLH only, mode 2 only, no Ed25519 or cosignature fields |
| Replay | Bound account, network, expiry, epoch, nonce; checked counters | Bound root and role; separate primary/rescue nonces; epoch barrier on authority change |
| State changes | Authentication precedes state/actions; rejection does not mutate authority | Validate complete successor tuple before installation; no partial fee-route/root update |
| Seqno/getters | Ordinary wallet fields and observable state | Saturated ordinary seqno cannot block narrow rescue; explicit migration reset only |
| Entry points | Strict V5R1 disables classical/extension bypass after cutover | R2 is strict at initialization; fail closed for missing state, old AUTH or malformed modes |
| Retirement | Existing no-downgrade discipline | Mandatory global and set-only local retirement at both module and receiver, including queued relays |
| Pairing | Installed-module sender binding | Canonical module/vault witnesses, exact code/profile/network/keys, non-circular address derivation |
| Funding | Real transaction/action outcomes, not only compute acceptance | Lock → prepare/fund successor → fresh-key POP → migrate → actual payment, without old primary/Ed25519 payers |
| Client integration | Frozen code identity, builders, signatures and serialization agree | SDK/CLI/mobile creation, restore, getters and anti-rollback LMS signer; no premature default switch |

The full R2 state layout, codecs, initialization DAG, module relay and fee route
must be implemented together. In particular, genesis wallet data contains fee
metadata rather than a circular vault address; the runtime cache is derived and
validated. Policy, retirement, PQ-only authorization and canonical witnesses are not
optional follow-up hardening of a supposedly complete wallet.

The original policy distinction is retained: RESCUE_READY permits the daily key
until retirement, while SLH_REQUIRED requires SLH for value/authority operations.
Neither name means ML-DSA AND SLH on every transfer. The LMS fee key grants no
wallet authority. Changing that signature policy is a separate protocol change.

## Acceptance gates

1. Preserve the V5R1 frozen BOC and existing FunC/Tol authentication regressions.
2. Implement the full R2 receiver on this baseline and port equivalent behavior
   tests through the v2 message codec, including every send-mode byte and action
   list boundaries. A passing test of the shared engine alone is insufficient.
3. Implement strict initialization, global/local retirement, PQ-only admission,
   canonical successor/fee-route validation and the full recovery handoff together.
4. Exercise real primary/SLH signatures and every transaction hop in both VMs;
   verify recipient state, failed actions, bounces, queued old relays and replay.
5. Integrate all client surfaces and durable signer/restore behavior; approve
   release hardware pricing, independent review and final-head CI before release.

Current completed work for this baseline: bytecode-preserving shared action engine,
266 V5R1 action cases (all 256 mode bytes, 0/1/254/255/256 actions and malformed
lists), targeted action-guard mutation controls, and existing authentication tests.
This is foundation work; it does not mark the full R2 receiver or client as done.

## Reproduce the baseline

Build `func`, `fift`, `tol`, and `emulator`. Set FUNC_PATH, FIFT_PATH, TOL_PATH and
EMULATOR_PATH to this checkout's tools. Install `cryptography==46.0.4` in a test venv.

```sh
python scripts/update-auth-contract-code.py --check
python test/auth-extensions/test_auth.py
python test/auth-extensions/mutations.py
python test/wallet-v5r2/test_v5r1_action_baseline.py --output /path/to/retained-baseline
```

The last runner compiles each guard-deletion mutant and requires the intended
expected-exit assertion to fail. Compiler/setup errors are not accepted as kills.
The action-cap control must reach compute success with 256 actions and then fail
in the action phase; that distinct result proves the contract's earlier cap was
actually removed. Restored source is exercised again afterwards.

## Retirement implementation progress

`auth-policy.fc` and the native `block/auth-policy` implementation now enforce the
v1 record and monotonic retirement transitions. Governance installation, native
configuration validity, collator/validator transition predicates and the canonical
ConfigParam 48 schema are connected. See `auth-policy-v1.md` and its evidence index.
Explicit candidate genesis construction and trusted-state admission are also
implemented, with actual zero-state and mutation controls. Linux full-node build
evidence, shard propagation, and the full R2 module/receiver role dispatch still
need integration and end-to-end evidence.

## Receiver authorization and module identity integration components

`wallet-v5r2-auth.fc` implements read-only AUTH v2 receiver validation and checked
counter transitions. It binds the installed sender, account, network, role,
epoch, nonce, expiry and operation; checks retirement again at receipt; forbids
primary use of the rescue fee route. The PQ-only AU3B relay has no classical
cosignature field; AU2B and extra fields are rejected. The caller must validate its installed identity
and the complete operation payload before committing state or actions.

`wallet-v5r2-identity.fc` validates canonical module StateInit witnesses against
a caller-supplied compiled code identity, full address commitment, network,
profile and canonical key encoding. It rejects exotic/library cells and bounds
DAG traversal to 1024 reference visits and depth 128. These limits still require
validation against the final compiled dependency graph and release gas pricing.
The expected code must never be obtained from the untrusted witness itself.

The pre-v6 native action-phase component tests covered 333 receiver cases and 29 identity
cases, with four and five guard-deletion mutation controls respectively. The
receiver test uses a fixture entry point: migration exercises counters only,
not successor installation. The identity test pins research module code as a
fixture. Neither result proves a full deployable wallet, signed module relay,
canonical vault pairing, fresh-key POP or atomic recovery handoff. Those remain
required integration work, alongside both-VM and client acceptance gates.

```sh
python test/wallet-v5r2/test_receiver_auth.py --output /path/to/receiver-auth
python test/wallet-v5r2/test_identity.py --output /path/to/r2-identity
```

These tests run in authentication-extension CI. The shared Python cell decoder
continues rejecting exotic cells by default; identity negative fixtures explicitly
opt into decoding level-zero library-reference cells without resolving them.

## Strict complete-wallet storage candidate

`wallet-v5r2-state.fc` implements the `AuthStateV4` storage candidate in
`wallet-v5r2-rescue.tlb`. The ordinary V5 fields remain present; signature authority
is disabled and the extension dictionary must be empty. Modes 0/1/3, missing AUTH,
trailing fields and nonzero inert classical-key fields fail admission. The installed module
StateInit is validated against the caller's compiled dependency and expected
network. Root address, policy and keys are derived from that witness rather than
separately writable assertions.

Genesis stores only fee metadata (profile, public fee tree id, epoch, fixed 3600-second/four-leaf slots
and canonical HSS L1/H20/W4 public key), with no vault address. This removes the
circular genesis input in the earlier v2 storage proposal. The immutable module
witness contains the network and code identity. A future runtime vault-address
cache must be derived from the wallet address and validated metadata. Vault code,
reserve/budget policy, pairing derivation and migration installation still require
integration; the storage codec alone does not establish these properties.

The native fixture round-trips all ordinary and AUTH fields, including saturated
counters and every retirement bit. It tests malformed admission and guard-deletion
sensitivity without claiming wallet message authorization or deployment. Run:

```sh
python test/wallet-v5r2/test_state.py --output /path/to/r2-state
```

## Canonical paired-vault identity

`wallet-v5r2-fee-identity.fc` constructs `PairedVaultData` and its full canonical
StateInit from compiled vault code, network, standard basechain wallet/module
addresses and validated fee metadata. The initial leaf is zero. Neither the vault
address nor its balance appears in its own data. Validation binds the whole data
commitment and rejects altered parties, key, tree id, network, initial leaf, code
or address. A future runtime cache must equal this derivation.

The public fee tree id is a separate 256-bit restore KDF input, not a public-key
hash. It is retained alongside the key and bound by the vault identity. On-chain
encoding checks cannot prove that someone derived a key using that id or retained
its secret. Fresh possession and signer custody remain separate requirements.

The new paired-vault layout is a candidate for the complete implementation, not a
claim that the historical contextual fee-admission probe understands it. Its
15 native fixture cases and pairing guard-deletion control use a minimal compiled
vault-code fixture solely to check independent Python/FunC address derivation.
No fee signature, payment, reserve sufficiency or production code identity is
inferred from these tests. Storage regression also passes all 22 cases after adding
the required tree id. Both runners are included in authentication CI.

```sh
python test/wallet-v5r2/test_fee_identity.py --output /path/to/r2-fee-identity
```

## Complete receiver candidate

`wallet-v5r2-code.fc` now joins strict storage, AUTH v2, the shared full V5 action
engine and canonical paired-vault validation in actual internal/external wallet
entry points. Deployment must provide compiled definitions for the network,
module code hash and vault code; no mutable allowlist or witness-selected code
is used. There is not yet a release dependency bundle. The test compiles the
receiver with a research module and a non-paying vault stub as explicit fixtures.

Execute processes the complete V5 OutList. Configure uses SLH authorization
and an optional validated fee replacement. Lock preserves mode and
sets retirement irreversibly. Migration validates the complete successor module,
metadata and vault before writing any state, enters mode 2, advances epoch,
resets nonces/seqno and preserves all retirement bits. READY successors are
refused under local or current global retirement. Migration emits no value;
subsequent rescue execution is a separate transaction. Signed migration payloads
now carry the actual witnesses so identity assertions cannot diverge from them.

The receiver exposes ordinary V5 getters plus an R2 AUTH tuple getter and refuses
external legacy signatures. Empty internal transfers are deposits only. The
native integration runner covers all 256 send modes, action counts 0/1/254/255/256,
PQ-only configure, lock, saturated migration, old-module rejection, successor
rescue execution and failed successor pairing without partial installation.
Two mutations cover successor retirement and retirement-bit preservation.

These 269 cases validate actual receiver transactions with fixture module senders;
they do not establish real PQ module delivery, recipient-account execution,
production vault payments, getters via client APIs, both-VM parity or final gas
pricing. Those remain required before release. The compiled fixture wallet must
never be published as a production code artifact.

```sh
python test/wallet-v5r2/test_wallet.py --output /path/to/r2-wallet
```

## Owner v6 correction: PQ-only, 2026-10-05

The authoritative owner clarification in memo commit `ab136478` supersedes all
previous R2 hybrid behavior and evidence. Complete V5 capabilities do not imply
Ed25519 compatibility. R2 accepts mode 2 only, requires the legacy-shaped public-key
field to be zero, and uses storage version 4. SUB3 submits a PQ signature without
any classical field; AU3B relays the request and funder without a cosignature.
AU2B and SUB1/SUB2 do not select the new parsers. The signed AUTH request/domain
remains unchanged; the installed module code/address binds the revised protocol.
V5R1 and its frozen bytecode remain unchanged.

`wallet-v5r2-common.fc` contains only error/domain primitives. R2 no longer includes
legacy AUTH or classical verification helpers; tests assert that generated wallet
and module assembly contain no CHKSIGN instruction or strong-classical-key helper.
Historical evidence files retain their original source hashes and scope. They are
not acceptance of the current PQ-only ABI; fresh evidence is recorded separately.

`wallet-v5r2-module.fc` now verifies actual ML-DSA/SLH submissions, rechecks global
retirement for primary authorization, validates migration/configuration witnesses
against MYCODE and its compiled vault dependency, and reserves its earlier balance after protocol storage charges
before relaying only incoming funds. Real native transactions exercise primary,
rescue, lock and migration through the actual outgoing module message into the
complete wallet, plus invalid primary signature and retired-primary refusal. A
signature-check deletion control must turn rejection into an authorization relay.
This still uses a fee-vault stub: fee origination, POP client readiness, preparation, actual recipient
execution, both-VM delivery and production acceptance remain outstanding.

## Per-key non-authorizing possession proofs

The complete module accepts PPS3 separately from SUB3. `wallet-v5r2-pop.fc`
verifies a canonical POP3 challenge binding the global id, network, basechain
account, prepared module address, daily suite, both public keys, immutable policy,
role, nonzero 256-bit challenge and at most one-hour expiry. Parties and keys are
separate cells to remain within the 1023-bit limit. The signed digest commits to
`TOS-POP1` plus the challenge cell, using the independent `TOS-RESCUE-POP-v1`
context. PRIMARY and RESCUE each require their own signature with the corresponding
key; an SLH proof does not establish possession of the primary secret.

Success leaves module data unchanged and emits no actions or authorization relay.
Repeated proofs are non-authorizing, not persistent enrollment or readiness tokens.
A client must generate a fresh CSPRNG challenge per attempt and verify the exact
proof in authenticated canonical execution. A verifier cannot infer custody,
backup quality or future fee availability from this result.

The native runner exercises both genuine signature schemes, wrong-domain and
changed-challenge rejection, identity/profile/expiry boundaries, unchanged state,
no outgoing messages and separate guard-deletion controls for both verifiers.
These 19 cases use funded internal messages and a compiled vault stub. Independent
SLH implementation checks for user-key POP, real fee-vault origination, client
readiness enforcement and both-VM acceptance remain open.

```sh
python test/wallet-v5r2/test_pop.py --output /path/to/r2-pop
```

## Paired fee-vault admission gap (not a release pass)

`wallet-v5r2-fee-vault.fc` is an incomplete candidate using the actual LMS verifier,
SUB3/PPS3/FPR3 allowlist, exact signed destination/config/body/value, monotonic time-slot
leaf, fee-relative amount limits and current-price solvency checks before ACCEPT.
The v3 paired data caches the config hash, canonical rescue request prefix and POP
parties hash derived by `r2pair_data`; wallet/module witness validation compares the
whole reconstructed data hash. Arbitrary caches cannot be installed as a paired
route. The public tree id and full metadata remain committed by the config hash.

The measured SUB3 path requires **12,600 gas to reach ACCEPT**, exceeding the
unchanged default **10,000**. This is a failed release gate. No credit or tariff
change is made to production configuration and no check is moved after ACCEPT.
The 1024-cell envelope, compute/storage bounds and class limits are provisional
and still require worst-case pricing/coverage. Preparation is admitted only at
diagnostic credit, as described below.

`test_fee_delivery.py` defaults to requiring actual admission. Its explicit
`--credit-probe` option changes only the emulator's copied fee configuration to
binary-search the required credit, records `production_admission_passed: false`,
and diagnoses downstream behavior. At 20,000 diagnostic credit, actual derived StateInit
addresses form vault -> module -> wallet -> recipient transactions, the recipient
state/balance changes, the vault consumes leaf 8 to 9, and exact replay is refused.
These observations are **not** evidence that the default-credit fee route works.
The H20 key in this test is deterministic public test material, never a usable
custody key. Its 64 MiB tree stays outside Git.

Resolve the credit gap while retaining fail-closed signature, class, identity,
value and solvency checks, then test all classes, failure paths and both VMs before
freezing the dependency identities or publishing any code artifact.

The 2026-10-06 predicate optimizations retain rejection of exotic cells and
nonzero cell levels. Ordinary parent cells inherit their children's level masks;
a checked ordinary level-zero parent therefore bounds each direct child's level.
The three child parsing sites still explicitly reject exotic children. The
native VM fixture constructs a real level-one pruned branch and ordinary ancestors
to verify this inheritance; removing the parent-level guard admits that forbidden
case. Independently removing the root or child exotic guard admits a library cell.
`test_fee_cells.py` covers 20 cases and three deletion controls. No exotic-cell
support was added to the default Python decoder.

`test_fee_bounds.py` compares the exact production class/role/TTL and gas-config
tag predicates with independent specification bounds: all 256 class, role and
tag values, deadline extremes and TTL boundaries, plus four guard deletion
controls (781 cases total).
Floor division checks TTL [1, 3600] and classes {1, 2, 3}; signed right shift
checks roles {1, 2}.
The native AUTH workflow now runs and retains both suites; wiring is not evidence
that remote CI has passed on this revision.

The delivery runner's `--pop-role 1` and `--pop-role 2` now exercise actual fee vault
payments for ML-DSA and SLH POP. Both require **13,190 gas** at ACCEPT, still exceeding
default credit. Diagnostic 20,000-credit transactions verify POP without module
data changes, outgoing authorization messages or spending its pre-message funds.
Both also reject replay, corrupt LMS signatures and insufficient reserves. Wallet
and recipient receipt fields are null for POP, rather than claiming a payment.
The class-1 four-hop AUTH delivery remains separately checked. These are candidate
bounds, not worst-case production headroom or both-VM acceptance.

`--gas-trace` can retain instruction accounting. Historical instruction totals in
`test/wallet-v5r2/fee-admission-paths-20261006.json` apply to that indexed source,
before the configured-gas-cap guard; they are not current admission measurements.
No hardware repricing justification is inferred from these diagnostics.

The next admission optimization shares the existing class dispatch with the
constructor check, computes the doubled forwarding bound once, and derives the
class compute budget from the already-validated class. It preserves constructor,
value and reserve checks. The delivery harness now signs 11 malformed or out-of-
policy envelopes for each of AUTH, primary POP and rescue POP: mismatched payload
constructor, class 0/3, wrong vault/config, expired/overlong TTL, old/future leaf
slots, and one unit outside each fee bound. Together with invalid LMS signatures
and insufficient reserves, each path has 13 negative cases. Exact amount and TTL
endpoints are accepted in four separate admission transactions per path. Fee
endpoints are derived independently from the fixture's ConfigParams 21 and 25.

Deleting either class's payload-constructor guard makes the corresponding test
fail because the incorrectly tagged, LMS-authenticated envelope is accepted and
leaf 8 advances to 9. These are fee-admission sensitivity controls, not claims
that an invalid inner request gains wallet authority. All positive and negative
path diagnostics use copied 20,000-credit configuration while the default-credit
receipts remain failed. See `test/wallet-v5r2/fee-envelope-20261006.json`.

## Fee failure safety and configured gas cap

A copied configuration with 20,000 external credit but a 12,000 execution cap
exposed a real conditional defect in the previous candidate: ACCEPT succeeded,
execution exhausted gas before COMMIT, and the leaf remained unused while the
vault paid fees. The identical request could be charged again. This is not a
claim that the candidate admitted under unchanged 10,000 default credit.

The vault now reads trusted basechain ConfigParam 21 from the VM unpacked
configuration and rejects caps below its provisional 65,536 compute bound with
error 2017 before ACCEPT. A balance reserve cannot compensate for a configured
execution cap. Tests cover flat-prefixed extended, bare extended and legacy gas
price encodings, each at 65,535, 65,536 and 1,000,000. Three deletion controls admit
the forbidden lower cap. The native AUTH CI runs these 12 trusted-config cases.
Actual fee transactions reject caps 12,000 and 65,535; the 65,536 boundary admits
the vault transaction. Removing the production guard reproduces repeated charging
at cap 12,000. This boundary result does not establish downstream SLH execution
under the same low cap or prove worst-case compute coverage.

`test_fee_delivery.py --fault NAME` exercises 12 cap/failure scenarios in private
contract copies, including throw and out-of-gas before/after COMMIT, insufficient
funds with and without ignore-errors send mode, and oversized outgoing messages
with a matching permissive-limit control. Injected pre-COMMIT faults and strict
unfunded sends demonstrate state rollback and repeated charges; post-COMMIT
compute failures and ignored send failures retain the consumed leaf. These are
sensitivity controls, not assertions that every injected fault is reachable in
the candidate. COMMIT alone does not protect against all action-phase rollback.

Normal AUTH and both POP routes also submit a genuine LMS-funded request with a
corrupted inner PQ signature. The actual module rejects it with 1808 and emits a
bounce; the actual vault receives the returned funds without changing its data
or rolling back leaf 10. Exact fee replay fails with 2004. This verifies refund
handling and replay protection, not successful authorization of the failed inner
request. All three routes still require diagnostic 20,000 credit. With preparation enabled, current minimum
admission values are 12,600 for AUTH and 13,190 for either POP route. Historical
indexes below retain their original source-bound measurements.

Source hashes, commands and retained before/after, deletion, action and bounce
receipts are indexed in `test/wallet-v5r2/fee-failure-safety-20261006.json`.
Default-credit admission, worst-case compute/action bounds and both-VM parity
remain release gates. No production configuration is changed by this fix.

## Full fee transaction parity diagnostics

`fee_tx_parity.py` records the actual native delivery runner inputs and replays
identical account cells, messages, timestamps, logical times and configuration in
the Rust transaction executor. It compares refusal/exit codes, action result,
ordered outgoing message hashes, final balance/data hash, compute success, gas
used, aborted status and action success. AUTH covers 26 transactions; primary and
rescue POP each cover 24. These include authenticated delivery, signed negative
envelopes, exact fee/TTL boundaries, inner-signature refusal, actual refund and
replay. Binary-search configurations are excluded: this parity result applies
only to copied 20,000 diagnostic credit, and default admission remains failed.

The transaction driver has opt-in `--details` output for these additional phase
fields; existing consumers retain their original output. `fee_tx_mutation.py`
disables only the Rust LMS invalid-signature refusal in a temporary source edit,
requires an actual native 2007 refusal to become a Rust acceptance with an
outgoing message, then restores/rebuilds and requires exact parity again. No
signing keys are regenerated by the control. These suites are wired into the
existing x86-64/AArch64 rescue-context CI; local execution does not establish
remote hardware clearance. See `test/wallet-v5r2/fee-tx-parity-20261006.json`.

The gas-configuration tag predicate now uses signed shift of `tag - 0xdd`, which
is zero exactly for the two allowed encodings (0xdd/0xde). Exhaustive byte inputs
and a deletion control preserve rejection of every other encoding. Actual trusted
configuration parsing still passes its 12 cases. The complete AUTH and both POP
routes save 80 gas each, with all 74 transaction parity comparisons passing again.
This small optimization leaves a substantial default-credit gap; it does not
justify weaker checks or tariff changes. Current-source evidence is in
`test/wallet-v5r2/fee-config-predicate-20261006.json`.

## Module-side successor preparation candidate

The complete module now accepts `FPR3` carrying `PRP3`, a separate SLH-only
preparation request in Pure context `TOS-RESCUE-FEE-PREP-v1`. The signed cell hash
binds global/network identity, wallet, current module, deadline, exact module and
vault amounts, both canonical StateInit witnesses and fee metadata. Primary or
legacy authorization is not selected by this envelope. The module checks its own
SLH key and same-code successor/module-to-vault pairing, including policy rules.

It reserves the pre-message balance remaining after protocol storage charges and emits exactly two fixed-destination
messages, each with the signed StateInit, signed amount, empty deposit body and
send mode 3. It never emits wallet AUTH or updates wallet/module state. Repeating
an unchanged valid preparation requires fresh incoming funds. Surplus incoming
funds stay at the source module; no arbitrary refund or withdrawal is introduced.

Current-price provisional bounds require a module reserve floor, a vault floor
covering two conservative AUTH fee budgets and reserves, an aggregate setup cap
of four times the combined floors, and incoming value covering both amounts plus
bounded module compute/forwarding. These are candidate bounds requiring worst-case
pricing and the real recovery drill; they are not a release funding quote.

`test_preparation.py` covers 24 cases: actual deployment of both recipients,
repeated funding, wrong SLH key/domain, modified amounts, identity/expiry checks,
wrong pairing, funding floors/cap and refusal to spend prior funds. Deleting the
preparation verifier accepts a wrong-domain request and sends both deployments;
restoring it returns to rejection. Separate deletion controls remove the funding
floors, setup cap and incoming budget, and expose the corresponding unwanted
sends. A reduced message-cell cap skips the larger
module deployment while sending the smaller vault deployment: this deliberately
proves partial completion, not cross-account atomicity. Both funds and state at
the source retain their invariants. Twenty-three standard-config transactions, including
actual deployments, have exact native/Rust output/state/gas/phase parity; the
custom-cap partial-send scenario is currently native-only. Existing 74 fee-route
parity transactions and real module/POP regressions also pass with the new code.

At this module-only checkpoint the paired vault still refused preparation class 3.
The following integrations add funded preparation, fresh-key POP and the
continuous wallet handoff. Restore/device drills remain open.
The source-bound local evidence is `test/wallet-v5r2/preparation-module-20261006.json`.


## Paired-vault successor preparation and fresh-key POP candidate

The fee vault now admits class 3 FPR3 requests with the exact current namespace,
wallet and source module. Before ACCEPT it checks the PRP3 constructor, canonical
plan shape, module/vault funding floors, signed forwarding amount and solvency,
then verifies LMS. The forwarding floor covers the actual signed setup amounts
plus preparation compute and forwarding overhead. The ceiling covers the fixed
setup cap plus the same overhead. Together these bounds also enforce the setup
sum cap. The module independently verifies the current SLH signature, successor
StateInit identities and all preparation budgets before emitting its two sends.
No check is moved after ACCEPT to reduce admission cost.

`fee_tx_parity.py --prepare` executes V0 -> M0 -> M1/V1 with real deployment
receipts, distinct successor ML-DSA, SLH and LMS keys, then pays through the actual
new V1 for a fresh SLH proof of possession at M1. Both old and new fee replays are
refused. The preparation suite includes 22 signed negative envelopes and four
accepted fee/TTL endpoints with actual module execution. Its 42 transactions
match native/Rust state, balance, outgoing messages, gas and phase results.
AUTH (26), primary POP (24) and rescue POP (24) also match: 116 fee-route
transactions in total. These are local native Release / Rust debug diagnostics.
Three independent fee guard deletions expose unwanted accepted sends and leaf
consumption: constructor, funding floors and fee ceiling. All 12 existing
failure/cap controls were rerun against the expanded vault.

Current minimum admission credit is 12,600 for AUTH, 13,190 for either POP route,
and **13,515 for preparation**. Default 10,000 remains a failed release gate;
20,000 is only the copied emulator diagnostic setting. This preparation-only
checkpoint does not prove the continuous wallet handoff described below,
client/device recovery, restore safety, worst-case pricing or production readiness.
CI runs preparation parity on both configured architectures and the three guard
deletion controls on x86-64; workflow wiring does not establish a remote pass.
Source and retained receipts are indexed in
`test/wallet-v5r2/fee-preparation-20261006.json`.


## Continuous SLH-funded wallet recovery diagnostic

`fee_tx_parity.py --prepare --recovery` additionally runs 20 linked transactions
starting from the installed wallet and its funded V0/M0 accounts. The chain uses
only SLH authorization and LMS fee signing: lock the wallet through V0/M0; use a
fresh V0 leaf to prepare and deploy M1/V1; obtain fresh SLH POP through deployed
V1/M1; migrate through V0/M0; then pay through V1/M1 and the actual migrated wallet
to an executed recipient account. Each successful hop passes its resulting
account into the next hop. No balance top-up or fabricated wallet transition is
inserted. Fixture key generation is not a production signer or restore workflow.

Exact wallet data hashes establish local retirement after lock, epoch increments,
atomic module/metadata replacement, preserved retirement, zeroed migration
counters, and the new rescue execution counter/ordinary seqno after payment.
M1 uses REQUIRED policy. Old-module relay, stale lock, payment relay and fee
replays are rejected. Module prior balances remain protected, V0 consumes leaves
8 through 10, V1 consumes leaves 8 and 9, and the recipient's state and balance
prove delivery. Separate negative probes do not replace the progressing account.

The combined preparation/recovery suite has 62 exact native/Rust transaction
comparisons. `recovery_controls.py` independently removes the lock retirement
write and the migration module assignment from private contract copies. In both
cases the wallet transaction still returns exit 0 without aborting, but the
expected state assertion fails. Restoring the source restores the full chain.
These controls prevent a successful phase result from substituting for the
required authority transition. CI runs the full chain on both architectures and
the two deletion controls on x86-64.

Evidence is indexed in `test/wallet-v5r2/funded-recovery-20261006.json`. This is
local emulator/executor evidence at diagnostic credit 20,000, not public-network
acceptance. Default-credit admission, worst-case envelope/pricing validation,
restart/partial-deployment recovery, durable fee-key anti-rollback and device/SDK
restore integration, independent review and final-head CI remain release gates.


## Admission cost decomposition

The `--credit-probe --gas-trace` delivery diagnostic reconciles instruction charges
with the independently binary-searched minimum credit, including the 26 gas for
ACCEPT itself. At the source indexed in `admission-profile-20261006.json`:

| Route | LMS instruction | Other checks before ACCEPT | ACCEPT | Minimum credit | Shortfall against 10,000 |
| --- | ---: | ---: | ---: | ---: | ---: |
| AUTH | 6,135 | 6,439 | 26 | 12,600 | 2,600 |
| SLH POP | 6,135 | 7,029 | 26 | 13,190 | 3,190 |
| Preparation | 6,135 | 7,354 | 26 | 13,515 | 3,515 |

The LMS instruction charge includes its native verifier/parsing work. Its current
compression tariff charges the fixed profile's worst-case compression count;
these numbers do not show that charging only the observed signature's work is
safe. Non-LMS charges include dispatch, cell reads, shape/identity checks,
replay/time gates, configuration and reserve calculations, and stack operations.
The total is for these fixtures, not all hostile envelopes or every legitimate
future configuration. Do not treat this as wall-clock benchmarking.

`check_admission_profiles.py --artifacts <directory>` checks the retained `auth`,
`pop` and `prepare` delivery traces. Nine evidence controls require rejection of
missing ACCEPT, missing LMS verifier and a one-gas mismatch with probed admission.
The profile provides an optimization baseline; it does not justify removing a
check, accepting unauthenticated requests early, discounting verification or
raising network credit without node-cost and abuse-budget validation. The
contract must save 3,515 gas on this preparation fixture alone to meet the current
default, with additional worst-case headroom still required.


Three compiler-structure experiments were rejected after complete native delivery
runs: extracting fee bounds with `inline_ref` changed AUTH/POP/preparation credit
to 12,593/13,183/13,546; extracting payload checks with `inline_ref` changed them
to 12,763/13,235/13,616; inline fee bounds required 13,525 for preparation. All
increase the largest measured class. Production source was restored byte-for-byte.
`probe_admission_helpers.py` reproduces each transformation only in the delivery
runner's private compiler directory and asserts that production source remains
unchanged. These results narrow the optimization search; they do not prove that
all safe compiler/contract optimizations are exhausted. The retained index is
`test/wallet-v5r2/admission-helper-experiments-20261006.json`.

### Distinct forged-signature cost comparison

`admission_forgery_timing.py` selects successful AUTH, POP and preparation fee
messages from a recorded dual-VM run. For each class it produces 16 distinct
LMOTS randomizers and 16 distinct final authentication-path nodes, preserving
the intent and fixed signature framing. All 96 forged messages must reach the
LMS rejection (2007) at diagnostic credit 20,000. At the current default 10,000,
they instead exhaust admission gas (-14). Three original valid messages serve
as positive controls at 20,000 and also fail admission at 10,000.

The independent Rust executor supplies the exact expected receipts, and every
native timing sample is checked against them. A sensitivity test substitutes an
early structural rejection for the expected LMS rejection; the validator rejects
that result, and deleting its exit-code check admits the substitution. This
prevents timing an unintended cheap rejection as though it exercised LMS.

The local Release native emulator run performed 6,534 receipt-checked executions
(99 scenarios per credit, three warmups and 30 timed samples). The maximum invalid
scenario median was 108,458 ns at 10,000 and 230,104.5 ns at 20,000. These are
sequential warm-cache C API timings, including BOC decoding and serialization;
they are not ingress throughput, a causal speed ratio, exhaustive adversarial
bounds or reference-hardware clearance. Randomizers sample differing verification
work; they do not prove that maximum hash-chain work was reached. No tariff or
credit setting changes. Both architecture CI jobs include a smaller smoke run.
Evidence: `test/wallet-v5r2/admission-forgery-timing-20261006.json`.

`admission_envelope_probe.py` additionally replaces the inner PQ signature with
a balanced ordinary-cell tree while preserving the fee request's class/identity
fields. The resulting outer LMS signature is invalid because the intent changed.
For each of AUTH, POP and preparation, it probes 1,023/1,024/1,025 distinct cells
and a 1,024-cell envelope serialized to exactly 65,535 bytes, plus the original
valid positive control. Every input is at or below 65,535 bytes. The contract's
incoming-storage count includes the root cell; the builder counts distinct hashes.

At both credit settings, 1,025 cells fail the pre-signature 2015 size guard.
At 20,000 credit, in-bound forged envelopes reach LMS rejection 2007; at 10,000
they exhaust gas with -14. A private compiler copy deletes only the cell guard,
substitutes the resulting code into synthetic account prestates, and causes all
three 1,025-cell classes to reach 2007 instead. The ordinary boundary validator
rejects those results. Rust expectations and native replay agree for the control
and the original fixtures; production source is never edited.

The completed local run checked 1,008 native executions. Across the three classes,
the largest 65,535-byte scenario median was 313,479.5 ns at 10,000 credit and
433,146 ns at 20,000. Even a rejected message incurs BOC decoding and storage
traversal outside the signature instruction. These C API probes do not execute
the validator's network admission path or establish concurrent-load limits,
maximum-depth behavior, cold-cache behavior or reference-hardware pricing.
Both architecture CI jobs run a smaller sample. Evidence:
`test/wallet-v5r2/admission-envelope-probe-20261006.json`.

### Structural node ingress boundaries

The actual `ExtMessageQ::create_ext_message` structural parser is now compiled
in `tos_external_message_parser`, shared by the node and an isolated native test
target. Its constructor, normalization and parser definitions were moved without
behavior changes; formatted definitions were compared against the previous source.
The remaining execution-side translation unit also compiles locally.

`test-ext-message-ingress` exercises an exact serialized-size limit (one byte
below the message size rejects; equal and one above permit parsing) and the
default depth boundary (511 permits parsing; 512 and 513 reject). The native
transaction executor currently uses `>` for its depth check, whereas structural
node ingress uses `>=`; executor-only acceptance must not be reported as network
admission. No limit or comparison was changed to hide this distinction.

`ingress_boundary_controls.py` deletes the size guard or relaxes the depth guard
in the production parser, rebuilds, and requires each forbidden input to trigger
its named test's failed rejection assertion. Restoring the source restores both
positive tests. Linux CI also builds and runs the full message-pool/checker test
target to cover the node's consumer linkage.

The full node test target is locally blocked by unrelated Linux-only diagnostic
IPC constants/types in `metrics/diagnostic-ipc.h` on macOS. The isolated parser
tests and deletion controls passed locally; Linux consumer linkage remains a CI
gate. This does not establish a masterchain-backed admission check, network load
budget or successful wallet execution. Evidence:
`test/wallet-v5r2/ingress-boundary-20261006.json`.

`test-ext-message-ingress-fixtures` now also invokes that same production parser
on the actual envelope probe's serialized messages. `ingress_fixture_probe.py`
retains all 15 original fee/boundary cases and adds, for each class, exact
65,536-byte and depth 511/512/513 inputs. All 27 cases are checked for the expected
structural verdict and exact message root. Eighteen parse successfully; nine
reject at the byte or depth boundary. A unit sensitivity control substitutes a
different returned message root, requires rejection, and shows that deleting
the comparison admits it.

The 1,025-cell cases pass structural parsing but fail the contract's separate
cell-count guard in the preceding dual-VM probe. Similarly, a forged fee signature
can be structurally valid yet fail wallet authorization. The original 65,535-byte
messages parse, while the added 65,536-byte messages fail before BOC parsing.
This closes the previously unmeasured handoff of those particular fixtures into
the node parser; it does not prove masterchain-backed admission or delivery.

The local run made 891 parser calls (27 cases, three warmups and 30 timed samples).
Timing covers `create_ext_message` only, excluding input-buffer copying and
cleanup of the returned object. It is sequential warm-cache evidence, not a
network throughput or concurrent-load budget. Both architecture CI jobs replay
the fixture corpus. Evidence: `test/wallet-v5r2/ingress-fixtures-20261006.json`.


## Client fee-leaf scheduling boundary

The Rust SDK `contracts::lms_fee_schedule` provides read-only reservation planning
for H20, four leaves per 3,600-second slot. It binds continuity state to network,
global id, vault, tree id and epoch. Given proof-checked chain time/counter and
intact protected local state, the proposal takes the highest of the current slot
start, accepted chain counter and local reservation high water. It never selects
a previous-slot or future-slot leaf. Lower chain counters cannot reclaim exported
but unbroadcast or forked-out reservations; stale proven times are refused.

When continuity is lost, an opaque restore barrier fixes the next slot boundary
from the observed proven time, even when restoration occurs exactly at a boundary.
The recovered writer must observe that boundary on chain before planning a leaf.
Calendar exhaustion, counter overflow and route changes fail closed. All arithmetic
on slot boundaries and counters uses checked operations.

Four crate tests cover all 1,048,576 leaf positions plus restore, stale-time,
identity, exhaustion and overflow boundaries. Three independent source deletions
remove local reservation protection, restore waiting and expired-slot burning;
all fail semantic assertions, and restored source passes. `contract-sandboxes`
CI covers actual crate integration, while rescue-context CI runs the source's
standalone tests and deletion controls on both architectures. Local evidence is
`test/wallet-v5r2/fee-schedule-20261006.json`.

A `ReservationPlan` is not permission to sign. The caller still needs a finalized
proof verifier, atomic durable reservation before signature generation/export,
a protected high water, identical-byte retry caching and exclusive device custody.
A restored snapshot cannot be supplied as `IntactState`; a restore must revoke the
old writer. This module has no signing API and is not yet connected to a production
fee signer, wallet creation, CLI or mobile restore. Those integrations remain
required before release; a filesystem mutex alone cannot prove rollback safety.


## Durable local fee reservations

On Unix, `contracts::lms_fee_journal::FeeJournal` binds an append-only journal to
one route. Its existing directory must be private mode 0700 and owned by the
caller. Descriptor-relative opens refuse symlink journal files; journal files
must be private regular files with one link. An exclusive file lock is held for
the session lifetime. Records contain leaf, proven time, exact intent hash and a
hash chain rooted in the versioned route header. Bounded parsing rejects damaged,
truncated, reordered or reused records and route mismatches. Hash chaining detects
accidental corruption; it is not protection against a writer who controls the file.

`preview` is read-only. `reserve` rechecks the expected leaf, appends the bound
record, synchronizes the file, and only then returns a reservation receipt. The
session becomes unusable if append/sync completion is uncertain. New-file creation
also synchronizes the directory. Ordinary restart and restored backups both
create a next-proven-slot barrier: there is no unsafe option to treat an ordinary
file snapshot as intact same-slot continuity. This deliberately adds up to one
slot of waiting on every restart. An old device must still be revoked; local
file locking cannot enforce exclusion across machines or restored directories.

Ten SDK tests pass, including the scheduler tests and real two-process lock and
restart handoff. One ignored child helper is explicitly invoked twice by the
parent test, which checks that it actually ran. Tests also cover old-snapshot
rollback, persisted intent/leaf records, stale previews, real OS write failure
followed by handle repair, truncated/corrupted files, wrong routes, hard/symbolic
links and unsafe permissions. Four independent deletions (lock, append, uncertain
write poisoning, restore barrier) fail semantic assertions; restored source
passes. Evidence: `test/wallet-v5r2/fee-journal-20261006.json`.

This journal is not yet a production signing service. It stores no secrets or
signature cache and does not verify proof freshness, reserve/call the real LMS
signer atomically across its service boundary, enforce cross-device revocation,
or provide CLI/mobile integration. Tests exercise process handoff and damaged
records, not physical power-loss guarantees on every target filesystem. Those
requirements and default-credit admission remain release gates.


## Immutable signature retry cache and signing adapter

The journal now consumes a session-bound reservation receipt to create an
immutable per-leaf signature file. It stores the exact intent hash, reservation
hash, fixed HSS L1 H20/W4 framing, signature bytes and integrity checksum. Creation
uses descriptor-relative exclusive/no-follow opens; an existing or partial file
is never overwritten. A receipt from a different reopened session is refused.
Cache reads require the exact intent and its actual hash-chained reservation,
check bounded size/framing/integrity and synchronize the cache and directory
before returning identical bytes. Missing, damaged or rollback-orphaned cache
files return errors and never trigger a signer invocation. Near calendar
exhaustion the journal can still open for cached retries while new reservations
remain refused; transport must independently enforce the intent's expiry.

`FeeJournal::sign_once` calls caller-supplied LMS signing and verification
primitives only after durable reservation. Failed backend calls or rejected
verification outputs burn their leaf. Successful output is cached before return;
a stale leaf request is refused before invoking the backend a second time.
Retries use `cached_signature`, never `sign_once` on an old reservation.

This is a storage/control-flow adapter, not a shipped LMS primitive or a vetted
key-custody service. Tests use explicit framing-only signatures, not claims of
cryptographic conformance. A production caller must verify real LMS backend
output against the proven route's public key, reverify cached bytes before
export, construct the exact fee intent and provide current finalized proofs and
exclusive device custody. Neither the checksum nor the journal hash chain
protects against a malicious owner who can rewrite both files.

Eighteen SDK tests and eleven independent deletion/order controls cover
reservation-before-signing, failed-signature burning, no backend recall on retry,
immutable cache creation, session/intent/leaf/reservation binding, corruption,
restart and last-slot retries. The child-process helper remains explicitly run
by its parent test. Evidence is `test/wallet-v5r2/fee-cache-20261006.json`.
Real signer/cache-to-chain delivery, proof freshness, cross-device revocation,
CLI/mobile integration and production-credit admission remain open.


## Real LMS cache-to-transaction diagnostic

The test-only `lms_fee_cache_fixture` SDK example now supplies an actual H20/W4
signature to the journal adapter using the public deterministic C fixture signer.
Its callback verifies the signature independently with the Rust VM's
LMSCHECKFEEHASH instruction before caching. A second process reopens the journal
at the current fixture time and retrieves identical cached bytes with its signer
path deliberately unavailable; backend calls are one for creation and zero for
retry. Cache export is reverified against the provided public key. Wrong intent,
wrong public key, same-slot restarted signing and corrupt backend output are
refused; rejected output burns the reservation and leaves no usable cache.

`fee_tx_parity.py --cache-driver <example>` uses those returned bytes for the
initial positive external fee request in AUTH, primary POP, rescue POP and
preparation runs. The actual native transactions verify the LMS signature, and
the AUTH route reaches an executed recipient account. The preparation/recovery
suite retains its full linked wallet handoff. The initial four-suite evidence
records 136 matching native/Rust transactions, with only four initial requests
using the SDK cache. The subsequent session integration below extends cache
coverage to all five linked recovery fee requests. Adversarial fixtures retain
explicit public test signing; production custody is not integrated.

Deleting the example's verification-result check makes a cached signature pass
under a wrong public key; the fixture detects that semantic failure. Restoring
the verifier restores all cache/real-signature controls. CI builds the example,
runs all four cache-fed routes on both architectures and performs the deletion
control on x86-64. Evidence: `test/wallet-v5r2/cache-chain-20261006.json`.

The example embeds public test seed/identifier/randomizer constants and accepts
fixture times. It must not be used for live funds. A production signer backend,
key isolation, proof-checked current chain state, device revocation and client
integration remain unimplemented. Transaction runs still use diagnostic credit
20,000; default-credit admission and final-head CI remain release gates.

### Persistent signing sessions across recovery slots

`funded_recovery.py` now uses two persistent SDK fixture sessions when
`--cache-driver` is present. V0 opens at fixture time 1780000000 and refuses
preview both immediately and one second before the next slot. At 1780003590,
lock and preparation reserve leaves 12 and 13. M1/V1 are actually deployed;
V1 opens its journal at deployment time and likewise refuses signing until
1780007190. Fresh POP uses V1 leaf 16, migration uses V0 leaf 16, and the
recipient payment uses V1 leaf 17. Expired V0 leaves 14 and 15 are skipped.
Each of the five signatures is verified, cached, and exported again with an
unavailable signing backend; the exported bytes must match exactly.

AUTH, preparation and POP deadlines are rebuilt and signed at the advanced
chain time. The parity recorder exports that same time per transaction. The
linked chain remains monotonic; the emulator time is restored only when leaving
this independent fixture branch. Final on-chain next-leaf values must be 17
for V0 and 18 for V1, with the existing wallet state, replay rejection, prior
module balance and actual recipient-account assertions preserved.

The preparation suite has 62 matching native/Rust transactions, including the
20-transaction linked recovery. This is controlled-time public-key fixture
evidence, not a verified chain-proof client or a production signer: backend
keys are public, chain time is supplied by the harness, and chain next-leaf
inputs remain fixture assumptions. The default 10,000 gas release failure is
unchanged. Evidence: `test/wallet-v5r2/session-chain-20261006.json`.

A further private `late-send` compiler experiment reconstructed immutable/send
fields only after ACCEPT, retaining every admission check. Minimum credit fell
from 12,600/13,190/13,515 to 12,528/13,118/13,453 for AUTH/POP/preparation,
but total vault execution gas increased. This variant is not adopted: it moves
62–72 gas across the payment boundary without resolving any default-credit
failure. The official contract remains unchanged. Exact totals, source hashes
and reproduction are in `test/wallet-v5r2/admission-late-send-20261006.json`.

Artifact integrity correction: a later repeat of the preparation experiment
accidentally reused its retained directory and replaced 46 raw files. The
original manifest is preserved, but the overwritten original bytes are not
available and its hashes no longer authenticate those paths. AUTH/POP artifacts
were verified unchanged. The repeat still measured 13,453 minimum credit and
failed default admission. `admission-output-audit-20261006.json` records original
versus current hashes, the repeat output and this limitation. The experiment
runner now refuses nonempty output directories before writing or linking files;
its preservation tests include a semantic guard-deletion control.

### PQ-only AUTH SDK encoding

`contracts::wallet_v5r2` provides typed AUTH construction for execution,
configuration (mode 2 only, with optional fee replacement), primary-key lock,
and migration. The primary role is ML-DSA-44 and permits execution only; the
rescue role uses the separate SLH context. There is no Ed25519, classic
cosignature, hybrid-mode or manage-action constructor. Basechain standard
addresses are encoded directly. The encoder rejects equal wallet/module hashes,
expired or over-one-hour deadlines, and signature lengths outside the exact
role profile. Request bytes, role context and domain-separated digest are held
in one immutable object. SUB3 signature chains use canonical 127-byte chunks.

This is a wire encoder, not an authority or cryptographic verifier. Supplied
chain time, counters, code identity, StateInit witnesses and action lists still
require client proof/policy verification and on-chain validation; signature
framing acceptance alone never establishes authenticity. No backend or key
custody is provided by this module.

Six independent Python wire vectors cover both roles and all four action kinds,
including fee replacement. Byte-filled signatures in those vectors test framing
only. In the real public-key fixture suite, `sdk_auth_parity.py` compares Rust
SDK bytes/digests/contexts with Python, then actually signs and submits the Rust
requests for lock, migration and recipient payment through the persistent fee
sessions. All 62 native/Rust transaction outcomes match at diagnostic credit
20,000. Five semantic controls remove distinct-party, primary-role, TTL, signature-width
or signing-domain safeguards and require the relevant SDK tests to fail before
restoring source and rerunning them. CI runs wire and transaction checks on both
architectures and deletion controls on x86-64. Evidence:
`test/wallet-v5r2/auth-sdk-20261006.json`.

Trusted release-code and chain-view binding,
real custody and user-facing create/restore flows remain to be integrated.
Default-credit admission remains a separate failed release gate.

### Separate per-key POP SDK encoding

`contracts::wallet_v5r2_pop` encodes POP3/PPS3 for either ML-DSA-44 or SLH,
with explicit READY/REQUIRED policy. It binds the namespace, wallet/module,
canonical primary-key cell hash, rescue key, role, nonzero challenge and
one-hour deadline. Its immutable digest uses `TOS-POP1` and the separate
`TOS-RESCUE-POP-v1` context. There are no action, transfer or authority-update
fields. Exact signature sizes and canonical chunks share the AUTH framing
helper; no classic or hybrid signature path is introduced.

The caller still supplies a fresh random challenge, trusted chain time and
verified module/key identity. Nonzero is only a shape check, not randomness or
freshness evidence. Successful POP is a non-authorizing transaction, never an
enrollment token; application verification must bind its own outstanding
challenge to an authenticated result. The SDK does not perform that verification.

Four independent Python vectors cover both roles and both policies. Real
fixture signing checks compare the Rust challenge, digest, context and complete
PPS3 body against Python. SDK-encoded signature cells are used in both POP fee
routes and the retimed successor proof within the continuous recovery chain.
Native/Rust parity remains diagnostic-credit evidence. Five POP semantic
controls check challenge, party, TTL, domain and context sensitivity; AUTH
controls also rerun after sharing the signature-framing helper. Evidence:
`test/wallet-v5r2/pop-sdk-20261006.json`. Production custody, verified challenge
receipts and default-credit admission remain open.

### SLH-only preparation SDK encoding

`contracts::wallet_v5r2_prepare` constructs PRP3 requests and FPR3 submissions,
with no role selector and only the exact SLH signature framing. The request hash
binds the namespace, wallet/source module, deadline, both deployment amounts,
and all three full module/metadata/vault witness cells. The signing context is
`TOS-RESCUE-FEE-PREP-v1`. Input amounts preserve the complete Coins range through
u128 encoding rather than a u64 cast. Canonical serialization rejects values
outside the 120-bit wire range; deployment amounts must be positive. The checked
sum accessor explicitly excludes compute and forwarding fees.

Encoding does not validate witness pairing or dynamic network fee floors/caps.
Callers must still verify code/key identity and current bounds, then confirm both
actual deployments and a fresh POP before constructing migration. Preparation
alone grants no wallet authority and cannot be treated as recovery completion.

Three independent vectors include amounts above u64 and the maximum 120-bit
Coins value. Six semantic controls exercise distinct parties, TTL, positive
amounts, context, witness binding and sum calculation. All ten AUTH/POP/preparation
SDK tests pass. Real public-fixture SLH signatures are enclosed in SDK-produced
FPR3 bytes for both the initial preparation and its retimed counterpart in the
continuous recovery branch. The complete suite retains 62 matching native/Rust
transactions, actual M1/V1 deployment and recipient payment, at diagnostic
credit 20,000. Malformed negative fixtures continue to use their explicit test
encoders. Evidence: `test/wallet-v5r2/prepare-sdk-20261006.json`.

### Fee-intent SDK encoding and cached-signature export

`contracts::wallet_v5r2_fee` builds FEE4 and its two-reference external body.
Its immutable digest binds the fixed fee domain, class, vault, full paired
configuration hash, leaf, deadline, value and actual submitted payload. Amounts
retain the full Coins wire range. Payload import checks envelope/request framing
and refuses primary AUTH in the rescue fee class. It is not an inner-signature,
full policy, configuration-pairing or dynamic fee/balance verifier.

New intent construction permits only current-slot leaves, not the prior-slot
network delivery allowance; it rejects exhaustion, invalid TTL and zero value.
It does not reserve or sign anything. The caller must pass this exact digest
and leaf through the durable journal and a reviewed signing/verification backend.
External export checks the cached HSS L1/H20/W4 signature framing and leaf. It
does not prove cryptographic validity or fresh admission; cache verification,
expiry and chain checks remain mandatory before broadcast.

Four independent Python vectors cover all classes and the maximum Coins value.
Sixteen wallet SDK tests pass. Eleven semantic controls exercise class/shape,
rescue-only routing, TTL, current slot, exhaustion, value, signature length/leaf
and domain. In actual public-fixture recovery, all five fee intents and external
bodies now come from Rust SDK bytes around persistent journal/cache signing,
with independent Python hash equality checked at both boundaries. The initial
positive preparation request uses the same integration. Twelve retained encoder
calls correspond to those six intents and six external bodies. The suite still
has 62 matching native/Rust transaction outcomes and actual recipient payment,
using diagnostic credit 20,000. Malformed negative requests remain explicit
fixture encodings. Evidence: `test/wallet-v5r2/fee-sdk-20261006.json`.

This completes encoding coverage for the recovery messages, not production
signer custody, verified state/receipt handling or user-facing recovery. Trusted genesis-code distribution, complete client policy validation and the default-credit release
failure remain open alongside the other production gates.

### PQ-only genesis SDK and deployment-derived recovery

`contracts::wallet_v5r2_genesis` deterministically constructs module data and
StateInit, fee metadata, wallet data/StateInit, then the paired vault data and
StateInit. Vault caches are derived from the complete configuration, wallet,
module and metadata; they are not caller assertions. Initial seqno/nonces and
retired bits are zero, epoch is one, mode is two, classic signature entry is
disabled, the inert classic key is zero and the extension dictionary is empty.
Only fixed-size ML-DSA-44 and SLH keys and HSS L1/H20/W4 fee keys are accepted.
READY/REQUIRED remain explicit policies.

CodeBundle requires matching code hashes and ordinary level-zero code. Those
pins must come from an independently reviewed release bundle: hashing untrusted
code and presenting its own hashes is not authentication. The SDK neither audits
code dependencies nor proves key possession/custody. Four independent vectors
cover policies, wallet-id and fee-tree variation, comparing seven complete cells
and the configuration hash. Seven semantic controls exercise code identity,
ordinary code, fee profile, classic flag/key, epoch and metadata pairing.

The real fixture suite now deploys SDK StateInit for all three initial accounts
from absent accounts. It checks actual state and balances, then starts the
independent linked recovery branch from those deployment results. The suite has
65 matching native/Rust transactions (including three genesis deployments), and
retains successor deployments, fresh POP, migration and actual recipient payment.
These are local public-key fixture transactions, not a public-network launch.

This exposed a limitation of earlier pre-created account fixtures: their storage
usage was zero. A genuinely deployed M0 pays 3,497 units of storage rent across
the first restore wait. Its observed balance loss equals the transaction's
storage_fees_collected exactly, with no storage debt/status change. The funded
module invariant now decodes actual storage rent and permits no additional loss
of prior funds; unchanged data remains mandatory. A real-receipt control rejects
one extra unit of loss, accepts it only after deleting the invariant, then
rejects it again with the guard restored. No contract check or tariff changed.
Evidence: `test/wallet-v5r2/genesis-sdk-20261006.json`.

Production release-code distribution, key custody, trustworthy fresh chain views,
challenge/transaction receipt verification, complete client policy and recovery
UX, default-credit admission, reference-hardware/worst-case pricing, independent
review and final-head CI remain unfinished.

### Raw authenticated account reads for signer integration

`ProvenGetterProvider::read_account` uses the existing local proof verifier's
account-only request: it omits `get_methods` rather than sending an empty array.
The existing getter API still refuses empty method lists. Raw reads retain the
same provisioned anchor, target/request binding and historical/live policy.
The returned `ProvenAccountState` has private fields and no public constructor;
its read-only accessors expose the authenticated Account and its evidence.
The raw BOC root hash, embedded address, code/data hashes and native balance
must match that evidence before the object is returned.

Eight focused tests include a recorded real finality/account proof, a modified
account rejected by the real verifier, and a positive wrapper plus five corrupted
verifier-output cases. The latter exercise the Rust response boundary, not a
cryptographic proof. Five independent guard deletions must produce the explicit
"accepted corrupted" test failure; restoration must pass all eight tests.
The existing contract-sandbox CI runs these tests and the deletion controls.

This is account-read plumbing, not a complete V5R2 signing authorization.
Historical reads do not prove freshness. Live masterchain freshness does not by
itself establish a sufficiently recent shard time for fee-leaf scheduling.
Vault code/configuration pairing, shard-time policy, receipt binding and actual
custody integration remain required before these reads can authorize signing.
The recorded account is an elector, not a deployed V5R2 wallet.

### Initial fee-vault enrollment and freshness binding

`ProvenInitialFeeVault::bind` accepts only an opaque proven account plus locally
trusted `WalletGenesis`. It requires a live read at the expected vault address
and code hash. It compares the complete immutable data suffix with enrollment,
including config/epoch, module address, parties commitment, fee public key and
AUTH prefix. Only the bounded next-leaf counter may differ. The route and config
hash are derived from enrollment, rather than accepted as independent caller
assertions.

The caller supplies its trusted local clock and a maximum observation age of
1..3599 seconds. Both authenticated masterchain and shard times must be no later
than that clock, within the age limit and in the same fee slot as that clock.
The conservative same-slot rule can refuse a recent proof around a boundary;
fetch a newer authenticated observation rather than signing from the previous
slot. The read-only reservation proposal rechecks freshness when called, so
retaining the object does not bypass expiry. Actual durable reservation and
signing remain the custody journal's responsibility.

Synthetic account tests cover this binding and expiration; they are not a live
V5R2 deployment proof. The separate recorded-account tests cover proof plumbing.
Nine guard deletion controls require explicit acceptance of a bad input to be
detected by the tests. The original `bind` entry point covers initial enrollment. The successor
entry point described below additionally checks locally enrolled recovery pairing;
authoritative preparation/migration receipts remain a separate requirement.
Wallet/module deployment, POP outcome, balances/pricing, transaction receipts,
local enrollment provenance and the complete signer integration remain open.


### Successor deployment construction and observed vault binding

`SuccessorDeployment` derives canonical module/metadata/vault witnesses from a
locally enrolled key/code template and the existing wallet address. The unused
new-wallet address from the template is never installed into the successor
vault. Initial and successor construction share the exact paired-vault codec.
`preparation_plan` supplies those three witnesses directly to the SLH preparation
encoder, with explicit deployment amounts; canonical amounts and network fee
bounds still require their respective checks.

`ProvenFeeVault::bind_successor` applies the same live-proof, code/address,
immutable-data, counter and time checks as initial binding. Its expectation is
the enrolled successor tuple. It does not infer wallet installation or successful
POP from the existence of a vault. `ProvenInitialFeeVault` remains a compatibility
alias for callers using initial enrollment.

Four independently generated successor vectors cover READY/REQUIRED, existing
wallet identity and tree identity. The real public-key local recovery harness
compares all five successor cells against Python, then uses the SDK cells for
preparation, deployment, POP, migration and recipient payment. All 65 native/Rust
transaction outcomes match at diagnostic credit 20,000. Synthetic proven-state
binding tests separately reject an initial vault and another wallet's successor;
they are not cryptographic proof or live-network evidence. Evidence index:
`test/wallet-v5r2/successor-sdk-20261006.json`.

Fresh authenticated recovery receipts, authorization from current wallet state,
production signer custody, reference hardware/pricing and final-head CI remain
open. Default-credit admission remains a failed release gate.

### Proven fee observation to durable signing adapter

The Unix journal offers `open_proven`, `preview_proven` and `sign_proven_fee`. Opening requires
fresh authenticated enrollment-bound vault state and retains the existing
next-slot restore barrier. Signing checks freshness again, requires the complete
journal route to match, and refuses a deadline already expired by local time.
It derives the current leaf from both journal state and the proven chain counter,
then builds the exact FEE4 intent from that vault/config/epoch. The caller cannot
supply a separate route, leaf, configuration hash or digest to this entry point.

`preview_proven` performs the same freshness, route and local capacity checks
without writing a reservation or invoking a signer. Repeated previews do not
consume leaves. A chain-only candidate can still be refused because unbroadcast
local reservations consumed the slot or a restored journal is waiting for its
next slot. `sign_proven_fee` uses this shared preflight and still rechecks and
durably reserves before signing. A preview never grants permission to sign later;
it can become stale. `observed_continuity` exports the active session's local
high water and route only after checking its restore barrier and capacity.
The migration gate requires this trusted local custody input separately from
chain state. It is not an attestation suitable for an untrusted RPC channel or
proof of exclusive ownership across devices; a caller must preserve custody
continuity and recheck/reserve before the later fee signature.

The existing reserve-sign-verify-cache sequence fsyncs the reservation before
calling the backend. Verification receives the public key from the bound vault
metadata. After reading the immutable cache, the adapter verifies those bytes
again before returning the destination, intent and external body. Failure burns
the reserved leaf; it never permits re-signing. Callback implementations remain
trusted local cryptographic primitives, not remote verification assertions.

A synthetic proven-account test with a framing-only backend checks durable
record/digest presence before signing, both verification calls with the bound
key, exact intent construction, cache retry bytes, restore waits, expiry,
wrong-route rejection, chain high-water and leaf consumption on failed checks.
Ten semantic controls remove or substitute the relevant bindings, including
the restore barrier, local reservation high water and continuity export guard. This proves
adapter ordering/binding, not cryptographic validity or real-network V5R2 proofs.
Inner action authorization, live fee/admission bounds, production key custody,
preparation/POP/payment receipts and cross-device ownership remain separate gates.
Preview-specific evidence is retained in
`test/wallet-v5r2/proven-fee-preview-20261006.json`.

### Current wallet/module observation binding

`ProvenWalletState` binds a live wallet observation and a module observation at
exactly the same authenticated masterchain checkpoint. The module can be fetched
historically at that pinned target; both account shard times and the masterchain
time must satisfy the local freshness policy. Enrollment fixes the wallet's
original address/code/id and the intended installed module/fee tuple. Successor
binding preserves the original wallet identity and module code family/namespace.
The deployed module's data must equal the enrolled immutable module data.

The decoder requires the exact PQ-only wallet storage shape, disabled classical
entry/key, no legacy extensions, AUTH version 4/mode 2 and the complete installed
tuple. It exposes the proven counters and retirement bits. `rescue_request`
rechecks freshness and the local deadline before deriving the SLH AUTH binding
from these fields. Execution checks both rescue nonce and seqno exhaustion;
configure checks epoch and seqno; lock/migration check epoch without blocking
recovery merely because execution counters are exhausted. Action validation,
POP/delivery and actual signing are not implied by constructing this request.

`primary_locally_enabled` explicitly reports local eligibility only. The
`primary_request` path below additionally requires authenticated ConfigParam 48
at the same wallet checkpoint; local eligibility alone never grants permission.

Five synthetic-account tests exercise current counters, stale/mismatched proofs,
installed successor state, PQ-only entry and independent counter exhaustion.
Eleven semantic guard controls require erroneous acceptance to be detected.
These are SDK binding tests, not live V5R2 finality/receipt evidence. The existing
raw-account proof suite separately covers the cryptographic account-read boundary.


### Proven ConfigParam 48 and PRIMARY request construction

`read_account_with_config` asks the existing native verifier to prove an account
and explicit configuration indices at one target block. The Rust response path
requires the exact requested count/order, binds each returned BOC to its cell
hash and stores the cells privately with the opaque account result. Duplicate,
out-of-range or excessive indices refuse before invocation; a missing parameter
refuses rather than becoming a default policy. Existing getter/raw-account reads
continue to request no configuration parameters.

`ProvenWalletState::primary_request` requires local READY/non-retired status,
current time/deadline/counters, and ConfigParam 48 proven at exactly the wallet's
checkpoint and masterchain time. The policy decoder checks the v1 tag, network,
known retirement mask, specification hash, exact optional single-suite schedule,
positive deadline and current retirement decision. It builds only a PRIMARY
execute request from the proven epoch/primary nonce; it does not approve actions
or invoke a signer. Retirement during later delivery can still reject the request
on chain. SLH request construction remains independent of global primary policy.

Recorded real proof tests read an account plus ConfigParam 8 and reject a
configuration proof from another block. This proves the generic account/config
read path, not real-network deployment of ConfigParam 48. Synthetic policy and
wallet tests cover ConfigParam 48 semantics, missing/retired/wrong-checkpoint
policy, REQUIRED status, nonce/seqno exhaustion and rescue independence. Twelve
semantic controls cover response binding and PRIMARY policy gates. Live V5R2
proof/receipt integration, production signing/custody, default-credit admission
and independent/final-head acceptance remain open.

### Account-anchored transaction history and internal delivery

Raw account reads now require the native verifier's proven `last_trans_hash`
as well as `last_trans_lt`, and retain a fingerprint of the locally provisioned
trust anchor. `ProvenTransaction::latest` binds an untrusted transaction cell to
that hash/LT/account and requires its post-state hash to equal the authenticated
raw Account root. `previous` follows both the predecessor hash/LT and the complete
Account state-update chain. These operations prove history, not freshness.
Callers fetching a long history must bound their own fetch/iteration budget.

`require_complete_execution` refuses aborted/destroyed/bounced transactions,
skipped or failed compute, invalid/failed action phases and silently skipped
actions. It is not a recipient-completion predicate by itself.
`require_internal_delivery` additionally requires a common trust anchor, an
actually emitted internal message with exact sender/destination, an identical
original message cell at the receiver and a later receiver transaction LT.
Both executions must be complete. Original outbound cells are retained rather
than reserialized, since valid message encodings can differ after round trips.

Six tests use bounded frozen native-executor payment/recipient/migration receipts
from the existing full recovery run. Their Account proof wrappers are explicitly
synthetic; they do not establish real-network V5R2 finality. Mutated receipt tests
exercise refusals, and fourteen semantic guard controls require bad history or
completion to be accepted when the corresponding guard is removed. Generic real
account-proof tests still cover the native cryptographic read boundary.

The account-read API currently requires active accounts. Destroyed-account/block
transaction proofs, application-specific payment amounts and state effects,
POP challenge interpretation, live transport/fetch orchestration and production
key custody remain open. This layer does not turn phase flags into proof of an
application's intended outcome, nor clear default-credit admission.

### Bounded authenticated receipt lookup

`ProvenTransaction::find_inbound` starts from an opaque proven account head and
passes the exact account, transaction LT and hash to an asynchronous fetcher.
Every response is checked by `latest` or `previous` before matching the original
inbound message hash. It retains only the current transaction and accepts a
caller budget of 1..=1024 transactions. Exhaustion, history termination and
transport errors are errors, never evidence of non-execution. Finding an
included transaction remains separate from checking execution and delivery.

The native recovery fixtures exercise two-step migration lookup, cursor binding,
a one-step budget miss, a matching but unauthenticated transaction and invalid
budgets. The receipt suite now has seven tests and sixteen semantic controls.
The fetcher is an integration boundary, not a completed RPC transport: callers
must enforce transport deadlines, response byte limits and BOC decoding bounds.
Live network receipt lookup and application-specific outcome checks remain open.

### JSON-RPC receipt transport

`find_inbound_rpc` connects bounded authenticated lookup to the existing
`ClientJsonRpc::get_transactions` read path, requesting one transaction per
proven hash/LT cursor. It requires exactly one returned transaction, treats RPC
metadata as untrusted, and authenticates the decoded BOC through the account
history chain. The transport already enforces a 1 MiB HTTP response cap and a
30-second per-request timeout. This adapter adds a caller-selected, nonzero
whole-lookup deadline capped at 300 seconds, checks the deadline during BOC
reading and after authentication, limits encoded BOC input to 1 MiB, and caps
cell depth at 1024. These client limits may reject unusually large histories or
transactions; a bounded failure is never proof of absence or permission to
resign/replay a request.

Loopback HTTP tests serve native recovery transaction fixtures behind synthetic
account proof metadata. They verify exact outbound RPC cursors, two-step lookup,
ignored false RPC metadata, refusal of empty/oversized pages and substituted
transactions, and delayed-response cancellation. The receipt suite now contains
nine tests and eighteen semantic controls, including page cardinality and
caller-deadline enforcement. This exercises real HTTP plumbing, not real-network
V5R2 finality, and still does not interpret application payment/POP outcomes.

### Payment intent and credit-phase evidence

`PaymentExpectation` carries locally approved recipient, full native/extra-currency
value, credited currency collection, bounce flag, normalized body cell and
StateInit. `require_payment` first binds the sender transaction to its exact
originating inbound request and proves complete internal delivery, then compares
all expected fields and requires the receiver's credit phase to record exactly
the expected amount. Bounced refund messages are refused. Expectations must come
from the approved request, not be populated from an untrusted RPC observation.

The native recovery payment fixture passes these checks; recipient, value,
credit, body, StateInit and bounce mismatches are independently refused. The
receipt suite now has ten tests and twenty-four semantic controls. The fixture
account-proof wrappers remain synthetic. Credit-phase value is not final
spendable balance: recipient execution may consume fees or send value onward.
Token-ledger/application state, POP interpretation, the full fee/module/wallet
request chain and real-network acceptance still require their own checks.

### POP execution identity and fresh challenge receipts

`PopRequest::require_initial_receipt` and `require_successor_receipt` interpret an
account-anchored module transaction against the locally enrolled module. The
caller supplies the pre-transaction Account cell; `ProvenTransaction::pre_account`
binds it to the transaction's old-state hash and address. The executed code and
key data must equal the enrollment, not merely the module's current code. Full
execution must succeed, and the inbound message must be internal, non-bounced,
exactly PPS3-shaped and contain the exact locally generated POP request cell.
Signature acceptance follows from authenticated execution of the enrolled
verifier code, never from RPC flags or signature framing alone.

The successor SLH POP and preceding deployment receipts are retained as bounded
native-executor fixtures. Synthetic proof wrappers exercise the full predicate;
four semantic deletion controls detect substituted pre-state, other executed
code, unrelated challenge and a bounced input that would otherwise return
success without verifying possession. The complete receipt suite has eleven
tests and the earlier twenty-four controls remain regression gates.

Release code pins and fresh CSPRNG challenges remain caller responsibilities.
A POP proves possession for that key/challenge, not wallet enrollment, authority,
continued key availability or safe custody. This fixture covers successor SLH;
initial/per-key live network enrollment and production acceptance remain open.

### Complete fee/module/wallet payment route

`PaymentRoute` derives immutable addresses/code pins from initial or successor
local enrollment, retaining the original wallet identity across migration.
`PaymentReceipts` supplies four authenticated transactions and the three sender
pre-state Account cells. Verification binds each pre-state to the actual
transaction, requires the enrolled addresses/code, checks the vault's immutable
configuration while allowing its bounded LMS counter to advance, and checks the
module's exact enrolled key data. It then binds the fee transaction to the exact
submitted external message, verifies original-message delivery from vault to
module and module to wallet, and applies payment-intent/credit checks to the
wallet-to-recipient delivery. All four executions must be complete and every
adjacent receipt pair must share a trust anchor.

The full native successor recovery payment fixture passes this route check.
Six semantic controls detect wrong address/code/module keys/vault configuration,
an unrelated submitted request and a route spliced with a successful POP module
transaction. Loopback/proof plumbing and these native receipts still use
synthetic finality wrappers for V5R2; real-network acceptance is not established.
The API is read-only and historical, does not approve or submit requests, and
cannot infer final spendable balance, replay safety or custody readiness.

### In-memory PQ wallet signing backend

`tos_wallet_pq_signer` is a separate native library with wallet-only ML-DSA
key-generation/signing symbols. It supports ML-DSA-44 primary and
SLH-DSA-SHA2-128s rescue keys, with no classical algorithm or caller-chosen
context. Requests accept exactly a 32-byte SDK digest. AUTH uses each role's
frozen context, POP uses its separate context, and preparation is SLH-only.
Invalid roles/purposes and moved-from key stores refuse signing.

Fresh keys and per-signature randomizers use `RAND_priv_bytes` and fail closed.
Recovery accepts explicit 32-byte ML-DSA or 48-byte SLH seeds; the caller owns
and must wipe its input copy. The move-only signer wipes its expanded secrets,
local generation seeds and randomizers on destruction. Every signature is
verified before returning it. No key material is printed or persisted by this
library, and it is not linked into node verification or validator custody.

Native tests cover both suites and five allowed role/purpose combinations,
deterministic recovery identity, fresh-key separation, randomized signatures,
wrong context/message/key/signature, invalid lengths and moved-from refusal.
Two separate executables substitute failed random-source and failed verification
verdicts. Five source mutation controls must cause semantic failures; restored
binaries pass. The rescue-context workflow runs these on both architectures.

This is a cryptographic component, not completed production custody. Protected
persistence, backup/revocation, process/device isolation, locked-memory/core-dump
policy, independent secret-handling review and SDK approval/state integration
remain required. It does not approve the actions behind a digest, prove current
wallet policy, or solve LMS stateful custody/default-credit admission.

### Native signer / SDK / executor integration

The explicitly public-key-only `test-wallet-pq-signer-fixture` invokes the new
wallet signing library for fixed fixture identities. It accepts no private key
or arbitrary seed and is not installed as a custody tool. The Python fixture
adapter compares its public key against the existing independently invoked key
fixture, records exact request digests/signatures, and supplies signatures to
the Rust SDK submission encoders and actual contract transactions.

With this backend, the complete SDK-funded successor recovery suite has 65
matching native/Rust transactions; the ML-DSA primary POP fee suite has 24.
Both retain the default-credit failure and use 20,000 only for downstream
diagnostics. Nine separate native module-to-wallet cases cover primary AUTH,
rescue, lock, migration, retirement, bad signature and legacy/classical refusal;
that module suite uses a compiled fee-vault stub, not the full fee route. Its
signature-guard deletion still converts corrupted-primary rejection into an
incorrect successful relay. Across these runs all five allowed role/purpose
combinations execute through the native signer. CI uses the same adapter on
both architecture jobs.

This is interoperability evidence with public fixture keys and controlled time,
not production SDK custody integration or real-network finality. The first
primary-POP invocation supplied a genesis option reserved for the recovery
harness and failed setup; the corrected fresh-directory run passed. Raw runs,
source hashes and that limitation are indexed in `native-signer-integration-20261006.json`.

## Receipt-checked native transaction timing

`test/wallet-v5r2/benchmark_transactions.py` replays the recorded full recovery
transactions through the native emulator C API with signature verification enabled
and VM tracing disabled. Each warmup and measured execution must match the recorded
parity transcript (including rejection codes, gas, outgoing message hashes, balance,
data hash and execution flags where available). A changed rejection receipt is
refused; deleting that comparison demonstrably admits the changed receipt. Existing
output directories are refused to preserve evidence.

The timed interval includes native input BOC decoding, transaction execution and
JSON/BOC result serialization, but excludes Python decoding, comparison, setup and
warmup. This is repeated-input, warm-cache measurement at the fixture's recorded
credit. It does not isolate pre-ACCEPT cost, characterize worst-case adversarial
inputs, measure node ingress/finality, or establish a hardware tariff. Both CI
architectures run a short receipt-checked timing smoke; hosted runners are not
approved reference hardware. No gas tariff or default credit is changed.

The local Release/arm64 sample covers 65 transactions with 30 measured repetitions
and three warmups each (2,145 verified executions), at diagnostic credit 20,000.
See `test/wallet-v5r2/native-timing-20261006.json` for source and artifact hashes.
Default-credit admission and production hardware/pricing approval remain open.

`default_credit_timing.py` derives a separate fixture configuration by changing
only ConfigParam 21's gas credit to 10,000. It obtains expected transcripts from
the Rust executor, then checks every native timed execution against those results.
The recorded account prestates are retained: these are isolated transaction
probes, not an end-to-end recovery run at default credit. In the local 65-input
sample, 13 transcripts change from diagnostic execution to out-of-gas rejection
(`-14`); all 2,145 native executions match Rust expectations. Other gas fields and
configuration entries are preserved by the adapter's regression test. Both CI
architectures run this comparison alongside the diagnostic-credit measurements.
See `test/wallet-v5r2/default-credit-timing-20261006.json`; neither these repeated
public samples nor their measured rejection latency establish worst-case safety.

The native LMS verifier now reuses a fixed 55-byte chain input buffer for
`I || q || i || j || tmp`, removing per-step temporary string allocations.
The signature profile, hash input bytes, verification policy and gas tariff are
unchanged. Full recovery (65 transactions, 2,145 verified executions) and primary
POP (24 transactions, 288 executions) retain their recorded receipts. Two native
mutations, zeroing the chain index and omitting chain hashing, each cause a real
receipt mismatch; the restored implementation passes. The reproducible control is
`lms_buffer_controls.py`, also wired into the native CI job. Evidence is indexed in
`lms-buffer-20261006.json`. Sequential timing samples were noisy, with regressions
on some paths, so no wall-clock speedup or revised pricing is claimed. This change
does not resolve the default-credit gas shortfall.

## Primary and rescue recipient delivery across both executors

`module_tx_parity.py` now runs the native signer module suite with the actual
compiled fee-vault dependency, replacing its earlier deposit-only vault stub.
PRIMARY and RESCUE execute messages reach a recipient whose data counter advances
and whose balance increases. A global-retirement configuration refuses PRIMARY
while a real SLH submission still traverses module, wallet and recipient. The
suite records and compares 19 transactions under two configurations in native
and Rust executors, covering 10 cases including legacy framing, corrupted primary
signature, classical extra fields, lock and signed migration. The primary signature
guard deletion still changes a rejected signature into an unauthorized relay.

A separate recipient mutation removes its state update: execution succeeds, but
the delivery assertion fails. This prevents successful compute or wallet emission
alone from being reported as delivery. Both CI architectures run these checks.
Evidence and the corrected initial one-transaction retired-configuration driver
failure are indexed in `primary-module-delivery-20261006.json`.

The first funded internal message and active account prestates are harness inputs;
this suite does not prove an upstream payer transaction, wallet deployment, or an
external PRIMARY admission route. The paired rescue vault remains RESCUE-only for
AUTH. This closes the module-to-recipient evidence gap without claiming production
funding, custody, client integration or finality acceptance.

## SDK action validation before signing

`AuthRequest::new` now validates execute OutLists before exposing the signing
digest, for both PRIMARY and RESCUE. It applies the shared wallet's structural
and mode rules: 0–255 send actions, exact 40-bit/two-reference nodes and empty
terminal cell, send opcode only, mandatory `+2`, no bits 2/3/5, and no combined
64/128 value modes. Validation traverses the entire list with a checked counter.
Tests enumerate all 256 mode bytes for both roles and cover action-count, tag,
shape and tail boundaries. Independent wire vectors retain their prior hashes.
Eight new deletion controls cover the call site and each rule in addition to the
five existing AUTH controls, using the existing SDK CI runner.

This rejects known-invalid requests before signature generation. It does not
approve recipients or amounts, parse application payload semantics, establish
available funds, prove delivery, or replace the on-chain action checks. Other
request constructors still require proven state and appropriate key custody.

## Native signer client ABI

`crypto/pq/wallet-pq-signer-c.h` exposes owned opaque signer handles for generation,
seed import, public-key retrieval, bound signing and destruction. The C interface
requires the expected role/public key and one of the protocol-defined purposes;
it checks exact digest/output lengths and exports only signatures reverified by
the existing native backend. Exceptions from generation/import/signing become
failure results. Valid output buffers are untouched on failure. Callers own and
must wipe imported seeds; pointers must reference live buffers/handles, and handle
destruction must not race operations. No private bytes are serialized or exported.

Tests compile the header as C and exercise both algorithms and all five allowed
role/purpose pairs, wrong bindings, malformed sizes and unchanged failure outputs.
Injected RNG failure and invalid/backend-error verifier verdicts are also tested
through this ABI. Three interface deletion controls detect wrong-key, unknown-purpose
and wrong-output-size acceptance, alongside the five native-backend controls.
Both architecture CI jobs run the combined four-executable suite and controls.

This is an in-process integration boundary, not a completed Rust wrapper or key
store. Authenticated enrollment, request approval, seed persistence/backup,
device isolation and client transport remain required. Supplying a matching
expected key is not itself proof of chain state or user consent.

## Rust signer ownership and proven-state signing

The workspace `wallet-pq-signer` crate compiles the existing wallet-only native
backend and C ABI from the pinned repository sources, using the OpenSSL dependency's
include/link metadata. It provides a non-copyable, single-thread opaque owner with
automatic destruction, fixed role/purpose enums, and no raw-pointer or private-key
export. Seed import wipes the supplied mutable buffer on success, rejection and
unwinding; other seed copies and storage remain the caller's responsibility.
Native signatures are reverified before return, and Rust exports no output when
the native operation reports failure. Primary signatures are also tested with the
separate `fips204` verifier and a wrong-context negative control.

With the opt-in `contracts/native-wallet-signer` feature, `ProvenWalletState`
offers `sign_primary_submission` and `sign_rescue_submission`. These construct the
request from the authenticated wallet/module snapshot, derive the expected key
from the exact installed module data, and return SUB3 only after key-bound signing.
PRIMARY still requires fresh matching ConfigParam 48; retirement, stale proof,
wrong role and a different key refuse signing. Rescue remains independent of the
primary policy. The default contracts build does not link the signing backend.

The proof-binding tests use synthetic authenticated-state fixtures, not live chain
finality. They exercise real signing, canonical submission/request binding and
independent primary verification. Controls delete seed wiping, ignore native
failure status, and replace the proven key with the signer's own key; each must
fail semantically. Caller action approval, concurrent-request/nonce coordination,
encrypted persistence, backup, device isolation, POP/preparation client integration
and transport remain open. This feature does not activate a wallet or alter gas.

Local validation includes two wrapper unit tests, two compile-fail ownership tests,
11 feature-enabled state tests and 10 default-feature state tests, plus three
semantic deletion controls. The Rust public-test-key fixture driver (fixed public
test seeds; not a production CLI) signs the 65-transaction recovery suite and the
19-transaction module/wallet/recipient suite, with matching native/Rust receipts.
The recovery suite still uses diagnostic 20,000 credit. Both architecture CI jobs
now exercise the Rust signer in SDK recovery/POP, retaining the direct C++ signer
module suite as well. Evidence is indexed in `rust-signer-20261006.json`.

## Native POP signing for initial and successor enrollment

Under `native-wallet-signer`, `PopRequest::sign_initial` and `sign_successor`
reconstruct the expected POP from the pinned enrollment and compare its complete
cell hash before signing. Namespace, wallet/module identities, both keys and policy
must match; the supplied fresh proof-checked time must still admit the deadline.
The signer must match the selected enrolled key and uses the POP-only context,
returning PPS3. Successor POP does not require installation in the wallet: it is
needed before migration. PRIMARY POP remains allowed under REQUIRED policy and
does not consult global primary retirement, because it grants no authority.

The signing methods do not independently verify the supplied time. Callers must
obtain fresh chain evidence and use a new unpredictable challenge for each proof;
the fresh constructors below supply that challenge. Successful signing is not possession-proof completion: the existing
authenticated initial/successor receipt checks must still prove funded execution of
that exact challenge. Tests use locally constructed enrollment, real signatures and
independent primary verification, including wrong parties/keys/policy, expiry, and
old-key/wrong-role refusal for successor POP. Three new mutations remove enrollment
matching, replace the POP context with AUTH, and substitute the signer's own key;
the Rust signer control suite detects them alongside its existing three controls.


## Native preparation signing from proven wallet state

`ProvenWalletState::preparation_request` constructs PRP3 for a typed
`SuccessorDeployment`, requiring the same wallet, namespace and pinned module/vault
code. Positive canonical deployment amounts and the deadline are bound into the
request along with all three deployment witnesses. READY successors require
ConfigParam 48 from the wallet's exact checkpoint to authorize primary operation;
REQUIRED successors remain preparable after global primary retirement and wallet
counter exhaustion. The snapshot must still be fresh.

With `native-wallet-signer`, `sign_preparation_submission` signs that exact request
with the installed module's SLH rescue key and the preparation-only context, then
returns FPR3. A successor's new rescue key cannot substitute for the current key.
Tests use synthetic proven-state fixtures and real signatures; verification passes
through the VM C shim using the same pinned SLH implementation, so this is a
separate integration boundary, not independent cryptographic implementation
validation. Wrong contexts and digests fail verification. Seven added mutations
remove wallet/code/namespace/policy binding or substitute the signing key/context.

The caller still approves deployment amounts, obtains current network fee bounds,
funds submission, checks actual successor deployment, completes both fresh POPs,
and proves migration and subsequent delivery. This API does not establish live
chain acceptance or resolve the default 10,000-credit admission gate. Evidence:
`test/wallet-v5r2/preparation-native-signing-20261006.json`.


## Fresh POP challenge construction

With `native-wallet-signer`, `PopRequest::fresh_initial` and `fresh_successor`
derive the entire enrollment binding and generate a 256-bit challenge through
`wallet_pq_signer::fresh_pop_challenge`, backed by OpenSSL `RAND_bytes`. RNG failure
or an all-zero result returns an error and no usable challenge. There is no clock,
counter or fixed-value fallback. The same enrollment parser is used by signing,
while tests independently reconstruct expected POP wire cells.

Create a fresh request for each new proof, retain that exact request for transport
retries, sign against the intended enrolled key, and verify its funded execution
using the existing authenticated receipt API. Randomness makes accidental reuse
negligible; these constructors do not supply durable request storage, prevent VM
snapshot rollback, verify caller-supplied chain time, or mark a receipt consumed.
The low-level `PopRequest::new` remains available for deterministic encoding and
explicit challenge workflows and does not claim to generate randomness.

Local tests cover fresh initial and successor construction, deadline rejection,
real bound signing and independent primary verification. Injected RNG status and
zero-output tests exercise the wrapper's rejection behavior. Three additional
semantic mutations ignore RNG failure, admit zero output, or replace both fresh
constructors' random challenges with a constant. Evidence is indexed in
`test/wallet-v5r2/fresh-pop-20261006.json`.


## POP receipt enrollment binding

Both public POP receipt methods now reconstruct the request from the supplied
initial or successor enrollment, including its wallet address, and compare the
complete request hash before accepting execution evidence. This closes a client
binding gap: the immutable module can answer challenges naming different wallets,
so matching only module code/data and a successful challenge transaction did not
establish that the caller's selected wallet was the subject of that proof.

The reconstructed deadline is checked at the authenticated transaction time.
Existing pre-state, enrolled-code/key, successful execution, exact challenge and
non-bounced-input checks remain in place. Historical acceptance is not current
readiness: the client still needs fresh chain state and per-key fresh requests.

The regression test uses the existing native successor POP transaction fixture
with a synthetic authenticated anchor. It accepts the correct wallet and rejects
the same transaction when a different enrollment wallet is supplied. Deleting the
new binding check reproduces wrong-wallet acceptance; all five receipt deletion
controls and restored tests must pass. This proves the client validation boundary,
not public-network finality or completed migration orchestration. Evidence:
`test/wallet-v5r2/pop-receipt-enrollment-20261006.json`.


## Funded POP route receipts

`FundedPopReceipts` supplies the fee-vault and module transactions plus each
transaction's pre-state. `PopRequest::require_initial_funded_receipt` and
`require_successor_funded_receipt` validate the exact enrolled vault address,
executed vault code and immutable vault configuration (allowing the replay counter
to advance). The fee input must be the caller's exact submitted external message.
The module must execute the exact enrollment-bound POP, and the fee transaction
must actually emit the same internal message consumed by that module. Both
transactions must have complete execution and the same authenticated trust anchor.

This prevents a direct module payment or an unrelated successful vault transaction
from being treated as proof that the enrolled fee route worked. The existing
module-only POP methods remain explicitly narrower evidence. Neither API by
itself proves both keys, current reserve availability, successful migration, or a
restored-backup recovery drill.

The local positive test uses the recorded native `successor-pop-fee` and
`successor-pop-module` transactions, with synthetic authenticated proof metadata.
Wrong vault identity, altered executed code/configuration, internal instead of
external funding input, and a missing emitted message all fail. Five new guard
deletion controls reproduce the corresponding false acceptances alongside the
five existing POP receipt controls. Evidence is indexed in
`test/wallet-v5r2/funded-pop-receipt-20261006.json`. The migration signing gate below consumes both funded per-key proofs.


## Migration signing requires both funded POPs

`ProvenWalletState::migration_request` and `sign_migration_submission` consume
`MigrationEvidence`: distinct PRIMARY and RESCUE requests, both fee-vault/module
receipt pairs and their exact external submissions, a current successor-vault
proof and local fee continuity from the successor's custody session. The existing native `sign_rescue_submission` rejects raw `Migrate` actions;
callers must use the gated migration method. The low-level AUTH wire encoder remains
available and does not claim to enforce a client lifecycle.

The gate checks the successor's wallet, namespace, pinned code and policy, verifies
both funded POPs for that exact deployment, and requires all four transactions to
be authenticated at the wallet's checkpoint and trust anchor. Transaction history
now preserves its originating proof checkpoint when walking backwards. Each POP
transaction must also be recent under the wallet snapshot's maximum-age policy.
The current successor vault must be live and match that checkpoint, masterchain
time, trust anchor and exact enrollment. It must have an available leaf in the
current proven slot; an unexhausted tree alone is insufficient when that slot's
four leaves have already been consumed. The gate combines the proven chain
counter with local reservations and rejects a different custody route, regressed
proof time or an active restore barrier. Local continuity must never be inferred
from chain state. The result is an observation, not a durable fee reservation.
READY successors still need current global primary authorization; REQUIRED
successors do not. Migration uses the installed rescue key and existing epoch
rules, preserving recovery after execute counters are exhausted.

The new gate test uses synthetic successful transaction metadata and placeholder
POP signatures to isolate client validation. It is not a successful VM execution
of those POPs. It exercises a real native SLH migration signature; earlier funded
POP receipt tests separately use actual recorded native transaction pairs. Fourteen
semantic deletion controls cover generic signing bypass, duplicate roles, stale
POPs, receipt/vault checkpoint substitution, non-live vault acceptance, exhausted
fee trees, exhausted current slots, local custody reservations/route/time/restore,
and removal of either funded-POP verification. Both architecture CI
jobs run the new control suite.

This closes the native client signing bypass, not the full release gate. Callers
still generate and retain fresh requests, collect trustworthy proofs, approve the
migration, coordinate signing/fee reservations and funding, verify successful
on-chain installation and a subsequent payment, and handle retries/restores.
Current reserve sufficiency, LMS custody continuity, live-proof integration and
default-credit admission still require validation. Evidence:
`test/wallet-v5r2/migration-signing-20261006.json`.
The current-slot capacity extension is recorded separately in
`test/wallet-v5r2/migration-capacity-20261006.json`.


## Continuous dual-key funded POP recovery

The continuous recovery harness now executes both successor POP roles through the
actually deployed successor vault before migration: SLH at leaf 16, ML-DSA at leaf
17, then post-migration SLH payment at leaf 18 in the cached SDK flow. The separate
non-cache control uses leaves 8, 9 and 10. Module storage/data preservation,
actual emitted-message delivery, migration state, recipient update and both wallet
and fee replay rejection remain checked. No intervening balance top-up or wallet
state substitution is introduced. PRIMARY signs only POP, never AUTH; REQUIRED
policy and the retired-primary wallet state remain intact.

The Rust SDK wire/signing run now has 67 transactions with identical native/Rust
transcripts, including a 22-transaction continuous recovery and six journal-backed
fee signatures. SDK POP calls are explicitly checked as roles `[2, 2, 1]` (the
preparatory probe, retimed rescue POP, and successor primary POP). An additional
native control corrupts the successor primary signature before the valid fee
envelope is signed: the vault executes successfully, the module rejects with
1808, and migration is not attempted. Both architecture CI jobs run this control.

This harness exercises real transactions using public test keys and diagnostic
20,000 gas credit. That run used SDK wire encoding; the integration below additionally routes the
recorded transactions through the proof-bound migration signing API. Neither
result establishes live-network finality or default-credit admission. Evidence:
`test/wallet-v5r2/dual-pop-recovery-20261006.json`.


## Recorded transactions through the native migration gate

The full SDK recovery harness now invokes a test-only Rust adapter after both
successor POPs and before migration. It reconstructs typed initial/successor
enrollment from the compiled fixture pins, authenticates the primary POP at each
recorded account head, and walks backwards to the rescue POP using actual previous
transaction hashes and account state updates. Both exact funded POPs and current
account states feed `sign_migration_submission`, which produces the SLH body
actually signed into the subsequent LMS fee envelope.

The harness compares the gated request against independently encoded expected
AUTH bytes. After native/Rust replay, a second explicit Rust test checks that the
module's actual inbound body equals the generated signed body, proves fee-to-module
and module-to-wallet delivery, and binds the resulting wallet to the installed
successor. A sensitivity control substitutes a different signature over the same
request: verification fails; deleting the body binding admits it; restoration
recovers rejection. Both architecture CI jobs run this control.

These adapters live only under `cfg(test)` and `native-wallet-signer`. Their
ignored-by-default tests are explicitly invoked by the harness, which requires a
named successful test and exactly one passing result. Required artifacts and output
paths must be supplied; missing fixtures or reused output paths fail. The adapter
uses only the fixed PUBLIC test rescue seed. Its account proof metadata, trust
anchor and checkpoint are deliberately synthetic; the actual transaction cells,
state preimages, signatures and execution results are real local VM artifacts.
No production unverified-proof constructor or live custody path is introduced.

The 67-transaction dual-VM flow still uses diagnostic 20,000 credit. Public-chain
proof/finality, production custody, reserve readiness and default-credit admission
remain open. Evidence is indexed in
`test/wallet-v5r2/recorded-migration-gate-20261006.json`.

### Local custody continuity at migration signing

`MigrationEvidence::fee_continuity` is now mandatory. The gate calls the same
reservation planner as fee signing with both the proven accepted counter and
the local custody observation. It refuses locally exhausted slots, a mismatched
route, regressed proof time and a pending restore barrier before producing a
migration signature. Four additional semantic deletion controls exercise these
conditions independently of the chain-only capacity tests.

In the full recovery harness, the successor's still-running fee signer exports
`observed_continuity` over its private stdin/stdout pipe after signing both POPs.
The exact response is retained as `recovery/fee-continuity.json` and passed to the
test-only migration adapter. It is not reconstructed from the chain counter.
The signer remains open through migration and the subsequent payment, whose fee
signature still requires its own durable reservation and verification.

This snapshot does not reserve future capacity, authenticate an untrusted RPC
response, prevent concurrent reservations elsewhere, or establish rollback-free
cross-device custody. The caller must keep custody ownership intact and recheck
before fee signing. Fixture keys remain public and chain proof metadata remains
synthetic. Evidence: `test/wallet-v5r2/migration-custody-20261006.json`.

### Aggregate external-message admission byte budget

The admission pool now reserves serialized input bytes before checking chain state
or suspending for a checker slot. A move-only scope reservation holds the charge
through coroutine completion and releases it on success and early errors. The
default per-pool cap is 64 MiB; exhaustion returns `notready`. The existing size,
source-rate and adaptive count limits remain in force. Operators can observe the
used and limit values in `ext_msg_admission_bytes` statistics.

The previous maximum of 50,000 waiting requests permitted about 3.28 GB of raw
65,535-byte inputs by count alone, excluding active checks and other allocations.
This is a static capacity calculation, not a demonstrated network exploit. With
the new cap, at most 1,024 such inputs can hold reservations simultaneously.
Transport actor mailboxes before admission, parsed cell expansion, coroutine
metadata, accepted mempool ownership and caller-held buffers are outside this
budget. This change does not establish a whole-process memory cap or a concurrent
network load SLA, and it does not change gas credit, tariffs or signature rules.

Two local native tests cover aggregate exhaustion, overflow-sized requests,
move ownership and early-return release. Deleting either the rejection or release
guard produces a semantic test failure; restored tests pass. An actual pool actor
test also checks charging before state lookup and release on missing-state errors.
Both its translation unit and the production pool compile locally. Full actor
execution and its charge-deletion control require Linux CI because this macOS
build encounters unrelated Linux-only diagnostic IPC dependencies. Both rescue
CI architectures run these tests and controls. Evidence and exact local limits:
`test/wallet-v5r2/admission-byte-budget-20261006.json`.

The admission budget also has an isolated actor-scheduler test using the same
coroutine task and bridge-promise types as the pool. It waits until the reservation
is held, confirms a competing admission is rejected while the task is suspended,
and then checks release after success, an explicit producer error and destruction
of an unresolved producer promise. Removing release fails this test semantically;
restoration passes all three native tests. This covers coroutine unwinding without
requiring full node linkage, but does not replace the actual pool actor test or a
network load test. Evidence: `test/wallet-v5r2/admission-coroutine-20261006.json`.

### Combined admission helper experiment

A private compiler-copy experiment combined the previously tested fee-bound and
payload helper extractions, retaining all checks and the real LMS verifier.
Preparation required 13,673 credit (13,647 before ACCEPT plus 26 for ACCEPT),
versus the recorded 13,515 baseline. LMS remained 6,135; other admission work
rose to 7,512. The complete preparation fixture runner passed with diagnostic
20,000 credit, while default 10,000 admission failed as expected.

Reject this candidate: it worsens the most expensive measured request class.
AUTH and POP were not measured for this candidate because a preparation regression
already disqualifies it. Production source was not modified. This is evidence
against this particular compiler refactoring, not a proof that every safe
optimization is exhausted or justification for changing the network gas credit.
The reproducible `bounds-payload` variant and retained artifact hashes are indexed
in `test/wallet-v5r2/admission-combined-helpers-20261006.json`.

### PQ signer loading from encrypted Vault records

The optional `wallet-pq-signer/vault` feature adds `vault::load_bound`. It accepts
an existing `SecretVault`, a record ID, a fixed PQ role and an independently
trusted enrollment public key. A record must be an `Algorithm::None` blob with
`tos-wallet-pq-seed-profile=v5r2-seed-v1` and
`tos-wallet-pq-seed-role=ml-dsa-44` (32 seed bytes) or
`tos-wallet-pq-seed-role=slh-dsa-sha2-128s` (48 seed bytes). The record ID, algorithm,
profile, role and expiration are checked before import. The native importer
validates seed length. The derived public key must equal the supplied enrollment
key before a signer is returned; tags do not authenticate enrollment.

Seed access uses the Vault's protected memory and a mutable guard directly,
without an intermediate ordinary Rust seed vector in the production adapter.
`import_and_wipe` clears that import buffer even if native import fails. Other
Vault-owned protected copies follow the Vault's destruction policy. Errors are
mapped to a content-free rejection. The adapter neither exposes a classical
signing branch nor changes wallet authorization. The generic Vault dependency
still contains its unrelated existing classical-key functionality.

Tests create actual encrypted file stores using PUBLIC fixed test seeds and
master keys, flush and close them, reopen them and produce native PQ signatures
for both roles. Wrong master keys, mismatched enrollment keys, wrong record
profile/role and expired records are rejected. Four semantic deletion controls
remove profile, role, expiration and derived-key binding checks independently;
each must yield the corresponding false acceptance. Restored tests pass. Both
rescue CI architectures run the same controls.

This is a loading adapter, not a complete production custody service. The caller
must select/authenticate an encrypted backend, provision records safely, supply
trusted enrollment, keep primary and rescue custody separate and apply the proven
state/action signing gates. Expiration is checked when loading, not continuously
on an already returned handle. Revocation, creation UX, backup/restore policy,
device isolation and secure deployment of the master key remain release gates.
No real user keys were accessed. Evidence:
`test/wallet-v5r2/vault-pq-load-20261006.json`.

### Vault atomic-save hardening before PQ creation

Review of the persistent backend found that its fixed `vault.tmp` name was opened
with truncation. A pre-existing symlink at that name caused saving the encrypted
Vault to overwrite the symlink target before rename. A controlled temporary-directory
regression test reproduced that overwrite on the previous implementation. This
requires an attacker able to plant that filesystem entry; it is not a demonstrated
remote exploit or a disclosure of plaintext keys.

`FileJsonStorage::safe_save` now creates a random exclusive `NamedTempFile` in the
same directory, writes and synchronizes it, atomically persists it at the target,
and synchronizes the parent directory on Unix. Blocking file operations run in
`spawn_blocking`. The Unix regression checks that the planted symlink's target is
unchanged, both successive saves produce the requested contents and the saved file
has mode 0600. Existing callers and serialization remain unchanged.

All 51 storage tests passed locally. Reinstating the old save implementation
causes the exact unrelated-file overwrite assertion to fail; restoring the repair
passes. The encrypted PQ reopen tests are rerun against this backend. These are
local filesystem functional tests, not a power-loss or filesystem fault campaign.
A trusted parent directory is still required. Separate Vault instances/processes
can still have stale in-memory snapshots: this repair does not provide exclusive
writer ownership, cross-process merge safety or rollback protection. Safe PQ key
creation must retain those as explicit prerequisites. Evidence:
`test/wallet-v5r2/vault-persistence-20261006.json`.

### Exclusive ownership of file Vault snapshots

Every `FileJsonStorage::new` now obtains a nonblocking exclusive OS lock before
reading or auto-migrating the file. The descriptor remains owned by the instance
until destruction. Public standalone migration obtains the same lock; an internal
migration helper reuses constructor ownership without recursively locking.
Canonical parent paths and a stable filename-appended `.lock` sidecar keep atomic
replacement of the data file from changing the locked inode. The sidecar is never
unlinked by the library. Symlink Vault aliases are refused; Unix hard-link aliases,
unsafe lock ownership/permissions and nonregular lock files are also refused.

The test suite checks a second instance and standalone migration are refused while
held, reopening works after drop, alias paths are refused, and a separate child
process cannot open until the parent's instance closes. Deleting OS acquisition
causes both local-instance and child-process false acceptance; removing migration
acquisition causes migration false acceptance. Both controls restore passing tests.
The PQ wrong-master test now closes its previous Vault before reopening, so it
continues to test decryption rejection instead of accidentally testing lock refusal.

This is a cooperating-library local ownership guarantee, not protection against
an owner who replaces the lock file, software that ignores locks, restore of an
older closed snapshot or cross-device replicas. Parent directory trust and actual
filesystem locking semantics remain deployment requirements. The current API has
no separately unlocked read-only mode; callers should share one instance through
`Arc`. This closes the known simultaneous-instance stale-snapshot overwrite path
for callers using the updated backend; PQ creation still needs its own store,
flush, reread and failure-path validation. Evidence:
`test/wallet-v5r2/vault-ownership-20261006.json`.

### Fresh PQ creation through the Vault adapter

`wallet_pq_signer::vault::create_new` generates a role-specific seed directly in
protected memory using OpenSSL's platform-seeded random generator. It rejects
random-generator failure and all-zero output. A protected copy is imported and
wiped to derive the expected public key; the temporary native handle is destroyed.
The original protected seed becomes a versioned PQ blob with the fixed role tag.
The adapter stores it with `NewOnly`, requires `flush` success, drops its temporary
record and loads the stored seed through `load_bound` with the generated public
key. Only that successfully rebound signer is returned.

The caller must supply an authenticated encrypted backend with exclusive writer
ownership, keep role custody separate and enroll the returned public key through
the wallet's existing proof and possession gates. This API does not create or fund
an on-chain wallet and does not export seed bytes. A persistence error or cancelled
future may leave a record already stored. The adapter neither deletes that record
nor overwrites it on retry; the caller must resolve uncertain creation explicitly.
A successful backend flush/readback is not an independent hardware durability or
backup guarantee.

Tests create fresh ephemeral ML-DSA-44 and SLH keys, reject duplicate IDs, close and
reopen real encrypted file storage, and produce native POP signatures with the
recovered keys. A fault-injecting wrapper around the real backend reports store
or flush errors after writing, or substitutes another seed on readback. Creation
returns no signer in all three cases, while the original stored record survives.
RNG failure and all-zero output must leave no record. Six semantic controls remove
RNG status/zero checks, permit overwrite, ignore store/flush errors or remove the
readback key binding; each must fail its explicit false-acceptance assertion.

This completes a local library creation path, not production custody acceptance.
UI/CLI provisioning, secure master-key management, isolated rescue devices,
backup/restore, revocation, closed-snapshot anti-rollback and actual chain
activation remain open. Evidence: `test/wallet-v5r2/vault-creation-20261006.json`.

### CI mutation anchors and governance answer reconciliation

The native ML-DSA mutation runner's base-gas text became ambiguous when the generic
suite gained its own ML-DSA charge. Its mutation now includes the standalone
opcode's four-input stack check, leaving the suite path unchanged. All seven
mutations produced semantic failures locally and each restored baseline passed;
all anchors are checked before beginning the campaign.

The governance proposal regression retained the pre-AUTH-policy configuration
upgrade answer. With the current compiler and unchanged other inputs, compiling
`config-code.fc` from `52d2e8b66` in a private source copy and substituting only the
generated configuration assembly reproduces the old answer. The old artifact
fails the new answer; restoring the current artifact passes it. Only the
`config_upgrade_root_hash` field changes; the configuration proposal, elector
upgrade and complaint envelope roots remain identical. The source difference is
the AUTH retirement-policy include and transition/membership checks introduced by
`367d41e41`. The full check then exposed a second stale answer in the zerostate
regression, which had not run after the first fatal governance mismatch. The same
old/current configuration controls reproduce both zerostate answers; only its BOC
size, file hash and root hash change. Basechain state and all address summaries
remain identical. These two records are updated; no contract guard or policy is
removed. `governance_policy_regression.py` preserves both sets of cross-checks and
restores the generated assembly even if a test fails.

These fixes address failures observed on CI head `f6837f42a`; local evidence does
not substitute for a fresh Linux run of the final branch head. Reproduction and
retained outputs: `test/wallet-v5r2/native-ci-repair-20261006.json`.

### Proven-state signing with a borrowed Vault session

The optional contracts feature `native-wallet-vault` exposes
`wallet_v5r2_vault::VaultKey`. Its PRIMARY and ordinary RESCUE methods first build
the request through `ProvenWalletState`, then load the exact proven role/public
key from the selected encrypted Vault record. After the asynchronous load, they
sample the caller's trusted clock again, reject backward movement, and invoke the
existing strict signing method with the new time. This reruns freshness, deadline,
identity, counter, action and PRIMARY policy gates before producing a signature.
No authorization decision is derived from Vault tags or a raw record ID.

Ordinary rescue refuses Migrate before accessing custody and retains the existing
signing gate's rejection as well. The funded dual-POP migration API remains the
required migration path. Preparation and migration now have the equivalent Vault
methods described below, as do initial and successor POP. Applications must still
approve actions, use a trusted clock, authenticate current proof sources, reserve concurrent counters and fee
leaves, submit exact bytes and check delivery/finality. These methods do not perform
network I/O or prove that chain state cannot change after the observed checkpoint.

The integration test creates separate encrypted PRIMARY and RESCUE files, generates
fresh ephemeral native keys, binds them to synthetic authenticated-proof fixtures,
and checks both signed request bodies against the expected requests. It rejects
wrong-role custody, missing policy before secret access, stale rescue proofs before
secret access, backward clocks, proofs/deadlines that expire across loading, and
ungated migration before secret access. Six controls independently remove PRIMARY
or RESCUE preflight, clock ordering, each role's post-load time check, or migration
preflight; each fails the corresponding assertion and restoration passes.

These are real Vault/native-signature operations with synthetic proof metadata,
not live network evidence or full client release acceptance. Evidence:
`test/wallet-v5r2/proven-vault-20261006.json`.


### Vault-backed preparation and funded migration

`VaultKey::sign_preparation` validates the exact approved successor, funding
amounts, current wallet and applicable policy before loading the current SLH
record. `VaultKey::sign_migration` first requires the complete `MigrationEvidence`
gate: both funded POPs, their bound receipts and submissions, current successor
state and fee-custody continuity. Both methods load only the rescue key bound to
the proven current wallet. They sample the clock again, reject regression and
invoke the existing strict signing method with that new time. They do not offer
a seed-only migration bypass or authorize classical signatures.

The existing preparation and migration tests now also exercise encrypted Vault
loading using public fixture seeds. Preparation compares the exact request and
passes the Vault-produced signature through the independent SLH verifier. Migration
compares the signed request with the existing dual-POP gate's expected request.
Missing records combined with invalid successor/POP evidence establish validation
before custody access. Both tests reject backward clocks, stale proofs and expired
requests after loading. Six semantic controls remove each method's preflight,
clock ordering or post-load time refresh; each must fail its named test and
specific assertion, and both restored tests must pass. The control runner is
included in both architecture jobs of the rescue-context workflow.

This extends the custody API, not the production acceptance claim: these tests
use synthetic proof/receipt metadata. They do not establish live funded POP
execution, device independence, nonce reservation, delivery or finality. The same
immutable snapshot is checked twice; no newer network proof is fetched during
loading. Full client flows and default-credit admission remain release gates.
Evidence: `test/wallet-v5r2/vault-recovery-20261006.json`.


### Vault-backed initial and successor POP

`VaultKey::sign_pop_initial` and `sign_pop_successor` accept an already generated
`PopRequest` and the locally pinned complete enrollment. They share the native
signer's enrollment/deadline validator to resolve the exact PQ role and public
key before loading custody. After loading the matching encrypted record, they
reject clock regression and rerun the original strict signing path with the new
time. The request/challenge is retained unchanged; retries must reuse the exact
submission and funded receipt verification remains mandatory. The supplied clock
must represent current proof-checked time; these methods do not fetch or verify
chain proofs themselves.

A new test exercises both roles in both enrollment routes using real encrypted
storage and public test seeds. It independently verifies the ML-DSA signatures
with the Rust verifier and SLH signatures with the VM verifier shim, checks exact
PPS3/request framing, and rejects wrong enrollment and expired requests before
accessing a deliberately missing record. Each route rejects backward clocks and
requests that expire during loading. Six semantic controls remove shared
registration/deadline validation or each route's clock/post-load checks; each
must fail the named assertion, followed by a passing restored test. The existing
native signer controls also cover the shared validator after extraction.

The test deliberately uses REQUIRED policy: per-key POP remains allowed without
turning PRIMARY POP into AUTH or migration authority. These are signature and
custody tests, not funded transaction, live-proof or production-client evidence.
Full CLI/mobile lifecycle, actual proof sources, device isolation, default-credit
admission and final-head release validation remain open. Evidence:
`test/wallet-v5r2/vault-pop-20261006.json`.


### Fixed dual-root and fee derivation in the native client library

`wallet_pq_signer::kdf` now implements the design's fixed
`TOS-WALLET-DUALROOT-KDF-v1` encoding using OpenSSL HKDF-SHA256 in explicit
Extract-and-Expand mode. `DerivationContext` binds the public network tag, signed
big-endian global ID, unsigned account index and key generation. The three fixed
labels derive 32 bytes for ML-DSA-44, 48 bytes for SLH-DSA-SHA2-128s, or 48 bytes
for LMS SEED/identifier with the additional public fee-tree identity. Callers
cannot substitute labels, an expansion-only mode, hash functions or output widths.
The existing locked OpenSSL crate is reused; no package versions are upgraded.

`derive_seed_and_wipe` writes into caller-owned secret storage and clears the
provided master on success and failure. It clears output before validation and
copies the derived result only after successful native derivation of the exact
expected size. Temporary seed material is zeroized on drop. The caller must
protect and wipe successful output; the library cannot erase other master copies
owned by callers or guarantee operating-system snapshot/register erasure.
`derive_signer_and_wipe` imports derived PQ material directly into the native
single-owner handle without returning the seed.

Tests match all seven existing public dual-root/fee vectors byte-for-byte,
including the complete info encoding, and compare derived signer public keys with
those generated from the frozen seeds. They test exact master/output widths,
cleanup on success/rejection, and separation across network, global ID, account
index and generation, including unsigned maxima. Eleven deletion/substitution
controls detect omitted bindings, changed labels/salt/mode, accepted short masters
and missing cleanup, followed by restored positive tests. Both architecture jobs
run these controls.

This is the deterministic derivation layer, not a completed mnemonic restore or
wallet creation flow. Native mnemonic validation, recovery manifest authentication,
Vault persistence of derived roles (implemented below), separate-device custody
and the LMS restore barrier must still be integrated by clients. Fee derivation neither proves that a
tree identity is fresh nor licenses reuse of previously signed leaves. Independent
masters use the same public generation; legacy derivations remain unchanged.
Evidence: `test/wallet-v5r2/kdf-20261006.json`.


### Bound derived-key restoration into encrypted Vault records

`vault::restore_derived_and_wipe` restores exactly one PQ role from the fixed KDF
context into a new Vault record. It requires an independently authenticated public
key, checks its width, derives in protected seed storage, and compares the actual
native public key before any persistent write. Wrong masters, namespaces, roles
or enrollment keys cannot silently create a replacement record. The full public
context and its authenticated wallet association remain recovery-manifest duties;
Vault tags alone are not trusted enrollment evidence.

Creation and restoration now share `persist_new`: no overwriting, successful
store and flush, then exact public-key-bound readback before returning a signer.
A reported write/flush/readback failure may leave a durable record; it is preserved
for explicit reconciliation, never erased or overwritten automatically. The
restoration function constructs its borrowed-master wipe guard before returning
its future, so even cancellation without one poll clears that buffer. Once
derivation completes the master is cleared before persistence awaits. The
successful secret record contains the derived role seed, not the master.

Tests restore both roles into actual encrypted files, close/reopen and sign POP,
refuse duplicate IDs, check mismatched inputs leave no record, and verify unpolled
cancellation cleanup. Injected store/flush failures after a real write and a
substituted readback return no signer; reopening still finds the original derived
key. Six controls remove pre-store enrollment binding, unpolled cleanup, duplicate
protection, store/flush error handling or readback binding. Each fails a relevant
assertion and restored tests pass; the existing creation controls are also rerun
against the extracted persistence path.

This restores a seed record, not a wallet's chain state, complete mnemonic/UI flow,
recovery-manifest authenticity, separate-device custody or LMS scheduling journal.
Closed-snapshot rollback, fee-state loss barriers, actual chain readiness and
production deployment gates remain separate. Evidence:
`test/wallet-v5r2/vault-derived-restore-20261006.json`.


### Fee-scheduler mutation runner repair

ARM job 112091164565 in run 37408434711 at `8e9cd91dd` stopped before its
scheduler mutations because the runner still matched the old inline
`first.max(chain_next_leaf).max(local_next)` expression. Production scheduling
had moved local-custody merging into `plan` and calendar selection into
`select_leaf`. The runner now targets those two exact checks, validates all
replacement counts before compiling candidates, uses a fresh output directory,
and requires all six positive tests to execute. The local reservation, restore
wait and calendar-burn mutations each fail the expected semantic assertion;
production and restored candidates pass. Production scheduler code is unchanged.
This resolves the reproduced harness defect locally; it is not a claim that the
remaining Linux CI or deployment gates pass. Evidence:
`test/wallet-v5r2/fee-schedule-ci-repair-20261006.json`.


### Shared native mnemonic derivation and bound PQ recovery

The CLI's existing `tos_mnemonic` implementation is now the workspace library
`tos-native-mnemonic`; the CLI module reexports the same three functions. Word
normalization, 12/24-word acceptance, English word-list membership, native
basic-seed check, exact password input and 100,000-round private-seed derivation
are retained. This remains a TOS-native mnemonic format, not BIP39 checksum/seed
semantics. Internal normalized words, rejected generated candidates and the joined
phrase use zeroizing containers. Successful returned words/seed and caller-owned
phrase/password buffers remain the caller's cleanup responsibility; no complete
memory-snapshot erasure claim is made.

`vault::restore_mnemonic` validates and derives the native 32-byte master, protects
its local buffer with a zeroizing guard, then invokes the fixed KDF and the
independently public-key-bound new-record restoration path. It exposes no
classical signing branch and does not infer enrollment from the mnemonic itself.
Public fixed fixtures cover 12 words with the empty password and 24 words with an
exact whitespace-bearing password, two master seeds and four PQ role seeds.
Python hashlib/hmac independently recomputes every seed. The original CLI
implementation from `4a2e32a9b` passes those same frozen native vectors before the
shared implementation is restored. Six semantic controls change the basic-seed
check, normalization, password use, private-seed salt, rounds or selected seed
half, and each fails its named test before restored tests pass.

End-to-end library tests restore both roles for both public phrases into actual
encrypted Vault files, reject an incompatible mnemonic and wrong account index
before storage, reopen and produce native POP signatures under the expected keys
from independently computed frozen seeds. This is a library recovery path; full
CLI/mobile creation/restore commands, authenticated recovery manifests, separate
custody and chain readiness remain to be completed. Existing CLI identities are
not relabelled V5R2. Evidence:
`test/wallet-v5r2/native-mnemonic-20261006.json`.


### PQ key restoration through the actual CLI

Building `tosctl` with `--features pq-wallet` enables `wallet pq-restore-key`.
The command requires an explicit local encrypted Vault path, record ID, PQ role,
independently authenticated expected public key and every public KDF namespace
field. It accepts only PRIMARY/ML-DSA-44 and RESCUE/SLH-DSA-SHA2-128s. It does not
reuse the classical wallet import/configuration path or change wallet defaults.

Mnemonic and Vault encryption-key inputs use the existing protected file, inherited
FD or hidden-prompt reader. The encryption key is exactly 32 bytes of hex and is
moved into protected memory before the Vault is opened. Optional password file/FD
input preserves exact UTF-8 bytes, including whitespace and newlines; no selector
means the empty password. The new `read_secret_exact` retains the same file/FD
protection and size limits while permitting empty passwords. Existing mandatory
secret readers continue rejecting empty/whitespace-only inputs. No mnemonic,
password or encryption-key value is a command-line argument or environment input
for this command. Distinct FD selectors are required for distinct secrets.

Public metadata is validated before secret reading. The mnemonic and derived
public key are validated before opening custody, then the shared bound restoration
path repeats derivation and enforces new-record persistence/readback. Output is
public JSON with status `key_record_restored`, role, public key and namespace;
it is not wallet deployment, on-chain readiness or a completed recovery handoff.
Callers must independently authenticate the enrollment key and recovery metadata.

For example, after obtaining the public values from authenticated enrollment:

```sh
cargo build --manifest-path tosctl/src/Cargo.toml --locked -p tosctl --features pq-wallet
tosctl wallet pq-restore-key --role rescue --record-id wallet.rescue \
  --vault-file /secure/rescue.json --vault-key-file /secure/vault-key.hex \
  --mnemonic-file /secure/rescue.words \
  --expected-public-key "$RESCUE_PUBLIC_KEY" --network-tag "$NETWORK_TAG" \
  --global-id 42 --account-index 5 --key-generation 7
```

Only public values are shown as environment substitutions. Secret files must be
owned by the current user and have no group/other access. A password file, when
needed, contains the exact password rather than an automatically trimmed line.

The actual built executable is tested against four frozen mnemonic/role
combinations, duplicate restoration, wrong encryption keys, classical-role
rejection, exposed mnemonic permissions and inherited FD input. Public-input
checks cover empty IDs, wrong public-key/network widths and reused FDs before
attempting to read a deliberately missing mnemonic. Five controls rebuild the
binary after removing preflight guards or trimming exact password bytes and
require the corresponding command-level assertion to fail, followed by restored
positive commands. Both architecture jobs run the CLI and its controls.

This command restores one custody record. Complete wallet creation/manifest
workflows, transaction CLI/mobile integration, independent-device custody, LMS
loss handling, default-credit admission and final-head deployment acceptance
remain release gates. Evidence: `test/wallet-v5r2/cli-restore-20261006.json`.


### Recoverable PQ key creation through the CLI

The same `pq-wallet` build feature now enables `wallet pq-create-key`. It creates
one selected PRIMARY or RESCUE role with a newly generated native 24-word mnemonic
and the empty mnemonic password. Vault encryption-key input remains protected
file/FD/hidden prompt input. The public namespace fields and target record are
explicit; this key-level command does not assemble or deploy a complete wallet.
Each invocation generates a new master, so separate invocations do not implicitly
claim a shared master or independent physical devices.

After public input validation and exclusive Vault opening, an existing record
is rejected before generating a new backup. The command derives the public key,
writes the recovery phrase to a mode-0600 same-directory temporary file, syncs the
file, persists it without clobbering an existing destination, syncs the parent
and checks exact protected readback. Only then does it read the saved backup and
use the bound mnemonic restoration path to persist the derived role. A later
failure preserves the recovery backup and any uncertain record. There is no
automatic deletion/overwrite retry. Success reports `key_record_created` and
public key/namespace metadata, never the mnemonic or a wallet-ready claim.

```sh
tosctl wallet pq-create-key --role rescue --record-id wallet.rescue \
  --vault-file /secure/rescue.json --vault-key-file /secure/vault-key.hex \
  --mnemonic-backup-file /secure/new-rescue.words \
  --network-tag "$NETWORK_TAG" --global-id 42 --account-index 5 --key-generation 7
```

The mnemonic backup is plaintext recovery material despite its restrictive file
permissions; keep it offline as directed by the custody plan. A shared device
holding both masters can access both authorities. Filesystem durability and
trusted-directory assumptions remain the same as the encrypted Vault backend.

Eight actual CLI outcomes cover both roles: existing-backup refusal, successful
creation, duplicate-record refusal before another backup appears, and recovery
from that saved backup into another encrypted Vault with the same public key.
Tests check 24 words, mode 0600, no mnemonic in output or encrypted Vault, and
unchanged existing data. Fresh test secrets live only in disposable directories
and are removed when the harness exits. Three rebuilt-binary controls permit
backup overwrite, remove the duplicate preflight or generate only 12 words;
each must fail its specific command assertion, then restored commands pass.
The existing restore CLI controls are rerun after extracting the shared Vault
opening and public reporting helpers.

This completes a recoverable key-creation primitive, not full wallet creation,
manifest authentication, verified off-device backup, readiness, deployment or
mobile acceptance. No power-loss/device-isolation claim follows from these local
filesystem tests. Evidence: `test/wallet-v5r2/cli-create-20261006.json`.


## Initial public recovery manifest (2026-10-06)

`wallet_v5r2_manifest::InitialRecoveryManifest` prepares and reconstructs the
initial wallet, rescue module and fee vault identities. The strict JSON profile
`TOS-WALLET-V5R2-INITIAL-RECOVERY-v1` records public enrollment inputs, the fixed
PQ KDF identifier, declared master-input formats and derivation namespace,
release code hashes, all three StateInit hashes and the fee configuration hash.
It contains no private seed or mutable LMS leaf counter.

Reconstruction requires an independently trusted basechain wallet address and
an independently pinned `CodeBundle`; reading those trust anchors from the same
manifest defeats the binding. The parser bounds input to 16 KiB before JSON
parsing, rejects unknown and duplicate fields, unsupported profiles and policies,
noncanonical hexadecimal and invalid field widths, and reconstructs identities
through `WalletGenesis`. Both RESCUE_READY and SLH_REQUIRED remain supported.
The seed profile enum has only native mnemonic and raw 32-byte master formats;
it does not introduce classical wallet authorization.

Declared account index, key generation and seed-input formats are recovery hints
until actual recovered public keys are compared against enrollment. Address
reconstruction alone does not authenticate those derivation claims or prove
backup possession. `last_observed_epoch` is explicitly untrusted display metadata
and cannot affect reconstruction or authorization. An initial manifest can remain
valid after rotation: current authenticated chain state, retirement checks,
funded POP and durable fee-journal continuity remain mandatory separate gates.
This format does not supply authenticated backup transport or successor recovery.

Three local tests cover both policies, identity reconstruction, hint independence,
malformed inputs and independent trust anchors. Seventeen semantic deletion
controls each fail a named assertion when a guard is removed, followed by passing
restored tests. Both CI architectures run these controls. Fixtures use dummy code
cells and public test keys; these tests do not prove deployment or real-key
possession. Complete creation/CLI orchestration with compiled release code remains
pending. Evidence: `test/wallet-v5r2/initial-manifest-20261006.json`.

### Compiled-code manifest reconstruction in the execution fixture

The genesis adapter now accepts optional declared derivation metadata and an
independently supplied expected wallet identity. With those fields, initial
StateInit output is taken from `InitialRecoveryManifest::parse_and_reconstruct`,
not the pre-manifest genesis object. The Python fixture independently computes
the expected wallet address and all seven cells, supplies code pins from its local
compiler, and compares reconstructed cell hashes. Successor deployment keeps its
separate path; the adapter refuses initial-manifest use for successors.

The fixture rejects changes to wallet/module/vault StateInit hashes, wallet code
hash and the independent expected wallet. A rebuilt-adapter negative control
replaces supplied manifest bytes with freshly prepared bytes, bypassing the
supplied manifest. The rejection test must then fail specifically because a
tampered manifest was accepted; four altered manifests are confirmed accepted
by that mutant. Restoring and rebuilding the adapter restores all refusals and
identical compiled-code outputs. Both CI architectures run this control after
the complete recovery fixture.

Local execution with reconstructed initial cells passed 67 transaction comparisons
across both executors with no differences, including a 22-transaction continuous
recovery sequence with both funded POP roles and confirmed recipient delivery.
The suite still uses diagnostic gas credit 20,000: default-credit admission is
explicitly false. Public fixture keys and declared derivation inputs do not prove
real backup recovery; local compiler pins are not authenticated production release
pins. This is execution integration evidence, not a complete user-facing creation
command, current chain proof verification or production readiness.
Evidence: `test/wallet-v5r2/manifest-integration-20261006.json`.

### Verify the recovered initial PQ key

With `native-wallet-signer`, an initial manifest exposes
`verify_initial_master_and_wipe`. It checks the selected role's declared input
profile, derives its native PQ public key using the manifest's network, global ID,
account index and key generation, and compares it with initial enrollment. The
caller supplies a resolved 32-byte master; native mnemonic validation must already
have run for that input profile. The method clears the caller's master on every
return, including profile rejection before derivation. It returns no signer or
secret material and performs no storage or chain write.

This closes the gap between reconstructing an address and checking recovered
key material. Derivation metadata can change without changing StateInit; tests
explicitly reconstruct such a changed manifest successfully and then require
actual key recovery to fail for both PQ roles. Both correct masters pass; wrong
masters, profiles and short inputs fail with wiped input. Five semantic controls
remove key binding, input-profile binding, account-index use, generation use or
preflight cleanup and must fail the corresponding assertion. Restored tests pass.

Successful checking is limited to the initial key. It does not show that the key
is still authorized after rotation, recover LMS leaf state, validate physical
backup separation or complete a mnemonic/CLI/Vault recovery operation. Existing
live proof, retirement and custody requirements continue to apply.
Evidence: `test/wallet-v5r2/manifest-key-recovery-20261006.json`.

### Initial manifest to encrypted Vault recovery

With `native-wallet-vault`, `restore_initial_master_to_vault` uses the initial
manifest's role public key, network, global ID, account index and generation to
restore a resolved master into an authenticated, exclusively owned encrypted
Vault session. It checks the role-specific input format before invoking the
existing bound derivation/persistence API. The master wipe guard is constructed
before returning the future, so dropping an unpolled operation also clears the
borrowed input. Success returns only the public key, not a signing handle.

The existing Vault adapter enforces key binding before writing, new-only storage,
flush and bound readback. Errors do not automatically erase or overwrite an
uncertain record. This operation accepts an already opened Vault; it does not
claim preflight before storage opening. Native mnemonic validation precedes the
resolved-master API. Restoring an initial key does not establish its current
on-chain authority or authorize any message.

Tests use real encrypted file storage and both PQ roles with different declared
input formats. They check unpolled cancellation, profile and master mismatch,
changed derivation metadata, absence of records after rejection, successful
persistence, duplicate refusal without changing file bytes, and bound loading
after closing and reopening the Vault. Four semantic controls bypass profile
checking, force the original account index/generation, or delay the wipe guard
until polling. Each must fail its corresponding assertion; restored tests pass.
The existing five initial-master controls are rerun after sharing the wipe guard.

These are local public-fixture custody tests, not authenticated backup transport,
CLI orchestration, successor recovery, real chain readiness or device isolation.
Existing persistence-failure tests remain at the underlying Vault adapter.
Evidence: `test/wallet-v5r2/manifest-vault-20261006.json`.

### Native control log decoding repair (2026-10-06)

Run `37410539906` at `4a2e32a9bc3e2343bb72da402612169cb840dfcd`
completed successfully on AArch64. Its x86-64 job stopped in
`admission_budget_controls.py`: a native diagnostic contained byte `0x99`, and
Python's implicit strict UTF-8 decoding raised `UnicodeDecodeError` before the
control could inspect the process result. This is not a passing pool-control
receipt or final-head clearance.

Admission-budget and ingress-boundary runners now capture bytes, retain each
stdout/stderr stream exactly in separate binary artifacts, and render invalid
UTF-8 as backslash escapes in the text log. Build success, native exit status,
named test and semantic assertion checks are unchanged. A subprocess emitting
invalid UTF-8 reproduces the former failure and confirms exact raw preservation,
nonzero status and assertion text with the repaired reader. The three local
budget controls and two parser controls pass, including restored positives.
The Linux-only complete pool control still requires the next x86-64 CI run.
Evidence: `test/wallet-v5r2/native-log-repair-20261006.json`.

### CLI initial-manifest key restoration

`tosctl wallet pq-restore-initial` combines bounded initial identity reconstruction
with the existing protected mnemonic-to-Vault recovery path. It requires all
`pq-restore-key` enrollment/custody options, plus `--recovery-manifest`,
`--expected-wallet` (basechain account ID, 32-byte hex), three BOC paths
`--wallet-code`, `--module-code`, `--vault-code`, and separately authenticated
`--wallet-code-hash`, `--module-code-hash`, `--vault-code-hash` values. Do not obtain
the expected wallet or release pins solely from the manifest being checked.

Public input validation and `CodeBundle`/manifest reconstruction precede mnemonic
input and Vault opening. The CLI reads at most 16 KiB plus one byte for a manifest
and 256 KiB plus one byte for each code BOC, rejecting oversize files. Code hashes
are checked against the separately supplied pins. Once the native mnemonic and
exact password have been validated, a wiped copy of the resolved master is
checked against the manifest's initial role and derivation metadata. The existing
independent enrollment/public-key check also runs before persistent custody is
opened. Only then does the established new-only Vault restore/flush/readback run.
This command accepts only the native-mnemonic input profile for the selected role.

Success retains the `key_record_restored` public JSON output. It does not deploy
accounts, authorize the initial key after rotation, restore LMS state, establish
current chain readiness or implement successor recovery. Callers still obtain
live authenticated state before any signing or submission. This is an offline
initial-key recovery command, not a complete wallet recovery declaration.

Eighteen actual CLI outcomes cover both roles: successful restoration, duplicate
refusal without changing the encrypted file, changed account index/generation,
wrong seed-input profile, wrong independent wallet/code pin and oversized manifest
or code. Public identity/resource failures use a missing mnemonic path to prove
that validation stops before reading secrets. Rejected preflight leaves neither
Vault data nor its lock file. Tests use public native mnemonic vectors with an
exact whitespace-bearing password and compiled-code fixtures in disposable
custody directories. A rebuilt-binary control bypasses the manifest-to-master
binding and must fail because mismatched derivation metadata is accepted; the
restored CLI passes all eighteen outcomes. Existing restore controls are rerun
after extracting the shared optional-manifest execution path.
Evidence: `test/wallet-v5r2/cli-initial-20261006.json`.

### CLI initial public bundle preparation

`tosctl wallet pq-prepare-initial --enrollment-file public-enrollment.json
--output-dir new-bundle` accepts the same six code-path/hash options as
`pq-restore-initial`. It validates independently pinned code and strict public
JSON, calls the deterministic genesis/manifest builder, then writes
`wallet-state-init.boc`, `module-state-init.boc`, `vault-state-init.boc` and
`recovery-manifest.json` into a new directory. Each file is created exclusively,
synced and read back exactly; the directory and its parent are synced before
success. The manifest is written last. Failures preserve a possibly partial
bundle, and retries refuse an existing directory instead of erasing or replacing
it. This ordering does not claim atomic all-or-nothing directory publication or
power-loss fault coverage.

Enrollment fields are `global_id`, `network` (32-byte hex), `wallet_id`,
`primary_key` (1312-byte hex), `rescue_key` (32-byte hex), `policy`
(`RESCUE_READY` or `SLH_REQUIRED`), `fee_tree_id` (32-byte hex), `fee_public_key`
(60-byte hex), `fee_epoch0` and `derivation`. The latter contains `account_index`,
`key_generation`, `primary_seed_profile`, `rescue_seed_profile` and
`fee_seed_profile`, using the closed manifest input-profile identifiers.
Unknown fields, including secret material, are rejected. Only public enrollment
is accepted; no signing secrets or classical authorization algorithm are added.

The command returns `initial_wallet_prepared`, basechain wallet/module/vault
identities and the fee configuration hash. It does not generate the LMS tree,
prove fee-tree freshness or custody, verify any private key, fund/deploy accounts
or run the required per-key POP. Supplied public keys and derivation metadata
remain enrollment claims until the corresponding recovery/possession checks.
Use fresh fee material from the eventual production signing backend, not the
public test-only LMS adapter. The complete creation workflow remains gated on
that backend, state custody and authenticated funded POP acceptance.

Nine CLI outcomes compare both policies' three StateInit files against the SDK
fixture adapter, and cover duplicate/partial-directory preservation, unsupported
policy, wrong key width, unknown fields and wrong code pins before output writes.
A rebuilt-binary policy substitution must fail the requested-policy assertion;
restoring the CLI passes all outcomes. The eighteen initial-key restoration
outcomes now consume the actual CLI-prepared manifest and compare it with the
SDK output; their manifest-binding bypass control is rerun after sharing the
code-loading options. Public fixture keys and local code pins remain test-only.
Evidence: `test/wallet-v5r2/cli-prepare-20261006.json`.

### In-process native fee verification and journal export

`wallet-pq-signer::fee::verify_reserved_signature` verifies the fixed HSS L1 /
LMS SHA256 M32 H20 / LMOTS SHA256 N32 W4 profile using the existing native
consensus verifier. A small C ABI checks pointer/length bounds and the exact
reserved leaf before calling that implementation. The Rust API accepts only a
32-byte intent digest and returns a content-free rejection for failure. It adds
no private-key backend, tree generation or signing state.

With `native-wallet-signer`, `FeeJournal::sign_once_verified` durably reserves
before invoking the supplied signing backend, uses the native verifier before
caching, then rereads and cryptographically checks the cache before export.
`cached_signature_verified` similarly checks exact cached bytes against the
supplied enrolled public key, digest and leaf without invoking a signer. These
are low-level adapters: callers still authenticate route/key/time and enforce
current chain state, expiry and admission. The existing proof-bound fee flow
continues to require trusted cryptographic callbacks until its concrete backend
integration is completed.

A bounded public signature fixture comes from a fee cache used by the recorded
67-transaction dual-executor recovery fixture. Tests cover the valid signature,
wrong reserved leaf/digest, changed key/signature fields and malformed sizes.
Actual journal tests cover valid signing once, identical retry bytes, duplicate
reservation rejection, wrong-key export, burning a leaf without caching invalid
backend output, and refusing a cache whose signature was altered even after its
non-secret checksum was recomputed. Four semantic controls remove leaf binding,
cryptographic verification, pre-cache verification or export verification; each
must fail its named assertion and restored tests pass.

This supplies verification for a future real fee signing backend, not that
backend itself. The current test LMS tool remains unsuitable for secrets or
production custody. No change to VM consensus verification or gas pricing is
made here. Evidence: `test/wallet-v5r2/native-fee-verification-20261006.json`.

### Internal fee signing primitive and pinned source

`third-party/lms-reference/SOURCE.json` pins selected signing/derivation sources
and headers to revision `44e6c7de934c05942bf17cc819a81e765cfe67d7` of
<https://github.com/cisco/hash-sigs>. The retained license permits redistribution
subject to its notices and conditions. Selected files are unmodified and each
SHA-256 is checked by the semantic-control runner. The build uses SECRET_METHOD=2
and OpenSSL SHA-256. That profile accepts direct SEED[32] || I[16] material, as
required by the frozen fee KDF; the high-level HSS state-management APIs are not
compiled into this subset.

An internal C ABI accepts a borrowed 48-byte seed/identifier, reserved leaf,
32-byte intent digest, twenty-node public authentication path and the enrolled
60-byte public key. It builds only the fixed H20/W4 single-level HSS signature,
using the primitive's deterministic per-leaf randomizer. It checks identifier
binding and validates the result with the existing native consensus verifier
before returning success. For correctly sized output storage, preflight and
verification failures clear every output byte; derivation context storage is
cleared before return. The caller owns the seed buffer and must protect and wipe
it. No full stack/snapshot erasure or side-channel audit claim is made.

The primitive has no public unreserved Rust signing API. It owns no persistent
state and cannot prove leaf uniqueness. The proof-bound journal adapter below
provides reservation integration, and the encrypted-record adapter below adds
bound storage/loading. The full client recovery and device-takeover workflow
remains incomplete, so this is not a production-ready fee signer. The new source
is not a replacement for the reservation/restore barriers or exclusive custody.
It also does not generate authentication trees. RFC 8554 section 9.2 remains the
state-reuse constraint: <https://www.rfc-editor.org/rfc/rfc8554.html#section-9.2>.

A fixed public seed/identifier and authentication path generate a fresh signature
that passes both the native verifier and the independent Rust VM; a corrupted
signature fails the Rust VM. Primitive tests cover wrong seed, identifier, root,
path, leaf bounds and input lengths, with rejected outputs cleared. Three
semantic controls remove post-signature verification or either output-clearing
step and must fail named assertions before restored tests pass. Evidence:
`test/wallet-v5r2/native-fee-signing-20261006.json`. This is an internal primitive
and interoperability result, not production fee-signer completion.


### Proof-bound native fee signing with seed cleanup

With `native-wallet-signer`,
`FeeJournal::sign_proven_fee_with_seed_and_wipe` connects the fixed native signer
and verifier to the existing proven route, freshness, local deadline, restore
barrier and durable reservation checks. It accepts borrowed SEED[32] || I[16]
and a public 640-byte authentication path. Width and identifier mismatches are
rejected before reserving a leaf. A cleanup guard wipes the caller's seed on
all returns; the native-call path additionally wipes it immediately after the
call, before verification or caching. Invalid secret material or a bad path
found after reservation burns that leaf and produces no cache entry.

Successful signatures are verified against the proven public key and retained
for exact-byte retries. Reopening retains cached output but enforces the normal
restore barrier for new signing. The test uses a fixed public cryptographic
fixture and synthetic proof metadata with a framing-only inner POP; it does not
prove transaction execution, live proof acquisition or funded POP completion.
Three semantic controls remove preflight cleanup, identifier binding and the
local deadline guard and require named assertion failures. Both CI architectures
run the controls. Evidence: `test/wallet-v5r2/native-fee-journal-20261006.json`.

The adapters below add encrypted fee-seed storage/loading and full public tree
reconstruction. Live enrollment authentication, client takeover and hardware
rollback resistance remain separate unfinished gates.
The caller must also authorize the inner action and establish fee affordability;
a valid fee signature alone does not establish either condition.


### Read-only fee seed enrollment binding

`wallet_pq_signer::fee::verify_seed_and_wipe` verifies a restored fee seed against
an independently authenticated HSS L1 / LMS H20 / LMOTS W4 public key and a
640-byte public authentication path. The native backend derives one full LMOTS
public key, hashes its LMS leaf and walks all twenty authentication nodes to the
enrolled root. It never produces a message signature; the leaf can already be
used, and no reservation is needed for this read-only check. It rejects wrong
seed, identifier, root, path, leaf, profile and lengths. Rust clears the borrowed
seed on success and rejection. This is the pre-storage binding primitive for
fee-seed custody, not a restored signer or proof of exclusive device ownership.

The fixture is the existing independently generated public LMS enrollment and
leaf-12 path. Removal controls require root comparison, fixed-profile checking
and seed cleanup to fail named assertions. Evidence:
`test/wallet-v5r2/fee-seed-binding-20261006.json`. The encrypted fee-key record
lifecycle and full tree reconstruction are covered below; client recovery
integration remains unfinished.


### Encrypted fee records and journal-bound signing

With `native-wallet-vault`, `lms_fee_vault::restore_seed_and_wipe` imports a
48-byte fee seed into a versioned encrypted blob record. It verifies enrollment
without signing, uses `NewOnly`, flushes, then reads back and independently binds
the decrypted seed again. A guard installed before future construction clears
the input even if the future is never polled. Failed or cancelled persistence
may leave a record; callers must resolve it rather than deleting or overwriting
it. This API receives an already derived seed and an independently authenticated
public key/path. The SDK master/mnemonic adapters and complete reconstruction test below
cover fee recovery; a complete CLI/client flow is still required.

`FeeJournal::sign_proven_fee_from_vault` loads only a correctly tagged, unexpired
blob with matching record identity and algorithm. Its private loader returns
protected memory only inside the adapter; no public fee-seed export or unreserved
signer handle is added. The loaded seed is bound to the proven public key using
the selected leaf's authentication path before the existing journal signing
operation. A trusted local clock is sampled again after asynchronous loading;
a proof that expires during that wait is rejected before reservation. The
existing proven-time slot selection, restore barrier, durable reservation,
post-signature verification and exact cache retry remain in force.

Tests use a real encrypted file backend, fixed public test seeds and synthetic
proof metadata: wrong enrollment leaves no new record; duplicate import preserves
the file; close/reopen and exact signed-message/cache parity succeed; untagged
records and stale post-load proofs fail. Six semantic deletion controls cover
pre-store binding, load binding, record profile, new-only storage, unpolled
cleanup and post-load clock sampling. Evidence:
`test/wallet-v5r2/fee-vault-20261006.json`. These results do not establish live
proof acquisition, a production deployment, independent device custody or
hardware rollback resistance. The caller must keep the encrypted Vault and
journal exclusively owned and revoke an old device during takeover.


### Complete fixed-profile fee tree reconstruction

`wallet_pq_signer::fee::FeeTree::generate_and_wipe` reconstructs all 1,048,576
LMOTS public leaves and the complete LMS H20 binary tree from SEED[32] || I[16].
The backend uses the pinned W4 public-key derivation primitive and fixed leaf and
parent domains. It produces public nodes only, never a message signature. Rust
uses fallible allocation for the 64 MiB node buffer and clears the borrowed seed
on every return. The API returns the fixed-profile 60-byte public key and bounded
640-byte authentication paths; it exposes no signing handle or journal state.

Generation is synchronous and CPU-heavy. Clients must run it on a worker and
compare the result with independently authenticated enrollment during restore.
Rebuilding the public tree does not revoke another signer or bypass the journal's
next-slot wait. The cache adapter below persists and authenticates public nodes. The
mnemonic-driven SDK recovery is covered below; CLI/client integration remains. No phone performance, side-channel resistance or hardware
anti-rollback claim follows from this implementation.

The explicit full-tree test reconstructs the existing independent public fixture,
compares its entire public key and leaf-12 authentication path, then checks paths
at both tree ends and across the middle against the seed-binding verifier.
Ordinary tests check path bounds/order and rejected-input cleanup. The full test
is marked ignored only to avoid accidental repetition in generic test runs;
`fee_tree_controls.py` explicitly runs it in baseline, native domain mutation and
restored states on both CI architectures. Evidence:
`test/wallet-v5r2/fee-tree-20261006.json`.


### Enrollment-bound public fee tree cache

`FeeTree::write_cache` writes `TOSFT001`, the fixed 60-byte public key and exactly
64 MiB of public binary-heap nodes. No seed, signature reservation or restore
state is encoded. `read_cache` requires an independently authenticated expected
public key, validates the exact profile and framing, checks canonical unused
node zero and root equality, then recomputes every parent from its two children.
This authenticates all cached nodes to the enrolled root; an attacker-controlled
checksum is not used as an enrollment check. Allocation is bounded to one node
buffer, and truncated or trailing input is rejected.

On Unix, `save_cache_new` creates a new destination with mode 0600, synchronizes
contents, validates readback using the same file handle, and synchronizes the
parent directory. It refuses existing destinations. The caller must control the
parent directory. A failed operation may leave a partial file; this is not atomic
publication, and callers must not overwrite it automatically. The generic stream
writer delegates publication/durability to its caller. Cache loading is read-only
and does not replace secret-to-key verification or journal recovery barriers.

Structural tests use public zero leaf hashes solely to exercise cache integrity
and file lifecycle. The separately executed full H20 reconstruction test also
round-trips the real independent cryptographic fixture through the cache codec.
Eight semantic controls require magic, enrollment, profile, canonical zero, root,
parent hashing, trailing-byte rejection and new-only publication to fail named
assertions when removed. Evidence:
`test/wallet-v5r2/fee-tree-cache-20261006.json`. These are local SDK results, not
proof of live enrollment authentication or completed mnemonic recovery UX.


### Native mnemonic and master restoration of fee custody

`lms_fee_vault::restore_derived_and_wipe` derives the 48-byte fee seed using the
fixed dual-root KDF and supplied network, global id, account index, key generation
and fee-tree identity. It keeps derived material in protected memory, binds it
to independently authenticated fee enrollment, then uses the new-only encrypted
record adapter. A master wipe guard is installed before returning the future,
including unpolled cancellation. `restore_mnemonic` first validates the native
phrase and exact password, holds its resolved master in zeroizing storage, and
uses the same derivation path. It does not trim passwords or derive classical
signing keys. Borrowed phrase/password buffers remain the caller's responsibility.

The fixture `wallet-pq-signer/tests/fixtures/native-fee-recovery.json` is public
test material only. `fee_recovery_fixture.py` independently computes the fee KDF
with Python HMAC and obtains the enrolled root/leaf-zero path using the separate
LMS test tool. Tests cover wrong master, every public KDF namespace field, tree
identity, width, enrollment and path, invalid mnemonic and password whitespace,
unpolled cleanup, duplicate refusal and encrypted close/reopen. Seven semantic
controls require namespace substitution, misplaced cleanup and password trimming
to fail named assertions. The explicit full reconstruction test starts from the
native mnemonic, rebuilds the complete H20 tree, matches the independent key/path,
persists and reopens its public cache, and restores the bound encrypted fee record.

These adapters neither create nor modify the leaf journal. A recovered device
must still obtain authenticated current state, take exclusive custody, revoke
old writers and wait for the next-slot restore barrier before new signatures.
The tests establish an SDK recovery path, not a CLI workflow, live proof service,
funded rescue transaction or production admission. Evidence:
`test/wallet-v5r2/fee-recovery-20261006.json`.


### Initial recovery manifest fee binding

`InitialRecoveryManifest::verify_initial_fee_master_and_wipe` performs read-only
fee enrollment verification before custody storage is opened. It enforces the
manifest's fee seed-input profile and derives using only its network, global id,
account index, key generation and fee-tree identity. The supplied public path
binds the derived seed to the manifest's fee public key without signing. The
master is wiped on every return, including profile rejection.

With `native-wallet-vault`, `restore_initial_fee_master_to_vault` uses the same
manifest-bound namespace and the encrypted fee recovery adapter. It returns only
the initial public key after new-only persistence, flush and bound readback.
Unpolled cancellation wipes the input master. A successful preflight does not
allow persistence to bypass its own key binding. Mnemonic validation must precede
these resolved-master APIs when the declared profile is native mnemonic.

Tests reconstruct identities from separately supplied code pins and wallet ID,
then use an independently generated public fee fixture. Changed derivation
metadata can preserve the wallet address but must still fail private-key binding.
Tests also refuse incompatible enrolled network/global/tree contexts, wrong or
short master input and wrong seed profile without a new record. Successful
preflight/persistence wipes input, returns the correct public key and refuses
overwrite. Ten semantic controls cover those namespace/profile/key bindings and
both early-return and unpolled cleanup. Evidence:
`test/wallet-v5r2/manifest-fee-20261006.json`.

This is initial custody reconstruction only. It cannot authorize a retired fee
tree, waive current proof/readiness checks or reconstruct spent-leaf state. The CLI fee recovery entry is described below; the current-chain takeover
flow remains unfinished.


### Initial fee recovery CLI

With `pq-wallet`, `tosctl wallet pq-restore-fee-initial` accepts the initial
recovery manifest, independent basechain wallet identity and the same six release
code file/hash arguments as primary/rescue initial restoration. It requires the
native-mnemonic fee input profile. Mnemonic, exact password and Vault encryption
key use protected file/descriptor or hidden input; descriptors must be distinct.
No secret CLI literal or classical signature role is introduced.

`--fee-tree-cache` loads and authenticates an existing exact-size public cache
before collecting secrets. Without it, a blocking worker derives and reconstructs
the complete H20 tree and verifies its key against initial enrollment. Both
paths perform manifest-bound master verification before opening the encrypted
Vault. `--write-fee-tree-cache` optionally publishes the verified tree to a new
Unix file with sync/readback; a storage failure is not permission to overwrite.
A cache may already have been published if a later Vault operation fails. After
new-only encrypted persistence and bound readback, output reports only
`fee_key_record_restored`, the record ID, initial wallet and public fee key.

The CLI never opens a signing journal, chooses a signing leaf or declares rescue
readiness. Its leaf-zero path is used only for read-only seed enrollment binding.
Old-device revocation, current authenticated fee-route proofs, the next-slot wait
and funded rescue completion remain mandatory outside this offline operation.

Actual CLI tests exercise 14 outcomes, including no-cache reconstruction matching
every byte of an independently generated public tree, cached restoration,
wrong wallet/code/metadata/password/mnemonic/cache, unsafe secret inputs, duplicate refusal and
existing cache-output refusal. A CLI mutation removes preflight binding and must
expose that wrong-context input opened custody; restored code rejects it before
storage. A separate full-rebuild mutation requires the SDK enrollment comparison
to reject an independently supplied mismatched root. Evidence:
`test/wallet-v5r2/cli-fee-20261006.json`.


The parity job budget is 150 minutes for the expanded native custody/recovery
matrix, including repeated complete H20 rebuilds. The earlier ARM run at
`82d74c610c78ed13904c2ac2d9ff83f6f630889c` took about 71 minutes before these added
controls. Increasing the job deadline does not waive individual assertions or
semantic-control subprocess deadlines; final-head CI is still required.

### Native fee signing in the funded transaction fixture

The test-only `lms_fee_cache_fixture` example now selects the in-process native
LMS primitive with `native-wallet-signer`. It reads authentication paths from
independently generated public H20 trees and calls the primitive only inside
`FeeJournal::sign_once`'s post-reservation callback. The no-feature example keeps
the external public test signer. Neither mode is an application custody API.

`sdk_auth_parity.py --require-native-fee-signer` makes external fee signing
unavailable and requires the native backend report for the single-process and
persistent-session fixtures. The local run completed 67 transactions with no
C++/Rust executor differences, including 22 continuous funded recovery
transactions, six journal-backed recovery signatures and recipient delivery.
Primary/rescue signing uses the existing native signer fixture. Cached retries
return identical bytes without another signing call; corrupt backend output
burns the leaf and creates no signature cache. Removing the independent Rust VM
cache verification admits the wrong public key and triggers the intended
negative assertion; restoring it passes all cache checks.

These are public test keys, controlled chain-time inputs and diagnostic gas
credit 20,000. They do not demonstrate encrypted-Vault-to-live-chain integration,
current proof acquisition, device takeover/revocation, default-credit admission,
or production readiness. Evidence: `test/wallet-v5r2/native-fee-integration-20261006.json`.
The full SDK transaction CI and cache deletion control require this native mode.

### Encrypted fee custody matches executed recovery messages

`recorded_fee_custody.py` reconstructs both local enrollments and binds the
recorded pre-transaction fee account states. Its Rust test restores the two
public test fee seeds to separate, new-only encrypted Vault records, closes
custody, and reopens it for each of six recovery signatures. The production
`sign_proven_fee_from_vault` path selects leaves through the proof-bound journal,
loads and checks enrollment, resamples the clock, reserves durably, signs and
verifies output. No direct fixture signing callback is used in this replay.

Each output body matches the SDK-encoded body byte for byte and the input body
of the corresponding successful recorded transaction: lock, preparation,
successor rescue POP, successor primary POP, migration and payment. Cached
signatures read after dropping the Vault also match exactly. A stale clock
sample after key loading is rejected without reserving a leaf for every case.
Config-hash substitution and removal of the post-load clock sample must fail
named semantic assertions; restored code must pass all six messages.

This closes the local encrypted-custody-to-executed-message comparison. It does
not acquire or authenticate network proofs: the account cells come from actual
execution, while their proof metadata and local clock are explicitly synthetic.
The prior dual-VM execution used diagnostic credit 20,000. Live deployment,
revocation/takeover and default-credit admission remain open. Evidence:
`test/wallet-v5r2/recorded-fee-custody-20261006.json`.

### Public tree selection at the encrypted signing boundary

`FeeJournal::sign_proven_fee_from_vault_tree` accepts a validated `FeeTree`,
checks its enrollment against the fresh proven fee vault, and obtains the path
for the leaf selected by the journal. It then delegates to the existing
protected-custody signer, which rechecks the plan before loading and resamples
the trusted clock after loading. A clock transition or stale proof fails closed;
no caller-supplied leaf/path can be mixed with this API's selected tree.

The recorded six-message custody replay now loads both independently generated
public trees through the cache validator and signs through this API. A different
tree must be rejected before entering the delegated key-loading path. Deleting
that early enrollment check, substituting the fee config hash, or removing the
post-load clock sample must trigger distinct semantic assertions. Existing
path-based signing remains available with its original preflight and custody
checks. Tree loading/validation is synchronous and should occur on a worker
before interactive signing, rather than blocking a UI/event loop.

Evidence: `test/wallet-v5r2/tree-fee-custody-20261006.json`. This remains local
fixture evidence at diagnostic credit 20,000, not live proof acquisition or
production admission.

### Per-message admission boundaries

`recorded_admission.py` selects every successful fee external from the complete
recorded transaction set and binary-searches its minimum credit without changing
contract code, gas prices or any other configuration field. At both the minimum
and minimum minus one, the native and Rust executors must agree on the complete
receipt transcript. Each Rust invocation also replays three other recorded
transactions, retaining the driver's scenario-set completeness check. Accepted
native probes must match the original diagnostic receipt, including gas, actions,
state and balance. Below-boundary probes must fail before acceptance with out of
gas; zero credit can instead skip execution entirely.

The local native-signer fixture contained 13 successful fee externals. All 26
boundary points matched across VMs. Observed minima were 12,600 for the three
AUTH cases, 13,190 for three POP cases and 13,515 for seven preparation cases,
including amount/TTL boundaries. This confirms the default 10,000 gap across the
recorded recovery sequence; it is not a maximum over all legal message shapes or
a justification to change network credit. Existing function-extraction and
late-send experiments remain rejected. Evidence:
`test/wallet-v5r2/recorded-admission-20261006.json`.

The ARM job for remote `48dc1af037e5f2ac924eccb9bf2728a394da041f` stopped before
fee-recovery mutation execution because the `exact_password` source anchor
matched both production code and a subsequently added full-tree test. The runner
now targets the production call's `Rejected` error mapping explicitly. All seven
fee-recovery mutations were rerun locally and reached their named semantic
assertions; restored code passed. This fixes the test selector, not a password
behavior change. Final-head cross-architecture CI remains required. Evidence:
`test/wallet-v5r2/fee-recovery-anchor-20261006.json`.
