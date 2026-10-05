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
against MYCODE and its compiled vault dependency, and reserves its earlier balance
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

It reserves its entire pre-message balance and emits exactly two fixed-destination
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
