# Confidential workchain V2 implementation

Scope: implement the V2 specification in `/home/tomi/memo/TOS_UNO_PRIVACY_WORKCHAIN_V2.md`, with milestone review and corrections before claiming completion. This plan records implementation evidence, not deployment approval. Amounts are confidential; counterparties and transfer relationships are public.

## Authority and current decisions

The owner now delegates necessary design decisions to the implementer. Decisions must be explicit, derived from conservation, deterministic execution and bounded resources, and must not be hidden local defaults. Real-value deployment and irreversible external operations remain separate from coding.

Current specification/decision baseline: memo `1b2be223`; the earlier component work used `274258e5`. Operation fees now follow D24/D25: no public payer, user-authorized confidential debits flow through custody, with at most one aggregate operation-fee settlement per batch. D26 congestion allocation remains an activation obligation, not a property of fixed fees or admission limits. Process the authenticated inbox against open withdrawals before closing remaining expired records. Rich bounce messages return original logical time for scoped matching. Retirement does not remove the workchain configuration or custody while the native message lifecycle remains unresolved.

`created_lt` must be determined before committing effects. Allocate one transaction per affected account, with a common start strictly beyond authenticated host/inbox timing and every affected account's previous transaction end. Within each account, assign outgoing message times in canonical order. The native wrapper must reproduce those values, never fill an uncommitted identity into state afterward.

The specification separately authorizes a payout and one aggregate operation-fee settlement per batch (D24). The current payout materializer implements only the first output; an amount exposure limit alone is not permission to emit additional messages. Existing obligations retain the settlement period and fee reservation committed when admitted; configuration changes govern new obligations, not retrospective reduction of existing reservations. These are implementation decisions to include in the next design review, not claims of completed host enforcement.

## Milestones and evidence

| Stage | Required outcome | Status |
|---|---|---|
| M0 | Consistent design decisions, configuration semantics and review | Existing design/review; implementation decisions tracked here. Production numeric calibration is not proven by research measurements. |
| M1 | Multi-account wire, one logical execution, exact account coverage, native settlement, version gates, independent replay and synchronization | In progress. Private settlement/replay and outbound queue components exist; dual Native destination admission is integrated. Multi-account execution is not integrated into live collator/validator. None of these component results closes I13 acceptance. |
| M2 | Complete deterministic relations, system encryption, prover/verifier, ABI and supply-chain gates | Existing kernel work is partial evidence; not marked complete. |
| M3 | Registered accounts, real candidate source, SEND/COLLECT and pending lifecycle | Not accepted. |
| M4 | Native deposits and fee isolation | Not accepted. |
| M5 | Withdrawals, matched/late returns, reservations and settlement ordering | Not accepted. |
| M6 | Capacity, minimum hardware, state acquisition, lifecycle and migration | Not accepted. |
| M7 | External review and restricted public testnet evidence | Not accepted; no public deployment performed. |
| M8 | Real-value activation gates and operational rehearsal | Not authorized by a coding request. |

## Current integration boundary and next sequence

Source audit at `df73ed000`, after the reviewed dual-ingress development
snapshot; this section supersedes older per-component "next step" statements
below where later components already exist.

| Boundary | Current authoritative shape | Remaining connection |
|---|---|---|
| Dispatch | `ResolvedScopedWorkchainExecution` contains account-compute and singleton block execution only | Add explicit multi-account resolution with descriptor-bound authenticated policy; do not reinterpret the singleton engine interface |
| Admission | `ResolvedInputPolicy::from_resolved_fields` accepts supplied fields; dual destinations come from Config84 | Resolve every resource limit from the authenticated engine configuration and retain the same policy identity through admission and input commitment; no local defaults |
| Execution | `execute_and_settle_workchain_disposal` calls the account engine and private payout/disposal overlays | Invoke through the live block path only after bounded admission, commitment and complete authenticated inbox reconstruction |
| Validation | `ValidateQuery::check_transactions` still calls `replay_resolved_workchain_account_block` | Add an explicit versioned multi-record path that independently reconstructs every wrapper and dictionary difference; retain the singleton path |
| Publication | `build_workchain_outbound_queues` builds private Native queues from reconstructed exports | Publish accounts, AccountBlocks, InMsg/OutMsg and queue changes together, with rollback evidence; queue construction alone is not I13e |

Implement in that dependency order. The registry work must not invent resource
values: a profile without a fully resolved authenticated policy cannot execute.
The native account-engine interface is separate from the cryptographic kernel;
registering a placeholder is not a real candidate source or M3 completion.
Any immediate consensus-boundary review must include configuration provenance
and the zero-engine-call failures before admission completes.

The development snapshot does not prevent installation of unsupported execution:
`SUPPORTED_VERSION` only causes logging. The sole configuration-installation
code gate is `valid_config_data` through its ingress version/capability checks;
v16 does not prove that a binary has a multi-account executor. Release readiness
and a dry-run of premature v16 activation remain mandatory. No global warning
is changed into reject/fatal as part of this integration.

M1 acceptance requires all seven properties on those live paths: one logical
batch; one engine invocation per authenticated execution context; independent
actual-write-set equality and bound reads; exact account coverage with untouched
accounts unchanged; all-or-nothing state/message publication; the complete fixed
validation order; and independently rebuilt wrappers including payout and
aggregate-operation-fee exceptions. Helper-only fixtures cannot close any of
these live integration gates. Source-aware sticky errors and identical
authenticated budgets for collator/validator are additional required gates.

### Explicit multi-account registry binding (boundary reviewed, not live)

The registry now owns a separate `RegisteredWorkchainAccountEngine` map and an
explicit `resolve_account_binding` path. Three-way key isolation covers
AccountCompute, singleton BlockTransition and multi-account BlockTransition.
The result retains the descriptor-bound dual ingress and exact engine payload
configuration. It does not execute, admit resources, choose configuration values,
or add a multi-account alternative to generic scoped dispatch. Production startup
does not register a multi-account implementation. The dispatch row above describes
the live path and remains incomplete.

The positive binding test first failed against an unimplemented registration
stub. After implementation it verifies callback identity/role retention and
zero execution, and after review it also tests compute registration conflicts,
absent/mismatched entries and callback failures. Six independently rebuilt
mutations fail: registry presence, reserved-key rejection, dual-ingress
requirement, descriptor binding, null-config rejection and retained custody.
These controls are manual, not recurring CI or coverage of every guard. Shared
activation/active predicates are not duplicated for the sake of error wording.
VM exceptions propagate to a source-aware enclosing boundary; plain binding
Status is not a voting classification.

Review scope, disagreements and residual obligations are in
`uno-v2-account-registry-review-disposition.md`; evidence is in
`measurements/uno-v2-account-registry-evidence.json`. This closes a registry
binding prerequisite, not authenticated policy resolution or M1 integration.

### Configuration-sourced descriptor binding (boundary reviewed, not live)

`resolve_account_binding_from_config` obtains Config12 from the same Config
snapshot used for Config84. No caller-supplied workchain map or separately
constructed descriptor enters this wrapper. A snapshot not unpacked with both
workchain-info and capability modes produces an existing LocalUnavailable code;
it is not evidence of an absent descriptor or disabled capability. An intact,
authenticated snapshot remains an enclosing-host requirement, not a certificate
created by this method. Generic live dispatch remains unchanged.

The positive first failed against a compiled stub. After review, the fixture
covers incomplete unpack modes, absent entries, unsupported engines, mismatched
version/mode, and nonzero returned fields. Four independently rebuilt mutations
fail for unpack-mode provenance, descriptor version, mode and address width.
These are manual controls, not recurring mutation CI. Review/disposition:
`uno-v2-config-account-binding-review-disposition.md`; exact evidence:
`measurements/uno-v2-config-account-binding-evidence.json`. This unit does not
freeze the remaining logical-root definition or add engine resource defaults.

## Verification discipline

New tests must fail with the relevant behavior removed. A failed compilation is not such evidence. Preserve mutation logs and source identities. Missing dependencies fail rather than skip. Arithmetic and narrowing must be checked. Classify failures by provenance, not only exception type; local faults must not become candidate judgments.

Review completed milestones with Claude Code; review consensus-judgment changes or new error classifications immediately. Put verbatim reviews in `/home/tomi/memo/reviews/`. Do not label a milestone complete because its helper tests pass. Keep existing single-account semantics until a versioned migration replaces them.

## Participant timing evidence

`crypto/block/workchain-participant-lt.h` now computes the per-account schedule without cells or state writes. It requires strictly sorted, unique account keys, bounds participant/message counts, and checks all LT addition. The host must supply authenticated lower bounds and resolved limits; this helper is not an authentication or consensus-error-classification boundary. Allocation failures are not converted into candidate errors.

Two tests were first executed against unimplemented stubs and failed on positive numerical boundary cases. After implementation, independently disabling the checked-add overflow guard fails `ParticipantLtExhaustion`; disabling strict account ordering fails `ParticipantLtPlan` on duplicate input. Both guards were restored and rebuilt. The two focused tests and the full existing `test-workchain-block` CTest pass. Raw mutation output, restored output and source/binary hashes are in `measurements/uno-v2-participant-lt-evidence.json`.

The new tests are in the existing registered test binary. The mutation operations were manual and are not automatically rerun by CTest. This unit has no new consensus call site or error category; code review awaits M1 under the milestone rule. The preceding wire design review is not represented as a review of this implementation.

## Read/write access ledger

`crypto/block/workchain-account-access.h` now checks canonical unique declarations, authenticated old-hash/absence agreement, read-before-write, sticky failures, and exact actual-change/participant coverage. Every write needs an old-state read, including proof of absence for creation. Multiple semantic writes to one declared account are allowed; only one final physical participant record is allowed. Successful finalization seals the ledger.

Implementation decision: unused read declarations are rejected at finalization, rather than providing alternate padded representations of the same access plan. The host must derive actual old-state hashes and actual changed keys from the authenticated dictionaries. This utility cannot establish I13d by being handed two identical engine-supplied lists. Its declaration lookup must precede old-account fetch; its input vectors must themselves be constructed under bounded admission.

`AccountAccessBinding` and `AccountAccessExactCoverage` run in the existing CTest binary. The binding positive control failed against an unimplemented factory. Independently removing the old-hash/absence comparison makes the binding test fail; removing actual-change equality makes the coverage test fail. Restored focused tests and the complete `test-workchain-block` CTest pass. Evidence is in `measurements/uno-v2-account-access-evidence.json`. These are manual mutation runs, not a CI mutation facility or completed multi-account replay evidence. Review remains due at M1; no consensus entry point or new error classification was changed.

## Native account dictionary adapter

`crypto/block/workchain-account-dictionary.h` reads old Account hashes from Native ShardAccounts entries and obtains actual changed keys using augmented dictionary differences. Tests cover creation, deletion, data replacement, and a last-transaction-only change, plus exact coverage through the access ledger. The change limit bounds collected keys, not traversal cost; bounded admission and source authentication remain host responsibilities. Old-state parse failures propagate to the source-aware boundary, never becoming proof of account absence.

Replacing the actual old hash with its declaration fails the false-absence assertion. Omitting changed-key collection fails the numerical key-count assertion. Both mutations were restored and the full `test-workchain-block` CTest passed. Raw manual logs and restored source/binary identities are in `measurements/uno-v2-account-dictionary-evidence.json`; mutated artifact hashes were not captured. Tests are registered through the existing binary, but mutations are not rerun by CI. There is still no consensus integration or completed I13 acceptance, and milestone review remains pending.

## Access declaration wire

`UnoV2HostRead` and `UnoV2HostAccess` are now independent types in `block.tlb`. Neither extends TransactionDescr or configuration acceptance. The automatic CRC32 tags are `439e6964` and `7bc07a6d`; canonical definition strings and independent CRC results are recorded with the evidence. A read record is 33 or 289 bits, zero references. The access root is 34 bits, zero to two references. These local sizes are not closure, depth or deployment capacity bounds.

`workchain-account-access-codec.h` encodes and decodes the declarations, preserving absent versus existing old Account hashes. Entry bounds apply before copying or materializing entries. The access ledger enforces unique sorted reads/writes and write inclusion in reads. The decoder requires deterministic dictionary encoding by rebuilding and comparing the root hash; alternative valid TL-B label encodings are not accepted as V2 canonical encodings. This rebuild is additional bounded work, not free admission. The caller must admit the entire input closure before invoking the codec; this unit does not solve preflight integration or classify exceptions by provenance.

Both new tests first failed against unimplemented codec stubs. The implemented codec interoperates with generated TL-B validation and rejects malformed read records, unknown tags, root tails, writes without reads, duplicates and limit violations. Removing only the canonical comparison fails the alternate-label negative test. A separate combined mutation removes root size, tail-consumption and canonical checks, failing the trailing-bit test: these overlapping checks are not claimed as independently mutation-covered. All changes were restored and the full CTest passed. Source/binary hashes and logs are in `measurements/uno-v2-account-access-codec-evidence.json`. Mutation runs remain manual; M1 review is pending.

## Host identity wire

Independent domain, policy, context and identity TL-B types now encode the complete host identity. `workchain-host-identity.h` commits all 16 fields, including the full engine selector/mode and the finality reference. It does not authenticate values, recognize policy versions or construct the complete batch input. Finality closure admission is still the caller's responsibility. It introduces no transaction constructor or consensus call site.

`HostIdentityBinding` independently reads field order and extreme signed/unsigned values, checks generated parsing, and changes every field separately to require a distinct root hash. Its initial stub fails; replacing vm_mode with constant zero independently fails the numeric field assertion. Restored CTest passes. Logs and artifact hashes are in `measurements/uno-v2-host-identity-evidence.json`; the manual mutation does not claim removal coverage of all sixteen fields. Native Cell hashing is retained; no new hash backend is introduced.

Integration prerequisite discovered here: the earlier `InputPolicyIdentity` admission prototype omits vm_mode. Before coupling admission to this wire, extend that prototype and its preservation tests, derive engine-format/extended consistently, and prove that the same resolved identity is committed. Do not fill the missing mode with a local default. This pending integration is not represented as a completed input-policy binding gate. M1 review remains due at milestone completion.

### Admission identity agreement

The prototype identity now carries explicit `extended` and `vm_mode` fields; all current source call sites, including the optional measurement target, supply them. `encode_admitted_workchain_host_identity` compares configuration hash, extended flag, selector, mode, descriptor version and admission version with the identity retained by `AdmittedInput` before serializing. A test changes each of these fields while keeping the standalone encoding valid. It fails against an encoder without the agreement check; independently removing only mode comparison also fails. Clearing mode while copying the admitted identity fails the preservation test's numeric assertion. Restored block/admission CTest targets and the measurement self-test pass. Evidence: `measurements/uno-v2-admitted-identity-evidence.json`.

This closes the missing-field utility prerequisite above, not the authentication/configuration gate: the host still must derive resolved values from authenticated configuration and use the guarded encoder in the full input commitment path. Existing standalone encoders are serialization primitives, not authorization. No new error category or consensus entry point was introduced. Mutation runs are manual and milestone review remains pending.

## Complete input envelope construction

`UnoV2HostInput` now references identity, access, admitted candidate and optional canonical Native inbox. The automatic tag is `7c0766c8`; local layout is 33 bits and three/four references. The encoder uses the admitted-policy agreement check and access codec, then canonicalizes the host-provided inbox. Empty inbox is absent, never a fabricated nonempty list. Native envelope profiles remain separate from the ordinary-candidate profile.

This is post-admission construction, not validator preflight. The existing inbox codec performs semantic decoding. The validator must first bound and check the claimed commitment, then authenticate/rebuild the full inbox before using this constructor for replay comparison. The supplied count limits do not bound closure bytes or derived-wrapper cost. Source authentication, completeness, candidate effects and final atomic account commitment remain unimplemented integration work; a root hash here proves none of those independently.

`HostInputCommitment` checks generated parsing, each reference, empty/nonempty inbox, canonical inbox order, candidate/access/context changes, duplicate messages, count limits and policy disagreement. It fails against a stub. Independently omitting the inbox reference fails a numerical reference-count assertion; replacing access with a structurally valid empty declaration fails the access-root comparison after generated validation passes. Restored block/admission CTest targets pass. Logs and hashes: `measurements/uno-v2-host-input-evidence.json`. These mutations are manual, not CI mutation jobs; M1 review remains pending.

## Participant binding payloads

`UnoV2HostRecord` is an independent TL-B payload, tag `35739af6`, exactly 832 bits and no references. It binds input hash, effects hash, account ID and the zero-based position of that account in the canonical account-effects sequence. Record construction accepts a nonempty, strictly ordered write-key set under a supplied participant limit and the uint32 count space. Position narrowing follows a checked size bound and a nonnegative iterator-distance invariant. It performs no amount arithmetic or database writes.

Roles and permissions are not record fields. The host must derive them from authenticated state, check exact actual changes and rebuild every native wrapper. No TransactionDescr tag, payout exception, version gate or multi-account acceptance path is added here. The effects schema and its ordered account sequence still need implementation; a caller-supplied effects hash is not proof that those effects are valid.

`ParticipantRecordBinding` verifies generated parsing, exact local layout and values, changes each bound digest/account, and checks duplicate/reversed/empty/over-limit key sets. It fails against a stub. Forcing every index to zero independently fails the second record's numerical index assertion; removing strict ordering independently fails the duplicate-key test. Restored block/admission CTest targets pass. Raw manual mutation logs and hashes are in `measurements/uno-v2-participant-record-evidence.json`; mutation runs are not CI jobs. M1 remains incomplete and milestone review is pending.

## Per-account Native value-flow arithmetic

`workchain-value-flow.h` checks `old + imported + internal credits = new + exported + fees + internal debits` for every account. Each explicit internal transfer contributes the same CurrencyCollection to its source debit and destination credit, so internal movement cancels when summing the equations. Row keys are unique and canonical; missing endpoints, invalid values and excessive counts are rejected. No persistent state is changed. Native checked add/sub operations cover extra currencies; numeric comparison uses a checked difference, not dictionary-hash equality.

Accumulators explicitly fit unsigned 256 bits: the bigint backing storage may temporarily hold larger values, so add success alone is insufficient for this chosen arithmetic envelope. A boundary test demonstrated that before the width guard was added. This does not widen wire amounts: account/message adapters must enforce their existing TL-B limits independently. The helper accepts wide totals because sums of wire amounts need not fit one wire amount. Closure/resource admission remains external, including the supplied extra-currency validation budget.

Tests cover an operating-budget-to-custody transfer, total-preserving but wrong account allocation, omitted/reversed transfers, invalid amounts, missing accounts, extra-currency conservation and the accumulator boundary. The stub fails. Ignoring extra currencies independently fails their negative case; omitting per-account equality independently fails the total-preserving misallocation case. Restored block/admission CTest passes. Evidence: `measurements/uno-v2-value-flow-evidence.json`. A test-construction compile error was corrected and the stale binary result discarded.

This is not completed independent Native value-flow acceptance: rows must still be extracted from independently rebuilt accounts and message records in the host. It does not authorize transfer edges, prove fee isolation, or establish the confidential backing invariant. No consensus entry point was changed; milestone review remains pending.

## Native storage-participant wrapper (not activated)

The `1010` TransactionDescr constructor carries a participant binding. Generated
and handwritten parsers agree on its four bits and one reference. Preparation
uses a real active Native Account, changes data under existing account limits,
and runs no compute, storage, credit, action or bounce phase. Native value and
fees are pinned; this is the storage-only participant primitive, not custody
payout, coordinator fee settlement or account registration. Existing scope
dispatch still rejects it in both scopes. The named version-16 construction
floor does not activate it, change SUPPORTED_VERSION or replace the required
authenticated multi-account policy gate.

Claude reviewed this consensus-boundary change; the verbatim record is
`~/memo/reviews/uno-v2-storage-participant-review.txt`. Disposition:

| Finding | Disposition |
|---|---|
| M1 address mutation | Fixed using CellSlice contents comparison, including null checks. The suggested Cell hash API does not apply to CellSlice. |
| M2 activation | Named construction floor and descriptor tag added. Deferred full capability/profile activation to the explicit multi-account host switch; no claim that a version bump authorizes this path. Both current scopes remain closed. |
| M3 masked version test | Fixed with successful preparation at 16 followed by serialization at 15. Added field-specific mutation inputs for every new serialization clause. |
| L1 unknown diagnostic | Deferred wording until the explicit profile switch; rejection classification and both closed scopes are unchanged. |
| L2 exception contract | Documented source-aware caller responsibility for VmError, VmVirtError, CellCreateError and CellWriteError. A Status return is not a no-throw promise. |
| L3 role/no-op checks | Deferred role authorization to the host's authenticated role map. This low-level Account wrapper cannot infer a coordinator address from an absent policy. Data equality alone also does not imply an unchanged Native account: last_trans changes. Exact permitted effects and participant coverage remain host checks, not authorization by this helper. |
| L4 zero balance | Fixed: the positive fixture now preserves 1000 nanotomi. |
| L5 comment placement | Fixed. |

The initial unimplemented preparation failed its positive test. Independent
removal of account binding, address comparison, serialization version check,
code preservation, and the storage-specific cache guard each fails a real
assertion after a successful rebuild. Raw logs, patches and artifact hashes
are in `measurements/uno-v2-storage-participant-evidence.json`. These five manual
mutations are not a CI mutation facility or removal coverage of every guard.
The other field cases execute in the registered test, without that stronger
mutation claim. Two test-construction compile errors were corrected; no stale
binary result is used as evidence for those revisions.

Additional integration prerequisite: Transaction exposes mutable staging fields
and `commit()` copies them. Rechecking `serialize()` even with a cached root now
detects guarded mutations, but this is not a seal on arbitrary post-serialization
mutation followed directly by commit. The multi-account overlay must own these
objects without engine access, reconstruct/finalize their native state, and
publish once only after all wrappers and the actual dictionary diff pass. No
Account is committed by this test, and I13c/I13d/I13e are not accepted yet.

### Storage-only Native dictionary overlay

`workchain-storage-overlay.h` now composes the access ledger, authenticated-old
dictionary adapter, checked LT planner and storage wrapper into real Native
Account commits and AccountBlocks. Each Account and Transaction is private to
the function; no engine callback or mutable alias can intervene between
serialization and commit. Commits affect temporary Accounts only. Persistent
ShardAccounts and ShardAccountBlocks roots are returned together after the
actual dictionary diff matches the declared writes and participant keys. Failure
returns neither root and never writes CellDb or modifies the old root.

The fixture changes two of three accounts, parses both new accounts and both
AccountBlocks with Native parsers, checks each transaction's previous link and
its published last_trans hash/LT, and independently compares AccountBlock
old/new hashes against old/new Account roots. The untouched third entry is
byte-for-byte unchanged. Rebuilding from the same input produces the same two
roots. A second-account invalid data cell fails after the first private Account
commit, with no published result; a false old hash fails earlier during reads.

The test failed against an unimplemented builder. Independent mutations replace
the published last_trans LT with 1, and the last_trans hash with zero, each
failing a numeric/hash assertion. Raw logs and identities are in
`measurements/uno-v2-storage-overlay-evidence.json`. These are manual mutations,
not a CI mutation runner. The ordinary test is in the registered block target.

This is still only storage-only materialization. It does not authorize account
roles/effects, authenticate supplied configuration, implement registration,
custody payout or coordinator funding, integrate a full shard Merkle update,
or publish live manager state. Count limits do not replace closure/state-read
budgets. Source-aware exception handling remains at the enclosing admission
boundary. Complete validator replay and I13 acceptance are pending; existing
single-account acceptance stays unchanged. No consensus call site or error
category changed in this step; review is due with M1.

### Payout principal and Native fee allocation

The Native mode-1 sender reports both total forwarding fees and the fraction
collected by the current transaction. `workchain-payout-accounting.h` separates
these: for payment X, total fee F and locally collected C, custody decreases by
X, coordinator decreases by F, and the exported value is X plus F minus C. An
explicit internal funding edge carries F from coordinator to custody; custody's
transaction fee is C. Both per-account conservation equations are checked, not
just the batch total. Native checked CurrencyCollection operations reject
underfunded principal, underfunded operator fees, C greater than F, invalid or
overflowing amounts. Distinct source accounts are mandatory.

This is an allocation helper, not a Native pricing oracle or payout authority.
The next integration must obtain X/F/C from the actual reconstructed send,
match its destination/amount and message LT to effects, and use the resulting
balances in private participant wrappers. Passing self-consistent engine fee
claims here does not authenticate them. No host entry point is changed yet.

The test fails against the unimplemented helper, then checks nonzero payment,
both remaining balances, exported value including residual forwarding fees,
each shortage independently, reversed address order and zero-fee exhaustion.
Independent mutations publish the old operator balance or omit the forwarding
value from the returned export; each fails a numeric amount assertion. These
are publication-consistency controls, not independent removal coverage of
every arithmetic guard. Raw manual evidence is in
`measurements/uno-v2-payout-accounting-evidence.json`; ordinary tests are in
CTest, mutation jobs are not. M1 review and full Native settlement remain due.

### Native payout reconstruction and pricing (boundary reviewed)

`Transaction::price_workchain_payout` reconstructs one mode-1 Native message in
a private scratch transaction, using real configured forwarding prices. It
returns the actual encoded payment, total fee, collected fee and end LT, without
committing the custody account. A fee budget is only a ceiling: the test supplies
500 and observes a fee of 102, not 500. Referenced body storage exercises the
basechain price path: 256 bits and one cell produce 460 with a collected share
of 230 under the fixture's price configuration. These are test prices, not
production initial values. Principal affordability and funding arithmetic are
checked before Native construction; LT additions are checked before entering
the existing constructor and message increment paths.

The request must use rich bounce, no anycast, no caller-quoted forwarding fee,
and positive payment. The returned value is unpacked from the actual generated
message and compared numerically. A zero extra entry passes generated syntax
validation but fails Native's handwritten currency validator, which uses
positive extra amounts before the send normalization path. Such requests remain
rejected; this helper does not widen Native's admissible currency encodings.

Claude Code's boundary review is retained at
`~/memo/reviews/uno-v2-native-payout-pricing-review.txt`. Disposition:

- Findings 1/2: fixed production-version feature flags in the fixture, added
  referenced-body pricing, basechain lookup and surplus-budget assertions.
- Findings 3/4: documented actual escaping exception types. The new path asks
  the existing staging helper to preserve VM exceptions; its default remains
  unchanged for old callers. Injected request-root load faults must propagate,
  including faults during staging. This does not prove all descendant or
  allocation failure paths. Disputed the claim that VmVirtError alone proves
  a local fault: input provenance, not exception class alone, determines that.
  The enclosing authenticated admission boundary still must classify failures.
- Finding 5: added validly encoded profile negatives and context boundaries.
  Independent removal controls cover the special-account guard and version
  floor; no removal coverage is claimed for every guard or redundant check.
- Finding 6: disputed the address interpretation: `-1:X` and `2:X` are different
  addresses; the fee-paying coordinator is not necessarily the payout payee.
  Added an actual `2:custody` to `0:payee` case, including destination checks,
  configured workchain lookup, and rejection when that workchain is absent.
- Finding 7: fixed returned-message value binding. Disputed that removing zero
  entries from virtual funding would make the sample Native-sendable: the new
  sample failed even with that attempted fix, because the existing handwritten
  validator rejects it before send normalization. The attempted normalization
  patch was withdrawn. The test explicitly checks both parser outcomes and
  rejection; this is compatibility evidence, not a new independent guard.
- Finding 8: documented the deliberately repeated principal check and fee
  meanings, restored declaration/comment adjacency, and asserted the changed
  collected share. Structural builder checks are not claimed as independent
  security gates.

Manual controls also disable exception propagation or return the maximum fee
budget instead of the Native fee; each fails an exception/numeric assertion.
Raw controls are in `measurements/uno-v2-native-payout-pricing-evidence.json`.
They are not automated CI mutations. The ordinary test is in the registered
block target. A zero-literal BitArray constructor initially selected a pointer
conversion; explicit `set_zero()` avoids that construction bug.

This helper does not authenticate role assignments, input policy or effects;
it is not a payout-authorizing transaction wrapper. Its local version floor
does not activate the multi-account profile. Effects-to-message binding,
coordinator debit and custody wrapper construction, independent validator
replay, and live shard publication remain M1 work. No retirement transition
removes configuration 84, the descriptor or custody: economic settlement is
not proof that Native messages no longer need those destinations.

### Two-account payout wrapper construction (boundary reviewed; admission pending)

`build_workchain_payout_pair` constructs two private Native transactions from
the real priced message and checked allocation. It returns custody/coordinator
transactions **and** `WorkchainPayoutAccounting`, preserving the internal fee
funding edge and derived flow rows. Those rows are construction results, not
independent verification of external evidence. The enclosing validator must
reconstruct them from authenticated effects and actual Native account/message
artifacts before comparing wrappers and publishing any state.

The new descriptor uses explicit prefix `1011`, following the existing
TransactionDescr four-bit allocation, not an implicit CRC32 tag. It does not
overlap `0000` through `0111`, retired `1000`, batch `1001`, or storage `1010`.
Its referenced UnoV2HostRecord keeps its existing derived tag. Both current
execution scopes reject `1011`; adding structural parser support is not
activation. Old single-account semantics are unchanged. Handwritten skip,
validation and storage-fee extraction must agree with the generated parser.

The strengthened fixture uses principal 137, total fee 100, collected fee 25
and remaining forwarding fee 75. Starting from 1000 each, the serialized
custody and coordinator accounts contain 863 and 900 respectively. Exported
value is 212. The test unpacks Native accounts, checks data and end LTs, reads
transaction fees and message counts, and checks each descriptor's exact binding.
An underfunded coordinator has a real encoded old balance of 99. Failure while
preparing the second account returns no pair and does not commit either old
account; this is not a live CellDb rollback demonstration.

Review transcript: `~/memo/reviews/uno-v2-native-payout-pair-review.txt`.
Disposition:

- Fixed symmetric test values and added serialized-value checks, fee-funding
  evidence, coordinator shortage, configuration and individual binding cases.
  Added skip/storage-phase/storage-fee extraction checks for the new prefix.
- Returned the accounting artifact instead of discarding it. A hash binding
  does not replace effects availability, role authorization or independent
  message/value reconstruction. Neither participant satisfies the ordinary
  per-transaction equation without its internal funding edge; only a dedicated,
  version-gated batch validator may account for that edge.
- Renamed `batch_storage_only` to `batch_metadata_sealed`: it enforces metadata
  preservation and cached serialization checks, not a claim of zero value
  movement. Removed the repeated state-limit traversal; the data/code/library
  roots do not change after storage preparation. This does not establish a
  complete account/message/wrapper resource budget.
- Kept amount/LT arithmetic checked, and documented both old-end LT bounds
  that keep constructors from increasing the already-checked start LT.
- Split context diagnostics, but **deferred source-aware failure classification
  to the enclosing admission boundary**. A configuration mismatch in locally
  derived inputs is not evidence of a bad candidate. Generic serialize failure
  still lacks a detailed Native failure reason, and escaping VM/builder/dictionary
  exceptions still require tested handling at that boundary. This is an explicit
  prerequisite for integration, not an accepted error-classification gate.
- Disputed treating additional error-string assertions as adequate negative
  evidence. Independent removal/publication controls are required; a null data
  case covers construction failure isolation, not every new guard. Also, the
  reseal test already fails if the flag is disabled: the flag's misleading name
  is real, but it is not an untested cache bypass.

The pair is returned in role order, not sorted account-key order. The final
overlay must own the referenced Accounts, derive the complete batch LT plan,
bind roles and all data changes from effects, handle coordinator batch entry
and inbox processing, re-sort for exact write-set coverage, and commit only
after every wrapper and value-flow check succeeds. This factory is a building
block for that overlay, not a replacement for it or evidence of complete I13.

Seven independent manual controls changed the coordinator debit role, collected
fee, input/effects/index binding checks, configuration agreement and published
binding reference. Every rebuilt mutant failed its numeric or acceptance/hash
assertion. Logs, patches and artifact hashes are retained in
`measurements/uno-v2-native-payout-pair-evidence.json`. This is not a CI mutation
facility, nor removal coverage of every context guard. The original stub failed
the positive construction case; ordinary tests run in the registered block
target. Review comments and their scope do not replace M1 end-to-end acceptance.

### Payout plus storage dictionary materialization

`workchain-payout-overlay.h` materializes a single authorized-by-caller payout
alongside the complete supplied storage write set. It authenticates each declared
old hash against the supplied old account dictionary before unpacking that
account, maps roles to canonical key positions, and runs the shared LT planner
over all participants. Custody/coordinator transactions come from the reviewed
pair constructor; other accounts receive storage-only wrappers. The old
storage-only builder and all production entry points remain unchanged.

All Account and Transaction objects are private to the call. No engine callback
can intervene between serialization and a private commit. The final dictionary
diff must exactly match the declared writes and participant set. Account roots,
AccountBlock roots and the one outgoing message are returned only together,
after all checks; the function neither writes CellDb nor publishes a message.

Value-flow rows are re-read from serialized old/new Native Account storage,
Transaction fees and the actual outbound dictionary. The transaction's account
state-update hashes are compared against those Account roots. Exported value
includes the actual message's remaining forwarding fee, not just its payment.
The returned internal fee-funding edge is included in the per-account check.
This removes reliance on allocation rows as proof of serialization consistency;
it does **not** authenticate a withdrawal or replace independent validator
replay of externally supplied block/state artifacts.

The fixture changes three of four funded accounts and puts custody after the
coordinator in key order. It unpacks all three new accounts and AccountBlocks,
checks principal/fee separation, transaction links, data, the outgoing message
hash and LT, and leaves the fourth account byte-for-byte unchanged. A repeated
construction has the same roots. A false old hash is rejected before account
preparation. Invalid storage data after an earlier private commit returns no
result. The original unimplemented builder failed the positive case.

This is post-execution materialization, still not a live multi-account host.
Role/effects authorization, full source-aware admission and exception mapping,
closure/read/serialization budgets, coordinator entry/inbox/storage charges,
and final shard update/replay/queue publication remain required. Count bounds
are not traversal budgets. The single outgoing-message bound is the current
custody participant shape, not a new production throughput setting. No
consensus call site or error category changed here; review is due with M1.

Three rebuilt manual mutants omit the returned message, publish an incorrect
last_trans LT, or omit the remaining forwarding fee from decoded export value.
They fail nullness, numeric-link or successful-construction assertions
respectively. The last control exercises the serialized value-flow check; it
is not an externally supplied malicious-block test. Raw logs and hashes are in
`measurements/uno-v2-payout-overlay-evidence.json`. These controls are not CI
mutation automation; the ordinary fixture runs in the registered block test.

### Claimed payout overlay replay

`replay_workchain_payout_overlay` reconstructs all Native artifacts from the
supplied old state and post-execution inputs, then compares the complete account
dictionary root, AccountBlock dictionary root, outgoing message and end LT.
It returns the reconstructed result, including locally derived fee funding;
the claim type has no field for untrusted accounting rows or fee-funding claims.

The fixture accepts the correct complete result. Negative cases re-encode a
ShardAccount last-trans hash, an AccountBlock hash update and an outgoing
message timestamp as structurally valid Native cells; a fourth changes end LT
with checked arithmetic. Each must be rejected by replay rather than merely
by a syntax decoder. These checks include untouched accounts through the full
dictionary-root comparison, not only listed changed keys.

This is artifact replay, not independent engine execution. Inputs still require
the enclosing source-aware admission boundary, authenticated role/effects
derivation and resource acceptance. Hash comparison does not establish data
availability for unmaterialized claims. No validator/collator call site is
connected, no execution scope is enabled, and neither full shard Merkle-update
replay nor network reception is covered. M1 acceptance remains pending.

The unimplemented replay failed its positive case. Independently removing each
of the four comparisons admits its corresponding negative fixture and fails
the test. Patches, raw logs and artifact hashes are retained in
`measurements/uno-v2-payout-replay-evidence.json`. These manual controls are not
CI mutation automation; normal coverage is in the registered block target.
No consensus entry point or error category changed; milestone review remains
due. The next integration gap is the engine's still-single-state result and
source-aware context, not additional root-comparison helpers.

### Declared account engine interface

`WorkchainAccountEngine` accepts the committed input envelope and a read view
restricted to declared accounts. The post-admission runner checks old account
hashes or absence before invoking the engine once. It does not expose the shard
dictionary or mutable Native Account/Transaction handles. Undeclared reads stick:
even an engine that ignores the read error and returns valid-looking effects
cannot succeed. Returned account data updates must exactly match the declared
ordered write keys, with no missing entries or null data.

This is not yet an authenticated execution boundary. The enclosing host must
authenticate the old shard, bound state closures and inbox construction, accept
resources, resolve policy and authorize effects. Native source exceptions still
propagate to that source-aware boundary. The optional payout request is not a
finalized message or a payment authorization. Actual Native dictionary changes,
participant coverage and value flow remain the settlement overlay's independent
responsibility; matching engine claims alone cannot establish I13c/I13d.

The reference engine fixture checks successful two-account execution, wrong old
hash rejection before any engine call, ignored unauthorized reads, omitted
updates, duplicate/wrong keys and null data. Removing each of the five runner
checks separately makes its corresponding test fail. Raw mutation logs and
artifact hashes are in `measurements/uno-v2-account-engine-evidence.json`.
Normal coverage runs in the registered block target; the mutation runs were
manual, not CI automation. No production call site or error category changed;
M1 review and live integration remain pending. Next is connecting this interface
to independently derived effects and the private Native settlement overlay,
then the source-aware collator/validator boundary and versioned activation.

### Engine effects to Native settlement

`execute_and_settle_workchain_accounts` now connects one declared-account engine
invocation to private Native materialization. The runner returns the exact input
envelope supplied to the engine. The settlement derives both participant hashes
itself, encodes the returned effects, and obtains every storage update and the
optional custody payout from that same result. Callers cannot supply alternate
input/effects hashes or substitute a second update vector. Old account hashes
come from the declarations already checked before execution.

`UnoV2HostEffects` is an independent TL-B type, not an activation or an extension
of accepted TransactionDescr scope. Its initial implicit tag was `0e15071a`, derived by
the repository compiler and independently recomputed with CRC32 from:

```
uno_v2_host_effects updates:HashmapE 256 ^Cell payout:Maybe ^Cell receipts:Maybe ^Cell events:Maybe ^Cell wire_bytes:uint64 verification_units:uint64 written_cells:uint64 = UnoV2HostEffects
```

That initial root had 228 bits and at most four references. The Native-transfer
extension below supersedes that inactive encoding. This is a local encoding size,
not a closure/depth bound. Sorted account keys commit each new data root; optional
payout, receipts and events and all three usage fields are committed. No final
Native transaction, AccountBlock, last-trans hash or shard root is included, so
participant bindings introduce no self-reference. The type has one constructor;
the generated table has no other occurrence of this tag.

The fixture executes storage-only and custody-payout cases. It decodes actual
Native balances, updated data, AccountBlocks and participant binding records;
both hashes must match the committed roots. Test-only initial balances of 1000
and principal 137 produce custody 863 and coordinator 900 under test forwarding
cost 100. They are not production policy values. Both paths call the engine once.
Eight independent mutations replace the input/effects binding, replace the data
source, skip payout dispatch, accept an unsupported inbox, omit receipts/events
or exchange usage fields. Each fails a state, count or numeric assertion. Raw
logs and hashes are in `measurements/uno-v2-account-settlement-evidence.json`;
manual mutation runs are not CI automation.

This is not the complete V2 settlement engine. Roles, configuration, resource
admission and withdrawal authority still need the resolved production boundary;
fees are independently priced in the Native overlay, not yet represented by the
complete protocol's explicit fee effects. Nonempty Native inboxes are rejected
before engine invocation rather than silently omitted from value settlement.
Account creation similarly requires a registration participant. Neither path
is an accepted substitute for coordinator batch-entry/import records. Full
shard-update replay, registry selection, proof/state transitions and live
collator/validator wiring remain M1 work. No consensus judgement file or error
category changed in this unit; milestone review remains pending.

### Coordinator entry record (boundary reviewed)

The inactive `trans_workchain_entry_v3$1100` descriptor carries three references:
the participant binding, complete host input and complete engine effects. Its
four-bit explicit prefix follows TransactionDescr allocation, not CRC tagging
of the separate payload types. Both current execution scopes continue to reject
it. The handwritten skip, validate, classification and storage-phase paths are
updated alongside the generated parser; no activation gate is removed.

`Transaction::prepare_workchain_entry` checks the input/effects hashes, workchain,
time/LT context and this account's data in the effects dictionary. It reuses the
Native inbound-credit validation for messages addressed to this account, then
seals a restricted entry without storage/compute/action/credit/bounce phases or
outbound messages. Only message value changes the balance; remaining forwarding
fees belong to Native InMsg accounting. The legacy credit sum now uses the
explicit checked CurrencyCollection addition API with the same wire-encoding
overflow check. Native source exceptions still propagate to the caller's
source-aware boundary; generic Status does not classify provenance.

The fixture starts at 1000, imports two messages with value 100 and forwarding
fee 67 each, and independently decodes 1200 from the resulting Native account.
After review the shared input also includes a third, foreign-destination message
with value 100; it is retained in the input and does not become coordinator credit.
It checks zero transaction fees, no outputs, unchanged original Account, exact
descriptor references and rejection by both execution scopes. Independently
removing credit application, the two hash guards, data consistency or any of
the three context guards makes its corresponding assertion fail. Evidence is
in `measurements/uno-v2-coordinator-entry-evidence.json`; manual mutation runs
are not CI. The positive case also failed against the unimplemented entry.

This is gross import into a private coordinator transaction, not Deposit
completion. The same logical batch must still allocate principal to custody,
allocate the paid slot fee to the coordinator, update the target pending state,
reconstruct per-account value flow and produce Native InMsg evidence. Custody
imports and wrong-destination handling remain separate unfinished paths. Roles,
inbox completeness, policy resolution and structural/work budgets are not
authenticated by this factory. Entry references provide actual cells in the
transaction; they do not establish archive retention or network availability.
The existing settlement runner still rejects nonempty inboxes until those
paths are connected. No production candidate is enabled by this unit.

The boundary review is retained verbatim at
`~/memo/reviews/uno-v2-coordinator-entry-review.txt`. Its dispositions are:

| Review item | Disposition |
|---|---|
| Shared inbox rejected on a foreign destination | Fixed: the entry selects its own destinations; the complete inbox remains committed, and other records must settle the rest. The legacy single-account call retains strict destination rejection. |
| Unchecked effect index | Fixed: the sole entry scans canonical effects ordering with a checked ordinal, checks the binding index, and tests a coordinator at index 1 as well as a wrong index. |
| Ambiguous diagnostic | Fixed: argument/encoding, input hash, effects hash, workchain, time/LT and data errors now have separate diagnostics. Error text is not a provenance classifier. |
| Descriptor failure after partial preparation | Fixed: construct the descriptor before preparing the storage participant. A child-depth probe raises CellWriteError and leaves the Transaction unserializable. Restoring the old order turns that assertion red. |
| Missing account access checks | Hardened: require this account's write membership and declared old hash before mutation. Both negative controls bind their changed declarations into otherwise correct inputs. |
| Entry necessarily differs from executor because of special status | Disputed: kWorkchainExecutorIsSpecial is false, the same value required by participants. The existing collator address filter is nevertheless a real integration prerequisite. |
| Complete-suite evidence | Expanded to VM, cells and smart-contract tests in addition to block/admission; still not a whole-repository or network acceptance claim. |

The review called descriptor construction failure unreachable because its local
shape is four bits and three references. That overlooks child depth: a valid
input root at depth 1024 cannot be wrapped in another ordinary cell. The test
deliberately supplies this boundary outside an admitted deployment profile; it
proves exception safety, not a live network exploit. The first probe caught only
CellCreateError and correctly failed because finalize_novm actually throws
CellWriteError. The final test catches that actual type and asserts that no
fallback storage transaction can be serialized. No production catch-all was
introduced.

Six additional review-fix mutations cover shared-inbox projection, index
matching, nonzero ordinal calculation, write membership, old hash and preparation
ordering. They all fail state/numeric/structural assertions. Updated evidence is
in `measurements/uno-v2-coordinator-entry-review-fixes.json`. Mutation evidence
remains manual and source/binary pinned. These are engineering corrections under
the already-required complete-inbox and I13 semantics, not new economic policy.
The source-aware replay boundary must still handle actual builder/allocation
exceptions and distinguish authenticated-source faults from candidate defects;
the review's broad classification of all Status failures is not an admission
certificate for future callers.

### Committed internal Native transfers

Engine effects now include canonical directed Native transfers. These are
public physical-account allocations, not the hidden amount in a confidential
SEND. A transfer is not authorization: the engine must derive allocations from
authenticated operations, and the host must independently reconstruct balances
and per-currency value flow. Native endpoints must both be in the account update
set. Self transfers, zero amounts, duplicate edges and noncanonical order are
rejected. Edges are ordered by source then destination; repeated contributions
to one directed edge must be aggregated with checked arithmetic by the engine,
not represented as order-dependent payment attempts.

`UnoV2NativeTransfer` contains source, destination and CurrencyCollection.
`UnoV2NativeEffects` contains the optional payout and a contiguous uint32-indexed
dictionary of those transfers. `UnoV2HostEffects` now references that Native
container in place of the old optional payout field, preserving a maximum of
four root references. The root is now 227 bits plus its referenced closure;
that local size is not a deployment capacity bound. The previous unactivated
encoding is superseded, not accepted as an alternate active format. No currently
accepted transaction profile uses this type.

Implicit CRC32 tags, independently checked against the repository compiler:

| Constructor | Tag |
|---|---|
| uno_v2_native_transfer | 6b953015 |
| uno_v2_native_effects | 0bd47725 |
| uno_v2_host_effects (with Native container) | 4155a803 |

Transfer count has its own explicit caller-supplied bound, separate from account
count. Extra-currency validation also has an explicit budget. These function
arguments do not freeze ConfigParam 84 fields or production values; production
resolution must supply the same authenticated limits to every validator. Wire
indices are narrowed only after the count fits uint32; iterator distances are
nonnegative and within that checked vector. Native amounts must be valid and
nonnegative, extra currencies must validate, and full CurrencyCollection storage
must succeed within Native wire limits. Allocation/source exceptions still
propagate to the enclosing provenance-aware boundary.

The fixture independently decodes both directed edges and amounts through the
generated parser. Eight mutations expose count, self-transfer, reverse order,
duplicate edge, endpoint coverage, zero-value, wire-size and ignored-transfer
failures. Negative/oversize amounts are also exercised. Evidence is retained in
`measurements/uno-v2-native-transfer-effects-evidence.json`; these are manual
source/binary-pinned controls, not CI mutation automation.

At this stage the settlement runner rejected nonempty Native transfers after
encoding rather than silently ignoring them. The message-free allocation
integration below supersedes that restriction, not the inbox or combined-payout
restrictions. No new fee model or production limit is selected here; no consensus
judgement file or error category changed. M1 review and activation remain pending.

### Entry-side Native allocation (boundary reviewed)

The inactive entry factory now derives its final balance from its own imported
message values and the committed internal transfer effects. It independently
decodes the transfer sequence, requires contiguous indices, strictly ordered
source/destination edges, nonzero values, distinct endpoints and endpoint
membership in the updates. All incoming and outgoing allocations are summed
before checked per-currency subtraction. This is simultaneous batch accounting,
not a sequence of payment attempts whose success depends on account order.
The final CurrencyCollection must fit Native wire encoding before any entry
preparation is committed to the temporary Transaction.

`allocate_workchain_native_balance` is post-admission arithmetic, not spending
authorization or a structural/work budget. Engine-derived purposes, roles,
all other participant balances, complete Native import records and independent
whole-batch value flow remain mandatory. In particular, a conserved transfer
graph does not authorize taking custody principal. This public Native allocation
must not be confused with the hidden SEND amount.

Tests decode the actual serialized entry AccountStorage balance, assert that
the original Account remains unchanged, and exercise exact depletion, a
one-unit deficit, and an incoming allocation funding the final outgoing unit.
The second-account entry case is an isolated alternative-role fixture, not two
entry records admitted in one block. A separate decoder test bypasses the
effects encoder's semantic guards using valid generated TL-B, and covers extra
currencies as well as Native TOS. Ten individually rebuilt mutations fail
numeric or status assertions; raw logs and source/binary hashes are in
`measurements/uno-v2-entry-allocation-evidence.json`. They are manual controls,
not automated mutation CI, and do not claim exhaustive independent coverage of
redundant arithmetic-width checks. Expanded VM/cells/smart-contract/block/
admission regression passed 5/5 after source restoration.

At this stage the whole-batch runner rejected nonempty imports and internal
transfers. The later allocation overlay integrates message-free transfers and
their restricted records with independently reconstructed value flow; imports
remain closed pending Native message evidence reconstruction.
Existing execution scopes still reject the new record profile. No configuration
initial value, message-finality rule or activation policy was changed.

The boundary review is retained verbatim at
`~/memo/reviews/uno-v2-entry-allocation-review.txt`. It independently reran the
two focused tests, checked source/binary hashes, and compiled the new header as
the sole include with project flags. Its dispositions are:

| Item | Disposition |
|---|---|
| A1: assignment comment described gross credit only | Fixed: the comment now describes imported values plus incoming minus outgoing allocations, with forwarding fees excluded from credit. |
| B1: updates membership relied on engine validation | Fixed: entry reconstruction checks effects and declared writes in both directions. The former own-write check is subsumed, not retained as an unmeasured duplicate. This enforces existing I13, not a new policy. |
| B2/B3: missing transfer bound and borrowed account-size budget | Fixed at the interface: allocation and entry require explicit transfer-count and extra-currency validation bounds, without defaults. Zero transfers permit an empty graph. No ConfigParam 84 fields or production values are selected here. |
| B4: balance extra-currency count and closure remain unbounded by this helper | Deferred to complete authenticated account/effects resource admission. A message's currency-count limit is not automatically an account-state rule. This inactive helper does not claim full anti-DoS admission. |
| B5: unpinned green baseline | Fixed: original green source/binary hashes independently confirmed by the reviewer are retained in its artifact; review-fix evidence includes new passing output and hashes. |
| B6: canonical leaf guard unmeasured | Fixed: a structurally invalid dictionary leaf with a valid transfer reference plus a trailing bit reaches the decoder directly; removing the guard accepts it and turns the status assertion red. |
| Additional coverage | Controls now reach Native-container parse-before-use and extra-currency accumulation/subtraction, not just Native-TOS projection. |

The invalid-container mutation ignores a failed unpack and then throws VmError
when constructing a dictionary from missing parsed fields. That control proves
the checked parse-before-use boundary; it is not evidence that candidate/local
fault classification is implemented. The other review-fix controls fail numeric
or returned-status assertions. All are manual source/binary-pinned runs, not
mutation CI. Raw results are retained in
`measurements/uno-v2-entry-allocation-review-fixes.json`.

The review's blanket characterization of all Status failures as candidate
invalid is not adopted: invalid resolved limits are a configuration/caller
failure, and provenance determines whether malformed cells came from a candidate
or authenticated state. Its required source-aware exception boundary remains
an integration obligation. Likewise, absence of a production caller is not the
only current barrier: both execution scopes still reject the record tag. The
runner's former blanket transfer rejection is superseded by the message-free
allocation integration below, not by a production activation gate.

Explicit entry/validation bounds do not replace complete closure accounting,
aggregate work admission or the activation gate before execution. Those must be
provided by the real host before its first production call. No message-count
policy or account-currency policy is inferred from these API arguments. The
per-entry scan is also not a plan to rescan the whole transfer graph for every
participant; batch-wide materialization must share checked accounting work.

### Restricted allocation participant (boundary reviewed)

The Native constructor can now materialize the other endpoint of an internal
allocation using the existing inactive settlement-participant descriptor. The
caller supplies per-account incoming/outgoing CurrencyCollection aggregates,
derived once by the enclosing batch from reconstructed effects. This factory
checks the opening balance and both aggregates, sums before checked subtraction,
requires final Native wire encoding, and prepares a sealed restricted record.
It does not receive user messages, emit messages, run ordinary phases, charge
fees or commit a live account. Only the binding is stored in its descriptor;
the full input/effects cells remain on the single entry.

This is a construction API, not authorization: an arbitrary aggregate supplied
by a caller is not proof that a transfer exists. Complete overlay settlement
must derive the aggregates from the replayed graph and independently verify
the actual serialized Native rows against that graph. That integration for
message-free transfers is recorded below; nonempty imports remain closed.
Custody inbound bounce handling and its separate payout exception are not
implemented by this no-message constructor.

The paired fixture now constructs an entry at 1073 and a participant at 1127,
from two opening balances of 1000 and two imported messages of 100 each. It
decodes Native AccountStorage balances and transaction fees, then checks the
per-account equations against the transfer graph. Changing one transfer by a
unit fails the check. The imported 200 is the independently known fixture value,
not production InMsg reconstruction. No AccountBlock/shard publication is
claimed by these two private transaction objects.

Nine independently rebuilt controls cover incoming funding, outgoing debit,
the record tag, Native wire width, validation budget, negative values, balance
sealing and the existing no-inbox/no-output guards as reached by this new API.
Raw output and source/binary hashes are retained in
`measurements/uno-v2-allocation-participant-evidence.json`; these are manual
mutation controls, not mutation CI. No new TL-B constructor, production limit,
activation policy or error-origin category is introduced.

The boundary review is retained at
`~/memo/reviews/uno-v2-allocation-participant-review.txt`. The reviewer reran the
green test and independently confirmed the archived source/binary hashes.

| Finding | Disposition |
|---|---|
| 1: null binding throws before validation | Fixed with an explicit argument check returning Status before descriptor construction. This is not a candidate/local provenance classification. The descriptor remains local and is built before preparation; moving it after preparation would weaken failure atomicity. |
| 2: missing builder exception probe | Fixed: null returns an error without a serializable record; a deliberately non-admitted deep binding exercises CellWriteError with unchanged balance and no serializable record. A valid binding has no references, so the deep fixture is an exception-class instrument, not evidence of a reachable valid-wire attack. |
| 3: extra-currency shortcuts hid coverage | Fixed: an independently encoded Native opening balance of currency 7 grows from 5 by incoming 7 and outgoing 3 to 9 in the serialized account. Tests also reject insufficient extra funds, a 248-bit addition overflow, and a positive but insufficient traversal budget. |
| 4: fault-loop output did not identify the arm | Fixed diagnostics now name each case. Separate controls reach negative outgoing and wrong-account binding. The original nine controls are not claimed to independently prove every fault arm; the insufficient-funding arm is not an independently isolated mutation. |
| 5: tag 11 allegedly requires a new owner decision | Disputed: build_workchain_payout_pair already assigns tag 11 to both records, but only custody has an output and fees. The coordinator already has neither. Tag 11 is not payout authority: the existing effects-based reconstruction requirement determines each physical record, including the custody exception. This helper adds no tag or authorization rule. |
| 6: parser parity | Fixed: generated/handwritten validation, exact skip, absent storage phase, zero storage fees and rejection in both current execution scopes are checked. |

Six additional rebuilt controls are archived with raw output and hashes in
`measurements/uno-v2-allocation-participant-review-fixes.json`. Four fail on
returned-status or numeric assertions; removing the null guard exposes
CellCreateError and changing the artificial probe's catch class exposes
CellWriteError. The latter mutates the test instrument, not production logic.
These are manual controls, not mutation CI. An intermediate compile failed due
to a duplicate local variable name; the following stale-binary pass is excluded
from evidence. A corrected-source rebuild and final regression are recorded.

Per-record nonnegative funding and whole-batch conservation are both necessary:
the first alone permits fabricated mutual credits, and the second alone permits
negative balances. The enclosing overlay must independently derive actual
Native message rows and re-decode the effects graph; this fixture still uses
known fixture imports and the pre-encoding transfer vector. Source-aware error
handling, bounded admission, shared graph aggregation, complete AccountBlock /
shard reconstruction and atomic publication remain integration work.

The concurrent design update at memo@74a4d424 changes operation fees to a public
deduction from the initiating confidential balance and adds an aggregate custody
fee-settlement path. This generic allocation factory neither defines nor
authorizes that path. Subsequent relation and settlement integration must follow
the revised design rather than treat the previous zero-operation-fee model as
complete; unresolved fee/congestion parameters are not supplied by this helper.

### Batch-wide allocation planning (M1 integration in progress)

`workchain-allocation-plan.h` decodes the admitted, replayed effects graph once
and accumulates incoming/outgoing CurrencyCollection values in an ordered map.
Every updated account has a row, including accounts with no internal transfer.
Canonical sequential transfer indices, strict source/destination ordering,
nonzero non-self transfers, endpoint membership, explicit entry bounds and
per-currency checked addition are enforced. Its retained transfer vector is
decoded from the wire, not the encoder's original in-memory object.

This is the shared input for restricted participant materialization, avoiding
one full transfer scan per account. It is not a new authorization boundary:
the enclosing host must authenticate/replay effects and admit complete input
closures before this call. The returned aggregates do not prove sufficient
funds. Constructors must check each account's actual old/imported balance,
and whole-batch validation must independently rebuild Native message and
account evidence before checking conservation against this decoded graph.
The current entry factory still has its one entry-local scan; integration may
share the plan but must preserve its existing input/effects binding checks.

The tests use three accounts and four directed edges with independently stated
totals, zero-transfer accounts, generated valid TL-B that bypasses encoder
semantic guards, malformed leaf layouts and real extra-currency dictionaries.
This header and its tests do not enable any live execution scope, change a
consensus caller, add an error category or select resource/configuration values.
They await the M1 milestone review with the overlay integration; no separate
boundary review is claimed for this unconnected helper.

Twelve rebuilt mutations fail numeric or returned-status assertions, with raw
logs, patch substitutions, source/binary hashes, standalone-header compilation
and the restored five-test regression retained in
`measurements/uno-v2-batch-allocation-evidence.json`. These are manual controls,
not mutation CI or exhaustive independent branch coverage. Endpoint membership,
invalid Native-container decoding, zero configuration budget and overflow have
test cases but no individually isolated mutation in this artifact. M1 remains
incomplete until the shared plan feeds actual Native records and full replay.

### Message-free allocation overlay (M1 integration in progress)

`workchain-allocation-overlay.h` now connects the graph plan to private Native
accounts, a single coordinator entry and restricted allocation participants.
The settlement runner invokes the engine once and passes its encoded input and
effects to this path. Even a zero-transfer, no-payout batch now has the entry
carrying the full input/effects; it no longer falls back to only storage records.
Current execution scopes still reject these tags in real blocks.

The overlay binds the complete identity to the caller's resolved context,
decodes declarations, verifies every old read (including read-only accounts),
requires the update keys to equal the declared write set and requires an entry
role. It derives every participant's data from effects and every allocation
from the decoded graph. One entry-local scan remains, but other accounts use
the shared plan rather than rescanning the graph. Currency validation is an
explicit runner argument with no default, checked before engine invocation;
it is not borrowed from an account-storage limit for this path.

For each constructed transaction, Native AccountStorage balances and transaction
fees are decoded independently. The input inbox, effects payout, transaction
in-message and out-message dictionary must all be absent; this is the evidence
for zero imports and exports, not an assumption about nonempty messages. Actual
rows are compared with the wire-decoded transfer graph. The transaction's prior
hash/LT, state hashes, account address and planned LTs are checked before private
commit. Each account gets its own AccountBlock and last_trans chain. The final
dictionary diff and access ledger require exact write/participant/change sets.
Only complete account and AccountBlock roots are returned; no CellDb write or
live account mutation occurs. Replay rebuilds both roots and the end LT and
compares each artifact, returning reconstructed roots rather than claimed ones.

The engine test now has an untouched third account, bidirectional transfer
checks, actual Native balances and descriptor contents, both AccountBlock
parsers, last_trans and state hashes, and replay mutations of each final artifact.
A failure in the second account follows construction of the first private
record but returns no overlay and leaves the old root unchanged. Foreign
destination inbox and payout-presence tests directly exercise this materializer,
not only the earlier runner guard. An invalid currency budget asserts zero
engine calls, independently of rejection wording.

This is not M1 completion or a production conservation gate. Nonempty Native
inbox settlement, allocations combined with payouts, the revised aggregate
custody fee-settlement path, registration, production admission/classification,
and live collate/validate publication remain open. The older payout-only helper
was subsequently connected to the single full entry below. No message is dropped to
make any of those cases fit this message-free path. Milestone review remains
pending; this unit changes no named production consensus-judgement file and
adds no error-origin classification.

The implementation also checks the actual nullable return of Native
`Transaction::commit`; failure is not interpreted as a successful downgrade.
Eleven rebuilt controls cover identity, required entry role, inbox/payout
exclusion, each allocation direction, the entry profile, three separate replay
artifacts and budget-before-engine ordering. A twelfth control restores the old
storage-field narrowing on the allocation path and fails the API-width test.
Logs, patch substitutions and source/binary hashes are retained in
`measurements/uno-v2-allocation-overlay-evidence.json`. All controls are manual,
not mutation CI. The first eleven precede the explicit commit-return check and
the payout-only narrowing refinement; both subsequent changes have a restored
green regression recorded separately. No exhaustive independent mutation of
every redundant Native consistency check is claimed.

### Native final-import evidence (M1 integration in progress)

`workchain-import-evidence.h` constructs standard final InMsg records referencing
serialized Native transactions. Records are keyed by the message hash, not the
envelope hash. The helper checks destination/account agreement, creation and
emission logical times, original versus remaining forwarding fees, explicit
entry bounds and the currency-validation budget. Native import-fee evaluation
and the actual augmented InMsg dictionary independently reconstruct totals.
Account credit is imported value minus collected fees using checked currency
subtraction; forwarding fees must not increase the recipient's principal.

The paired-entry fixture now feeds its independently decoded value-flow rows
from actual InMsg-derived credits rather than a literal imported amount. Tests
also inspect both InMsg parsers and actual envelope/transaction references.
Extra-currency examples test primitive accounting only: they do not claim that
the changed inbox is authorized by the fixture's original batch commitment.
A zero-value, zero-remaining-fee duplicate is important: aggregate totals cannot
detect that duplicate, so it independently witnesses the dictionary Add rule.

This is a post-admission construction primitive, not queue authentication or
complete batch acceptance. Queue membership, inbox completeness, transaction
roles, own-queue dequeue evidence, DispatchQueue provenance and unexpected
destination disposal remain enclosing-host obligations. Entry-count bounds do
not replace closure admission. Exceptions retain their source for the caller;
this helper introduces no error-origin classification or production wiring.
The runner still rejects nonempty inboxes before engine invocation. M1 review
and production admission remain pending.

Thirteen rebuilt manual controls independently remove credit/fee separation,
message-key selection, transaction-address binding, creation/emission LT checks,
the remaining-fee ceiling, each entry bound, the version gate, each currency
budget guard, zero-value duplicate rejection and the processing-transaction
reference. Each build succeeds and each test fails on a state/value or rejection
assertion, not an error-string comparison. Restored five-target regression and
standalone-header compilation pass. Substitutions, raw output and source/binary
hashes are in `measurements/uno-v2-final-import-evidence.json`; these controls
were run manually and are not mutation CI or exhaustive guard coverage.

### Joint final-import and allocation reconstruction (M1 in progress)

The allocation materializer now has a shared implementation that can reconstruct
coordinator-addressed final imports together with internal allocations. It
returns accounts, AccountBlocks and InMsgDescr together, only after independently
decoded Native balance rows balance against actual InMsg credits and the decoded
allocation graph. Transaction references in InMsgDescr point to the transactions
actually committed to those private AccountBlocks. Remaining forwarding fees
are collected in Native import accounting, not credited to accounts.

The common transaction schedule includes both message creation and emitted LTs;
checked scheduling rejects overflow. Replay independently reconstructs all three
roots and the end LT. Credits and fee totals are derived caches, so replay returns
the reconstruction rather than adopting a claimant's copies of those caches.
The existing message-free API delegates with a zero inbox bound. The settlement
runner still rejects nonempty inboxes before engine invocation: custody imports,
unexpected-destination disposal, own-queue/DispatchQueue provenance, payouts and
full authenticated queue completeness are not made supported by this helper.
The explicit new API rejects non-coordinator destinations, including zero-value
messages that would otherwise leave the balance equation unchanged.

Tests inspect two actual incoming message records, both modified Native accounts,
the untouched account, AccountBlock transaction hashes, exact balances and fees,
each independent LT source, four replay artifact mutations and stale derived
caches. This is a post-admission, existing-account integration fixture, not a
confidential Deposit authorization test, a production queue test or M1 closure.
The existing input decoder's fixed semantic-validation allowance and the entry's
timestamp policy still need their production admission/Native-ingress audit;
this change does not silently choose new policy values or classify their errors.

Ten successful rebuilds followed by failing tests witness destination exclusion,
both LT sources, actual imported-row credit, each of the four replay artifacts,
reconstruction rather than adoption of caches, and the combined inbox limit.
The last control removes both count checks; it is not evidence that either
individual check alone is indispensable. All five regression targets and the
standalone header compile pass after restoration. Raw output, substitutions and
hashes are archived in `measurements/uno-v2-inbound-allocation-evidence.json`.
These are manual controls, not mutation CI. M1 milestone review remains pending;
no named production consensus-judgement file or error classification changed.

### Independent payout currency-validation budget (M1 prerequisite)

Payout pair construction, private overlay and replay now receive the same
explicit currency-validation budget as allocation settlement. Neither the pair
accounting nor the independently reconstructed Native value-flow rows borrow
`max_acc_state_cells`. The runner no longer narrows that storage setting to an
integer before payout; storage limits still apply to actual Native account
serialization. No fallback policy value is introduced. The enclosing resolved
policy and source-aware admission remain required before production wiring.

The budget is rejected when nonpositive. Tests use a Native-encoded coordinator
account with an actual extra-currency dictionary: a sufficient budget preserves
that currency while debiting only the Native forwarding fee; a positive but
insufficient budget rejects. Both runner branches produce identical artifacts
with the same currency budget and an account-storage setting above the signed
integer range. This is a width/independence probe, not a proposed storage limit.
The tests do not claim that each repeated defensive check is indispensable.

At this prerequisite stage the full coordinator entry was not integrated; the
following unit connects it. Combined allocations/payouts and custody inbound
settlement remain M1 work; scopes still reject the inactive participant formats.

The consensus-boundary review prompted extra overlay/replay fixtures, explicit
zero-load ordering assertions at invalid budgets, a persisted-balance decode,
and two legal storage-limit comparisons with real extra currencies. Review
disposition and limitations are in `uno-v2-payout-budget-review-disposition.md`.
Early rejection preserves ordering but does not itself classify the Status.
Production integration still must supply the resolved policy and attach each
failure to its actual source; test-only entry points cannot settle that gate.

Nine successful rebuilds followed by failing controls and the restored five-target
regression are archived with substitutions and hashes in
`measurements/uno-v2-payout-budget-evidence.json`. They are manual evidence, not
mutation CI. The boundary review is complete for this substitution and its
test repairs; the full M1 milestone review and production integration remain open.

### Full coordinator entry on the payout path (M1 integration)

The settlement runner now passes the complete committed input and effects
through payout materialization and replay. The coordinator is a tag-12 entry
with the full roots; custody remains the restricted tag-11 payout record and
other storage participants at that stage remained tag 10 (the mixed unit below
changes full-entry participants to tag 11). The pair checks both context roots,
their binding hashes, the payout request and custody data. Entry preparation
binds coordinator data/access/context. The profile at that stage excluded
Native inbox and extra allocations before any credit could be overwritten;
the mixed unit below adds allocations.

There are no default context arguments. Low-level tests explicitly select two
null roots for the participant-only primitive; this is not a live batch mode.
The full-context overlay verifies committed writes, every update, supplied old
hashes and every authenticated read, including read-only accounts, under an
explicit read bound. It verifies each serialized descriptor independently,
including its role, exact refs and full context. Replay rebuilds Native roots
with the same explicit profile. Nothing is published or written to CellDb.

Tests cover a third changed participant and a separate read-only participant,
incorrect third-account data, a conflicting supplied old hash, a conflicting
host LT boundary, missing writes and an invalid read-only hash. They also check
the actual coordinator description and full-root replay. Boundary review and
its corrections are recorded in `uno-v2-payout-entry-review-disposition.md`.
Custody imports, disposal, aggregate operation-fee settlement and production
admission/publication remain unfinished M1 work. The next unit removes the
combined allocation/payout limitation of this intermediate stage.

Thirteen rebuilt failing controls cover runner/replay profile propagation,
partial context, inbox exclusion, request/custody/third-account data bindings,
supplied old hashes, the host LT boundary, entry preservation, read-only state
authentication and the two composite hash contracts. Restored five-target
regression and standalone-header compilation pass. Logs, substitutions and
source/binary hashes are in `measurements/uno-v2-payout-entry-evidence.json`.
These are manual controls, not mutation CI or exhaustive guard coverage.

### Mixed internal allocations and priced payout (M1 integration)

Full-entry payout batches now apply the committed allocation graph before
debiting custody principal and coordinator forwarding fees. All other changed
accounts receive restricted allocation participants. Every full-entry non-entry
record uses tag 11, including zero-allocation participants; explicitly null-root
primitive tests retain their old storage-only third-record shape. Production
scope acceptance is unchanged.

The full overlay independently reconstructs Native rows from serialized
accounts, transactions and messages, then checks the effects graph plus exactly
one priced fee-funding edge. Shared endpoints do not deduplicate away either
value. A checked extra verification slot accommodates this host edge without
expanding the engine's transfer allowance. Overflow rejects before state reads.
Pricing still checks old custody funds independently of allocated funds; an
incoming edge cannot enlarge the prior payout authorization envelope.

Tests now cover both role balances at exact funding boundaries and one unit
beyond, third-account incoming and outgoing allocations, mixed replay at the
exact edge limit, four altered replay artifacts, the full-entry third-account
tag, direct pair balances and the previously untested old-custody envelope.
The pair remains a partial primitive: any graph touching another account
requires that account's participant and the complete independent value-flow
check. Conservation is not withdrawal or fee authorization.

The boundary review and dispositions are recorded in
`uno-v2-mixed-payout-review-disposition.md`. Fifteen manual controls were rebuilt
successfully and then failed on value, tag, load-count, required-success or
rejection assertions. The zero-allocation tag control intentionally changes
both construction and its independent tag expectation, isolating the explicit
serialized-tag assertion. Raw results, substitutions and artifact hashes are in
`measurements/uno-v2-mixed-payout-evidence.json`. They are not mutation CI or
exhaustive coverage of every redundant guard.

This removes the allocation/payout combination limitation, not the remaining
M1 gates: nonempty custody/coordinator inbox integration, unexpected-destination
disposal, aggregate operation-fee output, registration, source-aware production
admission, actual collate/validate publication and synchronization remain open.
No production policy value, additional payout authority or retirement rule is
silently selected. Full M1 milestone review remains due.

### Shared Native inbox planning (M1 integration)

`workchain-native-inbox.h` now supplies a common post-admission plan for final
imports: a bounded canonical envelope list, an explicit strictly ordered set of
allowed recipient roles, and a lower LT bound covering the host, message
creation and message emission. It rejects the whole unsupported message set;
it never filters a foreign recipient out. This is not Deposit, return or fee
authorization. The allocation materializer now consumes the same plan for its
schedule and actual final InMsg reconstruction. Its allowed role remains the
coordinator until custody settlement is integrated; the planner itself supports
an explicitly supplied multi-role set.

The count check precedes dictionary traversal. It does not replace full closure
admission or bound the caller's recipient vector. Native message bodies retain
Native TL-B semantics, not the ordinary-only candidate closure restriction.
The executable positive control uses an ordinary referenced body with an opaque
library-cell child. A first attempted fixture used a library cell as the direct
`^Any` root, which Native TL-B correctly rejects; that setup failure is not
counted as a planner defect or a successful red control.

The existing inbox decoder still converts some VM exceptions into legacy Status
errors. This extraction does not solve source-aware production classification,
authenticate queues, choose disposal semantics, or establish a network delivery
deadline. The timestamp policy audit and enclosing production admission remain
open. No named consensus-judgment file or new error category changed in this
unit; review remains due at the M1 milestone under the current review rule.

The initial positive test failed against an unimplemented stub. Fifteen later
controls were each rebuilt successfully and failed independently: host/creation/
emission LT sources, recipient and workchain matching, anycast exclusion, role
set order/uniqueness/nonemptiness/domain, complete message retention, count-check
placement before dictionary loads, Native opaque body compatibility, and both
allocation schedule/import call-site uses. Moving the count check after decode
changed observed child loads from zero to one while still returning an error.
After exact source restoration, all five regression targets and standalone
header compilation pass. Logs, substitutions and source/binary identities are
in `measurements/uno-v2-native-inbox-evidence.json`. These are manual controls,
not a recurring mutation CI gate or completed Native inbox/payout integration.

### Importing participant and remaining inbound settlement work

The restricted import participant reuses entry validation of full input/effects,
the old account, its write/index and data, then stores only its tag-11 binding.
It applies its own Native message credit and internal allocations without an
engine invocation, ordinary phases or outputs. The unique coordinator entry
retains the full roots. The importing pair test reconstructs actual final InMsg
records and serialized account/transaction balances before checking independent
value flow. Boundary review prompted twelve negative input/context/access/budget
fixtures at the import wrapper, a cached direct-input rejection, and three
perturbed import-flow rows. All seventeen manual removal controls rebuilt and
failed; restored five-target regression and standalone header compilation pass.
See `uno-v2-import-participant-review-disposition.md` and
`measurements/uno-v2-import-participant-evidence.json`. These are manual evidence,
not mutation CI, production custody authorization or completed M1 acceptance.

The next integration must cover both coordinator and custody receiving roles
in non-payout materialization, and the same two roles in payout materialization.
Full input admission and the shared inbox LT plan precede transaction creation.
In the payout pair, imported values and the committed allocation graph must be
applied before debiting payout principal and forwarding fees. The separate old
custody authorization envelope must not be enlarged by those imports. Actual
InMsg augmentation, actual outputs and serialized account/transaction balances
must supply independent value flow, and replay must compare the reconstructed
InMsg root as well as accounts, AccountBlocks, output and LT. A participant's
local credit selection never licenses omission of another envelope.

The complete runner's nonempty-inbox restriction remains until every supported
role and the mandatory disposal paths are integrated. Mechanical credit is not
proof of queue provenance, Deposit admission or authenticated bounce matching.
Repeated full-context validation must be included in admission costs. Retirement
does not remove the descriptor, parameter 84 or custody; this work makes no new
claim about message termination or a finite network delivery deadline.

### Dual receiving-role allocation materialization (M1 integration)

The non-payout materializer and replay now take both coordinator and custody
explicitly, require distinct roles, and canonicalize the two-element receiving
set before planning the complete inbox. Only these two accounts use full-context
credit preparation. Other changed accounts use allocation-only records even if
they appear in the write set; membership in that set is not permission to
receive Native messages. The message-free wrapper still passes a zero inbox
bound and the complete runner still refuses nonempty inboxes until mandatory
disposal and payout integration are delivered.

The test carries three actual envelopes: two for the coordinator, one for
custody. It checks both credited balances, the complete Native augmentation,
each InMsg's actual processing transaction, both participant bindings and the
unique full entry, last-transaction links, replay roots, and an untouched
account. An unsupported-recipient witness includes that third account in the
real write set and imports zero principal. Thus missing transaction evidence
and independent balance checks cannot mask removal of the receiving-role gate.
Distinct-role rejection is tested with a coordinator-only inbox so foreign
message rejection cannot mask it either.

The pre-change materializer rejected the positive custody import. After
implementation the positive fixture passes. Nine rebuilt removal controls fail:
receiving set, custody preparation and independent credit, actual InMsg
processing reference, distinct roles, an unsupported written recipient,
replayed InMsg root, replayed custody role and canonical role order. The role
alias control also removes the planner's redundant duplicate rejection by
deduplicating its input. Restored five-target regression and standalone header
compilation pass. Exact substitutions, logs and hashes are archived in
`measurements/uno-v2-dual-inbound-allocation-evidence.json`; these are manual
controls, not recurring mutation CI. This unit adds neither a new classification nor a
change to a named live consensus-judgment file; independent review remains due
at the M1 milestone. Shared decoder source attribution, aggregate traversal
admission, authenticated bounce matching and full live publication remain open.

### Inbound allocations combined with payout (M1, internal materializer)

The pair prices against old custody and checks its LT additions before creating
private transactions. With full input/effects it then prepares both receiving
roles, including own imports and committed internal allocations, before
debiting payout principal and forwarding fees. Imported or allocated value
cannot enlarge the separately checked old-custody payout envelope. Null-context
primitive callers retain explicit zero-inbox materialization.

The enclosing payout materializer now accepts an explicit inbox count bound,
plans only coordinator/custody recipients before old-state reads, and includes
message creation/emission LTs in the common schedule. Actual serialized
transactions supply final InMsg references. Their Native augmentation supplies
independent account credits before value-flow verification. Replay compares
the rebuilt InMsg root in addition to accounts, AccountBlocks, payout and end
LT. Import totals are returned as derived artifacts, not trusted claimed caches.
The private account commit result is also checked rather than ignored.

The old pair rejected the new importing positive fixture. The implemented
pair/overlay tests pass, including two imported balances, the independent old
principal boundary, a later inbound LT schedule, actual processing references,
explicit count limits and five changed replay artifacts. Boundary review has
completed; disposition is in `uno-v2-inbound-payout-review-disposition.md`.
An added outgoing-allocation pair tests exactly sufficient custody funding
and a one-unit shortfall after imports. One rebuilt control independently
zeros the Native-derived import credit while preserving credited account
state: the legitimate overlay then fails its value-flow check (exit 1).
The unsupported-recipient fixture includes an actual written account and zero
principal so other invariants do not mask the role check. Ten rebuilt controls
turn red: independent import credit, unsupported written recipient, inbound LT
schedule, the composite count limit, all five replay artifacts, and unfunded
principal with the helper's repeated conservation check also removed. The
early-count-only control survives the downstream repeated bound; no independent
zero-state-load overlay witness is claimed. Raw logs, exact substitutions and
hashes are in `measurements/uno-v2-inbound-payout-evidence.json`; these are manual
controls, not recurring CI. This is not M1 acceptance. The complete runner still rejects nonempty inboxes;
disposal, authenticated return/withdrawal authorization, aggregate operation-fee
output, production classification/publication and synchronization remain open.

### Shared Native bounce body encoding (M1, shared encoding component)

The ordinary bounce caller now delegates body encoding to a stateless helper
that writes only its caller-owned CellBuilder. Format and phase selection stay
in the ordinary caller; address rewriting, pricing, debit and queue publication
are unchanged. This is a prerequisite for sharing bounce construction with
batch disposal, not a second fee algorithm and not completed disposal.

The new test directly decodes legacy prefix/truncation, rich body with and
without references, original value/LT/time and diagnostics. Twenty-four actual
ordinary calls cover flags 0/1/2/3, legacy lengths 0/256 and three phase
outcomes. The reviewed fixture gap is fixed: action result 7 differs from
compute exit 42. Five rebuilt controls fail for source selection, full-body
refs, original LT, truncation and swapped compute counters. A separate
capacity fixture first exposed an ignored prefix-write result; the throwing
store now propagates CellCreateError. The initial catch named the wrong class
and was corrected against runtime and ensure_throw, not hidden from evidence.
Explicit price initialization also fixes an earlier fixture failure, which is
not mutation evidence. Review disposition is in
`uno-v2-native-bounce-body-review-disposition.md`; logs and hashes are in
`measurements/uno-v2-native-bounce-body-evidence.json`. This remains an encoding
component, not full pricing, disposal or production activation.

### Shared Native bounce storage measurement (M1, shared component)

A stateless wrapper now measures the Native bounce pricing closure with one
CellStorageStat, preserving deduplication across optional currency and body
roots. An absent currency root explicitly contributes zero; actual traversal
errors are returned rather than used as partial sizes. The ordinary caller
checks the result before calculating fees or debiting balances. Source
failures are not reclassified. The inherited NoVm walker can fail fatally on
unavailable descendants: future batch callers must authenticate, admit and
fully materialize/validate the closure first, not rely on root is_loaded().
The legacy walker and fee arithmetic are unchanged;
this helper is not resource admission or a source-classification boundary.

Direct tests cover separate/shared currency roots, optional absence and an
actual null body root. Existing ordinary bounce tests now assert exact pricing
cells/bits for legacy and both rich modes. Twelve additional actual Native
calls cover the version/currency switch and exact-funds/nofunds pricing.
Six rebuilt controls fail for currency inclusion, optional absence, shared-root
deduplication, actual body-root failure, caller switch and caller pricing input.
These are manual controls, not recurring mutation CI. Review disposition is in
`uno-v2-native-bounce-storage-review-disposition.md`; raw evidence is in
`measurements/uno-v2-native-bounce-storage-evidence.json`. The defensive phase
reset has no independently demonstrated canonical Native wire trigger.
This is not completed disposal, live admission or M1 acceptance.

### Bounce value isolation (M1, post-selection accounting)

The read-only bounce accounting primitive derives returned value, in-flight
forwarding value and collected fees from an already selected affordable bounce.
Only the imported message funds the return; the processing account's old
balance is unchanged. Extra currencies remain in the returned value. Checked
CurrencyCollection operations and the independent per-account value-flow
equation close the arithmetic before any state write.

This is not a second price algorithm: callers must obtain fees from the shared
Native price rules. It neither chooses the three-way disposal branch nor
authenticates an input or authorizes an address exception. Its Result cannot
be converted into permission to credit the unexpected bucket. No production
caller or new error category is installed. It is queued for the M1 milestone
review; any later consensus-boundary wiring requires immediate review.

The actual test preserves an extra-currency amount of five, returns 23 from
an imported 123 with a total fee of 100, and independently exports 98 including
the remaining forwarding fee. Exact-funds, zero-fee and insufficient-funds
cases are included. Three rebuilt mutations (return debit, remaining forwarding
fee, old-balance preservation) fail. Restored workchain-block CTest passes.
Raw evidence: `measurements/uno-v2-bounce-accounting-evidence.json`; these manual
controls do not claim isolated coverage of every guard or recurring mutation CI.

### Shared Native bounce message encoding (M1, shared component)

The ordinary caller delegates final message serialization to the shared builder.
It retains source/destination rewriting, masking of extra_flags, fee debits and
LT allocation. The builder fixes bounced=true/bounce=false/IHR-disabled, encodes
the admitted CurrencyCollection and remaining forwarding fee, and chooses the
same inline/reference body form. Construction failure is never nofunds.

This is not the assembled multi-account disposal path: address exceptions,
admission, fee affordability and queue publication remain caller obligations.
The direct decoder test covers both body forms and all header fields. Boundary
review exposed two surviving mutations in the original coarse sizes. Eight
revised vectors include adjacent 350/351-bit bodies and extra-currency reference
pressure. The pre-existing ordinary collator exception gap is recorded, not
claimed repaired by this extraction. Review disposition:
`uno-v2-native-bounce-message-review-disposition.md`. This is still not complete
multi-account disposal or production activation.

### Shared Native destination rewrite (M1, shared routing component)

The ordinary Transaction wrapper delegates to the same routing algorithm with
its account address as the explicit anycast prefix source. Batch reconstruction
can reuse it without constructing a mutable ordinary Transaction or copying
the unknown-workchain, accept_msgs, address-length, ingress and normalization
rules. The resolved workchain table and complete admitted address closures are
preconditions; this bool API is not a local-data/configuration error classifier.

Direct tests cover addr_var normalization, masterchain classification, unknown
workchains, disabled receiving, anycast prefix replacement and ingress checks.
The existing actual send test now explicitly initializes both price records;
no default production price is installed. Review found a masked anycast test;
the matching-address negative now isolates that guard. Rebuilt controls for
that guard, allow_anycast and sender prefix all fail. Typed resolved configuration
remains a prerequisite for any new batch caller, not enforced by this bool API.
See `uno-v2-native-destination-review-disposition.md` and
`measurements/uno-v2-native-destination-evidence.json` (manual controls, not CI).
The two-address V2 ingress policy and full disposal are not
implemented merely by exposing this existing single-address policy function.

### Composed Native disposal planning (M1, reviewed component)

A post-admission planner now composes routing, body construction, closure
measurement, Native bigint pricing, checked value-flow accounting and
outgoing message encoding. Already-bounced, bounce-disabled, protocol-unreachable
and insufficient-imported-value paths credit the unexpected balance. Errors and
exceptions do not select credit. The resolved workchain table is supplied by
reference and rebound locally; no nullable cfg pointer is used for routing.

The message's effective final destination is checked against the supplied
workchain/address. The processing account intentionally differs; its authorized
role must be authenticated by the enclosing batch. The result names the branch
explicitly and retains the original message for attribution. Source address,
diagnostics and anycast policy have explicit, non-default profile inputs; the
ordinary-comparison fixture does not select a production profile. A constructor
requires all three profile arguments; empty aggregate construction is disallowed.

This is still not live disposal: legitimate-entry classification,
complete closure materialization/admission,
typed failure provenance, bucket counters and InMsg/OutMsg publication remain
outer obligations, including versioned InMsg/OutMsg address exceptions. The
planner checks its constructed accounting row; this is not independent replay
of Native records. The comparison fixture independently executes an ordinary
Native transaction and compares the complete bounce hash, balance and fees.
The new bigint serializer retains the full 120-bit Tomis wire fee; the existing
ordinary uint64 call remains unchanged. Large measured prices are not truncated
or turned into local faults merely for exceeding uint64. An unaffordable but
representable price selects credit using the actual imported value.

Tests exercise bounce amounts and all four economic credit reasons, invalid
configuration not becoming credit, and compare the returned message hash,
balance and fees with an actual ordinary Native bounce. This measures
composition, not independent implementations of the shared encoding helpers.
Follow-up review fixes include direct diagnostic/anycast/reference-body witnesses
and a stale-but-valid configuration witness that fails without null-pointer UB.
Thirteen rebuilt runtime mutations fail in the named test; a separate removed-
constructor control fails at the intended compile-time assertion. Restored
five-target CTest and standalone-header compilation pass. These are manually
run controls, not recurring mutation CI or exhaustive branch coverage. Evidence:
`measurements/uno-v2-native-disposal-evidence.json`; disposition:
`uno-v2-native-disposal-review-disposition.md`. M1 acceptance remains open.

### Detached Native closure acquisition (M1, boundary reviewed)

NativeCellMaterializer constructs an owned DataCell DAG before Native parsing
or legacy NoVm pricing. It preserves encoded special cells and all significant
hashes/depths, never executes library references, and never replaces an encoded
pruned branch with an imagined complete subtree. Virtualized acquisition,
unavailable data, mismatched metadata and builder/allocation failures are local
failures. Resource exhaustion has a separate NativeClosureLimit result; it is
not authorization to discard a queued message or declare its contents invalid.

The result has a private constructor and contains no lazy descendants. A fresh
call is a new acquisition attempt; no partial result is published on failure.
These are physical acquisition counters, not V2's final logical-root definition.
Production admission must allocate a budget from authenticated policy, account
for the shared candidate/inbox/witness union and derived wrappers, and establish
queue provenance and completeness separately. Zero limits permit empty input.
No configuration fields, defaults, production gate or message profile are
installed by this component. The post-admission multi-account runner now accepts
owned Native input, checks allowed destinations before invoking the engine, and
passes the inbound bound through allocation and payout settlement. This is not
integration into the live collator or validator. Misdelivery disposal, complete
admission and production version gates remain open.

Manual rebuilt controls and their source snapshots are recorded in
`measurements/uno-v2-native-materialization-evidence.json`. All 22 closure
controls failed as intended (21 runtime controls and one constructor compile
control); restoration passed all nine admission tests. The five runner controls
precede the final closure exception-test additions; their snapshots are recorded
separately. These controls are not recurring mutation CI or M1 acceptance.

Retirement remains migration without removal of ConfigParam 84 entries, the
workchain descriptor or custody. Economic settlement does not establish that no
Native message still needs the old destination. Complete workchain removal needs
a separately authorized message-termination design; a failed bounce constructor
must not be interpreted as successful degraded delivery.

### Unified account settlement replay (M1, not live)

`workchain-account-replay.h` reconstructs the input from the separately supplied
admitted context and checks the claimed input before acquiring old accounts or
calling the engine. It then invokes the full settlement runner once in this
independent validation context, rebuilding effects, accounts, AccountBlocks,
InMsg evidence, end LT and the optional outgoing message. Each artifact is
compared, not merely a batch digest. Returned import totals and account credits
are reconstructed caches, never adopted from the claim.

This remains post-admission code: complete source authentication, claimed-cell
materialization, physical/semantic budgets and source-aware error containment
belong to the enclosing host. The preliminary input reconstruction and the
runner's reconstruction are both work that admission must cover. It neither
publishes state nor enables the multi-account consensus version. Missing
misdelivery and operation-fee settlement paths are not made supported by replay.

The positive fixture first failed against an unimplemented replay stub, then
passed for payout and no-payout with a two-role inbox. Ten rebuilt removal
controls fail independently, covering input, effects, accounts, AccountBlocks,
InMsg, end LT, message presence/content, reconstructed caches and missing claims.
The restored positive passes. Raw evidence and the exact replay source are in
`measurements/uno-v2-account-replay-evidence.json`. These are manual controls,
not recurring mutation CI. This new replay integration awaits milestone review;
the preceding materialization boundary review does not cover this later file.
Final checkpoint regression passes all five related CTest targets and standalone
compilation of both new headers. Commands and final source/binary identities:
`measurements/uno-v2-account-replay-regression.json`.

### Candidate acquisition provenance (F11, boundary reviewed)

The candidate factory now classifies a local virtualized view as
`LocalUnavailable::CellIdentity`, matching Native acquisition. An encoded,
profile-forbidden special constructor remains `CandidateInvalid::ForbiddenSpecial`.
These are different representations and different provenance, not two verdicts
on the same wire constructor. The unused prototype `VirtualizedInput` rejection
enumerator is removed; no serialized policy, transaction or ABI changes.

The test explicitly deserializes a nonzero-level pruned BoC to isolate this
boundary from an earlier decoder profile gate. It then creates local views at
the root and below an ordinary root, checking local classification, zero loader
calls and the retained first outcome after the loader changes. On the original
implementation it fails at the local-variant assertion; after the change all ten
admission tests pass. Manual evidence:
`measurements/uno-v2-candidate-provenance-evidence.json`. No claim is made that
this narrow change closes every loaded-metadata, exception or production
admission integration obligation. Immediate classification review confirmed the
decision (`~/memo/reviews/uno-v2-candidate-provenance-review.txt`). Review fixes
clarify the synthetic descendant fixture, remove nondiscriminating retention
assertions and correct the older admission contract. The load counter remains
the independent retention witness. The legacy preflight counter still has plain
Status errors and is explicitly prohibited as a production verdict adapter.
Loaded-metadata validation beyond this view check remains a separate obligation.
After review corrections, three rebuilt controls separately change local views
to candidate rejection, encoded special cells to local failure, and remove the
outcome cache. All fail; restoration passes both related CTest targets (2.76 s).
Exact source, substitutions, raw logs and final hashes:
`measurements/uno-v2-candidate-provenance-controls.json`. These are manual
controls, not recurring mutation CI or completed production admission evidence.

### Candidate loaded identity (boundary reviewed)

Candidate acquisition now checks full significant-level hash/depth identity on
fresh loads and cache hits, and checks loaded virtualization/effective level
before interpreting the candidate's encoded profile. A local metadata mismatch
cannot be converted into either proof of absence or a forbidden-special verdict.
`VmFatal` and `std::length_error` from acquisition are contained as existing local
execution/allocation categories. No new wire error codes or production callers
are introduced. This does not authenticate old shard state or finish aggregate
candidate/inbox/witness admission.

Six separate tests failed on the unchanged implementation: fresh and cached
depth corruption, effective-level mismatch, loaded-view traversal ordering, and
the two exception types. After implementation all sixteen admission tests pass.
The ordering witness observes descendant work, not rejection text. Faulty loader
fixtures are local acquisition models, not alleged serializable peer inputs.
Evidence: `measurements/uno-v2-candidate-identity-evidence.json`. Immediate
error-boundary review confirmed the changes
(`~/memo/reviews/uno-v2-candidate-identity-review.txt`). Test comments now
identify the synthetic masked-loader shape and the query counter that isolates
traversal ordering. The finish-path hash comparison retains its documented
ordinary-only, level-zero induction. As a review follow-up, rebuilding now uses
`finalize_novm`: the ambient-VM test first observed two create callbacks on the
old path, rather than assuming verification was isolated. Existing exception
clauses not exercised by these new candidate tests are not claimed as newly
mutation-covered. Seven rebuilt controls independently remove fresh/cache
identity, effective-level, loaded-view, the two new exception clauses, and
ambient-VM isolation. All fail; restoration passes both related CTest targets
(2.86 s). The admission binary now has seventeen tests. Exact source,
substitutions, raw logs and final hashes:
`measurements/uno-v2-candidate-identity-controls.json`. Manual controls remain
distinct from recurring mutation CI; M1 production integration is still open.

### Routed final-import records (M1, not live)

The explicit routed constructor shares Native import encoding, checked
CurrencyCollection arithmetic and dictionary augmentation with the unchanged
strict constructor. Resolved custody arrivals retain their own transaction;
other arrivals use the resolved coordinator. The original destination and
envelope remain unchanged. The processing account's actual serialized identity
must match the derived role, not merely a key in a supplied map.

This is the common InMsg record shape needed by both disposal outcomes. It
does not decide bounce versus unexpected credit, settle bucket data, construct
OutMsg evidence, or enable a Native semantic-validation exception. The mixed
fixture uses real transaction encodings but does not claim those transactions
already settled its changed inbox. Full disposal settlement and exact replay
integration remain required. Gross imported credits are not backing entries.
No retirement behavior or configuration gate changes here.

The unimplemented constructor first failed at the positive-result assertion.
Subsequent manual controls and regression evidence are recorded in
`measurements/uno-v2-routed-import-evidence.json`; scope and arithmetic are in
`uno-v2-routed-final-imports.md`. These controls are not recurring mutation CI.
This helper-only unit awaits M1 milestone review and is not milestone closure.

### Coordinator disposal transaction (M1, boundary reviewed)

The explicit disposal entry now shares the strict entry's full input/effects,
read/write, ordinal and data checks, then reconstructs foreign final-import
disposal through the Native planner. Own and custody entries are not consumed
twice. The transaction retains unexpected value, applies internal allocations,
serializes its actual balance and fees, and seals all bounce messages with
checked LTs. Existing strict entry and importing-participant behavior is
unchanged. The work still does not publish a queue or accept a live address
exception.

The new two-account fixture is stronger than the preceding record-shape
fixture: the transactions actually prepare against this same committed inbox.
It checks value flow from decoded account balances, serialized out-messages and
fees, and reconstructed InMsg credits. It also exercises an unaffordable bounce
as economic credit with a zero-output budget, one-bounce LT overflow without a
later message masking it, context limits and sealed-output mutation. The
unimplemented factory first failed the success assertion after a build.

Immediate consensus-boundary review ran both the new test and all 82 block
tests. Follow-up adds five isolated custody-context witnesses and a transfer
whose funding depends on retained credit. The latter pins Native cash ordering,
not bucket-spend authorization: preservation and authorized movement of that
liability still belong to the engine. An ordinary Status is not a voting
classification; source-aware configuration and exception adaptation remain
production prerequisites. Review disposition and scope:
`uno-v2-disposal-entry-review-disposition.md`. No M1 completion is claimed.

### Disposal allocation overlay (M1 integration, milestone review pending)

The reviewed disposal entry now feeds the private multi-account overlay. The
coordinator is prepared once before the output-aware LT schedule is finalized;
participants, actual exported value, AccountBlocks and routed final imports are
then reconstructed together. Replay compares every returned root and the end LT,
and returns reconstructed output caches rather than caller-provided caches.
The old strict entry remains strict; the explicit disposal entry requires an
unsplit shard. A third untouched account and a later insolvent participant are
included in the integration fixture.

Ten rebuilt manual removal controls turned red; restored five-test CTest
regression and standalone header compilation passed. Scope and remaining Native
queue/metadata/actual-source FIFO obligations are in
`uno-v2-disposal-allocation-overlay.md`; raw evidence and substitutions are in
`measurements/uno-v2-disposal-overlay-evidence.json`. No live queue publication,
validator address exception or M1 completion is claimed.

### Disposal runner and replay (M1 integration, milestone review pending)

The explicit runner now carries all materialized Native final imports through
one account-engine invocation into the disposal overlay. Independent replay
checks the full input before its own single invocation and reconstructs the
Native roots and derived export caches. The strict existing runner is unchanged.
Unsplit, distinct-role and pricing consistency failures occur before engine
execution. These structural checks do not authenticate configuration.

Ten rebuilt controls failed, including zero-call witnesses for the early checks.
An additional positive payout regression exposed an unnecessarily broad initial
guard; removing it preserves the existing no-foreign-input payout path. Combined
custody payout and coordinator disposal remains the next settlement integration
step, before live queue/validator activation. No input filtering is introduced.
Restored five-test CTest regression and standalone header compilation passed.
See `uno-v2-disposal-runner.md` and
`measurements/uno-v2-disposal-runner-evidence.json`. M1 remains incomplete.

### Joint payout/disposal pair (M1, boundary reviewed)

The private payout pair can now prepare coordinator disposal and custody payout
together, retaining disposal fees/messages while charging payout principal and
forwarding against their separate accounts. The resolved output count is
batch-total and includes custody's message. Pricing and routing tables must come
from the same resolved references. This is not authentication by pointer identity.

Boundary review findings and disagreements are recorded in
`uno-v2-joint-pair-review-disposition.md`. Follow-up added table/context witnesses
and a complete value-flow check decoded from serialized Native artifacts.
Eight rebuilt controls turned red; restored production validator compilation,
five-test CTest regression and standalone header compilation passed.
The next step is integrating the pair into the full write-set overlay with
multi-emitter scheduling and Native queue reconstruction. The old payout overlay
still accepts only its existing single-emitter shape; no mixed-batch publication
or M1 completion is claimed.
