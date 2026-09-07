# Confidential workchain V2 implementation

Scope: implement the V2 specification in `/home/tomi/memo/TOS_UNO_PRIVACY_WORKCHAIN_V2.md`, with milestone review and corrections before claiming completion. This plan records implementation evidence, not deployment approval. Amounts are confidential; counterparties and transfer relationships are public.

## Authority and current decisions

The owner now delegates necessary design decisions to the implementer. Decisions must be explicit, derived from conservation, deterministic execution and bounded resources, and must not be hidden local defaults. Real-value deployment and irreversible external operations remain separate from coding.

Specification baseline: memo `274258e5`. Late returns fund the slot fee from their actual carried value; the coordinator does not subsidize them. Process the authenticated inbox against open withdrawals before closing remaining expired records. Rich bounce messages return original logical time for scoped matching. Retirement does not remove the workchain configuration or custody while the native message lifecycle remains unresolved.

`created_lt` must be determined before committing effects. Allocate one transaction per affected account, with a common start strictly beyond authenticated host/inbox timing and every affected account's previous transaction end. Within each account, assign outgoing message times in canonical order. The native wrapper must reproduce those values, never fill an uncommitted identity into state afterward.

The custody exception remains the specification's single outgoing payout per batch until that permission is explicitly revised; an amount exposure limit alone is not permission to emit additional messages. Existing obligations retain the settlement period and fee reservation committed when admitted; configuration changes govern new obligations, not retrospective reduction of existing reservations. These are implementation decisions to include in the next design review, not claims of completed host enforcement.

## Milestones and evidence

| Stage | Required outcome | Status |
|---|---|---|
| M0 | Consistent design decisions, configuration semantics and review | Existing design/review; implementation decisions tracked here. Production numeric calibration is not proven by research measurements. |
| M1 | Multi-account wire, one logical execution, exact account coverage, native settlement, version gates, independent replay and synchronization | In progress. Participant LT allocator implemented and tested in isolation; no consensus integration yet. |
| M2 | Complete deterministic relations, system encryption, prover/verifier, ABI and supply-chain gates | Existing kernel work is partial evidence; not marked complete. |
| M3 | Registered accounts, real candidate source, SEND/COLLECT and pending lifecycle | Not accepted. |
| M4 | Native deposits and fee isolation | Not accepted. |
| M5 | Withdrawals, matched/late returns, reservations and settlement ordering | Not accepted. |
| M6 | Capacity, minimum hardware, state acquisition, lifecycle and migration | Not accepted. |
| M7 | External review and restricted public testnet evidence | Not accepted; no public deployment performed. |
| M8 | Real-value activation gates and operational rehearsal | Not authorized by a coding request. |

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

Actual balance allocation is the next integration step. Until it is wired, the
existing settlement runner explicitly rejects nonempty Native transfers after
encoding rather than silently producing a storage/payout result that ignores
them. No new fee model or production limit is selected here; no consensus
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

The whole-batch runner still rejects nonempty imports and internal transfers.
The next integration work is the matching restricted participant records and
private overlay materialization with independently reconstructed value flow;
only then can the runner consume these effects instead of rejecting them.
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
only current barrier: the runner rejects these effects and both execution
scopes reject the record tag. All those independent barriers remain intact.

Explicit entry/validation bounds do not replace complete closure accounting,
aggregate work admission or the activation gate before execution. Those must be
provided by the real host before its first production call. No message-count
policy or account-currency policy is inferred from these API arguments. The
per-entry scan is also not a plan to rescan the whole transfer graph for every
participant; batch-wide materialization must share checked accounting work.
