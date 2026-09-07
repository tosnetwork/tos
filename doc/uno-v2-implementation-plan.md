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
