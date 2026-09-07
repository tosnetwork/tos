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
