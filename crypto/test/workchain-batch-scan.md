# Private I13a scan mechanism

The scanner uses the existing producer's `get_hash()`, an explicit
level check, and a required `WorkchainBatchScanSource` enum without a default.
An encoded pruned DataCell has no marker for delivered versus
locally derived representation. Neither level nor is_virtualized() supplies it.

`ReceivedCandidate` means the representation received unchanged in candidate
block bytes, NOT merely data logically belonging to a candidate. `AcquiredView`
means a local storage or locally virtualized/pruned view, including views of
candidate content. The same pruned cell is invalid in the former and unavailable
in the latter. Callers must know how their representation was obtained.

Repository evidence (not an assumption about the protocol):
`ValidateQuery::unpack_block_candidate` deserializes `block_candidate.data`
directly into `block_root_` (validate-query.cpp:478-486), checks its level is zero
(:493), and `unpack_block_data` obtains `BlockExtra.account_blocks` from that root
(:2897-2918). That AccountBlocks path does not virtualize a proof. Separately,
`collated_data` explicitly accepts and virtualizes MerkleProofs (:666-684) and
AccountStorageDictProof (:700-715). Thus it would be FALSE to claim all candidate
auxiliary data is complete. A future proof-backed AccountBlocks caller must use
`AcquiredView`; the raw-block path is not a blanket candidate-origin guarantee.

The precise ordinary-only guarantee is in workchain-host-input.h: roots are
candidate, declarations, finality, then inbox; `Visit.ordinary` is seeded with
`i < 2`, inherited by descendants, and `visit.ordinary && data->is_special()`
is rejected. Separate seen-map state prevents sharing with Native roots from
bypassing that check. Thus candidate/declaration closures are ordinary-only;
finality/inbox and therefore the entire input wrapper have no such guarantee.
An ordinary parent itself may have nonzero level through a pruned descendant.

The root cells themselves have a narrower construction guarantee: successful
`BatchInputAdmissionSession` builds the input wrapper with `finalize_novm()`
(workchain-host-input.h:188-195), and `encode_workchain_account_effects` builds
the effects root with ordinary `CellBuilder::finalize()`
(workchain-account-effects.h:72-81). Neither is an ordinary-closure guarantee.
The effects encoder retains update data, receipts, events and payout references;
settlement's `charge_closure` uses `NativeStateReadMeter::load_encoded`, not
`load_ordinary`. Its documented contract admits encoded special cells, including
stored pruning, and rejects virtual missing content. Therefore neither the full
input nor full effects closure is guaranteed level zero by these constructors.
Also, a candidate's claimed entry references are not trusted to have passed those
constructors. The scanner loads both roots (rejecting forbidden special roots)
and explicitly checks level zero before comparing commitments. These checks
remain necessary even with the local ordinary-root construction invariant.

This is not live validation, activation, or an I13a acceptance claim. The caller
must select the wc=2 AccountBlocks and pass the resolved authenticated policy.
No collator or validator `.cpp` is changed by this mechanism.

## Identity and count

The existing `UnoV2HostRecord` supplies `(input_hash, effects_hash)` for all
three restricted descriptions. The entry additionally carries input and effects
references; their representation hashes must equal that pair. Storage and
settlement participants carry the same binding record, without those references.
`account_id` must equal the AccountBlock and Transaction address. `effect_index`
is a position in the canonical write set, not part of the batch identity; its
agreement with independently reconstructed effects remains I13c's obligation.

The scanner counts distinct pairs encountered in actual Transaction descriptions.
Counters expose observed progress on incomplete scans with `scan_complete=false`;
only a completed traversal may compare its count with the claim.
The claimed count is used only in the final comparison, never to allocate memory,
choose a traversal length, or seed the result. After a complete scan the count
must agree, there must be one distinct identity, and there must be one entry.
Only acceptance exposes the verified identity; partial or rejected scans do not.
The count comparison precedes uniqueness: two identities with claimed count two
is rejected specifically for multiplicity, not for a dishonest count.

## Bound and exclusions

Under the restricted §9.2 shape, every AccountBlock is a write participant and
contains one restricted transaction (including the coordinator entry). Thus the
resolved `resources.input.max_writes` also bounds these AccountBlocks. This is
not a general bound for ordinary or mixed-family blocks. There is no independent
local integer override and no new wire budget. Live integration must establish
the caller's workchain/profile selection before applying this mechanism.

Traversal decodes loaded Native HashmapAug labels, left then right, without a
pre-collected vector or recursively validating payload closures. A 256-bit
account path and a 64-bit transaction path decrease structurally at every fork.
Even shared subtrees are bounded by logical leaves visited: work is
O((max_writes + 1) * (256 + 64)); stored identities are O(max_writes), plus at
most 257 + 65 active dictionary frames. The account limit is checked before
decoding the over-limit account or allocating an identity-set node. Transient
cell loading and bounded traversal frames are not claimed to allocate zero.

This is not full Transaction, input/effects, augmentation-sum, fee, role, or
write-set validation. Test input/effects closures are synthetic hash payloads,
not executable batch envelopes. The tests construct actual Native transaction
and augmented AccountBlock framing, but do not claim valid complete candidates.
The legacy `trans_workchain_batch_v2` belongs to the singleton BlockTransition
family, not this restricted multi-account scanner. Its wire name is not an
admission profile number. Live family selection must retain that existing path;
this mechanism is not a replacement decoder for all supported profiles.

## Classification

Known malformed loaded structure, inconsistent commitments/addresses, account
bound violations, and completed count/identity violations are CandidateInvalid.
Missing acquisition and loader failures are LocalUnavailable. Pruned cells,
virtualization failures and nonzero entry-root levels use the explicit
representation source: ReceivedCandidate yields CandidateInvalid with
ForbiddenPrunedRepresentation; AcquiredView yields LocalUnavailable with
MissingContent. Neither falls through to EntryCommitment. A fully
available forbidden exotic cell is malformed, not missing data. Only cell loading
is inside the VM exception boundary; parsing loaded candidate bits is outside it.
Allocation failure is separate from the authenticated account-bound result.
Entry input/effects root cells must be loadable and level zero before comparing
`get_hash()` with their producer's commitments. On level-zero cells it equals
`get_hash(0)`; this does not justify using different accessors on the two sides.
This does not force their entire closures to be loaded.

For the current raw-block validator path, the earlier block-root level check and
ordinary ancestor chain already exclude a nonzero entry-root level. The scanner's
own check is defense in depth there, and directly exercised by the private
unadmitted representations; it also protects future acquired-view callers. The
header's admission-closure example explains why the constructors alone are not
a general level-zero guarantee, not a claim that this raw-block precheck is absent.
Level zero does not prove a wholly unpruned closure: embedded Merkle objects can
shift level masks. Closure validation remains outside this scan's scope.

The producer accessor is deliberately retained. Once the level guard succeeds,
a black-box test cannot distinguish get_hash() from get_hash(0): they are equal
by construction. Removing the level guard is independently observable as the
wrong typed reason; removing it AND changing the accessor can incorrectly accept
a pruned-descendant input. No claim is made that the accessor alone has a
behavioral mutation control. The ordinary-root positive check records the
equivalence on the admitted comparison domain, not permission to change producer
commitments or mix accessors in future representations.

An unavailable later branch cannot be hidden by accepting the first identity.
No classification assertion depends on logs, an exit code alone, or a generic
local failure code: the C++ tests compare typed disposition and reason.

## Running

The opt-in `workchain-batch-scan.cmake` registers a bounded CTest driver; the
private aggregate and manual-only workflow include it as the fifth check.
Ordinary full regression does not include the private I13 harnesses. The driver
checks selected source/header paths and completion, but is not a full dependency
closure or build-freshness attestation; build the named target explicitly first.
