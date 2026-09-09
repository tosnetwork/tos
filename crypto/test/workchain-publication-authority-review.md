# Review of the proposed consensus authority boundary

**The distinction between authoritative content and local availability is
supported by the inspected code. The literal statements that an incompletely
stored block is not externally served, and that N3 carries only candidates/proofs,
are not true in general. Neither observation establishes promotion of an
unaccepted block into authoritative state.** No concrete such promotion was
identified in the paths reviewed here. This is not an exhaustive proof that no
consumer can make that mistake.

This read-only review evaluates propositions 2 and 3 of the proposed D47 rewrite.
It does not approve a new definition, implement publication, or claim I13e
acceptance. Source commits, blob hashes and complete numbered excerpts are in
`doc/measurements/uno-m1-publication-authority-review.json` and its directory.
The previously drafted publication input files are excluded.

## What the preceding visibility review did and did not prove

The eight transition roles in `workchain-publication-visibility-review.md` remain
real. They show that data acquisition, in-memory processing and persistence do
not share one store transition. They do **not** show that partially persisted
content becomes independently authoritative. The inference from those roles to
"I13e necessarily requires storage-layer atomicity work" is not established once
D47's authority boundary is questioned. This review qualifies that inference;
it does not withdraw the observed ordering or rewrite the historical evidence.

## Proposition 2: partial storage and authoritative content

| Claim or path | Source result | What follows |
|---|---|---|
| A block commits to its serialized content | `collator.cpp:6404–6418,6458–6486` binds AccountBlocks/descriptors in BlockExtra and value flow/state update in Block. `impl/block.cpp:86–103` checks actual block root and file hashes against BlockIdExt | A different serialized component cannot be silently substituted under the same checked block identity, within the content-hash model. This is integrity binding, not an independent consensus certificate |
| State remains bound to the block | `ValidateQuery::compute_next_state`, `validate-query.cpp:1489–1505`, applies the block update and compares the resulting state hash. Proof readers bind account/queue content to the selected block/state | Missing locally stored content can cause failure/unavailability without authorizing a different partial state |
| Finality can precede local store availability | `simplex/state-resolver.cpp:292–319` tests `is_finalized`, attempts `ChainState::from_manager`, and on timeout/notready reconstructs the finalized candidate from validated candidate data | Concrete evidence that the implementation distinguishes consensus finalization from local data/index readiness. Finalization is not defined by P4 completion |
| A not-yet-accepted candidate can become locally stored and externally queryable | `manager.cpp:569–606` handles candidate broadcasts, stores data and requests state under `nonfinal_ls_queries_enabled`. `get_block_handle_for_litequery` (`3643–3654`) permits a handle without the archive condition when that option is enabled | The literal "it has not offered that block externally" explanation is too strong. Availability before acceptance is an intentional path, not necessarily an authority leak |
| Normal versus nonfinal serving | The normal lite-query predicate uses `handle_moved_to_archive`, not simply `received/state_boc`; the nonfinal option relaxes that predicate. The flag defaults false and has an explicit `--nonfinal-ls` option | Do not replace this predicate with an imagined `is_applied` check. Its normal archive-lifecycle implications are not a full finality proof audited here |
| Same-shard account queries can use an explicitly supplied block ID | `liteserver.cpp:799–833` routes that request directly to the block/state; `getBlock/getState` return block-bound data. Their response is not itself a quorum certificate | A successful query alone cannot serve as the authority criterion |
| Account-proof validation is relative to the caller's reference | `check-proof.cpp:209–240` checks the response against `ref_blk` and validates shard/account proofs. At `98–104`, `check_shard_proof` accepts the identical-reference-block case without a masterchain ancestry proof | A candidate's internally consistent proof can validate against that candidate as an explicit reference. This does not prove that the candidate was accepted. The caller must establish the reference's authority independently |
| Example external client | `lite-client.cpp:1197–1239,2129–2157` sends a chosen reference and validates the returned account proof against it, displaying the reference context | This does not close all external consumers' trust anchors. It is not evidence that successful membership validation means finality, nor a demonstrated promotion into canonical state |

There is consequently a real boundary to preserve if proposition 2 is adopted:
**authority-bound consumption of an accepted block, not mere successful access
to any stored block or state proof**. The latter already admits nonfinal data in
an explicitly enabled mode. This review found no code in those serving paths
that turns the candidate into the latest authoritative masterchain state merely
because its data/state were stored.

`do_get_last_liteserver_state` (`manager.cpp:1963–1983`) selects maintained
masterchain/liteserver states, not `nonfinal_info_.last_candidate`. Candidate
broadcast handling records `last_candidate` separately. This is evidence against
a direct candidate-cache-to-latest-state promotion in these inspected methods;
it is not a complete audit of every updater of those maintained states.

## Proposition 3: candidate/proof propagation versus acceptance

N2 and N3 must be distinguished, not treated as one candidate-only channel.

**N2, candidate queue proofs:** the earlier observed send before candidate
archival is a data/proof handoff. The consumer requests specified neighbor block
IDs derived from shard configuration (`collator.cpp:971–1005`).
`OutMsgQueueProof::fetch` (`out-msg-queue-proof.cpp:168–204`) validates queue proof
roots against those blocks. The validator separately selects neighbor blocks
from its shard configuration (`validate-query.cpp:1710–1776`), and its collated
proof path derives the state root from the block-bound update
(`7684–7705`). A proof being present in a cache does not itself select that block
as a neighbor. No promotion of an arbitrary candidate proof to an authorized
queue source was identified in these paths.

**N3, block/finality broadcasts:** this channel can contain finality-bearing
signatures, not just a candidate. `BlockAccepterImpl` handles `FinalizeBlock` and
passes its signatures to `ManagerFacade::accept_block`
(`consensus/block-accepter.cpp:30–66`). Its `CandidateGenerated` handler is a
separate candidate-broadcast path (`74–90`).
`AcceptBlockQuery::create_new_proof` checks final or approve signatures according
to their kind (`accept-block.cpp:253–267`); it then sends configured broadcasts
before its local state-store continuation, as the previous report showed.
Thus "broadcast before local P4" is compatible with already having a consensus
certificate. It is not by itself evidence of premature authority.

On reception, `ValidateBroadcast` distinguishes final and approve signatures
(`validate-broadcast.cpp:244–253`); masterchain broadcasts require final signatures
(`83–87`). `ValidatorManagerImpl::new_block_broadcast` triggers
`validated_accepted_block_broadcast` only on successful validation **and**
`sig_set->is_final()` (`manager.cpp:241–252`). The separate finality-broadcast
receiver checks signatures before recording pending finality, and the
`process_accepted_nonfinal_block` path is invoked there for final shard signatures
(`manager.cpp:633–681`). The name "nonfinal" in that method refers to its serving
context and must not erase the explicit final-signature condition at this caller.
There are other callers (e.g. validated shard descriptions); this is not a claim
that the method alone authenticates its inputs.

The approve/final distinction means "consensus accepted" needs an exact event or
certificate definition. A local `received`, `state_boc`, query success or a
method name containing "accepted" is not a substitute. A shard certificate and
masterchain inclusion are also distinct observations in the implementation.
This report identifies that distinction without deciding a new D47 definition.

## Construction beyond one immediate call

There is also speculative construction outside a single block's local collator.
`simplex/state-resolver.cpp:275–328` reconstructs candidate chains and applies
candidate updates into `ChainState` while separately testing finalized anchors.
That is computation over candidate-bound state, not necessarily promotion to
finalized state. Consequently "no observer outside the same block can read an
unfinalized result" would be too strong as well. The relevant exclusion is from
**authoritative consumption**, not from explicitly speculative computation.
This review does not establish rollback/isolation of the mutable N1 context or
of all speculative descendants; those remain construction-side obligations.

## Residual review limits

No actual instance was found where a block lacking the required acceptance basis
has only some components substituted into an authoritative generation. The
following are **not** closed by that negative finding:

- Every external client/RPC consumer's trust anchor. In particular, account
  membership validation at a caller-selected candidate reference is not finality
  verification; arbitrary applications might misuse that result.
- Every updater of canonical head/shard configuration, the complete archive
  eligibility lifecycle, and every recovery/permanent-store path. The inspected
  consumers require selected identities, but this is not a proof of consensus
  safety or of all provenance leading to those identities.
- Delegated signature-check paths. `ValidateBroadcast` can trust its internal
  `signatures_checked_` flag (`225–228`); this review does not certify every caller
  supplying it. Fake/forced-fork administrative paths are likewise not audited
  as ordinary consensus acceptance.
- Complete live wc=2 integration. Its D47 batch count/identity/context carrier and
  the I13a/b/e mechanisms are still absent; consensus cannot commit fields which
  have not been represented, nor can it replace the independent I13 checks.

These are explicit limits, not evidence that those paths are unsafe. There was
no runtime experiment or fault injection in this review.

## Verdict on the rewrite

Proposition 2's **authority-versus-availability distinction is supported** in the
reviewed paths, but its "not externally offered" explanation is false in nonfinal
serving mode. Proposition 3's **broadcast-does-not-create-authority distinction is
supported**, but N3 can carry already-final signatures and is not candidate-only.
Neither correction is the requested counterexample of unaccepted partial content
being consumed as authoritative state.

The evidence therefore supports reconsidering the original storage-layer
interpretation and does **not** justify insisting on a new atomic store wrapper
from P1–P5 alone. It does not establish the universal claim that all outside
observers enforce acceptance, and it does not approve the rewrite as a completed
I13e argument. A decision separating construction isolation, consensus authority
and local recovery is for the coordinator; no solution is designed here.
