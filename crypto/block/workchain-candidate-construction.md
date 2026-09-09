# Candidate construction isolation draft

This is an implementation draft for D47(a), not I13e acceptance. The private
context is not connected to the collator. Existing consensus authority, nonfinal
serving, storage transactions and restart behavior are not implemented here.
No gate is moved or opened. The proposed persistent publication entry is superseded by this construction
boundary; no second authoritative store is introduced.

## Ownership and observations

`WorkchainCandidateConstruction` owns the current immutable construction view.
A trusted host builder receives the previous view and a private draft. It must
run all fallible preparation before the context installs the completed view.
Accounts, transactions and mutable dictionaries remain private to their Native
builders. An engine must not receive the context or the host builder capability.
The final assignment has no observer, allocation or fallible operation after it.
The caller supplies the expected predecessor snapshot obtained from this context;
construction refuses installation against another snapshot identity. This is a
local generation binding, observable even for byte-identical snapshots, not I13b execution accounting or a restriction on
independent validator replay.
Thrown exceptions retain their provenance and destroy the draft; returned
failures also leave the current view in place. Nested construction is refused.

Every same-block consumer must read this context's snapshot. This is a required
integration property, not something a root container can enforce for unrelated
collator fields. A consumer retaining an old immutable snapshot can observe the
old generation, never half of a new one. No snapshot confers finality or a
permission to send. No live transport handle is passed to construction.

The bypass controls change a private-stage checkpoint to install the
draft directly into the live context before notifying the observer. A sticky
observer records the changed live state immediately, even if a subsequent
failure restores the old view. A final-state equality check alone is insufficient.
These controls are intended to establish sensitivity to that bypass in the tested context;
it will not establish that all live collator consumers have been rerouted.
Execution and source restoration records are archived separately under
`doc/measurements/uno-m1-construction-isolation/`. The scope of those records,
not the presence of this implementation, determines the demonstrated coverage.

## Providers

All ten roots are explicit host inputs/results, in the order documented by
`WorkchainCandidateField`. None is filled with a placeholder to make a partial
pipeline appear complete.

| Field | Provider |
|---|---|
| Accounts | Account settlement plus whole-candidate account assembly |
| AccountBlocks | Native participant records plus whole-candidate block assembly |
| InMsgDescr | Final-import evidence plus enclosing inbound processing |
| OutMsgDescr, OutQueue, DispatchQueue | Native outbound queue construction using the current private processing roots |
| ShardState | Host shard-state assembler |
| ShardUpdate | Host proof builder bound to the actual old/new shard states |
| ValueFlow | Host whole-block value-flow assembler and checker |
| ProcessingMetadata | Host context owner, including logical times, counters, budgets and consumed-input progress |
| Batch identity | Host block-content assembler; opaque to this context |
| Committed batch count | Host block-content assembler; explicit submitted value |
| Pending messages | Host reconstruction of transaction-bound outputs and all prior pending messages |
| Revision | Host candidate-context owner; separate from logical batch count |

The context carries the supplied count unchanged. D48's independent I13a
checker must recount actual block identities and compare the submitted value.
Atomic installation of a false count does not make the count true. Identity and
count are never inferred from an invocation or normalized by this entry.

The complete metadata, shard-state and value-flow providers and the live
same-block consumer mapping are not supplied by a presence check. Unknown or
missing providers must remain missing integration, not become accepted defaults.
Existing metered engine interfaces are separate: the reported v4 integration
uses `execute_metered_accounts(..., WorkchainProofVerifier&)`, with the same meter
forwarded by its configured adapter and no fallback to the legacy entry. This
construction context implements neither engine interface and selects no meter.

## Copy costs and D31

Copying a candidate carrier copies ten cell references, one identity reference,
one shared message-list reference and two scalars. It does not walk account,
queue, shard-state or proof closures. Native dictionaries use persistent cell
paths; they do not duplicate the complete shard dictionary for this carrier.

`WorkchainCandidateMessages` copies the supplied message elements into owned
immutable storage. Sharing a `const vector` pointer from a mutable provider
would not freeze that provider's retained aliases. Freezing a new list costs
O(M) elements, where M is the **complete** supplied pending list, including prior
messages, not only the current batch's outputs. Old snapshots can retain earlier
lists and cell closures. This context currently imposes no aggregate bound on M
or on the number/lifetime of retained snapshots. It must not be described as
having a proved D31 resource bound.

Native builders separately check participant/write counts, inbound counts and
`WorkchainOutboundQueuePolicy::max_outputs`. Queue construction copies and sorts
the supplied output list; those explicit bounds do not authenticate themselves,
bound prior pending messages or account for retained snapshots. Cell traversal,
new cells, message freezing, context retention and final assembly must be charged
or bounded by the enclosing admitted host policy before live integration. There
is no established authenticated aggregate limit for these new context costs in
this draft. Connecting it is a D31 integration obligation, not a silently chosen
limit or a claim that the per-batch output bound already covers it.

## Stage status

Native observer hooks run after participant private commit, AccountBlock
insertion, account-root replacement, final import insertion, outbound descriptor
insertion and outgoing/deferred insertion. Observers receive only stage and
occurrence, not mutable candidate objects. Missing an expected observer must
fail the eventual fixture; no observation cannot establish isolation.

The private fixture runs concrete late providers: checked Native value-flow
assembly (including final-import fees), independent dictionary delta coverage,
a bound Native Merkle update checked by application, and a serialized-size limit.
These are fixture providers, not the complete collator's final budget/metadata
providers. Their four checkpoints therefore establish isolation in that private
composition, not live integration. The context supplies predecessor-check and
before-install positions. Every one of the 23 positions has a failure case.

The fixture starts from six funded accounts and nonempty historical outgoing and
dispatch queues. A preceding private Native batch supplies three genuine prior
pending messages; the tested batch touches three different accounts and supplies
three more messages. This block's initial AccountBlocks and descriptors are real
empty Native dictionaries, not prior-block descriptors reused as current ones.
Whole-block value flow is reconstructed for the tested private composition.
Processing metadata records the fixture's actual logical times, queue counts,
input and effects bindings; it does not stand in for unknown collator fields.

The original durable-adapter assertions remain pending and unchanged. Their
coverage-complete flag is not forged for the new context. All live
consensus-affecting consumers still require an explicit integration audit,
including observations later rolled back. No omitted live consumer is treated
as isolated. Retaining this gap does not turn the fixture's real snapshot or
message reader into an adapter-maintained expected-state model.

## Cost-to-limit correspondence in the inspected branch

| Construction cost | Existing limit or explicit gap |
|---|---|
| Carrier copy | Fixed ten roots, one identity, one shared list handle and two scalars; no closure traversal |
| Participant reads and private Account/Transaction vectors | `resources.input.max_reads/max_writes`, passed as `max_reads/max_participants`; this fixture supplies 3/3, not a resolved D31 certificate |
| Native transfer planning | `resources.work_output.max_transfers`; fixture supplies 2 |
| Final-import enumeration | `resources.input.max_inbound`; fixture supplies 2 |
| New outgoing/deferred list copying and sorting | `WorkchainOutboundQueuePolicy::max_outputs` and disposal `max_outbound`; fixture supplies 3; authoritative derivation/connection remains outside this entry |
| Account body/closure work | `resources.state.max_cells/max_bits/max_account_cells/max_account_bits/max_account_depth`; no additional meter is attached by this entry |
| Effect and newly produced cell closures | `resources.work_output.max_effect_cells/max_effect_bits/max_output_cells/max_output_bits`; fixture's 1 MiB-per-root serialization check is not a substitute |
| Complete pending-list freezing | No authenticated aggregate bound on prior plus new messages is connected here |
| Retained snapshots and their cell/list lifetimes | No bound on concurrent retained generations is connected here |
| Full BOC oracle reads and late size-check serialization | Test-provider work only, including shared historical closures; not production admission evidence |

These field names refer to this branch's committed resource schema. Reported
newer metered-runner work on the integration branch is not assumed to be present
here. No resource-policy or engine interface was modified by this unit.
