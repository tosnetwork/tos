# I13e commit-boundary inventory

This is a static scope inventory, **not acceptance evidence**. No failure
injection has been run for I13e, and no atomicity or activation claim is made.
The inspected commit and source hashes are recorded in
`doc/measurements/uno-m1-i13e-boundary-inventory.json`.

## Existing private stages

| Surface | Existing stages relevant to later failure injection | What becomes visible at return |
|---|---|---|
| `build_workchain_storage_overlay` | Per-account prepare/serialize; commit private Account; build AccountBlock; replace ShardAccount; record coverage; derive actual changes; finish coverage | A returned pair of persistent roots, not a live-state installation |
| Allocation/payout overlays | Per-account private commit and dictionary updates; outbound transaction extraction; final imports; value-flow verification; actual coverage | Returned private state, import and export artifacts |
| `account_settlement_detail::execute` | Engine effects admission/encoding; selected overlay; output/account closure admission; immutable budget snapshots; returned result; sticky read-footprint check | A `Result<WorkchainAccountSettlement>` |
| `build_workchain_outbound_queues` | Validate/bind outputs; encode export; insert descriptor; insert outgoing or account-dispatch entry; return queue roots | A `Result<WorkchainOutboundQueueResult>` |
| `continue_workchain_outbound_queues` | Construct private queues; extend output admission; retain state admission; sticky observer failure | Another private result, not publication |

Each per-account/per-message stage would require position-specific controls,
including a failure after an earlier participant/message has been staged.
Merely failing the final coverage check is not a substitute for those controls.
These functions provide useful preparation-stage subjects, but they do not
supply the requested visible commit/publication boundary.

## Missing acceptance subject

The inspected multi-account private interfaces expose no operation that installs
account state and outgoing/dispatch publication state atomically, no durable
commit handle, and no external publication observer. `tx.commit(account)` here
updates a private temporary Account. The payout overlay explicitly says it does
not touch CellDb or publish a message. Creating a `NewOutMsg`, descriptor or queue
root is not itself sending or publishing that message.

A test-side visible-state variable that is never passed to these operations
would stay unchanged trivially. Likewise, a newly invented test-side atomic
publisher would test itself, not establish the production I13e requirement.
Neither will be counted as acceptance evidence.

The existing singleton `Collator::create_workchain_batch_transaction` is a
different surface. It mutates the collator's local import/account structures,
then registers new messages. Whether those mutations survive failure depends on
the enclosing collation lifecycle. Its ordering is not, by itself, evidence of
an externally visible split commit. No such defect is claimed by this inventory.
That surface is in the other agent's production ownership and is not the
multi-account private API used by the preceding acceptance units.

## Coordinator decision needed

Identify the real private operation and visibility boundary that I13e should
exercise, or coordinate introducing that operation before its acceptance tests.
The decision must establish what an observer can see, how account roots and
message/queue publication are bound to one commit, and what reports a successful
single commit versus a failed attempt. If the intended subject is the collator's
larger lifecycle, its ownership and test access need coordination instead.

Once a subject is identified, the failure-stage matrix can bind each injection
to a concrete stage of that operation and assert both unchanged state and no
orphaned publication against a real observer. The existing shadow-copy/blob,
numeric-identity and immutable-oracle discipline remains required. This inventory
does not choose a new commit design or weaken the invariant.
