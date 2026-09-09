# Read-only review of publication visibility

**Finding: the inspected observer paths do not converge on one durable handle
transition.** Accounts and persistent queues do share a state-root commitment;
block records use a separate block/archive path. Same-block processing uses live
collator objects, and network handoff can occur without waiting for the local
state-store completion. No complete D47 generation or batch-count persistence
mechanism exists in this inspected code. These facts do not establish a violation
of the existing protocol's finality rules or delivery of an unauthorized message.

Follow-up: [the authority-boundary review](workchain-publication-authority-review.md)
qualifies the inference from these transitions to required storage-layer work.
Different availability transitions do not themselves prove partial authoritative
publication. The eight observed roles remain valid; necessity of storage-layer
atomicity for a redefined consensus-authority boundary is not established here.

This is static analysis, not a failure-injection measurement or an implementation
proposal. The companion `doc/measurements/uno-m1-publication-visibility-review.json`
pins every reviewed source to a commit/blob/hash and archives numbered excerpts.
Uncommitted publication-input drafts were not used as implementation evidence.
No production source, gate or approved assertion was changed by this review.

## Contents, providers and visibility paths

The names below identify existing fields; they do not invent a complete publisher.
`P1`–`P5` and `N1`–`N3` are defined in the next section.

| D47 component | Existing provider/representation | Same-block observer | Storage/recovery path | Remote/external observation |
|---|---|---|---|---|
| Accounts / participant updates | Account objects and ShardAccounts; private settlement returns `state.accounts` | N1: subsequent processing of live collator accounts/dictionaries; not a storage read | ShardState contains accounts; P1 stores state cells and root registration, P4 makes state available through the recovered handle | State proof is bound to a selected block; not merely to this node's P4 |
| AccountBlocks / transactions | `create_block_extra` references `shard_account_blocks_`; private settlement returns `state.account_blocks` | N1: serialized transactions and local account bookkeeping | Block body via P2/P3; not the ShardState account dictionary | N3 block body; corresponding transactions/messages are cryptographically committed by the block |
| Inbound descriptors / consumed inputs | `in_msg_dict` in BlockExtra; final-import evidence is a private ingredient | N1: local import/dequeue processing | Descriptors P2/P3; persistent processed-up-to state in OutMsgQueueInfo follows P1/P4 | Block descriptors and state proofs have different acquisition paths; a received descriptor is not independent queue-consumption authorization |
| Outbound descriptors | `out_msg_dict` in BlockExtra; queue builder returns `roots.descriptors` | N1: local descriptor insertion | P2/P3 | N3 exposes the block body containing descriptors |
| Outgoing queue | `OutMsgQueueInfo.out_queue` | N1: mutable `out_msg_queue_` | P1/P4, under the same ShardState root as accounts | N2 can carry a queue proof before candidate archival completes; consumption additionally requires the selected neighbor block and matching proof |
| Dispatch queue | `OutMsgQueueInfo.extra.dispatch_queue` | N1: mutable `dispatch_queue_` | P1/P4, not a separate per-queue database in this path | Included in the state commitment; its eventual dispatch is governed by later processing, not a separate observed D47 flag |
| Shard state | `Collator::create_shard_state` | Private `state_root` becomes available to later construction | P1/P4 | Queue/state proofs identify the block's state root; availability is not application/finality |
| Shard update | `MerkleUpdate::generate`, then Block.state_update | Later block construction reads the local update | P2/P3 as block data. The resulting state is separately P1/P4 and may be reconstructed from block data | N3 block content includes the update |
| Whole-block value flow | `check_value_flow` / `value_flow_.store` into Block | Local construction and checks | P2/P3 | N3 block content |
| Processing metadata | Split among local counters/LT bounds, BlockInfo, state fields and processed-up-to | N1: later execution uses local metadata before any store call | Some serialized fields follow P1/P4, others P2/P3; no single complete D47 context serialization was found | Only serialized fields are part of block/state proofs; a complete batch-context external view does not yet exist |
| Batch identity | Private participant binding carries input/effects hashes; no block-wide identity checker | Private record construction | Commitments occur in participant transactions when present; complete live wc=2 D47 identity publication is absent | No implemented D47 generation binding to trace |
| Committed batch count | No implemented block-wide count provider/store field | No corresponding live D47 field | **Absent**, not implicitly one, not a handle flag | Absent. D48's independent recomputation/comparison remains separate from publication |
| Messages / release eligibility | Transactions, descriptors, queues, neighbor selection and proof checks | N1: `new_msgs` feeds later processing; not a network send | Message content is bound into block/state paths above; no standalone complete D47 eligibility record was found | N2/N3 expose data independently of P4. Cross-shard consumption follows authenticated block selection and proofs, not the sender node's local handle flag |

The queue result is important: **there is no evidence here for independent
outgoing/dispatch persistence apart from their common ShardState root.** The
failure of convergence must not be justified by inventing such a split. Equally,
being hash-bound into one Block does not make every observer wait for one local
storage transaction. Commitment, data availability and consumption eligibility
are different properties.

## Identified transition roles and their count

This review identifies **eight transition roles: five persistence-related roles
and three non-storage observation roles**. This is a count of the explicitly
traced roles below, not a claim that every run has exactly eight writes or that
all node/RPC paths have been enumerated. P3/P4/P5 use the same handle serializer
but are independently requested updates. Archive batching may coalesce updates;
the code does not require them all to be one transaction with P1/P2.

| Role | Actual transition and source | What it covers / does not cover |
|---|---|---|
| P1 | `CellDbIn::store_cell`, `celldb.cpp:562–631`: prepare cells; `begin_write_batch`; set block/root linked-list records; commit cells; `commit_write_batch`; refresh snapshot | The state-root registration and cells in CellDb, including account/outgoing/dispatch commitments. This is more than unreferenced raw cell bytes. It does not write the entire BlockExtra or archive handle. Standard RootDb state reads still require P4's flag |
| P2 | `ArchiveSlice::add_file/add_file_cont`, `archive-slice.cpp:406–453`: package append, then archive key/value file-offset/status transaction | Block data, including AccountBlocks, descriptors, value flow and update. Distinct from CellDb. This row identifies the archive's transaction boundary, not an independent power-loss audit of package syncing |
| P3 | `RootDb::store_block_data`, `rootdb.cpp:35–52`: after file success, `set_received`, then `ArchiveManager::update_handle` | Block-data availability flag. `get_block_data` checks `received`, not `state_boc` or `applied`. The in-memory bit changes before the subsequent persistent handle write |
| P4 | `RootDb::store_block_state`, `rootdb.cpp:257–290`: after CellDb success, set root hash and `state_boc`, then update archive handle | State availability flag. `get_block_state` checks `state_boc`; it does not require `is_applied`. The in-memory flag mutation is not itself the durable transaction |
| P5 | `ApplyBlock::applied_set`, `apply-block.cpp:273–318`: set `applied`, then flush handle when needed; `ArchiveSlice::get_handle` reconstructs flags from persisted serialization | Applied status is another separately flushed state. Application also involves manager/archive processing; this row does not turn that whole lifecycle into one write |
| N1 | `collator.cpp:3544–3554,2524–2529,5137–5172,5180–5204`: commit private Account, update local metadata, register messages, then process them | Same-block downstream computation observes live working objects before a storage publication. It is neither P4 nor a disk read. Local processing can affect produced block content; it cannot be excluded merely by calling the builder private |
| N2 | `ValidatorManagerImpl::set_block_candidate`, `manager.cpp:1732–1745`: send queue-proof broadcasts before requesting candidate storage when `cache_only` is false | Real outbound callback invocation, not waiting on local state-store success. This is proof/data handoff, not proof of an internal message being consumed |
| N3 | `AcceptBlockQuery::written_block_info/send_broadcasts`, `accept-block.cpp:504–528,960–986`: send configured block/finality broadcasts before this path requests previous state and later stores resulting state | Carries block data/proof/signatures or finality notification when enabled. It is not governed by completion of this node's P4. The accept path has its own prerequisites; no unauthorized-send conclusion follows from this ordering alone |

The durable handle write behind P3/P4/P5 is concrete:
`ArchiveSlice::update_handle` (`331–356`) serializes the handle into the archive
key/value transaction; `commit_transaction_now` (`956–960`) commits it.
`ArchiveSlice::get_handle` (`455–479`) reconstructs a handle from that stored value.
Conversely, `BlockHandleImpl::set_received/set_state_boc/set_applied`
(`block-handle.hpp:405–413,473–480,489–495`) mutate shared atomic flags in memory.
The manager can return cached/shared handles (`manager.cpp:1888–1910`). Thus
"flip the handle" names two different events unless explicitly qualified:
**in-memory flag publication and subsequent durable serialization**.

## Three observer paths do not share a gate

**Same-block processing:** the existing singleton path commits to its local
Account and calls `register_new_msgs`; the enclosing collator then runs
`process_new_messages(enqueue_only=true)`. That later work determines queue and
block contents before persistence. This is a concrete consensus-affecting
consumer of working state, not evidence of a live multi-account D47 mechanism.
It also does not prove that discarded candidate state leaks into a different
candidate. The new wc=2 multi-account path is still disconnected.

**Recovery:** state cells/root records, archived block bytes and handle flags have
separate operations. The normal recovered-handle readers distinguish block
availability (`received`) from state availability (`state_boc`) and application
(`applied`). There is no read of one complete D47 generation covering all listed
fields. Restart scheduling, CellDb permanent mode/GC, archive migration and every
alternate recovery fast path have not been exhaustively closed by this review;
none is silently treated as providing the missing D47 generation.

**Other shards/external consumers:** queue availability is not queue eligibility.
`Collator::request_neighbor_msg_queues` (`971–998`) selects neighbor block IDs
from shard configuration, rather than from the sender's local handle.
`OutMsgQueueProof::fetch` (`out-msg-queue-proof.cpp:168–204`) binds queue proofs to
the requested blocks' state roots. `got_neighbor_msg_queue` (`1066–1116`) also
checks the returned block identity and decodes OutMsgQueueInfo. Consequently a
proof broadcast does not alone authorize consumption. These conditions concern
selected/authenticated remote blocks, not one shared local database transition.
This is not a full audit of consensus/finality acquisition or every external
interface, and no received proof is assumed authorized merely because it arrived.

## Answer and limits

The hypothesis "write unreachable cells, then one durable pointer flip makes
all D47 components visible to all three observer classes" is **not the shape of
the inspected paths**. The state-side grouping is real, but the whole content
set and observer gates do not reduce to it. Count and complete processing-context
publication are missing altogether. One extra wrapper call cannot establish
atomicity across the identified transitions.

Under D47's current whole-generation, three-observer definition, this is a
storage/visibility integration gap, not merely a missing function wrapper. Which
existing transition should define a revised or implemented D47 decision point
requires coordinator judgement. This report does not select a solution, change
the contract, move/open a gate, or claim an exploitable split publication in the
existing protocol. There were no writes to the reviewed production files, no
experiments, and no I13e acceptance claim.
