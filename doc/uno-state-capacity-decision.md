# UNO state capacity: decision required before activation

Status: proposal only. No host, consensus, configuration or state-schema change
is authorized or activated by this document. M3 expansion remains paused.

## Evidence and boundary

At `09e92500d`, the real `UsedNullifiers` dictionary staged through native
batch preparation accepted 32,765 deterministic random keys and rejected
32,766 under the default 65,536-cell account limit. This excludes the rest of
UNO state; it is not a production capacity or transaction quota. Removing the
native limit made the rejection control fail. The original comparison was
restored and all 41 WorkchainBlock tests passed.

The current extractor requires exactly one executor account. The executor
data retains the engine state and result wrapper. Splitting that reachable DAG
into more Cells does not partition account storage accounting. Merely placing
copies in additional accounts also does not help if the executor's state or
retained result still references the entire DAG.

The design draft's sections 9, 10 and 16 require atomic block execution,
replayable state, permanent spent-nullifier uniqueness, refund reservations,
and full collate/validate agreement. A representation change must preserve
these; it must not silently turn the chain into a small disposable pool.

## Alternatives to price

1. Keep one account with a separately justified larger budget. This preserves
   the most current host code. It requires full-state growth/RSS/import/replay
   measurements, bounded per-block work, storage funding, reserved exit space
   and a concrete migration horizon. A finite increase only moves exhaustion.
   Do not raise the shared Native account limit as an incidental UNO change.

2. Partition engine storage across native accounts within the same workchain
   and unsplit shard. This could reuse native CellDb, proofs, checkpoints and
   account-level storage machinery. It requires a new host storage contract:
   deterministic partition ownership, authorized atomic multi-account updates,
   transaction/account-dictionary consistency, fees and resource accounting.
   Neither the coordinator data nor its retained result may retain references
   to all partition payloads. Commitments must still bind every changed part;
   hash-only commitments do not supply availability or replay data themselves.
   This is not a request to add another chain or change UNO's 1:1 backing.

3. Retain one coordinator account with an authenticated external engine store.
   This bounds its visible DAG only if state data truly leaves that DAG. It
   adds consensus-critical state availability, transactional store updates,
   proofs, snapshot acquisition, restart and GC obligations outside normal
   account storage. A root hash or local database alone is insufficient.

Recommendation: authorize a design comparison centered on native partitioned
storage before selecting a production schema. This is not a claim that option
2 is already compatible with the one-synthetic-transaction invariant. It must
first show how that invariant and native state-update validation remain valid.
Keep option 1 as a measured alternative, not an automatic limit increase;
option 3 has a substantially larger new synchronization responsibility.

## Required outputs of the authorized design step

- Explicit active-state capacity, growth envelope, block work/RSS budgets and
  emergency exit/refund capacity; no deletion of historical spent nullifiers.
- Exact owner of every state component and commitment, including retained
  execution results, with no hidden whole-DAG reference through the coordinator.
- Host input/result, atomic commit, account/transaction proofs and version gates;
  retain full-wrapper replay comparison or specify its equally binding successor.
- Cold bootstrap, authenticated checkpoint-to-current catch-up, restart, GC and
  retention rules for every partition/store, including unavailable data cases.
- Migration and obligation handling before exhaustion; explicit changes to the
  design draft and activation freeze list, reviewed before implementation.

Decision pending: permission to revise the M0/M1 storage contract and compare
these alternatives. No alternative has been selected for production.
