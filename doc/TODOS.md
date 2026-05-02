# TOS Validator Subsystem - Tracked Open Questions

This file consolidates legacy TODO/FIXME markers extracted from
`validator/*` during the validator subsystem cleanup pass. Each
entry preserves a `file:line` reference (as of commit
`ad9b48a72`) and the original verbatim comment text so future
investigators can locate and reason about the source. Source
files no longer carry these markers; this file is the
authoritative backlog for the validator subsystem.

The vast majority of entries below originate from upstream
TON-style code that TOS inherits. They were not raised in any
audit cycle (tos11-tos15) and are tracked here purely so the
in-tree comment hygiene stays clean. Entries flagged
"TOS-owned" reflect work the TOS team owns directly.

## Convention

Each entry has:

- **Status**: `open`, `in-progress`, or `resolved`
- **Category**: `collator`, `validate-query`, `consensus`, `db`,
  or `other`
- **Source**: `validator/<file>:<line>` at commit `ad9b48a72`
- **Origin**: `upstream-TON` or `tos-owned`
- **Original comment**: verbatim from the source
- **Context**: a short description of the surrounding code
- **Suggested resolution**: when known

## Entries

### V-001: storage transaction verification not implemented

- Status: resolved
- Category: validate-query
- Source: validator/impl/validate-query.cpp:5941 (commit ad9b48a72)
- Origin: upstream-TON
- Original comment:
  > // FIXME
- Context: In the `trans_storage` branch of transaction descriptor
  dispatch, after rejecting transactions that contain inbound or
  outbound messages, the validator unconditionally rejects all
  storage transactions with "unable to verify storage transaction".
  The verification logic for storage transactions has never been
  implemented in upstream TON either, so blocks containing such
  transactions cannot be validated.
- Suggested resolution: implement `Transaction::tr_storage`
  re-execution against the previous shard state and compare the
  resulting account state against the recorded post-state hash.
- Resolution: implemented in `crypto/block/transaction.cpp`
  (`Transaction::serialize` case `tr_storage`) and
  `validator/impl/validate-query.cpp` (`check_one_transaction`
  `trans_storage` branch). The storage-only re-execution path runs
  `prepare_storage_phase` then `serialize`/compare, skipping the
  compute/credit/action/bounce phases that do not exist for this
  transaction type.

### V-002: merge prepare transaction verification not implemented

- Status: open
- Category: validate-query
- Source: validator/impl/validate-query.cpp:5965 (commit ad9b48a72)
- Origin: upstream-TON
- Original comment:
  > // FIXME
- Context: `trans_merge_prepare` branch unconditionally rejects
  with "unable to verify merge prepare transaction". Re-execution
  logic for merge-prepare transactions is missing.
- Suggested resolution: implement re-execution comparing emitted
  outbound message and post-state hash; gate behind shard merge
  configuration.

### V-003: merge install transaction verification not implemented

- Status: open
- Category: validate-query
- Source: validator/impl/validate-query.cpp:5977 (commit ad9b48a72)
- Origin: upstream-TON
- Original comment:
  > // FIXME
- Context: `trans_merge_install` branch unconditionally rejects
  with "unable to verify merge install transaction". Inbound
  message presence is checked but credit phase and re-execution
  are absent.
- Suggested resolution: implement merge install re-execution path,
  reusing credit-phase logic shared with ordinary inbound.

### V-004: split prepare transaction verification not implemented

- Status: open
- Category: validate-query
- Source: validator/impl/validate-query.cpp:5992 (commit ad9b48a72)
- Origin: upstream-TON
- Original comment:
  > // FIXME
- Context: `trans_split_prepare` branch unconditionally rejects
  with "unable to verify split prepare transaction". Re-execution
  logic for split-prepare transactions is missing.
- Suggested resolution: implement re-execution and outbound
  message comparison; cross-check with the corresponding split
  install on the sibling shard.

### V-005: split install transaction verification not implemented

- Status: open
- Category: validate-query
- Source: validator/impl/validate-query.cpp:6003 (commit ad9b48a72)
- Origin: upstream-TON
- Original comment:
  > // FIXME
- Context: `trans_split_install` branch unconditionally rejects
  with "unable to verify split install transaction".
- Suggested resolution: implement split install re-execution
  symmetric with V-003 (merge install).

### V-006: refine library publishers diff error message

- Status: open
- Category: validate-query
- Source: validator/impl/validate-query.cpp:6685 (commit ad9b48a72)
- Origin: upstream-TON
- Original comment:
  > // TODO: better error message with by-element comparison?
- Context: When the sorted vectors `lib_publishers_` and
  `lib_publishers2_` differ, the rejection message is generic.
  An element-by-element diff would help operators diagnose the
  exact public library set mismatch.
- Suggested resolution: walk both sorted ranges in lock-step and
  emit added/removed publisher account ids in the rejection text.

### V-007: revisit OutMsgQueueInfo full validation cost

- Status: open
- Category: validate-query
- Source: validator/impl/validate-query.cpp:1789 (commit ad9b48a72)
- Origin: upstream-TON
- Original comment:
  > // TODO: comment the next two lines in the future when the
  > //       output queues become huge
  > // (do this carefully)
- Context: Two `validate_ref(1000000, ...)` calls run against the
  neighbor's `OutMsgQueueInfo` whenever `debug_checks_` is on.
  When real-world output queues grow, these full revalidations
  may become prohibitively expensive and need to be replaced
  with incremental checks.
- Suggested resolution: track queue size; when above a threshold,
  switch to incremental delta validation against the previous
  validated queue root.

### V-008: skip ProcessedUpto mc state requests when no relevant messages

- Status: open
- Category: validate-query
- Source: validator/impl/validate-query.cpp:1811 (commit ad9b48a72)
- Origin: upstream-TON
- Original comment:
  > // TODO: perform this only if there are messages for this
  > //       shard in our output queue
  > // .. (have to check the above condition and perform a `break`
  > // here) ..
- Context: The validator requests masterchain blocks referenced
  by every neighbor's `ProcessedUpto` list, even when our shard
  has no messages addressed to that neighbor.
- Suggested resolution: short-circuit the loop when our outbound
  queue contains no messages destined for the neighbor's shard.

### V-009: skip ProcessedUpto mc state requests in collator

- Status: open
- Category: collator
- Source: validator/impl/collator.cpp:1146 (commit ad9b48a72)
- Origin: upstream-TON
- Original comment:
  > // TODO: perform this only if there are messages for this
  > //       shard in our output queue
  > // .. (have to check the above condition and perform a `break`
  > // here) ..
- Context: Mirror of V-008 in the collator path.
- Suggested resolution: same as V-008.

### V-010: extract start_lt and end_lt from prev_mc_block

- Status: open
- Category: collator
- Source: validator/impl/collator.cpp:936 (commit ad9b48a72)
- Origin: upstream-TON
- Original comment:
  > // TODO: extract start_lt and end_lt from prev_mc_block as well
- Context: After verifying capabilities and global version,
  collator initialization could also pull `start_lt`/`end_lt`
  bounds from the previous masterchain block to tighten lt-window
  invariants for shardchain collation.
- Suggested resolution: thread `prev_mc_block` lt bounds through
  `init_lt`/`fix_one_processed_upto`.

### V-011: implement merge prepare/install for large smart contracts

- Status: open
- Category: collator
- Source: validator/impl/collator.cpp (after_merge_ hook in do_collate_inner)
- Origin: upstream-TON
- Original comment:
  > // TODO: implement merge prepare/install transactions for
  > //       "large" smart contracts
- Context: When `after_merge_` is true the collator currently
  skips merge-prepare/install transaction creation because
  `tr_merge_prepare` / `tr_merge_install` are globally disabled:
  `Transaction::serialize()` has no case for these types (falls
  through to `default:return false`) and validate-query
  unconditionally rejects them (validate-query.cpp ~line 5874).
  The collator hook point is in place; the empty body is correct
  given these constraints.  Counterpart of V-002/V-003.
- Blocked by: V-002 (merge-prepare validator), V-003 (merge-install
  validator), and missing `Transaction::serialize` cases for
  `tr_merge_prepare` / `tr_merge_install`.
- Suggested resolution: add serialize cases for tr_merge_prepare and
  tr_merge_install in transaction.cpp; implement validator re-execution
  in validate-query (V-002/V-003); then fill in the collator hook to
  emit tr_merge_prepare for every account whose state exceeds the
  single-transaction storage budget and tr_merge_install from the
  sibling shard's prepare message.

### V-012: implement split prepare/install for large smart contracts

- Status: open
- Category: collator
- Source: validator/impl/collator.cpp (before_split_ hook in do_collate_inner)
- Origin: upstream-TON
- Original comment:
  > // TODO: implement split prepare/install transactions for
  > //       "large" smart contracts
- Context: When `before_split_` is true the collator currently
  skips split-prepare/install transaction creation because
  `tr_split_prepare` / `tr_split_install` are globally disabled:
  `Transaction::serialize()` has no case for these types (falls
  through to `default:return false`) and validate-query
  unconditionally rejects them (validate-query.cpp ~line 5874).
  The collator hook point is in place; the empty body is correct
  given these constraints.  Counterpart of V-004/V-005.
- Blocked by: V-004 (split-prepare validator), V-005 (split-install
  validator), and missing `Transaction::serialize` cases for
  `tr_split_prepare` / `tr_split_install`.
- Suggested resolution: add serialize cases for tr_split_prepare and
  tr_split_install in transaction.cpp; implement validator re-execution
  in validate-query (V-004/V-005); then fill in the collator hook to
  emit tr_split_prepare for every account whose state exceeds the
  single-transaction storage budget (keeping the account in the shard
  whose prefix matches the account-id) and tr_split_install on the
  receiving shard.

### V-013: ihr_delivered flag is hard-coded false

- Status: open
- Category: collator
- Source: validator/impl/collator.cpp:3552 (commit ad9b48a72)
- Origin: upstream-TON
- Original comment:
  > bool ihr_delivered = false;  // FIXME
- Context: When unpacking an inbound message into a fresh
  ordinary transaction, the `ihr_delivered` flag is always set
  to false, regardless of whether the message was actually
  delivered via IHR. IHR is presently inactive in TON-style
  networks so the constant produces correct behavior, but the
  hard-coding will need to be replaced when IHR is reactivated.
- Suggested resolution: derive `ihr_delivered` from the IHR
  pending info dictionary tracked elsewhere in the collator.

### V-014: handle previously-IHR-delivered messages on reorg

- Status: open
- Category: collator
- Source: validator/impl/collator.cpp:4164 (commit ad9b48a72)
- Origin: upstream-TON
- Original comment:
  > // .. TODO ..
- Context: Inside the inbound-internal-message processor, after
  the "already processed" branch and before the deliver/transit
  branching, there is a hole where the collator should check
  whether the message has already been processed via IHR and,
  if so, emit a `msg_discard_fin` InMsg and remove the entry from
  `IhrPendingInfo`. Linked to V-013.
- Suggested resolution: implement the IHR pending-info lookup
  and the discard-fin in-message construction.

### V-015: drop is_key_block guard around BlockExtra unpack

- Status: resolved
- Category: other (check-proof)
- Source: validator/impl/check-proof.cpp:218 (commit ad9b48a72)
- Origin: upstream-TON
- Original comment:
  > // FIXME: remove "is_key_block_ &&" later
- Context: `CheckProof::process_block_header` only unpacked
  `BlockExtra` when the block is a key block. Once block extra
  parsing is robust enough for non-key blocks, this guard can
  be removed so all proofs receive the same treatment.
- Suggested resolution: remove the `is_key_block_` predicate
  once non-key BlockExtra unpacking is exercised in tests.
- Resolution: `tlb::unpack_cell(blk.extra, extra)` is now
  attempted for all non-aux blocks. A failure is fatal only when
  `is_key_block_` is true; for non-key blocks the extra cell may
  simply not be included in the Merkle proof and the failure is
  tolerated. The `extra` value continues to be consumed only in
  the `is_key_block_ && !is_aux` branch, so behaviour for key
  blocks is unchanged.

### V-016: validate post-check-proof invariants in skip-signature mode

- Status: resolved
- Category: other (check-proof)
- Source: validator/impl/check-proof.cpp:64 (commit ad9b48a72)
- Origin: upstream-TON
- Original comment:
  > // TODO: check other invariants
- Context: When `skip_check_signatures_` is true, the
  `finish_query` path ran no invariant validation at all. The
  signature-skipping mode is intended for replay scenarios but
  should still verify structural invariants.
- Suggested resolution: factor out the structural subset of
  `ValidatorInvariants::check_post_check_proof` and call it on
  the skip-signatures path.
- Resolution: `finish_query` now calls
  `ValidatorInvariants::check_post_check_proof(handle_)` on the
  skip-signatures branch. The skip-sig path always goes through
  `got_block_handle_2` (which sets merge/split/is_key_block/
  state_root_hash/logical_time/unix_time/prev on the handle and
  stores the proof via `set_block_proof`), so all fields
  checked by `check_post_check_proof` are guaranteed to be
  initialised before `finish_query` is reached. No separate
  structural subset was needed; the full proof invariant applies.

### V-017: cache out-msg-queue proofs across queries

- Status: open
- Category: other (out-msg-queue-proof)
- Source: validator/impl/out-msg-queue-proof.cpp:409 (commit ad9b48a72)
- Origin: upstream-TON
- Original comment:
  > // TODO: maybe save proof to small cache? It would allow
  > //       other queries to reuse this result
- Context: When a proof arrives via query, it is delivered to
  the requesting cache entry but not added to the small shared
  cache, so concurrent queries for the same proof refetch.
- Suggested resolution: insert proofs into the small cache on
  the query path, mirroring the broadcast path.

### V-018: report misbehavior on parent-slot inversion

- Status: resolved
- Category: consensus
- Source: validator/consensus/simplex/consensus.cpp:177 (commit ad9b48a72)
- Origin: upstream-TON
- Original comment:
  > // FIXME: report misbehavior
- Context: When a candidate's parent slot is greater than or
  equal to its own slot, the consensus actor silently drops the
  candidate without producing a `MisbehaviorReport`.
- Resolution: added `SlotInversionCandidate` misbehavior type in
  `validator/consensus/simplex/misbehavior.h`; consensus.cpp now
  constructs the proof from the serialized (signed) candidate and
  emits `MisbehaviorReport` before returning.

### V-019: report misbehavior on conflicting pending block

- Status: resolved
- Category: consensus
- Source: validator/consensus/simplex/consensus.cpp:183 (commit ad9b48a72)
- Origin: upstream-TON
- Original comment:
  > // FIXME: Report misbehavior
- Context: When a slot already has a pending block but a
  different candidate arrives, the second candidate is dropped
  without a misbehavior report.
- Resolution: added `ConflictingCandidates` misbehavior type in
  `validator/consensus/simplex/misbehavior.h`; consensus.cpp now
  serializes both the existing pending candidate and the new
  conflicting candidate into the proof and emits `MisbehaviorReport`.

### V-020: report misbehavior on rejected candidate

- Status: resolved
- Category: consensus
- Source: validator/consensus/simplex/consensus.cpp:237 (commit ad9b48a72)
- Origin: upstream-TON
- Original comment:
  > // FIXME: Report misbehavior
- Context: When `validation_result` is a `CandidateReject`, the
  candidate's leader is logged but no `MisbehaviorReport` is
  emitted.
- Resolution: added `RejectedCandidate` misbehavior type in
  `validator/consensus/simplex/misbehavior.h`; consensus.cpp now
  constructs the proof from the serialized candidate and the
  rejection reason string and emits `MisbehaviorReport`.

### V-021: relocate PrecheckCandidateBroadcast handler to the right actor

- Status: resolved
- Category: consensus
- Source: validator/consensus/simplex/pool.cpp:545 (commit ad9b48a72)
- Origin: upstream-TON
- Original comment:
  > // FIXME: This should probably live in another actor.
- Context: The `PrecheckCandidateBroadcast` handler currently
  lives in the pool actor but it primarily concerns broadcast
  validation, which is conceptually closer to the overlay
  bridge.
- Resolution: Moved the handler and `seen_broadcasts_` map from
  `simplex::PoolImpl` to `PrivateOverlayImpl` in
  `validator/consensus/private-overlay.cpp`. Added a
  `FinalizeBlock` handle to track `first_nonfinalized_slot_`
  for the already-finalized guard, a `NoncriticalParamsUpdated`
  handle to keep `params_` current, and initialized
  `slots_per_leader_window_` from `bus.config` at start-up.
  The upper-bound "too far in future" check uses
  `first_nonfinalized_slot_` as a conservative proxy for `now_`
  (sound because `now_ >= first_nonfinalized_slot_` always).

### V-022: GenericRequest path: support accelerator via CollationManager

- Status: open
- Category: consensus
- Source: validator/consensus/bridge.cpp:34 (commit ad9b48a72)
- Origin: upstream-TON
- Original comment:
  > // TODO: support accelerator (use CollationManager)
- Context: `collate_block` always invokes `run_collate_query`
  directly. The accelerator-aware path should route through
  `CollationManager` when accelerator features are enabled in
  validator opts.
- Suggested resolution: branch on
  `opts_->get_collator_options().use_accelerator()` and dispatch
  through `collation_manager_` for that case.

### V-023: implement get_validator_group_info_for_litequery

- Status: resolved
- Category: consensus
- Source: validator/consensus/bridge.cpp:205 (commit ad9b48a72)
- Origin: tos-owned
- Original comment:
  > // TODO
- Context: The lite server hook
  `get_validator_group_info_for_litequery` returns
  `Status::Error("Not implemented")`. Lite clients querying
  non-finalized validator group info will see this error.
- Resolution: Added `QueryValidatorGroupInfo` request to
  `simplex::Bus`. `PoolImpl` handles it: returns per-candidate
  `notarize_weight`/`finalize_weight` from the active slot plus
  the last-finalized `CandidateId`. `PoolImpl` also subscribes
  to `CandidateReceived` to cache `CandidateRef` objects for
  hash-data extraction. `BridgeImpl` now launches a coroutine
  that queries the Pool, then resolves the chain state via
  `ResolveState(last_finalized_block)` for `prev_block_ids` and
  `next_seqno`, and assembles the TL response.

### V-024: pass max response size from caller in private-overlay request

- Status: resolved
- Category: consensus
- Source: validator/consensus/private-overlay.cpp:105 (commit ad9b48a72)
- Origin: tos-owned
- Original comment:
  > // FIXME: Pass max response size from the caller.
- Context: `OutgoingOverlayRequest::process` hard-codes the
  per-request maximum response size as
  `max_block_size + max_collated_data_size + (1 << 20)`.
  Different request kinds have different reasonable size
  bounds; the caller should choose.
- Resolution: Added `td::uint32 max_response_size` field to
  `OutgoingOverlayRequest` in `validator/consensus/bus.h`.
  `PrivateOverlayImpl::process(OutgoingOverlayRequest)` now
  passes `message->max_response_size` to `send_query_via`.
  The only caller (`CandidateResolverImpl` in
  `validator/consensus/simplex/candidate-resolver.cpp`) passes
  `bus.config.max_block_size + bus.config.max_collated_data_size
  + (1 << 20)`, preserving the existing behaviour while
  enabling per-request overrides in the future.

### V-025: produce MisbehaviorProof on broadcast deserialization failure

- Status: resolved
- Category: consensus
- Source: validator/consensus/private-overlay.cpp:206 (commit ad9b48a72)
- Origin: tos-owned
- Resolution: Added `simplex::MalformedBroadcast` to `simplex/misbehavior.h`
  carrying the raw broadcast bytes, the sender's `PeerValidatorId`, and the
  parse error string.  On deserialization failure in
  `private-overlay.cpp::on_overlay_broadcast`, the raw bytes are cloned before
  the `Candidate::deserialize` call; on error a `MisbehaviorReport` is
  published to the bus exactly like V-018/V-019/V-020.

### V-026: refine ReadFile error mapping

- Status: open
- Category: db
- Source: validator/db/files-async.hpp:109 (commit ad9b48a72)
- Origin: upstream-TON
- Original comment:
  > // TODO check error code
- Context: `ReadFile::start_up` maps every `td::read_file` error
  to `ErrorCode::notready` with the message "file does not
  exist". Real I/O errors (permission denied, EIO, etc.) are
  reported as missing files.
- Suggested resolution: dispatch on the underlying error code so
  permission/IO errors propagate distinctly from "file missing".

### V-027: long-tail shard signature support in McBlockExtra

- Status: open
- Category: collator
- Source: validator/impl/collator.cpp:6251 (commit ad9b48a72)
- Origin: upstream-TON
- Original comment:
  > && cb2.store_long_bool(0, 1)
  > // ^[ TODO: prev_blk_signatures:(HashmapE 16 CryptoSignature)
- Context: When constructing `McBlockExtra`, the
  `prev_blk_signatures` field is always written as the
  zero-bit (empty `HashmapE 16 CryptoSignature`). The TL-B
  schema reserves the slot but the collator never populates it.
- Suggested resolution: collect previous-block masterchain
  signatures (if available from the validator group) and serialize
  them when present.

### V-028: wire MisbehaviorReport proofs to the masterchain

- Status: partially resolved
- Category: consensus
- Source: validator/consensus/bus.h:124 (MisbehaviorReport struct)
- Origin: tos-owned
- Context: V-018/V-019/V-020/V-025 publish `MisbehaviorReport` to the
  consensus bus but no subscriber consumed these reports.  Without a
  consumer, evidence of validator equivocation and slot inversion was
  silently discarded.
- Resolution: Added `MisbehaviorReporter` actor in
  `validator/consensus/misbehavior-reporter.cpp`.  On every
  `MisbehaviorReport` event the actor:
  1. Emits a structured `LOG(ERROR)` with validator key-hash,
     ADNL id, session id, misbehavior kind, and proof byte-count.
  2. Builds a compact 99-byte evidence cell (opcode 0xd1,
     validator_pubkey, session_id, kind, SHA-256 of proof bytes).
  3. Calls `ManagerFacade::send_misbehavior_report` which forwards
     the cell to `ValidatorManager::new_external_message_broadcast`.
     The evidence enters the normal external-message queue and is
     included in the next masterchain block.
  Added `send_misbehavior_report` virtual method to `ManagerFacade`
  (default: no-op) and implemented it in `ManagerFacadeImpl` in
  `bridge.cpp`.  Added public `td::Slice` accessors to all six
  concrete `Misbehavior` subclasses in `simplex/misbehavior.h`.
  `MisbehaviorReporter::register_in` is called from
  `BridgeImpl::start_up` alongside the other consensus actors.
- Remaining work (on-chain slashing): the elector contract does not
  yet have a `report_simplex_misbehavior` entry point.  Once
  deployed, replace the opcode-0xd1 cell with a full
  `ValidatorComplaint` (block.tlb:877) addressed to config param #1
  (elector address).  The `send_misbehavior_report` plumbing path
  requires no changes — only the cell builder in
  `misbehavior-reporter.cpp` needs updating.
