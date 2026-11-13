// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// Offline ValidateQuery (validate-offline.hpp): a test-only validator manager that serves the inputs of
// one validation from memory, and a single-threaded actor scheduler that runs the node's own
// run_validate_query until it reports.
//
// Served (validator/impl/validate-query.cpp is the only client):
//   get_top_masterchain_state_block    the state of Request::top_masterchain
//   get_block_handle                   a handle with an initialized proof, for a block whose state is supplied
//   wait_block_state(_short)           the supplied state of the block
//   wait_block_message_queue_short     the message queue of the supplied state of the block
//   get_out_msg_queue_size             the entries of that queue, counted as the node's queue-size counter does
//   wait_verify_shard_blocks           accepted, as the interface's default (shard blocks are not re-verified)
//   get_storage_stat_cache             refused, as the interface's default (no cache; storage is read from state)
//   set_block_candidate                never called: candidates are not stored (skip_store_candidate)
// Every other request fails its promise and is recorded, so an input this manager does not serve is never
// answered with something invented.
#include <cstdlib>
#include <mutex>
#include <set>
#include <utility>

#include "block/block-auto.h"
#include "block/block-db.h"
#include "block/block-parse.h"
#include "common/errorlog.h"
#include "td/actor/actor.h"
#include "td/utils/Time.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"
#include "validator/db/celldb.hpp"
#include "validator/fabric.h"
#include "validator/impl/shard.hpp"
#include "validator/interfaces/validator-manager.h"
#include "vm/dict.h"

#include "validate-offline.hpp"

namespace tos::validator {
namespace {

// Recorded by the manager, read by the caller after the scheduler has stopped (one thread throughout).
struct ManagerRecord {
  std::vector<BlockIdExt> states_requested;
  std::vector<std::string> unserved;
};

// Entries of a state's outbound message queue, the count validator/queue-size-counter.cpp computes.
td::Result<td::uint64> count_queue(const td::Ref<ShardState> &state) {
  td::uint64 size = 0;
  TRY_RESULT(queue_descr, state->message_queue());
  block::gen::OutMsgQueueInfo::Record info;
  if (!tlb::unpack_cell(queue_descr->root_cell(), info)) {
    return td::Status::Error("invalid message queue");
  }
  vm::AugmentedDictionary queue{info.out_queue->prefetch_ref(0), 352, block::tlb::aug_OutMsgQueue};
  if (!queue.check_for_each([&](td::Ref<vm::CellSlice>, td::ConstBitPtr, int) {
        ++size;
        return true;
      })) {
    return td::Status::Error("invalid message queue dict");
  }
  return size;
}

class OfflineManager final : public ValidatorManager {
 public:
  OfflineManager(std::map<BlockIdExt, td::Ref<vm::Cell>> states, BlockIdExt top, std::shared_ptr<ManagerRecord> record)
      : states_(std::move(states)), top_(top), record_(std::move(record)) {
  }

  void get_top_masterchain_state_block(td::Promise<std::pair<td::Ref<MasterchainState>, BlockIdExt>> promise) override {
    auto state = load(top_);
    if (state.is_error()) {
      promise.set_error(state.move_as_error());
      return;
    }
    promise.set_value({td::Ref<MasterchainState>(state.move_as_ok()), top_});
  }
  void get_block_handle(BlockIdExt block_id, bool force, td::Promise<BlockHandle> promise) override {
    if (states_.count(block_id) == 0) {
      promise.set_error(unserved("get_block_handle"));
      return;
    }
    auto handle = create_empty_block_handle(block_id);
    // The supplied state stands for a block the node has applied, whose proof it holds.
    handle->set_proof();
    // Nothing is written to a database here: the handle counts as flushed.
    handle->flushed_upto(handle->version());
    promise.set_value(std::move(handle));
  }
  void wait_block_state(BlockHandle handle, td::uint32 priority, td::Timestamp timeout, bool wait_store,
                        td::Promise<td::Ref<ShardState>> promise) override {
    promise.set_result(load(handle->id()));
  }
  void wait_block_state_short(BlockIdExt block_id, td::uint32 priority, td::Timestamp timeout, bool wait_store,
                              td::Promise<td::Ref<ShardState>> promise) override {
    promise.set_result(load(block_id));
  }
  void wait_block_message_queue_short(BlockIdExt id, td::uint32 priority, td::Timestamp timeout,
                                      td::Promise<td::Ref<MessageQueue>> promise) override {
    auto state = load(id);
    if (state.is_error()) {
      promise.set_error(state.move_as_error());
      return;
    }
    promise.set_result(state.ok()->message_queue());
  }
  void get_out_msg_queue_size(BlockIdExt block_id, td::Promise<td::uint64> promise) override {
    auto state = load(block_id);
    if (state.is_error()) {
      promise.set_error(state.move_as_error());
      return;
    }
    promise.set_result(count_queue(state.ok()));
  }
  void set_block_candidate(BlockIdExt id, BlockCandidate candidate, CatchainSeqno cc_seqno,
                           td::uint32 validator_set_hash, bool cache_only, td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("set_block_candidate"));
  }
  void add_perf_timer_stat(std::string name, double duration) override {
  }

  // Not used by ValidateQuery: refused, and recorded.
  td::actor::Task<> new_external_message_broadcast(td::BufferSlice data, int priority,
                                                   td::optional<PublicKeyHash> source_peer) override {
    co_return unserved("new_external_message_broadcast");
  }
  void install_callback(std::unique_ptr<Callback> new_callback, td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("install_callback"));
  }
  void add_permanent_key(PublicKeyHash key, td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("add_permanent_key"));
  }
  void add_temp_key(PublicKeyHash key, td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("add_temp_key"));
  }
  void add_pq_consensus_key(tos::ValidatorId validator_id, std::shared_ptr<const tos::pq::ValidatorPQKeyStore> store,
                            td::uint32 valid_from, td::uint32 expire_at, td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("add_pq_consensus_key"));
  }
  void del_pq_consensus_key(tos::ValidatorId validator_id, tos::ConsensusKeyId key_id,
                            td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("del_pq_consensus_key"));
  }
  void del_permanent_key(PublicKeyHash key, td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("del_permanent_key"));
  }
  void del_temp_key(PublicKeyHash key, td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("del_temp_key"));
  }
  void validate_block_is_next_proof(BlockIdExt prev_block_id, BlockIdExt next_block_id, td::BufferSlice proof,
                                    td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("validate_block_is_next_proof"));
  }
  void validate_block_proof(BlockIdExt block_id, td::BufferSlice proof, td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("validate_block_proof"));
  }
  void validate_block_proof_link(BlockIdExt block_id, td::BufferSlice proof, td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("validate_block_proof_link"));
  }
  void validate_block_proof_rel(BlockIdExt block_id, BlockIdExt rel_block_id, td::BufferSlice proof,
                                td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("validate_block_proof_rel"));
  }
  void validate_block(ReceivedBlock block, td::Promise<BlockHandle> promise) override {
    promise.set_error(unserved("validate_block"));
  }
  void new_block_broadcast(BlockBroadcast broadcast, bool signatures_checked, BroadcastSource source,
                           td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("new_block_broadcast"));
  }
  void validate_block_broadcast_signatures(BlockBroadcast broadcast, td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("validate_block_broadcast_signatures"));
  }
  void sync_complete(td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("sync_complete"));
  }
  void get_top_masterchain_state(td::Promise<td::Ref<MasterchainState>> promise) override {
    promise.set_error(unserved("get_top_masterchain_state"));
  }
  void get_top_masterchain_block(td::Promise<BlockIdExt> promise) override {
    promise.set_error(unserved("get_top_masterchain_block"));
  }
  void get_last_liteserver_state_block(td::Promise<std::pair<td::Ref<MasterchainState>, BlockIdExt>> promise) override {
    promise.set_error(unserved("get_last_liteserver_state_block"));
  }
  void get_shard_client_state_block(td::Promise<std::pair<td::Ref<MasterchainState>, BlockIdExt>> promise) override {
    promise.set_error(unserved("get_shard_client_state_block"));
  }
  void get_node_consensus_status(td::Promise<NodeConsensusStatus> promise) override {
    promise.set_error(unserved("get_node_consensus_status"));
  }
  void get_block_data(BlockHandle handle, td::Promise<td::BufferSlice> promise) override {
    promise.set_error(unserved("get_block_data"));
  }
  void check_zero_state_exists(BlockIdExt block_id, td::Promise<bool> promise) override {
    promise.set_error(unserved("check_zero_state_exists"));
  }
  void get_zero_state(BlockIdExt block_id, td::Promise<td::BufferSlice> promise) override {
    promise.set_error(unserved("get_zero_state"));
  }
  void get_persistent_state_size(BlockIdExt block_id, BlockIdExt masterchain_block_id, PersistentStateType type,
                                 td::Promise<td::uint64> promise) override {
    promise.set_error(unserved("get_persistent_state_size"));
  }
  void get_persistent_state(BlockIdExt block_id, BlockIdExt masterchain_block_id, PersistentStateType type,
                            td::Promise<td::BufferSlice> promise) override {
    promise.set_error(unserved("get_persistent_state"));
  }
  void get_persistent_state_slice(BlockIdExt block_id, BlockIdExt masterchain_block_id, PersistentStateType type,
                                  td::int64 offset, td::int64 max_length,
                                  td::Promise<td::BufferSlice> promise) override {
    promise.set_error(unserved("get_persistent_state_slice"));
  }
  void get_previous_persistent_state_files(
      BlockSeqno cur_mc_seqno, td::Promise<std::vector<std::pair<std::string, ShardIdFull>>> promise) override {
    promise.set_error(unserved("get_previous_persistent_state_files"));
  }
  void get_block_proof(BlockHandle handle, td::Promise<td::BufferSlice> promise) override {
    promise.set_error(unserved("get_block_proof"));
  }
  void get_block_proof_link(BlockHandle handle, td::Promise<td::BufferSlice> promise) override {
    promise.set_error(unserved("get_block_proof_link"));
  }
  void get_key_block_proof(BlockIdExt block_id, td::Promise<td::BufferSlice> promise) override {
    promise.set_error(unserved("get_key_block_proof"));
  }
  void get_key_block_proof_link(BlockIdExt block_id, td::Promise<td::BufferSlice> promise) override {
    promise.set_error(unserved("get_key_block_proof_link"));
  }
  void get_next_key_blocks(BlockIdExt block_id, td::uint32 cnt, td::Promise<std::vector<BlockIdExt>> promise) override {
    promise.set_error(unserved("get_next_key_blocks"));
  }
  void get_next_block(BlockIdExt block_id, td::Promise<BlockHandle> promise) override {
    promise.set_error(unserved("get_next_block"));
  }
  void write_handle(BlockHandle handle, td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("write_handle"));
  }
  void new_ihr_message(td::BufferSlice data) override {
    note_unserved("new_ihr_message");
  }
  void new_shard_block_description_broadcast(BlockIdExt block_id, CatchainSeqno cc_seqno,
                                             td::BufferSlice data) override {
    note_unserved("new_shard_block_description_broadcast");
  }
  void add_ext_server_id(adnl::AdnlNodeIdShort id) override {
    note_unserved("add_ext_server_id");
  }
  void add_ext_server_port(td::uint16 port) override {
    note_unserved("add_ext_server_port");
  }
  void get_download_token(size_t download_size, td::uint32 priority, td::Timestamp timeout,
                          td::Promise<std::unique_ptr<ActionToken>> promise) override {
    promise.set_error(unserved("get_download_token"));
  }
  void get_block_data_from_db(ConstBlockHandle handle, td::Promise<td::Ref<BlockData>> promise) override {
    promise.set_error(unserved("get_block_data_from_db"));
  }
  void get_block_data_from_db_short(BlockIdExt block_id, td::Promise<td::Ref<BlockData>> promise) override {
    promise.set_error(unserved("get_block_data_from_db_short"));
  }
  void get_block_candidate_from_db(ValidatorId source, BlockIdExt id, FileHash collated_data_file_hash,
                                   td::Promise<BlockCandidate> promise) override {
    promise.set_error(unserved("get_block_candidate_from_db"));
  }
  void get_candidate_data_by_block_id_from_db(BlockIdExt id, td::Promise<td::BufferSlice> promise) override {
    promise.set_error(unserved("get_candidate_data_by_block_id_from_db"));
  }
  void get_shard_state_from_db(ConstBlockHandle handle, td::Promise<td::Ref<ShardState>> promise) override {
    promise.set_error(unserved("get_shard_state_from_db"));
  }
  void get_shard_state_from_db_short(BlockIdExt block_id, td::Promise<td::Ref<ShardState>> promise) override {
    promise.set_error(unserved("get_shard_state_from_db_short"));
  }
  void get_block_proof_from_db(ConstBlockHandle handle, td::Promise<td::Ref<Proof>> promise) override {
    promise.set_error(unserved("get_block_proof_from_db"));
  }
  void get_block_proof_from_db_short(BlockIdExt id, td::Promise<td::Ref<Proof>> promise) override {
    promise.set_error(unserved("get_block_proof_from_db_short"));
  }
  void get_block_proof_link_from_db(ConstBlockHandle handle, td::Promise<td::Ref<ProofLink>> promise) override {
    promise.set_error(unserved("get_block_proof_link_from_db"));
  }
  void get_block_proof_link_from_db_short(BlockIdExt id, td::Promise<td::Ref<ProofLink>> promise) override {
    promise.set_error(unserved("get_block_proof_link_from_db_short"));
  }
  void get_block_by_lt_from_db(AccountIdPrefixFull account, LogicalTime lt,
                               td::Promise<ConstBlockHandle> promise) override {
    promise.set_error(unserved("get_block_by_lt_from_db"));
  }
  void get_block_by_unix_time_from_db(AccountIdPrefixFull account, UnixTime ts,
                                      td::Promise<ConstBlockHandle> promise) override {
    promise.set_error(unserved("get_block_by_unix_time_from_db"));
  }
  void get_block_by_seqno_from_db(AccountIdPrefixFull account, BlockSeqno seqno,
                                  td::Promise<ConstBlockHandle> promise) override {
    promise.set_error(unserved("get_block_by_seqno_from_db"));
  }
  void wait_block_state_merge(BlockIdExt left_id, BlockIdExt right_id, td::uint32 priority, td::Timestamp timeout,
                              td::Promise<td::Ref<ShardState>> promise) override {
    promise.set_error(unserved("wait_block_state_merge"));
  }
  void wait_state_by_prev_blocks(BlockIdExt block_id, std::vector<BlockIdExt> prev_blocks,
                                 td::Promise<td::Ref<ShardState>> promise) override {
    promise.set_error(unserved("wait_state_by_prev_blocks"));
  }
  void wait_neighbor_msg_queue_proofs(ShardIdFull dst_shard, std::vector<BlockIdExt> blocks, td::Timestamp timeout,
                                      td::Promise<std::map<BlockIdExt, td::Ref<OutMsgQueueProof>>> promise) override {
    promise.set_error(unserved("wait_neighbor_msg_queue_proofs"));
  }
  void get_archive_id(BlockSeqno masterchain_seqno, ShardIdFull shard_prefix,
                      td::Promise<td::uint64> promise) override {
    promise.set_error(unserved("get_archive_id"));
  }
  void get_archive_slice(td::uint64 archive_id, td::uint64 offset, td::uint32 limit,
                         td::Promise<td::BufferSlice> promise) override {
    promise.set_error(unserved("get_archive_slice"));
  }
  void run_ext_query(adnl::AdnlNodeIdShort source, td::BufferSlice data,
                     td::Promise<td::BufferSlice> promise) override {
    promise.set_error(unserved("run_ext_query"));
  }
  void prepare_stats(td::Promise<std::vector<std::pair<std::string, std::string>>> promise) override {
    promise.set_error(unserved("prepare_stats"));
  }
  void prepare_actor_stats(td::Promise<std::string> promise) override {
    promise.set_error(unserved("prepare_actor_stats"));
  }
  void prepare_perf_timer_stats(td::Promise<std::vector<PerfTimerStats>> promise) override {
    promise.set_error(unserved("prepare_perf_timer_stats"));
  }
  void update_options(td::Ref<ValidatorManagerOptions> opts) override {
    note_unserved("update_options");
  }
  void add_collator(adnl::AdnlNodeIdShort id, ShardIdFull shard) override {
    note_unserved("add_collator");
  }
  void del_collator(adnl::AdnlNodeIdShort id, ShardIdFull shard) override {
    note_unserved("del_collator");
  }
  void get_collation_manager_stats(
      td::Promise<tl_object_ptr<tos_api::engine_validator_collationManagerStats>> promise) override {
    promise.set_error(unserved("get_collation_manager_stats"));
  }
  void set_block_state(BlockHandle handle, td::Ref<ShardState> state, vm::StoreCellHint hint,
                       td::Promise<td::Ref<ShardState>> promise) override {
    promise.set_error(unserved("set_block_state"));
  }
  void store_block_state_part(BlockId effective_block, td::Ref<vm::Cell> cell,
                              td::Promise<td::Ref<vm::DataCell>> promise) override {
    promise.set_error(unserved("store_block_state_part"));
  }
  void set_block_state_from_data(BlockHandle handle, td::Ref<BlockData> block,
                                 td::Promise<td::Ref<ShardState>> promise) override {
    promise.set_error(unserved("set_block_state_from_data"));
  }
  void set_block_state_from_data_bulk(std::vector<td::Ref<BlockData>> blocks, td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("set_block_state_from_data_bulk"));
  }
  void get_cell_db_reader(td::Promise<std::shared_ptr<vm::CellDbReader>> promise) override {
    promise.set_error(unserved("get_cell_db_reader"));
  }
  void create_celldb_streaming_writer_unsafe_for_tests_only(
      td::Promise<std::unique_ptr<CellDbStreamingWriter>> promise) override {
    promise.set_error(unserved("create_celldb_streaming_writer_unsafe_for_tests_only"));
  }
  void import_persistent_state_streaming(PersistentStateImportRequest request,
                                         td::Promise<PersistentStateImportResult> promise) override {
    promise.set_error(unserved("import_persistent_state_streaming"));
  }
  void store_persistent_state_file(BlockIdExt block_id, BlockIdExt masterchain_block_id, PersistentStateType type,
                                   td::BufferSlice state, td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("store_persistent_state_file"));
  }
  void store_persistent_state_file_gen(BlockIdExt block_id, BlockIdExt masterchain_block_id, PersistentStateType type,
                                       std::function<td::Status(td::FileFd &)> write_data,
                                       td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("store_persistent_state_file_gen"));
  }
  void store_zero_state_file(BlockIdExt block_id, td::BufferSlice state, td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("store_zero_state_file"));
  }
  void store_zero_state_file_gen(BlockIdExt block_id, std::function<td::Status(td::FileFd &)> write_data,
                                 td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("store_zero_state_file_gen"));
  }
  void set_block_data(BlockHandle handle, td::Ref<BlockData> data, td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("set_block_data"));
  }
  void wait_block_data(BlockHandle handle, td::uint32 priority, td::Timestamp,
                       td::Promise<td::Ref<BlockData>> promise) override {
    promise.set_error(unserved("wait_block_data"));
  }
  void wait_block_data_short(BlockIdExt block_id, td::uint32 priority, td::Timestamp,
                             td::Promise<td::Ref<BlockData>> promise) override {
    promise.set_error(unserved("wait_block_data_short"));
  }
  void set_block_proof(BlockHandle handle, td::Ref<Proof> proof, td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("set_block_proof"));
  }
  void wait_block_proof(BlockHandle handle, td::Timestamp timeout, td::Promise<td::Ref<Proof>> promise) override {
    promise.set_error(unserved("wait_block_proof"));
  }
  void wait_block_proof_short(BlockIdExt id, td::Timestamp timeout, td::Promise<td::Ref<Proof>> promise) override {
    promise.set_error(unserved("wait_block_proof_short"));
  }
  void set_block_proof_link(BlockHandle handle, td::Ref<ProofLink> proof, td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("set_block_proof_link"));
  }
  void wait_block_proof_link(BlockHandle handle, td::Timestamp timeout,
                             td::Promise<td::Ref<ProofLink>> promise) override {
    promise.set_error(unserved("wait_block_proof_link"));
  }
  void wait_block_proof_link_short(BlockIdExt id, td::Timestamp timeout,
                                   td::Promise<td::Ref<ProofLink>> promise) override {
    promise.set_error(unserved("wait_block_proof_link_short"));
  }
  void set_block_signatures(BlockHandle handle, td::Ref<block::BlockSignatureSet> signatures,
                            Ref<block::ValidatorSet> vset, td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("set_block_signatures"));
  }
  void wait_block_signatures(BlockHandle handle, td::Timestamp timeout,
                             td::Promise<td::Ref<block::BlockSignatureSet>> promise) override {
    promise.set_error(unserved("wait_block_signatures"));
  }
  void wait_block_signatures_short(BlockIdExt id, td::Timestamp timeout,
                                   td::Promise<td::Ref<block::BlockSignatureSet>> promise) override {
    promise.set_error(unserved("wait_block_signatures_short"));
  }
  void send_block_candidate_broadcast(BlockIdExt id, CatchainSeqno cc_seqno, td::uint32 validator_set_hash,
                                      td::BufferSlice data, int mode) override {
    note_unserved("send_block_candidate_broadcast");
  }
  void wait_prev_block_state(BlockHandle handle, td::uint32 priority, td::Timestamp timeout,
                             td::Promise<td::Ref<ShardState>> promise) override {
    promise.set_error(unserved("wait_prev_block_state"));
  }
  void wait_block_message_queue(BlockHandle handle, td::uint32 priority, td::Timestamp timeout,
                                td::Promise<td::Ref<MessageQueue>> promise) override {
    promise.set_error(unserved("wait_block_message_queue"));
  }
  void get_external_messages(ShardIdFull shard, std::unique_ptr<ExtMsgCallback> callback) override {
    note_unserved("get_external_messages");
  }
  void get_ihr_messages(ShardIdFull shard, td::Promise<std::vector<td::Ref<IhrMessage>>> promise) override {
    promise.set_error(unserved("get_ihr_messages"));
  }
  void get_shard_blocks_for_collator(BlockIdExt masterchain_block_id,
                                     td::Promise<std::vector<td::Ref<ShardTopBlockDescription>>> promise) override {
    promise.set_error(unserved("get_shard_blocks_for_collator"));
  }
  void cleanup_applied_external_messages(BlockHandle handle, td::Ref<BlockData> block) override {
    note_unserved("cleanup_applied_external_messages");
  }
  void complete_ihr_messages(std::vector<IhrMessage::Hash> to_delay, std::vector<IhrMessage::Hash> to_delete) override {
    note_unserved("complete_ihr_messages");
  }
  void set_next_block(BlockIdExt prev, BlockIdExt next, td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("set_next_block"));
  }
  void new_block(BlockHandle handle, td::Ref<ShardState> state, td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("new_block"));
  }
  void send_get_block_request(BlockIdExt id, td::uint32 priority, td::Promise<ReceivedBlock> promise) override {
    promise.set_error(unserved("send_get_block_request"));
  }
  void send_get_zero_state_request(BlockIdExt id, td::uint32 priority,
                                   td::Promise<fullnode::DownloadedPersistentState> promise) override {
    promise.set_error(unserved("send_get_zero_state_request"));
  }
  void send_get_persistent_state_request(BlockIdExt id, BlockIdExt masterchain_block_id, PersistentStateType type,
                                         td::uint32 priority,
                                         td::Promise<fullnode::DownloadedPersistentState> promise) override {
    promise.set_error(unserved("send_get_persistent_state_request"));
  }
  void send_get_block_proof_request(BlockIdExt block_id, td::uint32 priority,
                                    td::Promise<td::BufferSlice> promise) override {
    promise.set_error(unserved("send_get_block_proof_request"));
  }
  void send_get_block_proof_link_request(BlockIdExt block_id, td::uint32 priority,
                                         td::Promise<td::BufferSlice> promise) override {
    promise.set_error(unserved("send_get_block_proof_link_request"));
  }
  void send_get_next_key_blocks_request(BlockIdExt block_id, td::uint32 priority,
                                        td::Promise<std::vector<BlockIdExt>> promise) override {
    promise.set_error(unserved("send_get_next_key_blocks_request"));
  }
  void send_ihr_message(td::Ref<IhrMessage> message) override {
    note_unserved("send_ihr_message");
  }
  void send_top_shard_block_description(td::Ref<ShardTopBlockDescription> desc) override {
    note_unserved("send_top_shard_block_description");
  }
  void send_block_broadcast(BlockBroadcast broadcast, int mode) override {
    note_unserved("send_block_broadcast");
  }
  void send_block_finality_broadcast(BlockFinalityBroadcast finality, int mode) override {
    note_unserved("send_block_finality_broadcast");
  }
  void send_get_out_msg_queue_proof_request(ShardIdFull dst_shard, std::vector<BlockIdExt> blocks,
                                            block::ImportedMsgQueueLimits limits,
                                            td::Promise<std::vector<td::Ref<OutMsgQueueProof>>> promise) override {
    promise.set_error(unserved("send_get_out_msg_queue_proof_request"));
  }
  void send_download_archive_request(BlockSeqno mc_seqno, ShardIdFull shard_prefix, std::string tmp_dir,
                                     td::Timestamp timeout, td::Promise<std::string> promise) override {
    promise.set_error(unserved("send_download_archive_request"));
  }
  void update_shard_client_state(BlockIdExt masterchain_block_id, td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("update_shard_client_state"));
  }
  void get_shard_client_state(bool from_db, td::Promise<BlockIdExt> promise) override {
    promise.set_error(unserved("get_shard_client_state"));
  }
  void update_async_serializer_state(AsyncSerializerState state, td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("update_async_serializer_state"));
  }
  void get_async_serializer_state(td::Promise<AsyncSerializerState> promise) override {
    promise.set_error(unserved("get_async_serializer_state"));
  }
  void try_get_static_file(FileHash file_hash, td::Promise<td::BufferSlice> promise) override {
    promise.set_error(unserved("try_get_static_file"));
  }
  void allow_block_state_gc(BlockIdExt block_id, td::Promise<bool> promise) override {
    promise.set_error(unserved("allow_block_state_gc"));
  }
  void archive(BlockHandle handle, td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("archive"));
  }
  void check_is_hardfork(BlockIdExt block_id, td::Promise<bool> promise) override {
    promise.set_error(unserved("check_is_hardfork"));
  }
  void get_vertical_seqno(BlockSeqno seqno, td::Promise<td::uint32> promise) override {
    promise.set_error(unserved("get_vertical_seqno"));
  }
  void update_last_known_key_block(BlockHandle handle, bool send_request) override {
    note_unserved("update_last_known_key_block");
  }
  void update_gc_block_handle(BlockHandle handle, td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("update_gc_block_handle"));
  }
  void update_shard_client_block_handle(BlockHandle handle, td::Ref<MasterchainState> state,
                                        td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("update_shard_client_block_handle"));
  }
  void truncate(BlockSeqno seqno, ConstBlockHandle handle, td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("truncate"));
  }
  void wait_shard_client_state(BlockSeqno seqno, td::Timestamp timeout, td::Promise<td::Unit> promise) override {
    promise.set_error(unserved("wait_shard_client_state"));
  }
  void get_block_handle_for_litequery(BlockIdExt block_id, td::Promise<ConstBlockHandle> promise) override {
    promise.set_error(unserved("get_block_handle_for_litequery"));
  }
  void get_block_data_for_litequery(BlockIdExt block_id, td::Promise<td::Ref<BlockData>> promise) override {
    promise.set_error(unserved("get_block_data_for_litequery"));
  }
  void get_block_state_for_litequery(BlockIdExt block_id, td::Promise<td::Ref<ShardState>> promise) override {
    promise.set_error(unserved("get_block_state_for_litequery"));
  }
  void get_block_by_lt_for_litequery(AccountIdPrefixFull account, LogicalTime lt,
                                     td::Promise<ConstBlockHandle> promise) override {
    promise.set_error(unserved("get_block_by_lt_for_litequery"));
  }
  void get_block_by_unix_time_for_litequery(AccountIdPrefixFull account, UnixTime ts,
                                            td::Promise<ConstBlockHandle> promise) override {
    promise.set_error(unserved("get_block_by_unix_time_for_litequery"));
  }
  void get_block_by_seqno_for_litequery(AccountIdPrefixFull account, BlockSeqno seqno,
                                        td::Promise<ConstBlockHandle> promise) override {
    promise.set_error(unserved("get_block_by_seqno_for_litequery"));
  }
  void get_block_candidate_for_litequery(ValidatorId source, BlockIdExt block_id, FileHash collated_data_hash,
                                         td::Promise<BlockCandidate> promise) override {
    promise.set_error(unserved("get_block_candidate_for_litequery"));
  }
  void get_validator_groups_info_for_litequery(
      td::optional<ShardIdFull> shard,
      td::Promise<tl_object_ptr<lite_api::liteServer_nonfinal_validatorGroups>> promise) override {
    promise.set_error(unserved("get_validator_groups_info_for_litequery"));
  }
  void add_persistent_state_description(td::Ref<PersistentStateDescription> desc) override {
    note_unserved("add_persistent_state_description");
  }

 private:
  std::map<BlockIdExt, td::Ref<vm::Cell>> states_;
  BlockIdExt top_;
  std::shared_ptr<ManagerRecord> record_;

  td::Status unserved(const char *request) {
    record_->unserved.emplace_back(request);
    return td::Status::Error(ErrorCode::notready, PSLICE() << "offline validation input not served: " << request);
  }
  void note_unserved(const char *request) {
    record_->unserved.emplace_back(request);
  }
  td::Result<td::Ref<ShardState>> load(const BlockIdExt &block) {
    record_->states_requested.push_back(block);
    auto it = states_.find(block);
    if (it == states_.end()) {
      return td::Status::Error(ErrorCode::notready,
                               PSLICE() << "offline validation input not served: state of " << block.to_str());
    }
    return create_shard_state(block, it->second);
  }
};

}  // namespace
}  // namespace tos::validator

namespace conformance::validate {
namespace {

using tos::BlockIdExt;

// Upper bound of one validation; history blocks validate in well under a second.
constexpr double kTimeoutSeconds = 600.0;

// ValidateQuery records every rejection in the node's error log, which must be open. It goes to a
// private directory: CONFORMANCE_VALIDATE_ERRORLOG when set, else a fresh one under the temporary
// directory, removed when the process exits.
std::string errorlog_root;

void remove_errorlog() {
  if (!errorlog_root.empty()) {
    (void)td::rmrf(errorlog_root);
  }
}

td::Status open_errorlog() {
  static std::once_flag flag;
  static td::Status status;
  std::call_once(flag, [] {
    if (const char *dir = std::getenv("CONFORMANCE_VALIDATE_ERRORLOG"); dir != nullptr && *dir != 0) {
      auto made = td::mkpath(PSLICE() << dir << "/");
      if (made.is_error()) {
        status = std::move(made);
        return;
      }
      tos::errorlog::ErrorLog::create(dir);
      return;
    }
    auto dir = td::mkdtemp(td::get_temporary_dir(), "conformance-validate");
    if (dir.is_error()) {
      status = dir.move_as_error();
      return;
    }
    errorlog_root = dir.move_as_ok();
    std::atexit(remove_errorlog);
    tos::errorlog::ErrorLog::create(errorlog_root);
  });
  return status.clone();
}

}  // namespace

td::Result<Outcome> run(Request request) {
  TRY_STATUS(open_errorlog());
  std::map<BlockIdExt, td::Ref<vm::Cell>> states;
  for (auto &served : request.states) {
    if (served.root.is_null()) {
      return td::Status::Error(PSLICE() << "state of " << served.block.to_str() << " is null");
    }
    if (!states.emplace(served.block, std::move(served.root)).second) {
      return td::Status::Error(PSLICE() << "state of " << served.block.to_str() << " is supplied twice");
    }
  }
  // The validator group's set, as the manager computes it from its masterchain state.
  auto from = states.find(request.validator_set_from);
  if (!request.validator_set_from.is_masterchain() || from == states.end()) {
    return td::Status::Error("validator_set_from must name a supplied masterchain state");
  }
  td::Ref<block::ValidatorSet> validator_set;
  try {
    auto mc_state = tos::validator::MasterchainStateQ::fetch(request.validator_set_from, {}, from->second);
    if (mc_state.is_error()) {
      return mc_state.move_as_error_prefix("validator_set_from: ");
    }
    validator_set = mc_state.ok()->get_validator_set(request.candidate.shard_full());
  } catch (const vm::VmVirtError &error) {
    return td::Status::Error(PSLICE() << "validator_set_from: " << error.get_msg());
  } catch (const vm::VmError &error) {
    return td::Status::Error(PSLICE() << "validator_set_from: " << error.get_msg());
  }
  if (validator_set.is_null()) {
    return td::Status::Error("validator_set_from: no validator set for the candidate's shard");
  }

  tos::BlockCandidate candidate;
  candidate.producer = tos::ValidatorId{request.created_by};
  candidate.id = request.candidate;
  candidate.collated_file_hash = block::compute_file_hash(request.collated_data.as_slice());
  candidate.data = std::move(request.data);
  candidate.collated_data = std::move(request.collated_data);
  tos::validator::ValidateParams params{.shard = request.candidate.shard_full(),
                                        .min_masterchain_block_id = request.min_masterchain,
                                        .prev = std::move(request.prev),
                                        .validator_set = std::move(validator_set),
                                        .is_fake = request.skip_shard_signatures,
                                        .skip_store_candidate = true,
                                        .parallel_validation = false};

  auto record = std::make_shared<tos::validator::ManagerRecord>();
  Outcome outcome;
  bool done = false;
  {
    // No worker threads: every actor runs on this thread, in the order its messages were sent.
    td::actor::Scheduler scheduler({0});
    td::actor::ActorOwn<tos::validator::OfflineManager> manager;
    scheduler.run_in_context([&] {
      manager = td::actor::create_actor<tos::validator::OfflineManager>("offline-manager", std::move(states),
                                                                        request.top_masterchain, record);
      auto promise = td::PromiseCreator::lambda([&](td::Result<tos::validator::ValidateCandidateResult> result) {
        done = true;
        if (result.is_error()) {
          outcome.verdict = Verdict::error;
          outcome.error_code = result.error().code();
          outcome.message = result.error().message().str();
          return;
        }
        result.ok_ref().visit(td::overloaded(
            [&](const tos::validator::CandidateAccept &accept) {
              outcome.verdict = Verdict::accepted;
              outcome.ok_from_utime = accept.ok_from_utime;
            },
            [&](const tos::validator::CandidateReject &reject) {
              outcome.verdict = Verdict::rejected;
              outcome.message = reject.reason;
            }));
      });
      tos::validator::run_validate_query(std::move(candidate), std::move(params), manager.get(),
                                         td::Timestamp::in(kTimeoutSeconds), std::move(promise));
    });
    const double deadline = td::Time::now() + kTimeoutSeconds + 10;
    while (!done && td::Time::now() < deadline) {
      scheduler.run(0.1);
    }
    scheduler.run_in_context([&] { manager.reset(); });
  }
  if (!done) {
    return td::Status::Error("ValidateQuery did not report");
  }
  outcome.states_requested = std::move(record->states_requested);
  outcome.unserved = std::move(record->unserved);
  return outcome;
}

namespace {

struct Pattern {
  const char *needle;
  const char *reason;
};

// First match wins, so specific texts come before general ones. A message no entry matches is
// "unclassified": a new failure path shows up as that class until it is given its own.
const Pattern kPatterns[] = {
    // A cell the validation read is not in a supplied (partial) state. First: the validation wraps the
    // virtualization error's text in messages that would otherwise match a content class below.
    {"prunned branch", "pruned_input"},
    {"virtualization error", "pruned_input"},
    // The manager had no answer: a missing input, not a verdict on the block.
    {"offline validation input not served", "input_unavailable"},
    // The candidate and the parameters it is validated with.
    {"block candidate has invalid file hash", "candidate_id_mismatch"},
    {"block candidate has invalid root hash", "candidate_id_mismatch"},
    {"different from current shard", "shard_mismatch"},
    {"shard mismatch in the block header", "shard_mismatch"},
    {"sub-shards cannot exist in the masterchain", "shard_mismatch"},
    {"block header contains block id", "shard_mismatch"},
    {"previous blocks, but we are given", "prev_block_mismatch"},
    {"mismatch: expected", "prev_block_mismatch"},
    {"has creator", "creator_mismatch"},
    {"declares cc_seqno", "validator_set_mismatch"},
    {"declares validator set hash", "validator_set_mismatch"},
    // States.
    {"previous state hash mismatch", "prev_state_mismatch"},
    {"next state hash mismatch", "new_state_mismatch"},
    {"new state contains generation", "new_state_mismatch"},
    // Time and logical time.
    {"larger than the hard limit", "limit_exceeded"},
    {"exceeds hard limit", "limit_exceeded"},
    {"is not aligned", "utime_lt_invalid"},
    {"creation time", "utime_lt_invalid"},
    {"gen_utime", "utime_lt_invalid"},
    {"now_ms", "utime_lt_invalid"},
    {"start_lt", "utime_lt_invalid"},
    // Contents.
    {"ValueFlow", "value_flow_invalid"},
    {"AccountBlock", "account_update_invalid"},
    {"HASH_UPDATE", "account_update_invalid"},
    {"transaction", "transaction_invalid"},
    {"OutMsg", "message_invalid"},
    {"InMsg", "message_invalid"},
    {"message", "message_invalid"},
};

}  // namespace

const char *classify(const Outcome &outcome) {
  if (outcome.verdict == Verdict::accepted) {
    return "";
  }
  for (const auto &pattern : kPatterns) {
    if (outcome.message.find(pattern.needle) != std::string::npos) {
      return pattern.reason;
    }
  }
  return "unclassified";
}

const std::vector<std::string> &reason_classes() {
  static const std::vector<std::string> classes = [] {
    std::set<std::string> unique{"unclassified"};
    for (const auto &pattern : kPatterns) {
      unique.insert(pattern.reason);
    }
    return std::vector<std::string>(unique.begin(), unique.end());
  }();
  return classes;
}

}  // namespace conformance::validate
