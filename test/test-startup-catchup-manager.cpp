/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// The startup catch-up wiring of the production manager: the entry decision, the
// group fence in the group update, the exit reconciliation, the sync predicate after
// the mode, the verification entry of discovery, and prestart completion with the
// startup inventory of orphaned session directories. The manager runs its own code
// with a real RootDb; only its network-heavy startup, the group actors (counted by a
// fake) and the shard client start are substituted.

#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "adnl/adnl.h"
#include "block/validator-session-id.h"
#include "common/checksum.h"
#include "keyring/keyring.h"
#include "quic/quic-sender.h"
#include "rldp2/rldp.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"
#include "td/utils/tests.h"
#include "validator/consensus/db-path.h"
#include "validator/fabric.h"
#include "validator/impl/applied-ext-message-cleanup.hpp"
#include "validator/impl/ext-message-pool.hpp"
#include "validator/impl/shard.hpp"
#include "validator/manager.hpp"
#include "validator/validator-options.hpp"
#include "vm/cells.h"
#include "vm/dict.h"

namespace tos::validator {
namespace {

td::Bits256 hash(td::Slice value) {
  return td::sha256_bits256(value);
}

struct Epoch {
  std::vector<PrivateKey> transport;
  std::vector<std::shared_ptr<const pq::ValidatorPQKeyStore>> custody;
  std::vector<ValidatorDescr> members;
  explicit Epoch(int index, size_t count = 4) {
    for (size_t i = 0; i < count; ++i) {
      auto label = PSTRING() << "startup-catchup-epoch-" << index << "-" << i;
      transport.push_back(PrivateKey{privkeys::Ed25519::random()});
      auto store = pq::ValidatorPQKeyStore::from_seed(hash(label).as_slice().str());
      CHECK(store);
      custody.push_back(std::make_shared<const pq::ValidatorPQKeyStore>(std::move(*store)));
      const auto& key = custody.back()->consensus_key();
      td::Bits256 key_id;
      key_id.as_slice().copy_from(td::Slice(key.key_id.data(), key.key_id.size()));
      members.emplace_back(ValidatorId{hash(PSTRING() << label << "-validator")},
                           static_cast<td::uint16>(key.algorithm_id), ConsensusKeyId{key_id}, key.public_key, 1,
                           transport.back().compute_public_key().compute_short_id().bits256_value());
    }
  }
  td::Ref<block::ValidatorSet> set(CatchainSeqno cc) const {
    return td::make_ref<block::ValidatorSet>(cc, ShardIdFull{masterchainId}, std::vector<ValidatorDescr>(members));
  }
  // The same consensus key as member `i`, with a signing deadline.
  std::shared_ptr<const pq::ValidatorPQKeyStore> windowed(int index, size_t i, td::uint32 expire_at) const {
    auto label = PSTRING() << "startup-catchup-epoch-" << index << "-" << i;
    auto store = pq::ValidatorPQKeyStore::from_seed(hash(label).as_slice().str());
    CHECK(store);
    auto shared = std::make_shared<pq::ValidatorPQKeyStore>(std::move(*store));
    shared->set_expire_at(expire_at);
    return shared;
  }
};

// A shard of the workchain configuration: its catchain counter and its split/merge state.
// `fsm_in` places the state's fsm_utime relative to the real clock when the state is made,
// since the group update compares fsm_utime with the real clock.
struct ShardSpec {
  ShardIdFull shard;
  CatchainSeqno cc = 0;
  block::McShardHashI::FsmState fsm = block::McShardHashI::FsmState::fsm_none;
  double fsm_in = 0;
};

// One masterchain state: the validator sets, the catchain seqno of the masterchain
// shard, the consensus config, and the workchain shards (none by default).
struct Snapshot {
  td::Ref<block::ValidatorSet> previous, current, next;
  CatchainSeqno cc = 1;
  std::vector<ShardSpec> shards = {};
  td::int32 global_id = 3;
};

class StateConfig : public ConfigHolder {
 public:
  explicit StateConfig(Snapshot snapshot) : snapshot_(std::move(snapshot)) {
  }
  td::Ref<block::ValidatorSet> get_total_validator_set(int offset) const override {
    return offset < 0 ? snapshot_.previous : offset > 0 ? snapshot_.next : snapshot_.current;
  }
  td::Ref<block::ValidatorSet> get_validator_set(ShardIdFull, UnixTime, CatchainSeqno) const override {
    return snapshot_.current;
  }
  std::pair<UnixTime, UnixTime> get_validator_set_start_stop(int) const override {
    return {0, 0x7fffffff};
  }
  td::int32 get_global_id() const override {
    return snapshot_.global_id;
  }
  td::Result<td::int32> get_config_global_id() const override {
    return snapshot_.global_id;
  }
  ValidatorSessionConfig get_consensus_config() const override {
    ValidatorSessionConfig result;
    result.new_catchain_ids = true;
    return result;
  }
  td::optional<SelectedNewConsensusConfig> get_selected_new_consensus_config(WorkchainId) const override {
    NewConsensusConfig result;
    result.protocol_version = 2;
    return SelectedNewConsensusConfig{result, hash("protocol-2")};
  }
  td::Result<td::Ref<vm::Cell>> get_auth_policy_config_root() const override {
    vm::CellBuilder version;
    CHECK(version.store_long_bool(0xc4, 8) && version.store_long_bool(16, 32) && version.store_long_bool(0, 64));
    vm::Dictionary configuration{32};
    CHECK(configuration.set_ref(td::BitArray<32>{8}, version.finalize()));
    return configuration.get_root_cell();
  }
  td::Status validate_pq_launch_resource_config() const override {
    return td::Status::OK();
  }

 protected:
  Snapshot snapshot_;
};

// The masterchain state's configuration as the chain stores it: a ShardStateUnsplit
// whose McStateExtra holds the masterchain catchain counter and the workchain shard
// hashes, each shard a ShardDescr packed by McShardHash in a BinTree. Unpacked with the
// production ConfigInfo, so counters, inheritance, a merged parent's counter and the
// next set's counter come from the production derivation, not from this test.
td::Ref<vm::Cell> shard_tree(WorkchainId workchain, ShardId prefix,
                             const std::vector<td::Ref<block::McShardHash>>& shards, int depth = 0) {
  CHECK(depth <= 8);
  vm::CellBuilder cb;
  for (const auto& descr : shards) {
    if (descr->shard() == ShardIdFull{workchain, prefix}) {
      CHECK(cb.store_long_bool(0, 1) && descr->pack(cb));  // bt_leaf$0
      return cb.finalize();
    }
  }
  CHECK(cb.store_long_bool(1, 1)  // bt_fork$1
        && cb.store_ref_bool(shard_tree(workchain, shard_child(prefix, true), shards, depth + 1)) &&
        cb.store_ref_bool(shard_tree(workchain, shard_child(prefix, false), shards, depth + 1)));
  return cb.finalize();
}

std::unique_ptr<block::ConfigInfo> chain_config(td::int32 global_id, CatchainSeqno mc_cc,
                                                const std::vector<td::Ref<block::McShardHash>>& shards) {
  vm::Dictionary shard_hashes{32};
  std::set<WorkchainId> workchains;
  for (const auto& descr : shards) {
    workchains.insert(descr->workchain());
  }
  for (auto workchain : workchains) {
    CHECK(shard_hashes.set_ref(td::BitArray<32>{workchain}, shard_tree(workchain, shardIdAll, shards)));
  }
  vm::Dictionary params{32};
  CHECK(params.set_ref(td::BitArray<32>::zero(), vm::CellBuilder{}.store_zeroes(256).finalize()));
  vm::CellBuilder r1;
  CHECK(r1.store_long_bool(0, 16)                                                            // flags
        && r1.store_long_bool(0, 32) && r1.store_long_bool(mc_cc, 32)                        // validator_info
        && r1.store_long_bool(0, 1)                                                          //   nx_cc_updated
        && r1.store_long_bool(0, 1) && r1.store_long_bool(0, 1) && r1.store_zeroes_bool(64)  // prev_blocks: empty
        && r1.store_long_bool(0, 1)                                                          // after_key_block
        && r1.store_long_bool(0, 1));                                                        // last_key_block: nothing
  vm::CellBuilder extra;
  CHECK(extra.store_long_bool(0xcc26, 16) && shard_hashes.append_dict_to_bool(extra) && extra.store_zeroes_bool(256) &&
        extra.store_ref_bool(params.get_root_cell()) && extra.store_ref_bool(r1.finalize()) &&
        extra.store_zeroes_bool(4 + 1));  // global_balance
  vm::CellBuilder rest;
  CHECK(rest.store_zeroes_bool(64 + 64) && rest.store_zeroes_bool(5) && rest.store_zeroes_bool(5) &&
        rest.store_zeroes_bool(1) && rest.store_zeroes_bool(1));
  vm::CellBuilder root;
  CHECK(root.store_long_bool(0x9023afe2, 32) && root.store_long_bool(global_id, 32)  // shard_state#9023afe2
        && root.store_long_bool(0, 2) && root.store_long_bool(0, 6) && root.store_long_bool(masterchainId, 32) &&
        root.store_long_bool(0, 64)                        // shard_id
        && root.store_zeroes_bool(32 + 32 + 32 + 64 + 32)  // seq_no ... min_ref_mc_seqno
        && root.store_ref_bool(vm::CellBuilder{}.finalize()) && root.store_long_bool(0, 1) &&
        root.store_ref_bool(vm::CellBuilder{}.finalize()) && root.store_ref_bool(rest.finalize()) &&
        root.store_long_bool(1, 1) && root.store_ref_bool(extra.finalize()));
  auto config = block::ConfigInfo::extract_config(root.finalize(), BlockIdExt{masterchainId, shardIdAll, 0, {}, {}},
                                                  block::ConfigInfo::needShardHashes);
  LOG_CHECK(config.is_ok()) << config.error();
  return config.move_as_ok();
}

class State : public MasterchainStateQ {
 public:
  State(BlockIdExt id, Snapshot snapshot)
      : MasterchainStateQ(id, vm::CellBuilder{}.finalize_novm()), snapshot_(std::move(snapshot)) {
    const double now = td::Clocks::system();
    std::vector<td::Ref<block::McShardHash>> shards;
    for (const auto& spec : snapshot_.shards) {
      auto descr = td::make_ref<block::McShardHash>(
          BlockId{spec.shard.workchain, spec.shard.shard, 1}, 0, 0, 0,
          hash(PSTRING() << "shard-root-" << spec.shard.shard), hash(PSTRING() << "shard-file-" << spec.shard.shard),
          block::CurrencyCollection{td::zero_refint()}, block::CurrencyCollection{td::zero_refint()}, 0, 0, spec.cc);
      if (spec.fsm != block::McShardHashI::FsmState::fsm_none) {
        descr.write().set_fsm(spec.fsm, static_cast<UnixTime>(now + spec.fsm_in), 100);
      }
      shards.push_back(descr);
    }
    config_ = chain_config(snapshot_.global_id, snapshot_.cc, shards);
  }
  td::Ref<block::ValidatorSet> get_total_validator_set(int offset) const override {
    return offset < 0 ? snapshot_.previous : offset > 0 ? snapshot_.next : snapshot_.current;
  }
  // The members are this test's; the counter is the configuration's, as the production
  // state derives it: delta 0 for the current set, delta 1 for the next.
  td::Ref<block::ValidatorSet> get_validator_set(ShardIdFull shard) const override {
    if (shard.is_masterchain()) {
      return snapshot_.current;
    }
    return shard_set(shard, 0);
  }
  // The masterchain has no next set here.
  td::Ref<block::ValidatorSet> get_next_validator_set(ShardIdFull shard) const override {
    if (shard.is_masterchain()) {
      return {};
    }
    return shard_set(shard, 1);
  }
  CatchainSeqno get_shard_cc_seqno(ShardIdFull shard) const override {
    return config_->get_shard_cc_seqno(shard);
  }
  td::int32 get_global_id() const override {
    return snapshot_.global_id;
  }
  bool rotated_all_shards() const override {
    return false;
  }
  // As the production state lists them: from the shard hashes, unpacked.
  std::vector<td::Ref<McShardHash>> get_shards() const override {
    std::vector<td::Ref<McShardHash>> out;
    for (const auto& id : config_->get_shard_hash_ids(true)) {
      out.push_back(config_->get_shard_hash(ShardIdFull{id}));
    }
    return out;
  }
  td::Ref<McShardHash> get_shard_from_config(ShardIdFull, bool) const override {
    return {};
  }
  ValidatorSessionConfig get_consensus_config() const override {
    return StateConfig(snapshot_).get_consensus_config();
  }
  td::optional<SelectedNewConsensusConfig> get_selected_new_consensus_config(WorkchainId wc) const override {
    return StateConfig(snapshot_).get_selected_new_consensus_config(wc);
  }
  td::Result<td::Ref<ConfigHolder>> get_config_holder() const override {
    return td::Ref<ConfigHolder>{td::make_ref<StateConfig>(snapshot_)};
  }
  td::uint32 monitor_min_split_depth(WorkchainId) const override {
    return 0;
  }
  block::SizeLimitsConfig::ExtMsgLimits get_ext_msg_limits() const override {
    return {};
  }
  block::ImportedMsgQueueLimits get_imported_msg_queue_limits(bool) const override {
    return {};
  }

 private:
  td::Ref<block::ValidatorSet> shard_set(ShardIdFull shard, CatchainSeqno delta) const {
    // The production derivation of the counter: compute_validator_set_cc adds `delta` to
    // the shard's counter, or leaves it when the shard has none. No validator list is
    // given, so it computes no members; this test supplies its own.
    if (config_->get_shard_cc_seqno(shard) == std::numeric_limits<CatchainSeqno>::max()) {
      return {};
    }
    CatchainSeqno cc = delta;
    config_->compute_validator_set_cc(shard, block::TotalValidatorSet{}, 0, &cc);
    return td::make_ref<block::ValidatorSet>(cc, shard, snapshot_.current->export_vector());
  }

  Snapshot snapshot_;
  std::shared_ptr<block::ConfigInfo> config_;
};

// Everything the fakes saw, in order.
struct Journal {
  std::mutex mu;
  std::vector<std::string> events;
  std::set<ValidatorSessionId> validator_groups;
  int observer_groups = 0;
  int probe_rounds = 0;
  void add(std::string e) {
    std::lock_guard<std::mutex> lock(mu);
    events.push_back(std::move(e));
  }
  size_t index_of(const std::string& prefix) {
    std::lock_guard<std::mutex> lock(mu);
    for (size_t i = 0; i < events.size(); ++i) {
      if (events[i].rfind(prefix, 0) == 0) {
        return i;
      }
    }
    return events.size();
  }
  size_t count(const std::string& prefix) {
    std::lock_guard<std::mutex> lock(mu);
    size_t n = 0;
    for (auto& e : events) {
      if (e.rfind(prefix, 0) == 0) {
        n++;
      }
    }
    return n;
  }
};

class FakeGroup : public IValidatorGroup {
 public:
  FakeGroup(std::shared_ptr<Journal> journal, ValidatorSessionId session)
      : journal_(std::move(journal)), session_(session) {
  }
  void start(std::vector<BlockIdExt>, BlockIdExt) override {
    journal_->add("start " + session_.to_hex());
  }
  void create_session() override {
    journal_->add("create_session " + session_.to_hex());
  }
  void update_options(td::Ref<ValidatorManagerOptions>, bool) override {
  }
  void get_validator_group_info_for_litequery(
      td::Promise<tl_object_ptr<lite_api::liteServer_nonfinal_validatorGroupInfo>> promise) override {
    promise.set_error(td::Status::Error("fake group"));
  }
  void notify_mc_finalized(BlockIdExt) override {
  }
  void destroy() override {
    stop();
  }
  void close_for_retirement(td::uint64) override {
    journal_->add("close " + session_.to_hex());
    stop();
  }

 private:
  std::shared_ptr<Journal> journal_;
  ValidatorSessionId session_;
};

class ProbeCallback : public ValidatorManagerInterface::Callback {
 public:
  explicit ProbeCallback(std::shared_ptr<Journal> journal) : journal_(std::move(journal)) {
  }
  void probe_next_masterchain_block(BlockIdExt, td::Timestamp, td::uint32,
                                    td::Promise<startup_catchup::RoundResult> promise) override {
    {
      std::lock_guard<std::mutex> lock(journal_->mu);
      journal_->probe_rounds++;
    }
    startup_catchup::RoundResult r;
    r.outcome = startup_catchup::RoundOutcome::NoVerifiedSuccessor;
    promise.set_value(std::move(r));
  }

 private:
  std::shared_ptr<Journal> journal_;
};

}  // namespace

class StartupCatchupManagerProbe : public ValidatorManagerImpl {
 public:
  StartupCatchupManagerProbe(std::string root, std::shared_ptr<Journal> journal,
                             td::actor::ActorId<keyring::Keyring> keys, td::actor::ActorId<adnl::Adnl> adnl,
                             td::actor::ActorId<rldp2::Rldp> rldp, BlockIdExt zero_state = BlockIdExt{})
      : ValidatorManagerImpl(options(zero_state), std::move(root), keys, adnl, rldp, {}, {})
      , journal_(std::move(journal)) {
  }
  // The options as the engine builds them: nothing about the own-decision log, which every
  // validator keeps.
  static td::Ref<ValidatorManagerOptions> options(BlockIdExt zero_state) {
    return ValidatorManagerOptions::create(zero_state, zero_state);
  }
  void start_up() override {
    db_ = create_db_actor(actor_id(this), db_root_, opts_);
    callback_ = std::make_unique<ProbeCallback>(journal_);
    ext_message_pool_ = td::actor::create_actor<ExtMessagePool>("catchup ext messages", opts_, actor_id(this));
    allow_validate_ = true;
    auto zero = create_empty_block_handle(BlockIdExt{masterchainId, shardIdAll, 0, {}, {}});
    zero->flushed_upto(zero->version());
    last_key_block_handle_ = zero;
    last_known_key_block_handle_ = zero;
  }

  // Stores a masterchain block handle in the node's real database, as block application
  // does: the handle, then its archive entry.
  void archive_block(BlockIdExt id, UnixTime unix_time, LogicalTime lt, td::Promise<td::Unit> promise) {
    auto handle = create_empty_block_handle(id);
    handle->set_unix_time(unix_time);
    handle->set_logical_time(lt);
    handle->set_is_key_block(id.seqno() == 0);
    td::actor::send_closure(
        db_, &Db::store_block_handle, handle,
        [db = db_.get(), handle, promise = std::move(promise)](td::Result<td::Unit> stored) mutable {
          if (stored.is_error()) {
            promise.set_error(stored.move_as_error());
            return;
          }
          td::actor::send_closure(db, &Db::add_handle_to_archive, handle, std::move(promise));
        });
  }
  // Whether the database's seqno index finds the masterchain block at `seqno`.
  void find_by_seqno(BlockSeqno seqno, td::Promise<bool> promise) {
    get_block_by_seqno_from_db(AccountIdPrefixFull{masterchainId, 0}, seqno,
                               [promise = std::move(promise)](td::Result<ConstBlockHandle> found) mutable {
                                 promise.set_value(found.is_ok());
                               });
  }

  // Custody as the engine installs it, through the manager's own entry.
  void hold(std::shared_ptr<const pq::ValidatorPQKeyStore> store, ValidatorId id, td::uint32 expire_at) {
    add_pq_consensus_key(id, std::move(store), 0, expire_at,
                         td::PromiseCreator::lambda([](td::Result<td::Unit> r) { r.ensure(); }));
  }
  // Every key of `id` removed, as a rebind or a rotation away does.
  void release(ValidatorId id, td::Promise<td::Unit> promise) {
    pq_custody_.remove(id);
    signing_custody_changed(id);
    promise.set_value(td::Unit());
  }
  // The wall clock custody is measured from, `offset` seconds ahead of the real one.
  void set_custody_clock_offset(double offset, td::Promise<td::Unit> promise) {
    custody_clock_offset_ = offset;
    promise.set_value(td::Unit());
  }
  double signing_custody_clock() const override {
    return td::Clocks::system() + custody_clock_offset_;
  }
  // The identity's record: {t0, the seqno of its fence block or -1}, or nothing.
  void identity_record(ValidatorId id, td::Promise<std::optional<std::pair<td::uint64, td::int64>>> promise) {
    auto it = signing_identities_.find(id);
    if (it == signing_identities_.end()) {
      promise.set_value(std::nullopt);
      return;
    }
    promise.set_value(std::make_pair(it->second.t0, it->second.fence_block.has_value()
                                                        ? static_cast<td::int64>(it->second.fence_block->block.seqno())
                                                        : td::int64{-1}));
  }
  void genesis_hint_logged(td::Promise<bool> promise) {
    promise.set_value(bool{signing_genesis_hint_logged_});
  }
  // Whether the ledger directory exists under this node's database.
  void ledger_exists(td::Promise<bool> promise) {
    promise.set_value(td::stat(consensus::signing::ledger_dir(db_root_) + "/ledger").is_ok());
  }
  // An Ed25519 operator key only: no post-quantum consensus custody.
  void hold_operator_key() {
    permanent_keys_.insert(PublicKeyHash{hash("operator-key")});
  }
  // Install a masterchain tip (and the same shard-client block) aged `age` seconds,
  // without running the group update.
  void set_tip(Snapshot snapshot, BlockSeqno height, double age) {
    last_masterchain_seqno_ = height;
    last_masterchain_block_id_ = BlockIdExt{masterchainId, shardIdAll, height, hash(PSTRING() << "root-" << height),
                                            hash(PSTRING() << "file-" << height)};
    last_masterchain_state_ = td::make_ref<State>(last_masterchain_block_id_, std::move(snapshot));
    last_masterchain_block_handle_ = create_empty_block_handle(last_masterchain_block_id_);
    last_masterchain_block_handle_->set_is_key_block(false);
    last_masterchain_block_handle_->set_unix_time(static_cast<UnixTime>(td::Clocks::system() - age));
    last_masterchain_block_handle_->flushed_upto(last_masterchain_block_handle_->version());
    shard_client_handle_ = last_masterchain_block_handle_;
  }
  void advance(Snapshot snapshot, BlockSeqno height, double age, td::Promise<td::Unit> promise) {
    set_tip(std::move(snapshot), height, age);
    new_masterchain_block();
    promise.set_value(td::Unit());
  }
  void decide(td::Promise<bool> promise) {
    decide_startup_catchup();
    promise.set_value(startup_catchup_.active());
  }
  void end(startup_catchup::ExitReason reason, td::Promise<td::Unit> promise) {
    end_startup_catchup(reason);
    promise.set_value(td::Unit());
  }
  void run_mode(td::Promise<td::Unit> promise) {
    [](StartupCatchupManagerProbe* self, td::Promise<td::Unit> promise) -> td::actor::Task<> {
      co_await self->run_startup_catchup_mode();
      promise.set_value(td::Unit());
      co_return td::Unit{};
    }(this, std::move(promise))
                                                                               .start()
                                                                               .detach();
  }
  void complete_prestart(td::Promise<td::Unit> promise) {
    completed_prestart_sync();
    promise.set_value(td::Unit());
  }
  // Build a group for the current masterchain set directly, past every caller's gate.
  void build_directly(td::Promise<bool> promise) {
    auto set = last_masterchain_state_->get_validator_set(ShardIdFull{masterchainId});
    auto selected = last_masterchain_state_->get_selected_new_consensus_config(masterchainId);
    consensus::ValidatorSessionOptions opts{last_masterchain_state_->get_consensus_config()};
    auto group = create_validator_group(hash("direct"), ShardIdFull{masterchainId}, set, 0, selected.value().config,
                                        opts, false);
    bool built = !group.empty();
    if (built) {
      td::actor::send_closure(group, &IValidatorGroup::destroy);
      group.release();
    }
    promise.set_value(std::move(built));
  }
  void sync_done(td::Promise<td::Unit> promise) {
    sync_complete({});
    promise.set_value(td::Unit());
  }
  void query(td::Promise<std::vector<bool>> promise) {
    // active, fence closed, groups permitted, out of sync, reconciled
    promise.set_value(std::vector<bool>{startup_catchup_.active(), startup_catchup_.fence_closed(),
                                        validator_groups_permitted(), out_of_sync(), startup_reconciled_});
  }
  void verify(BlockIdExt prev, BlockIdExt next, td::Promise<startup_catchup::SuccessorVerdict> promise) {
    verify_startup_probe_successor(prev, next, td::BufferSlice("not a proof"), td::Timestamp::in(30.0),
                                   std::move(promise));
  }
  void session_of(Snapshot snapshot, td::Promise<ValidatorSessionId> promise) {
    // The canonical id the group update derives for the masterchain set of `snapshot`.
    auto state = td::make_ref<State>(last_masterchain_block_id_, snapshot);
    auto selected = state->get_selected_new_consensus_config(masterchainId);
    auto config = state->get_consensus_config();
    consensus::ValidatorSessionOptions opts{config};
    promise.set_value(block::derive_validator_session_identity(
                          block::ValidatorSessionIdentityInput{
                              .global_id = snapshot.global_id,
                              .validator_options_hash = block::validator_session_options_hash(config),
                              .simplex_config_cell_hash = selected.value().cell_hash,
                              .shard = ShardIdFull{masterchainId},
                              .catchain_seqno = snapshot.current->get_catchain_seqno(),
                              .validators = snapshot.current->export_vector(),
                              .vertical_seqno = opts_->get_maximal_vertical_seqno(),
                              .last_key_block_seqno = last_key_block_handle_->id().seqno(),
                              .new_catchain_ids = opts.new_catchain_ids,
                          })
                          .session_id);
  }
  // The canonical id the group update derives for `shard` at counter `cc`, with the
  // validators of `snapshot` and this node's current last key block.
  void session_for(Snapshot snapshot, ShardIdFull shard, CatchainSeqno cc, td::Promise<ValidatorSessionId> promise) {
    auto state = td::make_ref<State>(last_masterchain_block_id_, snapshot);
    auto selected = state->get_selected_new_consensus_config(shard.workchain);
    auto config = state->get_consensus_config();
    consensus::ValidatorSessionOptions opts{config};
    promise.set_value(block::derive_validator_session_identity(
                          block::ValidatorSessionIdentityInput{
                              .global_id = snapshot.global_id,
                              .validator_options_hash = block::validator_session_options_hash(config),
                              .simplex_config_cell_hash = selected.value().cell_hash,
                              .shard = shard,
                              .catchain_seqno = cc,
                              .validators = snapshot.current->export_vector(),
                              .vertical_seqno = opts_->get_maximal_vertical_seqno(),
                              .last_key_block_seqno = last_key_block_handle_->id().seqno(),
                              .new_catchain_ids = opts.new_catchain_ids,
                          })
                          .session_id);
  }
  // A new last key block, as applying a key block records it.
  void key_block(BlockSeqno seqno, td::Promise<td::Unit> promise) {
    auto handle =
        create_empty_block_handle(BlockIdExt{masterchainId, shardIdAll, seqno, hash(PSTRING() << "key-root-" << seqno),
                                             hash(PSTRING() << "key-file-" << seqno)});
    handle->set_is_key_block(true);
    handle->flushed_upto(handle->version());
    last_key_block_handle_ = handle;
    last_known_key_block_handle_ = handle;
    promise.set_value(td::Unit());
  }
  void teardown(td::Promise<td::Unit> promise) {
    for (auto& [id, entry] : validator_groups_) {
      td::actor::send_closure(entry.actor, &IValidatorGroup::destroy);
    }
    for (auto& [id, entry] : next_validator_groups_) {
      td::actor::send_closure(entry.actor, &IValidatorGroup::destroy);
    }
    for (auto& [id, entry] : observer_groups_) {
      td::actor::send_closure(entry.actor, &IValidatorGroup::destroy);
    }
    validator_groups_.clear();
    next_validator_groups_.clear();
    observer_groups_.clear();
    shard_block_verifier_.reset();
    promise.set_value(td::Unit());
  }

 protected:
  void start_shard_client() override {
    journal_->add("shard client start");
  }
  td::actor::ActorOwn<IValidatorGroup> construct_group(
      bool observer, ValidatorSessionId session, ShardIdFull,
      const std::function<td::actor::ActorOwn<IValidatorGroup>()>&) override {
    if (!observer) {
      // What the group would be built with: its session's admission, decided before it.
      auto it = signing_admissions_.find(session);
      journal_->add(it == signing_admissions_.end() ? "admission none " + session.to_hex()
                    : it->second->fenced            ? "admission fenced " + session.to_hex()
                                                    : "admission admitted " + session.to_hex());
    }
    {
      std::lock_guard<std::mutex> lock(journal_->mu);
      if (observer) {
        journal_->observer_groups++;
      } else {
        journal_->validator_groups.insert(session);
      }
    }
    journal_->add((observer ? "observer " : "group ") + session.to_hex());
    return td::actor::create_actor<FakeGroup>("fake group", journal_, session);
  }

 private:
  std::shared_ptr<Journal> journal_;
  double custody_clock_offset_ = 0;
};

namespace {

class Fixture {
 public:
  Epoch old{1}, current{2}, next{3}, outsider{4, 1};
  std::shared_ptr<Journal> journal = std::make_shared<Journal>();

  // The manager keeps an own-decision log under its database root, as every validator does;
  // `before_start` runs on that root before the manager exists.
  explicit Fixture(const std::function<void(const std::string&)>& before_start = nullptr,
                   BlockIdExt zero_state = BlockIdExt{})
      : root_(td::mkdtemp("/tmp", "startup-catchup-manager").move_as_ok()), scheduler_({1}) {
    if (before_start) {
      before_start(root_);
    }
    scheduler_.run_in_context([&] {
      keys_ = keyring::Keyring::create(root_);
      adnl_ = adnl::Adnl::create(root_, keys_.get());
      rldp_ = rldp2::Rldp::create(adnl_.get());
      // The validators' transport identities, for the local consumers of a group's ADNL id.
      for (const auto* epoch : {&old, &current, &next}) {
        for (auto& key : epoch->transport) {
          td::actor::send_closure(keys_, &keyring::Keyring::add_key, key, true, [](td::Result<td::Unit>) {});
          td::actor::send_closure(adnl_, &adnl::Adnl::add_id, adnl::AdnlNodeIdFull{key.compute_public_key()},
                                  adnl::AdnlAddressList{}, static_cast<td::uint8>(0));
        }
      }
      manager_ = td::actor::create_actor<StartupCatchupManagerProbe>("catchup manager", root_, journal, keys_.get(),
                                                                     adnl_.get(), rldp_.get(), zero_state);
    });
  }
  ~Fixture() {
    ask<td::Unit>([&](td::Promise<td::Unit> p) {
      td::actor::send_closure(manager_, &StartupCatchupManagerProbe::teardown, std::move(p));
    });
    run_for(0.2);
    scheduler_.run_in_context([&] {
      manager_.reset();
      rldp_.reset();
      adnl_.reset();
      keys_.reset();
      td::actor::SchedulerContext::get().stop();
    });
    while (scheduler_.run(1)) {
    }
    td::rmrf(root_).ignore();
  }
  template <class T, class Send>
  T ask(Send send) {
    std::mutex mu;
    std::optional<td::Result<T>> result;
    scheduler_.run_in_context([&] {
      send(td::PromiseCreator::lambda([&](td::Result<T> r) {
        std::lock_guard<std::mutex> lk(mu);
        result.emplace(std::move(r));
      }));
    });
    auto deadline = td::Timestamp::in(60.0);
    while (true) {
      {
        std::lock_guard<std::mutex> lk(mu);
        if (result) {
          break;
        }
      }
      LOG_CHECK(!deadline.is_in_past()) << "timed out waiting for the manager";
      scheduler_.run(0.01);
    }
    return result->move_as_ok();
  }
  void run_for(double seconds) {
    auto deadline = td::Timestamp::in(seconds);
    while (!deadline.is_in_past()) {
      scheduler_.run(0.01);
    }
  }
  // Validators of `epoch` at catchain seqno `cc`, with `old` before and `next` after.
  Snapshot snapshot(const Epoch& epoch, CatchainSeqno cc) {
    return Snapshot{old.set(cc), epoch.set(cc), next.set(cc + 1), cc};
  }
  void hold(const Epoch& epoch, size_t i) {
    scheduler_.run_in_context([&] {
      td::actor::send_closure(manager_, &StartupCatchupManagerProbe::hold, epoch.custody[i],
                              epoch.members[i].validator_id, 0u);
    });
  }
  void hold_expiring(const Epoch& epoch, int index, size_t i, td::uint32 expire_at) {
    scheduler_.run_in_context([&] {
      td::actor::send_closure(manager_, &StartupCatchupManagerProbe::hold, epoch.windowed(index, i, expire_at),
                              epoch.members[i].validator_id, expire_at);
    });
  }
  void hold_operator_key() {
    scheduler_.run_in_context(
        [&] { td::actor::send_closure(manager_, &StartupCatchupManagerProbe::hold_operator_key); });
  }
  void set_tip(Snapshot s, BlockSeqno height, double age) {
    scheduler_.run_in_context(
        [&] { td::actor::send_closure(manager_, &StartupCatchupManagerProbe::set_tip, std::move(s), height, age); });
  }
  void advance(Snapshot s, BlockSeqno height, double age) {
    ask<td::Unit>([&](td::Promise<td::Unit> p) {
      td::actor::send_closure(manager_, &StartupCatchupManagerProbe::advance, std::move(s), height, age, std::move(p));
    });
  }
  void archive_block(BlockIdExt id, UnixTime unix_time, LogicalTime lt) {
    ask<td::Unit>([&](td::Promise<td::Unit> p) {
      td::actor::send_closure(manager_, &StartupCatchupManagerProbe::archive_block, id, unix_time, lt, std::move(p));
    });
  }
  bool find_by_seqno(BlockSeqno seqno) {
    return ask<bool>([&](td::Promise<bool> p) {
      td::actor::send_closure(manager_, &StartupCatchupManagerProbe::find_by_seqno, seqno, std::move(p));
    });
  }
  bool decide() {
    return ask<bool>([&](td::Promise<bool> p) {
      td::actor::send_closure(manager_, &StartupCatchupManagerProbe::decide, std::move(p));
    });
  }
  void end(startup_catchup::ExitReason reason) {
    ask<td::Unit>([&](td::Promise<td::Unit> p) {
      td::actor::send_closure(manager_, &StartupCatchupManagerProbe::end, reason, std::move(p));
    });
  }
  void run_mode() {
    ask<td::Unit>([&](td::Promise<td::Unit> p) {
      td::actor::send_closure(manager_, &StartupCatchupManagerProbe::run_mode, std::move(p));
    });
  }
  void complete_prestart() {
    ask<td::Unit>([&](td::Promise<td::Unit> p) {
      td::actor::send_closure(manager_, &StartupCatchupManagerProbe::complete_prestart, std::move(p));
    });
  }
  bool build_directly() {
    return ask<bool>([&](td::Promise<bool> p) {
      td::actor::send_closure(manager_, &StartupCatchupManagerProbe::build_directly, std::move(p));
    });
  }
  void sync_done() {
    ask<td::Unit>([&](td::Promise<td::Unit> p) {
      td::actor::send_closure(manager_, &StartupCatchupManagerProbe::sync_done, std::move(p));
    });
  }
  // active, fence closed, groups permitted, out of sync, reconciled
  std::vector<bool> query() {
    return ask<std::vector<bool>>([&](td::Promise<std::vector<bool>> p) {
      td::actor::send_closure(manager_, &StartupCatchupManagerProbe::query, std::move(p));
    });
  }
  startup_catchup::SuccessorVerdict verify(BlockIdExt prev, BlockIdExt next) {
    return ask<startup_catchup::SuccessorVerdict>([&](td::Promise<startup_catchup::SuccessorVerdict> p) {
      td::actor::send_closure(manager_, &StartupCatchupManagerProbe::verify, prev, next, std::move(p));
    });
  }
  ValidatorSessionId session_of(Snapshot s) {
    return ask<ValidatorSessionId>([&](td::Promise<ValidatorSessionId> p) {
      td::actor::send_closure(manager_, &StartupCatchupManagerProbe::session_of, std::move(s), std::move(p));
    });
  }
  ValidatorSessionId session_for(Snapshot s, ShardIdFull shard, CatchainSeqno cc) {
    return ask<ValidatorSessionId>([&](td::Promise<ValidatorSessionId> p) {
      td::actor::send_closure(manager_, &StartupCatchupManagerProbe::session_for, std::move(s), shard, cc,
                              std::move(p));
    });
  }
  void release(const Epoch& epoch, size_t i) {
    ask<td::Unit>([&](td::Promise<td::Unit> p) {
      td::actor::send_closure(manager_, &StartupCatchupManagerProbe::release, epoch.members[i].validator_id,
                              std::move(p));
    });
  }
  void custody_clock_offset(double offset) {
    ask<td::Unit>([&](td::Promise<td::Unit> p) {
      td::actor::send_closure(manager_, &StartupCatchupManagerProbe::set_custody_clock_offset, offset, std::move(p));
    });
  }
  std::optional<std::pair<td::uint64, td::int64>> identity_record(const Epoch& epoch, size_t i) {
    return ask<std::optional<std::pair<td::uint64, td::int64>>>(
        [&](td::Promise<std::optional<std::pair<td::uint64, td::int64>>> p) {
          td::actor::send_closure(manager_, &StartupCatchupManagerProbe::identity_record, epoch.members[i].validator_id,
                                  std::move(p));
        });
  }
  bool genesis_hint_logged() {
    return ask<bool>([&](td::Promise<bool> p) {
      td::actor::send_closure(manager_, &StartupCatchupManagerProbe::genesis_hint_logged, std::move(p));
    });
  }
  bool ledger_exists() {
    return ask<bool>([&](td::Promise<bool> p) {
      td::actor::send_closure(manager_, &StartupCatchupManagerProbe::ledger_exists, std::move(p));
    });
  }
  void key_block(BlockSeqno seqno) {
    ask<td::Unit>([&](td::Promise<td::Unit> p) {
      td::actor::send_closure(manager_, &StartupCatchupManagerProbe::key_block, seqno, std::move(p));
    });
  }
  bool wait_event(const std::string& prefix, double timeout) {
    auto deadline = td::Timestamp::in(timeout);
    while (!deadline.is_in_past()) {
      if (journal->count(prefix) > 0) {
        return true;
      }
      scheduler_.run(0.01);
    }
    return journal->count(prefix) > 0;
  }
  std::optional<consensus::PendingValidatorConsensusDbCleanup> record_of(const ValidatorSessionId& s) {
    return ask<std::optional<consensus::PendingValidatorConsensusDbCleanup>>(
        [&](td::Promise<std::optional<consensus::PendingValidatorConsensusDbCleanup>> p) {
          td::actor::send_closure(manager_, &StartupCatchupManagerProbe::startup_orphan_read_record, s, std::move(p));
        });
  }
  void make_session_dir(const ValidatorSessionId& s, CatchainSeqno cc) {
    td::mkdir(consensus::consensus_db_root(root_)).ignore();
    td::mkdir(consensus::consensus_db_root(root_) +
              consensus::consensus_db_dir_name(ShardIdFull{masterchainId}, cc, s, ""))
        .ensure();
  }

 private:
  std::string root_;
  td::actor::Scheduler scheduler_;
  td::actor::ActorOwn<keyring::Keyring> keys_;
  td::actor::ActorOwn<adnl::Adnl> adnl_;
  td::actor::ActorOwn<rldp2::Rldp> rldp_;
  td::actor::ActorOwn<StartupCatchupManagerProbe> manager_;
};

constexpr double kStale = 3600.0;
constexpr double kFresh = 5.0;

}  // namespace
}  // namespace tos::validator

using namespace tos;
using namespace tos::validator;
using startup_catchup::ExitReason;

// T12. While the mode imports catchain rotations and a validator-set rotation, no
// validator and no observer group is built. When the mode ends, exactly the groups
// the final state selects are built, before the shard client starts, and sync
// completion activates them.
TEST(StartupCatchupManager, T12_FenceThenExactGroupsBeforeShardClient) {
  Fixture f;
  f.hold(f.current, 0);  // a member of the current set
  f.hold(f.old, 1);      // a member of the previous set only: an observer
  f.set_tip(f.snapshot(f.current, 1), 10, kStale);
  ASSERT_TRUE(f.decide());
  f.advance(f.snapshot(f.current, 1), 10, kStale);  // the startup group update
  f.advance(f.snapshot(f.current, 2), 20, kStale);  // catchain rotations
  f.advance(f.snapshot(f.current, 3), 30, kStale);
  f.advance(f.snapshot(f.current, 4), 40, kStale);
  f.advance(f.snapshot(f.next, 5), 50, kStale);  // a validator-set rotation
  f.advance(f.snapshot(f.current, 6), 60, kFresh);
  {
    std::lock_guard<std::mutex> lock(f.journal->mu);
    ASSERT_EQ(0u, f.journal->validator_groups.size());
    ASSERT_EQ(0, f.journal->observer_groups);
  }
  f.end(ExitReason::Fresh);
  auto expected = f.session_of(f.snapshot(f.current, 6));
  {
    std::lock_guard<std::mutex> lock(f.journal->mu);
    ASSERT_EQ(1u, f.journal->validator_groups.size());
    ASSERT_TRUE(f.journal->validator_groups.count(expected) == 1);
    ASSERT_EQ(1, f.journal->observer_groups);
  }
  f.complete_prestart();
  ASSERT_TRUE(f.wait_event("shard client start", 30.0));
  ASSERT_TRUE(f.journal->index_of("group " + expected.to_hex()) < f.journal->index_of("shard client start"));
  ASSERT_TRUE(f.journal->index_of("start " + expected.to_hex()) < f.journal->index_of("shard client start"));
  f.sync_done();
  ASSERT_TRUE(f.wait_event("create_session " + expected.to_hex(), 10.0));
}

// T12 (final defence). The group factory itself refuses while the mode is active, even
// when called past the group update's own gates; once the mode ended the same call
// builds the group.
TEST(StartupCatchupManager, T12_FactoryRefusesWhileFenced) {
  Fixture f;
  f.hold(f.current, 0);
  f.set_tip(f.snapshot(f.current, 1), 10, kStale);
  ASSERT_TRUE(f.decide());
  ASSERT_TRUE(!f.build_directly());
  {
    std::lock_guard<std::mutex> lock(f.journal->mu);
    ASSERT_EQ(0u, f.journal->validator_groups.size());
  }
  f.end(ExitReason::Fresh);
  // A group is built once its session's admission is decided; the first call requests it.
  bool built = false;
  for (int attempt = 0; attempt < 100 && !built; ++attempt) {
    built = f.build_directly();
    if (!built) {
      f.run_for(0.05);
    }
  }
  ASSERT_TRUE(built);
}

// T13. The old signing key has expired and only the new set's key is held: the node
// is not a member of the restored set, yet it enters the mode; the fence holds while
// the import crosses into the set that contains it, and the mode does not end early.
TEST(StartupCatchupManager, T13_NewKeyHolderEntersAndStaysFenced) {
  Fixture f;
  // The old key expires a moment after it is installed; the next set's key is held.
  f.hold_expiring(f.current, 2, 1, static_cast<td::uint32>(td::Clocks::system()) + 1);
  f.hold(f.next, 0);
  f.run_for(1.5);
  f.set_tip(f.snapshot(f.current, 1), 10, kStale);
  ASSERT_TRUE(f.decide());
  f.advance(f.snapshot(f.current, 1), 10, kStale);
  f.advance(f.snapshot(f.next, 2), 20, kStale);  // now a member
  auto q = f.query();
  ASSERT_TRUE(q[0]);  // still active
  ASSERT_TRUE(q[3]);  // and still out of sync: the stale-validator short-circuit does not end it
  std::lock_guard<std::mutex> lock(f.journal->mu);
  ASSERT_EQ(0u, f.journal->validator_groups.size());
}

// T14. The decision is taken once: after the mode ended, a stale tip and the startup
// paths again neither re-enter it nor start discovery.
TEST(StartupCatchupManager, T14_NoReentry) {
  Fixture f;
  // A key of no set at all: no validator or observer group is built when the mode
  // ends, so nothing but the terminal state can refuse a second entry.
  f.hold(f.outsider, 0);
  f.set_tip(f.snapshot(f.current, 1), 10, kStale);
  ASSERT_TRUE(f.decide());
  f.end(ExitReason::NoVerifiedSuccessor);
  f.set_tip(f.snapshot(f.current, 1), 11, kStale);
  ASSERT_TRUE(!f.decide());
  f.run_mode();  // the startup orchestration runs the loop only while the mode is active
  auto q = f.query();
  ASSERT_TRUE(!q[0]);
  ASSERT_TRUE(!q[1]);
  std::lock_guard<std::mutex> lock(f.journal->mu);
  ASSERT_EQ(0, f.journal->probe_rounds);
}

// T6 (manager half). The verification entry answers "frontier moved" for an answer
// about a block that is no longer the tip, without checking the proof.
TEST(StartupCatchupManager, T6_VerificationEntryRefusesAMovedTip) {
  Fixture f;
  f.set_tip(f.snapshot(f.current, 1), 10, kStale);
  auto old_tip = BlockIdExt{masterchainId, shardIdAll, 9, hash("root-9"), hash("file-9")};
  auto next = BlockIdExt{masterchainId, shardIdAll, 10, hash("other-root"), hash("other-file")};
  ASSERT_TRUE(f.verify(old_tip, next) == startup_catchup::SuccessorVerdict::FrontierMoved);
}

// T28. The entry is refused at once (the tip is not stale), at catchain seqno 1; the
// local replay then advances to seqno 2. The inventory runs at prestart completion, on
// the final state, and records the session that rotation made obsolete.
TEST(StartupCatchupManager, T28_InventoryRunsOnTheFinalState) {
  Fixture f;
  f.hold(f.current, 0);
  auto first = f.snapshot(f.current, 1);
  f.set_tip(first, 10, kFresh);
  // A session of the previous process this node never reopens: a directory only the
  // inventory can record (a group this process builds is recorded when it retires).
  auto session = f.session_of(f.snapshot(f.old, 1));
  f.make_session_dir(session, 1);
  ASSERT_TRUE(!f.decide());  // Done already
  f.advance(first, 10, kFresh);
  f.advance(f.snapshot(f.current, 2), 20, kFresh);  // local replay
  f.run_mode();                                     // the mode is not active: nothing runs
  f.complete_prestart();
  ASSERT_TRUE(f.wait_event("shard client start", 30.0));
  auto record = f.record_of(session);
  ASSERT_TRUE(record.has_value());
}

// T29. The mode ends Abandoned; mandatory legacy import then continues through a
// rotation. The inventory at prestart completion sees the final state.
TEST(StartupCatchupManager, T29_InventoryAfterLegacyImport) {
  Fixture f;
  f.hold(f.current, 0);
  auto first = f.snapshot(f.current, 1);
  f.set_tip(first, 10, kStale);
  // A session of the previous process this node never reopens: a directory only the
  // inventory can record (a group this process builds is recorded when it retires).
  auto session = f.session_of(f.snapshot(f.old, 1));
  f.make_session_dir(session, 1);
  ASSERT_TRUE(f.decide());
  f.advance(first, 10, kStale);
  f.end(ExitReason::Abandoned);
  f.advance(f.snapshot(f.current, 2), 20, kFresh);  // the legacy archive loop's import
  f.complete_prestart();
  ASSERT_TRUE(f.wait_event("shard client start", 30.0));
  ASSERT_TRUE(f.record_of(session).has_value());
}

// T31. A key-holding node that is not a member of the restored set leaves the mode
// without a verified successor: the sync predicate still reports out of sync through
// its non-validator branch, so the legacy archive loop runs; the fence is open; and
// the inventory still runs at prestart completion.
TEST(StartupCatchupManager, T31_NonMemberFallsBackToTheLegacyLoop) {
  Fixture f;
  f.hold(f.next, 0);  // not in the current set
  f.set_tip(f.snapshot(f.current, 1), 10, kStale);
  ASSERT_TRUE(f.decide());
  f.advance(f.snapshot(f.current, 1), 10, kStale);
  f.end(ExitReason::NoVerifiedSuccessor);
  auto q = f.query();
  ASSERT_TRUE(!q[0]);
  ASSERT_TRUE(q[2]);  // groups permitted: the fence is open
  ASSERT_TRUE(q[3]);  // out of sync: the legacy archive loop runs
  f.complete_prestart();
  ASSERT_TRUE(f.wait_event("shard client start", 30.0));
  ASSERT_TRUE(f.query()[4]);
}

// The entry counts any held validator key, an Ed25519 operator key included: a node
// with no post-quantum custody at all enters the mode, builds no group when it ends,
// and keeps the legacy non-validator fallback.
TEST(StartupCatchupManager, Ed25519OnlyKeyEnters) {
  Fixture f;
  f.hold_operator_key();
  f.set_tip(f.snapshot(f.current, 1), 10, kStale);
  ASSERT_TRUE(f.decide());
  f.advance(f.snapshot(f.current, 1), 10, kStale);
  f.end(ExitReason::NoVerifiedSuccessor);
  auto q = f.query();
  ASSERT_TRUE(!q[0]);
  ASSERT_TRUE(q[3]);  // the legacy non-validator branch: out of sync
  std::lock_guard<std::mutex> lock(f.journal->mu);
  ASSERT_EQ(0u, f.journal->validator_groups.size());
  ASSERT_EQ(0, f.journal->observer_groups);
}

// C5. Prestart completion runs once: a second completion is refused, so the shard client
// is started once and the inventory runs once.
TEST(StartupCatchupManager, PrestartCompletesOnce) {
  Fixture f;
  f.hold(f.current, 0);
  f.set_tip(f.snapshot(f.current, 1), 10, kFresh);
  ASSERT_TRUE(!f.decide());
  f.complete_prestart();
  ASSERT_TRUE(f.wait_event("shard client start", 30.0));
  f.complete_prestart();
  f.run_for(1.0);
  ASSERT_EQ(1u, f.journal->count("shard client start"));
}

// T15 (without the cleanup checkpoint). The group predicate is the fence alone while
// the checkpoint condition is absent; it is open outside the mode.
TEST(StartupCatchupManager, T15_PredicateWithoutTheCheckpoint) {
  Fixture f;
  f.hold(f.current, 0);
  f.set_tip(f.snapshot(f.current, 1), 10, kStale);
  ASSERT_TRUE(f.query()[2]);
  ASSERT_TRUE(f.decide());
  ASSERT_TRUE(!f.query()[2]);
  f.end(ExitReason::Fresh);
  ASSERT_TRUE(f.query()[2]);
}

// ===== The own-decision log in the group update =====

namespace {

std::string ledger_of(const std::string& root) {
  return consensus::signing::ledger_dir(root);
}

// A ledger for `validator`, optionally with a floor.
void make_ledger(const std::string& root, const ValidatorId& validator, std::optional<BlockIdExt> floor) {
  CHECK(consensus::signing::create_ledger(ledger_of(root), validator.value).is_ok());
  if (floor.has_value()) {
    consensus::signing::Header header;
    header.validator = validator.value;
    header.dir = consensus::signing::binding_of(ledger_of(root)).move_as_ok();
    header.floor = floor;
    consensus::signing::default_file_ops()
        ->replace_file(ledger_of(root), "ledger", consensus::signing::encode_header(header))
        .ensure();
  }
}

// The validator id of member `i` of epoch `index`, as Epoch derives it.
ValidatorId member_id(int index, size_t i) {
  return ValidatorId{hash(PSTRING() << "startup-catchup-epoch-" << index << "-" << i << "-validator")};
}

}  // namespace

// A group is built only once its session's admission is decided: never before, and the
// group update runs again by itself when the answer arrives.
TEST(StartupCatchupManager, DecisionLogAdmitsBeforeTheGroup) {
  Fixture f([&](const std::string& root) { make_ledger(root, member_id(2, 0), std::nullopt); });
  f.hold(f.current, 0);
  f.set_tip(f.snapshot(f.current, 1), 10, kFresh);
  ASSERT_TRUE(!f.decide());
  f.advance(f.snapshot(f.current, 1), 10, kFresh);
  auto expected = f.session_of(f.snapshot(f.current, 1));
  ASSERT_TRUE(f.wait_event("group " + expected.to_hex(), 10.0));
  ASSERT_EQ(1u, f.journal->count("admission admitted " + expected.to_hex()));
  ASSERT_EQ(0u, f.journal->count("admission none"));
}

// Without a ledger nothing is admitted: the group is built, fenced, and signs nothing.
TEST(StartupCatchupManager, DecisionLogWithoutALedgerFences) {
  Fixture f;
  f.hold(f.current, 0);
  f.set_tip(f.snapshot(f.current, 1), 10, kFresh);
  ASSERT_TRUE(!f.decide());
  f.advance(f.snapshot(f.current, 1), 10, kFresh);
  auto expected = f.session_of(f.snapshot(f.current, 1));
  ASSERT_TRUE(f.wait_event("group " + expected.to_hex(), 10.0));
  ASSERT_EQ(1u, f.journal->count("admission fenced " + expected.to_hex()));
}

// A head below the ledger's floor builds no group: it could be a state the floor retired.
TEST(StartupCatchupManager, DecisionLogWaitsForTheFloor) {
  const BlockIdExt floor{masterchainId, shardIdAll, 100, hash("floor-root"), hash("floor-file")};
  Fixture f([&](const std::string& root) { make_ledger(root, member_id(2, 0), floor); });
  f.hold(f.current, 0);
  f.set_tip(f.snapshot(f.current, 1), 10, kFresh);
  ASSERT_TRUE(!f.decide());
  f.advance(f.snapshot(f.current, 1), 10, kFresh);
  f.run_for(2.0);
  std::lock_guard<std::mutex> lock(f.journal->mu);
  ASSERT_EQ(0u, f.journal->validator_groups.size());
}

// A chain without the floor's block at the floor's height admits nothing in this process.
TEST(StartupCatchupManager, DecisionLogRefusesAChainWithoutTheFloor) {
  const BlockIdExt floor{masterchainId, shardIdAll, 5, hash("floor-root"), hash("floor-file")};
  Fixture f([&](const std::string& root) { make_ledger(root, member_id(2, 0), floor); });
  f.hold(f.current, 0);
  f.set_tip(f.snapshot(f.current, 1), 10, kFresh);
  ASSERT_TRUE(!f.decide());
  f.advance(f.snapshot(f.current, 1), 10, kFresh);
  auto expected = f.session_of(f.snapshot(f.current, 1));
  ASSERT_TRUE(f.wait_event("group " + expected.to_hex(), 10.0));
  ASSERT_EQ(1u, f.journal->count("admission fenced " + expected.to_hex()));
}

// Unknown history on the masterchain. Without a ledger the node's earlier signing is
// unknown: the first session is fenced and a pending ledger records when this process
// started. A masterchain block generated at least the margin after that start is the
// fence: sessions up to two catchain counters above it stay fenced, the next one signs.
TEST(StartupCatchupManager, DecisionLogFencesUnknownHistory) {
  // A block generated in the future of this process's start, by more than the margin.
  constexpr double kAfterTheMargin = -(consensus::signing::kHistoryMarginSeconds + 5.0);
  Fixture f;
  f.hold(f.current, 0);
  f.set_tip(f.snapshot(f.current, 1), 10, kFresh);
  ASSERT_TRUE(!f.decide());
  f.advance(f.snapshot(f.current, 1), 10, kFresh);
  auto first = f.session_of(f.snapshot(f.current, 1));
  ASSERT_TRUE(f.wait_event("group " + first.to_hex(), 10.0));
  ASSERT_EQ(1u, f.journal->count("admission fenced " + first.to_hex()));

  // A block generated before the margin has passed is not the fence.
  f.advance(f.snapshot(f.current, 2), 11, kFresh);
  auto early = f.session_of(f.snapshot(f.current, 2));
  ASSERT_TRUE(f.wait_event("group " + early.to_hex(), 10.0));
  ASSERT_EQ(1u, f.journal->count("admission fenced " + early.to_hex()));

  // The fence block, at catchain counter 2.
  f.advance(f.snapshot(f.current, 2), 12, kAfterTheMargin);
  f.run_for(0.5);
  // Counter 4 = 2 + 2 is fenced: a session the previous process could have reached.
  f.advance(f.snapshot(f.current, 4), 13, kAfterTheMargin);
  auto within = f.session_of(f.snapshot(f.current, 4));
  ASSERT_TRUE(f.wait_event("group " + within.to_hex(), 10.0));
  ASSERT_EQ(1u, f.journal->count("admission fenced " + within.to_hex()));
  // Counter 5 signs.
  f.advance(f.snapshot(f.current, 5), 14, kAfterTheMargin);
  auto above = f.session_of(f.snapshot(f.current, 5));
  ASSERT_TRUE(f.wait_event("group " + above.to_hex(), 10.0));
  ASSERT_EQ(1u, f.journal->count("admission admitted " + above.to_hex()));
}

// ===== The genesis ceremony's ledger at a real database =====

namespace {

const BlockIdExt kZeroState{masterchainId, shardIdAll, 0, hash("zerostate-root"), hash("zerostate-file")};

// Starts a node whose ledger the genesis ceremony made with `floor`, configured with the
// zerostate kZeroState, and whose real database holds the zerostate and block 1 as block
// application stores them. Returns how the first session was admitted.
std::string genesis_start(const BlockIdExt& floor) {
  Fixture f(
      [&](const std::string& root) {
        CHECK(consensus::signing::create_ledger(ledger_of(root), member_id(2, 0).value,
                                                consensus::signing::default_file_ops(), floor)
                  .is_ok());
      },
      kZeroState);
  f.archive_block(kZeroState, 1000, 0);
  f.archive_block(BlockIdExt{masterchainId, shardIdAll, 1, hash("block-1-root"), hash("block-1-file")}, 1001, 1000000);
  // The database an ordinary floor check reads: a zerostate is not in its seqno index.
  CHECK(!f.find_by_seqno(0));
  CHECK(f.find_by_seqno(1));
  f.hold(f.current, 0);
  f.set_tip(f.snapshot(f.current, 1), 10, kFresh);
  CHECK(!f.decide());
  f.advance(f.snapshot(f.current, 1), 10, kFresh);
  auto session = f.session_of(f.snapshot(f.current, 1));
  if (!f.wait_event("group " + session.to_hex(), 10.0)) {
    return "no group";
  }
  if (f.journal->count("admission admitted " + session.to_hex()) == 1) {
    return "admitted";
  }
  if (f.journal->count("admission fenced " + session.to_hex()) == 1) {
    return "fenced";
  }
  return "unknown";
}

}  // namespace

// A ledger the genesis ceremony made at this node's zerostate admits the first session.
TEST(StartupCatchupManager, GenesisCeremonyLedgerAdmits) {
  ASSERT_EQ(std::string("admitted"), genesis_start(kZeroState));
}

// A ceremony ledger made for another zerostate admits nothing: another root hash, or
// another file hash.
TEST(StartupCatchupManager, GenesisCeremonyLedgerForAnotherRootHashFences) {
  BlockIdExt other = kZeroState;
  other.root_hash = hash("another-zerostate-root");
  ASSERT_EQ(std::string("fenced"), genesis_start(other));
}

TEST(StartupCatchupManager, GenesisCeremonyLedgerForAnotherFileHashFences) {
  BlockIdExt other = kZeroState;
  other.file_hash = hash("another-zerostate-file");
  ASSERT_EQ(std::string("fenced"), genesis_start(other));
}

// ===== Unknown history: which sessions the fence covers, through the group update =====
//
// Each test has two halves. The first runs a node that may sign (a complete ledger) and
// shows, through the production group update, a session such a node builds before an
// unknown restart. The second runs a node whose earlier signing is unknown: the session
// is not derived at its fence block M, comes back after M, and is fenced. The selection
// compares the split/merge time with the real clock: a split or merge due within 60 s
// derives the new lineage, so `kSoon` (30 s) derives it and `kLater` (600 s) does not.
// The tests take seconds, and assume the clock does not step by 30 s meanwhile.

namespace {

using Fsm = block::McShardHashI::FsmState;
constexpr double kSoon = 30.0;
constexpr double kLater = 600.0;
constexpr double kAfterTheMarginOfStart = -(consensus::signing::kHistoryMarginSeconds + 5.0);
const ShardIdFull kBase{basechainId, shardIdAll};
const ShardIdFull kLeft{basechainId, shard_child(shardIdAll, true)};
const ShardIdFull kRight{basechainId, shard_child(shardIdAll, false)};

Snapshot with_shards(Snapshot snapshot, std::vector<ShardSpec> shards) {
  snapshot.shards = std::move(shards);
  return snapshot;
}

// "admitted", "fenced", or "none" when no group was built for the session.
std::string admission_of(Fixture& f, const ValidatorSessionId& session, double timeout = 10.0) {
  if (!f.wait_event("group " + session.to_hex(), timeout)) {
    return "none";
  }
  if (f.journal->count("admission admitted " + session.to_hex()) > 0) {
    return "admitted";
  }
  if (f.journal->count("admission fenced " + session.to_hex()) > 0) {
    return "fenced";
  }
  return "unknown";
}

// A node that may sign: a complete ledger for member 0 of `current`.
std::function<void(const std::string&)> signing_node() {
  return [](const std::string& root) { make_ledger(root, member_id(2, 0), std::nullopt); };
}

// Starts a node with unknown history at `before` (fresh) and settles its fence at `at_m`,
// a block generated after the margin. Every group built before M is fenced.
void settle_fence_at(Fixture& f, const Snapshot& before, const Snapshot& at_m) {
  f.hold(f.current, 0);
  f.set_tip(before, 10, kFresh);
  CHECK(!f.decide());
  f.advance(before, 10, kFresh);
  CHECK(admission_of(f, f.session_of(before)) == "fenced");
  f.advance(at_m, 11, kAfterTheMarginOfStart);
  f.run_for(0.5);
}

}  // namespace

// A split due soon derives tentative children; a node may sign in them. At M the split is
// postponed, so the children are not derived; after M the split happens and a child's
// session with that counter comes back. It is fenced, through the parent's entry.
TEST(StartupCatchupManager, UnknownHistoryTentativeLineageDisappearsAndReturns) {
  {
    Fixture old(signing_node());
    old.hold(old.current, 0);
    auto soon = with_shards(old.snapshot(old.current, 1), {{kBase, 5, Fsm::fsm_split, kSoon}});
    old.set_tip(soon, 10, kFresh);
    ASSERT_TRUE(!old.decide());
    old.advance(soon, 10, kFresh);
    ASSERT_EQ(std::string("admitted"), admission_of(old, old.session_for(soon, kLeft, 6)));
  }
  Fixture f;
  auto at_m = with_shards(f.snapshot(f.current, 1), {{kBase, 5, Fsm::fsm_split, kLater}});
  settle_fence_at(f, f.snapshot(f.current, 1), at_m);
  auto returning = f.session_for(at_m, kLeft, 6);
  ASSERT_EQ(std::string("none"), admission_of(f, returning, 0.5));  // not derived at M
  ASSERT_EQ(std::string("fenced"), admission_of(f, f.session_for(at_m, kBase, 6)));
  auto split = with_shards(f.snapshot(f.current, 1), {{kLeft, 5}, {kRight, 5}});
  f.advance(split, 12, kAfterTheMarginOfStart);
  ASSERT_EQ(std::string("fenced"), admission_of(f, returning));
  // Three counters above the fence the child signs again.
  auto later = with_shards(f.snapshot(f.current, 1), {{kLeft, 8}, {kRight, 5}});
  f.advance(later, 13, kAfterTheMarginOfStart);
  ASSERT_EQ(std::string("admitted"), admission_of(f, f.session_for(later, kLeft, 8)));
}

// A merge due soon derives the prospective parent at max(children) + 1 and its tentative
// session at max + 2. At M the merge is postponed; after M it happens, and the parent's
// session at max + 2 is fenced. Max + 3 signs.
TEST(StartupCatchupManager, UnknownHistoryMergedParentTentative) {
  {
    Fixture old(signing_node());
    old.hold(old.current, 0);
    auto soon = with_shards(old.snapshot(old.current, 1),
                            {{kLeft, 5, Fsm::fsm_merge, kSoon}, {kRight, 7, Fsm::fsm_merge, kSoon}});
    old.set_tip(soon, 10, kFresh);
    ASSERT_TRUE(!old.decide());
    old.advance(soon, 10, kFresh);
    ASSERT_EQ(std::string("admitted"), admission_of(old, old.session_for(soon, kBase, 9)));
  }
  Fixture f;
  auto at_m =
      with_shards(f.snapshot(f.current, 1), {{kLeft, 5, Fsm::fsm_merge, kLater}, {kRight, 7, Fsm::fsm_merge, kLater}});
  settle_fence_at(f, f.snapshot(f.current, 1), at_m);
  auto parent_tentative = f.session_for(at_m, kBase, 9);
  ASSERT_EQ(std::string("none"), admission_of(f, parent_tentative, 0.5));  // not derived at M
  auto merged = with_shards(f.snapshot(f.current, 1), {{kBase, 8}});
  f.advance(merged, 12, kAfterTheMarginOfStart);
  ASSERT_EQ(std::string("fenced"), admission_of(f, f.session_for(merged, kBase, 8)));
  ASSERT_EQ(std::string("fenced"), admission_of(f, parent_tentative));
  auto later = with_shards(f.snapshot(f.current, 1), {{kBase, 10}});
  f.advance(later, 13, kAfterTheMarginOfStart);
  ASSERT_EQ(std::string("admitted"), admission_of(f, f.session_for(later, kBase, 10)));
}

// A tentative group, once built, is kept while no related active group passes its
// counter, even when the latest state no longer derives it. Such a group of the previous
// process is not derived at M; after M it becomes current and is fenced.
TEST(StartupCatchupManager, UnknownHistoryRetainedTentativeGroup) {
  {
    Fixture old(signing_node());
    old.hold(old.current, 0);
    auto soon = with_shards(old.snapshot(old.current, 1), {{kBase, 5, Fsm::fsm_split, kSoon}});
    old.set_tip(soon, 10, kFresh);
    ASSERT_TRUE(!old.decide());
    old.advance(soon, 10, kFresh);
    auto tentative = old.session_for(soon, kLeft, 6);
    ASSERT_EQ(std::string("admitted"), admission_of(old, tentative));
    auto postponed = with_shards(old.snapshot(old.current, 1), {{kBase, 5, Fsm::fsm_split, kLater}});
    old.advance(postponed, 11, kFresh);
    old.run_for(0.5);
    ASSERT_EQ(0u, old.journal->count("close " + tentative.to_hex()));  // kept, not derived
  }
  Fixture f;
  auto at_m = with_shards(f.snapshot(f.current, 1), {{kBase, 5}});
  settle_fence_at(f, f.snapshot(f.current, 1), at_m);
  auto split = with_shards(f.snapshot(f.current, 1), {{kLeft, 6}, {kRight, 6}});
  auto current = f.session_for(split, kLeft, 6);
  ASSERT_EQ(std::string("none"), admission_of(f, current, 0.5));  // not derived at M
  f.advance(split, 12, kAfterTheMarginOfStart);
  ASSERT_EQ(std::string("fenced"), admission_of(f, current));
  auto later = with_shards(f.snapshot(f.current, 1), {{kLeft, 8}, {kRight, 6}});
  f.advance(later, 13, kAfterTheMarginOfStart);
  ASSERT_EQ(std::string("admitted"), admission_of(f, f.session_for(later, kLeft, 8)));
}

// A key block after M changes every session id; the fence compares the lineage and the
// counter, so a session at a fenced counter stays fenced under its new id.
TEST(StartupCatchupManager, UnknownHistoryKeyBlockChangesTheId) {
  Fixture f;
  settle_fence_at(f, f.snapshot(f.current, 1), f.snapshot(f.current, 2));
  auto next = f.snapshot(f.current, 3);
  auto before_key_block = f.session_for(next, ShardIdFull{masterchainId, shardIdAll}, 3);
  f.key_block(12);
  auto after_key_block = f.session_for(next, ShardIdFull{masterchainId, shardIdAll}, 3);
  ASSERT_TRUE(before_key_block != after_key_block);
  f.advance(next, 13, kAfterTheMarginOfStart);
  ASSERT_EQ(std::string("fenced"), admission_of(f, after_key_block));
  auto later = f.snapshot(f.current, 5);
  f.advance(later, 14, kAfterTheMarginOfStart);
  ASSERT_EQ(std::string("admitted"), admission_of(f, f.session_for(later, ShardIdFull{masterchainId, shardIdAll}, 5)));
}

// ===== Every network, with the options the engine builds =====

namespace {

// Starts a node at a state of `global_id` with the options as the engine builds them, with
// or without a complete ledger, and returns how its first session was admitted.
std::string first_admission_on(td::int32 global_id, bool with_ledger, bool* ledger_after = nullptr) {
  Fixture f(with_ledger ? signing_node() : nullptr);
  f.hold(f.current, 0);
  auto state = f.snapshot(f.current, 1);
  state.global_id = global_id;
  f.set_tip(state, 10, kFresh);
  CHECK(!f.decide());
  f.advance(state, 10, kFresh);
  auto admission = admission_of(f, f.session_of(state));
  if (ledger_after != nullptr) {
    *ledger_after = f.ledger_exists();
  }
  return admission;
}

}  // namespace

// The production default: no flag, no network check. A validator records its decisions on
// mainnet, the public testnet and a local network alike.
TEST(StartupCatchupManager, EveryNetworkUsesTheLog) {
  for (td::int32 global_id : {1, 2, 3}) {
    ASSERT_EQ(std::string("admitted"), first_admission_on(global_id, true));
  }
}

// On the public testnet, a validator without a ledger is fenced, not signing without a
// record, and its first admission leaves a ledger on disk.
TEST(StartupCatchupManager, WithoutALedgerTheTestnetFencesAndCreatesOne) {
  bool ledger = false;
  ASSERT_EQ(std::string("fenced"), first_admission_on(2, false, &ledger));
  ASSERT_TRUE(ledger);
}

// ===== The fence block, per identity, from custody =====

// A validator-elect whose node has run since before the fence margin: the fence block is
// the first qualifying block this process applied after custody, recorded before the first
// admission, so the first session three counters above it signs. Before the fix the ledger
// waited for a block after the first admission and fenced the incoming set's first sessions.
TEST(StartupCatchupManager, FenceBlockRecordedBeforeFirstAdmission) {
  Fixture f;
  f.hold(f.next, 0);
  auto before = f.snapshot(f.current, 1);
  f.set_tip(before, 10, kFresh);
  ASSERT_TRUE(!f.decide());
  f.advance(before, 10, kAfterTheMarginOfStart);
  f.advance(f.snapshot(f.current, 1), 11, kAfterTheMarginOfStart);
  f.run_for(0.5);
  ASSERT_TRUE(!f.ledger_exists());  // recorded in memory, before any ledger
  auto record = f.identity_record(f.next, 0);
  ASSERT_TRUE(record.has_value());
  ASSERT_EQ(10, record->second);
  // The incoming set at counter 3 = cc(M) + 2 is fenced; at 4 it signs.
  auto at_margin = f.snapshot(f.next, 3);
  f.advance(at_margin, 12, kAfterTheMarginOfStart);
  ASSERT_EQ(std::string("fenced"), admission_of(f, f.session_of(at_margin)));
  auto elected = f.snapshot(f.next, 4);
  f.advance(elected, 13, kAfterTheMarginOfStart);
  ASSERT_EQ(std::string("admitted"), admission_of(f, f.session_of(elected)));
}

// Custody taken late: the process starts at T and applies blocks from T + 91 on, but the key
// is bound at T + 600. The first admission is pending, and only a block generated at
// T + 600 + 91 or later establishes the ledger.
TEST(StartupCatchupManager, LateCustody) {
  constexpr double kLate = 600.0;
  constexpr double kAfterCustody = -(kLate + consensus::signing::kHistoryMarginSeconds + 5.0);
  Fixture f;
  auto first = f.snapshot(f.current, 1);
  f.set_tip(first, 10, kFresh);
  ASSERT_TRUE(!f.decide());
  f.advance(first, 10, kAfterTheMarginOfStart);  // before custody: never the fence block
  f.custody_clock_offset(kLate);
  f.hold(f.current, 0);
  f.advance(first, 11, kAfterTheMarginOfStart);  // after custody, before custody + 91
  ASSERT_EQ(std::string("fenced"), admission_of(f, f.session_of(first)));
  auto record = f.identity_record(f.current, 0);
  ASSERT_TRUE(record.has_value());
  ASSERT_EQ(-1, record->second);
  f.advance(f.snapshot(f.current, 2), 12, kAfterCustody);
  f.run_for(0.5);
  record = f.identity_record(f.current, 0);
  ASSERT_TRUE(record.has_value());
  ASSERT_EQ(12, record->second);
  auto within = f.snapshot(f.current, 4);
  f.advance(within, 13, kAfterCustody);
  ASSERT_EQ(std::string("fenced"), admission_of(f, f.session_of(within)));
  auto above = f.snapshot(f.current, 5);
  f.advance(above, 14, kAfterCustody);
  ASSERT_EQ(std::string("admitted"), admission_of(f, f.session_of(above)));
}

// A rebind: identity A's record is dropped with its custody, and identity B waits from its
// own custody time; A's fence block is never used for B.
TEST(StartupCatchupManager, Rebind) {
  Fixture f;
  f.hold(f.next, 0);
  auto state = f.snapshot(f.current, 1);
  f.set_tip(state, 10, kFresh);
  ASSERT_TRUE(!f.decide());
  f.advance(state, 10, kAfterTheMarginOfStart);
  auto a = f.identity_record(f.next, 0);
  ASSERT_TRUE(a.has_value() && a->second == 10);
  f.release(f.next, 0);
  ASSERT_TRUE(!f.identity_record(f.next, 0).has_value());
  f.custody_clock_offset(300.0);
  f.hold(f.next, 1);
  auto b = f.identity_record(f.next, 1);
  ASSERT_TRUE(b.has_value() && b->second == -1);
  f.advance(state, 11, kAfterTheMarginOfStart);  // after B's custody, before B's t0 + 91
  b = f.identity_record(f.next, 1);
  ASSERT_TRUE(b.has_value() && b->second == -1);
  f.advance(state, 12, -(300.0 + consensus::signing::kHistoryMarginSeconds + 5.0));
  b = f.identity_record(f.next, 1);
  ASSERT_TRUE(b.has_value() && b->second == 12);
  // Re-added later, A is new: its old fence block is gone.
  f.hold(f.next, 0);
  a = f.identity_record(f.next, 0);
  ASSERT_TRUE(a.has_value() && a->second == -1);
}

// Two identities held at once keep independent records.
TEST(StartupCatchupManager, TwoIdentities) {
  Fixture f;
  f.hold(f.next, 0);
  f.custody_clock_offset(300.0);
  f.hold(f.next, 1);
  auto state = f.snapshot(f.current, 1);
  f.set_tip(state, 10, kFresh);
  ASSERT_TRUE(!f.decide());
  f.advance(state, 10, kAfterTheMarginOfStart);
  auto a = f.identity_record(f.next, 0);
  auto b = f.identity_record(f.next, 1);
  ASSERT_TRUE(a.has_value() && a->second == 10);
  ASSERT_TRUE(b.has_value() && b->second == -1);
  ASSERT_TRUE(b->first >= a->first + 299);
  f.advance(state, 11, -(300.0 + consensus::signing::kHistoryMarginSeconds + 5.0));
  a = f.identity_record(f.next, 0);
  b = f.identity_record(f.next, 1);
  ASSERT_TRUE(a.has_value() && a->second == 10);
  ASSERT_TRUE(b.has_value() && b->second == 11);
}

// At the zerostate, a validator whose history is unknown logs the genesis-ceremony hint once;
// it still signs nothing.
TEST(StartupCatchupManager, GenesisWithoutALedgerLogsTheCeremonyHint) {
  Fixture f;
  f.hold(f.current, 0);
  auto state = f.snapshot(f.current, 1);
  f.set_tip(state, 0, kFresh);
  ASSERT_TRUE(!f.decide());
  f.advance(state, 0, kFresh);
  ASSERT_EQ(std::string("fenced"), admission_of(f, f.session_of(state)));
  ASSERT_TRUE(f.genesis_hint_logged());
}

// Past the zerostate a pending node is an ordinary unknown history: no genesis hint.
TEST(StartupCatchupManager, PastGenesisNoCeremonyHint) {
  Fixture f;
  f.hold(f.current, 0);
  auto state = f.snapshot(f.current, 1);
  f.set_tip(state, 10, kFresh);
  ASSERT_TRUE(!f.decide());
  f.advance(state, 10, kFresh);
  ASSERT_EQ(std::string("fenced"), admission_of(f, f.session_of(state)));
  ASSERT_TRUE(!f.genesis_hint_logged());
}

// A split child not yet in the configuration reads its parent's counter through the
// production derivation (the ancestor branch), so the parent's entry at M fences the child's
// sessions up to parent + 2.
TEST(StartupCatchupManager, SplitChildReadsTheParentCounter) {
  Epoch epoch{2};
  Snapshot snapshot{epoch.set(1), epoch.set(1), epoch.set(2), 1};
  snapshot.shards = {{kBase, 5}};
  State state(BlockIdExt{masterchainId, shardIdAll, 1, hash("split-root"), hash("split-file")}, snapshot);
  ASSERT_EQ(5u, state.get_shard_cc_seqno(kLeft));
  ASSERT_EQ(5u, state.get_shard_cc_seqno(kRight));
  const std::vector<consensus::signing::FenceEntry> fence = {
      {masterchainId, shardIdAll, 1}, {basechainId, shardIdAll, state.get_shard_cc_seqno(kBase)}};
  ASSERT_TRUE(consensus::signing::fenced_by_history(fence, kLeft, 7));
  ASSERT_TRUE(!consensus::signing::fenced_by_history(fence, kLeft, 8));
}
