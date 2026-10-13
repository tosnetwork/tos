/* Copyright (c) 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <algorithm>
#include <atomic>
#include <map>
#include <mutex>
#include <set>
#include <thread>

#include "adnl/adnl-test-loopback-implementation.h"
#include "auto/tl/tos_api.hpp"
#include "block/validator-session-id.h"
#include "common/errorlog.h"
#include "keyring/keyring.h"
#include "overlay/overlay-manager.h"
#include "overlay/overlay.h"
#include "quic/quic-sender.h"
#include "rldp2/rldp.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"
#include "td/utils/tests.h"
#include "test/consensus-checkpoint-chain.h"
#include "test/plumtree/scheduler.h"
#include "test/plumtree/transport.h"
#include "test/plumtree/util.h"
#include "validator/consensus/bus.h"
#include "validator/consensus/db-path.h"
#include "validator/consensus/simplex/bus.h"
#include "validator/fabric.h"
#include "validator/impl/applied-ext-message-cleanup.hpp"
#include "validator/impl/ext-message-pool.hpp"
#include "validator/impl/shard.hpp"
#include "validator/manager.hpp"
#include "validator/validator-options.hpp"
#include "vm/cells.h"

namespace tos::validator {
using consensus::BusHandle;
namespace {
td::Bits256 hash(td::Slice value) {
  return td::sha256_bits256(value);
}
// Production manager requires the QUIC actor type. Only its transport is replaced;
// the overlay sender API and all overlay protocol processing remain unchanged.
class FixtureQuicSender : public quic::QuicSender {
 public:
  FixtureQuicSender(td::actor::ActorId<adnl::AdnlPeerTable> adnl, td::actor::ActorId<keyring::Keyring> keys,
                    std::shared_ptr<overlay::plumtree_sim::SimNetwork> network)
      : QuicSender(adnl, keys), network_(std::move(network)) {
  }
  void add_id(adnl::AdnlNodeIdShort) override {
  }
  void send_message(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, td::BufferSlice data) override {
    network_->enqueue(src, dst, std::move(data));
  }
  void send_query(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, std::string,
                  td::Promise<td::BufferSlice> promise, td::Timestamp, td::BufferSlice data) override {
    network_->enqueue_query(src, dst, std::move(data), std::move(promise));
  }
  void send_query_ex(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, std::string name,
                     td::Promise<td::BufferSlice> promise, td::Timestamp timeout, td::BufferSlice data,
                     td::uint64) override {
    send_query(src, dst, std::move(name), std::move(promise), timeout, std::move(data));
  }
  void get_conn_ip_str(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, td::Promise<std::string> promise) override {
    promise.set_value("");
  }

 private:
  void start_up() override {
  }
  void alarm() override {
  }
  void on_mtu_updated(td::optional<adnl::AdnlNodeIdShort>, td::optional<adnl::AdnlNodeIdShort>) override {
  }
  std::shared_ptr<overlay::plumtree_sim::SimNetwork> network_;
};
struct Epoch {
  std::vector<PrivateKey> transport;
  std::vector<std::shared_ptr<const pq::ValidatorPQKeyStore>> custody;
  std::vector<ValidatorDescr> members;
  explicit Epoch(int index, size_t count = 7) {
    for (size_t i = 0; i < count; ++i) {
      auto label = PSTRING() << "twostep-epoch-" << index << "-" << i;
      transport.push_back(overlay::plumtree_sim::make_key(label));
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
  td::Ref<block::ValidatorSet> set(CatchainSeqno cc, size_t committee = 0) const {
    auto rows = members;
    if (committee)
      rows.erase(rows.begin() + committee, rows.end());
    return td::make_ref<block::ValidatorSet>(cc, ShardIdFull{masterchainId}, std::move(rows));
  }
  std::set<adnl::AdnlNodeIdShort> ids() const {
    std::set<adnl::AdnlNodeIdShort> result;
    for (const auto& d : members)
      result.emplace(d.addr);
    return result;
  }
};
struct Snapshot {
  td::Ref<block::ValidatorSet> previous, current, next, committee, future;
  bool new_ids = true;
  unsigned protocol = 2;
};
class StateConfig : public ConfigHolder {
 public:
  explicit StateConfig(Snapshot snapshot) : snapshot_(std::move(snapshot)) {
  }
  td::Ref<block::ValidatorSet> get_total_validator_set(int offset) const override {
    return offset < 0 ? snapshot_.previous : offset > 0 ? snapshot_.next : snapshot_.current;
  }
  td::Ref<block::ValidatorSet> get_validator_set(ShardIdFull, UnixTime, CatchainSeqno) const override {
    return snapshot_.committee;
  }
  std::pair<UnixTime, UnixTime> get_validator_set_start_stop(int) const override {
    return {0, 0x7fffffff};
  }
  td::int32 get_global_id() const override {
    return 3;
  }
  td::Result<td::int32> get_config_global_id() const override {
    return 3;
  }
  ValidatorSessionConfig get_consensus_config() const override {
    ValidatorSessionConfig result;
    result.new_catchain_ids = snapshot_.new_ids;
    return result;
  }
  td::optional<SelectedNewConsensusConfig> get_selected_new_consensus_config(WorkchainId) const override {
    NewConsensusConfig result;
    result.protocol_version = snapshot_.protocol;
    return SelectedNewConsensusConfig{result, hash(PSTRING() << "protocol-" << snapshot_.protocol)};
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
class State : public MasterchainStateQ {
 public:
  // `ancestors` are the masterchain blocks this state verifies as strict
  // ancestors (its prev_blocks), for the consensus cleanup checkpoint checks.
  State(BlockIdExt id, Snapshot snapshot, std::set<BlockIdExt> ancestors = {})
      : MasterchainStateQ(id, vm::CellBuilder{}.finalize_novm())
      , snapshot_(std::move(snapshot))
      , ancestors_(std::move(ancestors)) {
  }
  bool check_old_mc_block_id(const BlockIdExt& id, bool strict) const override {
    return ancestors_.contains(id) || (!strict && id == get_block_id());
  }
  td::Ref<block::ValidatorSet> get_total_validator_set(int offset) const override {
    return offset < 0 ? snapshot_.previous : offset > 0 ? snapshot_.next : snapshot_.current;
  }
  td::Ref<block::ValidatorSet> get_validator_set(ShardIdFull) const override {
    return snapshot_.committee;
  }
  td::Ref<block::ValidatorSet> get_next_validator_set(ShardIdFull) const override {
    return snapshot_.future;
  }
  td::int32 get_global_id() const override {
    return 3;
  }
  bool rotated_all_shards() const override {
    return false;
  }
  std::vector<td::Ref<McShardHash>> get_shards() const override {
    return {};
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
  Snapshot snapshot_;
  std::set<BlockIdExt> ancestors_;
};
std::recursive_mutex observation_mutex;
struct ReceivedCandidate {
  adnl::AdnlNodeIdShort local;
  consensus::CandidateId id;
  PublicKeyHash source;
  ValidatorSessionId session;
  overlay::OverlayIdShort overlay;
};
class CandidateCapture : public overlay::Overlays::Callback {
 public:
  CandidateCapture(adnl::AdnlNodeIdShort local, std::unique_ptr<Callback> delegate, const std::vector<BusHandle>& buses,
                   std::vector<ReceivedCandidate>& received)
      : local_(local), delegate_(std::move(delegate)), buses_(buses), received_(received) {
  }
  void receive_message(adnl::AdnlNodeIdShort src, overlay::OverlayIdShort id, td::BufferSlice data) override {
    delegate_->receive_message(src, id, std::move(data));
  }
  void receive_query(adnl::AdnlNodeIdShort src, overlay::OverlayIdShort id, td::BufferSlice data,
                     td::Promise<td::BufferSlice> promise) override {
    delegate_->receive_query(src, id, std::move(data), std::move(promise));
  }
  void receive_broadcast_with_extra(PublicKeyHash src, overlay::OverlayIdShort id, td::BufferSlice data,
                                    td::BufferSlice extra) override {
    std::lock_guard lock(observation_mutex);
    auto metadata = fetch_tl_object<tos_api::consensus_broadcastExtra>(extra, true).move_as_ok();
    bool found = false;
    for (const auto& bus : buses_)
      if (bus->local_adnl_id == local_) {
        auto candidate = consensus::Candidate::deserialize(data.as_slice(), *bus, std::nullopt, metadata->slot_);
        if (candidate.is_ok()) {
          received_.push_back({local_, candidate.ok()->id, src, bus->session_id, id});
          found = true;
          break;
        }
      }
    CHECK(found);
    delegate_->receive_broadcast_with_extra(src, id, std::move(data), std::move(extra));
  }
  void check_broadcast(PublicKeyHash src, overlay::OverlayIdShort id, td::BufferSlice data,
                       td::Promise<> promise) override {
    delegate_->check_broadcast(src, id, std::move(data), std::move(promise));
  }
  void precheck_broadcast(PublicKeyHash src, overlay::OverlayIdShort id, td::Bits256 hash, td::BufferSlice extra,
                          bool checked, td::Promise<> promise) override {
    delegate_->precheck_broadcast(src, id, hash, std::move(extra), checked, std::move(promise));
  }
  void get_stats_extra(td::Promise<std::string> promise) override {
    delegate_->get_stats_extra(std::move(promise));
  }

 private:
  adnl::AdnlNodeIdShort local_;
  std::unique_ptr<Callback> delegate_;
  const std::vector<BusHandle>& buses_;
  std::vector<ReceivedCandidate>& received_;
};
struct Observation {
  adnl::AdnlNodeIdShort local;
  std::vector<adnl::AdnlNodeIdShort> members;
  std::set<adnl::AdnlNodeIdShort> relays;
  std::set<PublicKeyHash> authorized;
  std::string name;
  overlay::OverlayIdShort overlay;
};
class ObservedOverlays : public overlay::OverlayManager {
 public:
  ObservedOverlays(std::string root, td::actor::ActorId<keyring::Keyring> keys, td::actor::ActorId<adnl::Adnl> adnl,
                   std::vector<Observation>& observations, const std::vector<BusHandle>& buses,
                   std::vector<ReceivedCandidate>& received)
      : OverlayManager(root, keys, adnl, {}), observations_(observations), buses_(buses), received_(received) {
  }
  void create_private_overlay_ex(adnl::AdnlNodeIdShort local, overlay::OverlayIdFull id,
                                 std::vector<adnl::AdnlNodeIdShort> members, std::unique_ptr<Callback> callback,
                                 overlay::OverlayPrivacyRules rules, std::string scope,
                                 overlay::OverlayOptions options) override {
    std::lock_guard lock(observation_mutex);
    Observation row{local, members, options.twostep_intermediate_nodes_, {}, options.name_, id.compute_short_id()};
    for (const auto& key : rules.get_authorized_keys())
      row.authorized.insert(key);
    observations_.push_back(std::move(row));
    callback = std::make_unique<CandidateCapture>(local, std::move(callback), buses_, received_);
    OverlayManager::create_private_overlay_ex(local, std::move(id), std::move(members), std::move(callback),
                                              std::move(rules), std::move(scope), std::move(options));
  }

 private:
  std::vector<Observation>& observations_;
  const std::vector<BusHandle>& buses_;
  std::vector<ReceivedCandidate>& received_;
};
}  // namespace

// Only the node's network-heavy startup and unresolved chain-state I/O are held.
// The manager selection/reuse/retirement, RootDb, both factories, bus initialization
// and overlay construction remain production code.
class TwostepManagerProbe : public ValidatorManagerImpl {
 public:
  TwostepManagerProbe(std::string root, td::actor::ActorId<keyring::Keyring> keys, td::actor::ActorId<adnl::Adnl> adnl,
                      td::actor::ActorId<quic::QuicSender> sender, td::actor::ActorId<rldp2::Rldp> rldp,
                      td::actor::ActorId<overlay::Overlays> overlays)
      : ValidatorManagerImpl(ValidatorManagerOptions::create(BlockIdExt{}, BlockIdExt{}), root, keys, adnl, rldp,
                             sender, overlays) {
  }
  void start_up() override {
    db_ = create_db_actor(actor_id(this), db_root_, opts_);
    callback_ = std::make_unique<ValidatorManagerInterface::Callback>();
    ext_message_pool_ = td::actor::create_actor<ExtMessagePool>("relay fixture ext messages", opts_, actor_id(this));
    allow_validate_ = true;
    auto zero = create_empty_block_handle(BlockIdExt{masterchainId, shardIdAll, 0, {}, {}});
    last_key_block_handle_ = zero;
    last_known_key_block_handle_ = zero;
  }
  void hold(const Epoch& epoch, size_t index) {
    pq_custody_.install(epoch.members[index].validator_id, epoch.custody[index], 0, 0).ensure();
  }
  void advance(Snapshot snapshot, BlockSeqno height, bool key_block, td::Promise<> promise) {
    last_masterchain_seqno_ = height;
    last_masterchain_block_id_ = BlockIdExt{masterchainId, shardIdAll, height, hash(PSTRING() << "root-" << height),
                                            hash(PSTRING() << "file-" << height)};
    last_masterchain_state_ = td::make_ref<State>(last_masterchain_block_id_, std::move(snapshot));
    last_masterchain_block_handle_ = create_empty_block_handle(last_masterchain_block_id_);
    last_masterchain_block_handle_->set_is_key_block(key_block);
    last_masterchain_block_handle_->set_unix_time(static_cast<UnixTime>(td::Clocks::system()));
    last_masterchain_block_handle_->flushed_upto(last_masterchain_block_handle_->version());
    new_masterchain_block();
    promise.set_value(td::Unit());
  }
  void inspect(td::Promise<std::vector<ValidatorSessionId>> promise) {
    std::vector<ValidatorSessionId> result;
    for (const auto& [id, entry] : validator_groups_) {
      CHECK(!entry.actor.empty());
      CHECK(entry.started);
      result.push_back(id);
    }
    for (const auto& [id, entry] : observer_groups_) {
      CHECK(!entry.actor.empty());
      CHECK(entry.started);
      result.push_back(id.first);
    }
    promise.set_value(std::move(result));
  }
  void tentative(td::Promise<std::vector<ValidatorSessionId>> promise) {
    std::vector<ValidatorSessionId> result;
    for (const auto& entry : next_validator_groups_) {
      CHECK(!entry.second.actor.empty());
      CHECK(!entry.second.started);
      result.push_back(entry.first);
    }
    promise.set_value(std::move(result));
  }
  void wait_block_state_short(BlockIdExt, td::uint32, td::Timestamp, bool,
                              td::Promise<td::Ref<ShardState>> promise) override {
    held_state_requests_.push_back(std::move(promise));
  }
  void wait_block_data(BlockHandle, td::uint32, td::Timestamp, td::Promise<td::Ref<BlockData>> promise) override {
    held_data_requests_.push_back(std::move(promise));
  }
  void wait_block_data_short(BlockIdExt, td::uint32, td::Timestamp, td::Promise<td::Ref<BlockData>> promise) override {
    held_data_requests_.push_back(std::move(promise));
  }
  // Installs a checkpoint as the startup loader's result does (started()).
  void install_checkpoint(BlockIdExt id, td::Promise<> promise) {
    install_loaded_consensus_cleanup_checkpoint(create_empty_block_handle(id), td::make_ref<State>(id, Snapshot{}));
    promise.set_value(td::Unit());
  }
  // Installs a checkpoint as an acknowledged checkpoint write does, at runtime.
  void advance_checkpoint(BlockIdExt id, td::Promise<> promise) {
    if (!consensus_checkpoint_loaded_) {
      install_loaded_consensus_cleanup_checkpoint({}, {});
    }
    install_consensus_cleanup_checkpoint(create_empty_block_handle(id), td::make_ref<State>(id, Snapshot{}));
    promise.set_value(td::Unit());
  }
  // A new applied masterchain block through the production admission path.
  void apply(Snapshot snapshot, BlockIdExt id, std::set<BlockIdExt> ancestors, td::Promise<> promise) {
    if (!consensus_checkpoint_loaded_) {
      install_loaded_consensus_cleanup_checkpoint({}, {});
    }
    last_masterchain_seqno_ = id.seqno() - 1;
    auto handle = create_empty_block_handle(id);
    handle->set_is_key_block(false);
    handle->set_unix_time(static_cast<UnixTime>(td::Clocks::system()));
    handle->flushed_upto(handle->version());
    new_block_cont(handle, td::make_ref<State>(id, std::move(snapshot), std::move(ancestors)), std::move(promise));
  }
  // The shard client's durable advance, through the production entry point.
  void shard_client_advanced(Snapshot snapshot, BlockIdExt id, std::set<BlockIdExt> ancestors, td::Promise<> promise) {
    auto handle = create_empty_block_handle(id);
    handle->set_is_key_block(false);
    handle->set_unix_time(static_cast<UnixTime>(td::Clocks::system()));
    handle->set_applied();
    handle->flushed_upto(handle->version());
    update_shard_client_block_handle(handle, td::make_ref<State>(id, std::move(snapshot), std::move(ancestors)),
                                     std::move(promise));
  }
  void retry_checkpoint(td::Promise<> promise) {
    try_advance_consensus_cleanup_checkpoint();
    promise.set_value(td::Unit());
  }
  void checkpoint(td::Promise<std::tuple<std::optional<BlockIdExt>, bool, BlockIdExt>> promise) {
    promise.set_value(std::make_tuple(consensus_checkpoint_.installed(), bool{consensus_checkpoint_reached_},
                                      last_masterchain_block_id_));
  }
  void complete_sync(td::Promise<> promise) {
    sync_complete({});
    promise.set_value(td::Unit());
  }
  void validators(td::Promise<std::pair<std::vector<ValidatorSessionId>, std::vector<ValidatorSessionId>>> promise) {
    std::vector<ValidatorSessionId> active, tentative;
    for (const auto& [id, entry] : validator_groups_)
      active.push_back(id);
    for (const auto& [id, entry] : next_validator_groups_)
      tentative.push_back(id);
    promise.set_value(std::make_pair(std::move(active), std::move(tentative)));
  }
  void closed(td::Promise<std::set<ValidatorSessionId>> promise) {
    promise.set_value(std::set<ValidatorSessionId>(closed_.begin(), closed_.end()));
  }
  // Production stops the process here (exit status 2); the fixture records the
  // call and returns, and production code returns right after the hook.
  void fail_stop_consensus_checkpoint(td::Status status) override {
    fail_stops_.push_back(status.message().str());
  }
  void fail_stops(td::Promise<std::vector<std::string>> promise) {
    promise.set_value(std::vector<std::string>(fail_stops_));
  }
  // The rest of start-up after the init handoff talks to the network.
  void continue_start_up() override {
  }
  // Startup catch-up's group fence: the entry decision taken as entered, and the
  // production exit, which runs update_shards when the fence opens.
  void enter_catchup(td::Promise<bool> promise) {
    promise.set_value(startup_catchup_.decide(startup_catchup::EntryRefusal::None));
  }
  void end_catchup(startup_catchup::ExitReason reason, td::Promise<> promise) {
    // A node always has a shard client handle by then (the exit logs it); the
    // fixture's shard client is at the head.
    if (!shard_client_handle_) {
      shard_client_handle_ = last_masterchain_block_handle_;
    }
    end_startup_catchup(reason);
    promise.set_value(td::Unit());
  }
  // (checkpoint readiness, catch-up fence closed, validator groups permitted,
  // observer groups permitted)
  // The ADNL ids of the applied head's masterchain committee.
  void committee(td::Promise<std::set<adnl::AdnlNodeIdShort>> promise) {
    std::set<adnl::AdnlNodeIdShort> result;
    for (const auto& d : last_masterchain_state_->get_validator_set(ShardIdFull{masterchainId})->export_vector())
      result.emplace(d.addr);
    promise.set_value(std::move(result));
  }
  void gates(td::Promise<std::vector<bool>> promise) {
    promise.set_value(std::vector<bool>{consensus_checkpoint_reached_, startup_catchup_.fence_closed(),
                                        validator_groups_permitted(), observer_groups_permitted()});
  }
  // The group factory called directly, past every caller's gate, for the current
  // masterchain set; a built group is destroyed again at once.
  void build_directly(td::Promise<bool> promise) {
    auto set = last_masterchain_state_->get_validator_set(ShardIdFull{masterchainId});
    auto selected = last_masterchain_state_->get_selected_new_consensus_config(masterchainId);
    consensus::ValidatorSessionOptions opts{last_masterchain_state_->get_consensus_config()};
    auto group = create_validator_group(hash("direct-build"), ShardIdFull{masterchainId}, set,
                                        last_key_block_handle_->id().seqno(), selected.value().config, opts, false);
    bool built = !group.empty();
    if (built) {
      td::actor::send_closure(group, &IValidatorGroup::destroy);
      group.release();
    }
    promise.set_value(std::move(built));
  }
  // Checkpoint writes fail with an ordinary (uncertain) error while set.
  void set_fail_persist(bool fail, td::Promise<> promise) {
    fail_persist_ = fail;
    promise.set_value(td::Unit());
  }
  void persist_consensus_cleanup_checkpoint(BlockIdExt id, td::Promise<td::Unit> promise) override {
    persist_calls_++;
    if (fail_persist_) {
      promise.set_error(td::Status::Error("injected checkpoint write failure"));
      return;
    }
    ValidatorManagerImpl::persist_consensus_cleanup_checkpoint(id, std::move(promise));
  }
  struct WriteStatus {
    std::optional<BlockIdExt> installed, in_flight, anchor;
    bool uncertain = false, pending = false;
    int persist_calls = 0;
  };
  // The checkpoint's write state and the cleanup oracles' anchor.
  void write_status(td::Promise<WriteStatus> promise) {
    WriteStatus s;
    s.installed = consensus_checkpoint_.installed();
    s.in_flight = consensus_checkpoint_.in_flight();
    s.uncertain = consensus_checkpoint_.uncertain();
    s.pending = consensus_checkpoint_.has_pending();
    s.persist_calls = persist_calls_;
    if (auto oracles = validator_cleanup_oracles()) {
      s.anchor = oracles->gc;
    }
    promise.set_value(std::move(s));
  }
  // Persists a checkpoint without installing it (the next start loads it).
  void persist_checkpoint(BlockIdExt id, td::Promise<> promise) {
    td::actor::send_closure(db_, &Db::update_consensus_cleanup_checkpoint, id, std::move(promise));
  }
  // Stores a real block's handle and state, as the node would have.
  void seed_block(BlockIdExt id, td::Ref<MasterchainStateQ> state, td::Promise<> promise) {
    auto handle = create_empty_block_handle(id);
    handle->set_logical_time(state->get_logical_time());
    handle->set_unix_time(state->get_unix_time());
    handle->set_split(false);
    handle->set_merge(false);
    handle->set_is_key_block(false);
    handle->set_applied();
    handle->set_applied_stored();
    handle->set_processed();
    auto db = db_.get();
    td::actor::send_closure(db, &Db::store_block_state, handle, td::Ref<ShardState>{state}, vm::StoreCellHint{},
                            [db, handle, promise = std::move(promise)](td::Result<td::Ref<ShardState>> R) mutable {
                              if (R.is_error()) {
                                return promise.set_error(R.move_as_error());
                              }
                              td::actor::send_closure(db, &Db::store_block_handle, handle, std::move(promise));
                            });
  }
  // Persists a checkpoint and installs it, as an acknowledged write does.
  void persist_and_install_checkpoint(BlockIdExt id, td::Promise<> promise) {
    if (!consensus_checkpoint_loaded_) {
      install_loaded_consensus_cleanup_checkpoint({}, {});
    }
    persist_then_install(id, std::move(promise)).start().detach_silent();
  }
  // The production loader reads the checkpoint from this root's database, and
  // its result goes through the production init handoff (started) with a head
  // given by the test.
  void start_from_disk(Snapshot snapshot, BlockIdExt head_id, std::set<BlockIdExt> ancestors,
                       td::Promise<bool> promise) {
    load_and_start(std::move(snapshot), head_id, std::move(ancestors), std::move(promise)).start().detach_silent();
  }
  void cleanup_tick(td::Promise<> promise) {
    validator_cleanup_timer();
    promise.set_value(td::Unit());
  }
  void consensus_db_closed(ValidatorSessionId session_id, td::uint64 generation, std::string dir_name) override {
    closed_.insert(session_id);
    ValidatorManagerImpl::consensus_db_closed(session_id, generation, std::move(dir_name));
  }
  void preflight(td::Promise<std::optional<std::set<adnl::AdnlNodeIdShort>>> promise) {
    promise.set_value(get_twostep_relay_snapshot());
  }
  void finish() {
    for (auto& [id, entry] : validator_groups_)
      td::actor::send_closure(entry.actor, &IValidatorGroup::destroy);
    for (auto& [id, entry] : observer_groups_)
      td::actor::send_closure(entry.actor, &IValidatorGroup::destroy);
    for (auto& [id, entry] : next_validator_groups_)
      td::actor::send_closure(entry.actor, &IValidatorGroup::destroy);
    validator_groups_.clear();
    observer_groups_.clear();
    next_validator_groups_.clear();
    shard_block_verifier_.reset();
    for (auto& request : held_state_requests_)
      request.set_error(td::Status::Error(ErrorCode::cancelled, "fixture teardown"));
    held_state_requests_.clear();
    for (auto& request : held_data_requests_)
      request.set_error(td::Status::Error(ErrorCode::cancelled, "fixture teardown"));
    held_data_requests_.clear();
  }

 private:
  td::actor::Task<> persist_then_install(BlockIdExt id, td::Promise<> promise) {
    auto r = co_await persist_then_install_inner(id).wrap();
    promise.set_result(std::move(r));
    co_return td::Unit{};
  }
  td::actor::Task<> persist_then_install_inner(BlockIdExt id) {
    co_await td::actor::ask(db_.get(), &Db::update_consensus_cleanup_checkpoint, id);
    auto handle = co_await td::actor::ask(actor_id(this), &ValidatorManager::get_block_handle, id, false);
    auto state = td::Ref<MasterchainState>{
        co_await td::actor::ask(actor_id(this), &ValidatorManager::get_shard_state_from_db, ConstBlockHandle{handle})};
    install_consensus_cleanup_checkpoint(std::move(handle), std::move(state));
    co_return td::Unit{};
  }
  td::actor::Task<> load_and_start(Snapshot snapshot, BlockIdExt head_id, std::set<BlockIdExt> ancestors,
                                   td::Promise<bool> promise) {
    auto loaded = co_await load_consensus_cleanup_checkpoint_for_startup(db_.get(), actor_id(this)).wrap();
    if (loaded.is_error()) {
      promise.set_error(loaded.move_as_error());
      co_return td::Unit{};
    }
    auto checkpoint = loaded.move_as_ok();
    auto head = create_empty_block_handle(head_id);
    head->set_is_key_block(false);
    head->set_unix_time(static_cast<UnixTime>(td::Clocks::system()));
    head->set_applied();
    head->flushed_upto(head->version());
    auto head_state =
        td::Ref<MasterchainState>{td::make_ref<State>(head_id, std::move(snapshot), std::move(ancestors))};
    ValidatorManagerInitResult R;
    R.handle = head;
    R.state = head_state;
    R.gc_handle = head;
    R.gc_state = head_state;
    R.last_key_block_handle_ = last_key_block_handle_;
    R.consensus_cleanup_checkpoint_handle = std::move(checkpoint.handle);
    R.consensus_cleanup_checkpoint_state = std::move(checkpoint.state);
    started(std::move(R));
    new_masterchain_block();
    promise.set_value(bool{consensus_checkpoint_reached_});
    co_return td::Unit{};
  }
  std::vector<std::string> fail_stops_;
  std::set<ValidatorSessionId> closed_;
  bool fail_persist_ = false;
  int persist_calls_ = 0;
  std::vector<td::Promise<td::Ref<ShardState>>> held_state_requests_;
  std::vector<td::Promise<td::Ref<BlockData>>> held_data_requests_;
};
}  // namespace tos::validator

namespace {
using namespace tos;
using namespace tos::validator;
using namespace tos::validator::consensus;
using namespace tos::overlay::plumtree_sim;
class Fixture {
 public:
  Epoch old{1, 2}, current{2}, next{3, 2};
  std::vector<Observation> overlays;
  std::vector<BusHandle> buses;
  std::vector<ReceivedCandidate> received;
  std::set<adnl::AdnlNodeIdShort> first_hops;
  Fixture()
      : root_(td::mkdtemp("/tmp", "twostep-wiring").move_as_ok())
      , scheduler_({1}, true)
      , network_(std::make_shared<SimNetwork>()) {
    observe_bridge_bus_for_test([this](BusHandle bus) {
      std::lock_guard lock(observation_mutex);
      observed_buses_.push_back(std::move(bus));
    });
    observe_bridge_session_activated_for_test([this](ValidatorSessionId session, bool validator) {
      std::lock_guard lock(observation_mutex);
      activated_.push_back({session, validator});
    });
    scheduler_.run_in_context([&] {
      errorlog::ErrorLog::create(root_);
      keys_ = keyring::Keyring::create(root_);
      net_ = td::actor::create_actor<adnl::TestLoopbackNetworkManager>("wiring network");
      adnl_ = adnl::Adnl::create(root_, keys_.get());
      td::actor::send_closure(adnl_, &adnl::Adnl::register_network_manager, net_.get());
      rldp_ = rldp2::Rldp::create(adnl_.get());
      sender_ = td::actor::create_actor<FixtureQuicSender>("wiring sender", td::actor::ActorId<adnl::AdnlPeerTable>{},
                                                           keys_.get(), network_);
      overlays_ = td::actor::create_actor<ObservedOverlays>("observed overlays", root_, keys_.get(), adnl_.get(),
                                                            observed_overlays_, observed_buses_, observed_received_);
      manager_ = td::actor::create_actor<TwostepManagerProbe>("relay manager", root_, keys_.get(), adnl_.get(),
                                                              sender_.get(), rldp_.get(), overlays_.get());
      auto address = adnl::TestLoopbackNetworkManager::generate_dummy_addr_list();
      for (const auto* epoch : {&old, &current, &next})
        for (size_t i = 0; i < epoch->members.size(); ++i) {
          td::actor::send_closure(keys_, &keyring::Keyring::add_key, epoch->transport[i], true, [](td::Result<>) {});
          td::actor::send_closure(adnl_, &adnl::Adnl::add_id,
                                  adnl::AdnlNodeIdFull{epoch->transport[i].compute_public_key()}, address,
                                  static_cast<td::uint8>(0));
        }
      network_->overlay_manager = overlays_.get();
      network_->base_time = td::Time::now();
      network_->geo_alpha_ms = 1;
      network_->geo_beta_ms_per_km = 0;
      network_->jitter = 0;
      for (const auto* epoch : {&old, &current, &next})
        for (const auto& d : epoch->members) {
          network_->node_by_adnl.emplace(adnl::AdnlNodeIdShort{d.addr}, network_->node_by_adnl.size());
          network_->geo_by_node.push_back({true, 0, 0});
        }
    });
    pump();
  }
  ~Fixture() {
    scheduler_.run_in_context([&] {
      td::actor::send_closure(manager_, &TwostepManagerProbe::finish);
      for (auto& actor : direct_groups_)
        td::actor::send_closure(actor, &IValidatorGroup::destroy);
      direct_groups_.clear();
    });
    pump();
    scheduler_.run_in_context([&] {
      std::lock_guard lock(observation_mutex);
      buses.clear();
      observed_buses_.clear();
    });
    observe_bridge_bus_for_test({});
    observe_bridge_session_activated_for_test({});
    pump();
    scheduler_.run_in_context([&] {
      manager_.reset();
      overlays_.reset();
      sender_.reset();
      rldp_.reset();
      adnl_.reset();
      net_.reset();
      keys_.reset();
    });
    pump();
    scheduler_.stop();
    td::rmrf(root_).ensure();
  }
  Snapshot initial(unsigned protocol = 2) const {
    return {old.set(1), current.set(1), next.set(2), current.set(1, 2), next.set(2), true, protocol};
  }
  void hold(Epoch& epoch, size_t i) {
    scheduler_.run_in_context(
        [&] { td::actor::send_closure(manager_, &TwostepManagerProbe::hold, std::cref(epoch), i); });
    pump();
  }
  void advance(Snapshot snapshot, unsigned height = 1, bool key = false) {
    std::atomic<bool> done = false;
    scheduler_.run_in_context([&] {
      td::actor::send_closure(manager_, &TwostepManagerProbe::advance, std::move(snapshot), height, key,
                              td::PromiseCreator::lambda([&](td::Result<> result) {
                                result.ensure();
                                done = true;
                              }));
    });
    wait_for([&] { return done.load(); }, "manager advance did not complete");
    // An equal historical Bus/overlay count is not evidence that this update's
    // new groups have started. Wait for every registered live session too.
    std::map<ValidatorSessionId, size_t> required;
    for (const auto& id : entries())
      ++required[id];
    for (const auto& id : entries(true))
      ++required[id];
    wait_for(
        [&] {
          std::map<ValidatorSessionId, size_t> observed;
          size_t expected_overlays = 0;
          for (const auto& bus : buses) {
            ++observed[bus->session_id];
            expected_overlays +=
                (bus->is_validator() || bus->config.observers_in_private_overlay()) + bus->config.enable_block_sync();
          }
          return overlays.size() == expected_overlays &&
                 std::all_of(required.begin(), required.end(),
                             [&](const auto& row) { return observed[row.first] >= row.second; });
        },
        "registered sessions or their overlays did not start");
  }
  // ---- consensus cleanup checkpoint ----
  static BlockIdExt main_block(BlockSeqno height) {
    return BlockIdExt{masterchainId, shardIdAll, height, hash(PSTRING() << "root-" << height),
                      hash(PSTRING() << "file-" << height)};
  }
  // A block at `height` on a branch that leaves the main chain after `fork_point`.
  static BlockIdExt fork_block(BlockSeqno height) {
    return BlockIdExt{masterchainId, shardIdAll, height, hash(PSTRING() << "fork-root-" << height),
                      hash(PSTRING() << "fork-file-" << height)};
  }
  static std::set<BlockIdExt> main_ancestors(BlockSeqno height) {
    std::set<BlockIdExt> result;
    for (BlockSeqno h = 1; h < height; ++h)
      result.insert(main_block(h));
    return result;
  }
  static std::set<BlockIdExt> fork_ancestors(BlockSeqno height, BlockSeqno fork_point) {
    auto result = main_ancestors(fork_point + 1);
    for (BlockSeqno h = fork_point + 1; h < height; ++h)
      result.insert(fork_block(h));
    return result;
  }
  template <class T, class Call>
  td::Result<T> query(Call call) {
    std::optional<td::Result<T>> result;
    scheduler_.run_in_context(
        [&] { call(td::PromiseCreator::lambda([&](td::Result<T> value) { result = std::move(value); })); });
    wait_for([&] { return result.has_value(); }, "manager query did not complete");
    return std::move(*result);
  }
  td::Status apply_head(Snapshot snapshot, BlockIdExt id, std::set<BlockIdExt> ancestors) {
    auto r = query<td::Unit>([&](auto promise) {
      td::actor::send_closure(manager_, &TwostepManagerProbe::apply, std::move(snapshot), id, std::move(ancestors),
                              std::move(promise));
    });
    if (r.is_error())
      return r.move_as_error();
    wait_registered_started();
    return td::Status::OK();
  }
  void install_checkpoint(BlockIdExt id, bool at_runtime = false) {
    query<td::Unit>([&](auto promise) {
      td::actor::send_closure(
          manager_, at_runtime ? &TwostepManagerProbe::advance_checkpoint : &TwostepManagerProbe::install_checkpoint,
          id, std::move(promise));
    }).ensure();
    pump();
  }
  std::tuple<std::optional<BlockIdExt>, bool, BlockIdExt> checkpoint() {
    return query<std::tuple<std::optional<BlockIdExt>, bool, BlockIdExt>>([&](auto promise) {
             td::actor::send_closure(manager_, &TwostepManagerProbe::checkpoint, std::move(promise));
           })
        .move_as_ok();
  }
  void complete_sync() {
    query<td::Unit>([&](auto promise) {
      td::actor::send_closure(manager_, &TwostepManagerProbe::complete_sync, std::move(promise));
    }).ensure();
    pump();
  }
  std::pair<std::vector<ValidatorSessionId>, std::vector<ValidatorSessionId>> validators() {
    return query<std::pair<std::vector<ValidatorSessionId>, std::vector<ValidatorSessionId>>>([&](auto promise) {
             td::actor::send_closure(manager_, &TwostepManagerProbe::validators, std::move(promise));
           })
        .move_as_ok();
  }
  std::set<ValidatorSessionId> closed() {
    return query<std::set<ValidatorSessionId>>([&](auto promise) {
             td::actor::send_closure(manager_, &TwostepManagerProbe::closed, std::move(promise));
           })
        .move_as_ok();
  }
  std::vector<std::string> fail_stops() {
    return query<std::vector<std::string>>([&](auto promise) {
             td::actor::send_closure(manager_, &TwostepManagerProbe::fail_stops, std::move(promise));
           })
        .move_as_ok();
  }
  void seed_block(BlockIdExt id, td::Ref<MasterchainStateQ> state) {
    query<td::Unit>([&](auto promise) {
      td::actor::send_closure(manager_, &TwostepManagerProbe::seed_block, id, state, std::move(promise));
    }).ensure();
  }
  td::Status persist_and_install_checkpoint(BlockIdExt id) {
    auto r = query<td::Unit>([&](auto promise) {
      td::actor::send_closure(manager_, &TwostepManagerProbe::persist_and_install_checkpoint, id, std::move(promise));
    });
    pump();
    return r.is_ok() ? td::Status::OK() : r.move_as_error();
  }
  td::Result<bool> start_from_disk(Snapshot snapshot, BlockIdExt head, std::set<BlockIdExt> ancestors) {
    auto r = query<bool>([&](auto promise) {
      td::actor::send_closure(manager_, &TwostepManagerProbe::start_from_disk, std::move(snapshot), head,
                              std::move(ancestors), std::move(promise));
    });
    pump();
    return r;
  }
  void cleanup_tick() {
    query<td::Unit>([&](auto promise) {
      td::actor::send_closure(manager_, &TwostepManagerProbe::cleanup_tick, std::move(promise));
    }).ensure();
  }
  bool consensus_dir_exists(ValidatorSessionId session, CatchainSeqno cc) {
    return td::stat(consensus::consensus_db_root(td::Slice{root_}) +
                    consensus::consensus_db_dir_name(ShardIdFull{masterchainId}, cc, session, ""))
        .is_ok();
  }
  // A process restart of the manager on the same database root: the groups are
  // destroyed, the manager and its database actors stop, and a fresh manager
  // opens the same root with nothing in memory.
  void restart_manager() {
    scheduler_.run_in_context([&] { td::actor::send_closure(manager_, &TwostepManagerProbe::finish); });
    pump();
    release_buses();
    scheduler_.run_in_context([&] {
      std::lock_guard lock(observation_mutex);
      overlays.clear();
      observed_overlays_.clear();
    });
    scheduler_.run_in_context([&] { manager_.reset(); });
    // Let the old groups' and database actors finish closing their databases.
    for (int i = 0; i < 300; ++i)
      pump();
    scheduler_.run_in_context([&] {
      manager_ = td::actor::create_actor<TwostepManagerProbe>("relay manager", root_, keys_.get(), adnl_.get(),
                                                              sender_.get(), rldp_.get(), overlays_.get());
    });
    pump();
  }
  // Drops the fixture's own references to every bus, so a retired group's bus
  // can finish stopping (a bus stops only once its last reference is gone).
  void release_buses() {
    scheduler_.run_in_context([&] {
      std::lock_guard lock(observation_mutex);
      buses.clear();
      observed_buses_.clear();
    });
  }
  size_t validator_buses() {
    pump();
    return std::count_if(buses.begin(), buses.end(), [](const auto& bus) { return bus->is_validator(); });
  }
  template <class Predicate>
  bool eventually(Predicate ready) {
    for (unsigned round = 0; round < 1000; ++round) {
      pump();
      if (ready())
        return true;
    }
    return false;
  }
  void shard_client_advanced(Snapshot snapshot, BlockIdExt id, std::set<BlockIdExt> ancestors) {
    query<td::Unit>([&](auto promise) {
      td::actor::send_closure(manager_, &TwostepManagerProbe::shard_client_advanced, std::move(snapshot), id,
                              std::move(ancestors), std::move(promise));
    }).ensure();
  }
  // ---- composition with startup catch-up ----
  bool enter_catchup() {
    return query<bool>([&](auto promise) {
             td::actor::send_closure(manager_, &TwostepManagerProbe::enter_catchup, std::move(promise));
           })
        .move_as_ok();
  }
  void end_catchup(startup_catchup::ExitReason reason) {
    query<td::Unit>([&](auto promise) {
      td::actor::send_closure(manager_, &TwostepManagerProbe::end_catchup, reason, std::move(promise));
    }).ensure();
    pump();
  }
  // (checkpoint readiness, catch-up fence closed, validator groups permitted,
  // observer groups permitted)
  std::vector<bool> gates() {
    return query<std::vector<bool>>([&](auto promise) {
             td::actor::send_closure(manager_, &TwostepManagerProbe::gates, std::move(promise));
           })
        .move_as_ok();
  }
  bool build_directly() {
    auto built = query<bool>([&](auto promise) {
                   td::actor::send_closure(manager_, &TwostepManagerProbe::build_directly, std::move(promise));
                 }).move_as_ok();
    pump();
    return built;
  }
  void persist_checkpoint(BlockIdExt id) {
    query<td::Unit>([&](auto promise) {
      td::actor::send_closure(manager_, &TwostepManagerProbe::persist_checkpoint, id, std::move(promise));
    }).ensure();
  }
  std::set<adnl::AdnlNodeIdShort> committee() {
    return query<std::set<adnl::AdnlNodeIdShort>>([&](auto promise) {
             td::actor::send_closure(manager_, &TwostepManagerProbe::committee, std::move(promise));
           })
        .move_as_ok();
  }
  // The local ADNL id of the bus of each running validator session.
  std::set<adnl::AdnlNodeIdShort> local_ids_of(const std::vector<ValidatorSessionId>& sessions) {
    pump();
    std::set<adnl::AdnlNodeIdShort> result;
    for (const auto& bus : buses)
      if (bus->is_validator() && std::find(sessions.begin(), sessions.end(), bus->session_id) != sessions.end())
        result.insert(bus->local_adnl_id);
    return result;
  }
  void set_fail_persist(bool fail) {
    query<td::Unit>([&](auto promise) {
      td::actor::send_closure(manager_, &TwostepManagerProbe::set_fail_persist, fail, std::move(promise));
    }).ensure();
  }
  TwostepManagerProbe::WriteStatus write_status() {
    return query<TwostepManagerProbe::WriteStatus>([&](auto promise) {
             td::actor::send_closure(manager_, &TwostepManagerProbe::write_status, std::move(promise));
           })
        .move_as_ok();
  }
  // Sessions the real bridges activated (create_session reached them), in which
  // this node signs.
  size_t activated_validator_sessions() {
    pump();
    std::lock_guard lock(observation_mutex);
    return std::count_if(activated_.begin(), activated_.end(), [](const auto& row) { return row.second; });
  }
  size_t observer_buses() {
    pump();
    return std::count_if(buses.begin(), buses.end(), [](const auto& bus) { return !bus->is_validator(); });
  }
  void retry_checkpoint() {
    query<td::Unit>([&](auto promise) {
      td::actor::send_closure(manager_, &TwostepManagerProbe::retry_checkpoint, std::move(promise));
    }).ensure();
  }
  void wait_registered_started() {
    std::map<ValidatorSessionId, size_t> required;
    for (const auto& id : entries())
      ++required[id];
    for (const auto& id : entries(true))
      ++required[id];
    wait_for(
        [&] {
          std::map<ValidatorSessionId, size_t> observed;
          size_t expected_overlays = 0;
          for (const auto& bus : buses) {
            ++observed[bus->session_id];
            expected_overlays +=
                (bus->is_validator() || bus->config.observers_in_private_overlay()) + bus->config.enable_block_sync();
          }
          return overlays.size() == expected_overlays &&
                 std::all_of(required.begin(), required.end(),
                             [&](const auto& row) { return observed[row.first] >= row.second; });
        },
        "registered sessions or their overlays did not start");
  }
  std::vector<ValidatorSessionId> entries(bool future = false) {
    std::optional<std::vector<ValidatorSessionId>> result;
    std::atomic<bool> done = false;
    scheduler_.run_in_context([&] {
      auto promise = td::PromiseCreator::lambda([&](td::Result<std::vector<ValidatorSessionId>> value) {
        value.ensure();
        result = value.move_as_ok();
        done = true;
      });
      if (future)
        td::actor::send_closure(manager_, &TwostepManagerProbe::tentative, std::move(promise));
      else
        td::actor::send_closure(manager_, &TwostepManagerProbe::inspect, std::move(promise));
    });
    wait_for([&] { return done.load(); }, "manager inspection did not complete");
    return *result;
  }
  std::optional<std::set<adnl::AdnlNodeIdShort>> preflight() {
    std::optional<std::set<adnl::AdnlNodeIdShort>> answer;
    std::atomic<bool> done = false;
    scheduler_.run_in_context([&] {
      td::actor::send_closure(
          manager_, &TwostepManagerProbe::preflight,
          td::PromiseCreator::lambda([&](td::Result<std::optional<std::set<adnl::AdnlNodeIdShort>>> value) {
            answer = value.move_as_ok();
            done = true;
          }));
    });
    wait_for([&] { return done.load(); }, "manager preflight did not complete");
    return answer;
  }
  std::set<adnl::AdnlNodeIdShort> all_members() const {
    auto result = current.ids();
    for (const auto* epoch : {&old, &next}) {
      auto ids = epoch->ids();
      result.insert(ids.begin(), ids.end());
    }
    return result;
  }
  void fallback_factory(std::set<adnl::AdnlNodeIdShort> relays, bool observer) {
    const auto members = all_members();
    static std::atomic<unsigned> factory_sequence = 0;
    scheduler_.run_in_context([&] {
      std::vector<adnl::AdnlNodeIdShort> broad(members.begin(), members.end());
      auto options = ValidatorManagerOptions::create(BlockIdExt{}, BlockIdExt{});
      NewConsensusConfig config;
      config.protocol_version = 2;
      // Each direct call owns a different overlay, even on the same local id.
      const auto session = hash(PSTRING() << "factory-" << observer << "-" << ++factory_sequence);
      auto actor =
          observer
              ? IValidatorGroup::create_bridge_observer(
                    "fallback observer", ShardIdFull{masterchainId}, adnl::AdnlNodeIdShort{old.members[0].addr},
                    session, current.set(1, 2), config, keys_.get(), adnl_.get(), sender_.get(), overlays_.get(), broad,
                    relays, root_, manager_.get(), options, false)
              : IValidatorGroup::create_bridge(
                    "fallback active", ShardIdFull{masterchainId}, current.members[0].validator_id, current.custody[0],
                    session, current.set(1, 2), 0, config, keys_.get(), adnl_.get(), sender_.get(), overlays_.get(),
                    broad, relays, root_, manager_.get(), {}, true, false, options, false);
      ASSERT_TRUE(!actor.empty());
      direct_groups_.push_back(std::move(actor));
    });
    // Wait for the actual overlay: removing normalization for an empty set must
    // reach its invariant CHECK, rather than being masked by a test assertion.
    wait_for([&] { return buses.size() == 1 && overlays.size() == 1; }, "factory overlay did not start");
    ASSERT_TRUE(!buses.back()->all_current_validators);
    ASSERT_TRUE(overlays.back().relays.empty());
    ASSERT_TRUE(buses.back()->is_validator() != observer);
    if (!observer) {
      broadcast(members, 0);
    } else {
      ASSERT_TRUE(!buses.back()->local_id);
      ASSERT_TRUE(first_hops.empty());
    }
  }
  void broadcast(const std::set<adnl::AdnlNodeIdShort>& expected, std::optional<size_t> observer_count,
                 const Epoch* origin_epoch = nullptr) {
    if (!origin_epoch)
      origin_epoch = &current;
    auto it = std::find_if(buses.rbegin(), buses.rend(), [&](const auto& bus) {
      return bus->is_validator() && bus->local_adnl_id == adnl::AdnlNodeIdShort{origin_epoch->members[0].addr};
    });
    CHECK(it != buses.rend());
    const auto bus = *it;
    auto observation = std::find_if(overlays.rbegin(), overlays.rend(), [&](const auto& row) {
      return row.local == bus->local_adnl_id &&
             (row.name.find("blocksync") != std::string::npos) == bus->config.enable_block_sync();
    });
    CHECK(observation != overlays.rend());
    const auto case_overlay = observation->overlay;
    {
      std::lock_guard lock(observation_mutex);
      first_hops.clear();
      received.clear();
      observed_received_.clear();
    }
    LOG(INFO) << "trace case=" << ++broadcast_sequence_ << " overlay=" << case_overlay
              << " session=" << bus->session_id;
    const BlockIdExt block{masterchainId, shardIdAll, 1, hash(PSTRING() << "candidate-root-" << broadcast_sequence_),
                           hash("candidate-file")};
    const CandidateId parent{0, hash("parent")};
    auto id = CandidateHashData::create_empty(block, parent).build_id_with(0);
    auto sign_data = create_serialize_tl_object<tos_api::consensus_dataToSign>(bus->session_id,
                                                                               serialize_tl_object(id.to_tl(), true));
    auto signature = origin_epoch->custody[0]->sign_consensus(sign_data.as_slice().str());
    CHECK(signature);
    auto candidate =
        td::make_ref<Candidate>(id, parent, bus->local_id->idx, block, td::BufferSlice(signature->signature));
    scheduler_.run_in_context([&] { bus.publish<CandidateGenerated>(candidate, std::nullopt); });
    pump();
    const auto origin = bus->local_adnl_id;
    for (unsigned step = 0; step < 300; ++step) {
      auto events = network_->pop_due_events(network_->now_s() + 1);
      scheduler_.run_in_context([&] {
        for (auto& event : events) {
          if (event.kind == SimEventKind::Message) {
            td::Slice body = event.data.as_slice();
            auto prefix = fetch_tl_prefix<tos_api::overlay_message>(body, true);
            if (prefix.is_ok() && prefix.ok()->overlay_ == case_overlay.bits256_value()) {
              auto frame = fetch_tl_object<tos_api::overlay_Broadcast>(body, true);
              if (frame.is_ok() && event.src == origin &&
                  (frame.ok()->get_id() == tos_api::overlay_broadcastTwostepFec::ID ||
                   frame.ok()->get_id() == tos_api::overlay_broadcastTwostepSimple::ID))
                first_hops.insert(event.dst);
            }
            td::actor::send_closure(overlays_, &overlay::OverlayManager::receive_message, event.src, event.dst,
                                    std::move(event.data));
          } else if (event.kind == SimEventKind::Query) {
            td::actor::send_closure(overlays_, &overlay::OverlayManager::receive_query, event.src, event.dst,
                                    std::move(event.data), std::move(event.promise));
          } else
            event.promise.set_value(std::move(event.data));
        }
      });
      pump();
    }
    auto remote = expected;
    remote.erase(origin);
    LOG(INFO) << "trace first hops actual=" << first_hops.size() << " expected=" << remote.size()
              << " overlay=" << case_overlay;
    for (const auto& destination : first_hops)
      LOG(INFO) << "trace first-hop destination=" << destination << " overlay=" << case_overlay;
    ASSERT_TRUE(first_hops == remote);
    std::set<adnl::AdnlNodeIdShort> observers;
    for (const auto& row : received) {
      if (row.overlay != case_overlay)
        continue;
      LOG(INFO) << "trace delivery local=" << row.local << " session=" << row.session << " overlay=" << row.overlay
                << " candidate=" << row.id;
      ASSERT_TRUE(row.id == id);
      ASSERT_TRUE(row.source == origin.pubkey_hash());
      for (const auto& b : buses)
        if (b->local_adnl_id == row.local && b->session_id == row.session && !b->is_validator())
          observers.insert(row.local);
    }
    if (observer_count)
      ASSERT_EQ(observers.size(), *observer_count);
    LOG(INFO) << "candidate first hops=" << first_hops.size() << " observers=" << observers.size();
  }
  void pump() {
    for (unsigned i = 0; i < 10; ++i) {
      scheduler_.run(.001);
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    std::lock_guard lock(observation_mutex);
    buses = observed_buses_;
    overlays = observed_overlays_;
    received = observed_received_;
  }

 private:
  template <class Predicate>
  void wait_for(Predicate ready, const char* failure) {
    // RootDb uses worker threads; retain the bounded worker-progress pump rather
    // than letting a lost promise hang the test process indefinitely.
    for (unsigned round = 0; round < 1000; ++round) {
      pump();
      if (ready())
        return;
    }
    LOG_CHECK(ready()) << failure;
  }
  unsigned broadcast_sequence_ = 0;
  std::vector<td::actor::ActorOwn<IValidatorGroup>> direct_groups_;
  std::vector<BusHandle> observed_buses_;
  std::vector<std::pair<ValidatorSessionId, bool>> activated_;
  std::vector<Observation> observed_overlays_;
  std::vector<ReceivedCandidate> observed_received_;
  std::string root_;
  td::actor::Scheduler scheduler_;
  std::shared_ptr<SimNetwork> network_;
  td::actor::ActorOwn<keyring::Keyring> keys_;
  td::actor::ActorOwn<adnl::TestLoopbackNetworkManager> net_;
  td::actor::ActorOwn<adnl::Adnl> adnl_;
  td::actor::ActorOwn<rldp2::Rldp> rldp_;
  td::actor::ActorOwn<FixtureQuicSender> sender_;
  td::actor::ActorOwn<ObservedOverlays> overlays_;
  td::actor::ActorOwn<TwostepManagerProbe> manager_;
};
}  // namespace

TEST(TwostepWiring, ManagerActiveObserverAndOptions) {
  Fixture f;
  f.hold(f.current, 0);
  f.hold(f.old, 0);
  f.advance(f.initial());
  ASSERT_EQ(f.entries().size(), 2u);
  ASSERT_EQ(f.buses.size(), 2u);
  ASSERT_EQ(f.overlays.size(), 2u);
  for (const auto& bus : f.buses) {
    auto row = std::find_if(f.overlays.begin(), f.overlays.end(),
                            [&](const auto& overlay) { return overlay.local == bus->local_adnl_id; });
    CHECK(row != f.overlays.end());
    LOG(INFO) << "wiring local=" << bus->local_adnl_id << " active=" << bus->is_validator()
              << " snapshot_present=" << bus->all_current_validators.has_value()
              << " captured_relay_count=" << row->relays.size();
    ASSERT_TRUE(bus->all_current_validators == f.current.ids());
    ASSERT_EQ(bus->all_validators.size(), 11u);
  }
  for (const auto& row : f.overlays) {
    ASSERT_TRUE(row.relays == f.current.ids());
    ASSERT_EQ(row.members.size(), 11u);
    ASSERT_EQ(row.authorized.size(), 2u);
  }
  ASSERT_TRUE(f.buses[0]->is_validator() != f.buses[1]->is_validator());
}
namespace {
void check_manager_fallback(int condition) {
  Fixture f;
  ASSERT_TRUE(!f.preflight());
  f.hold(f.current, 0);
  f.hold(f.old, 0);
  f.hold(f.next, 0);
  auto snapshot = f.initial();
  if (condition == 0)
    snapshot.new_ids = false;
  else if (condition == 1)
    snapshot.current = {};
  else
    snapshot.current = td::make_ref<block::ValidatorSet>(1, ShardIdFull{masterchainId}, std::vector<ValidatorDescr>{});
  f.advance(snapshot);
  ASSERT_EQ(f.entries().size(), 3u);
  ASSERT_EQ(f.entries(true).size(), 1u);
  ASSERT_TRUE(!f.preflight());
  for (const auto& bus : f.buses)
    ASSERT_TRUE(!bus->all_current_validators);
  for (const auto& row : f.overlays)
    ASSERT_TRUE(row.relays.empty());
  auto active = std::find_if(f.overlays.begin(), f.overlays.end(), [&](const auto& row) {
    return row.local == adnl::AdnlNodeIdShort{f.current.members[0].addr};
  });
  CHECK(active != f.overlays.end());
  f.broadcast({active->members.begin(), active->members.end()}, std::nullopt);
  const auto begin = f.buses.size();
  f.advance(f.initial(), 2, true);
  ASSERT_EQ(f.entries().size(), 3u);
  ASSERT_TRUE(f.preflight() == f.current.ids());
  ASSERT_TRUE(f.buses.size() > begin);
  for (size_t i = begin; i < f.buses.size(); ++i)
    ASSERT_TRUE(f.buses[i]->all_current_validators == f.current.ids());
  f.broadcast(f.current.ids(), std::nullopt);
}
}  // namespace
TEST(TwostepWiring, FalsePrerequisiteFallbackAndRecovery) {
  check_manager_fallback(0);
}
TEST(TwostepWiring, MissingCurrentFallbackAndRecovery) {
  check_manager_fallback(1);
}
TEST(TwostepWiring, EmptyCurrentFallbackAndRecovery) {
  check_manager_fallback(2);
}
TEST(TwostepWiring, ObserverCeilingFailureIsNotStarted) {
  Fixture f;
  f.hold(f.old, 0);
  Epoch oversized{4, 22};
  auto snapshot = f.initial();
  snapshot.committee = oversized.set(1);
  f.advance(snapshot);
  ASSERT_TRUE(f.entries().empty());
  ASSERT_TRUE(f.entries(true).empty());
  ASSERT_TRUE(f.buses.empty());
  ASSERT_TRUE(f.overlays.empty());
  f.advance(f.initial(), 2, true);
  ASSERT_EQ(f.entries().size(), 1u);
}
TEST(TwostepWiring, TotalSetSwitchRecreatesActiveAndObservers) {
  Fixture f;
  f.hold(f.current, 0);
  f.hold(f.old, 0);
  f.hold(f.next, 0);
  f.hold(f.next, 1);
  auto outgoing = f.initial();
  // The prebuilt and promoted committees must be identical. Otherwise a member
  // change alone makes their IDs differ and masks broken key-block binding.
  outgoing.future = f.next.set(2, 1);
  f.advance(outgoing);
  const auto tentative = f.entries(true);
  ASSERT_EQ(tentative.size(), 1u);
  auto prepared = std::find_if(f.buses.begin(), f.buses.end(),
                               [&](const auto& bus) { return bus->is_validator() && bus->session_id == tentative[0]; });
  ASSERT_TRUE(prepared != f.buses.end());
  ASSERT_TRUE((*prepared)->all_current_validators == f.current.ids());
  auto incoming = f.initial();
  incoming.previous = f.current.set(1);
  incoming.current = f.next.set(2);
  incoming.next = {};
  incoming.committee = outgoing.future;
  incoming.future = {};
  auto identity = [&](BlockSeqno key, bool new_ids) {
    auto snapshot = outgoing;
    snapshot.new_ids = new_ids;
    auto options = block::validator_session_options_hash(StateConfig(snapshot).get_consensus_config());
    return block::derive_validator_session_identity(3, options, hash("protocol-2"), ShardIdFull{masterchainId},
                                                    incoming.committee->get_catchain_seqno(),
                                                    incoming.committee->export_vector(), 0, key, new_ids)
        .session_id;
  };
  ASSERT_TRUE(tentative[0] == identity(0, true));
  ASSERT_TRUE(identity(0, true) != identity(2, true));
  ASSERT_TRUE(identity(0, false) == identity(2, false));
  auto begin = f.buses.size();
  f.advance(incoming, 2, true);
  auto active = f.entries();
  ASSERT_TRUE(!active.empty());
  for (const auto& id : active) {
    ASSERT_TRUE(id != tentative[0]);
    ASSERT_TRUE(id == identity(2, true));
  }
  ASSERT_TRUE(f.buses.size() > begin);
  for (size_t i = begin; i < f.buses.size(); ++i)
    ASSERT_TRUE(f.buses[i]->all_current_validators == f.next.ids());
  LOG(INFO) << "rotation old tentative=" << tentative[0] << " new active=" << active[0];
  f.broadcast(f.next.ids(), 2, &f.next);
}
TEST(TwostepWiring, SameEpochTentativeCanBeReused) {
  Fixture f;
  f.hold(f.current, 0);
  f.hold(f.current, 2);  // a current-total-set observer outside the committee
  auto before = f.initial();
  before.next = {};
  before.future = f.current.set(2, 2);
  // Both committees come from the same current total set, with no election or
  // key-block change. Do not promote the disjoint next epoch's committee here.
  for (const auto& member : before.future->export_vector())
    ASSERT_TRUE(before.current->is_validator(member.validator_id));
  f.advance(before);
  auto tentative = f.entries(true);
  ASSERT_EQ(tentative.size(), 1u);
  auto count = f.buses.size();
  auto within = before;
  within.committee = before.future;
  within.future = {};
  f.advance(within, 2, false);
  auto active = f.entries();
  ASSERT_EQ(active.size(), 2u);  // promoted validator and recreated observer
  for (const auto& id : active)
    ASSERT_TRUE(id == tentative[0]);
  ASSERT_EQ(f.buses.size(), count + 1);  // only the observer needs a new Bus
  for (const auto& bus : f.buses)
    ASSERT_TRUE(bus->all_current_validators == f.current.ids());
}
TEST(TwostepWiring, ProtocolTwoCandidateThroughManagerObservers) {
  Fixture f;
  f.hold(f.current, 0);
  for (size_t i = 2; i < 7; ++i)
    f.hold(f.current, i);
  f.hold(f.old, 0);
  f.advance(f.initial());
  for (const auto& row : f.overlays)
    ASSERT_TRUE(row.name.find("blocksync") == std::string::npos);
  f.broadcast(f.current.ids(), 6);
}
TEST(TwostepWiring, ProtocolOneBlockSyncCandidateThroughManagerObservers) {
  Fixture f;
  f.hold(f.current, 0);
  for (size_t i = 2; i < 7; ++i)
    f.hold(f.current, i);
  f.hold(f.old, 0);
  f.advance(f.initial(1));
  size_t sync = 0;
  for (const auto& row : f.overlays)
    if (row.name.find("blocksync") != std::string::npos) {
      ++sync;
      ASSERT_TRUE(row.relays == f.current.ids());
    }
  ASSERT_EQ(sync, 7u);
  f.broadcast(f.current.ids(), 6);
}
TEST(TwostepWiring, EmptyFactorySnapshotFallsBack) {
  for (bool observer : {false, true}) {
    Fixture f;
    f.fallback_factory({}, observer);
  }
}
TEST(TwostepWiring, OutsideFactorySnapshotFallsBack) {
  for (bool observer : {false, true}) {
    Fixture f;
    auto outside = f.current.ids();
    auto fresh = adnl::AdnlNodeIdShort{hash("outside-all-epochs")};
    ASSERT_TRUE(!f.all_members().contains(fresh));
    outside.insert(fresh);
    f.fallback_factory(std::move(outside), observer);
  }
}
TEST(TwostepWiring, FlagFlipWhileRunningKeepsGroups) {
  Fixture f;
  f.hold(f.current, 0);
  f.hold(f.next, 0);
  f.hold(f.old, 0);
  f.advance(f.initial());
  const auto active_before = f.entries();
  const auto tentative_before = f.entries(true);
  ASSERT_EQ(active_before.size(), 3u);
  ASSERT_EQ(tentative_before.size(), 1u);
  const auto begin = f.buses.size();
  auto legacy = f.initial();
  legacy.new_ids = false;
  f.advance(legacy, 2, false);
  const auto active = f.entries();
  ASSERT_EQ(active.size(), 3u);
  for (const auto& id : active)
    ASSERT_TRUE(std::find(active_before.begin(), active_before.end(), id) == active_before.end());
  for (size_t i = begin; i < f.buses.size(); ++i)
    ASSERT_TRUE(!f.buses[i]->all_current_validators);
  const auto tentative = f.entries(true);
  ASSERT_TRUE(std::find(tentative.begin(), tentative.end(), tentative_before[0]) != tentative.end());
  // The older true-prerequisite prebuild remains safe under its different id.
  ASSERT_TRUE(tentative.size() > tentative_before.size());
  f.broadcast(f.all_members(), std::nullopt);
  const auto recovery = f.buses.size();
  f.advance(f.initial(), 3, true);
  ASSERT_EQ(f.entries().size(), 3u);
  ASSERT_TRUE(f.buses.size() > recovery);
  for (size_t i = recovery; i < f.buses.size(); ++i)
    ASSERT_TRUE(f.buses[i]->all_current_validators == f.current.ids());
  f.broadcast(f.current.ids(), std::nullopt);
}
TEST(TwostepWiring, LegacyTotalSetSwitchReusesBroadTentative) {
  Fixture f;
  f.hold(f.current, 0);
  f.hold(f.old, 0);
  f.hold(f.next, 0);
  f.hold(f.next, 1);
  auto outgoing = f.initial();
  outgoing.new_ids = false;
  outgoing.future = f.next.set(2, 1);
  f.advance(outgoing);
  const auto tentative = f.entries(true);
  ASSERT_EQ(tentative.size(), 1u);
  auto prepared = std::find_if(f.buses.begin(), f.buses.end(),
                               [&](const auto& bus) { return bus->is_validator() && bus->session_id == tentative[0]; });
  CHECK(prepared != f.buses.end());
  const auto prepared_bus = *prepared;
  // Defer the snapshot assertion until after the broadcast: ignoring the
  // prerequisite must be caught as outgoing-only first hops after promotion.
  auto incoming = outgoing;
  incoming.previous = outgoing.current;
  incoming.current = outgoing.next;
  incoming.next = {};
  incoming.committee = outgoing.future;
  incoming.future = {};
  auto identity = [&](BlockSeqno key) {
    return block::derive_validator_session_identity(
               3, block::validator_session_options_hash(StateConfig(outgoing).get_consensus_config()),
               hash("protocol-2"), ShardIdFull{masterchainId}, incoming.committee->get_catchain_seqno(),
               incoming.committee->export_vector(), 0, key, false)
        .session_id;
  };
  ASSERT_TRUE(tentative[0] == identity(0));
  ASSERT_TRUE(identity(0) == identity(2));
  const auto count = f.buses.size();
  f.advance(incoming, 2, true);
  ASSERT_EQ(f.entries().size(), 3u);
  for (const auto& id : f.entries())
    ASSERT_TRUE(id == tentative[0]);
  ASSERT_EQ(f.buses.size(), count + 2);  // reused active, two fresh observers
  f.broadcast(f.all_members(), std::nullopt, &f.next);
  ASSERT_TRUE(!prepared_bus->all_current_validators);
  for (const auto& bus : f.buses)
    ASSERT_TRUE(!bus->all_current_validators);
  LOG(INFO) << "legacy rotation reused tentative=" << tentative[0] << " with broad first hops";
}

// ---- consensus cleanup checkpoint: the production group gates ----------------
//
// Validator groups (current and tentative) are selected, built and activated
// only once the applied masterchain head is the consensus cleanup checkpoint or
// a verified descendant. Observer groups carry no votes and are not gated, so
// these tests look at validator groups and validator buses only.

// Startup replay from an older init block: nothing is built or activated below
// the checkpoint, sync completion activates nothing, and reaching the checkpoint
// starts the groups without any rotation.
TEST(TwostepWiring, CheckpointGatesValidatorGroupsUntilTheHeadReachesIt) {
  Fixture f;
  f.hold(f.current, 0);
  f.hold(f.old, 0);
  f.hold(f.next, 0);
  f.install_checkpoint(Fixture::main_block(5));
  for (BlockSeqno h : {3u, 4u}) {
    ASSERT_TRUE(f.apply_head(f.initial(), Fixture::main_block(h), Fixture::main_ancestors(h)).is_ok());
    auto [active, tentative] = f.validators();
    ASSERT_TRUE(active.empty());
    ASSERT_TRUE(tentative.empty());
    ASSERT_EQ(f.validator_buses(), 0u);
    ASSERT_TRUE(!std::get<1>(f.checkpoint()));
  }
  f.complete_sync();
  ASSERT_EQ(f.validator_buses(), 0u);
  ASSERT_TRUE(f.apply_head(f.initial(), Fixture::main_block(5), Fixture::main_ancestors(5)).is_ok());
  auto [active, tentative] = f.validators();
  ASSERT_TRUE(!active.empty());
  ASSERT_TRUE(!tentative.empty());
  ASSERT_TRUE(f.validator_buses() > 0);
  ASSERT_TRUE(std::get<1>(f.checkpoint()));
}

// A head that excludes the checkpoint -- at its height or above it -- is refused
// before it is installed; the head and the running groups are unchanged.
TEST(TwostepWiring, CheckpointRefusesAConflictingHeadBeforeInstallation) {
  Fixture f;
  f.hold(f.current, 0);
  f.hold(f.old, 0);
  f.install_checkpoint(Fixture::main_block(5));
  ASSERT_TRUE(f.apply_head(f.initial(), Fixture::main_block(5), Fixture::main_ancestors(5)).is_ok());
  auto before = f.validators();
  ASSERT_TRUE(!before.first.empty());
  ASSERT_TRUE(f.apply_head(f.initial(), Fixture::fork_block(5), Fixture::fork_ancestors(5, 4)).is_error());
  ASSERT_TRUE(f.apply_head(f.initial(), Fixture::fork_block(6), Fixture::fork_ancestors(6, 3)).is_error());
  ASSERT_TRUE(std::get<2>(f.checkpoint()) == Fixture::main_block(5));
  ASSERT_TRUE(std::get<1>(f.checkpoint()));
  ASSERT_TRUE(f.validators() == before);
  ASSERT_TRUE(f.closed().empty());
  // A descendant is admitted.
  ASSERT_TRUE(f.apply_head(f.initial(), Fixture::main_block(6), Fixture::main_ancestors(6)).is_ok());
  ASSERT_TRUE(std::get<1>(f.checkpoint()));
}

// A conflict found only after the head was installed (here: a checkpoint is
// installed that the running head does not descend from) calls the fail-stop
// hook at once, inside the installation; production exits there (the DB-level
// test checks the real exit). Nothing waits for retirement first.
TEST(TwostepWiring, CheckpointConflictFoundAfterInstallationFailStops) {
  Fixture f;
  f.hold(f.current, 0);
  f.hold(f.old, 0);
  f.hold(f.next, 0);
  ASSERT_TRUE(f.apply_head(f.initial(), Fixture::main_block(3), Fixture::main_ancestors(3)).is_ok());
  auto before = f.validators();
  ASSERT_TRUE(!before.first.empty());
  ASSERT_TRUE(f.fail_stops().empty());
  f.install_checkpoint(Fixture::fork_block(2), /*at_runtime=*/true);
  auto stops = f.fail_stops();
  ASSERT_EQ(stops.size(), 1u);
  ASSERT_TRUE(stops[0].find("excludes the consensus cleanup checkpoint") != std::string::npos);
  ASSERT_TRUE(!std::get<1>(f.checkpoint()));
}

// The restart property through the production loader and the production init
// handoff. Phase A: a validator session S runs, is retired by a set change, and
// its consensus database is deleted by the production cleanup pass anchored to a
// persisted checkpoint (a real masterchain state, B6). The manager restarts on
// the same root without the destroyed-session fence (as after it was pruned), the
// production loader reads the checkpoint from disk, and its result goes through
// started(). Replaying from an older head where S is again the current set never
// reopens S.
TEST(TwostepWiring, CheckpointRestartDoesNotReopenADeletedSession) {
  const char* genesis = std::getenv("TOS_TEST_GENESIS_BOC");
  ASSERT_TRUE(genesis != nullptr);
  auto r_chain = checkpoint_chain::build_chain(genesis);
  ASSERT_TRUE(r_chain.is_ok());
  auto chain = r_chain.move_as_ok();
  auto real = [&](BlockSeqno h) { return chain[PSTRING() << "B" << h].id; };
  auto real_ancestors = [&](BlockSeqno h) {
    std::set<BlockIdExt> result;
    for (BlockSeqno i = 1; i < h && i <= 6; ++i)
      result.insert(real(i));
    return result;
  };
  BlockIdExt h7{masterchainId, shardIdAll, 7, hash("restart-root-7"), hash("restart-file-7")};

  Fixture f;
  // Only the current epoch's member is held: no observer group, whose database
  // a restart in one process could not reopen while the old one is closing.
  f.hold(f.current, 0);
  auto with_s = f.initial();
  auto without_s = f.initial();
  without_s.committee = f.next.set(2, 2);
  without_s.future = {};
  // After the restart a different committee follows S's: the observer group the
  // held key gets then is a new session, not the one still closing in this process.
  auto without_s_after_restart = f.initial();
  without_s_after_restart.committee = f.old.set(1, 2);
  without_s_after_restart.future = {};
  // Phase A.
  for (BlockSeqno h : {3u, 4u})
    ASSERT_TRUE(f.apply_head(with_s, real(h), real_ancestors(h)).is_ok());
  auto running = f.validators().first;
  ASSERT_EQ(running.size(), 1u);
  const auto s = running[0];
  const CatchainSeqno s_cc = f.current.set(1, 2)->get_catchain_seqno();
  ASSERT_TRUE(f.consensus_dir_exists(s, s_cc));
  ASSERT_TRUE(f.apply_head(without_s, real(5), real_ancestors(5)).is_ok());
  ASSERT_TRUE(f.validators().first.empty());
  ASSERT_TRUE(f.apply_head(without_s, real(6), real_ancestors(6)).is_ok());
  for (BlockSeqno h = 1; h <= 6; ++h)
    f.seed_block(real(h), chain[PSTRING() << "B" << h].state);
  ASSERT_TRUE(f.persist_and_install_checkpoint(real(6)).is_ok());
  f.release_buses();
  ASSERT_TRUE(f.eventually([&] { return f.closed().contains(s); }));
  f.cleanup_tick();
  ASSERT_TRUE(f.eventually([&] { return !f.consensus_dir_exists(s, s_cc); }));

  // Restart.
  f.restart_manager();
  f.hold(f.current, 0);
  auto ready = f.start_from_disk(with_s, real(3), real_ancestors(3));
  ASSERT_TRUE(ready.is_ok());
  auto s_absent = [&] {
    auto [active, tentative] = f.validators();
    return std::find(active.begin(), active.end(), s) == active.end() &&
           std::find(tentative.begin(), tentative.end(), s) == tentative.end() && !f.consensus_dir_exists(s, s_cc);
  };
  ASSERT_TRUE(s_absent());
  ASSERT_TRUE(!ready.ok());
  ASSERT_TRUE(std::get<0>(f.checkpoint()) == std::optional<BlockIdExt>{real(6)});
  ASSERT_TRUE(f.apply_head(with_s, real(4), real_ancestors(4)).is_ok());
  ASSERT_TRUE(s_absent());
  for (BlockSeqno h : {5u, 6u}) {
    ASSERT_TRUE(f.apply_head(without_s_after_restart, real(h), real_ancestors(h)).is_ok());
    ASSERT_TRUE(s_absent());
  }
  auto ancestors7 = real_ancestors(7);
  ancestors7.insert(real(6));
  ASSERT_TRUE(f.apply_head(without_s_after_restart, h7, ancestors7).is_ok());
  ASSERT_TRUE(s_absent());
  ASSERT_TRUE(std::get<1>(f.checkpoint()));
}

// The checkpoint advances through the production shard-client entry point only
// once the applied head covers the candidate: an advancement offered during
// replay waits, and activates nothing; once written and installed, readiness is
// recomputed and the running groups stay.
TEST(TwostepWiring, CheckpointAdvanceDuringReplayWaitsForTheHead) {
  Fixture f;
  f.hold(f.current, 0);
  f.hold(f.old, 0);
  f.install_checkpoint(Fixture::main_block(5));
  ASSERT_TRUE(f.apply_head(f.initial(), Fixture::main_block(3), Fixture::main_ancestors(3)).is_ok());
  f.shard_client_advanced(f.initial(), Fixture::main_block(7), Fixture::main_ancestors(7));
  f.retry_checkpoint();
  ASSERT_TRUE(std::get<0>(f.checkpoint()) == std::optional<BlockIdExt>{Fixture::main_block(5)});
  f.complete_sync();
  ASSERT_EQ(f.validator_buses(), 0u);
  for (BlockSeqno h = 4; h <= 7; ++h)
    ASSERT_TRUE(f.apply_head(f.initial(), Fixture::main_block(h), Fixture::main_ancestors(h)).is_ok());
  ASSERT_TRUE(!f.validators().first.empty());
  f.retry_checkpoint();
  ASSERT_TRUE(
      f.eventually([&] { return std::get<0>(f.checkpoint()) == std::optional<BlockIdExt>{Fixture::main_block(7)}; }));
  ASSERT_TRUE(std::get<1>(f.checkpoint()));
  ASSERT_TRUE(!f.validators().first.empty());
  ASSERT_TRUE(f.closed().empty());
}

// ---- composition of the consensus cleanup checkpoint with startup catch-up ----
//
// Validator groups need both gates: the applied head has reached the checkpoint,
// and the startup catch-up fence is open. Observer groups need only the fence.
// The checkpoint here is the real masterchain block B5 (a state derived from the
// genesis state), persisted and then loaded by the production startup loader
// through the production init handoff; the head starts at B3, below it.
namespace {
struct CompositionChain {
  checkpoint_chain::Chain chain;
  BlockIdExt real(BlockSeqno h) const {
    return chain[PSTRING() << "B" << h].id;
  }
  std::set<BlockIdExt> ancestors(BlockSeqno h) const {
    std::set<BlockIdExt> result;
    for (BlockSeqno i = 1; i < h && i <= 6; ++i)
      result.insert(real(i));
    return result;
  }
};
CompositionChain composition_chain() {
  const char* genesis = std::getenv("TOS_TEST_GENESIS_BOC");
  CHECK(genesis != nullptr);
  auto r_chain = checkpoint_chain::build_chain(genesis);
  CHECK(r_chain.is_ok());
  return CompositionChain{r_chain.move_as_ok()};
}
// The masterchain set at catchain seqno `cc` (a catchain rotation per step).
Snapshot rotation(const Fixture& f, CatchainSeqno cc) {
  return {f.old.set(cc), f.current.set(cc), f.next.set(cc + 1), f.current.set(cc, 2), f.next.set(cc + 1), true, 2};
}
// Validator-set (membership) changes: the masterchain committee is taken from
// the `next` epoch, then from the `old` epoch, each with the other two epochs
// around it.
Snapshot next_in_office(const Fixture& f, CatchainSeqno cc) {
  return {f.current.set(cc), f.next.set(cc), f.old.set(cc + 1), f.next.set(cc, 2), f.old.set(cc + 1), true, 2};
}
Snapshot old_in_office(const Fixture& f, CatchainSeqno cc) {
  return {f.next.set(cc), f.old.set(cc), f.current.set(cc + 1), f.old.set(cc, 2), f.current.set(cc + 1), true, 2};
}
std::set<adnl::AdnlNodeIdShort> committee_of(const Epoch& epoch) {
  std::set<adnl::AdnlNodeIdShort> result;
  for (size_t i = 0; i < 2; ++i)
    result.emplace(epoch.members[i].addr);
  return result;
}
// Holds a current, a next (tentative) and an old (observer) key; persists the
// checkpoint B5; enters catch-up first when `fenced`; starts from disk at B3.
void start_composed(Fixture& f, const CompositionChain& c, bool fenced) {
  f.hold(f.current, 0);
  f.hold(f.next, 0);
  f.hold(f.old, 0);
  for (BlockSeqno h = 1; h <= 6; ++h)
    f.seed_block(c.real(h), c.chain[PSTRING() << "B" << h].state);
  f.persist_checkpoint(c.real(5));
  if (fenced)
    ASSERT_TRUE(f.enter_catchup());
  auto ready = f.start_from_disk(rotation(f, 1), c.real(3), c.ancestors(3));
  ASSERT_TRUE(ready.is_ok());
  ASSERT_TRUE(!ready.ok());
  ASSERT_TRUE(std::get<0>(f.checkpoint()) == std::optional<BlockIdExt>{c.real(5)});
}
// No validator group is selected, tentative, built (also by a direct factory
// call) or activated, and no validator bus exists.
void expect_no_validator_group(Fixture& f) {
  auto [active, tentative] = f.validators();
  ASSERT_TRUE(active.empty());
  ASSERT_TRUE(tentative.empty());
  ASSERT_EQ(f.validator_buses(), 0u);
  ASSERT_TRUE(!f.build_directly());
  ASSERT_EQ(f.validator_buses(), 0u);
  ASSERT_EQ(f.activated_validator_sessions(), 0u);
}
}  // namespace

// Release order 1: the head reaches the checkpoint while the fence is closed,
// then catch-up ends with no further block. Covers (behind, fenced),
// (reached, fenced) and (reached, open). Run with and without sync completion
// arriving while fenced: activation waits for both gates either way.
TEST(TwostepWiring, CompositionCheckpointReachedThenFenceOpens) {
  auto c = composition_chain();
  for (bool sync_while_fenced : {false, true}) {
    Fixture f;
    start_composed(f, c, true);
    expect_no_validator_group(f);
    ASSERT_EQ(f.observer_buses(), 0u);
    ASSERT_TRUE(f.gates() == (std::vector<bool>{false, true, false, false}));
    if (sync_while_fenced) {
      f.complete_sync();
      expect_no_validator_group(f);
    }
    for (BlockSeqno h : {4u, 5u})
      ASSERT_TRUE(f.apply_head(rotation(f, 1), c.real(h), c.ancestors(h)).is_ok());
    expect_no_validator_group(f);
    ASSERT_EQ(f.observer_buses(), 0u);
    ASSERT_TRUE(f.gates() == (std::vector<bool>{true, true, false, false}));
    if (sync_while_fenced) {
      f.complete_sync();
      expect_no_validator_group(f);
    }
    // The fence opens with no further block: end_startup_catchup builds the groups.
    f.end_catchup(startup_catchup::ExitReason::Fresh);
    auto [active, tentative] = f.validators();
    ASSERT_TRUE(!active.empty());
    ASSERT_TRUE(!tentative.empty());
    ASSERT_TRUE(f.eventually([&] { return f.validator_buses() > 0 && f.observer_buses() > 0; }));
    ASSERT_TRUE(f.gates() == (std::vector<bool>{true, false, true, true}));
    if (!sync_while_fenced) {
      ASSERT_EQ(f.activated_validator_sessions(), 0u);
      f.complete_sync();
    }
    ASSERT_TRUE(f.eventually([&] { return f.activated_validator_sessions() > 0; }));
  }
}

// Release order 2: catch-up ends first, by each terminal exit, while the head
// is still below the checkpoint. Covers (behind, fenced), (behind, open) and
// (reached, open). No exit releases the checkpoint gate: no validator group is
// built or activated, also after sync completion; observers do start. The
// checkpoint does not move with applied heads (T15). The head then reaches the
// checkpoint and the groups start.
TEST(TwostepWiring, CompositionFenceOpensFirstForEveryTerminalExit) {
  auto c = composition_chain();
  for (auto reason : {startup_catchup::ExitReason::NotStale, startup_catchup::ExitReason::NoVerifiedSuccessor,
                      startup_catchup::ExitReason::Fresh, startup_catchup::ExitReason::Abandoned}) {
    Fixture f;
    start_composed(f, c, true);
    expect_no_validator_group(f);
    ASSERT_TRUE(f.gates() == (std::vector<bool>{false, true, false, false}));
    f.end_catchup(reason);
    expect_no_validator_group(f);
    ASSERT_TRUE(f.eventually([&] { return f.observer_buses() > 0; }));
    ASSERT_TRUE(f.gates() == (std::vector<bool>{false, false, false, true}));
    f.complete_sync();
    expect_no_validator_group(f);
    ASSERT_TRUE(f.apply_head(rotation(f, 1), c.real(4), c.ancestors(4)).is_ok());
    expect_no_validator_group(f);
    ASSERT_TRUE(std::get<0>(f.checkpoint()) == std::optional<BlockIdExt>{c.real(5)});
    ASSERT_TRUE(f.apply_head(rotation(f, 1), c.real(5), c.ancestors(5)).is_ok());
    auto [active, tentative] = f.validators();
    ASSERT_TRUE(!active.empty());
    ASSERT_TRUE(!tentative.empty());
    ASSERT_TRUE(f.eventually([&] { return f.activated_validator_sessions() > 0; }));
    ASSERT_TRUE(f.gates() == (std::vector<bool>{true, false, true, true}));
    // T15: applying a head never moves the checkpoint; the shard client's
    // durable advance does.
    ASSERT_TRUE(f.apply_head(rotation(f, 1), c.real(6), c.ancestors(6)).is_ok());
    ASSERT_TRUE(std::get<0>(f.checkpoint()) == std::optional<BlockIdExt>{c.real(5)});
    f.shard_client_advanced(rotation(f, 1), c.real(6), c.ancestors(6));
    ASSERT_TRUE(f.eventually([&] { return std::get<0>(f.checkpoint()) == std::optional<BlockIdExt>{c.real(6)}; }));
  }
}

// Without catch-up entered, the fence is open from the start: (behind, open)
// with observers running and no validator group, then (reached, open).
TEST(TwostepWiring, CompositionCheckpointAloneWithTheFenceOpen) {
  auto c = composition_chain();
  Fixture f;
  start_composed(f, c, false);
  expect_no_validator_group(f);
  ASSERT_TRUE(f.eventually([&] { return f.observer_buses() > 0; }));
  ASSERT_TRUE(f.gates() == (std::vector<bool>{false, false, false, true}));
  f.complete_sync();
  expect_no_validator_group(f);
  ASSERT_TRUE(f.apply_head(rotation(f, 1), c.real(5), c.ancestors(5)).is_ok());
  ASSERT_TRUE(f.eventually([&] { return f.activated_validator_sessions() > 0; }));
  ASSERT_TRUE(f.gates() == (std::vector<bool>{true, false, true, true}));
}

// T16 (manager-side substitute; it does not run the archive importer): while
// fenced, heads cross two validator-set (membership) changes and catchain
// rotations: the committee of the `current` epoch, then of `next`, then of
// `old`. The checkpoint moves only through the shard client's durable advance;
// that write fails (uncertain). Readiness, the installed checkpoint and the
// cleanup anchor stay on B5 through the fence exit. The exit selects the final
// set's group (this node's `old` key), not an earlier set's. Once a rewrite is
// synced, the checkpoint and anchor move to B6.
TEST(TwostepWiring, CompositionRotationsAndAnUncertainWriteWhileFenced) {
  auto c = composition_chain();
  Fixture f;
  start_composed(f, c, true);
  ASSERT_TRUE(f.committee() == committee_of(f.current));
  ASSERT_TRUE(f.apply_head(next_in_office(f, 2), c.real(4), c.ancestors(4)).is_ok());
  ASSERT_TRUE(f.committee() == committee_of(f.next));
  expect_no_validator_group(f);
  ASSERT_TRUE(f.apply_head(old_in_office(f, 3), c.real(5), c.ancestors(5)).is_ok());
  ASSERT_TRUE(f.committee() == committee_of(f.old));
  expect_no_validator_group(f);
  ASSERT_TRUE(f.apply_head(old_in_office(f, 4), c.real(6), c.ancestors(6)).is_ok());
  ASSERT_TRUE(f.committee() == committee_of(f.old));
  expect_no_validator_group(f);
  ASSERT_TRUE(std::get<0>(f.checkpoint()) == std::optional<BlockIdExt>{c.real(5)});
  auto before = f.write_status();
  ASSERT_TRUE(!before.in_flight && !before.pending && !before.uncertain && before.persist_calls == 0);
  ASSERT_TRUE(before.anchor == std::optional<BlockIdExt>{c.real(5)});
  f.set_fail_persist(true);
  f.shard_client_advanced(old_in_office(f, 4), c.real(6), c.ancestors(6));
  ASSERT_TRUE(f.eventually([&] { return f.write_status().uncertain; }));
  auto failed = f.write_status();
  // Offered, issued and failed: one write attempt, now uncertain.
  ASSERT_TRUE(failed.persist_calls == 1 && failed.in_flight == std::optional<BlockIdExt>{c.real(6)});
  ASSERT_TRUE(failed.installed == std::optional<BlockIdExt>{c.real(5)});
  ASSERT_TRUE(failed.anchor == std::optional<BlockIdExt>{c.real(5)});
  expect_no_validator_group(f);
  f.end_catchup(startup_catchup::ExitReason::Fresh);
  auto [active, tentative] = f.validators();
  ASSERT_EQ(active.size(), 1u);
  ASSERT_TRUE(f.eventually([&] {
    return f.local_ids_of(active) == std::set<adnl::AdnlNodeIdShort>{adnl::AdnlNodeIdShort{f.old.members[0].addr}};
  }));
  auto after_exit = f.write_status();
  ASSERT_TRUE(after_exit.uncertain && after_exit.installed == std::optional<BlockIdExt>{c.real(5)} &&
              after_exit.anchor == std::optional<BlockIdExt>{c.real(5)});
  f.set_fail_persist(false);
  std::this_thread::sleep_for(std::chrono::milliseconds(1100));
  f.retry_checkpoint();
  ASSERT_TRUE(f.eventually([&] { return f.write_status().installed == std::optional<BlockIdExt>{c.real(6)}; }));
  ASSERT_TRUE(f.write_status().anchor == std::optional<BlockIdExt>{c.real(6)});
}
