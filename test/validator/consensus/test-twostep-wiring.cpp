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
#include "test/plumtree/scheduler.h"
#include "test/plumtree/transport.h"
#include "test/plumtree/util.h"
#include "validator/consensus/bus.h"
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
  bool fail_observer_creation = false;
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
  td::Status validate_pq_launch_resource_config() const override {
    return td::Status::OK();
  }

 protected:
  Snapshot snapshot_;
};
class State : public MasterchainStateQ {
 public:
  State(BlockIdExt id, Snapshot snapshot)
      : MasterchainStateQ(id, vm::CellBuilder{}.finalize_novm()), snapshot_(std::move(snapshot)) {
  }
  td::Ref<block::ValidatorSet> get_total_validator_set(int offset) const override {
    if (offset == 0 && snapshot_.fail_observer_creation && ++current_calls_ == 3)
      return {};
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
  mutable int current_calls_ = 0;
};
std::recursive_mutex observation_mutex;
struct ReceivedCandidate {
  adnl::AdnlNodeIdShort local;
  consensus::CandidateId id;
  PublicKeyHash source;
  ValidatorSessionId session;
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
          received_.push_back({local_, candidate.ok()->id, src, bus->session_id});
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
    Observation row{local, members, options.twostep_intermediate_nodes_, {}, options.name_};
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
    pq_custody_.install(epoch.members[index].validator_id, epoch.custody[index]).ensure();
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
    for (const auto& entry : next_validator_groups_)
      result.push_back(entry.first);
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
  void preflight(td::Promise<std::string> promise) {
    auto result = get_current_validator_adnl_ids();
    promise.set_value(result.is_error() ? result.error().message().str() : "ok");
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
    scheduler_.run_in_context([&] { td::actor::send_closure(manager_, &TwostepManagerProbe::finish); });
    pump();
    scheduler_.run_in_context([&] {
      std::lock_guard lock(observation_mutex);
      buses.clear();
      observed_buses_.clear();
    });
    observe_bridge_bus_for_test({});
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
    return {old.set(1), current.set(1), next.set(2), current.set(1, 2), next.set(2), true, protocol, false};
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
    wait_for([&] {
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
    }, "registered sessions or their overlays did not start");
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
  std::string preflight() {
    std::optional<std::string> answer;
    std::atomic<bool> done = false;
    scheduler_.run_in_context([&] {
      td::actor::send_closure(manager_, &TwostepManagerProbe::preflight,
                              td::PromiseCreator::lambda([&](td::Result<std::string> value) {
                                answer = value.move_as_ok();
                                done = true;
                              }));
    });
    wait_for([&] { return done.load(); }, "manager preflight did not complete");
    return *answer;
  }
  void refuse_factories(std::set<adnl::AdnlNodeIdShort> relays) {
    scheduler_.run_in_context([&] {
      auto members = current.ids();
      std::vector<adnl::AdnlNodeIdShort> broad(members.begin(), members.end());
      auto options = ValidatorManagerOptions::create(BlockIdExt{}, BlockIdExt{});
      auto active = IValidatorGroup::create_bridge(
          "refused active", ShardIdFull{masterchainId}, current.members[0].validator_id, current.custody[0],
          ValidatorSessionId{}, current.set(1, 2), 0, NewConsensusConfig{}, keys_.get(), adnl_.get(), sender_.get(),
          overlays_.get(), broad, relays, root_, manager_.get(), {}, true, false, options, false);
      auto observer = IValidatorGroup::create_bridge_observer(
          "refused observer", ShardIdFull{masterchainId}, adnl::AdnlNodeIdShort{old.members[0].addr},
          ValidatorSessionId{}, current.set(1, 2), NewConsensusConfig{}, keys_.get(), adnl_.get(), sender_.get(),
          overlays_.get(), broad, relays, root_, manager_.get(), options, false);
      ASSERT_TRUE(active.empty());
      ASSERT_TRUE(observer.empty());
    });
    pump();
    ASSERT_TRUE(buses.empty());
    ASSERT_TRUE(overlays.empty());
  }
  void broadcast(const std::set<adnl::AdnlNodeIdShort>& expected, size_t observer_count,
                 const Epoch* origin_epoch = nullptr) {
    if (!origin_epoch)
      origin_epoch = &current;
    auto it = std::find_if(buses.rbegin(), buses.rend(), [&](const auto& bus) {
      return bus->is_validator() && bus->local_adnl_id == adnl::AdnlNodeIdShort{origin_epoch->members[0].addr};
    });
    CHECK(it != buses.rend());
    const auto bus = *it;
    const BlockIdExt block{masterchainId, shardIdAll, 1, hash("candidate-root"), hash("candidate-file")};
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
            if (fetch_tl_prefix<tos_api::overlay_message>(body, true).is_ok()) {
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
    ASSERT_TRUE(first_hops == remote);
    std::set<adnl::AdnlNodeIdShort> observers;
    for (const auto& row : received) {
      ASSERT_TRUE(row.id == id);
      ASSERT_TRUE(row.source == origin.pubkey_hash());
      for (const auto& b : buses)
        if (b->local_adnl_id == row.local && b->session_id == row.session && !b->is_validator())
          observers.insert(row.local);
    }
    ASSERT_EQ(observers.size(), observer_count);
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
  std::vector<BusHandle> observed_buses_;
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
TEST(TwostepWiring, EpochRefusalAndRecovery) {
  Fixture f;
  f.hold(f.current, 0);
  f.hold(f.old, 0);
  f.hold(f.next, 0);
  auto bad = f.initial();
  bad.new_ids = false;
  f.advance(bad);
  ASSERT_TRUE(f.entries().empty());
  ASSERT_TRUE(f.entries(true).empty());
  ASSERT_TRUE(f.buses.empty());
  auto missing = f.initial();
  missing.current = {};
  f.advance(missing, 2);
  ASSERT_TRUE(f.entries().empty());
  ASSERT_TRUE(f.buses.empty());
  f.advance(f.initial(), 3, true);
  ASSERT_EQ(f.entries().size(), 3u);
  ASSERT_TRUE(!f.buses.empty());
}
TEST(TwostepWiring, ObserverCreationFailureIsNotStarted) {
  Fixture f;
  f.hold(f.old, 0);
  auto bad = f.initial();
  bad.fail_observer_creation = true;
  f.advance(bad);
  ASSERT_TRUE(f.entries().empty());
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
  auto prepared = std::find_if(f.buses.begin(), f.buses.end(), [&](const auto& bus) {
    return bus->is_validator() && bus->session_id == tentative[0];
  });
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
    return block::derive_validator_session_identity(
               3, options, hash("protocol-2"), ShardIdFull{masterchainId},
               incoming.committee->get_catchain_seqno(), incoming.committee->export_vector(), 0, key, new_ids)
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
TEST(TwostepWiring, CheckedFactoriesRefuseEmptyAndOutsideMembership) {
  Fixture f;
  ASSERT_EQ(f.preflight(), "two-step relays: no masterchain state");
  f.refuse_factories({});
  auto outside = f.current.ids();
  outside.insert(adnl::AdnlNodeIdShort{f.old.members[0].addr});
  f.refuse_factories(outside);
  f.hold(f.current, 0);
  auto empty = f.initial();
  empty.current = td::make_ref<block::ValidatorSet>(1, ShardIdFull{masterchainId}, std::vector<ValidatorDescr>{});
  f.advance(empty);
  ASSERT_TRUE(f.entries().empty());
  ASSERT_TRUE(f.buses.empty());
  f.advance(f.initial(), 2, true);
  ASSERT_TRUE(!f.entries().empty());
}
TEST(TwostepWiring, LegacyIdsRefusedEvenForExistingAndTentativeGroups) {
  Fixture f;
  f.hold(f.current, 0);
  f.hold(f.next, 0);
  f.hold(f.old, 0);
  f.advance(f.initial());
  ASSERT_TRUE(!f.entries().empty());
  ASSERT_TRUE(!f.entries(true).empty());
  const auto options = block::validator_session_options_hash(StateConfig(f.initial()).get_consensus_config());
  auto legacy0 = block::derive_validator_session_identity(3, options, hash("protocol-2"), ShardIdFull{masterchainId}, 2,
                                                          f.next.members, 0, 0, false)
                     .session_id;
  auto legacy1 = block::derive_validator_session_identity(3, options, hash("protocol-2"), ShardIdFull{masterchainId}, 2,
                                                          f.next.members, 0, 2, false)
                     .session_id;
  ASSERT_TRUE(legacy0 == legacy1);
  const auto count = f.buses.size();
  auto bad = f.initial();
  bad.new_ids = false;
  f.advance(bad, 2, true);
  ASSERT_TRUE(f.entries().empty());
  ASSERT_TRUE(f.entries(true).empty());
  ASSERT_EQ(f.buses.size(), count);
  f.advance(f.initial(), 3, true);
  ASSERT_TRUE(!f.entries().empty());
}
