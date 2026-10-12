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

#include "block/validator-session-id.h"
#include "adnl/adnl.h"
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

// One masterchain state: the validator sets, the catchain seqno of the masterchain
// shard, and the consensus config. No shards besides the masterchain.
struct Snapshot {
  td::Ref<block::ValidatorSet> previous, current, next;
  CatchainSeqno cc = 1;
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
    return 3;
  }
  td::Result<td::int32> get_config_global_id() const override {
    return 3;
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

class State : public MasterchainStateQ {
 public:
  State(BlockIdExt id, Snapshot snapshot)
      : MasterchainStateQ(id, vm::CellBuilder{}.finalize_novm()), snapshot_(std::move(snapshot)) {
  }
  td::Ref<block::ValidatorSet> get_total_validator_set(int offset) const override {
    return offset < 0 ? snapshot_.previous : offset > 0 ? snapshot_.next : snapshot_.current;
  }
  td::Ref<block::ValidatorSet> get_validator_set(ShardIdFull) const override {
    return snapshot_.current;
  }
  td::Ref<block::ValidatorSet> get_next_validator_set(ShardIdFull) const override {
    return {};
  }
  CatchainSeqno get_shard_cc_seqno(ShardIdFull shard) const override {
    return shard.is_masterchain() ? snapshot_.cc : std::numeric_limits<CatchainSeqno>::max();
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
  FakeGroup(std::shared_ptr<Journal> journal, ValidatorSessionId session) : journal_(std::move(journal)), session_(session) {
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
                             td::actor::ActorId<rldp2::Rldp> rldp)
      : ValidatorManagerImpl(ValidatorManagerOptions::create(BlockIdExt{}, BlockIdExt{}), std::move(root), keys, adnl,
                             rldp, {}, {})
      , journal_(std::move(journal)) {
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

  void hold(std::shared_ptr<const pq::ValidatorPQKeyStore> store, ValidatorId id, td::uint32 expire_at) {
    pq_custody_.install(id, std::move(store), 0, expire_at).ensure();
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
                              .global_id = 3,
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
};

namespace {

class Fixture {
 public:
  Epoch old{1}, current{2}, next{3};
  std::shared_ptr<Journal> journal = std::make_shared<Journal>();

  Fixture() : root_(td::mkdtemp("/tmp", "startup-catchup-manager").move_as_ok()), scheduler_({1}) {
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
                                                                     adnl_.get(), rldp_.get());
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
  void set_tip(Snapshot s, BlockSeqno height, double age) {
    scheduler_.run_in_context(
        [&] { td::actor::send_closure(manager_, &StartupCatchupManagerProbe::set_tip, std::move(s), height, age); });
  }
  void advance(Snapshot s, BlockSeqno height, double age) {
    ask<td::Unit>([&](td::Promise<td::Unit> p) {
      td::actor::send_closure(manager_, &StartupCatchupManagerProbe::advance, std::move(s), height, age, std::move(p));
    });
  }
  bool decide() {
    return ask<bool>(
        [&](td::Promise<bool> p) { td::actor::send_closure(manager_, &StartupCatchupManagerProbe::decide, std::move(p)); });
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
    td::mkdir(consensus::consensus_db_root(root_) + consensus::consensus_db_dir_name(ShardIdFull{masterchainId}, cc, s, ""))
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
  f.hold(f.current, 0);
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

// T28. The mode is left early (local replay made the tip fresh) at catchain seqno 1;
// replay continues to seqno 2. The inventory runs at prestart completion, on the final
// state, and records the session that rotation made obsolete.
TEST(StartupCatchupManager, T28_InventoryRunsOnTheFinalState) {
  Fixture f;
  f.hold(f.current, 0);
  auto first = f.snapshot(f.current, 1);
  f.set_tip(first, 10, kStale);
  auto session = f.session_of(first);
  f.make_session_dir(session, 1);
  ASSERT_TRUE(f.decide());
  f.advance(first, 10, kStale);
  f.advance(f.snapshot(f.current, 2), 20, kFresh);  // local replay
  f.run_mode();                                     // ends NotStale
  ASSERT_TRUE(!f.query()[0]);
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
  auto session = f.session_of(first);
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
