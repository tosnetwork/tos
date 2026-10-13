/* Copyright (c) 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// A production consensus group stopped while its initial chain-state wait is
// still owed by the manager must be destroyed at once, not when the manager
// answers.
//
// The group is the production bridge, built by its production factory over a
// real keyring, loopback ADNL, RLDP and overlay manager. The validator manager
// is the production one with its network start-up suppressed; it withholds
// every state and block-data wait and counts them, and records the database
// notifications the group sends it. The mode is a required argument:
//
//   zerostate-destroy   the group starts on a zero state, so it waits for
//                       that state only, and is stopped with destroy();
//   nonzero-retirement  the group starts on a non-zero block, so it waits for
//                       both the state and the block data, and is retired
//                       with close_for_retirement(), which must close its
//                       database, report the closure with the retirement
//                       generation, and leave the directory in place.
//
// In both modes the test:
//   1. starts the group and waits until the manager holds its waits;
//   2. stops the group and waits for the bridge's destruction notification,
//      with those waits still withheld;
//   3. only then fails the withheld waits as a timeout, the answer that would
//      make a live resolution retry, and checks that no new wait is asked for
//      and no group bus is started afterwards.

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <vector>

#include "adnl/adnl-test-loopback-implementation.h"
#include "common/errorlog.h"
#include "keyring/keyring.h"
#include "overlay/overlays.h"
#include "quic/quic-sender.h"
#include "rldp2/rldp.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "td/utils/logging.h"
#include "td/utils/port/Stat.h"
#include "td/utils/port/path.h"
#include "validator/consensus/bus.h"
#include "validator/consensus/db-path.h"
#include "validator/fabric.h"
#include "validator/impl/applied-ext-message-cleanup.hpp"
#include "validator/impl/ext-message-pool.hpp"
#include "validator/impl/shard.hpp"
#include "validator/manager.hpp"
#include "validator/validator-group.hpp"
#include "validator/validator-options.hpp"

namespace tos::validator {
namespace {

[[noreturn]] void fail(const std::string& message) {
  std::fprintf(stderr, "BRIDGE_RETIREMENT_FAILURE: %s\n", message.c_str());
  std::fflush(stderr);
  std::_Exit(1);
}

void require(bool condition, const std::string& message) {
  if (!condition) {
    fail(message);
  }
}

td::Bits256 hash(td::Slice value) {
  return td::sha256_bits256(value);
}

struct Members {
  std::vector<PrivateKey> transport;
  std::vector<ValidatorDescr> descriptors;

  explicit Members(size_t count) {
    for (size_t i = 0; i < count; ++i) {
      auto label = PSTRING() << "bridge-retirement-" << i;
      transport.push_back(PrivateKey{privkeys::Ed25519::random()});
      auto store = pq::ValidatorPQKeyStore::from_seed(hash(label).as_slice().str());
      CHECK(store);
      const auto& key = store->consensus_key();
      td::Bits256 key_id;
      key_id.as_slice().copy_from(td::Slice(key.key_id.data(), key.key_id.size()));
      descriptors.emplace_back(ValidatorId{hash(PSTRING() << label << "-validator")},
                               static_cast<td::uint16>(key.algorithm_id), ConsensusKeyId{key_id}, key.public_key, 1,
                               transport.back().compute_public_key().compute_short_id().bits256_value());
    }
  }

  // Every member but the last, which is the observing node.
  td::Ref<block::ValidatorSet> set() const {
    std::vector<ValidatorDescr> rows(descriptors.begin(), descriptors.end() - 1);
    return td::make_ref<block::ValidatorSet>(1, ShardIdFull{masterchainId}, std::move(rows));
  }
  std::vector<adnl::AdnlNodeIdShort> validators() const {
    std::vector<adnl::AdnlNodeIdShort> result;
    for (size_t i = 0; i + 1 < descriptors.size(); ++i) {
      result.emplace_back(descriptors[i].addr);
    }
    return result;
  }
  adnl::AdnlNodeIdShort observer() const {
    return adnl::AdnlNodeIdShort{descriptors.back().addr};
  }
};

struct Closure {
  ValidatorSessionId session_id;
  td::uint64 generation;
  std::string dir_name;
};

struct Observations {
  std::atomic<size_t> state_waits{0};
  std::atomic<size_t> data_waits{0};
  std::atomic<size_t> buses{0};
  std::atomic<bool> destroyed{false};
  std::atomic<size_t> cleanups_done{0};
  std::mutex mutex;
  std::vector<Closure> closures;

  size_t closure_count() {
    std::lock_guard lock(mutex);
    return closures.size();
  }
};

Observations observations;

}  // namespace

// The production manager with its network start-up suppressed. Every wait the
// group asks for is withheld until the test releases it.
class WithholdingManager : public ValidatorManagerImpl {
 public:
  WithholdingManager(std::string root, td::actor::ActorId<keyring::Keyring> keys, td::actor::ActorId<adnl::Adnl> adnl,
                     td::actor::ActorId<rldp2::Rldp> rldp, td::actor::ActorId<overlay::Overlays> overlays)
      : ValidatorManagerImpl(ValidatorManagerOptions::create(BlockIdExt{}, BlockIdExt{}), root, keys, adnl, rldp,
                             td::actor::ActorId<quic::QuicSender>{}, overlays) {
  }
  // The group only asks for waits and reports its database closed, so none of
  // the manager's own start-up is needed.
  void start_up() override {
  }
  void wait_block_state_short(BlockIdExt, td::uint32, td::Timestamp, bool,
                              td::Promise<td::Ref<ShardState>> promise) override {
    observations.state_waits++;
    held_state_.push_back(std::move(promise));
  }
  void wait_block_data_short(BlockIdExt, td::uint32, td::Timestamp, td::Promise<td::Ref<BlockData>> promise) override {
    observations.data_waits++;
    held_data_.push_back(std::move(promise));
  }
  void consensus_db_cleanup_done(std::string) override {
    observations.cleanups_done++;
  }
  void consensus_db_closed(ValidatorSessionId session_id, td::uint64 generation, std::string dir_name) override {
    std::lock_guard lock(observations.mutex);
    observations.closures.push_back(Closure{session_id, generation, std::move(dir_name)});
  }
  // Answers every withheld wait the way a lapsed wait ends.
  void release_as_timeout() {
    for (auto& promise : held_state_) {
      promise.set_error(td::Status::Error(ErrorCode::timeout, "withheld wait lapsed"));
    }
    held_state_.clear();
    for (auto& promise : held_data_) {
      promise.set_error(td::Status::Error(ErrorCode::timeout, "withheld wait lapsed"));
    }
    held_data_.clear();
  }

 private:
  std::vector<td::Promise<td::Ref<ShardState>>> held_state_;
  std::vector<td::Promise<td::Ref<BlockData>>> held_data_;
};

}  // namespace tos::validator

namespace {

using namespace tos;
using namespace tos::validator;

class Fixture {
 public:
  Fixture() : root_(td::mkdtemp("/tmp", "bridge-retirement").move_as_ok()), scheduler_({1}) {
    consensus::observe_bridge_bus_for_test([](consensus::BusHandle) { observations.buses++; });
    consensus::observe_bridge_destroyed_for_test([](std::string) { observations.destroyed = true; });
    scheduler_.run_in_context([&] {
      errorlog::ErrorLog::create(root_);
      keys_ = keyring::Keyring::create(root_);
      net_ = td::actor::create_actor<adnl::TestLoopbackNetworkManager>("retirement network");
      adnl_ = adnl::Adnl::create(root_, keys_.get());
      td::actor::send_closure(adnl_, &adnl::Adnl::register_network_manager, net_.get());
      rldp_ = rldp2::Rldp::create(adnl_.get());
      overlays_ = overlay::Overlays::create(root_, keys_.get(), adnl_.get(), td::actor::ActorId<dht::Dht>{});
      manager_ = td::actor::create_actor<WithholdingManager>("retirement manager", root_, keys_.get(), adnl_.get(),
                                                             rldp_.get(), overlays_.get());
      auto address = adnl::TestLoopbackNetworkManager::generate_dummy_addr_list();
      for (const auto& key : members_.transport) {
        td::actor::send_closure(keys_, &keyring::Keyring::add_key, key, true, [](td::Result<>) {});
        td::actor::send_closure(adnl_, &adnl::Adnl::add_id, adnl::AdnlNodeIdFull{key.compute_public_key()}, address,
                                static_cast<td::uint8>(0));
      }
    });
    pump(0.2);
  }

  ~Fixture() {
    scheduler_.run_in_context([&] {
      group_.reset();
      manager_.reset();
      overlays_.reset();
      rldp_.reset();
      adnl_.reset();
      net_.reset();
      keys_.reset();
    });
    pump(0.5);
    consensus::observe_bridge_bus_for_test({});
    consensus::observe_bridge_destroyed_for_test({});
    scheduler_.stop();
    td::rmrf(root_).ignore();
  }

  // A zero-state group stopped with destroy().
  void run_zerostate_destroy() {
    const BlockIdExt zero_state{masterchainId, shardIdAll, 0, hash("retirement-root"), hash("retirement-file")};
    start_group(zero_state);
    wait_for([] { return observations.state_waits.load() == 1; }, "the group never asked for its initial state");
    require(observations.buses.load() == 1, "the group bus was not built");
    require(!observations.destroyed.load(), "the group was destroyed before it was retired");

    // Retire the group while the manager still owes the state.
    scheduler_.run_in_context([&] { td::actor::send_closure(group_, &IValidatorGroup::destroy); });
    wait_for([] { return observations.destroyed.load(); },
             "a retired group stayed alive while the manager withheld its initial state", 10.0);
    require(observations.state_waits.load() == 1, "the retired group asked for its state again");

    // The manager answers late, with the error a live resolution retries on.
    scheduler_.run_in_context([&] { td::actor::send_closure(manager_, &WithholdingManager::release_as_timeout); });
    pump(1.0);
    require(observations.state_waits.load() == 1, "a late answer to a retired group started another wait");
    require(observations.data_waits.load() == 0, "a retired group asked for block data");
    require(observations.buses.load() == 1, "a late answer to a retired group built another bus");
    std::printf("BRIDGE_RETIREMENT_ZEROSTATE_OK\n");
  }

  // A group on a non-zero block retired with close_for_retirement(): its
  // database is closed and reported with the retirement generation, and its
  // directory is left for the manager to delete.
  void run_nonzero_retirement() {
    const BlockIdExt tip{masterchainId, shardIdAll, 7, hash("retirement-tip-root"), hash("retirement-tip-file")};
    const td::uint64 generation = 42;
    // The observer factory names the directory with an observer suffix; the
    // closure reports the directory name alone, the database lives under the
    // consensus root.
    const std::string dir_name =
        consensus::consensus_db_dir_name(ShardIdFull{masterchainId}, members_.set()->get_catchain_seqno(), session_id(),
                                         PSTRING() << ".observer." << members_.observer().pubkey_hash());
    const std::string dir_path = consensus::consensus_db_root(root_) + dir_name;

    start_group(tip);
    // A non-zero tip needs the block data as well as the state; the zero-state
    // path asks for the state alone.
    wait_for([] { return observations.state_waits.load() == 1 && observations.data_waits.load() == 1; },
             "the group never asked for both its initial state and its block data");
    require(observations.buses.load() == 1, "the group bus was not built");
    require(!observations.destroyed.load(), "the group was destroyed before it was retired");
    require(td::stat(dir_path).is_ok(), "the group's consensus database directory was not created: " + dir_path);

    // Retire the group while the manager still owes both waits.
    scheduler_.run_in_context(
        [&] { td::actor::send_closure(group_, &IValidatorGroup::close_for_retirement, generation); });
    wait_for([] { return observations.destroyed.load() && observations.closure_count() >= 1; },
             "a retired group stayed alive, or never reported its database closed, while the manager withheld its "
             "initial state",
             10.0);
    require(observations.state_waits.load() == 1, "the retired group asked for its state again");
    require(observations.data_waits.load() == 1, "the retired group asked for its block data again");

    // The manager answers late, with the error a live resolution retries on.
    scheduler_.run_in_context([&] { td::actor::send_closure(manager_, &WithholdingManager::release_as_timeout); });
    pump(1.0);
    require(observations.state_waits.load() == 1, "a late answer to a retired group started another state wait");
    require(observations.data_waits.load() == 1, "a late answer to a retired group started another data wait");
    require(observations.buses.load() == 1, "a late answer to a retired group built another bus");
    {
      std::lock_guard lock(observations.mutex);
      require(observations.closures.size() == 1,
              PSTRING() << "the retired group reported " << observations.closures.size() << " closures, not one");
      const auto& closure = observations.closures.front();
      require(closure.session_id == session_id(), "the closure names another session");
      require(closure.generation == generation,
              PSTRING() << "the closure reports generation " << closure.generation << ", not " << generation);
      require(closure.dir_name == dir_name, "the closure names directory " + closure.dir_name + ", not " + dir_name);
    }
    require(observations.cleanups_done.load() == 0, "a retired group reported its database deleted");
    require(td::stat(dir_path).is_ok(), "a retired group deleted its consensus database directory");
    std::printf("BRIDGE_RETIREMENT_NONZERO_OK\n");
  }

 private:
  static ValidatorSessionId session_id() {
    return hash("retirement-session");
  }

  void start_group(BlockIdExt tip) {
    scheduler_.run_in_context([&] {
      NewConsensusConfig config;
      config.protocol_version = 2;
      group_ = IValidatorGroup::create_bridge_observer(
          "retirement observer", ShardIdFull{masterchainId}, members_.observer(), session_id(), members_.set(), config,
          keys_.get(), adnl_.get(), rldp_.get(), overlays_.get(), members_.validators(), std::nullopt, root_,
          manager_.get(), ValidatorManagerOptions::create(BlockIdExt{}, BlockIdExt{}), false);
      require(!group_.empty(), "the factory refused the group");
      td::actor::send_closure(group_, &IValidatorGroup::start, std::vector<BlockIdExt>{tip}, tip);
    });
  }

  template <class F>
  void wait_for(F&& done, const std::string& what, double limit = 20.0) {
    auto deadline = td::Timestamp::in(limit);
    while (!done()) {
      scheduler_.run(0.01);
      if (deadline.is_in_past()) {
        fail(PSTRING() << what << " (state waits " << observations.state_waits.load() << ", data waits "
                       << observations.data_waits.load() << ", buses " << observations.buses.load() << ", destroyed "
                       << observations.destroyed.load() << ")");
      }
    }
  }
  void pump(double seconds) {
    auto until = td::Timestamp::in(seconds);
    while (!until.is_in_past()) {
      scheduler_.run(0.01);
    }
  }

  std::string root_;
  td::actor::Scheduler scheduler_;
  Members members_{5};
  td::actor::ActorOwn<keyring::Keyring> keys_;
  td::actor::ActorOwn<adnl::TestLoopbackNetworkManager> net_;
  td::actor::ActorOwn<adnl::Adnl> adnl_;
  td::actor::ActorOwn<rldp2::Rldp> rldp_;
  td::actor::ActorOwn<overlay::Overlays> overlays_;
  td::actor::ActorOwn<WithholdingManager> manager_;
  td::actor::ActorOwn<IValidatorGroup> group_;
};

}  // namespace

int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(ERROR));
  // No default mode: a registration that loses its argument must fail, not
  // quietly run the other case.
  const std::string mode = argc == 2 ? argv[1] : "";
  if (mode != "zerostate-destroy" && mode != "nonzero-retirement") {
    std::fprintf(stderr, "usage: %s zerostate-destroy|nonzero-retirement\n", argc > 0 ? argv[0] : "test");
    return 2;
  }
  Fixture fixture;
  if (mode == "zerostate-destroy") {
    fixture.run_zerostate_destroy();
  } else {
    fixture.run_nonzero_retirement();
  }
  return 0;
}
