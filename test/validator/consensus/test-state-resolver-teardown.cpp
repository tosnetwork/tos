/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
// Actor-level regression: a consensus group that stops while its state resolver has a
// finalization in flight and other callers waiting on it must still release everything.
//
// One validator node runs the production CandidateResolver, StateResolver and Db actors.
// The stand-ins are the validator manager, the private overlay, the database backend and
// the block accepter, whose FinalizeBlock handling is held open by the test so the first
// finalization attempt stays InFlight for as long as the scenario needs.
//
// Scenario:
//   1. A full candidate X on the genesis state is stored and a finalization certificate
//      for it is observed; finalize_blocks(X) runs until FinalizeBlock is held.
//   2. The same finalization is observed again: the second finalize_blocks(X) finds the
//      entry InFlight and registers a waiter.
//   3. ResolveState(X) is requested: resolve_state_inner asks finalization_of(X), which
//      also finds InFlight and registers a waiter.
//   4. StopRequested is published, the driver drops its bus handle, and the held
//      FinalizeBlock is failed with `cancelled` the way a stopped accepter fails it.
//
// Expected: ResolveState(X) completes with `cancelled`; no manager request is made after
// the stop; the bus destructs (its stop promise completes) within the deadline, which
// proves the resolver holds nothing. Before the teardown fix, the waiters woken during
// tear_down re-registered themselves on the list being walked: the bus never stopped.

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "auto/tl/tos_api.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "consensus/simplex/bus.h"
#include "consensus/simplex/certificate.h"
#include "consensus/simplex/votes.h"
#include "consensus/utils.h"
#include "crypto/pq/consensus-pq-signer.h"
#include "td/actor/BusRuntime.h"
#include "td/actor/coro_utils.h"
#include "vm/boc.h"

#include "block-auto.h"

using namespace tos;
using namespace tos::validator;
using namespace tos::validator::consensus;

namespace {

constexpr td::uint32 SLOTS_PER_LEADER_WINDOW = 4;
constexpr size_t VALIDATORS = 4;
constexpr double STEP_TIMEOUT = 10.0;
constexpr double SETTLE = 0.5;

const CatchainSeqno CC_SEQNO = 123;

td::Bits256 fill(unsigned char byte) {
  td::Bits256 value;
  std::memset(value.data(), byte, 32);
  return value;
}

td::Ref<vm::Cell> gen_shard_state(BlockSeqno seqno) {
  return vm::CellBuilder().store_long(0xabcdabcdU, 32).store_long(seqno, 32).finalize_novm();
}

const ShardIdFull SHARD{basechainId, shardIdAll};
const BlockIdExt MIN_MC_BLOCK_ID{masterchainId, shardIdAll, 0, fill(0xa1), fill(0xa2)};
const BlockIdExt FIRST_PARENT{basechainId, shardIdAll, 0, td::Bits256(gen_shard_state(0)->get_hash().bits()),
                              fill(0x89)};

Ref<vm::Cell> make_ext_blk_ref(BlockIdExt block_id, LogicalTime lt) {
  vm::CellBuilder cb;
  cb.store_long_bool(lt, 64);
  cb.store_long_bool(block_id.seqno(), 32);
  cb.store_bits_bool(block_id.root_hash);
  cb.store_bits_bool(block_id.file_hash);
  return cb.finalize_novm();
}

void emit(const std::string& line) {
  std::printf("%s\n", line.c_str());
  std::fflush(stdout);
}

[[noreturn]] void finish(int code, const std::string& line) {
  emit(line);
  std::fflush(stderr);
  std::_Exit(code);
}

std::string id_str(const CandidateId& id) {
  return PSTRING() << "{slot=" << id.slot << ", hash=" << id.hash.to_hex().substr(0, 16) << "}";
}

// ===== What the test observes =====

struct Observations {
  std::mutex mutex;
  size_t held_finalizations = 0;
  size_t released_finalizations = 0;
  size_t manager_requests = 0;
  size_t manager_requests_after_stop = 0;
};

Observations observations;
std::atomic<bool> stop_published{false};

size_t held_finalizations() {
  std::scoped_lock lock(observations.mutex);
  return observations.held_finalizations;
}

void note_manager_request(const char* what, const BlockIdExt& block_id) {
  std::scoped_lock lock(observations.mutex);
  ++observations.manager_requests;
  if (stop_published.load()) {
    ++observations.manager_requests_after_stop;
    emit(PSTRING() << "C10_MANAGER_REQUEST_AFTER_STOP " << what << " block=" << block_id.to_str());
  }
}

// Stands in for the private overlay: no candidate is ever fetched from a peer.
class OverlayStub : public td::actor::SpawnsWith<simplex::Bus>, public td::actor::ConnectsTo<simplex::Bus> {
 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();

  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const StopRequested>) {
    stop();
  }

  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const OutgoingProtocolMessage>) {
  }

  template <>
  td::actor::Task<ProtocolMessage> process(simplex::BusHandle, std::shared_ptr<OutgoingOverlayRequest>) {
    co_return ProtocolMessage{create_serialize_tl_object<tos_api::consensus_requestError>()};
  }
};

// Stands in for the block accepter. Every FinalizeBlock is held open until the actor stops,
// when the held requests are failed with `cancelled`, exactly what a stopped accepter's
// pending manager reply turns into.
class HoldingAccepter : public td::actor::SpawnsWith<simplex::Bus>, public td::actor::ConnectsTo<simplex::Bus> {
 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();

  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const StopRequested>) {
    stop();
  }

  template <>
  td::actor::Task<> process(simplex::BusHandle, std::shared_ptr<FinalizeBlock> event) {
    auto [task, promise] = td::actor::StartedTask<td::Unit>::make_bridge();
    held_.push_back(std::move(promise));
    {
      std::scoped_lock lock(observations.mutex);
      ++observations.held_finalizations;
    }
    emit(PSTRING() << "C10_FINALIZE_HELD " << id_str(event->candidate->id));
    co_return co_await std::move(task);
  }

  void tear_down() override {
    auto held = std::move(held_);
    held_.clear();
    for (auto& promise : held) {
      {
        std::scoped_lock lock(observations.mutex);
        ++observations.released_finalizations;
      }
      promise.set_error(td::Status::Error(ErrorCode::cancelled, "accepter stopped"));
    }
  }

 private:
  std::vector<td::actor::StartedTask<td::Unit>::ExternalPromise> held_;
};

class MemoryDb : public consensus::Db {
 public:
  std::optional<td::BufferSlice> get(td::Slice key) const override {
    std::scoped_lock lock(mutex_);
    auto it = map_.find(td::BufferSlice{key});
    if (it == map_.end()) {
      return std::nullopt;
    }
    return it->second.clone();
  }

  std::vector<std::pair<td::BufferSlice, td::BufferSlice>> get_by_prefix(td::uint32 prefix) const override {
    std::scoped_lock lock(mutex_);
    std::vector<std::pair<td::BufferSlice, td::BufferSlice>> result;
    td::BufferSlice begin{(const char*)&prefix, 4};
    td::uint32 next_prefix = prefix + 1;
    td::BufferSlice end{(const char*)&next_prefix, 4};
    for (auto it = map_.lower_bound(begin); it != map_.end() && it->first < end; ++it) {
      result.emplace_back(it->first.clone(), it->second.clone());
    }
    return result;
  }

  td::actor::Task<std::optional<td::BufferSlice>> get_latest(td::BufferSlice key) const override {
    co_return get(key.as_slice());
  }

  td::actor::Task<> set(td::BufferSlice key, td::BufferSlice value) override {
    std::scoped_lock lock(mutex_);
    map_[std::move(key)] = std::move(value);
    co_return td::Unit{};
  }

  td::actor::Task<> close() override {
    co_return td::Unit{};
  }

 private:
  mutable std::mutex mutex_;
  std::map<td::BufferSlice, td::BufferSlice> map_;
};

// The validator manager: holds the zerostate and counts every request, flagging the ones
// that arrive after the stop was published.
class ControlledManager : public ManagerFacade {
 public:
  td::actor::Task<GeneratedCandidate> collate_block(CollateParams, td::CancellationToken) override {
    co_return td::Status::Error("this node does not collate");
  }

  td::actor::Task<ValidateCandidateResult> validate_block_candidate(BlockCandidate, ValidateParams,
                                                                    td::Timestamp) override {
    co_return CandidateAccept{};
  }

  td::actor::Task<> accept_block(BlockIdExt id, td::Ref<BlockData>, size_t, td::Ref<block::BlockSignatureSet>,
                                 ValidatorSessionId, int, int, bool, bool) override {
    note_manager_request("accept_block", id);
    co_return td::Unit{};
  }

  td::actor::Task<td::Ref<vm::Cell>> wait_block_state_root(BlockIdExt block_id, td::Timestamp,
                                                           std::optional<CandidateId>) override {
    note_manager_request("wait_block_state_root", block_id);
    if (block_id == FIRST_PARENT) {
      co_return gen_shard_state(0);
    }
    co_return td::Status::Error(ErrorCode::notready, "only the zerostate is available");
  }

  td::actor::Task<td::Ref<BlockData>> wait_block_data(BlockIdExt block_id, td::Timestamp) override {
    note_manager_request("wait_block_data", block_id);
    co_return td::Status::Error(ErrorCode::notready, "no block data is available");
  }
};

BlockCandidate make_block(BlockSeqno seqno, const BlockIdExt& prev) {
  BlockSeqno prev_seqno = seqno - 1;
  double gen_utime = 1'700'000'000.0 + seqno;

  block::gen::BlockInfo::Record info;
  info.version = 0;
  info.not_master = !SHARD.is_masterchain();
  info.after_merge = info.before_split = info.after_split = false;
  info.want_split = info.want_merge = false;
  info.key_block = info.vert_seqno_incr = false;
  info.flags = 0;
  info.seq_no = seqno;
  info.vert_seq_no = 0;
  vm::CellBuilder cb;
  block::ShardId{SHARD}.serialize(cb);
  info.shard = cb.as_cellslice_ref();
  info.gen_utime = (UnixTime)gen_utime;
  info.start_lt = (LogicalTime)seqno * 1000;
  info.end_lt = (LogicalTime)seqno * 1000 + 1;
  info.gen_validator_list_hash_short = 0;
  info.gen_catchain_seqno = CC_SEQNO;
  info.min_ref_mc_seqno = MIN_MC_BLOCK_ID.seqno();
  info.prev_key_block_seqno = MIN_MC_BLOCK_ID.seqno();
  info.master_ref = make_ext_blk_ref(MIN_MC_BLOCK_ID, 0);
  info.prev_ref = make_ext_blk_ref(prev, (LogicalTime)prev_seqno * 1000 + 1);
  td::Ref<vm::Cell> block_info;
  CHECK(block::gen::pack_cell(block_info, info));

  td::Ref<vm::Cell> value_flow = vm::CellBuilder{}.finalize_novm();
  td::Ref<vm::Cell> merkle_update =
      vm::CellBuilder::create_merkle_update(gen_shard_state(prev_seqno), gen_shard_state(seqno));
  td::Ref<vm::Cell> block_extra = vm::CellBuilder{}.store_long(seqno, 32).finalize_novm();
  td::Ref<vm::Cell> block_root = vm::CellBuilder{}
                                     .store_long(0x11ef55aa, 32)
                                     .store_long(-111, 32)
                                     .store_ref(block_info)
                                     .store_ref(value_flow)
                                     .store_ref(merkle_update)
                                     .store_ref(block_extra)
                                     .finalize_novm();
  td::BufferSlice data = vm::std_boc_serialize(block_root, 31).move_as_ok();

  // consensus_extra_data#638eb292 flags:# gen_utime_ms:uint64 = ConsensusExtraData;
  auto extra = vm::CellBuilder{}
                   .store_long(0x638eb292, 32)
                   .store_long(0, 32)
                   .store_long((td::uint64)(gen_utime * 1000.0), 64)
                   .finalize_novm();
  td::BufferSlice collated_data = vm::std_boc_serialize_multi({extra}, 2).move_as_ok();

  return BlockCandidate(ValidatorId{fill(0x99)},
                        BlockIdExt(BlockId(SHARD, seqno), block_root->get_hash().bits(), td::sha256_bits256(data)),
                        td::sha256_bits256(collated_data), data.clone(), collated_data.clone());
}

class Driver : public td::actor::Actor {
 public:
  td::actor::Task<> run() {
    auto result = co_await run_inner().wrap();
    if (result.is_error()) {
      finish(1, "C10_HARNESS_FAILED: " + result.error().to_string());
    }
    co_return td::Unit{};
  }

 private:
  std::vector<std::shared_ptr<const tos::pq::ValidatorPQKeyStore>> signers_;
  td::actor::Runtime runtime_;
  td::actor::ActorOwn<ControlledManager> manager_;
  simplex::BusHandle bus_;
  std::shared_ptr<simplex::Bus> bus_ptr_;
  std::optional<td::actor::StartedTask<>> bus_stopped_;
  size_t target_ = 1;

  td::BufferSlice sign(size_t signer, td::Slice inner) const {
    auto envelope =
        create_serialize_tl_object<tos_api::consensus_dataToSign>(bus_ptr_->session_id, td::BufferSlice(inner));
    auto signature =
        signers_.at(signer)->sign_consensus(std::string_view(envelope.as_slice().data(), envelope.as_slice().size()));
    CHECK(signature.has_value());
    return td::BufferSlice(signature->signature);
  }

  // A certificate for `vote` signed by the three validators other than the node under test.
  template <typename Vote>
  td::Ref<simplex::Certificate<Vote>> make_cert(Vote vote) {
    auto inner = serialize_tl_object(vote.to_tl(), true);
    std::vector<simplex::tl::VoteSignatureRef> signatures;
    for (size_t i = 0; i < VALIDATORS; ++i) {
      if (i != target_) {
        signatures.push_back(
            create_tl_object<simplex::tl::voteSignature>(static_cast<td::int32>(i), sign(i, inner.as_slice())));
      }
    }
    auto set = create_tl_object<simplex::tl::voteSignatureSet>(std::move(signatures));
    auto cert = simplex::Certificate<Vote>::from_tl(std::move(*set), vote, *bus_ptr_);
    CHECK(cert.is_ok());
    return cert.move_as_ok();
  }

  CandidateRef make_candidate(BlockSeqno seqno, const BlockIdExt& prev, ParentId parent, td::uint32 slot) {
    auto block = make_block(seqno, prev);
    auto id = CandidateHashData::create_full(block, parent).build_id_with(slot);
    auto leader = bus_ptr_->collator_schedule->expected_collator_for(slot);
    auto signature = sign(leader.value(), serialize_tl_object(id.to_tl(), true).as_slice());
    return td::make_ref<Candidate>(id, parent, leader, std::move(block), std::move(signature));
  }

  template <typename F>
  td::actor::Task<bool> wait_until(F condition, double timeout = STEP_TIMEOUT) {
    auto deadline = td::Timestamp::in(timeout);
    while (!condition()) {
      if (deadline.is_in_past()) {
        co_return false;
      }
      co_await td::actor::coro_sleep(td::Timestamp::in(0.005));
    }
    co_return true;
  }

  td::actor::Task<> settle(double seconds = SETTLE) {
    co_await td::actor::coro_sleep(td::Timestamp::in(seconds));
    co_return td::Unit{};
  }

  void start_node() {
    std::vector<PeerValidator> validators;
    ValidatorWeight total_weight = 0;
    for (size_t i = 0; i < VALIDATORS; ++i) {
      // Deliberately public fixture seeds, never operational key material.
      auto store = tos::pq::ValidatorPQKeyStore::from_seed(std::string(32, static_cast<char>(0x60 + i)));
      CHECK(store.has_value());
      signers_.push_back(std::make_shared<const tos::pq::ValidatorPQKeyStore>(std::move(*store)));
      auto adnl = adnl::AdnlNodeIdShort{fill(static_cast<unsigned char>(0x90 + i))};
      validators.push_back(PeerValidator{.validator_id = ValidatorId{fill(static_cast<unsigned char>(0x70 + i))},
                                         .idx = PeerValidatorId{i},
                                         .consensus_key = signers_.back()->consensus_key(),
                                         .transport_key_id = adnl.pubkey_hash(),
                                         .adnl_id = adnl,
                                         .weight = 1});
      total_weight += 1;
    }

    runtime_.register_actor<OverlayStub>("PrivateOverlay");
    runtime_.register_actor<HoldingAccepter>("HoldingAccepter");
    simplex::CandidateResolver::register_in(runtime_);
    simplex::StateResolver::register_in(runtime_);
    simplex::Db::register_in(runtime_);
    simplex::DefaultCollatorSchedule::provide_for(runtime_);

    manager_ = td::actor::create_actor<ControlledManager>("ControlledManager");
    auto bus = std::make_shared<simplex::Bus>();
    bus->shard = SHARD;
    bus->manager = manager_.get();
    bus->validator_set = validators;
    std::set<adnl::AdnlNodeIdShort> current_relays;
    for (const auto& validator : validators) {
      bus->all_validators.push_back(validator.adnl_id);
      current_relays.insert(validator.adnl_id);
    }
    bus->all_current_validators = std::move(current_relays);
    bus->total_weight = total_weight;
    bus->config = NewConsensusConfig{
        .max_block_size = 1 << 20,
        .max_collated_data_size = 1 << 20,
        .protocol_version = 2,
        .slots_per_leader_window = SLOTS_PER_LEADER_WINDOW,
    };
    bus->config.noncritical_params.first_block_timeout = std::chrono::milliseconds(600'000);
    bus->config.noncritical_params.standstill_timeout = std::chrono::milliseconds(600'000);
    bus->session_id = fill(0x42);
    bus->cc_seqno = CC_SEQNO;
    bus->validator_set_hash = 0;
    bus->db = std::make_unique<MemoryDb>();
    bus->pq_signer = signers_.at(target_);
    bus->local_id = validators.at(target_);
    bus->local_adnl_id = validators.at(target_).adnl_id;

    // The bus signals its own destruction through this promise, exactly as the bridge's
    // stop waiter observes it in production.
    auto [stopped, stop_promise] = td::actor::StartedTask<>::make_bridge();
    bus_stopped_ = std::move(stopped);
    bus->stop_promise = std::move(stop_promise);
    bus_ptr_ = bus;

    bus_ = runtime_.start(std::static_pointer_cast<simplex::Bus>(bus), "c10-target");
    bus_.publish<Start>(
        td::make_ref<ChainState>(ChainState::ZerostateTip{FIRST_PARENT, gen_shard_state(0)}, MIN_MC_BLOCK_ID));
  }

  td::actor::Task<> run_inner() {
    start_node();

    // X: a full candidate on the genesis state, stored locally so the resolver finds it.
    auto X = make_candidate(1, FIRST_PARENT, std::nullopt, 0);
    emit(PSTRING() << "C10_CHAIN X=" << id_str(X->id));
    co_await bus_.publish<simplex::StoreCandidate>(X);
    // The resolver only answers ResolveCandidate for a candidate it also holds a
    // notarization certificate for.
    bus_.publish<simplex::NotarizationObserved>(X->id, make_cert(simplex::NotarizeVote{X->id}));
    auto cert = make_cert(simplex::FinalizeVote{X->id});

    // 1. First finalization: runs until FinalizeBlock is held by the accepter stand-in.
    bus_.publish<simplex::FinalizationObserved>(X->id, cert);
    if (!co_await wait_until([&] { return held_finalizations() >= 1; })) {
      finish(1, "C10_PRECONDITION_FAILED: the first finalization never reached FinalizeBlock");
    }
    emit("C10_STEP first finalization is InFlight");

    // 2. Second finalization of the same candidate: registers a waiter on the InFlight entry.
    bus_.publish<simplex::FinalizationObserved>(X->id, cert);
    co_await settle();

    // 3. ResolveState(X): finalization_of(X) registers another waiter on the same entry.
    auto resolve = bus_.publish<simplex::ResolveState>(ParentId{X->id}).start();
    co_await settle();
    if (held_finalizations() != 1) {
      finish(1, PSTRING() << "C10_PRECONDITION_FAILED: expected exactly one held finalization, got "
                          << held_finalizations());
    }
    size_t requests_before_stop;
    {
      std::scoped_lock lock(observations.mutex);
      requests_before_stop = observations.manager_requests;
    }
    emit(PSTRING() << "C10_STEP waiters registered; manager_requests=" << requests_before_stop);

    // 4. Stop the group and drop the driver's own references, as the bridge does.
    stop_published.store(true);
    bus_.publish<StopRequested>();
    std::weak_ptr<simplex::Bus> weak_bus = bus_ptr_;
    bus_ptr_.reset();
    bus_ = {};
    emit("C10_STEP StopRequested published, driver handle dropped");

    // ResolveState(X) must end, and end with the teardown cancellation. Before the fix its
    // waiter was re-registered on a list nobody drains any more, and this never completed.
    if (!co_await wait_until([&] { return resolve.await_ready(); })) {
      finish(2, "C10_FAILED: ResolveState never completed after the stop (stranded waiter)");
    }
    auto resolved = co_await std::move(resolve).wrap();
    if (resolved.is_ok()) {
      finish(2, "C10_FAILED: ResolveState completed successfully after the stop");
    }
    emit(PSTRING() << "C10_RESOLVE_STATE " << resolved.error().to_string());
    if (resolved.error().code() != ErrorCode::cancelled) {
      finish(2,
             PSTRING() << "C10_FAILED: ResolveState ended with " << resolved.error().code() << " instead of cancelled");
    }

    // The bus must destruct: every actor gone, every coroutine frame released.
    if (!co_await wait_until([&] { return bus_stopped_->await_ready(); })) {
      emit(PSTRING() << "C10_BUS_STILL_ALIVE bus_refs=" << weak_bus.use_count());
      finish(3, "C10_FAILED: the consensus bus did not stop; the resolver still holds it");
    }
    co_await std::move(*bus_stopped_);
    co_await settle();

    size_t after_stop;
    size_t released;
    {
      std::scoped_lock lock(observations.mutex);
      after_stop = observations.manager_requests_after_stop;
      released = observations.released_finalizations;
    }
    emit(PSTRING() << "C10_RESULT bus_expired=" << weak_bus.expired() << " released_finalizations=" << released
                   << " manager_requests_after_stop=" << after_stop);
    if (!weak_bus.expired()) {
      finish(3, "C10_FAILED: the bus object is still referenced after its stop promise completed");
    }
    if (after_stop != 0) {
      finish(4, "C10_FAILED: the resolver asked the manager for work after the stop");
    }
    finish(0, "C10_TEARDOWN_OK");
  }
};

}  // namespace

int main() {
  SET_VERBOSITY_LEVEL(verbosity_WARNING);
  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<Driver> driver;
  scheduler.run_in_context([&] {
    driver = td::actor::create_actor<Driver>("c10-driver");
    td::actor::ask(driver, &Driver::run).detach();
  });
  while (scheduler.run(1)) {
  }
  return 0;
}
