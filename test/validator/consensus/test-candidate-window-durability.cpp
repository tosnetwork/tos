/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
// Actor-level regression: a leader signs a candidate only after its leader window is durably
// recorded.
//
// The record of the first leader window not yet announced (poolState) is what keeps a restarted
// leader from announcing a window it already led, and so from collating and signing a second,
// different candidate for a slot it already proposed in. Pool publishes LeaderWindowObserved as a
// bus request: the Db is its processor, and Consensus, which starts candidate generation, is only
// a listener. The bus notifies the listeners of a request only after its processor succeeded, so
// generation, and with it every candidate signature, follows the durable write. Nothing else
// orders the two; this test pins that the ordering holds.
//
// One validator node, the leader of window 0, runs the production Consensus, Pool, BlockProducer,
// CandidateResolver, StateResolver, BlockValidator and Db actors. The stand-ins are the validator
// manager (which collates a different block on every call, so every collation yields a different
// CandidateId), the private overlay and the database backend, which can hold the poolState write
// and then either let it land or lose it as a crash would. No peer certificate is delivered, so
// the node never leaves window 0 on its own.
//
// Modes:
//   crash-restart     the poolState write is held, the node crashes (the write is lost) and
//                     restarts. The first life signs nothing, and over both lives the node signs
//                     at most one CandidateId per slot.
//   release           the write is held: no candidate is signed; once it lands, the candidate is.
//   shutdown-waiting  the group stops while the write is held: it stops and signs nothing.

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "auto/tl/tos_api.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "consensus/simplex/bus.h"
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
constexpr size_t TARGET = 0;  // the leader of window 0
constexpr double STEP_TIMEOUT = 10.0;
// Several times first_block_timeout + target_rate + collation: a candidate that could be signed
// is signed well within it.
constexpr double PRODUCTION_WINDOW = 1.5;

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

enum class Mode { CrashRestart, Release, ShutdownWaiting };

// ===== The database backend: one durable store shared by both lives of the node =====

using WritePromise = decltype(td::actor::StartedTask<>::make_bridge().second);

struct HeldWrite {
  td::BufferSlice key;
  td::BufferSlice value;
  WritePromise promise;
};

struct Storage {
  std::mutex mutex;
  std::map<td::BufferSlice, td::BufferSlice> map;
  bool hold_pool_state = false;
  std::vector<HeldWrite> held;
  // The poolState value most recently made durable (0: none yet).
  td::uint32 durable_pool_state = 0;
};

Storage storage;

bool is_pool_state(td::Slice value) {
  td::int32 tag = 0;
  if (value.size() < sizeof(tag)) {
    return false;
  }
  std::memcpy(&tag, value.data(), sizeof(tag));
  return tag == tos_api::consensus_simplex_db_poolState::ID;
}

td::uint32 decode_pool_state(td::Slice value) {
  auto parsed = fetch_tl_object<tos_api::consensus_simplex_db_poolState>(value, true);
  CHECK(parsed.is_ok());
  return static_cast<td::uint32>(parsed.ok()->first_nonannounced_window_);
}

// Must be called with storage.mutex held.
void apply_locked(td::BufferSlice key, td::BufferSlice value) {
  if (is_pool_state(value.as_slice())) {
    storage.durable_pool_state = decode_pool_state(value.as_slice());
  }
  storage.map[std::move(key)] = std::move(value);
}

void hold_pool_state_writes() {
  std::scoped_lock lock(storage.mutex);
  storage.hold_pool_state = true;
}

size_t held_writes() {
  std::scoped_lock lock(storage.mutex);
  return storage.held.size();
}

td::uint32 durable_pool_state() {
  std::scoped_lock lock(storage.mutex);
  return storage.durable_pool_state;
}

// The held writes land, in order, and later ones are no longer held.
void release_writes() {
  std::vector<HeldWrite> held;
  {
    std::scoped_lock lock(storage.mutex);
    storage.hold_pool_state = false;
    held = std::move(storage.held);
    storage.held.clear();
    for (auto& write : held) {
      apply_locked(std::move(write.key), std::move(write.value));
    }
  }
  emit(PSTRING() << "CWD_RELEASE n=" << held.size());
  for (auto& write : held) {
    write.promise.set_value(td::Unit{});
  }
}

// A crash: the held writes never reach the disk.
void drop_writes() {
  std::vector<HeldWrite> held;
  {
    std::scoped_lock lock(storage.mutex);
    storage.hold_pool_state = false;
    held = std::move(storage.held);
    storage.held.clear();
  }
  emit(PSTRING() << "CWD_DROP n=" << held.size());
  for (auto& write : held) {
    write.promise.set_error(td::Status::Error(ErrorCode::cancelled, "lost in a crash"));
  }
}

class MemoryDb : public consensus::Db {
 public:
  MemoryDb() {
    std::scoped_lock lock(storage.mutex);
    for (auto& [key, value] : storage.map) {
      snapshot_.emplace(key.clone(), value.clone());
    }
  }

  std::optional<td::BufferSlice> get(td::Slice key) const override {
    auto it = snapshot_.find(td::BufferSlice{key});
    if (it == snapshot_.end()) {
      return std::nullopt;
    }
    return it->second.clone();
  }

  std::vector<std::pair<td::BufferSlice, td::BufferSlice>> get_by_prefix(td::uint32 prefix) const override {
    std::vector<std::pair<td::BufferSlice, td::BufferSlice>> result;
    td::BufferSlice begin{(const char*)&prefix, 4};
    td::uint32 next_prefix = prefix + 1;
    td::BufferSlice end{(const char*)&next_prefix, 4};
    for (auto it = snapshot_.lower_bound(begin); it != snapshot_.end() && it->first < end; ++it) {
      result.emplace_back(it->first.clone(), it->second.clone());
    }
    return result;
  }

  td::actor::Task<std::optional<td::BufferSlice>> get_latest(td::BufferSlice key) const override {
    std::scoped_lock lock(storage.mutex);
    auto it = storage.map.find(key);
    if (it == storage.map.end()) {
      co_return std::nullopt;
    }
    co_return it->second.clone();
  }

  td::actor::Task<> set(td::BufferSlice key, td::BufferSlice value) override {
    std::optional<td::actor::StartedTask<>> wait;
    {
      std::scoped_lock lock(storage.mutex);
      if (storage.hold_pool_state && is_pool_state(value.as_slice())) {
        auto [task, promise] = td::actor::StartedTask<>::make_bridge();
        storage.held.push_back(HeldWrite{std::move(key), std::move(value), std::move(promise)});
        wait.emplace(std::move(task));
      } else {
        apply_locked(std::move(key), std::move(value));
      }
    }
    if (wait) {
      auto landed = co_await std::move(*wait).wrap();
      co_return landed;
    }
    co_return td::Unit{};
  }

  td::actor::Task<> close() override {
    co_return td::Unit{};
  }

 private:
  std::map<td::BufferSlice, td::BufferSlice> snapshot_;
};

// ===== What the test observes =====

struct SignedCandidate {
  td::uint32 slot;
  std::string id;
  size_t life;
  td::uint32 durable_pool_state;  // the durable record when the signed candidate appeared
};

std::mutex observations_mutex;
std::vector<SignedCandidate> observed_candidates;
std::atomic<size_t> current_life{0};

std::vector<SignedCandidate> candidates() {
  std::scoped_lock lock(observations_mutex);
  return observed_candidates;
}

// The equivocation the ordering prevents: two different CandidateIds signed by this leader for
// one slot. Different signatures over one CandidateId would not be one.
std::optional<std::string> conflicting_candidates() {
  std::map<td::uint32, std::set<std::string>> by_slot;
  for (const auto& c : candidates()) {
    by_slot[c.slot].insert(c.id);
  }
  for (const auto& [slot, ids] : by_slot) {
    if (ids.size() > 1) {
      return PSTRING() << ids.size() << " different candidates signed for slot " << slot;
    }
  }
  return std::nullopt;
}

class ObserverActor : public td::actor::SpawnsWith<simplex::Bus>, public td::actor::ConnectsTo<simplex::Bus> {
 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();

  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const StopRequested>) {
    stop();
  }

  // Published by the block producer after it signed the candidate.
  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const CandidateGenerated> event) {
    const auto& id = event->candidate->id;
    const auto durable = durable_pool_state();
    emit(PSTRING() << "CWD_CANDIDATE life=" << current_life.load() << " slot=" << id.slot << " id=" << id.hash.to_hex()
                   << " durable_pool_state=" << durable);
    std::scoped_lock lock(observations_mutex);
    observed_candidates.push_back(SignedCandidate{id.slot, id.hash.to_hex(), current_life.load(), durable});
  }
};

class OverlayStub : public td::actor::SpawnsWith<simplex::Bus>, public td::actor::ConnectsTo<simplex::Bus> {
 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();

  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const StopRequested>) {
    stop();
  }

  template <>
  td::actor::Task<ProtocolMessage> process(simplex::BusHandle, std::shared_ptr<OutgoingOverlayRequest> message) {
    co_await td::actor::coro_sleep(message->timeout);
    co_return td::Status::Error(ErrorCode::timeout, "no peer answered");
  }
};

BlockCandidate make_block(BlockSeqno seqno, const BlockIdExt& prev, td::uint64 nonce, double gen_utime) {
  BlockSeqno prev_seqno = seqno - 1;

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
  // The nonce makes every collation a different block, as a real re-collation is.
  td::Ref<vm::Cell> block_extra = vm::CellBuilder{}.store_long(nonce, 64).finalize_novm();
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

  return BlockCandidate(ValidatorId{fill(0x70)},
                        BlockIdExt(BlockId(SHARD, seqno), block_root->get_hash().bits(), td::sha256_bits256(data)),
                        td::sha256_bits256(collated_data), data.clone(), collated_data.clone());
}

std::atomic<td::uint64> collations{0};

// The validator manager: collates a new block on every call and accepts every candidate.
class CollatingManager : public ManagerFacade {
 public:
  td::actor::Task<GeneratedCandidate> collate_block(CollateParams params, td::CancellationToken) override {
    CHECK(params.prev.size() == 1);
    auto prev = params.prev[0];
    double gen_utime = params.utime ? params.utime.value() : td::Clocks::system();
    auto nonce = ++collations;
    auto candidate = make_block(prev.seqno() + 1, prev, nonce, gen_utime);
    co_return GeneratedCandidate{.candidate = std::move(candidate),
                                 .is_cached = false,
                                 .self_collated = true,
                                 .processed_external_messages = params.processed_external_messages};
  }

  td::actor::Task<ValidateCandidateResult> validate_block_candidate(BlockCandidate, ValidateParams,
                                                                    td::Timestamp) override {
    co_return CandidateAccept{};
  }

  td::actor::Task<> accept_block(BlockIdExt, td::Ref<BlockData>, size_t, td::Ref<block::BlockSignatureSet>,
                                 ValidatorSessionId, int, int, bool, bool) override {
    co_return td::Unit{};
  }

  td::actor::Task<td::Ref<vm::Cell>> wait_block_state_root(BlockIdExt block_id, td::Timestamp,
                                                           std::optional<CandidateId>) override {
    if (block_id != FIRST_PARENT) {
      co_return td::Status::Error(ErrorCode::notready, "only the zerostate is available");
    }
    co_return gen_shard_state(0);
  }

  td::actor::Task<td::Ref<BlockData>> wait_block_data(BlockIdExt, td::Timestamp) override {
    co_return td::Status::Error(ErrorCode::notready, "no block data is available");
  }
};

class Driver : public td::actor::Actor {
 public:
  explicit Driver(Mode mode) : mode_(mode) {
  }

  td::actor::Task<> run() {
    auto result = co_await run_inner().wrap();
    if (result.is_error()) {
      finish(1, "CWD_HARNESS_FAILED: " + result.error().to_string());
    }
    co_return td::Unit{};
  }

 private:
  Mode mode_;
  std::vector<std::shared_ptr<const tos::pq::ValidatorPQKeyStore>> signers_;
  std::vector<PeerValidator> validators_;
  std::unique_ptr<td::actor::Runtime> runtime_;
  td::actor::ActorOwn<CollatingManager> manager_;
  simplex::BusHandle bus_;
  std::optional<td::actor::StartedTask<>> stopped_;

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

  td::actor::Task<> settle(double seconds) {
    co_await td::actor::coro_sleep(td::Timestamp::in(seconds));
    co_return td::Unit{};
  }

  void require(bool condition, const std::string& what) {
    if (!condition) {
      finish(4, "CWD_ASSERTION_FAILED: " + what);
    }
  }

  void require_no_conflicts() {
    if (auto conflict = conflicting_candidates()) {
      finish(4, "CWD_CONFLICT: " + *conflict);
    }
  }

  // Every signed candidate appeared while the record covering its window was durable.
  void require_signed_after_record() {
    for (const auto& c : candidates()) {
      const td::uint32 window = c.slot / SLOTS_PER_LEADER_WINDOW;
      require(c.durable_pool_state > window, PSTRING()
                                                 << "the candidate for slot " << c.slot
                                                 << " was signed with the durable record at " << c.durable_pool_state);
    }
  }

  [[noreturn]] void pass(const std::string& line) {
    finish(0, line);
  }

  void make_validators() {
    for (size_t i = 0; i < VALIDATORS; ++i) {
      // Deliberately public fixture seeds, never operational key material.
      auto store = tos::pq::ValidatorPQKeyStore::from_seed(std::string(32, static_cast<char>(0x60 + i)));
      CHECK(store.has_value());
      signers_.push_back(std::make_shared<const tos::pq::ValidatorPQKeyStore>(std::move(*store)));
      auto adnl = adnl::AdnlNodeIdShort{fill(static_cast<unsigned char>(0x90 + i))};
      validators_.push_back(PeerValidator{.validator_id = ValidatorId{fill(static_cast<unsigned char>(0x70 + i))},
                                          .idx = PeerValidatorId{i},
                                          .consensus_key = signers_.back()->consensus_key(),
                                          .transport_key_id = adnl.pubkey_hash(),
                                          .adnl_id = adnl,
                                          .weight = 1});
    }
    manager_ = td::actor::create_actor<CollatingManager>("CollatingManager");
  }

  // One life of the node. The database backend persists across lives; actors do not.
  void start_node() {
    ++current_life;
    runtime_ = std::make_unique<td::actor::Runtime>();
    auto& runtime = *runtime_;
    runtime.register_actor<OverlayStub>("PrivateOverlay");
    runtime.register_actor<ObserverActor>("CwdObserver");
    BlockProducer::register_in(runtime);
    BlockValidator::register_in(runtime);
    simplex::CandidateResolver::register_in(runtime);
    simplex::Consensus::register_in(runtime);
    simplex::Pool::register_in(runtime);
    simplex::StateResolver::register_in(runtime);
    simplex::Db::register_in(runtime);
    simplex::DefaultCollatorSchedule::provide_for(runtime);

    auto bus = std::make_shared<simplex::Bus>();
    bus->shard = SHARD;
    bus->manager = manager_.get();
    bus->validator_set = validators_;
    std::set<adnl::AdnlNodeIdShort> current_relays;
    for (const auto& validator : validators_) {
      bus->all_validators.push_back(validator.adnl_id);
      current_relays.insert(validator.adnl_id);
    }
    bus->all_current_validators = std::move(current_relays);
    bus->total_weight = VALIDATORS;
    bus->config = NewConsensusConfig{
        .max_block_size = 1 << 20,
        .max_collated_data_size = 1 << 20,
        .protocol_version = 2,
        .slots_per_leader_window = SLOTS_PER_LEADER_WINDOW,
    };
    auto& params = bus->config.noncritical_params;
    params.first_block_timeout = std::chrono::milliseconds(300);
    params.target_rate = std::chrono::milliseconds(200);
    params.standstill_timeout = std::chrono::milliseconds(600'000);
    bus->session_id = fill(0x42);
    bus->cc_seqno = CC_SEQNO;
    bus->validator_set_hash = 0;
    bus->db = std::make_unique<MemoryDb>();
    auto [stopped, stop_promise] = td::actor::StartedTask<>::make_bridge();
    bus->stop_promise = std::move(stop_promise);
    stopped_.emplace(std::move(stopped));

    bus->pq_signer = signers_.at(TARGET);
    bus->local_id = validators_.at(TARGET);
    bus->local_adnl_id = validators_.at(TARGET).adnl_id;

    bus_ = runtime.start(std::static_pointer_cast<simplex::Bus>(bus), PSTRING() << "cwd-life" << current_life.load());
    bus_.publish<Start>(
        td::make_ref<ChainState>(ChainState::ZerostateTip{FIRST_PARENT, gen_shard_state(0)}, MIN_MC_BLOCK_ID));
    emit(PSTRING() << "CWD_START life=" << current_life.load());
  }

  // Stops the node. With `crash`, writes still held are lost instead of landing.
  td::actor::Task<> stop_node(bool crash) {
    bus_.publish<StopRequested>();
    co_await settle(0.2);
    if (crash) {
      drop_writes();
    } else {
      release_writes();
    }
    bus_ = {};
    co_await std::move(*stopped_);
    stopped_.reset();
    runtime_.reset();
    emit("CWD_STOPPED");
    co_return td::Unit{};
  }

  td::actor::Task<> await_held_write() {
    if (!co_await wait_until([] { return held_writes() > 0; })) {
      finish(1, "CWD_PRECONDITION_FAILED: the window-0 poolState write was never issued");
    }
    co_return td::Unit{};
  }

  td::actor::Task<> run_inner() {
    make_validators();
    switch (mode_) {
      case Mode::CrashRestart:
        co_return co_await run_crash_restart();
      case Mode::Release:
        co_return co_await run_release();
      case Mode::ShutdownWaiting:
        co_return co_await run_shutdown_waiting();
    }
    co_return td::Unit{};
  }

  td::actor::Task<> run_crash_restart() {
    hold_pool_state_writes();
    start_node();
    co_await await_held_write();
    // Time to collate and sign, were signing not ordered after the write.
    co_await settle(PRODUCTION_WINDOW);
    const auto first_life = candidates().size();
    emit(PSTRING() << "CWD_FIRST_LIFE candidates=" << first_life);
    co_await stop_node(/*crash=*/true);
    require(durable_pool_state() == 0, "the window-0 record was lost in the crash");

    start_node();
    // Window 0 is announced again, because its record never landed; this time it lands and the
    // candidate is signed.
    if (!co_await wait_until([] {
          auto all = candidates();
          return std::any_of(all.begin(), all.end(),
                             [](const auto& c) { return c.life == 2 && c.slot < SLOTS_PER_LEADER_WINDOW; });
        })) {
      require_no_conflicts();
      finish(4, "CWD_ASSERTION_FAILED: the restarted leader signed no candidate for window 0");
    }
    co_await settle(PRODUCTION_WINDOW);
    require_no_conflicts();
    require(first_life == 0,
            PSTRING() << "the first life signed " << first_life << " candidates before its leader window was durable");
    require_signed_after_record();
    co_await stop_node(/*crash=*/false);
    pass("CWD_OK crash-restart");
  }

  td::actor::Task<> run_release() {
    hold_pool_state_writes();
    start_node();
    co_await await_held_write();
    co_await settle(PRODUCTION_WINDOW);
    require(candidates().empty(), "a candidate was signed before its leader window was durable");
    release_writes();
    if (!co_await wait_until([] { return !candidates().empty(); })) {
      finish(4, "CWD_ASSERTION_FAILED: no candidate was signed after the window record landed");
    }
    co_await settle(0.3);
    require_signed_after_record();
    require_no_conflicts();
    co_await stop_node(/*crash=*/false);
    pass("CWD_OK release");
  }

  td::actor::Task<> run_shutdown_waiting() {
    hold_pool_state_writes();
    start_node();
    co_await await_held_write();
    co_await settle(PRODUCTION_WINDOW);
    require(candidates().empty(), "a candidate was signed before its leader window was durable");
    // The write lands only after the stop was requested; the stopping group signs nothing.
    co_await stop_node(/*crash=*/false);
    co_await settle(0.3);
    require(candidates().empty(), "a candidate was signed during shutdown");
    pass("CWD_OK shutdown-waiting");
  }
};

}  // namespace

int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(verbosity_WARNING);
  const std::vector<std::pair<std::string, Mode>> modes = {
      {"crash-restart", Mode::CrashRestart},
      {"release", Mode::Release},
      {"shutdown-waiting", Mode::ShutdownWaiting},
  };
  std::optional<Mode> mode;
  for (const auto& [name, value] : modes) {
    if (argc == 2 && name == argv[1]) {
      mode = value;
    }
  }
  if (!mode) {
    std::fprintf(stderr, "usage: %s <mode>; modes:", argv[0]);
    for (const auto& [name, _] : modes) {
      std::fprintf(stderr, " %s", name.c_str());
    }
    std::fprintf(stderr, "\n");
    return 2;
  }

  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<Driver> driver;
  scheduler.run_in_context([&] {
    driver = td::actor::create_actor<Driver>("cwd-driver", *mode);
    td::actor::ask(driver, &Driver::run).detach();
  });
  while (scheduler.run(1)) {
  }
  return 0;
}
