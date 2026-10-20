/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
// The state resolver's running count of unfinalized finalization entries, driven inside the
// production actor. One validator node runs the production CandidateResolver, StateResolver
// and Db; the stand-ins are the validator manager, the private overlay, the block accepter
// and the database backend. Run with TOS_SIMPLEX_TEST_CROSSCHECK_UNFINALIZED set: the
// resolver then checks the count against a full walk after every change and aborts on the
// first mismatch, and this test requires the transitions each mode exists to produce.
//
// Modes:
//   db-hit-overwrite  ResolveState(X) reads X's durable finalized marker; the test holds that
//                     read. Meanwhile a finalization of X starts, creates X's entry and runs
//                     (its FinalizeBlock held). The marker read then returns "finalized", so
//                     the resolver overwrites the running entry with Finalized; then the held
//                     attempt succeeds and finalizes the same entry again. The overwrite must
//                     be counted once and the second Finalized not at all.
//   backlog-sequence  Three chained certificates with the first injected attempts failing and
//                     the backlog limit at one: prints every FinalizationBacklog event in order,
//                     so the sequence can be compared with a build before the running count.

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
#include "td/utils/port/signals.h"
#include "vm/boc.h"

#include "block-auto.h"

// The counter checks exist only in builds with the running count; the backlog-sequence mode
// also builds against the tree before it, for comparison.
#if __has_include("consensus/simplex/counted-finalizations.h")
#define A142_HAS_RUNNING_COUNT 1
#endif

using namespace tos;
using namespace tos::validator;
using namespace tos::validator::consensus;

namespace {

constexpr td::uint32 SLOTS_PER_LEADER_WINDOW = 4;
constexpr size_t VALIDATORS = 4;
constexpr double STEP_TIMEOUT = 10.0;

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

enum class Mode { DbHitOverwrite, BacklogSequence };
Mode mode = Mode::DbHitOverwrite;

using Promise = td::actor::StartedTask<td::Unit>::ExternalPromise;

struct Observations {
  std::mutex mutex;
  std::vector<Promise> held_finalizations;
  size_t finalize_requests = 0;
  // The durable-marker read held by the database stand-in, and the key it is held for.
  std::optional<std::string> hold_marker_key;
  std::optional<Promise> held_marker_read;
  size_t marker_reads = 0;
  std::vector<std::pair<bool, size_t>> backlog_events;
};

Observations observations;

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

  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const FinalizationBacklog> event) {
    emit(PSTRING() << "A142_BACKLOG_EVENT over=" << event->over_limit << " pending=" << event->pending);
    std::scoped_lock lock(observations.mutex);
    observations.backlog_events.emplace_back(event->over_limit, event->pending);
  }
};

// The block accepter: in db-hit-overwrite every FinalizeBlock is held for the driver; in
// backlog-sequence each is accepted at once.
class Accepter : public td::actor::SpawnsWith<simplex::Bus>, public td::actor::ConnectsTo<simplex::Bus> {
 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();

  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const StopRequested>) {
    stop();
  }

  template <>
  td::actor::Task<> process(simplex::BusHandle, std::shared_ptr<FinalizeBlock>) {
    {
      std::scoped_lock lock(observations.mutex);
      ++observations.finalize_requests;
    }
    if (mode != Mode::DbHitOverwrite) {
      co_return td::Unit{};
    }
    auto [task, promise] = td::actor::StartedTask<td::Unit>::make_bridge();
    {
      std::scoped_lock lock(observations.mutex);
      observations.held_finalizations.push_back(std::move(promise));
    }
    emit("A142_FINALIZE_HELD");
    co_return co_await std::move(task);
  }
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

  // The first read of the held key waits for the driver, and then reports the marker as
  // present; every other read answers from the map at once.
  td::actor::Task<std::optional<td::BufferSlice>> get_latest(td::BufferSlice key) const override {
    std::optional<td::actor::StartedTask<td::Unit>> wait;
    {
      std::scoped_lock lock(observations.mutex);
      if (observations.hold_marker_key == key.as_slice().str()) {
        ++observations.marker_reads;
        if (observations.marker_reads == 1) {
          auto [task, promise] = td::actor::StartedTask<td::Unit>::make_bridge();
          observations.held_marker_read.emplace(std::move(promise));
          wait.emplace(std::move(task));
        }
      }
    }
    if (wait.has_value()) {
      emit("A142_MARKER_READ_HELD");
      co_await std::move(*wait);
      co_return td::BufferSlice("finalized");
    }
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

class ControlledManager : public ManagerFacade {
 public:
  td::actor::Task<GeneratedCandidate> collate_block(CollateParams, td::CancellationToken) override {
    co_return td::Status::Error("this node does not collate");
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
    if (block_id == FIRST_PARENT) {
      co_return gen_shard_state(0);
    }
    co_return td::Status::Error(ErrorCode::notready, "only the zerostate is available");
  }

  td::actor::Task<td::Ref<BlockData>> wait_block_data(BlockIdExt, td::Timestamp) override {
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
      finish(1, "A142_HARNESS_FAILED: " + result.error().to_string());
    }
    co_return td::Unit{};
  }

 private:
  std::vector<std::shared_ptr<const tos::pq::ValidatorPQKeyStore>> signers_;
  td::actor::Runtime runtime_;
  td::actor::ActorOwn<ControlledManager> manager_;
  simplex::BusHandle bus_;
  std::shared_ptr<simplex::Bus> bus_ptr_;
  size_t target_ = 1;

  td::BufferSlice sign(size_t signer, td::Slice inner) const {
    auto envelope =
        create_serialize_tl_object<tos_api::consensus_dataToSign>(bus_ptr_->session_id, td::BufferSlice(inner));
    auto signature =
        signers_.at(signer)->sign_consensus(std::string_view(envelope.as_slice().data(), envelope.as_slice().size()));
    CHECK(signature.has_value());
    return td::BufferSlice(signature->signature);
  }

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

  td::actor::Task<simplex::QueryFinalizationState::Result> query() {
    co_return co_await bus_.publish<simplex::QueryFinalizationState>(td::uint32{0});
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
    runtime_.register_actor<Accepter>("Accepter");
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
    bus_ptr_ = bus;

    bus_ = runtime_.start(std::static_pointer_cast<simplex::Bus>(bus), "a142-resolver");
    bus_.publish<Start>(
        td::make_ref<ChainState>(ChainState::ZerostateTip{FIRST_PARENT, gen_shard_state(0)}, MIN_MC_BLOCK_ID));
  }

  td::actor::Task<> run_inner() {
    start_node();
    if (mode == Mode::DbHitOverwrite) {
      co_return co_await run_db_hit_overwrite();
    }
    co_return co_await run_backlog_sequence();
  }

  td::actor::Task<> run_db_hit_overwrite() {
#ifdef A142_HAS_RUNNING_COUNT
    using simplex::UnfinalizedTransition;
    auto checks = [](UnfinalizedTransition kind) { return simplex::unfinalized_crosschecks_for_test(kind); };
    auto X = make_candidate(1, FIRST_PARENT, std::nullopt, 0);
    co_await bus_.publish<simplex::StoreCandidate>(X);
    bus_.publish<simplex::NotarizationObserved>(X->id, make_cert(simplex::NotarizeVote{X->id}));
    {
      std::scoped_lock lock(observations.mutex);
      observations.hold_marker_key =
          create_serialize_tl_object<tos_api::consensus_simplex_db_key_finalizedBlock>(X->id.to_tl()).as_slice().str();
    }

    // B: ResolveState(X) reaches X's durable-marker read, which is held.
    auto resolve = bus_.publish<simplex::ResolveState>(ParentId{X->id}).start();
    if (!co_await wait_until([] {
          std::scoped_lock lock(observations.mutex);
          return observations.held_marker_read.has_value();
        })) {
      finish(1, "A142_PRECONDITION_FAILED: ResolveState never read X's finalized marker");
    }

    // A: a finalization of X reads the marker (absent, not held), creates the entry and runs
    // until its FinalizeBlock is held.
    bus_.publish<simplex::FinalizationObserved>(X->id, make_cert(simplex::FinalizeVote{X->id}));
    if (!co_await wait_until([] {
          std::scoped_lock lock(observations.mutex);
          return observations.held_finalizations.size() == 1;
        })) {
      finish(1, "A142_PRECONDITION_FAILED: the finalization of X never reached FinalizeBlock");
    }
    if (checks(UnfinalizedTransition::InsertUnfinalized) != 1 ||
        checks(UnfinalizedTransition::BetweenUnfinalized) != 1) {
      finish(1, "A142_PRECONDITION_FAILED: the cross-check is not running, or the attempt did not create its entry");
    }
    auto running = co_await query();
    emit(PSTRING() << "A142_STEP entry in flight, peak=" << running.unfinalized_held_peak);

    // The held marker read now reports X finalized: the running entry is overwritten.
    {
      std::scoped_lock lock(observations.mutex);
      observations.held_marker_read->set_value(td::Unit{});
      observations.held_marker_read.reset();
    }
    if (!co_await wait_until([&] { return checks(UnfinalizedTransition::DbHitOverwrite) == 1; })) {
      finish(1, "A142_PRECONDITION_FAILED: the durable marker never overwrote the running entry");
    }
    emit("A142_STEP durable marker overwrote the running entry");

    // The held attempt then succeeds and finalizes the same entry again.
    {
      std::scoped_lock lock(observations.mutex);
      for (auto& promise : observations.held_finalizations) {
        promise.set_value(td::Unit{});
      }
      observations.held_finalizations.clear();
    }
    if (!co_await wait_until([&] { return checks(UnfinalizedTransition::RepeatFinalized) >= 1; })) {
      finish(1, "A142_PRECONDITION_FAILED: the attempt never finalized the overwritten entry");
    }
    auto settled = co_await query();
    (void)co_await std::move(resolve).wrap();  // NOLINT(bugprone-unused-return-value): only its completion matters
    emit(PSTRING() << "A142_RESULT insert_unfinalized=" << checks(UnfinalizedTransition::InsertUnfinalized)
                   << " between_unfinalized=" << checks(UnfinalizedTransition::BetweenUnfinalized)
                   << " to_finalized=" << checks(UnfinalizedTransition::ToFinalized)
                   << " db_hit_overwrite=" << checks(UnfinalizedTransition::DbHitOverwrite)
                   << " repeat_finalized=" << checks(UnfinalizedTransition::RepeatFinalized) << " legacy_samples="
                   << checks(UnfinalizedTransition::LegacySample) << " peak=" << settled.unfinalized_held_peak);
    // One overwrite into Finalized, then a repeated Finalized; the peak is the one entry.
    if (checks(UnfinalizedTransition::ToFinalized) != 1 || checks(UnfinalizedTransition::RepeatFinalized) != 1 ||
        checks(UnfinalizedTransition::LegacySample) < 2 || settled.unfinalized_held_peak != 1) {
      finish(4, "A142_FAILED: the overwrite and the repeated Finalized were not each counted exactly as expected");
    }
    finish(0, "A142_OK db-hit-overwrite");
#else
    finish(2, "A142_UNSUPPORTED: db-hit-overwrite needs the running count");
#endif
  }

  // Three chained certificates, each finalized at once by the accepter but with the first
  // injected attempts failing (TOS_SIMPLEX_INJECT_TRANSIENT_FINALIZATION_FAILURES), and the
  // backlog limit at one (TOS_SIMPLEX_PENDING_FINALIZATIONS_MAX). Prints the backlog events in
  // order; the comparison with the earlier build is made on that output.
  td::actor::Task<> run_backlog_sequence() {
    auto X1 = make_candidate(1, FIRST_PARENT, std::nullopt, 0);
    auto X2 = make_candidate(2, X1->block_id(), X1->id, 1);
    auto X3 = make_candidate(3, X2->block_id(), X2->id, 2);
    for (const auto& c : {X1, X2, X3}) {
      co_await bus_.publish<simplex::StoreCandidate>(c);
      bus_.publish<simplex::NotarizationObserved>(c->id, make_cert(simplex::NotarizeVote{c->id}));
    }
    for (const auto& c : {X1, X2, X3}) {
      bus_.publish<simplex::FinalizationObserved>(c->id, make_cert(simplex::FinalizeVote{c->id}));
      co_await td::actor::coro_sleep(td::Timestamp::in(0.05));
    }
    if (!co_await wait_until(
            [&] {
              std::scoped_lock lock(observations.mutex);
              return !observations.backlog_events.empty() && !observations.backlog_events.back().first;
            },
            30.0)) {
      finish(1, "A142_PRECONDITION_FAILED: the backlog never went over and cleared");
    }
    co_await td::actor::coro_sleep(td::Timestamp::in(1.0));
    auto state = co_await query();
    std::string sequence;
    {
      std::scoped_lock lock(observations.mutex);
      for (const auto& [over, pending] : observations.backlog_events) {
        sequence += PSTRING() << "(" << over << "," << pending << ")";
      }
    }
    emit(PSTRING() << "A142_BACKLOG_SEQUENCE " << sequence << " pending_peak=" << state.pending_finalizations_peak
                   << " pending_now=" << state.pending_finalizations);
    finish(0, "A142_OK backlog-sequence");
  }
};

}  // namespace

int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(verbosity_WARNING);
  td::set_default_failure_signal_handler().ensure();
  const std::string name = argc == 2 ? argv[1] : "";
  if (name == "db-hit-overwrite") {
    mode = Mode::DbHitOverwrite;
  } else if (name == "backlog-sequence") {
    mode = Mode::BacklogSequence;
  } else {
    std::fprintf(stderr, "usage: %s db-hit-overwrite|backlog-sequence\n", argv[0]);
    return 2;
  }
  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<Driver> driver;
  scheduler.run_in_context([&] {
    driver = td::actor::create_actor<Driver>("a142-resolver-driver");
    td::actor::ask(driver, &Driver::run).detach();
  });
  while (scheduler.run(1)) {
  }
  return 0;
}
