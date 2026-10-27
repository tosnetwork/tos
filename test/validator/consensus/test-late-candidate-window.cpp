/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
// Actor-level regression: a candidate that arrives after its slot is finalized.
//
// One validator node runs the production Consensus, Pool, CandidateResolver, StateResolver,
// BlockValidator, BlockAccepter and Db actors. The stand-ins are the validator manager (which
// records accepted blocks), the private overlay (which refuses every candidate request, as the
// peers of a retired session do) and the database backend.
//
// A finalized slot whose candidate this node never received can only be applied once the
// candidate reaches the candidate resolver. Peers cannot supply it here, so the late broadcast
// is the only source. Modes:
//
//   late-after-precheck   the broadcast passes precheck, then NotarCert and FinalCert, then the
//                         candidate is delivered: the block is applied, and no vote is cast.
//   late-before-precheck  NotarCert and FinalCert first; the broadcast's precheck must pass,
//                         then the candidate is delivered: the block is applied.
//   after-round-budget    one resolve attempt per round: a round gives up and the state
//                         resolver starts another before the candidate arrives; it is applied.
//   outside-window        with a one-slot window, after slot 1 is finalized a broadcast for
//                         slot 0 is refused and a candidate for slot 0 is not persisted, while
//                         one for slot 1 is.
//   frontier-skew         Pool has not seen the finalization Consensus and the resolver act
//                         on: Pool admits the slot-0 broadcast, Consensus still does not store
//                         its candidate; once Pool sees a later finalization it refuses slot 0.
//   late-dedup-bound      a second distinct broadcast for a finalized slot is refused, also
//                         after a later slot is finalized.
//   resolver-pin          a resolve task asleep after a refused request keeps the candidate
//                         resolver's entry alive after a store completes it and the window
//                         passes its slot; the entry is evicted when the task ends.
//   resolver-pin-error    a resolve task that fails releases its pin too.
//   window-helper         late_window_begin() agrees with CandidateRetentionPolicy.
//   restart-before-start  a node restarts with FinalCerts beyond the too-new gate in its
//                         database and has no Start yet, so its leader window is not
//                         announced: the candidates of the finalized slots are stored, the
//                         one for the slot after them is not, and nothing is voted; after
//                         Start the finalized blocks are applied.
//
// Without an argument every mode runs in its own child process.

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#include "auto/tl/tos_api.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "consensus/simplex/bus.h"
#include "consensus/simplex/candidate-retention.h"
#include "consensus/simplex/certificate.h"
#include "consensus/simplex/stats.h"
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
constexpr double STEP_TIMEOUT = 15.0;
// Cooldown after a refused request in resolver-pin mode: long enough that the steps after the
// refusal finish while the resolve task still sleeps.
constexpr double PIN_COOLDOWN_SECONDS = 4.0;

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

enum class Mode {
  LateAfterPrecheck,
  LateBeforePrecheck,
  AfterRoundBudget,
  OutsideWindow,
  LateDedupBound,
  ResolverPin,
  ResolverPinError,
  FrontierSkew,
  RestartBeforeStart,
};

struct Observations {
  std::mutex mutex;
  std::vector<CandidateId> notarize_votes;
  std::vector<CandidateId> notarized;
  std::vector<td::uint32> finalized_slots;
  std::vector<CandidateId> overlay_requests;
  std::vector<BlockIdExt> accepted;
  size_t misbehavior_reports = 0;
};

Observations observations;

size_t count_of(const std::vector<CandidateId>& list, const CandidateId& id) {
  return static_cast<size_t>(std::count(list.begin(), list.end(), id));
}

size_t notarize_votes_for(const CandidateId& id) {
  std::scoped_lock lock(observations.mutex);
  return count_of(observations.notarize_votes, id);
}

bool is_notarized(const CandidateId& id) {
  std::scoped_lock lock(observations.mutex);
  return count_of(observations.notarized, id) > 0;
}

bool is_finalized(td::uint32 slot) {
  std::scoped_lock lock(observations.mutex);
  return std::count(observations.finalized_slots.begin(), observations.finalized_slots.end(), slot) > 0;
}

size_t overlay_requests_for(const CandidateId& id) {
  std::scoped_lock lock(observations.mutex);
  return count_of(observations.overlay_requests, id);
}

size_t accepted_count(const CandidateRef& candidate) {
  std::scoped_lock lock(observations.mutex);
  return static_cast<size_t>(
      std::count(observations.accepted.begin(), observations.accepted.end(), candidate->block_id()));
}

size_t misbehavior_reports() {
  std::scoped_lock lock(observations.mutex);
  return observations.misbehavior_reports;
}

class ObserverActor : public td::actor::SpawnsWith<simplex::Bus>, public td::actor::ConnectsTo<simplex::Bus> {
 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();

  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const StopRequested>) {
    stop();
  }

  // Pool publishes Voted for every vote of this node before it signs and sends it.
  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const TraceEvent> event) {
    auto voted = dynamic_cast<const simplex::stats::Voted*>(event->event.get());
    if (voted == nullptr) {
      return;
    }
    if (auto notar = std::get_if<simplex::NotarizeVote>(&voted->vote().vote)) {
      std::scoped_lock lock(observations.mutex);
      observations.notarize_votes.push_back(notar->id);
      emit(PSTRING() << "LATE_VOTE notarize " << id_str(notar->id));
    }
  }

  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const simplex::NotarizationObserved> event) {
    std::scoped_lock lock(observations.mutex);
    observations.notarized.push_back(event->id);
  }

  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const simplex::FinalizationObserved> event) {
    std::scoped_lock lock(observations.mutex);
    observations.finalized_slots.push_back(event->id.slot);
  }

  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const MisbehaviorReport>) {
    std::scoped_lock lock(observations.mutex);
    ++observations.misbehavior_reports;
  }
};

// Stands in for the private overlay of a session the peers have already retired: every
// candidate request is answered with an error.
class OverlayStub : public td::actor::SpawnsWith<simplex::Bus>, public td::actor::ConnectsTo<simplex::Bus> {
 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();

  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const StopRequested>) {
    stop();
  }

  template <>
  td::actor::Task<ProtocolMessage> process(simplex::BusHandle, std::shared_ptr<OutgoingOverlayRequest> message) {
    auto request = fetch_tl_object<tos_api::consensus_simplex_requestCandidate>(message->request.data, true);
    if (request.is_ok()) {
      auto id = CandidateId::from_tl(request.ok()->id_);
      std::scoped_lock lock(observations.mutex);
      observations.overlay_requests.push_back(id);
    }
    co_return ProtocolMessage{create_serialize_tl_object<tos_api::consensus_requestError>()};
  }
};

// The records of a database backend. A restarted node opens the same storage again, as a
// validator reopens its consensus database after a restart.
struct MemoryStorage {
  std::mutex mutex;
  std::map<td::BufferSlice, td::BufferSlice> map;

  std::optional<td::BufferSlice> get(td::Slice key) {
    std::scoped_lock lock(mutex);
    auto it = map.find(td::BufferSlice{key});
    if (it == map.end()) {
      return std::nullopt;
    }
    return it->second.clone();
  }
};

class MemoryDb : public consensus::Db {
 public:
  explicit MemoryDb(std::shared_ptr<MemoryStorage> storage) : storage_(std::move(storage)) {
  }

  std::optional<td::BufferSlice> get(td::Slice key) const override {
    return storage_->get(key);
  }

  std::vector<std::pair<td::BufferSlice, td::BufferSlice>> get_by_prefix(td::uint32 prefix) const override {
    std::scoped_lock lock(storage_->mutex);
    std::vector<std::pair<td::BufferSlice, td::BufferSlice>> result;
    td::BufferSlice begin{(const char*)&prefix, 4};
    td::uint32 next_prefix = prefix + 1;
    td::BufferSlice end{(const char*)&next_prefix, 4};
    for (auto it = storage_->map.lower_bound(begin); it != storage_->map.end() && it->first < end; ++it) {
      result.emplace_back(it->first.clone(), it->second.clone());
    }
    return result;
  }

  td::actor::Task<std::optional<td::BufferSlice>> get_latest(td::BufferSlice key) const override {
    co_return get(key.as_slice());
  }

  td::actor::Task<> set(td::BufferSlice key, td::BufferSlice value) override {
    std::scoped_lock lock(storage_->mutex);
    storage_->map[std::move(key)] = std::move(value);
    co_return td::Unit{};
  }

  td::actor::Task<> close() override {
    co_return td::Unit{};
  }

 private:
  std::shared_ptr<MemoryStorage> storage_;
};

// The validator manager: holds the zerostate, validates and accepts every block, and records
// each accepted block.
class RecordingManager : public ManagerFacade {
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
    emit(PSTRING() << "LATE_ACCEPT_BLOCK " << id.to_str());
    std::scoped_lock lock(observations.mutex);
    observations.accepted.push_back(id);
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
  explicit Driver(Mode mode) : mode_(mode) {
  }

  td::actor::Task<> run() {
    auto result = co_await run_inner().wrap();
    if (result.is_error()) {
      finish(1, "LATE_HARNESS_FAILED: " + result.error().to_string());
    }
    co_return td::Unit{};
  }

 private:
  Mode mode_;
  std::vector<std::shared_ptr<const tos::pq::ValidatorPQKeyStore>> signers_;
  std::vector<PeerValidator> validators_;
  // A runtime starts one bus, so a restarted node gets a fresh runtime and fresh actors.
  std::shared_ptr<td::actor::Runtime> runtime_;
  td::actor::ActorOwn<RecordingManager> manager_;
  simplex::BusHandle bus_;
  std::shared_ptr<simplex::Bus> bus_ptr_;
  // Set when the bus is destroyed, which happens only after every actor on it has stopped.
  std::shared_ptr<std::atomic<bool>> bus_destroyed_;
  // The database records; they outlive the bus, so a restarted node reopens them.
  std::shared_ptr<MemoryStorage> storage_ = std::make_shared<MemoryStorage>();
  size_t target_ = 1;

  td::BufferSlice sign(size_t signer, td::Slice inner) const {
    auto envelope =
        create_serialize_tl_object<tos_api::consensus_dataToSign>(bus_ptr_->session_id, td::BufferSlice(inner));
    auto signature =
        signers_.at(signer)->sign_consensus(std::string_view(envelope.as_slice().data(), envelope.as_slice().size()));
    CHECK(signature.has_value());
    return td::BufferSlice(signature->signature);
  }

  // A certificate signed by the three validators other than the node under test.
  template <typename VoteT>
  simplex::CertificateRef<VoteT> make_cert(const VoteT& vote) {
    auto inner = serialize_tl_object(vote.to_tl(), true);
    std::vector<simplex::tl::VoteSignatureRef> signatures;
    for (size_t i = 0; i < VALIDATORS; ++i) {
      if (i != target_) {
        signatures.push_back(
            create_tl_object<simplex::tl::voteSignature>(static_cast<td::int32>(i), sign(i, inner.as_slice())));
      }
    }
    auto set = create_tl_object<simplex::tl::voteSignatureSet>(std::move(signatures));
    auto cert = simplex::Certificate<VoteT>::from_tl(std::move(*set), vote, *bus_ptr_);
    CHECK(cert.is_ok());
    return cert.move_as_ok();
  }

  template <typename VoteT>
  void deliver_cert(const VoteT& vote) {
    auto cert = make_cert(vote);
    const auto& peer = bus_ptr_->validator_set.at(target_ == 0 ? 1 : 0);
    bus_.publish<IncomingProtocolMessage>(peer.idx, peer.adnl_id, ProtocolMessage{cert->serialize()});
  }

  bool db_has(td::BufferSlice key) const {
    return storage_->get(key.as_slice()).has_value();
  }

  bool candidate_persisted(const CandidateId& id) const {
    return db_has(create_serialize_tl_object<tos_api::consensus_simplex_db_key_candidate>(id.to_tl()));
  }

  bool notar_persisted(const CandidateId& id) const {
    return db_has(
        create_serialize_tl_object<tos_api::consensus_simplex_db_key_candidateResolver_notarCert>(id.to_tl()));
  }

  td::actor::Task<> notarize_and_finalize(const CandidateId& id) {
    deliver_cert(simplex::NotarizeVote{id});
    if (!co_await wait_until([&] { return is_notarized(id); })) {
      finish(1, "LATE_PRECONDITION_FAILED: NotarCert " + id_str(id) + " was not installed");
    }
    deliver_cert(simplex::FinalizeVote{id});
    if (!co_await wait_until([&] { return is_finalized(id.slot); })) {
      finish(1, "LATE_PRECONDITION_FAILED: FinalCert " + id_str(id) + " was not installed");
    }
    co_return td::Unit{};
  }

  CandidateRef make_candidate(BlockSeqno seqno, const BlockIdExt& prev, ParentId parent, td::uint32 slot) {
    auto block = make_block(seqno, prev);
    auto id = CandidateHashData::create_full(block, parent).build_id_with(slot);
    auto leader = bus_ptr_->collator_schedule->expected_collator_for(slot);
    auto signature = sign(leader.value(), serialize_tl_object(id.to_tl(), true).as_slice());
    return td::make_ref<Candidate>(id, parent, leader, std::move(block), std::move(signature));
  }

  void deliver_candidate(const CandidateRef& candidate, const std::string& label) {
    emit(PSTRING() << "LATE_DELIVER " << label << " candidate=" << id_str(candidate->id));
    bus_.publish<CandidateReceived>(candidate);
  }

  // Runs both precheck passes the overlay makes for a new broadcast: before and after its
  // signature is checked.
  // A refusal is a value here, not an error of the task: a task that ends in an error would
  // end the scenario instead of letting it check the refusal.
  struct PrecheckResult {
    std::optional<std::string> refusal;

    bool is_ok() const {
      return !refusal.has_value();
    }
    bool is_error() const {
      return refusal.has_value();
    }
    std::string to_string() const {
      return refusal.value_or("ok");
    }
  };

  td::actor::Task<PrecheckResult> precheck(td::uint32 slot, const td::Bits256& broadcast_id) {
    auto before = co_await bus_.publish<PrecheckCandidateBroadcast>(slot, broadcast_id, false).wrap();
    if (before.is_error()) {
      co_return PrecheckResult{before.error().to_string()};
    }
    auto after = co_await bus_.publish<PrecheckCandidateBroadcast>(slot, broadcast_id, true).wrap();
    if (after.is_error()) {
      co_return PrecheckResult{after.error().to_string()};
    }
    co_return PrecheckResult{};
  }

  td::actor::Task<size_t> resolver_entries_in_slot(td::uint32 slot) {
    size_t from_slot = co_await bus_.publish<simplex::QueryResolverTrackedStateCount>(slot);
    size_t after_slot = co_await bus_.publish<simplex::QueryResolverTrackedStateCount>(slot + 1);
    co_return from_slot - after_slot;
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

  td::actor::Task<> settle(double seconds) {
    co_await td::actor::coro_sleep(td::Timestamp::in(seconds));
    co_return td::Unit{};
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
  }

  // Starts the node's bus on a fresh runtime over the shared database records. Without
  // `publish_start` the group stays where a validator is while it syncs: its actors and
  // overlay run, and Start has not arrived.
  void start_node(bool publish_start = true) {
    if (validators_.empty()) {
      make_validators();
    }
    if (manager_.empty()) {
      manager_ = td::actor::create_actor<RecordingManager>("RecordingManager");
    }

    runtime_ = std::make_shared<td::actor::Runtime>();
    runtime_->register_actor<OverlayStub>("PrivateOverlay");
    runtime_->register_actor<ObserverActor>("LateObserver");
    BlockValidator::register_in(*runtime_);
    BlockAccepter::register_in(*runtime_);
    simplex::CandidateResolver::register_in(*runtime_);
    simplex::Consensus::register_in(*runtime_);
    simplex::Pool::register_in(*runtime_);
    simplex::StateResolver::register_in(*runtime_);
    simplex::Db::register_in(*runtime_);
    simplex::DefaultCollatorSchedule::provide_for(*runtime_);

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
    bus->total_weight = static_cast<ValidatorWeight>(validators_.size());
    bus->config = NewConsensusConfig{
        .max_block_size = 1 << 20,
        .max_collated_data_size = 1 << 20,
        .protocol_version = 2,
        .slots_per_leader_window = SLOTS_PER_LEADER_WINDOW,
    };
    // No timeout may turn into a vote of the node's own while the scenario runs.
    bus->config.noncritical_params.first_block_timeout = std::chrono::milliseconds(600'000);
    bus->config.noncritical_params.standstill_timeout = std::chrono::milliseconds(600'000);
    if (mode_ == Mode::ResolverPin) {
      bus->config.noncritical_params.candidate_resolve_cooldown =
          std::chrono::milliseconds(static_cast<td::int64>(PIN_COOLDOWN_SECONDS * 1000));
    }
    bus->session_id = fill(0x42);
    bus->cc_seqno = CC_SEQNO;
    bus->validator_set_hash = 0;
    bus->db = std::make_unique<MemoryDb>(storage_);
    auto destroyed = std::make_shared<std::atomic<bool>>(false);
    bus->stop_promise = td::PromiseCreator::lambda([destroyed](td::Result<td::Unit>) { destroyed->store(true); });
    bus_destroyed_ = destroyed;
    bus_ptr_ = bus;

    bus->pq_signer = signers_.at(target_);
    bus->local_id = validators_.at(target_);
    bus->local_adnl_id = validators_.at(target_).adnl_id;

    bus_ = runtime_->start(std::static_pointer_cast<simplex::Bus>(bus), "late-target");
    if (publish_start) {
      publish_start_event();
    }
  }

  void publish_start_event() {
    bus_.publish<Start>(
        td::make_ref<ChainState>(ChainState::ZerostateTip{FIRST_PARENT, gen_shard_state(0)}, MIN_MC_BLOCK_ID));
  }

  // Stops the node and waits until its bus, and with it every actor, is gone. Only then are
  // the observations cleared, so nothing the old actors report reaches the next run.
  td::actor::Task<> stop_node() {
    auto destroyed = bus_destroyed_;
    bus_.publish<StopRequested>();
    bus_ = {};
    bus_ptr_.reset();
    if (!co_await wait_until([&] { return destroyed->load(); })) {
      finish(1, "LATE_PRECONDITION_FAILED: the stopped node's bus was never released");
    }
    runtime_.reset();
    std::scoped_lock lock(observations.mutex);
    observations.notarize_votes.clear();
    observations.notarized.clear();
    observations.finalized_slots.clear();
    observations.overlay_requests.clear();
    observations.accepted.clear();
    observations.misbehavior_reports = 0;
    co_return td::Unit{};
  }

  td::actor::Task<> run_inner() {
    if (mode_ == Mode::RestartBeforeStart) {
      co_return co_await run_restart_before_start();
    }
    start_node();
    auto leader0 = bus_ptr_->collator_schedule->expected_collator_for(0);
    if (leader0.value() == target_) {
      finish(1, "LATE_PRECONDITION_FAILED: the node under test leads window 0");
    }

    // Chain: X (slot 0, genesis) <- Y (slot 1) <- Z (slot 2); alternatives signed by the same
    // leaders.
    auto X = make_candidate(1, FIRST_PARENT, std::nullopt, 0);
    auto X_alt = make_candidate(2, FIRST_PARENT, std::nullopt, 0);
    auto Y = make_candidate(2, X->block_id(), X->id, 1);
    auto Y_alt = make_candidate(3, X->block_id(), X->id, 1);
    auto Z = make_candidate(3, Y->block_id(), Y->id, 2);

    switch (mode_) {
      case Mode::LateAfterPrecheck:
      case Mode::LateBeforePrecheck:
      case Mode::AfterRoundBudget:
        co_return co_await run_late_apply(X);
      case Mode::OutsideWindow:
        co_return co_await run_outside_window(X_alt, Y, Y_alt);
      case Mode::LateDedupBound:
        co_return co_await run_dedup_bound(X, Y);
      case Mode::ResolverPin:
        co_return co_await run_resolver_pin(X, Y);
      case Mode::ResolverPinError:
        co_return co_await run_resolver_pin_error(X_alt, Y);
      case Mode::FrontierSkew:
        co_return co_await run_frontier_skew(X_alt, Y, Y_alt, Z);
      case Mode::RestartBeforeStart:
        // Starts and restarts its own node; it is dispatched before this one is started.
        finish(1, "LATE_HARNESS_FAILED: restart-before-start reached the single-start path");
    }
    co_return td::Unit{};
  }

  // A validator restarts while its consensus database holds FinalCerts beyond the leader-window
  // gate. Until Start its leader window is not announced, yet Pool replays the FinalCerts and
  // admits broadcasts for the finalized slots; their candidates must reach the candidate
  // resolver. The chain is W <- X, both finalized, and Fut extends X in the next slot.
  td::actor::Task<> run_restart_before_start() {
    // The production parameters, as the node under test runs with them.
    const NewConsensusConfig::NoncriticalParams params{};
    // The first slot the consensus actor calls too new while its window is still 0.
    const td::uint32 gate = (params.max_leader_window_desync + 1) * SLOTS_PER_LEADER_WINDOW;
    const td::uint32 w_slot = gate / 2;
    const td::uint32 x_slot = gate + 1;
    const td::uint32 fut_slot = x_slot + 1;
    // Pool takes a certificate only below its own gate, which W's finalization moves.
    const td::uint32 pool_gate_after_w =
        (w_slot / SLOTS_PER_LEADER_WINDOW + 1 + params.max_leader_window_desync + 1) * SLOTS_PER_LEADER_WINDOW;
    if (!(w_slot < gate && x_slot >= gate && x_slot < pool_gate_after_w)) {
      finish(1, "LATE_PRECONDITION_FAILED: the slots do not straddle the too-new gate");
    }

    // First run: the certificates reach the database, and the candidates never arrive.
    start_node(/*publish_start=*/false);
    auto W = make_candidate(1, FIRST_PARENT, std::nullopt, w_slot);
    auto X = make_candidate(2, W->block_id(), W->id, x_slot);
    auto Fut = make_candidate(3, X->block_id(), X->id, fut_slot);
    co_await notarize_and_finalize(W->id);
    co_await notarize_and_finalize(X->id);
    // Pool publishes FinalizationObserved only after SaveCertificate returned.
    co_await stop_node();
    if (candidate_persisted(W->id) || candidate_persisted(X->id)) {
      finish(1, "LATE_PRECONDITION_FAILED: a candidate was persisted before it was delivered");
    }

    // The restart: the same database, a fresh runtime, and no Start.
    start_node(/*publish_start=*/false);
    if (!co_await wait_until([&] { return is_finalized(x_slot); })) {
      finish(1, "LATE_PRECONDITION_FAILED: the stored FinalCert was not replayed at startup");
    }
    if (!co_await wait_until([&] { return overlay_requests_for(X->id) >= 1; })) {
      finish(1, "LATE_PRECONDITION_FAILED: the finalized candidate was never requested from peers");
    }
    auto recovery = co_await bus_.publish<simplex::QueryConsensusRecoveryState>();
    if (recovery.current_window != 0) {
      finish(1, PSTRING() << "LATE_PRECONDITION_FAILED: the leader window is already " << recovery.current_window);
    }
    struct Broadcast {
      const char* label;
      td::uint32 slot;
      unsigned char id_byte;
    };
    const Broadcast broadcasts[] = {{"W", w_slot, 0xf1}, {"X", x_slot, 0xf2}, {"Fut", fut_slot, 0xf3}};
    for (const auto& broadcast : broadcasts) {
      auto status = co_await precheck(broadcast.slot, fill(broadcast.id_byte));
      if (status.is_error()) {
        finish(1, PSTRING() << "LATE_PRECONDITION_FAILED: Pool refused the broadcast for " << broadcast.label << ": "
                            << status.to_string());
      }
    }
    if (accepted_count(W) != 0 || accepted_count(X) != 0) {
      finish(1, "LATE_PRECONDITION_FAILED: a block was applied before its candidate arrived");
    }

    deliver_candidate(Fut, "not-finalized");
    deliver_candidate(W, "finalized-below-gate");
    deliver_candidate(X, "finalized-beyond-gate");
    // W lies below the gate, so even without the fix it is stored: the late path runs here.
    if (!co_await wait_until([&] { return candidate_persisted(W->id); })) {
      finish(1, "LATE_PRECONDITION_FAILED: the candidate below the gate was not stored before Start");
    }
    bool stored = co_await wait_until([&] { return candidate_persisted(X->id); });
    emit(PSTRING() << "LATE_RESULT before_start stored W=" << candidate_persisted(W->id) << " X=" << stored);
    if (!stored) {
      finish(3, "LATE_RESTART_DROPPED: a finalized candidate was dropped before Start");
    }
    co_await settle(0.5);
    auto votes = [&] { return notarize_votes_for(W->id) + notarize_votes_for(X->id) + notarize_votes_for(Fut->id); };
    emit(PSTRING() << "LATE_RESULT before_start Fut_persisted=" << candidate_persisted(Fut->id)
                   << " notarize_votes=" << votes() << " misbehavior_reports=" << misbehavior_reports());
    if (candidate_persisted(Fut->id)) {
      finish(4, "LATE_SCOPE_FAILED: a candidate for a slot that is not finalized passed the gate before Start");
    }
    if (votes() != 0 || misbehavior_reports() != 0) {
      finish(4, "LATE_VOTED: a finalized candidate must only be stored");
    }

    publish_start_event();
    bool applied = co_await wait_until([&] { return accepted_count(W) >= 1 && accepted_count(X) >= 1; });
    emit(PSTRING() << "LATE_RESULT applied W=" << accepted_count(W) << " X=" << accepted_count(X));
    if (!applied) {
      finish(3, "LATE_NOT_APPLIED: the finalized blocks were not applied from the stored candidates");
    }
    co_await settle(0.5);
    if (candidate_persisted(Fut->id) || votes() != 0 || misbehavior_reports() != 0) {
      finish(4, "LATE_VOTED: the run voted or reported after Start");
    }
    finish(0, "LATE_RESTART_OK");
  }

  td::actor::Task<> run_late_apply(CandidateRef X) {
    const td::Bits256 broadcast_id = fill(0xb1);
    if (mode_ == Mode::LateAfterPrecheck) {
      auto status = co_await precheck(X->id.slot, broadcast_id);
      if (status.is_error()) {
        finish(1, "LATE_PRECONDITION_FAILED: precheck before finalization: " + status.to_string());
      }
    }

    co_await notarize_and_finalize(X->id);
    // The node does not hold the candidate and no peer serves it.
    const size_t rounds = mode_ == Mode::AfterRoundBudget ? 2 : 1;
    if (!co_await wait_until([&] { return overlay_requests_for(X->id) >= rounds; })) {
      finish(1, "LATE_PRECONDITION_FAILED: the finalized candidate was never requested from peers");
    }
    if (accepted_count(X) != 0) {
      finish(1, "LATE_PRECONDITION_FAILED: the block was applied before its candidate arrived");
    }

    if (mode_ == Mode::LateBeforePrecheck) {
      auto status = co_await precheck(X->id.slot, broadcast_id);
      if (status.is_error()) {
        finish(3, "LATE_PRECHECK_REFUSED: a broadcast for a finalized slot in the window was refused: " +
                      status.to_string());
      }
    }

    deliver_candidate(X, "late");
    bool applied = co_await wait_until([&] { return accepted_count(X) >= 1; });
    emit(PSTRING() << "LATE_RESULT applied=" << applied << " overlay_requests=" << overlay_requests_for(X->id)
                   << " notarize_votes=" << notarize_votes_for(X->id)
                   << " misbehavior_reports=" << misbehavior_reports());
    if (!applied) {
      finish(3, "LATE_NOT_APPLIED: the late candidate never reached the resolver");
    }
    if (notarize_votes_for(X->id) != 0 || misbehavior_reports() != 0) {
      finish(4, "LATE_VOTED: a late candidate must only be stored");
    }
    finish(0, "LATE_APPLIED_OK");
  }

  td::actor::Task<> run_outside_window(CandidateRef X_alt, CandidateRef Y, CandidateRef Y_alt) {
    // A one-slot window: once slot 1 is finalized, slot 1 is inside it and slot 0 is not.
    co_await notarize_and_finalize(Y->id);

    auto refused = co_await precheck(0, fill(0xc0));
    auto admitted = co_await precheck(1, fill(0xc1));
    emit(PSTRING() << "LATE_PRECHECK slot0=" << (refused.is_ok() ? "ok" : refused.to_string())
                   << " slot1=" << (admitted.is_ok() ? "ok" : admitted.to_string()));
    if (admitted.is_error()) {
      finish(1, "LATE_PRECONDITION_FAILED: a broadcast inside the window was refused");
    }
    if (refused.is_ok()) {
      finish(3, "LATE_WINDOW_FAILED: a broadcast for a slot outside the window was admitted");
    }

    co_await expect_stored_only_inside(X_alt, Y_alt);
    finish(0, "LATE_WINDOW_OK");
  }

  // Delivers a candidate for a slot outside Consensus's window and then one inside it. The
  // resolver erases an evictable entry outside its window as soon as the store ends, so what
  // is observed is the persisted candidate, not a resolver entry. The candidate inside the
  // window must be persisted before the absence of the other one counts for anything.
  td::actor::Task<> expect_stored_only_inside(CandidateRef outside, CandidateRef inside) {
    if (candidate_persisted(outside->id) || candidate_persisted(inside->id)) {
      finish(1, "LATE_PRECONDITION_FAILED: a candidate was persisted before it was delivered");
    }
    deliver_candidate(outside, "outside-window");
    deliver_candidate(inside, "inside-window");
    if (!co_await wait_until([&] { return candidate_persisted(inside->id); })) {
      finish(1, "LATE_PRECONDITION_FAILED: a late candidate inside the window was not stored");
    }
    co_await settle(0.5);
    emit(PSTRING() << "LATE_RESULT persisted outside=" << candidate_persisted(outside->id)
                   << " inside=" << candidate_persisted(inside->id));
    if (candidate_persisted(outside->id)) {
      finish(3, "LATE_WINDOW_FAILED: a candidate for a slot outside the window was stored");
    }
    co_return td::Unit{};
  }

  // Pool's finalization frontier lags the one Consensus and the resolver act on. Each actor
  // applies its own window: Pool still admits the broadcast for slot 0, Consensus does not
  // store its candidate. When Pool catches up, it refuses the broadcast too.
  td::actor::Task<> run_frontier_skew(CandidateRef X_alt, CandidateRef Y, CandidateRef Y_alt, CandidateRef Z) {
    // Only Consensus, the resolver and the Db actor see this finalization; Pool learns of a
    // finalization from the certificate itself, which it has not received.
    bus_.publish<simplex::FinalizationObserved>(Y->id, make_cert(simplex::FinalizeVote{Y->id}));

    auto pool_behind = co_await precheck(0, fill(0xe0));
    emit(PSTRING() << "LATE_PRECHECK pool_behind slot0=" << pool_behind.to_string());
    if (pool_behind.is_error()) {
      finish(1, "LATE_PRECONDITION_FAILED: Pool refused slot 0 before it saw any finalization");
    }
    co_await expect_stored_only_inside(X_alt, Y_alt);

    // Pool catches up through a later slot: the Db actor has already pruned slot 1 on the
    // event above and would refuse to save its certificate a second time.
    co_await notarize_and_finalize(Z->id);
    bool pool_refuses = false;
    auto deadline = td::Timestamp::in(STEP_TIMEOUT);
    while (!deadline.is_in_past()) {
      // The same broadcast as before, so a refusal cannot come from the duplicate filter.
      if ((co_await precheck(0, fill(0xe0))).is_error()) {
        pool_refuses = true;
        break;
      }
      co_await td::actor::coro_sleep(td::Timestamp::in(0.01));
    }
    emit(PSTRING() << "LATE_PRECHECK pool_caught_up refuses_slot0=" << pool_refuses);
    if (!pool_refuses) {
      finish(3, "LATE_WINDOW_FAILED: Pool still admits slot 0 after it saw the finalization");
    }
    finish(0, "LATE_SKEW_OK");
  }

  // A resolve that fails must release the task's pin as well: the entry for an id nothing
  // else holds is erased once the failed task ends.
  td::actor::Task<> run_resolver_pin_error(CandidateRef X_alt, CandidateRef Y) {
    // Move the one-slot window past slot 0 first, so the entry is evictable the moment no
    // operation holds it.
    co_await notarize_and_finalize(Y->id);
    auto resolved = co_await bus_.publish<simplex::ResolveCandidate>(X_alt->id).wrap();
    emit(PSTRING() << "LATE_PIN resolve " << (resolved.is_ok() ? "ok" : resolved.error().to_string()));
    if (resolved.is_ok() || overlay_requests_for(X_alt->id) == 0) {
      finish(1, "LATE_PRECONDITION_FAILED: the resolve did not fail after asking a peer");
    }
    bool released = false;
    auto deadline = td::Timestamp::in(STEP_TIMEOUT);
    while (!deadline.is_in_past()) {
      if (co_await resolver_entries_in_slot(0) == 0) {
        released = true;
        break;
      }
      co_await td::actor::coro_sleep(td::Timestamp::in(0.05));
    }
    emit(PSTRING() << "LATE_PIN released_after_failed_task=" << released);
    if (!released) {
      finish(4, "LATE_PIN_LEAKED: a failed resolve task kept its entry");
    }
    finish(0, "LATE_PIN_ERROR_OK");
  }

  td::actor::Task<> run_dedup_bound(CandidateRef X, CandidateRef Y) {
    const td::Bits256 first = fill(0xd1);
    const td::Bits256 second = fill(0xd2);
    co_await notarize_and_finalize(X->id);
    auto first_status = co_await precheck(0, first);
    if (first_status.is_error()) {
      finish(1, "LATE_PRECONDITION_FAILED: the first late broadcast was refused: " + first_status.to_string());
    }
    auto second_status = co_await precheck(0, second);
    if (second_status.is_ok()) {
      finish(3, "LATE_DEDUP_FAILED: a second broadcast for the same finalized slot was admitted");
    }

    co_await notarize_and_finalize(Y->id);
    auto second_after = co_await precheck(0, second);
    auto first_after = co_await precheck(0, first);
    emit(PSTRING() << "LATE_RESULT after a later finalization: second="
                   << (second_after.is_ok() ? "ok" : second_after.to_string())
                   << " first=" << (first_after.is_ok() ? "ok" : first_after.to_string()));
    if (second_after.is_ok()) {
      finish(3, "LATE_DEDUP_FAILED: a later finalization reopened the slot to a second broadcast");
    }
    if (first_after.is_error()) {
      finish(1, "LATE_PRECONDITION_FAILED: the first broadcast is no longer admitted inside the window");
    }
    finish(0, "LATE_DEDUP_OK");
  }

  td::actor::Task<> run_resolver_pin(CandidateRef X, CandidateRef Y) {
    co_await notarize_and_finalize(X->id);
    if (!co_await wait_until([&] { return overlay_requests_for(X->id) >= 1; })) {
      finish(1, "LATE_PRECONDITION_FAILED: the resolver never asked a peer for X");
    }
    // The refusal is answered at once, so the resolve task is now asleep for the cooldown.
    auto task_wakes = td::Timestamp::in(PIN_COOLDOWN_SECONDS);

    // A store completes the entry and resumes the waiting finalization.
    co_await bus_.publish<simplex::StoreCandidate>(X);
    if (!co_await wait_until([&] { return accepted_count(X) >= 1; })) {
      finish(1, "LATE_PRECONDITION_FAILED: X was not applied after it was stored");
    }
    // Every other condition that keeps the entry must be gone before the window moves, so
    // that only the task's pin can keep it: both records are durable, the store returned
    // (it was awaited above) and the finalization that waited on the resolve has applied X.
    if (!co_await wait_until([&] { return candidate_persisted(X->id) && notar_persisted(X->id); })) {
      finish(1, "LATE_PRECONDITION_FAILED: X's candidate or NotarCert was not persisted");
    }
    // Finalizing slot 1 moves the one-slot window past slot 0.
    co_await notarize_and_finalize(Y->id);
    size_t entries_while_asleep = co_await resolver_entries_in_slot(0);
    bool measured_in_time = !task_wakes.is_in_past();
    emit(PSTRING() << "LATE_PIN entries_while_task_asleep=" << entries_while_asleep
                   << " measured_before_wake=" << measured_in_time);
    if (!measured_in_time) {
      finish(1, "LATE_PRECONDITION_FAILED: the steps outlasted the resolve task's cooldown");
    }
    if (entries_while_asleep != 1) {
      finish(3, "LATE_PIN_FAILED: the entry was evicted while the resolve task still held it");
    }

    co_await td::actor::coro_sleep(task_wakes);
    bool released = false;
    auto deadline = td::Timestamp::in(STEP_TIMEOUT);
    while (!deadline.is_in_past()) {
      if (co_await resolver_entries_in_slot(0) == 0) {
        released = true;
        break;
      }
      co_await td::actor::coro_sleep(td::Timestamp::in(0.05));
    }
    emit(PSTRING() << "LATE_PIN released_after_task=" << released);
    if (!released) {
      finish(4, "LATE_PIN_LEAKED: the entry outlived the resolve task");
    }
    finish(0, "LATE_PIN_OK");
  }
};

int check_window_helper() {
  int failures = 0;
  for (td::uint32 retained : {1u, 2u, 4096u}) {
    std::vector<td::uint32> inputs{0, retained - 1, retained, retained + 1, std::numeric_limits<td::uint32>::max()};
    for (td::uint32 first_nonfinalized : inputs) {
      simplex::CandidateRetentionPolicy policy{retained};
      if (first_nonfinalized > 0) {
        policy.observe_finalized(first_nonfinalized - 1);
      }
      td::uint32 expected = policy.first_retained_slot();
      td::uint32 actual = simplex::late_window_begin(first_nonfinalized, retained);
      if (expected != actual) {
        emit(PSTRING() << "LATE_HELPER_MISMATCH retained=" << retained << " first_nonfinalized=" << first_nonfinalized
                       << " policy=" << expected << " helper=" << actual);
        ++failures;
      }
    }
  }

  // Consensus and the resolver apply their frontiers independently. With R=4 and Consensus at
  // first_nonfinalized=10, Consensus admits slot 6, the lowest slot of its window.
  constexpr td::uint32 retained = 4;
  const td::uint32 admitted_slot = simplex::late_window_begin(10, retained);
  const CandidateId admitted{admitted_slot, {}};
  auto evictable = [](int) { return true; };
  auto check = [&](bool condition, const char* what) {
    if (!condition) {
      emit(PSTRING() << "LATE_HELPER_ORDERING_FAILED " << what);
      ++failures;
    }
  };
  check(admitted_slot == 6, "Consensus admits slot 6 at first_nonfinalized=10");
  {
    // The resolver is behind (latest finalized 7): the entry is inside its window, so it
    // stays until the resolver's own frontier passes it.
    simplex::CandidateRetentionPolicy behind{retained};
    behind.observe_finalized(7);
    std::map<CandidateId, int> states{{admitted, 0}};
    check(!behind.is_before_retained_window(admitted), "a lagging resolver retains the admitted entry");
    check(simplex::prune_candidate_states(states, behind.first_retained_slot(), evictable) == 0,
          "a lagging resolver does not prune the admitted entry");
    behind.observe_finalized(10);
    check(simplex::prune_candidate_states(states, behind.first_retained_slot(), evictable) == 1,
          "the entry is pruned once the resolver's frontier passes it");
  }
  {
    // The resolver is ahead (latest finalized 13): the admitted slot is already below its
    // window, so the entry is erased when the store's operation ends.
    simplex::CandidateRetentionPolicy ahead{retained};
    ahead.observe_finalized(13);
    check(ahead.is_before_retained_window(admitted), "a leading resolver treats the entry as evictable");
  }

  emit(failures == 0 ? "LATE_HELPER_OK" : "LATE_HELPER_FAILED");
  return failures == 0 ? 0 : 3;
}

struct ModeSpec {
  const char* name;
  std::optional<Mode> mode;
  const char* retention_slots;
  const char* resolve_attempts;
};

const ModeSpec MODES[] = {
    {"late-after-precheck", Mode::LateAfterPrecheck, nullptr, nullptr},
    {"late-before-precheck", Mode::LateBeforePrecheck, nullptr, nullptr},
    {"after-round-budget", Mode::AfterRoundBudget, nullptr, "1"},
    {"outside-window", Mode::OutsideWindow, "1", nullptr},
    {"late-dedup-bound", Mode::LateDedupBound, nullptr, nullptr},
    {"resolver-pin", Mode::ResolverPin, "1", nullptr},
    {"resolver-pin-error", Mode::ResolverPinError, "1", "1"},
    {"frontier-skew", Mode::FrontierSkew, "1", nullptr},
    {"restart-before-start", Mode::RestartBeforeStart, nullptr, nullptr},
    {"window-helper", std::nullopt, nullptr, nullptr},
};

int run_mode(const ModeSpec& spec) {
  if (spec.retention_slots != nullptr) {
    setenv("TOS_SIMPLEX_CANDIDATE_RETENTION_SLOTS", spec.retention_slots, 1);
  }
  if (spec.resolve_attempts != nullptr) {
    setenv("TOS_SIMPLEX_CANDIDATE_RESOLVE_MAX_ATTEMPTS", spec.resolve_attempts, 1);
  }
  if (!spec.mode.has_value()) {
    return check_window_helper();
  }
  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<Driver> driver;
  scheduler.run_in_context([&] {
    driver = td::actor::create_actor<Driver>("late-driver", *spec.mode);
    td::actor::ask(driver, &Driver::run).detach();
  });
  while (scheduler.run(1)) {
  }
  // The driver ends the process with its verdict; reaching here means it never gave one.
  return 1;
}

}  // namespace

int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(verbosity_WARNING);
  if (argc > 2) {
    std::fprintf(stderr, "usage: %s [mode]\n", argv[0]);
    return 2;
  }
  if (argc == 2) {
    for (const auto& spec : MODES) {
      if (std::strcmp(spec.name, argv[1]) == 0) {
        return run_mode(spec);
      }
    }
    std::fprintf(stderr, "unknown mode %s\n", argv[1]);
    return 2;
  }

  // Each mode needs fresh actors and its own environment, so each runs in a child process.
  int failed = 0;
  for (const auto& spec : MODES) {
    std::fflush(stdout);
    std::fflush(stderr);
    pid_t pid = fork();
    if (pid < 0) {
      std::perror("fork");
      return 1;
    }
    if (pid == 0) {
      std::_Exit(run_mode(spec));
    }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) {
      std::perror("waitpid");
      return 1;
    }
    bool ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    std::printf("LATE_MODE %s %s (status %d)\n", spec.name, ok ? "PASS" : "FAIL", status);
    std::fflush(stdout);
    failed += ok ? 0 : 1;
  }
  std::printf("LATE_SUMMARY %d of %zu modes failed\n", failed, std::size(MODES));
  return failed == 0 ? 0 : 1;
}
