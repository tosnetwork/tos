/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
// Actor-level regression: after StateResolver exhausts its own three origin-read attempts,
// can Consensus recover a slot's notarize vote without losing the pending candidate?
//
// One validator node runs the production Consensus, Pool, CandidateResolver, StateResolver,
// BlockValidator and Db actors. The only stand-ins are the validator manager (whose answers
// the test controls), the private overlay and the database backend. Candidates are published
// as CandidateReceived, exactly as the candidate resolver publishes them.
//
// Consensus records a candidate as the slot's pending block before try_notarize() resolves
// its parent state; a second delivery of the same candidate returns early because a pending
// block exists. Modes:
//
//   control           no fault: the candidate is validated and voted once; a re-delivery
//                     casts nothing more.
//   genesis-notready  three genesis reads after arming answer notready / timeout, so
//   genesis-timeout   StateResolver fails ResolveState(genesis) inside try_notarize();
//                     the manager then recovers.
//   ancestor-notready a candidate before the fault is voted normally; the next candidate's
//                     parent is notarized but its data is not held locally and every peer
//                     refuses it, so the candidate resolver gives up with `notready` and
//                     ResolveState(parent) fails; the parent data then arrives.
//
// Permanent/cancelled, a SkipVote cast before recovery and a second signed proposal
// during retry are negative controls. The candidate remains pending for V-019 proof.

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "auto/tl/tos_api.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "consensus/simplex/bus.h"
#include "consensus/simplex/certificate.h"
#include "consensus/simplex/misbehavior.h"
#include "consensus/simplex/stats.h"
#include "consensus/simplex/votes.h"
#include "consensus/utils.h"
#include "crypto/pq/consensus-pq-signer.h"
#include "td/actor/BusRuntime.h"
#include "td/actor/coro_utils.h"
#include "tos/quorum.h"
#include "vm/boc.h"

#include "block-auto.h"

using namespace tos;
using namespace tos::validator;
using namespace tos::validator::consensus;

namespace {

constexpr td::uint32 SLOTS_PER_LEADER_WINDOW = 4;
constexpr size_t VALIDATORS = 4;
constexpr double STEP_TIMEOUT = 10.0;
// How long a candidate is given to be voted once nothing more is pending.
constexpr double SETTLE = 2.0;

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
  Control,
  GenesisNotready,
  GenesisTimeout,
  AncestorNotready,
  Permanent,
  Cancelled,
  SkipBeforeRecovery,
  ConflictDuringRetry,
  ConflictingCertDuringRetry,
};

// ===== What the test observes =====

struct Observations {
  std::mutex mutex;
  std::vector<CandidateId> notarize_votes;
  std::vector<CandidateId> emitted_notarize_votes;
  std::vector<CandidateId> finalize_votes;
  std::vector<td::uint32> skip_votes;
  std::vector<BlockIdExt> validations;
  std::vector<CandidateId> notarized;
  std::vector<CandidateId> overlay_requests;
  size_t misbehavior_reports = 0;
  size_t manager_state_reads = 0;
  size_t manager_faults = 0;
};

Observations observations;

// Number of genesis-state reads still to fail, and with which code.
std::atomic<int> faults_remaining{0};
std::atomic<int> fault_code{ErrorCode::notready};
std::atomic<bool> refuse_overlay_requests{false};

size_t count_of(const std::vector<CandidateId>& list, const CandidateId& id) {
  size_t n = 0;
  for (const auto& entry : list) {
    n += entry == id;
  }
  return n;
}

size_t notarize_votes_for(const CandidateId& id) {
  std::scoped_lock lock(observations.mutex);
  return count_of(observations.notarize_votes, id);
}

size_t emitted_notarize_votes_for(const CandidateId& id) {
  std::scoped_lock lock(observations.mutex);
  return count_of(observations.emitted_notarize_votes, id);
}

size_t finalize_votes_for(const CandidateId& id) {
  std::scoped_lock lock(observations.mutex);
  return count_of(observations.finalize_votes, id);
}

size_t skip_votes_for(td::uint32 slot) {
  std::scoped_lock lock(observations.mutex);
  return static_cast<size_t>(std::count(observations.skip_votes.begin(), observations.skip_votes.end(), slot));
}

size_t manager_state_reads() {
  std::scoped_lock lock(observations.mutex);
  return observations.manager_state_reads;
}

size_t misbehavior_reports() {
  std::scoped_lock lock(observations.mutex);
  return observations.misbehavior_reports;
}

size_t validations_of(const CandidateRef& candidate) {
  std::scoped_lock lock(observations.mutex);
  size_t n = 0;
  for (const auto& block : observations.validations) {
    n += block == candidate->block_id();
  }
  return n;
}

bool is_notarized(const CandidateId& id) {
  std::scoped_lock lock(observations.mutex);
  return count_of(observations.notarized, id) > 0;
}

size_t overlay_requests_for(const CandidateId& id) {
  std::scoped_lock lock(observations.mutex);
  return count_of(observations.overlay_requests, id);
}

size_t manager_faults() {
  std::scoped_lock lock(observations.mutex);
  return observations.manager_faults;
}

void report_counts(const std::string& label) {
  std::scoped_lock lock(observations.mutex);
  emit(PSTRING() << "C09_COUNTS " << label << " notarize_votes=" << observations.notarize_votes.size()
                 << " emitted_signed_notarize=" << observations.emitted_notarize_votes.size()
                 << " finalize_votes=" << observations.finalize_votes.size()
                 << " skip_votes=" << observations.skip_votes.size()
                 << " validations=" << observations.validations.size()
                 << " manager_state_reads=" << observations.manager_state_reads
                 << " manager_faults=" << observations.manager_faults
                 << " misbehavior_reports=" << observations.misbehavior_reports);
}

class ObserverActor : public td::actor::SpawnsWith<simplex::Bus>, public td::actor::ConnectsTo<simplex::Bus> {
 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();

  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const StopRequested>) {
    stop();
  }

  // Pool publishes Voted for every vote of this node before it persists, signs and sends it.
  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const TraceEvent> event) {
    auto voted = dynamic_cast<const simplex::stats::Voted*>(event->event.get());
    if (voted == nullptr) {
      return;
    }
    const auto& vote = voted->vote().vote;
    std::scoped_lock lock(observations.mutex);
    if (auto notar = std::get_if<simplex::NotarizeVote>(&vote)) {
      observations.notarize_votes.push_back(notar->id);
      emit(PSTRING() << "C09_VOTE notarize " << id_str(notar->id));
    } else if (auto final_vote = std::get_if<simplex::FinalizeVote>(&vote)) {
      observations.finalize_votes.push_back(final_vote->id);
      emit(PSTRING() << "C09_VOTE finalize " << id_str(final_vote->id));
    } else if (auto skip = std::get_if<simplex::SkipVote>(&vote)) {
      observations.skip_votes.push_back(skip->slot);
      emit(PSTRING() << "C09_VOTE skip slot=" << skip->slot);
    }
  }

  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const simplex::NotarizationObserved> event) {
    std::scoped_lock lock(observations.mutex);
    observations.notarized.push_back(event->id);
  }

  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const MisbehaviorReport> event) {
    if (dynamic_cast<const simplex::ConflictingCandidates*>(event->proof.get()) == nullptr) {
      return;
    }
    std::scoped_lock lock(observations.mutex);
    ++observations.misbehavior_reports;
    emit("C05_V019_CONFLICTING_CANDIDATES");
    emit("C09_MISBEHAVIOR_REPORT");
  }
};

// Stands in for the private overlay. Nothing is broadcast; candidate requests are recorded
// and refused while `refuse_overlay_requests` is set, otherwise left to time out.
class OverlayStub : public td::actor::SpawnsWith<simplex::Bus>, public td::actor::ConnectsTo<simplex::Bus> {
 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();

  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const StopRequested>) {
    stop();
  }

  template <>
  void handle(simplex::BusHandle bus, std::shared_ptr<const OutgoingProtocolMessage> message) {
    if (!std::holds_alternative<OutgoingProtocolMessage::BroadcastToAll>(message->recipient)) {
      return;
    }
    auto signed_vote = simplex::Signed<simplex::Vote>::deserialize(message->message.data.as_slice(),
                                                                     bus->local_id->idx, *bus);
    if (signed_vote.is_error()) {
      return;
    }
    if (auto notar = std::get_if<simplex::NotarizeVote>(&signed_vote.ok().vote.vote)) {
      std::scoped_lock lock(observations.mutex);
      observations.emitted_notarize_votes.push_back(notar->id);
      emit(PSTRING() << "C05_EMITTED_SIGNED_NOTARIZE " << id_str(notar->id));
    }
  }

  template <>
  td::actor::Task<ProtocolMessage> process(simplex::BusHandle, std::shared_ptr<OutgoingOverlayRequest> message) {
    auto request = fetch_tl_object<tos_api::consensus_simplex_requestCandidate>(message->request.data, true);
    if (request.is_ok()) {
      auto id = CandidateId::from_tl(request.ok()->id_);
      emit(PSTRING() << "C09_OVERLAY_REQUEST id=" << id_str(id));
      std::scoped_lock lock(observations.mutex);
      observations.overlay_requests.push_back(id);
    }
    if (refuse_overlay_requests.load()) {
      co_return ProtocolMessage{create_serialize_tl_object<tos_api::consensus_requestError>()};
    }
    co_await td::actor::coro_sleep(message->timeout);
    co_return td::Status::Error(ErrorCode::timeout, "no peer answered");
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

// The validator manager: holds the zerostate, accepts every block, and fails the next
// `faults_remaining` genesis-state reads with `fault_code`.
class ControlledManager : public ManagerFacade {
 public:
  td::actor::Task<GeneratedCandidate> collate_block(CollateParams, td::CancellationToken) override {
    co_return td::Status::Error("this node does not collate");
  }

  td::actor::Task<ValidateCandidateResult> validate_block_candidate(BlockCandidate candidate, ValidateParams,
                                                                    td::Timestamp) override {
    emit(PSTRING() << "C09_MANAGER_VALIDATE block=" << candidate.id.to_str());
    {
      std::scoped_lock lock(observations.mutex);
      observations.validations.push_back(candidate.id);
    }
    co_return CandidateAccept{};
  }

  td::actor::Task<> accept_block(BlockIdExt, td::Ref<BlockData>, size_t, td::Ref<block::BlockSignatureSet>,
                                 ValidatorSessionId, int, int, bool, bool) override {
    co_return td::Unit{};
  }

  td::actor::Task<td::Ref<vm::Cell>> wait_block_state_root(BlockIdExt block_id, td::Timestamp) override {
    size_t call;
    {
      std::scoped_lock lock(observations.mutex);
      call = ++observations.manager_state_reads;
    }
    if (block_id != FIRST_PARENT) {
      emit(PSTRING() << "C09_MANAGER_STATE_READ call=" << call << " block=" << block_id.to_str() << " -> notready");
      co_return td::Status::Error(ErrorCode::notready, "only the zerostate is available");
    }
    if (faults_remaining.fetch_sub(1) > 0) {
      int code = fault_code.load();
      {
        std::scoped_lock lock(observations.mutex);
        ++observations.manager_faults;
      }
      emit(PSTRING() << "C09_MANAGER_STATE_READ call=" << call << " genesis -> injected code=" << code);
      co_return td::Status::Error(code, "injected manager failure");
    }
    faults_remaining.store(0);
    emit(PSTRING() << "C09_MANAGER_STATE_READ call=" << call << " genesis -> ok");
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
      finish(1, "C09_HARNESS_FAILED: " + result.error().to_string());
    }
    co_return td::Unit{};
  }

 private:
  Mode mode_;
  std::vector<std::shared_ptr<const tos::pq::ValidatorPQKeyStore>> signers_;
  td::actor::Runtime runtime_;
  td::actor::ActorOwn<ControlledManager> manager_;
  simplex::BusHandle bus_;
  std::shared_ptr<simplex::Bus> bus_ptr_;
  size_t target_ = 0;

  td::BufferSlice sign(size_t signer, td::Slice inner) const {
    auto envelope =
        create_serialize_tl_object<tos_api::consensus_dataToSign>(bus_ptr_->session_id, td::BufferSlice(inner));
    auto signature =
        signers_.at(signer)->sign_consensus(std::string_view(envelope.as_slice().data(), envelope.as_slice().size()));
    CHECK(signature.has_value());
    return td::BufferSlice(signature->signature);
  }

  // A notarization certificate signed by the three validators other than the node under test.
  void deliver_notar_cert(const CandidateId& id) {
    simplex::NotarizeVote vote{id};
    auto inner = serialize_tl_object(vote.to_tl(), true);
    std::vector<simplex::tl::VoteSignatureRef> signatures;
    std::vector<size_t> signers;
    for (size_t i = 0; i < VALIDATORS; ++i) {
      if (i != target_) {
        signers.push_back(i);
        signatures.push_back(
            create_tl_object<simplex::tl::voteSignature>(static_cast<td::int32>(i), sign(i, inner.as_slice())));
      }
    }
    auto set = create_tl_object<simplex::tl::voteSignatureSet>(std::move(signatures));
    auto cert = simplex::Certificate<simplex::NotarizeVote>::from_tl(std::move(*set), vote, *bus_ptr_);
    CHECK(cert.is_ok());
    const auto& peer = bus_ptr_->validator_set.at(signers.front());
    bus_.publish<IncomingProtocolMessage>(peer.idx, peer.adnl_id, ProtocolMessage{cert.ok()->serialize()});
  }

  CandidateRef make_candidate(BlockSeqno seqno, const BlockIdExt& prev, ParentId parent, td::uint32 slot) {
    auto block = make_block(seqno, prev);
    auto id = CandidateHashData::create_full(block, parent).build_id_with(slot);
    auto leader = bus_ptr_->collator_schedule->expected_collator_for(slot);
    auto signature = sign(leader.value(), serialize_tl_object(id.to_tl(), true).as_slice());
    return td::make_ref<Candidate>(id, parent, leader, std::move(block), std::move(signature));
  }

  void deliver_candidate(const CandidateRef& candidate, const std::string& label) {
    emit(PSTRING() << "C09_DELIVER " << label << " candidate=" << id_str(candidate->id)
                   << " parent=" << (candidate->parent_id ? id_str(*candidate->parent_id) : std::string("genesis")));
    bus_.publish<CandidateReceived>(candidate);
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
    runtime_.register_actor<ObserverActor>("C09Observer");
    BlockValidator::register_in(runtime_);
    simplex::CandidateResolver::register_in(runtime_);
    simplex::Consensus::register_in(runtime_);
    simplex::Pool::register_in(runtime_);
    simplex::StateResolver::register_in(runtime_);
    simplex::Db::register_in(runtime_);
    simplex::DefaultCollatorSchedule::provide_for(runtime_);

    manager_ = td::actor::create_actor<ControlledManager>("ControlledManager");
    auto bus = std::make_shared<simplex::Bus>();
    bus->shard = SHARD;
    bus->manager = manager_.get();
    bus->validator_set = validators;
    for (const auto& validator : validators) {
      bus->all_validators.push_back(validator.adnl_id);
    }
    bus->total_weight = total_weight;
    bus->config = NewConsensusConfig{
        .max_block_size = 1 << 20,
        .max_collated_data_size = 1 << 20,
        .protocol_version = 2,
        .slots_per_leader_window = SLOTS_PER_LEADER_WINDOW,
    };
    // No timeout may turn into a skip vote of the node's own while the scenario runs, and no
    // minimum interval may hold a vote back: every vote observed is caused by a delivery.
    bus->config.noncritical_params.first_block_timeout =
        mode_ == Mode::SkipBeforeRecovery ? std::chrono::milliseconds(300) : std::chrono::milliseconds(600'000);
    bus->config.noncritical_params.standstill_timeout = std::chrono::milliseconds(600'000);
    bus->session_id = fill(0x42);
    bus->cc_seqno = CC_SEQNO;
    bus->validator_set_hash = 0;
    bus->db = std::make_unique<MemoryDb>();
    bus_ptr_ = bus;

    // The node under test must not lead window 0: its own leader path would read the genesis
    // state from start_generation and consume the fault meant for try_notarize(). run_inner()
    // checks this against the production collator schedule.
    target_ = 1;
    bus->pq_signer = signers_.at(target_);
    bus->local_id = validators.at(target_);
    bus->local_adnl_id = validators.at(target_).adnl_id;

    bus_ = runtime_.start(std::static_pointer_cast<simplex::Bus>(bus), "c09-target");
    bus_.publish<Start>(
        td::make_ref<ChainState>(ChainState::ZerostateTip{FIRST_PARENT, gen_shard_state(0)}, MIN_MC_BLOCK_ID));
  }

  td::actor::Task<> run_inner() {
    start_node();
    auto leader0 = bus_ptr_->collator_schedule->expected_collator_for(0);
    if (leader0.value() == target_) {
      finish(1, "C09_PRECONDITION_FAILED: the node under test leads window 0");
    }
    emit(PSTRING() << "C09_NODE target=" << target_ << " window0_leader=" << leader0.value());

    // Chain: X (slot 0, genesis) <- Y (slot 1) <- Z (slot 2).
    auto X = make_candidate(1, FIRST_PARENT, std::nullopt, 0);
    auto X_alt = make_candidate(2, FIRST_PARENT, std::nullopt, 0);
    auto Y = make_candidate(2, X->block_id(), X->id, 1);
    auto Z = make_candidate(3, Y->block_id(), Y->id, 2);
    emit(PSTRING() << "C09_CHAIN X=" << id_str(X->id) << " Y=" << id_str(Y->id) << " Z=" << id_str(Z->id));

    switch (mode_) {
      case Mode::Control:
        co_return co_await run_control(X, Y);
      case Mode::GenesisNotready:
      case Mode::GenesisTimeout:
      case Mode::Permanent:
      case Mode::Cancelled:
      case Mode::SkipBeforeRecovery:
      case Mode::ConflictDuringRetry:
      case Mode::ConflictingCertDuringRetry:
        co_return co_await run_genesis_fault(X, Y, X_alt);
      case Mode::AncestorNotready:
        co_return co_await run_ancestor_fault(X, Y, Z);
    }
    co_return td::Unit{};
  }

  td::actor::Task<> run_control(CandidateRef X, CandidateRef Y) {
    deliver_candidate(X, "first");
    if (!co_await wait_until([&] { return notarize_votes_for(X->id) >= 1; })) {
      report_counts("control-no-vote");
      finish(1, "C09_CONTROL_FAILED: X was not voted without any fault");
    }
    co_await settle();
    deliver_candidate(X, "redelivery");
    co_await settle();
    report_counts("control-after-redelivery");

    deliver_notar_cert(X->id);
    deliver_candidate(Y, "next");
    co_await wait_until([&] { return notarize_votes_for(Y->id) >= 1; });
    co_await settle();
    report_counts("control-final");
    emit(PSTRING() << "C09_RESULT mode=control X_notarize=" << notarize_votes_for(X->id)
                   << " X_finalize=" << finalize_votes_for(X->id) << " X_validations=" << validations_of(X)
                   << " Y_notarize=" << notarize_votes_for(Y->id));
    bool ok = notarize_votes_for(X->id) == 1 && emitted_notarize_votes_for(X->id) == 1 &&
              finalize_votes_for(X->id) == 1 && notarize_votes_for(Y->id) == 1 &&
              emitted_notarize_votes_for(Y->id) == 1;
    finish(ok ? 0 : 1, ok ? "C09_CONTROL_OK" : "C09_CONTROL_FAILED");
  }

  td::actor::Task<> run_genesis_fault(CandidateRef X, CandidateRef Y, CandidateRef X_alt) {
    fault_code.store(mode_ == Mode::GenesisTimeout ? ErrorCode::timeout
                     : mode_ == Mode::Permanent ? ErrorCode::protoviolation
                     : mode_ == Mode::Cancelled ? ErrorCode::cancelled
                                                : ErrorCode::notready);
    // StateResolver now retries the origin read three times before returning
    // notready. Exhaust that inner bound so this test reaches the Consensus
    // try_notarize failure/recovery boundary, rather than being absorbed below it.
    faults_remaining.store(mode_ == Mode::Permanent || mode_ == Mode::Cancelled
                               ? 1
                               : mode_ == Mode::SkipBeforeRecovery ? 12
                               : mode_ == Mode::ConflictingCertDuringRetry ? 6 : 3);
    deliver_candidate(X, "first");
    const size_t required_faults = mode_ == Mode::ConflictingCertDuringRetry ? 3 : 1;
    if (!co_await wait_until([&] { return manager_faults() >= required_faults; })) {
      report_counts("fault-not-hit");
      finish(1, "C09_PRECONDITION_FAILED: the injected fault was never reached");
    }
    if (mode_ == Mode::ConflictDuringRetry) {
      deliver_candidate(X_alt, "conflict-while-pending");
      if (!co_await wait_until([&] { return misbehavior_reports() == 1; })) {
        finish(1, "C05_PRECONDITION_FAILED: pending candidate did not retain V-019 conflict evidence");
      }
    }
    if (mode_ == Mode::ConflictingCertDuringRetry) {
      deliver_notar_cert(X_alt->id);
      if (!co_await wait_until([&] { return is_notarized(X_alt->id); })) {
        finish(1, "C05_PRECONDITION_FAILED: conflicting NotarCert was not installed during retry");
      }
      faults_remaining.store(0);
    }
    co_await settle();
    report_counts("after-fault");
    size_t votes_after_fault = notarize_votes_for(X->id);
    size_t reads_after_fault = manager_state_reads();
    if (mode_ == Mode::SkipBeforeRecovery) {
      if (skip_votes_for(X->id.slot) == 0) {
        finish(1, "C05_PRECONDITION_FAILED: local SkipVote was not cast before source recovery");
      }
      faults_remaining.store(0);
    }

    // Recovery: the resolver answers the same request now.
    auto resolved = co_await bus_.publish<simplex::ResolveState>(ParentId{}).wrap();
    emit(PSTRING() << "C09_RECOVERY ResolveState(genesis) " << (resolved.is_ok() ? "ok" : resolved.error().to_string()));
    if (resolved.is_error()) {
      finish(1, "C09_PRECONDITION_FAILED: the resolver did not recover");
    }

    deliver_candidate(X, "redelivery");
    co_await settle();
    report_counts("after-redelivery");
    size_t votes_after_redelivery = notarize_votes_for(X->id);

    if (mode_ == Mode::Permanent || mode_ == Mode::Cancelled || mode_ == Mode::SkipBeforeRecovery ||
        mode_ == Mode::ConflictingCertDuringRetry) {
      bool rejected = votes_after_fault == 0 && votes_after_redelivery == 0 &&
                      emitted_notarize_votes_for(X->id) == 0;
      if (mode_ == Mode::Permanent || mode_ == Mode::Cancelled) {
        rejected = rejected && reads_after_fault == 1 && skip_votes_for(X->id.slot) == 0 && validations_of(X) == 0;
      } else if (mode_ == Mode::SkipBeforeRecovery) {
        rejected = rejected && skip_votes_for(X->id.slot) > 0 && validations_of(X) == 0;
      } else {
        rejected = rejected && is_notarized(X_alt->id) && skip_votes_for(X->id.slot) == 0;
      }
      emit(PSTRING() << "C05_NEGATIVE mode=" << (mode_ == Mode::Permanent ? "permanent"
                                                 : mode_ == Mode::Cancelled ? "cancelled"
                                                 : mode_ == Mode::SkipBeforeRecovery ? "skip-before-recovery"
                                                                                     : "conflicting-cert-during-retry")
                     << " reads_after_fault=" << reads_after_fault << " skip_votes=" << skip_votes_for(X->id.slot)
                     << " notarize=" << votes_after_redelivery << " validations=" << validations_of(X));
      finish(rejected ? 0 : 4, rejected ? "C05_NEGATIVE_OK" : "C05_NEGATIVE_FAILED");
    }

    // The rest of the network notarizes X; this node then gets a later candidate on X.
    deliver_notar_cert(X->id);
    co_await wait_until([&] { return is_notarized(X->id); });
    deliver_candidate(Y, "next");
    co_await wait_until([&] { return notarize_votes_for(Y->id) >= 1; });
    co_await settle();
    report_counts("final");

    emit(PSTRING() << "C09_RESULT mode=" << (mode_ == Mode::GenesisTimeout ? "genesis-timeout"
                                           : mode_ == Mode::ConflictDuringRetry ? "conflict-during-retry"
                                                                                 : "genesis-notready")
                   << " X_notarize_after_fault=" << votes_after_fault
                   << " X_notarize_after_redelivery=" << votes_after_redelivery
                   << " X_notarize_final=" << notarize_votes_for(X->id) << " X_finalize=" << finalize_votes_for(X->id)
                   << " X_validations=" << validations_of(X) << " X_notarized_by_network=" << is_notarized(X->id)
                   << " Y_notarize=" << notarize_votes_for(Y->id));
    if (notarize_votes_for(X->id) != 1 || emitted_notarize_votes_for(X->id) != 1 ||
        finalize_votes_for(X->id) != 1 || validations_of(X) != 1) {
      finish(3, "C05_VOTE_COUNT_FAILED: X must be validated and emit one signed notarize vote before finalizing");
    }
    if (mode_ == Mode::ConflictDuringRetry && (misbehavior_reports() != 1 || validations_of(X_alt) != 0)) {
      finish(4, "C05_CONFLICT_FAILED: V-019 conflict was lost or the conflicting candidate was validated");
    }
    finish(0, "C09_VOTE_RECOVERED");
  }

  td::actor::Task<> run_ancestor_fault(CandidateRef X, CandidateRef Y, CandidateRef Z) {
    // Before the fault: X is voted normally.
    deliver_candidate(X, "pre-fault");
    if (!co_await wait_until([&] { return notarize_votes_for(X->id) >= 1; })) {
      report_counts("pre-fault-no-vote");
      finish(1, "C09_PRECONDITION_FAILED: X was not voted before the fault");
    }
    deliver_notar_cert(X->id);

    // Y is notarized by the network but its data never reaches this node, and peers refuse it.
    refuse_overlay_requests.store(true);
    deliver_notar_cert(Y->id);
    if (!co_await wait_until([&] { return is_notarized(Y->id); })) {
      finish(1, "C09_PRECONDITION_FAILED: NotarCert(Y) was not installed");
    }
    deliver_candidate(Z, "first");
    if (!co_await wait_until([&] { return overlay_requests_for(Y->id) >= 1; })) {
      report_counts("ancestor-fault-not-hit");
      finish(1, "C09_PRECONDITION_FAILED: resolving Z never asked for Y");
    }
    // Let the candidate resolver exhaust its attempts and give up.
    co_await settle(5.0);
    report_counts("after-fault");
    size_t votes_after_fault = notarize_votes_for(Z->id);

    // Recovery: Y's data arrives and the resolver can now produce Y's state.
    refuse_overlay_requests.store(false);
    co_await bus_.publish<simplex::StoreCandidate>(Y);
    auto resolved = co_await bus_.publish<simplex::ResolveState>(ParentId{Y->id}).wrap();
    emit(PSTRING() << "C09_RECOVERY ResolveState(Y) " << (resolved.is_ok() ? "ok" : resolved.error().to_string()));
    if (resolved.is_error()) {
      finish(1, "C09_PRECONDITION_FAILED: the resolver did not recover");
    }

    deliver_candidate(Z, "redelivery");
    co_await settle();
    report_counts("final");
    emit(PSTRING() << "C09_RESULT mode=ancestor-notready X_notarize=" << notarize_votes_for(X->id)
                   << " Y_overlay_requests=" << overlay_requests_for(Y->id)
                   << " Z_notarize_after_fault=" << votes_after_fault
                   << " Z_notarize_final=" << notarize_votes_for(Z->id) << " Z_validations=" << validations_of(Z));
    if (notarize_votes_for(Z->id) != 1 || emitted_notarize_votes_for(Z->id) != 1 || validations_of(Z) != 1) {
      finish(3, "C05_VOTE_COUNT_FAILED: Z must be validated and emit one signed notarize vote");
    }
    finish(0, "C09_VOTE_RECOVERED");
  }
};

}  // namespace

int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(verbosity_WARNING);
  if (argc != 2) {
    std::fprintf(stderr, "usage: %s control|genesis-notready|genesis-timeout|ancestor-notready|permanent|cancelled|skip-before-recovery|conflict-during-retry|conflicting-cert-during-retry\n", argv[0]);
    return 2;
  }
  std::string mode_name = argv[1];
  Mode mode;
  if (mode_name == "control") {
    mode = Mode::Control;
  } else if (mode_name == "genesis-notready") {
    mode = Mode::GenesisNotready;
  } else if (mode_name == "genesis-timeout") {
    mode = Mode::GenesisTimeout;
  } else if (mode_name == "ancestor-notready") {
    mode = Mode::AncestorNotready;
  } else if (mode_name == "permanent") {
    mode = Mode::Permanent;
  } else if (mode_name == "cancelled") {
    mode = Mode::Cancelled;
  } else if (mode_name == "skip-before-recovery") {
    mode = Mode::SkipBeforeRecovery;
  } else if (mode_name == "conflict-during-retry") {
    mode = Mode::ConflictDuringRetry;
  } else if (mode_name == "conflicting-cert-during-retry") {
    mode = Mode::ConflictingCertDuringRetry;
  } else {
    std::fprintf(stderr, "unknown mode %s\n", argv[1]);
    return 2;
  }

  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<Driver> driver;
  scheduler.run_in_context([&] {
    driver = td::actor::create_actor<Driver>("c09-driver", mode);
    td::actor::ask(driver, &Driver::run).detach();
  });
  while (scheduler.run(1)) {
  }
  return 0;
}
