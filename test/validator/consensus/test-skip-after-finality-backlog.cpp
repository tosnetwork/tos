/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
// Actor-level regression: a skip timeout that expires while finality is behind must still be
// honoured once the finalization backlog clears.
//
// One validator node runs the production Consensus, Pool, CandidateResolver, StateResolver,
// BlockValidator and Db actors. The stand-ins are the validator manager, the private overlay
// and the database backend. The finalization backlog is toggled by publishing
// FinalizationBacklog on the bus, the same event the state resolver publishes. Peer
// certificates are real quorum certificates signed by the other three validators.
//
// A vote is observed at four points and by its identity, never by a count alone:
//   request   the Voted trace Pool emits once a vote passes its gates (before persistence);
//   intent    the committed PersistOwnVoteIntent;
//   signed    the committed PersistOwnSignedVote;
//   outgoing  the broadcast this node sends, decoded and its signature verified.
// A vote is cast exactly when all four are present once.
//
// Modes:
//   stall-recovers       the window-0 deadline expires while the backlog is over the limit;
//                        after it clears, every slot of the expired range is skipped once and
//                        the next window's timeout skips too. Unfixed code casts nothing.
//   short-hold           the backlog clears before the deadline: the deadline is neither
//                        advanced to the clear nor lost.
//   final-redrive        a slot whose notarization certificate arrived while behind is
//                        finalized after the clear, before the expired range is skipped; the
//                        finalized slot is not skipped.
//   superseded-deferral  peers skip the window while this node is behind; the new window
//                        supersedes the deferred skips, which are never cast, and the new
//                        window's timeout keeps the adaptive history of the expired one.
//   notar-rearm          out-of-order notarization certificates inside the expired range
//                        re-arm the timeout; they do not cancel the deferred skips, and the
//                        re-armed timeout does not duplicate them.
//   repeated-toggle      repeated over/clear events create no duplicate requests.
//   shutdown-pending     the group stops while deferred work is pending; nothing is cast.
//
// The modes below hold Pool's finality gate through the bus's test hook, so a backlog
// transition lands exactly between a vote's request and Pool's refusal of it before its
// intent, or between that refusal and its delivery:
//   race-refused-then-clear    four window-0 skips are refused while Consensus is behind;
//                              the clear requests each exact vote once more.
//   race-clear-before-refusal  the backlog clears before the refusals arrive; the refusals
//                              themselves bring the skips back, each once.
//   race-final-after-clear     the same for a final vote.
//   race-new-window            peers skip the window while refusals are on their way; the
//                              refused skips are obsolete and the next window's adaptive
//                              timeout is untouched.
//   race-notar-rearm           a notarization re-arm while refusals are on their way does not
//                              produce a second request.
//   bootstrap-suppressed       the skips the startup path casts are refused and recovered.
//   shutdown-suppressed        the group stops while refused votes are kept; nothing is cast.

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "auto/tl/tos_api.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "consensus/simplex/bus.h"
#include "consensus/simplex/certificate.h"
#include "consensus/simplex/stats.h"
#include "consensus/simplex/votes.h"
#include "consensus/utils.h"
#include "crypto/pq/consensus-pq-signer.h"
#include "metrics/consensus-health.h"
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

enum class Mode {
  StallRecovers,
  ShortHold,
  FinalRedrive,
  SupersededDeferral,
  NotarRearm,
  RepeatedToggle,
  ShutdownPending,
  RaceRefusedThenClear,
  RaceClearBeforeRefusal,
  RaceFinalAfterClear,
  RaceNewWindow,
  RaceNotarRearm,
  BootstrapSuppressed,
  ShutdownSuppressed,
};

bool uses_gate(Mode mode) {
  return mode >= Mode::RaceRefusedThenClear;
}

// ===== Pool's finality gate, held in place =====
//
// Through the bus's test hook, the first request of each vote can be held at the gate before
// Pool reads its backlog flag, and again after Pool refused it but before the refusal is
// delivered. The driver releases them once the backlog transition it wants in between has
// been processed, so the order is decided by the test rather than by the scheduler.

std::string identity(const simplex::Vote& vote);

using GatePromise = decltype(td::actor::StartedTask<>::make_bridge().second);

struct GateControl {
  std::mutex mutex;
  bool hold_before = false;
  bool hold_after = false;
  std::set<std::pair<int, std::string>> held_once;
  std::vector<GatePromise> before;
  std::vector<GatePromise> after;
};

GateControl gate;

td::actor::StartedTask<> gate_hook(const simplex::Vote& vote, simplex::VoteGatePoint point) {
  auto [task, promise] = td::actor::StartedTask<>::make_bridge();
  const bool at_gate = point == simplex::VoteGatePoint::BeforeFinalityGate;
  bool hold = false;
  {
    std::scoped_lock lock(gate.mutex);
    hold = (at_gate ? gate.hold_before : gate.hold_after) &&
           gate.held_once.emplace(static_cast<int>(point), identity(vote)).second;
    if (hold) {
      (at_gate ? gate.before : gate.after).push_back(std::move(promise));
    }
  }
  if (hold) {
    emit(PSTRING() << "A142_GATE_HELD " << (at_gate ? "before-gate " : "after-refusal ") << identity(vote));
  } else {
    promise.set_value(td::Unit{});
  }
  return std::move(task);
}

size_t gate_held(bool at_gate) {
  std::scoped_lock lock(gate.mutex);
  return at_gate ? gate.before.size() : gate.after.size();
}

// Releases what is held at one point and stops holding there: later votes pass freely.
void gate_release(bool at_gate) {
  std::vector<GatePromise> promises;
  {
    std::scoped_lock lock(gate.mutex);
    (at_gate ? gate.hold_before : gate.hold_after) = false;
    promises = std::move(at_gate ? gate.before : gate.after);
    (at_gate ? gate.before : gate.after).clear();
  }
  emit(PSTRING() << "A142_GATE_RELEASE " << (at_gate ? "before-gate" : "after-refusal") << " n=" << promises.size());
  for (auto& promise : promises) {
    promise.set_value(td::Unit{});
  }
}

// ===== What the test observes =====

enum class Stage { Request, Intent, Signed, Outgoing };

const char* stage_name(Stage stage) {
  switch (stage) {
    case Stage::Request:
      return "request";
    case Stage::Intent:
      return "intent";
    case Stage::Signed:
      return "signed";
    case Stage::Outgoing:
      return "outgoing";
  }
  return "?";
}

std::string identity(const simplex::Vote& vote) {
  return PSTRING() << vote;
}

std::string skip_id(td::uint32 slot) {
  return identity(simplex::Vote{simplex::SkipVote{slot}});
}

std::string final_id(const CandidateId& id) {
  return identity(simplex::Vote{simplex::FinalizeVote{id}});
}

std::string notar_id(const CandidateId& id) {
  return identity(simplex::Vote{simplex::NotarizeVote{id}});
}

struct Record {
  Stage stage;
  std::string id;
  td::uint32 slot;
  int kind;  // 0 notarize, 1 finalize, 2 skip
  std::string candidate;
  double time;
};

struct Observations {
  std::mutex mutex;
  std::vector<Record> records;
  std::map<td::uint32, double> windows;  // window start slot -> observed at
  std::vector<CandidateId> notarized;
};

Observations observations;

void record_vote(Stage stage, const simplex::Vote& vote) {
  Record record{.stage = stage,
                .id = identity(vote),
                .slot = vote.referenced_slot(),
                .kind = 2,
                .candidate = {},
                .time = td::Time::now()};
  if (auto notar = std::get_if<simplex::NotarizeVote>(&vote.vote)) {
    record.kind = 0;
    record.candidate = notar->id.hash.to_hex();
  } else if (auto final_vote = std::get_if<simplex::FinalizeVote>(&vote.vote)) {
    record.kind = 1;
    record.candidate = final_vote->id.hash.to_hex();
  } else {
    record.kind = 2;
  }
  emit(PSTRING() << "A142_" << stage_name(stage) << " " << record.id);
  std::scoped_lock lock(observations.mutex);
  observations.records.push_back(std::move(record));
}

size_t count_at(Stage stage, const std::string& id) {
  std::scoped_lock lock(observations.mutex);
  return static_cast<size_t>(std::count_if(observations.records.begin(), observations.records.end(),
                                           [&](const Record& r) { return r.stage == stage && r.id == id; }));
}

size_t count_kind(Stage stage, int kind) {
  std::scoped_lock lock(observations.mutex);
  return static_cast<size_t>(std::count_if(observations.records.begin(), observations.records.end(),
                                           [&](const Record& r) { return r.stage == stage && r.kind == kind; }));
}

size_t total_records() {
  std::scoped_lock lock(observations.mutex);
  return observations.records.size();
}

std::optional<double> first_time(Stage stage, const std::string& id) {
  std::scoped_lock lock(observations.mutex);
  for (const auto& r : observations.records) {
    if (r.stage == stage && r.id == id) {
      return r.time;
    }
  }
  return std::nullopt;
}

// Position of the first record of `id` at `stage` in the global order, or SIZE_MAX.
size_t first_index(Stage stage, const std::string& id) {
  std::scoped_lock lock(observations.mutex);
  for (size_t i = 0; i < observations.records.size(); ++i) {
    if (observations.records[i].stage == stage && observations.records[i].id == id) {
      return i;
    }
  }
  return SIZE_MAX;
}

std::optional<double> window_observed(td::uint32 start_slot) {
  std::scoped_lock lock(observations.mutex);
  auto it = observations.windows.find(start_slot);
  if (it == observations.windows.end()) {
    return std::nullopt;
  }
  return it->second;
}

bool is_notarized(const CandidateId& id) {
  std::scoped_lock lock(observations.mutex);
  return std::find(observations.notarized.begin(), observations.notarized.end(), id) != observations.notarized.end();
}

// Every vote this node signed, checked by identity: per slot at most one notarize candidate,
// at most one finalize candidate equal to it, and never both a skip and a finalize.
std::optional<std::string> conflicting_votes() {
  std::scoped_lock lock(observations.mutex);
  std::map<td::uint32, std::set<std::string>> notar, final_votes;
  std::set<td::uint32> skips;
  for (const auto& r : observations.records) {
    if (r.stage != Stage::Signed && r.stage != Stage::Outgoing) {
      continue;
    }
    if (r.kind == 0) {
      notar[r.slot].insert(r.candidate);
    } else if (r.kind == 1) {
      final_votes[r.slot].insert(r.candidate);
    } else {
      skips.insert(r.slot);
    }
  }
  for (const auto& [slot, ids] : notar) {
    if (ids.size() > 1) {
      return PSTRING() << "two notarize votes for slot " << slot;
    }
  }
  for (const auto& [slot, ids] : final_votes) {
    if (ids.size() > 1) {
      return PSTRING() << "two finalize votes for slot " << slot;
    }
    if (skips.contains(slot)) {
      return PSTRING() << "both skip and finalize for slot " << slot;
    }
    if (notar.contains(slot) && notar[slot] != ids) {
      return PSTRING() << "finalize differs from notarize for slot " << slot;
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

  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const TraceEvent> event) {
    auto voted = dynamic_cast<const simplex::stats::Voted*>(event->event.get());
    if (voted != nullptr) {
      record_vote(Stage::Request, voted->vote());
    }
  }

  // Published by the bus only after the database answered the request successfully.
  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const simplex::PersistOwnVoteIntent> event) {
    record_vote(Stage::Intent, event->vote);
  }

  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const simplex::PersistOwnSignedVote> event) {
    record_vote(Stage::Signed, event->vote);
  }

  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const simplex::LeaderWindowObserved> event) {
    emit(PSTRING() << "A142_WINDOW start_slot=" << event->start_slot);
    std::scoped_lock lock(observations.mutex);
    observations.windows.emplace(event->start_slot, td::Time::now());
  }

  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const simplex::NotarizationObserved> event) {
    std::scoped_lock lock(observations.mutex);
    observations.notarized.push_back(event->id);
  }
};

// Stands in for the private overlay: every vote this node broadcasts is decoded and its
// signature verified against this node's consensus key.
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
    auto signed_vote =
        simplex::Signed<simplex::Vote>::deserialize(message->message.data.as_slice(), bus->local_id->idx, *bus);
    if (signed_vote.is_error()) {
      emit(PSTRING() << "A142_OUTGOING_UNVERIFIED " << signed_vote.error());
      return;
    }
    record_vote(Stage::Outgoing, signed_vote.ok().vote);
  }

  template <>
  td::actor::Task<ProtocolMessage> process(simplex::BusHandle, std::shared_ptr<OutgoingOverlayRequest> message) {
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

// The validator manager: holds the zerostate and accepts every block.
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
      finish(1, "A142_HARNESS_FAILED: " + result.error().to_string());
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
  std::optional<td::actor::StartedTask<>> stopped_;
  size_t target_ = 1;
  double first_block_timeout_ = 0.3;
  double multiplier_ = 1.2;
  double target_rate_ = 0.4;

  td::BufferSlice sign(size_t signer, td::Slice inner) const {
    auto envelope =
        create_serialize_tl_object<tos_api::consensus_dataToSign>(bus_ptr_->session_id, td::BufferSlice(inner));
    auto signature =
        signers_.at(signer)->sign_consensus(std::string_view(envelope.as_slice().data(), envelope.as_slice().size()));
    CHECK(signature.has_value());
    return td::BufferSlice(signature->signature);
  }

  // A quorum certificate signed by the three validators other than the node under test.
  template <typename V>
  void deliver_cert(V vote) {
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
    auto cert = simplex::Certificate<V>::from_tl(std::move(*set), vote, *bus_ptr_);
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

  void backlog(bool over) {
    emit(PSTRING() << "A142_BACKLOG " << (over ? "over" : "clear") << " t=" << td::Time::now());
    bus_.publish<FinalizationBacklog>(over, size_t{over ? 2u : 0u});
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

  td::actor::Task<> sleep_until(double at) {
    co_await td::actor::coro_sleep(td::Timestamp::at(at));
    co_return td::Unit{};
  }

  td::actor::Task<> settle(double seconds) {
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
    runtime_.register_actor<ObserverActor>("A142Observer");
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
    auto& params = bus->config.noncritical_params;
    params.first_block_timeout = std::chrono::milliseconds(static_cast<int>(first_block_timeout_ * 1000));
    params.first_block_timeout_multiplier = multiplier_;
    params.target_rate = std::chrono::milliseconds(static_cast<int>(target_rate_ * 1000));
    params.standstill_timeout = std::chrono::milliseconds(600'000);
    bus->session_id = fill(0x42);
    bus->cc_seqno = CC_SEQNO;
    bus->validator_set_hash = 0;
    bus->db = std::make_unique<MemoryDb>();
    auto [stopped, stop_promise] = td::actor::StartedTask<>::make_bridge();
    bus->stop_promise = std::move(stop_promise);
    stopped_.emplace(std::move(stopped));
    if (uses_gate(mode_)) {
      bus->vote_gate_hook_for_test = gate_hook;
    }
    if (mode_ == Mode::BootstrapSuppressed) {
      // As after a restart inside window 0: the startup path skips its not-final slots.
      bus->first_nonannounced_window = 1;
    }
    bus_ptr_ = bus;

    bus->pq_signer = signers_.at(target_);
    bus->local_id = validators.at(target_);
    bus->local_adnl_id = validators.at(target_).adnl_id;

    bus_ = runtime_.start(std::static_pointer_cast<simplex::Bus>(bus), "a142-target");
    bus_.publish<Start>(
        td::make_ref<ChainState>(ChainState::ZerostateTip{FIRST_PARENT, gen_shard_state(0)}, MIN_MC_BLOCK_ID));
  }

  // The time the window starting at `start_slot` times out its first slot: the consensus
  // actor arms timeout_base = observed + first_block_timeout and fires target_rate later.
  double first_deadline(double observed, double first_block_timeout) const {
    return observed + first_block_timeout + target_rate_;
  }

  td::actor::Task<double> await_window(td::uint32 start_slot) {
    if (!co_await wait_until([&] { return window_observed(start_slot).has_value(); })) {
      finish(1, PSTRING() << "A142_PRECONDITION_FAILED: the window at slot " << start_slot << " was never observed");
    }
    co_return *window_observed(start_slot);
  }

  void require(bool condition, const std::string& what) {
    if (!condition) {
      finish(4, "A142_ASSERTION_FAILED: " + what);
    }
  }

  void require_no_conflicts() {
    if (auto conflict = conflicting_votes()) {
      finish(4, "A142_CONFLICT: " + *conflict);
    }
  }

  // Cast exactly once: one request, one committed intent, one committed signed record and
  // one verified broadcast.
  void require_cast_once(const std::string& id) {
    for (auto stage : {Stage::Request, Stage::Intent, Stage::Signed, Stage::Outgoing}) {
      auto n = count_at(stage, id);
      require(n == 1, PSTRING() << id << " has " << n << " " << stage_name(stage) << " records, expected 1");
    }
  }

  void require_never(const std::string& id) {
    for (auto stage : {Stage::Request, Stage::Intent, Stage::Signed, Stage::Outgoing}) {
      auto n = count_at(stage, id);
      require(n == 0, PSTRING() << id << " has " << n << " " << stage_name(stage) << " records, expected none");
    }
  }

  bool all_outgoing(const std::vector<std::string>& ids) {
    return std::all_of(ids.begin(), ids.end(), [](const auto& id) { return count_at(Stage::Outgoing, id) > 0; });
  }

  std::vector<std::string> skips(td::uint32 begin, td::uint32 end) {
    std::vector<std::string> ids;
    for (td::uint32 i = begin; i < end; ++i) {
      ids.push_back(skip_id(i));
    }
    return ids;
  }

  // Locally applied votes, from the production health ledger: Pool reports LocalApplied only
  // after handle_vote accepted the signed vote.
  std::uint64_t applied(tos::health::Action action) {
    return tos::health::consensus_stats.phase(action, tos::health::Origin::Live, tos::health::Phase::LocalApplied)
        .load();
  }

  // Waits for `ids` to be broadcast after a clear; reports the stall the fix exists for.
  td::actor::Task<> await_recovery(const std::vector<std::string>& ids, double timeout, const char* what) {
    if (!co_await wait_until([&] { return all_outgoing(ids); }, timeout)) {
      std::string missing;
      for (const auto& id : ids) {
        if (count_at(Stage::Outgoing, id) == 0) {
          missing += " " + id;
        }
      }
      finish(3, PSTRING() << "A142_STALL: " << what << "; never broadcast:" << missing);
    }
    co_return td::Unit{};
  }

  void configure() {
    switch (mode_) {
      case Mode::ShortHold:
        first_block_timeout_ = 1.5;
        break;
      case Mode::SupersededDeferral:
      case Mode::RaceNewWindow:
        multiplier_ = 3.0;
        break;
      case Mode::RaceFinalAfterClear:
      case Mode::BootstrapSuppressed:
        // No timeout of the node's own may cast a skip while these run.
        first_block_timeout_ = 600.0;
        break;
      default:
        break;
    }
  }

  td::actor::Task<> run_inner() {
    tos::health::enabled.store(true);
    tos::health::consensus_enabled.store(true);
    configure();
    start_node();
    auto leader0 = bus_ptr_->collator_schedule->expected_collator_for(0);
    if (leader0.value() == target_) {
      finish(1, "A142_PRECONDITION_FAILED: the node under test leads window 0");
    }
    switch (mode_) {
      case Mode::StallRecovers:
        co_return co_await run_stall_recovers();
      case Mode::ShortHold:
        co_return co_await run_short_hold();
      case Mode::FinalRedrive:
        co_return co_await run_final_redrive();
      case Mode::SupersededDeferral:
        co_return co_await run_superseded_deferral();
      case Mode::NotarRearm:
        co_return co_await run_notar_rearm();
      case Mode::RepeatedToggle:
        co_return co_await run_repeated_toggle();
      case Mode::ShutdownPending:
        co_return co_await run_shutdown_pending();
      case Mode::RaceRefusedThenClear:
        co_return co_await run_race_skips(/*clear_before_refusal=*/false);
      case Mode::RaceClearBeforeRefusal:
        co_return co_await run_race_skips(/*clear_before_refusal=*/true);
      case Mode::RaceFinalAfterClear:
        co_return co_await run_race_final_after_clear();
      case Mode::RaceNewWindow:
        co_return co_await run_race_new_window();
      case Mode::RaceNotarRearm:
        co_return co_await run_race_notar_rearm();
      case Mode::BootstrapSuppressed:
        co_return co_await run_bootstrap_suppressed();
      case Mode::ShutdownSuppressed:
        co_return co_await run_shutdown_suppressed();
    }
    co_return td::Unit{};
  }

  // Pool handles bus messages in order, so once it has answered this, it has processed every
  // backlog event published before it.
  td::actor::Task<> pool_barrier() {
    co_await bus_.publish<simplex::QueryValidatorGroupInfo>();
    co_return td::Unit{};
  }

  std::uint64_t finality_suppressed(tos::health::Action action) {
    return tos::health::consensus_stats.phase(action, tos::health::Origin::Live, tos::health::Phase::FinalitySuppressed)
        .load();
  }

  td::actor::Task<> await_held(bool at_gate, size_t n, double timeout, const char* what) {
    if (!co_await wait_until([&] { return gate_held(at_gate) == n; }, timeout)) {
      finish(1, PSTRING() << "A142_PRECONDITION_FAILED: " << what << " (held " << gate_held(at_gate) << " of " << n
                          << ")");
    }
    co_return td::Unit{};
  }

  // The window-0 skips are requested while finality is still fine and held at Pool's gate.
  // The backlog then goes over and Pool, having processed that, refuses them before their
  // intent. Consensus has decided the skips, and nothing about them exists anywhere else.
  td::actor::Task<double> refuse_window0_skips_at_gate(bool hold_refusals) {
    {
      std::scoped_lock lock(gate.mutex);
      gate.hold_before = true;
      gate.hold_after = hold_refusals;
    }
    auto w0 = co_await await_window(0);
    const double deadline = first_deadline(w0, first_block_timeout_);
    co_await await_held(true, SLOTS_PER_LEADER_WINDOW, deadline - td::Time::now() + 3.0,
                        "the window-0 skips did not reach Pool's gate");
    require(total_records() == 0, "a held vote passed the gate");
    backlog(true);
    co_await pool_barrier();
    gate_release(true);
    if (hold_refusals) {
      co_await await_held(false, SLOTS_PER_LEADER_WINDOW, 3.0, "Pool did not refuse the held skips");
    } else if (!co_await wait_until(
                   [&] { return finality_suppressed(tos::health::Action::Skip) == SLOTS_PER_LEADER_WINDOW; })) {
      finish(1, "A142_PRECONDITION_FAILED: Pool did not refuse the held skips");
    }
    require(finality_suppressed(tos::health::Action::Skip) == SLOTS_PER_LEADER_WINDOW,
            "every held skip was refused before its intent");
    co_return w0;
  }

  td::actor::Task<> finish_window0_recovery(const char* mode, const char* what) {
    auto window0 = skips(0, SLOTS_PER_LEADER_WINDOW);
    co_await await_recovery(window0, 3.0, what);
    co_await settle(0.5);
    for (const auto& id : window0) {
      require_cast_once(id);
    }
    require(applied(tos::health::Action::Skip) == SLOTS_PER_LEADER_WINDOW, "every skip was applied locally");
    require_no_conflicts();
    finish(0, PSTRING() << "A142_OK " << mode);
  }

  td::actor::Task<> run_race_skips(bool clear_before_refusal) {
    co_await refuse_window0_skips_at_gate(clear_before_refusal);
    if (clear_before_refusal) {
      // The backlog clears before the refusals reach Consensus. The clear's recovery has
      // nothing to see yet, so the refusals themselves must bring the skips back.
      backlog(false);
      co_await pool_barrier();
      gate_release(false);
      co_return co_await finish_window0_recovery("race-clear-before-refusal",
                                                 "refusals delivered after the clear were dropped");
    }
    co_await settle(0.2);
    require(total_records() == 0, "a refused skip was journalled, signed or sent");
    backlog(false);
    co_return co_await finish_window0_recovery("race-refused-then-clear",
                                               "skips refused before their intent were dropped");
  }

  td::actor::Task<> run_race_final_after_clear() {
    auto x = make_candidate(1, FIRST_PARENT, std::nullopt, 0);
    bus_.publish<CandidateReceived>(x);
    if (!co_await wait_until([&] { return count_at(Stage::Outgoing, notar_id(x->id)) == 1; })) {
      finish(1, "A142_PRECONDITION_FAILED: X was not notarized");
    }
    {
      std::scoped_lock lock(gate.mutex);
      gate.hold_before = true;
      gate.hold_after = true;
    }
    deliver_cert(simplex::NotarizeVote{x->id});
    co_await await_held(true, 1, 3.0, "the final vote did not reach Pool's gate");
    backlog(true);
    co_await pool_barrier();
    gate_release(true);
    co_await await_held(false, 1, 3.0, "Pool did not refuse the final vote");
    backlog(false);
    co_await pool_barrier();
    gate_release(false);
    co_await await_recovery({final_id(x->id)}, 3.0, "a final vote refused after the clear was dropped");
    co_await settle(0.5);
    require_cast_once(notar_id(x->id));
    require_cast_once(final_id(x->id));
    require(count_kind(Stage::Request, 2) == 0, "no skip was requested");
    require(applied(tos::health::Action::Finalize) == 1, "the final vote was applied locally");
    require_no_conflicts();
    finish(0, "A142_OK race-final-after-clear");
  }

  td::actor::Task<> run_race_new_window() {
    co_await refuse_window0_skips_at_gate(/*hold_refusals=*/true);
    // Peers skip window 0 while the refusals are still on their way to Consensus.
    for (td::uint32 i = 0; i < SLOTS_PER_LEADER_WINDOW; ++i) {
      deliver_cert(simplex::SkipVote{i});
    }
    auto w1 = co_await await_window(SLOTS_PER_LEADER_WINDOW);
    co_await settle(0.05);
    gate_release(false);
    co_await settle(0.1);
    backlog(false);
    const double deadline = first_deadline(w1, first_block_timeout_ * multiplier_);
    auto window1 = skips(SLOTS_PER_LEADER_WINDOW, 2 * SLOTS_PER_LEADER_WINDOW);
    co_await await_recovery(window1, 5.0, "the window after the late refusals did not time out");
    auto at = first_time(Stage::Request, window1.front());
    require(at.has_value() && *at >= deadline - 0.05,
            PSTRING() << "the late refusals left window 1's adaptive timeout alone (skip at " << (*at - w1)
                      << "s, deadline at " << (deadline - w1) << "s)");
    co_await settle(0.5);
    for (const auto& id : skips(0, SLOTS_PER_LEADER_WINDOW)) {
      require_never(id);
    }
    for (const auto& id : window1) {
      require_cast_once(id);
    }
    require_no_conflicts();
    finish(0, "A142_OK race-new-window");
  }

  td::actor::Task<> run_race_notar_rearm() {
    auto w0 = co_await refuse_window0_skips_at_gate(/*hold_refusals=*/true);
    // A certificate for the window's last slot re-arms the timeout while the refusals are
    // still on their way; the re-armed timeout must not cast a second request.
    deliver_cert(simplex::NotarizeVote{CandidateId{3, fill(0x33)}});
    if (!co_await wait_until([&] { return is_notarized(CandidateId{3, fill(0x33)}); })) {
      finish(1, "A142_PRECONDITION_FAILED: the certificate for slot 3 was not installed");
    }
    const double rearmed = w0 + first_block_timeout_ + SLOTS_PER_LEADER_WINDOW * target_rate_;
    backlog(false);
    co_await pool_barrier();
    gate_release(false);
    auto window0 = skips(0, SLOTS_PER_LEADER_WINDOW);
    co_await await_recovery(window0, 3.0, "refusals delivered after the clear were dropped");
    co_await sleep_until(rearmed + 0.5);
    for (const auto& id : window0) {
      require_cast_once(id);
    }
    require_no_conflicts();
    finish(0, "A142_OK race-notar-rearm");
  }

  td::actor::Task<> run_bootstrap_suppressed() {
    {
      std::scoped_lock lock(gate.mutex);
      gate.hold_before = true;
    }
    co_await await_held(true, SLOTS_PER_LEADER_WINDOW, 5.0, "the startup skips did not reach Pool's gate");
    backlog(true);
    co_await pool_barrier();
    gate_release(true);
    if (!co_await wait_until(
            [&] { return finality_suppressed(tos::health::Action::Skip) == SLOTS_PER_LEADER_WINDOW; })) {
      finish(1, "A142_PRECONDITION_FAILED: Pool did not refuse the startup skips");
    }
    co_await settle(0.2);
    require(total_records() == 0, "a refused startup skip was journalled, signed or sent");
    backlog(false);
    co_return co_await finish_window0_recovery("bootstrap-suppressed",
                                               "startup skips refused before their intent were dropped");
  }

  td::actor::Task<> run_shutdown_suppressed() {
    co_await refuse_window0_skips_at_gate(/*hold_refusals=*/false);
    co_await settle(0.2);
    emit("A142_STOP with refused skips kept for recovery");
    bus_.publish<StopRequested>();
    bus_ = {};
    bus_ptr_.reset();
    co_await std::move(*stopped_);
    co_await settle(0.3);
    require(total_records() == 0, "nothing was cast by a stopped group");
    finish(0, "A142_OK shutdown-suppressed");
  }

  // Goes over the limit before the window-0 deadline and returns that deadline.
  td::actor::Task<double> hold_across_first_deadline() {
    auto w0 = co_await await_window(0);
    const double deadline = first_deadline(w0, first_block_timeout_);
    backlog(true);
    require(td::Time::now() < deadline - 0.1, "the backlog went over the limit before the deadline");
    co_await sleep_until(deadline + 0.5);
    require(total_records() == 0, "nothing is cast while finality is behind");
    co_return deadline;
  }

  td::actor::Task<> run_stall_recovers() {
    const double deadline = co_await hold_across_first_deadline();
    backlog(false);
    emit(PSTRING() << "A142_HELD_ACROSS_DEADLINE by=" << (td::Time::now() - deadline));
    auto window0 = skips(0, SLOTS_PER_LEADER_WINDOW);
    co_await await_recovery(window0, 3.0, "the expired window-0 timeout was lost while finality was behind");

    // Progress continues: peers skip window 0, the next window opens and its own timeout
    // skips it.
    for (td::uint32 i = 0; i < SLOTS_PER_LEADER_WINDOW; ++i) {
      deliver_cert(simplex::SkipVote{i});
    }
    co_await await_window(SLOTS_PER_LEADER_WINDOW);
    auto window1 = skips(SLOTS_PER_LEADER_WINDOW, 2 * SLOTS_PER_LEADER_WINDOW);
    co_await await_recovery(window1, 5.0, "the window after recovery did not time out");
    co_await settle(0.5);
    for (const auto& id : window0) {
      require_cast_once(id);
    }
    for (const auto& id : window1) {
      require_cast_once(id);
    }
    require(applied(tos::health::Action::Skip) == 2 * SLOTS_PER_LEADER_WINDOW, "every skip was applied locally");
    require_no_conflicts();
    finish(0, "A142_OK stall-recovers");
  }

  td::actor::Task<> run_short_hold() {
    auto w0 = co_await await_window(0);
    const double deadline = first_deadline(w0, first_block_timeout_);
    backlog(true);
    co_await settle(0.3);
    backlog(false);
    require(td::Time::now() < deadline - 0.8, "the hold ended well before the deadline");
    co_await sleep_until(deadline - 0.2);
    require(total_records() == 0, "clearing the backlog did not bring the deadline forward");
    auto window0 = skips(0, SLOTS_PER_LEADER_WINDOW);
    co_await await_recovery(window0, 3.0, "the unexpired timeout was lost across a short hold");
    auto at = first_time(Stage::Request, skip_id(0));
    require(at.has_value() && *at >= deadline - 0.05, "the skip waited for the original deadline");
    co_await settle(0.3);
    for (const auto& id : window0) {
      require_cast_once(id);
    }
    require_no_conflicts();
    finish(0, "A142_OK short-hold");
  }

  td::actor::Task<> run_final_redrive() {
    auto w0 = co_await await_window(0);
    auto x = make_candidate(1, FIRST_PARENT, std::nullopt, 0);
    bus_.publish<CandidateReceived>(x);
    if (!co_await wait_until([&] { return count_at(Stage::Outgoing, notar_id(x->id)) == 1; })) {
      finish(1, "A142_PRECONDITION_FAILED: X was not notarized before the backlog");
    }
    backlog(true);
    co_await settle(0.05);
    deliver_cert(simplex::NotarizeVote{x->id});
    if (!co_await wait_until([&] { return is_notarized(x->id); })) {
      finish(1, "A142_PRECONDITION_FAILED: NotarCert(X) was not installed");
    }
    // The notarization of slot 0 moves the timeout to slot 1, due two target rates later.
    const double deadline = w0 + first_block_timeout_ + 2 * target_rate_;
    require(td::Time::now() < deadline - 0.1, "the certificate arrived before the deadline");
    co_await sleep_until(deadline + 0.5);
    require(count_at(Stage::Request, final_id(x->id)) == 0, "the final vote waited for the backlog");
    backlog(false);
    auto expected = skips(1, SLOTS_PER_LEADER_WINDOW);
    expected.push_back(final_id(x->id));
    co_await await_recovery(expected, 3.0, "the final vote or the expired skips were lost while finality was behind");
    co_await settle(0.5);
    require_cast_once(notar_id(x->id));
    require_cast_once(final_id(x->id));
    for (const auto& id : skips(1, SLOTS_PER_LEADER_WINDOW)) {
      require_cast_once(id);
      require(first_index(Stage::Intent, final_id(x->id)) < first_index(Stage::Intent, id),
              "the final vote was committed before the skips of the same recovery");
    }
    require_never(skip_id(0));
    require(applied(tos::health::Action::Finalize) == 1, "the final vote was applied locally");
    require_no_conflicts();
    finish(0, "A142_OK final-redrive");
  }

  td::actor::Task<> run_superseded_deferral() {
    co_await hold_across_first_deadline();
    for (td::uint32 i = 0; i < SLOTS_PER_LEADER_WINDOW; ++i) {
      deliver_cert(simplex::SkipVote{i});
    }
    auto w1 = co_await await_window(SLOTS_PER_LEADER_WINDOW);
    backlog(false);
    // Window 0 timed out, so window 1 waits first_block_timeout * multiplier.
    const double deadline = first_deadline(w1, first_block_timeout_ * multiplier_);
    auto window1 = skips(SLOTS_PER_LEADER_WINDOW, 2 * SLOTS_PER_LEADER_WINDOW);
    co_await await_recovery(window1, 5.0, "the window after the superseded deferral did not time out");
    auto at = first_time(Stage::Request, window1.front());
    require(at.has_value() && *at >= deadline - 0.05,
            PSTRING() << "window 1 kept the adaptive timeout of the expired window 0 (skip at " << (*at - w1)
                      << "s, deadline at " << (deadline - w1) << "s)");
    co_await settle(0.5);
    for (const auto& id : skips(0, SLOTS_PER_LEADER_WINDOW)) {
      require_never(id);
    }
    for (const auto& id : window1) {
      require_cast_once(id);
    }
    require_no_conflicts();
    finish(0, "A142_OK superseded-deferral");
  }

  td::actor::Task<> run_notar_rearm() {
    auto w0 = co_await await_window(0);
    co_await hold_across_first_deadline();
    // Certificates for slots 2 and 3 arrive out of order while slots 0 and 1 have nothing;
    // the one for the last slot of the window re-arms the timeout.
    deliver_cert(simplex::NotarizeVote{CandidateId{3, fill(0x33)}});
    deliver_cert(simplex::NotarizeVote{CandidateId{2, fill(0x32)}});
    if (!co_await wait_until(
            [&] { return is_notarized(CandidateId{3, fill(0x33)}) && is_notarized(CandidateId{2, fill(0x32)}); })) {
      finish(1, "A142_PRECONDITION_FAILED: the out-of-order certificates were not installed");
    }
    const double rearmed = w0 + first_block_timeout_ + SLOTS_PER_LEADER_WINDOW * target_rate_;
    require(td::Time::now() < rearmed - 0.2, "the clear comes before the re-armed timeout");
    backlog(false);
    auto window0 = skips(0, SLOTS_PER_LEADER_WINDOW);
    co_await await_recovery(window0, 3.0, "the deferred skips were cancelled by an out-of-order notarization");
    co_await sleep_until(rearmed + 0.5);
    for (const auto& id : window0) {
      require_cast_once(id);
    }
    require_no_conflicts();
    finish(0, "A142_OK notar-rearm");
  }

  td::actor::Task<> run_repeated_toggle() {
    co_await hold_across_first_deadline();
    backlog(true);
    co_await settle(0.05);
    backlog(false);
    backlog(false);
    auto window0 = skips(0, SLOTS_PER_LEADER_WINDOW);
    co_await await_recovery(window0, 3.0, "the expired timeout was lost while finality was behind");
    co_await settle(0.3);
    backlog(true);
    co_await settle(0.2);
    backlog(false);
    co_await settle(0.5);
    for (const auto& id : window0) {
      require_cast_once(id);
    }
    require(count_kind(Stage::Request, 2) == SLOTS_PER_LEADER_WINDOW, "no duplicate skip request");
    require_no_conflicts();
    finish(0, "A142_OK repeated-toggle");
  }

  td::actor::Task<> run_shutdown_pending() {
    co_await hold_across_first_deadline();
    emit("A142_STOP with deferred skips pending");
    bus_.publish<StopRequested>();
    bus_ = {};
    bus_ptr_.reset();
    co_await std::move(*stopped_);
    co_await settle(0.3);
    require(total_records() == 0, "nothing was cast by a stopped group");
    finish(0, "A142_OK shutdown-pending");
  }
};

}  // namespace

int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(verbosity_WARNING);
  const std::vector<std::pair<std::string, Mode>> modes = {
      {"stall-recovers", Mode::StallRecovers},
      {"short-hold", Mode::ShortHold},
      {"final-redrive", Mode::FinalRedrive},
      {"superseded-deferral", Mode::SupersededDeferral},
      {"notar-rearm", Mode::NotarRearm},
      {"repeated-toggle", Mode::RepeatedToggle},
      {"shutdown-pending", Mode::ShutdownPending},
      {"race-refused-then-clear", Mode::RaceRefusedThenClear},
      {"race-clear-before-refusal", Mode::RaceClearBeforeRefusal},
      {"race-final-after-clear", Mode::RaceFinalAfterClear},
      {"race-new-window", Mode::RaceNewWindow},
      {"race-notar-rearm", Mode::RaceNotarRearm},
      {"bootstrap-suppressed", Mode::BootstrapSuppressed},
      {"shutdown-suppressed", Mode::ShutdownSuppressed},
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
    driver = td::actor::create_actor<Driver>("a142-driver", *mode);
    td::actor::ask(driver, &Driver::run).detach();
  });
  while (scheduler.run(1)) {
  }
  return 0;
}
