/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
// Actor-level regression for the Simplex state-resolver base-state mismatch.
//
// One validator node runs the production Pool, CandidateResolver, StateResolver and Db
// actors. The test holds every validator key, so it delivers real quorum certificates
// through the production IncomingProtocolMessage ingress in an order it controls:
//
//   * the chain is full candidates 1..n+1; P is candidate n and C is candidate n+1 (C names P);
//   * NotarCert(P) is delivered, but its database write is held, so Pool knows it only as a
//     prospective certificate and has not installed it;
//   * SkipCert(P.slot) and NotarCert(C) are delivered and installed (a slot may legally carry
//     both a SkipCert and a NotarCert);
//   * Pool then opens the next leader window on base C -- the point at which a leader calls
//     ResolveState(C) without WaitForParent -- and the test issues exactly that request.
//
// A resolver that lets local skip evidence stand in for the signed parent replaces P with the
// base before P's slot, applies C's Merkle update to state n-1, and aborts with
// "expected old value hash = H(n), applied to value with hash = H(n-1)". A resolver that
// resolves the exact ancestor waits for P, and either produces state n+1 once NotarCert(P)
// is installed or refuses with a bounded error when P can never be obtained.
//
// The peer-consensus mode takes the other ordering and the real caller. A second node holds
// P and NotarCert(P) in its CandidateResolver and has no Pool, so it never gossips the
// certificate; the node under test never receives NotarCert(P) at all. Two skip-certified
// slots separate A from P, so Pool carries A as the available base across a skip run. The
// node under test registers the production Consensus actor: installing NotarCert(C) opens
// its own leader window on C, and Consensus::start_generation(C) resolves the state. A
// resolver that resolves the exact ancestor fetches NotarCert(P) from the peer and starts
// the window on state n+1; the skip shortcut aborts with the same N/N-1 mismatch.
//
// The sibling mode builds two notarized candidates at one height, both naming A: the sibling P'
// on the unfinalized branch and P on the branch a FinalizeCert(C) settles. Two full observer
// nodes receive the certificates in different orders. Both must finalize P and never P', and
// both must resolve C to the same block and state n+1, built on P, even after resolving P'
// first has put the sibling's state in the cache.
//
// The delayed-anchor mode finalizes P while the manager still refuses P's state, as it does
// until the masterchain block that references P is in: the manager serves an older anchor at
// once and P only after release. One observer resolves C while P is late and must reconstruct
// from candidate data; a second observer resolves C after release and must use P's anchor. Both
// must reach the same block and state n+1, and neither may read the older anchor.
//
// Each of these fixtures has a red control: the same file built against a test-only mutant of
// the resolver (make-state-resolver-mutant.py) that takes the skip shortcut, substitutes the
// sibling, or falls back to the start state while the anchor is late.
//
// The source uses only bus events that exist both before and after the exact-ancestor change,
// so the identical file builds against either resolver. Every run prints the preconditions it
// established before triggering resolution; a run whose ordering did not hold stops with
// MERKLE_ACTOR_PRECONDITION_FAILED instead of resolving.

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
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
#include "consensus/simplex/votes.h"
#include "consensus/utils.h"
#include "crypto/pq/consensus-pq-signer.h"
#include "td/actor/BusRuntime.h"
#include "td/actor/coro_utils.h"
#include "tos/quorum.h"
#include "validator/fabric.h"
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

// The state the sibling P' produces at the same height: a different cell, so its Merkle
// update and block differ from P's.
td::Ref<vm::Cell> gen_sibling_state(BlockSeqno seqno) {
  return vm::CellBuilder().store_long(0x51b11a6eU, 32).store_long(seqno, 32).finalize_novm();
}

std::string state_hash_hex(BlockSeqno seqno) {
  return gen_shard_state(seqno)->get_hash().to_hex();
}

std::string sibling_state_hash_hex(BlockSeqno seqno) {
  return gen_sibling_state(seqno)->get_hash().to_hex();
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

[[noreturn]] void precondition_failed(const std::string& reason) {
  finish(1, "MERKLE_ACTOR_PRECONDITION_FAILED: " + reason);
}

[[noreturn]] void test_failed(const std::string& reason) {
  finish(1, "MERKLE_ACTOR_FAILED: " + reason);
}

enum class Mode {
  // Hold NotarCert(P), trigger resolution, then release the write while resolution waits.
  HoldRelease,
  // Hold NotarCert(P) forever and let every peer refuse P: resolution must end in a bounded refusal.
  HoldRefuse,
  // Control: NotarCert(P) is installed before resolution. Both resolvers must produce state n+1.
  NoHold,
  // Gate positive control: the hold is aimed at the wrong slot, so the ordering the test
  // depends on never happens and the harness itself must say so.
  HoldWrongSlot,
  // Two nodes: NotarCert(P) exists only on the peer, and the real Consensus leader path
  // resolves C.
  PeerConsensus,
  // Two observers, two notarized siblings at P's height; FinalizeCert(C) settles P's branch.
  Sibling,
  // Two observers; P is finalized while the manager still withholds its anchor state.
  DelayedAnchor,
};

std::string candidate_id_str(const CandidateId& id) {
  return PSTRING() << "{slot=" << id.slot << ", hash=" << id.hash.to_hex() << "}";
}

// ===== What the test observes on the bus =====

struct Observations {
  std::mutex mutex;
  std::set<CandidateId> notarized;
  std::vector<std::pair<td::uint32, ParentId>> leader_windows;
  std::vector<CandidateId> overlay_requests;
  size_t misbehavior_reports = 0;
  // OurLeaderWindowStarted as published by the node under test.
  struct WindowStarted {
    td::uint32 start_slot = 0;
    ParentId base;
    std::string state_hash;
    BlockSeqno next_seqno = 0;
  };
  std::vector<WindowStarted> windows_started;
  // Requests for P that the peer answered with a notarization certificate.
  size_t peer_served_notar = 0;
  // Written by the database gate.
  size_t held_writes = 0;
  // Candidates this node's StateResolver handed over as finalized blocks.
  std::vector<CandidateId> finalized;
};

// The node under test, and in the two-observer modes the second observer.
Observations observations;
Observations second_observations;
std::atomic<long long> second_node_idx{-1};

Observations& observations_for(const simplex::BusHandle& bus) {
  if (static_cast<long long>(bus->local_id->idx.value()) == second_node_idx.load()) {
    return second_observations;
  }
  return observations;
}

// The database write of NotarCert for this slot waits until `released` is set.
std::atomic<long long> gate_slot{-1};
std::atomic<bool> gate_released{false};
std::atomic<bool> refuse_overlay_requests{false};

// Peer-consensus mode: the node whose CandidateResolver answers the target's requests.
std::mutex peer_mutex;
std::optional<simplex::BusHandle> peer_bus;
std::optional<PeerValidatorId> peer_idx;

// What the test-only mutant resolver consults in the red controls. Unused by the production
// build, which has no hooks.
std::mutex mutant_mutex;
// SkipCerts delivered to the node under test.
std::set<td::uint32> delivered_skips;
// Sibling mode: the exact parent P and the sibling the mutant puts in its place.
std::optional<CandidateId> mutant_exact_parent;
std::optional<CandidateId> mutant_sibling;

bool notarized(const CandidateId& id, Observations& node = observations) {
  std::scoped_lock lock(node.mutex);
  return node.notarized.contains(id);
}

bool finalized(const CandidateId& id, Observations& node = observations) {
  std::scoped_lock lock(node.mutex);
  for (const auto& done : node.finalized) {
    if (done == id) {
      return true;
    }
  }
  return false;
}

size_t held_writes() {
  std::scoped_lock lock(observations.mutex);
  return observations.held_writes;
}

bool overlay_requested(const CandidateId& id, Observations& node = observations) {
  std::scoped_lock lock(node.mutex);
  for (const auto& requested : node.overlay_requests) {
    if (requested == id) {
      return true;
    }
  }
  return false;
}

std::optional<ParentId> leader_window_base(td::uint32 start_slot) {
  std::scoped_lock lock(observations.mutex);
  for (const auto& [slot, base] : observations.leader_windows) {
    if (slot == start_slot) {
      return base;
    }
  }
  return std::nullopt;
}

std::optional<Observations::WindowStarted> window_started(td::uint32 start_slot) {
  std::scoped_lock lock(observations.mutex);
  for (const auto& started : observations.windows_started) {
    if (started.start_slot == start_slot) {
      return started;
    }
  }
  return std::nullopt;
}

size_t peer_served_notar() {
  std::scoped_lock lock(observations.mutex);
  return observations.peer_served_notar;
}

size_t misbehavior_reports(Observations& node = observations) {
  std::scoped_lock lock(node.mutex);
  return node.misbehavior_reports;
}

std::optional<td::int32> held_notar_slot(td::Slice value) {
  auto maybe_vote = fetch_tl_object<tos_api::consensus_simplex_db_Vote>(value, true);
  if (maybe_vote.is_error()) {
    return std::nullopt;
  }
  auto vote = maybe_vote.move_as_ok();
  if (vote->get_id() != tos_api::consensus_simplex_db_cert::ID) {
    return std::nullopt;
  }
  auto& cert = static_cast<tos_api::consensus_simplex_db_cert&>(*vote);
  if (cert.cert_->vote_->get_id() != tos_api::consensus_simplex_notarizeVote::ID) {
    return std::nullopt;
  }
  auto& notarize = static_cast<tos_api::consensus_simplex_notarizeVote&>(*cert.cert_->vote_);
  return notarize.id_->slot_;
}

class GatedDb : public consensus::Db {
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
    auto slot = held_notar_slot(value.as_slice());
    if (slot.has_value() && *slot == gate_slot.load()) {
      {
        std::scoped_lock lock(observations.mutex);
        ++observations.held_writes;
      }
      emit(PSTRING() << "MERKLE_ACTOR_GATE_HELD notar_slot=" << *slot);
      while (!gate_released.load()) {
        co_await td::actor::coro_sleep(td::Timestamp::in(0.005));
      }
      emit(PSTRING() << "MERKLE_ACTOR_GATE_RELEASED notar_slot=" << *slot);
    }
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

class ObserverActor : public td::actor::SpawnsWith<simplex::Bus>, public td::actor::ConnectsTo<simplex::Bus> {
 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();

  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const StopRequested>) {
    stop();
  }

  template <>
  void handle(simplex::BusHandle bus, std::shared_ptr<const simplex::NotarizationObserved> event) {
    auto& node = observations_for(bus);
    std::scoped_lock lock(node.mutex);
    node.notarized.insert(event->id);
  }

  template <>
  void handle(simplex::BusHandle bus, std::shared_ptr<const simplex::LeaderWindowObserved> event) {
    auto& node = observations_for(bus);
    std::scoped_lock lock(node.mutex);
    node.leader_windows.emplace_back(event->start_slot, event->base);
  }

  template <>
  void handle(simplex::BusHandle bus, std::shared_ptr<const MisbehaviorReport>) {
    auto& node = observations_for(bus);
    std::scoped_lock lock(node.mutex);
    ++node.misbehavior_reports;
  }

  // Stands in for the block accepter: records which candidates the resolver finalized.
  template <>
  td::actor::Task<> process(simplex::BusHandle bus, std::shared_ptr<FinalizeBlock> event) {
    emit(PSTRING() << "MERKLE_ACTOR_FINALIZED node=" << bus->local_id->idx.value() << " id="
                   << candidate_id_str(event->candidate->id) << " block=" << event->candidate->block_id().to_str());
    auto& node = observations_for(bus);
    std::scoped_lock lock(node.mutex);
    node.finalized.push_back(event->candidate->id);
    co_return td::Unit{};
  }

  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const OurLeaderWindowStarted> event) {
    Observations::WindowStarted started{.start_slot = event->start_slot,
                                        .base = event->base,
                                        .state_hash = event->state->state().at(0)->get_hash().to_hex(),
                                        .next_seqno = event->state->next_seqno()};
    emit(PSTRING() << "MERKLE_ACTOR_WINDOW_STARTED start_slot=" << started.start_slot
                   << " next_seqno=" << started.next_seqno << " state=" << started.state_hash);
    std::scoped_lock lock(observations.mutex);
    observations.windows_started.push_back(std::move(started));
  }
};

bool response_has_notar(const ProtocolMessage& response) {
  auto decoded = fetch_tl_object<tos_api::consensus_simplex_candidateAndCert>(response.data, true);
  return decoded.is_ok() && !decoded.ok()->notar_.empty();
}

// Stands in for the private overlay. Nothing is broadcast anywhere; candidate requests are
// recorded, then either left unanswered until their own timeout or refused at once.
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
  td::actor::Task<ProtocolMessage> process(simplex::BusHandle bus, std::shared_ptr<OutgoingOverlayRequest> message) {
    std::optional<simplex::BusHandle> peer;
    {
      std::scoped_lock lock(peer_mutex);
      if (peer_idx.has_value() && bus->local_id->idx == *peer_idx) {
        co_return td::Status::Error(ErrorCode::failure, "the peer makes no requests in this test");
      }
      peer = peer_bus;
    }
    auto request = fetch_tl_object<tos_api::consensus_simplex_requestCandidate>(message->request.data, true);
    if (request.is_ok()) {
      auto id = CandidateId::from_tl(request.ok()->id_);
      emit(PSTRING() << "MERKLE_ACTOR_OVERLAY_REQUEST id=" << candidate_id_str(id) << " want_candidate="
                     << request.ok()->want_candidate_ << " want_notar=" << request.ok()->want_notar_);
      auto& node = observations_for(bus);
      std::scoped_lock lock(node.mutex);
      node.overlay_requests.push_back(id);
    }
    if (peer.has_value()) {
      // Every request goes to the one peer, so which node serves P is not left to chance.
      auto forwarded = std::make_shared<IncomingOverlayRequest>(bus->local_id->idx, bus->local_adnl_id,
                                                                ProtocolMessage{message->request.data.clone()});
      auto response = co_await peer->publish(std::move(forwarded)).wrap();
      if (response.is_ok() && request.is_ok() && response_has_notar(response.ok())) {
        emit(PSTRING() << "MERKLE_ACTOR_PEER_SERVED_NOTAR id="
                       << candidate_id_str(CandidateId::from_tl(request.ok()->id_)));
        std::scoped_lock lock(observations.mutex);
        ++observations.peer_served_notar;
      }
      co_return response;
    }
    if (refuse_overlay_requests.load()) {
      co_return ProtocolMessage{create_serialize_tl_object<tos_api::consensus_requestError>()};
    }
    co_await td::actor::coro_sleep(message->timeout);
    co_return td::Status::Error(ErrorCode::timeout, "no peer answered");
  }
};

// Shard states the manager can serve beyond the zerostate, keyed by the exact block id. A
// delayed anchor is refused with notready until it is released, which is how the manager
// answers for a finalized block whose masterchain reference has not arrived yet.
struct ManagerAnchors {
  struct Anchor {
    td::Ref<vm::Cell> state;
    td::Ref<BlockData> data;
    bool delayed = false;
  };
  struct Request {
    size_t node = 0;
    BlockIdExt block;
    bool served = false;
  };
  std::mutex mutex;
  std::map<BlockIdExt, Anchor> anchors;
  bool released = false;
  std::vector<Request> requests;

  // nullopt: not available (absent, or delayed and not yet released).
  std::optional<Anchor> lookup(const BlockIdExt& block) {
    std::scoped_lock lock(mutex);
    auto it = anchors.find(block);
    if (it != anchors.end() && (!it->second.delayed || released)) {
      return it->second;
    }
    return std::nullopt;
  }

  void record(size_t node, const BlockIdExt& block, bool served) {
    emit(PSTRING() << "MERKLE_ACTOR_MANAGER_STATE node=" << node << " block=" << block.to_str()
                   << " served=" << (served ? "yes" : "no"));
    std::scoped_lock lock(mutex);
    requests.push_back(Request{.node = node, .block = block, .served = served});
  }

  void release() {
    std::scoped_lock lock(mutex);
    released = true;
  }

  std::vector<Request> requests_of(size_t node) {
    std::scoped_lock lock(mutex);
    std::vector<Request> result;
    for (const auto& request : requests) {
      if (request.node == node) {
        result.push_back(request);
      }
    }
    return result;
  }
};

class StaticManager : public ManagerFacade {
 public:
  StaticManager() = default;
  StaticManager(size_t node, std::shared_ptr<ManagerAnchors> anchors) : node_(node), anchors_(std::move(anchors)) {
  }

  td::actor::Task<GeneratedCandidate> collate_block(CollateParams, td::CancellationToken) override {
    co_return td::Status::Error("this node does not collate");
  }

  td::actor::Task<ValidateCandidateResult> validate_block_candidate(BlockCandidate, ValidateParams,
                                                                    td::Timestamp) override {
    co_return td::Status::Error("this node does not validate");
  }

  td::actor::Task<> accept_block(BlockIdExt, td::Ref<BlockData>, size_t, td::Ref<block::BlockSignatureSet>,
                                 ValidatorSessionId, int, int, bool, bool) override {
    co_return td::Status::Error("this node does not accept blocks");
  }

  // Without anchors only the zerostate is available from the manager: the whole chain above
  // it must be replayed from candidate data, which is the path under test.
  td::actor::Task<td::Ref<vm::Cell>> wait_block_state_root(BlockIdExt block_id, td::Timestamp,
                                                           std::optional<CandidateId>) override {
    std::optional<ManagerAnchors::Anchor> anchor;
    if (anchors_) {
      anchor = anchors_->lookup(block_id);
      anchors_->record(node_, block_id, anchor.has_value() || block_id == FIRST_PARENT);
    }
    if (anchor.has_value()) {
      co_return anchor->state;
    }
    if (block_id == FIRST_PARENT) {
      co_return gen_shard_state(0);
    }
    co_return td::Status::Error(ErrorCode::notready, "only the zerostate is available");
  }

  td::actor::Task<td::Ref<BlockData>> wait_block_data(BlockIdExt block_id, td::Timestamp) override {
    if (anchors_) {
      if (auto anchor = anchors_->lookup(block_id)) {
        co_return anchor->data;
      }
    }
    co_return td::Status::Error(ErrorCode::notready, "no block data is available");
  }

 private:
  size_t node_ = 0;
  std::shared_ptr<ManagerAnchors> anchors_;
};

// A full candidate whose Merkle update moves state `seqno - 1` to `seqno`, laid out exactly as
// the consensus fixture's collator lays out blocks.
BlockCandidate make_block(BlockSeqno seqno, const BlockIdExt& prev, bool sibling = false) {
  BlockSeqno prev_seqno = seqno - 1;
  double gen_utime = 1'700'000'000.0 + seqno + (sibling ? 0.5 : 0.0);

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
  td::Ref<vm::Cell> merkle_update = vm::CellBuilder::create_merkle_update(
      gen_shard_state(prev_seqno), sibling ? gen_sibling_state(seqno) : gen_shard_state(seqno));
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

struct ResolutionOutcome {
  std::mutex mutex;
  std::optional<td::Result<simplex::ResolveState::Result>> result;
};

class Driver : public td::actor::Actor {
 public:
  Driver(Mode mode, BlockSeqno n) : mode_(mode), n_(n) {
  }

  td::actor::Task<> run() {
    auto result = co_await run_inner().wrap();
    if (result.is_error()) {
      test_failed(result.error().to_string());
    }
    co_return td::Unit{};
  }

 private:
  Mode mode_;
  BlockSeqno n_;
  std::vector<std::shared_ptr<const tos::pq::ValidatorPQKeyStore>> signers_;
  td::actor::Runtime runtime_;
  td::actor::ActorOwn<StaticManager> manager_;
  td::actor::Runtime peer_runtime_;
  td::actor::ActorOwn<StaticManager> peer_manager_;
  simplex::BusHandle peer_bus_;
  simplex::BusHandle bus_;
  std::shared_ptr<simplex::Bus> bus_ptr_;
  // candidates_[k] is the full candidate producing state k (index 0 unused).
  std::vector<CandidateRef> candidates_;
  // Sibling mode: P', the second notarized candidate at P's height, also naming A.
  CandidateRef sibling_;
  // Two-observer modes: the second full node and the manager anchors both nodes read.
  std::shared_ptr<ManagerAnchors> anchors_;
  td::actor::Runtime second_runtime_;
  td::actor::ActorOwn<StaticManager> second_manager_;
  simplex::BusHandle second_bus_;

  bool two_observers() const {
    return mode_ == Mode::Sibling || mode_ == Mode::DelayedAnchor;
  }

  // Skip-certified slots between A and P. The peer-consensus mode puts a skip run there so
  // that Pool has to carry A as the available base across it; the sibling mode puts P' there.
  td::uint32 gap() const {
    switch (mode_) {
      case Mode::PeerConsensus:
        return 2;
      case Mode::Sibling:
        return 1;
      case Mode::HoldRelease:
      case Mode::HoldRefuse:
      case Mode::NoHold:
      case Mode::HoldWrongSlot:
      case Mode::DelayedAnchor:
        return 0;
    }
    return 0;
  }

  td::uint32 slot_of(BlockSeqno seqno) const {
    // Candidates 1..n-1 sit at consecutive slots after `offset` leading skipped slots; P follows
    // A after gap() skipped slots and C follows P. The offset puts C at the last slot of a
    // leader window, so that installing NotarCert(C) opens the next window on base C. In the
    // sibling mode it puts P at the first slot of a window instead, so that P and its sibling
    // in the slot before come from different leaders' windows.
    td::uint32 offset =
        mode_ == Mode::Sibling
            ? (SLOTS_PER_LEADER_WINDOW - n_ % SLOTS_PER_LEADER_WINDOW) % SLOTS_PER_LEADER_WINDOW
            : (SLOTS_PER_LEADER_WINDOW - (n_ + gap() + 1) % SLOTS_PER_LEADER_WINDOW) % SLOTS_PER_LEADER_WINDOW;
    return seqno - 1 + offset + (seqno >= n_ ? gap() : 0);
  }

  td::BufferSlice sign(size_t signer, td::Slice inner) const {
    auto envelope =
        create_serialize_tl_object<tos_api::consensus_dataToSign>(bus_ptr_->session_id, td::BufferSlice(inner));
    auto signature =
        signers_.at(signer)->sign_consensus(std::string_view(envelope.as_slice().data(), envelope.as_slice().size()));
    CHECK(signature.has_value());
    return td::BufferSlice(signature->signature);
  }

  template <typename T>
  simplex::CertificateRef<T> make_certificate(const T& vote, const std::vector<size_t>& signers) const {
    auto inner = serialize_tl_object(vote.to_tl(), true);
    std::vector<simplex::tl::VoteSignatureRef> signatures;
    for (size_t i : signers) {
      signatures.push_back(
          create_tl_object<simplex::tl::voteSignature>(static_cast<td::int32>(i), sign(i, inner.as_slice())));
    }
    auto set = create_tl_object<simplex::tl::voteSignatureSet>(std::move(signatures));
    auto cert = simplex::Certificate<T>::from_tl(std::move(*set), vote, *bus_ptr_);
    CHECK(cert.is_ok());
    return cert.move_as_ok();
  }

  template <typename T>
  td::BufferSlice certificate(const T& vote, const std::vector<size_t>& signers) const {
    return make_certificate(vote, signers)->serialize();
  }

  void deliver_to(simplex::BusHandle& bus, td::BufferSlice message, size_t source) {
    const auto& peer = bus_ptr_->validator_set.at(source);
    bus.publish<IncomingProtocolMessage>(peer.idx, peer.adnl_id, ProtocolMessage{std::move(message)});
  }

  void deliver(td::BufferSlice message, size_t source) {
    deliver_to(bus_, std::move(message), source);
  }

  void deliver_notar_to(simplex::BusHandle& bus, const CandidateRef& candidate) {
    deliver_to(bus, certificate(simplex::NotarizeVote{candidate->id}, {0, 1, 2}), 0);
  }

  void deliver_notar(BlockSeqno seqno) {
    deliver_notar_to(bus_, candidates_.at(seqno));
  }

  void deliver_skip_to(simplex::BusHandle& bus, td::uint32 slot) {
    // Validators 1 and 2 signed both the notarization and the skip of P's slot, which the
    // protocol allows: only a finalize vote conflicts with a skip vote.
    deliver_to(bus, certificate(simplex::SkipVote{slot}, {1, 2, 3}), 3);
  }

  void deliver_skip(td::uint32 slot) {
    {
      std::scoped_lock lock(mutant_mutex);
      delivered_skips.insert(slot);
    }
    deliver_skip_to(bus_, slot);
  }

  void deliver_final_to(simplex::BusHandle& bus, const CandidateRef& candidate) {
    deliver_to(bus, certificate(simplex::FinalizeVote{candidate->id}, {0, 1, 2}), 0);
  }

  // Leading skips and NotarCerts of candidates 1..n-1, each installed before the next.
  td::actor::Task<> notarize_prefix(simplex::BusHandle& bus, Observations& node) {
    for (td::uint32 slot = 0; slot < slot_of(1); ++slot) {
      deliver_skip_to(bus, slot);
    }
    for (BlockSeqno seqno = 1; seqno + 1 <= n_; ++seqno) {
      deliver_notar_to(bus, candidates_[seqno]);
      if (!co_await wait_until([&] { return notarized(candidates_[seqno]->id, node); })) {
        precondition_failed(PSTRING() << "NotarCert of candidate " << seqno << " was never installed");
      }
    }
    co_return td::Unit{};
  }

  td::actor::Task<> notarize(simplex::BusHandle& bus, Observations& node, const CandidateRef& candidate,
                             const char* name) {
    deliver_notar_to(bus, candidate);
    if (!co_await wait_until([&] { return notarized(candidate->id, node); })) {
      precondition_failed(PSTRING() << "NotarCert(" << name << ") was never installed");
    }
    co_return td::Unit{};
  }

  td::actor::Task<> finalize(simplex::BusHandle& bus, Observations& node, const CandidateRef& candidate,
                             const char* name) {
    deliver_final_to(bus, candidate);
    if (!co_await wait_until([&] { return finalized(candidate->id, node); })) {
      precondition_failed(PSTRING() << "FinalizeCert(" << name << ") did not finalize it");
    }
    co_return td::Unit{};
  }

  // Resolves `id` on `bus` and returns the outcome, or fails the test if it never finishes.
  td::actor::Task<td::Ref<ChainState>> resolve_on(simplex::BusHandle bus, ParentId id, const char* what) {
    auto outcome = std::make_shared<ResolutionOutcome>();
    [](simplex::BusHandle bus, ParentId id, std::shared_ptr<ResolutionOutcome> out) -> td::actor::Task<> {
      auto result = co_await bus.publish<simplex::ResolveState>(id).wrap();
      std::scoped_lock lock(out->mutex);
      out->result = std::move(result);
      co_return td::Unit{};
    }(bus, id, outcome)
                                                                                           .start()
                                                                                           .detach();
    if (!co_await wait_until([outcome] {
          std::scoped_lock lock(outcome->mutex);
          return outcome->result.has_value();
        })) {
      test_failed(PSTRING() << "resolution of " << what << " did not finish");
    }
    std::scoped_lock lock(outcome->mutex);
    auto result = std::move(*outcome->result);
    if (result.is_error()) {
      test_failed(PSTRING() << "resolution of " << what << " failed: " << result.error());
    }
    co_return result.move_as_ok().state;
  }

  // The resolved state must name exactly `block` and hold `root`.
  static std::string require_state(const td::Ref<ChainState>& state, const BlockIdExt& block, const std::string& root,
                                   const char* what) {
    auto ids = state->block_ids();
    auto got = state->state().at(0)->get_hash().to_hex();
    if (ids.size() != 1 || ids[0] != block || got != root) {
      test_failed(PSTRING() << what << " resolved to " << (ids.empty() ? std::string("nothing") : ids[0].to_str())
                            << " with state " << got << "; expected " << block.to_str() << " with state " << root);
    }
    return got;
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

  // The node under test is the leader of the window that opens on C, i.e. the node whose
  // Consensus would call ResolveState(C) from start_generation.
  size_t target() const {
    return (slot_of(n_ + 1) + 1) / SLOTS_PER_LEADER_WINDOW % VALIDATORS;
  }

  // Peer-consensus mode: the one node the target can fetch P from.
  size_t peer() const {
    return (target() + 1) % VALIDATORS;
  }

  // Two-observer modes: the second full node.
  size_t second() const {
    return (target() + 1) % VALIDATORS;
  }

  std::shared_ptr<simplex::Bus> make_bus(const std::vector<PeerValidator>& validators, ValidatorWeight total_weight,
                                         size_t local, td::actor::ActorId<StaticManager> manager) const {
    auto bus = std::make_shared<simplex::Bus>();
    bus->shard = SHARD;
    bus->manager = manager;
    bus->pq_signer = signers_.at(local);
    bus->validator_set = validators;
    std::set<adnl::AdnlNodeIdShort> current_relays;
    for (const auto& validator : validators) {
      bus->all_validators.push_back(validator.adnl_id);
      current_relays.insert(validator.adnl_id);
    }
    bus->all_current_validators = std::move(current_relays);
    bus->total_weight = total_weight;
    bus->local_id = validators.at(local);
    bus->local_adnl_id = validators.at(local).adnl_id;
    bus->config = NewConsensusConfig{
        .max_block_size = 1 << 20,
        .max_collated_data_size = 1 << 20,
        .protocol_version = 2,
        .slots_per_leader_window = SLOTS_PER_LEADER_WINDOW,
    };
    // Every skip in the scenario is a certificate the test delivers. Nothing may time out
    // into a vote of the node's own while the scenario runs.
    bus->config.noncritical_params.first_block_timeout = std::chrono::milliseconds(600'000);
    bus->config.noncritical_params.standstill_timeout = std::chrono::milliseconds(600'000);
    bus->session_id = fill(0x42);
    bus->cc_seqno = CC_SEQNO;
    bus->validator_set_hash = 0;
    bus->db = std::make_unique<GatedDb>();
    return bus;
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
    runtime_.register_actor<ObserverActor>("MerkleObserver");
    simplex::CandidateResolver::register_in(runtime_);
    simplex::Pool::register_in(runtime_);
    simplex::StateResolver::register_in(runtime_);
    simplex::Db::register_in(runtime_);
    if (mode_ == Mode::PeerConsensus) {
      simplex::Consensus::register_in(runtime_);
    }
    simplex::DefaultCollatorSchedule::provide_for(runtime_);

    if (mode_ == Mode::PeerConsensus) {
      // The peer only answers candidate requests. Without a Pool it never gossips a
      // certificate, so NotarCert(P) cannot reach the target by any other path.
      peer_runtime_.register_actor<OverlayStub>("PrivateOverlay");
      simplex::CandidateResolver::register_in(peer_runtime_);
      simplex::Db::register_in(peer_runtime_);
      simplex::DefaultCollatorSchedule::provide_for(peer_runtime_);
      peer_manager_ = td::actor::create_actor<StaticManager>("PeerManager");
      auto peer = make_bus(validators, total_weight, this->peer(), peer_manager_.get());
      peer_bus_ = peer_runtime_.start(std::static_pointer_cast<simplex::Bus>(peer), "merkle-peer");
      peer_bus_.publish<Start>(
          td::make_ref<ChainState>(ChainState::ZerostateTip{FIRST_PARENT, gen_shard_state(0)}, MIN_MC_BLOCK_ID));
      std::scoped_lock lock(peer_mutex);
      peer_bus = peer_bus_;
      peer_idx = validators.at(this->peer()).idx;
    }

    if (two_observers()) {
      // A second full node: the same production actors, its own database and manager.
      anchors_ = std::make_shared<ManagerAnchors>();
      second_runtime_.register_actor<OverlayStub>("PrivateOverlay");
      second_runtime_.register_actor<ObserverActor>("MerkleObserver");
      simplex::CandidateResolver::register_in(second_runtime_);
      simplex::Pool::register_in(second_runtime_);
      simplex::StateResolver::register_in(second_runtime_);
      simplex::Db::register_in(second_runtime_);
      simplex::DefaultCollatorSchedule::provide_for(second_runtime_);
      second_node_idx = static_cast<long long>(second());
      second_manager_ = td::actor::create_actor<StaticManager>("SecondManager", second(), anchors_);
      auto second_ptr = make_bus(validators, total_weight, second(), second_manager_.get());
      second_bus_ = second_runtime_.start(std::static_pointer_cast<simplex::Bus>(second_ptr), "merkle-second");
      second_bus_.publish<Start>(
          td::make_ref<ChainState>(ChainState::ZerostateTip{FIRST_PARENT, gen_shard_state(0)}, MIN_MC_BLOCK_ID));
      manager_ = td::actor::create_actor<StaticManager>("StaticManager", target(), anchors_);
    } else {
      manager_ = td::actor::create_actor<StaticManager>("StaticManager");
    }
    auto bus = make_bus(validators, total_weight, target(), manager_.get());
    bus_ptr_ = bus;
    bus_ = runtime_.start(std::static_pointer_cast<simplex::Bus>(bus), "merkle-target");
    bus_.publish<Start>(
        td::make_ref<ChainState>(ChainState::ZerostateTip{FIRST_PARENT, gen_shard_state(0)}, MIN_MC_BLOCK_ID));
  }

  void build_chain() {
    candidates_.resize(n_ + 2);
    ParentId parent;
    BlockIdExt prev = FIRST_PARENT;
    for (BlockSeqno seqno = 1; seqno <= n_ + 1; ++seqno) {
      auto block = make_block(seqno, prev);
      prev = block.id;
      td::uint32 slot = slot_of(seqno);
      auto id = CandidateHashData::create_full(block, parent).build_id_with(slot);
      auto leader = bus_ptr_->collator_schedule->expected_collator_for(slot);
      auto signature = sign(leader.value(), serialize_tl_object(id.to_tl(), true).as_slice());
      candidates_[seqno] = td::make_ref<Candidate>(id, parent, leader, std::move(block), std::move(signature));
      parent = id;
    }
    if (mode_ == Mode::Sibling) {
      // P' sits in the gap slot just before P, at P's height, and also names A.
      const auto& A = candidates_.at(n_ - 1);
      auto block = make_block(n_, A->block_id(), true);
      td::uint32 slot = slot_of(n_) - 1;
      auto id = CandidateHashData::create_full(block, A->id).build_id_with(slot);
      auto leader = bus_ptr_->collator_schedule->expected_collator_for(slot);
      auto signature = sign(leader.value(), serialize_tl_object(id.to_tl(), true).as_slice());
      sibling_ = td::make_ref<Candidate>(id, ParentId{A->id}, leader, std::move(block), std::move(signature));
    }
  }

  td::actor::Task<> run_inner() {
    start_node();
    build_chain();
    const auto& A = candidates_.at(n_ - 1);
    const auto& P = candidates_.at(n_);
    const auto& C = candidates_.at(n_ + 1);
    CHECK(C->parent_id == P->id && P->parent_id == A->id);
    emit(PSTRING() << "MERKLE_ACTOR_CHAIN n=" << n_ << " A=" << candidate_id_str(A->id)
                   << " P=" << candidate_id_str(P->id) << " C=" << candidate_id_str(C->id)
                   << " C_block=" << C->block_id().to_str());
    emit(PSTRING() << "MERKLE_ACTOR_BLOCKS A_block=" << A->block_id().to_str()
                   << " P_block=" << P->block_id().to_str());

    for (BlockSeqno seqno = 1; seqno <= n_ + 1; ++seqno) {
      co_await bus_.publish<simplex::StoreCandidate>(candidates_[seqno]);
    }
    if (mode_ == Mode::PeerConsensus) {
      co_return co_await run_peer_consensus();
    }
    if (two_observers()) {
      for (BlockSeqno seqno = 1; seqno <= n_ + 1; ++seqno) {
        co_await second_bus_.publish<simplex::StoreCandidate>(candidates_[seqno]);
      }
      if (mode_ == Mode::Sibling) {
        co_await bus_.publish<simplex::StoreCandidate>(sibling_);
        co_await second_bus_.publish<simplex::StoreCandidate>(sibling_);
        co_return co_await run_sibling();
      }
      co_return co_await run_delayed_anchor();
    }

    for (td::uint32 slot = 0; slot < slot_of(1); ++slot) {
      deliver_skip(slot);
    }
    for (BlockSeqno seqno = 1; seqno + 1 <= n_; ++seqno) {
      deliver_notar(seqno);
      if (!co_await wait_until([&] { return notarized(candidates_[seqno]->id); })) {
        precondition_failed(PSTRING() << "NotarCert of candidate " << seqno << " was never installed");
      }
    }

    switch (mode_) {
      case Mode::HoldRelease:
      case Mode::HoldRefuse:
        gate_slot = P->id.slot;
        break;
      case Mode::HoldWrongSlot:
        gate_slot = static_cast<long long>(P->id.slot) + 1000;
        break;
      case Mode::NoHold:
      case Mode::PeerConsensus:
      case Mode::Sibling:
      case Mode::DelayedAnchor:
        break;
    }
    refuse_overlay_requests = mode_ == Mode::HoldRefuse;

    deliver_notar(n_);
    if (mode_ == Mode::NoHold) {
      if (!co_await wait_until([&] { return notarized(P->id); })) {
        precondition_failed("control run: NotarCert(P) was never installed");
      }
    } else if (!co_await wait_until([&] { return held_writes() == 1; }, 2.0)) {
      precondition_failed("NotarCert(P) write was not held");
    }

    deliver_skip(P->id.slot);
    deliver_notar(n_ + 1);
    td::uint32 next_window = C->id.slot + 1;
    CHECK(next_window % SLOTS_PER_LEADER_WINDOW == 0);
    if (!co_await wait_until([&] { return leader_window_base(next_window).has_value(); })) {
      precondition_failed(PSTRING() << "no leader window was opened at slot " << next_window);
    }
    auto base = *leader_window_base(next_window);
    if (base != ParentId{C->id}) {
      precondition_failed(PSTRING() << "leader window " << next_window << " opened on " << base << ", not on C");
    }
    if (!notarized(C->id)) {
      precondition_failed("NotarCert(C) is not installed");
    }
    const bool p_installed = notarized(P->id);
    if (mode_ == Mode::NoHold) {
      if (!p_installed) {
        precondition_failed("control run: NotarCert(P) is not installed");
      }
    } else {
      if (p_installed || held_writes() != 1) {
        precondition_failed("NotarCert(P) was installed before resolution");
      }
      if (overlay_requested(P->id)) {
        precondition_failed("P was requested before resolution was triggered");
      }
    }
    if (misbehavior_reports() != 0) {
      precondition_failed("the certificate history was reported as misbehavior");
    }
    auto collator = bus_ptr_->collator_schedule->expected_collator_for(next_window);
    if (collator != bus_ptr_->local_id->idx) {
      precondition_failed(PSTRING() << "the node under test is not the leader of window " << next_window);
    }
    emit(PSTRING() << "MERKLE_ACTOR_PRECONDITION leader_window=" << next_window << " base=C leader=local"
                   << " skip_cert_P_slot=installed notar_cert_C=installed notar_cert_P="
                   << (p_installed ? "installed" : "held_prospective") << " misbehavior=0");
    emit(PSTRING() << "MERKLE_ACTOR_EXPECT stale_base_would_fail_with expected_old=" << state_hash_hex(n_)
                   << " applied_to=" << state_hash_hex(n_ - 1));

    // What a leader of this window does: resolve the state of its base, with no WaitForParent.
    emit("MERKLE_ACTOR_TRIGGER ResolveState(C)");
    auto outcome = std::make_shared<ResolutionOutcome>();
    [](simplex::BusHandle bus, CandidateId id, std::shared_ptr<ResolutionOutcome> out) -> td::actor::Task<> {
      auto result = co_await bus.publish<simplex::ResolveState>(ParentId{id}).wrap();
      std::scoped_lock lock(out->mutex);
      out->result = std::move(result);
      co_return td::Unit{};
    }(bus_, C->id, outcome)
                                                                                              .start()
                                                                                              .detach();
    auto finished = [outcome] {
      std::scoped_lock lock(outcome->mutex);
      return outcome->result.has_value();
    };
    auto take = [outcome] {
      std::scoped_lock lock(outcome->mutex);
      return std::move(*outcome->result);
    };

    switch (mode_) {
      case Mode::NoHold: {
        if (!co_await wait_until(finished)) {
          test_failed("control resolution did not finish");
        }
        check_state(take(), "MERKLE_ACTOR_CONTROL_OK");
      }
      case Mode::HoldRelease: {
        if (!co_await wait_until([&] { return overlay_requested(P->id) || finished(); })) {
          test_failed("resolution neither finished nor asked for the exact ancestor P");
        }
        if (finished()) {
          auto early = take();
          test_failed(PSTRING() << "resolution finished while NotarCert(P) was held: "
                                << (early.is_ok() ? std::string("ok") : early.error().to_string()));
        }
        // Resolution is parked on P. Give it time to do anything else it might do.
        co_await td::actor::coro_sleep(td::Timestamp::in(0.3));
        if (finished()) {
          test_failed("resolution finished while NotarCert(P) was held");
        }
        emit(PSTRING() << "MERKLE_ACTOR_WAITING_ON_EXACT_ANCESTOR P=" << candidate_id_str(P->id));
        gate_released = true;
        if (!co_await wait_until(finished)) {
          test_failed("resolution did not finish after NotarCert(P) was released");
        }
        if (!notarized(P->id)) {
          test_failed("NotarCert(P) was not installed after release");
        }
        check_state(take(), "MERKLE_ACTOR_GREEN");
      }
      case Mode::HoldRefuse: {
        if (!co_await wait_until(finished, 60.0)) {
          test_failed("resolution of an unobtainable exact ancestor did not end");
        }
        auto result = take();
        if (result.is_ok()) {
          test_failed(PSTRING() << "resolution succeeded without P; state root "
                                << result.ok().state->state().at(0)->get_hash().to_hex());
        }
        auto error = result.move_as_error();
        auto message = error.message().str();
        if (error.code() != ErrorCode::notready || message.find("cannot resolve exact ancestor") == std::string::npos ||
            !overlay_requested(P->id)) {
          test_failed(PSTRING() << "unexpected refusal: " << error);
        }
        finish(0, PSTRING() << "MERKLE_ACTOR_GREEN_BOUNDED error=" << error);
      }
      case Mode::HoldWrongSlot:
        test_failed("the misaimed gate reached resolution");
      case Mode::PeerConsensus:
        test_failed("the peer-consensus scenario ran the single-node path");
      case Mode::Sibling:
      case Mode::DelayedAnchor:
        test_failed("a two-observer scenario ran the single-node path");
    }
    co_return td::Unit{};
  }

  // Asks the peer for NotarCert(P) the way a third validator would, so the target's own
  // request budget at the peer is untouched.
  td::actor::Task<bool> peer_serves_notar(const CandidateId& id) {
    const auto& asker = bus_ptr_->validator_set.at((target() + 2) % VALIDATORS);
    auto request = create_serialize_tl_object<tos_api::consensus_simplex_requestCandidate>(id.to_tl(), false, true);
    auto response = co_await peer_bus_
                        .publish(std::make_shared<IncomingOverlayRequest>(asker.idx, asker.adnl_id,
                                                                          ProtocolMessage{std::move(request)}))
                        .wrap();
    co_return response.is_ok() && response_has_notar(response.ok());
  }

  td::actor::Task<> run_peer_consensus() {
    const auto& A = candidates_.at(n_ - 1);
    const auto& P = candidates_.at(n_);
    const auto& C = candidates_.at(n_ + 1);

    // The peer holds every candidate and its notarization, delivered straight to its
    // CandidateResolver.
    for (BlockSeqno seqno = 1; seqno <= n_ + 1; ++seqno) {
      co_await peer_bus_.publish<simplex::StoreCandidate>(candidates_[seqno]);
      peer_bus_.publish<simplex::NotarizationObserved>(
          candidates_[seqno]->id, make_certificate(simplex::NotarizeVote{candidates_[seqno]->id}, {0, 1, 2}));
    }
    // The preload is consumed asynchronously. Poll below the peer's per-source rate limit.
    bool peer_ready = false;
    for (int attempt = 0; attempt < 40 && !peer_ready; ++attempt) {
      peer_ready = co_await peer_serves_notar(P->id);
      if (!peer_ready) {
        co_await td::actor::coro_sleep(td::Timestamp::in(0.15));
      }
    }
    if (!peer_ready) {
      precondition_failed("the peer cannot serve NotarCert(P)");
    }

    for (td::uint32 slot = 0; slot < slot_of(1); ++slot) {
      deliver_skip(slot);
    }
    for (BlockSeqno seqno = 1; seqno + 1 <= n_; ++seqno) {
      deliver_notar(seqno);
      if (!co_await wait_until([&] { return notarized(candidates_[seqno]->id); })) {
        precondition_failed(PSTRING() << "NotarCert of candidate " << seqno << " was never installed");
      }
    }
    for (td::uint32 slot = A->id.slot + 1; slot <= P->id.slot; ++slot) {
      deliver_skip(slot);
    }
    // Pool cannot open the window after C until P's slot is skip-certified, so a window
    // started on C below also proves SkipCert(P.slot) was installed first.
    if (notarized(P->id) || overlay_requested(P->id) || misbehavior_reports() != 0) {
      precondition_failed("P was notarized, requested or disputed before C");
    }
    auto skip_run = P->id.slot - A->id.slot - 1;
    emit(PSTRING() << "MERKLE_ACTOR_PEER_PRECONDITION peer_serves_notar_P=yes target_notar_cert_P=absent"
                   << " skip_run=" << skip_run);
    emit(PSTRING() << "MERKLE_ACTOR_EXPECT stale_base_would_fail_with expected_old=" << state_hash_hex(n_)
                   << " applied_to=" << state_hash_hex(n_ - 1));

    // Nothing else is needed: installing NotarCert(C) opens this node's leader window on C,
    // and Consensus::start_generation(C) resolves the state.
    emit("MERKLE_ACTOR_TRIGGER NotarCert(C) -> Consensus::start_generation(C)");
    deliver_notar(n_ + 1);
    td::uint32 next_window = C->id.slot + 1;
    if (!co_await wait_until([&] { return window_started(next_window).has_value(); }, 60.0)) {
      test_failed(PSTRING() << "the leader window at " << next_window << " never started");
    }
    auto started = *window_started(next_window);
    auto base = leader_window_base(next_window);
    if (!base.has_value() || *base != ParentId{C->id} || started.base != ParentId{C->id}) {
      test_failed("the leader window did not start on C");
    }
    if (bus_ptr_->collator_schedule->expected_collator_for(next_window) != bus_ptr_->local_id->idx) {
      test_failed("the node under test is not the leader of the window");
    }
    if (!overlay_requested(P->id) || peer_served_notar() == 0) {
      test_failed("the target never obtained NotarCert(P) from the peer");
    }
    if (notarized(P->id)) {
      test_failed("the target's Pool installed NotarCert(P); the peer-only ordering did not hold");
    }
    if (misbehavior_reports() != 0) {
      test_failed("a misbehavior report was published");
    }
    if (started.state_hash != state_hash_hex(n_ + 1) || started.next_seqno != n_ + 2) {
      test_failed(PSTRING() << "the window started on state " << started.state_hash << " with next seqno "
                            << started.next_seqno);
    }
    finish(0,
           PSTRING() << "MERKLE_ACTOR_PEER_GREEN state=" << started.state_hash << " next_seqno=" << started.next_seqno);
  }

  bool manager_asked(size_t node, const BlockIdExt& block) const {
    for (const auto& request : anchors_->requests_of(node)) {
      if (request.block == block) {
        return true;
      }
    }
    return false;
  }

  td::actor::Task<> run_sibling() {
    const auto& A = candidates_.at(n_ - 1);
    const auto& P = candidates_.at(n_);
    const auto& C = candidates_.at(n_ + 1);
    const auto& S = sibling_;
    CHECK(S->parent_id == A->id && P->parent_id == A->id && C->parent_id == P->id);
    CHECK(S->id.slot + 1 == P->id.slot && P->id.slot % SLOTS_PER_LEADER_WINDOW == 0);
    CHECK(S->block_id().seqno() == P->block_id().seqno() && S->block_id() != P->block_id());
    emit(PSTRING() << "MERKLE_ACTOR_SIBLINGS n=" << n_ << " A=" << candidate_id_str(A->id)
                   << " P=" << candidate_id_str(P->id) << " P_sibling=" << candidate_id_str(S->id)
                   << " P_block=" << P->block_id().to_str() << " P_sibling_block=" << S->block_id().to_str());
    {
      std::scoped_lock lock(mutant_mutex);
      mutant_exact_parent = P->id;
      mutant_sibling = S->id;
    }

    // Observer 1: the sibling is notarized before the branch that will be finalized.
    co_await notarize_prefix(bus_, observations);
    co_await notarize(bus_, observations, S, "P'");
    deliver_skip(S->id.slot);
    co_await notarize(bus_, observations, P, "P");
    co_await notarize(bus_, observations, C, "C");
    co_await finalize(bus_, observations, C, "C");

    // Observer 2: the sibling's certificate arrives after the finalized branch's.
    co_await notarize_prefix(second_bus_, second_observations);
    deliver_skip_to(second_bus_, S->id.slot);
    co_await notarize(second_bus_, second_observations, P, "P");
    co_await notarize(second_bus_, second_observations, C, "C");
    co_await notarize(second_bus_, second_observations, S, "P'");
    co_await finalize(second_bus_, second_observations, C, "C");

    struct Node {
      Observations& observations;
      size_t idx;
      const char* order;
    };
    const Node nodes[] = {{observations, target(), "sibling-first"}, {second_observations, second(), "sibling-late"}};
    for (const auto& node : nodes) {
      for (BlockSeqno seqno = 1; seqno <= n_ + 1; ++seqno) {
        if (!finalized(candidates_[seqno]->id, node.observations)) {
          precondition_failed(PSTRING() << "node " << node.idx << " did not finalize candidate " << seqno);
        }
      }
      if (finalized(S->id, node.observations)) {
        precondition_failed(PSTRING() << "node " << node.idx << " finalized the sibling P'");
      }
      if (misbehavior_reports(node.observations) != 0) {
        precondition_failed(PSTRING() << "node " << node.idx << " reported the certificate history as misbehavior");
      }
      emit(PSTRING() << "MERKLE_ACTOR_SIBLING_PRECONDITION node=" << node.idx << " order=" << node.order
                     << " notar_cert_P_sibling=installed notar_cert_P=installed notar_cert_C=installed"
                     << " final_cert_C=installed finalized_P=yes finalized_P_sibling=no misbehavior=0");
    }
    emit(PSTRING() << "MERKLE_ACTOR_EXPECT wrong_branch_would_fail_with expected_old=" << state_hash_hex(n_)
                   << " applied_to=" << sibling_state_hash_hex(n_));

    // Observer 1 resolves the sibling first, so its state is in the cache when C is resolved.
    emit(PSTRING() << "MERKLE_ACTOR_TRIGGER ResolveState(P_sibling) node=" << target());
    auto sibling_state = co_await resolve_on(bus_, S->id, "P'");
    auto sibling_root = require_state(sibling_state, S->block_id(), sibling_state_hash_hex(n_), "P'");
    emit(PSTRING() << "MERKLE_ACTOR_SIBLING_STATE node=" << target() << " state=" << sibling_root);

    emit(PSTRING() << "MERKLE_ACTOR_TRIGGER ResolveState(C) node=" << target());
    auto first = co_await resolve_on(bus_, C->id, "C on observer 1");
    auto first_root = require_state(first, C->block_id(), state_hash_hex(n_ + 1), "C on observer 1");
    emit(PSTRING() << "MERKLE_ACTOR_RESOLVED node=" << target() << " block=" << C->block_id().to_str()
                   << " state=" << first_root);

    emit(PSTRING() << "MERKLE_ACTOR_TRIGGER ResolveState(C) node=" << second());
    auto second_state = co_await resolve_on(second_bus_, C->id, "C on observer 2");
    auto second_root = require_state(second_state, C->block_id(), state_hash_hex(n_ + 1), "C on observer 2");
    emit(PSTRING() << "MERKLE_ACTOR_RESOLVED node=" << second() << " block=" << C->block_id().to_str()
                   << " state=" << second_root);

    if (manager_asked(target(), S->block_id()) || manager_asked(second(), S->block_id())) {
      test_failed("a manager was asked for the sibling's state");
    }
    if (first_root != second_root || first->block_ids() != second_state->block_ids()) {
      test_failed("the observers resolved C to different blocks or states");
    }
    finish(0, PSTRING() << "MERKLE_ACTOR_SIBLING_GREEN state=" << first_root << " block=" << C->block_id().to_str()
                        << " observers=2 match=yes");
  }

  td::actor::Task<> run_delayed_anchor() {
    const auto& A = candidates_.at(n_ - 1);
    const auto& P = candidates_.at(n_);
    const auto& C = candidates_.at(n_ + 1);
    auto block_data = [](const CandidateRef& candidate) {
      const auto& block = std::get<BlockCandidate>(candidate->block);
      auto data = create_block(block.id, block.data.clone());
      CHECK(data.is_ok());
      return data.move_as_ok();
    };
    {
      // A was referenced by the masterchain long ago; P's reference has not arrived.
      std::scoped_lock lock(anchors_->mutex);
      anchors_->anchors[A->block_id()] =
          ManagerAnchors::Anchor{.state = gen_shard_state(n_ - 1), .data = block_data(A), .delayed = false};
      anchors_->anchors[P->block_id()] =
          ManagerAnchors::Anchor{.state = gen_shard_state(n_), .data = block_data(P), .delayed = true};
    }

    struct Node {
      simplex::BusHandle& bus;
      Observations& observations;
      size_t idx;
    };
    Node nodes[] = {{bus_, observations, target()}, {second_bus_, second_observations, second()}};
    for (auto& node : nodes) {
      co_await notarize_prefix(node.bus, node.observations);
      co_await notarize(node.bus, node.observations, P, "P");
      co_await notarize(node.bus, node.observations, C, "C");
      co_await finalize(node.bus, node.observations, P, "P");
      if (finalized(C->id, node.observations) || misbehavior_reports(node.observations) != 0) {
        precondition_failed(PSTRING() << "node " << node.idx << " finalized C or reported misbehavior");
      }
      if (!anchors_->requests_of(node.idx).empty()) {
        precondition_failed(PSTRING() << "node " << node.idx << " read manager state before resolution");
      }
      emit(PSTRING() << "MERKLE_ACTOR_ANCHOR_PRECONDITION node=" << node.idx
                     << " finalized_P=yes finalized_C=no anchor_P=delayed anchor_A=available misbehavior=0");
    }
    emit(PSTRING() << "MERKLE_ACTOR_EXPECT stale_anchor_would_fail_with expected_old=" << state_hash_hex(n_)
                   << " applied_to=" << state_hash_hex(0));

    // Observer 1 resolves C while the manager still refuses P.
    emit(PSTRING() << "MERKLE_ACTOR_TRIGGER ResolveState(C) node=" << target() << " anchor_P=delayed");
    auto first = co_await resolve_on(bus_, C->id, "C while P's anchor is delayed");
    auto first_root = require_state(first, C->block_id(), state_hash_hex(n_ + 1), "C while P's anchor is delayed");
    auto first_requests = anchors_->requests_of(target());
    bool refused_p = false;
    for (const auto& request : first_requests) {
      refused_p = refused_p || (request.block == P->block_id() && !request.served);
    }
    if (!refused_p) {
      test_failed("observer 1 never asked the manager for P's anchor while it was delayed");
    }
    emit(PSTRING() << "MERKLE_ACTOR_RESOLVED node=" << target() << " block=" << C->block_id().to_str()
                   << " state=" << first_root << " anchor_P=refused");

    // The masterchain reference arrives: the manager now serves P's state.
    anchors_->release();
    emit(PSTRING() << "MERKLE_ACTOR_ANCHOR_RELEASED block=" << P->block_id().to_str());
    emit(PSTRING() << "MERKLE_ACTOR_TRIGGER ResolveState(C) node=" << second() << " anchor_P=released");
    auto second_state = co_await resolve_on(second_bus_, C->id, "C after P's anchor arrived");
    auto second_root = require_state(second_state, C->block_id(), state_hash_hex(n_ + 1), "C after P's anchor arrived");
    auto second_requests = anchors_->requests_of(second());
    if (second_requests.size() != 1 || second_requests[0].block != P->block_id() || !second_requests[0].served) {
      test_failed("observer 2 did not resolve C from P's anchor alone");
    }
    emit(PSTRING() << "MERKLE_ACTOR_RESOLVED node=" << second() << " block=" << C->block_id().to_str()
                   << " state=" << second_root << " anchor_P=served");

    if (manager_asked(target(), A->block_id()) || manager_asked(second(), A->block_id())) {
      test_failed("a manager was asked for the older anchor A");
    }
    if (first_root != second_root || first->block_ids() != second_state->block_ids()) {
      test_failed("the observers resolved C to different blocks or states");
    }
    finish(0, PSTRING() << "MERKLE_ACTOR_ANCHOR_GREEN state=" << first_root << " block=" << C->block_id().to_str()
                        << " observers=2 match=yes");
  }

  [[noreturn]] void check_state(td::Result<simplex::ResolveState::Result> resolved, const char* label) {
    if (resolved.is_error()) {
      test_failed(PSTRING() << "resolution failed: " << resolved.error());
    }
    auto state = resolved.move_as_ok().state;
    auto ids = state->block_ids();
    auto root = state->state().at(0)->get_hash().to_hex();
    if (ids.size() != 1 || ids[0] != candidates_.at(n_ + 1)->block_id() || root != state_hash_hex(n_ + 1)) {
      test_failed(PSTRING() << "resolved to " << ids.at(0).to_str() << " with state " << root << "; expected state "
                            << state_hash_hex(n_ + 1));
    }
    finish(0, PSTRING() << label << " state=" << root);
  }
};

}  // namespace

#ifdef TOS_STATE_RESOLVER_MUTANT
// The hooks the generated mutant resolver calls. TOS_TEST_STATE_RESOLVER_MUTANT selects what
// the resolver gets wrong; unset, the mutant behaves like the production resolver.
namespace tos::validator::consensus::simplex {

namespace {

const std::string& mutant_kind() {
  static const std::string kind = [] {
    const char* value = std::getenv("TOS_TEST_STATE_RESOLVER_MUTANT");
    return std::string(value == nullptr ? "" : value);
  }();
  return kind;
}

}  // namespace

std::optional<ParentId> state_resolver_mutant_substitute(const ParentId& id) {
  if (!id.has_value()) {
    return std::nullopt;
  }
  if (mutant_kind() == "skip-shortcut") {
    // The base Pool would report for a skip-certified slot whose NotarCert it has not
    // installed: the newest notarized candidate at an older slot, or the null parent.
    {
      std::scoped_lock lock(mutant_mutex);
      if (!delivered_skips.contains(id->slot)) {
        return std::nullopt;
      }
    }
    if (notarized(*id)) {
      return std::nullopt;
    }
    ParentId base;
    {
      std::scoped_lock lock(observations.mutex);
      for (const auto& candidate : observations.notarized) {
        if (candidate.slot < id->slot && (!base.has_value() || candidate.slot > base->slot)) {
          base = candidate;
        }
      }
    }
    emit(PSTRING() << "MERKLE_ACTOR_MUTANT_FIRED kind=skip-shortcut id=" << candidate_id_str(*id)
                   << " base=" << (base.has_value() ? candidate_id_str(*base) : std::string("null")));
    return base;
  }
  if (mutant_kind() == "sibling") {
    std::scoped_lock lock(mutant_mutex);
    if (mutant_exact_parent.has_value() && mutant_sibling.has_value() && *id == *mutant_exact_parent) {
      emit(PSTRING() << "MERKLE_ACTOR_MUTANT_FIRED kind=sibling id=" << candidate_id_str(*id)
                     << " sibling=" << candidate_id_str(*mutant_sibling));
      return ParentId{*mutant_sibling};
    }
  }
  return std::nullopt;
}

bool state_resolver_mutant_stale_anchor() {
  if (mutant_kind() != "stale-anchor") {
    return false;
  }
  emit("MERKLE_ACTOR_MUTANT_FIRED kind=stale-anchor fallback=start-state");
  return true;
}

}  // namespace tos::validator::consensus::simplex
#endif

int main(int argc, char* argv[]) {
  if (argc != 3) {
    std::fprintf(stderr,
                 "usage: %s hold-release|hold-refuse|no-hold|hold-wrong-slot|peer-consensus|sibling|delayed-anchor "
                 "<n>\n",
                 argv[0]);
    return 2;
  }
  std::string mode_name = argv[1];
  Mode mode;
  if (mode_name == "hold-release") {
    mode = Mode::HoldRelease;
  } else if (mode_name == "hold-refuse") {
    mode = Mode::HoldRefuse;
  } else if (mode_name == "no-hold") {
    mode = Mode::NoHold;
  } else if (mode_name == "hold-wrong-slot") {
    mode = Mode::HoldWrongSlot;
  } else if (mode_name == "peer-consensus") {
    mode = Mode::PeerConsensus;
  } else if (mode_name == "sibling") {
    mode = Mode::Sibling;
  } else if (mode_name == "delayed-anchor") {
    mode = Mode::DelayedAnchor;
  } else {
    std::fprintf(stderr, "unknown mode %s\n", argv[1]);
    return 2;
  }
  auto n = td::to_integer_safe<BlockSeqno>(td::Slice(argv[2]));
  if (n.is_error() || n.ok() < 2 || n.ok() > 200) {
    std::fprintf(stderr, "n must be an integer in [2, 200]\n");
    return 2;
  }
#ifdef TOS_STATE_RESOLVER_MUTANT
  const char* mutant = std::getenv("TOS_TEST_STATE_RESOLVER_MUTANT");
  emit(PSTRING() << "MERKLE_ACTOR_BUILD resolver=mutant mutant=" << (mutant == nullptr ? "none" : mutant));
#else
  emit("MERKLE_ACTOR_BUILD resolver=production");
#endif

  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<Driver> driver;
  scheduler.run_in_context([&] {
    driver = td::actor::create_actor<Driver>("merkle-driver", mode, n.move_as_ok());
    td::actor::ask(driver, &Driver::run).detach();
  });
  while (scheduler.run(1)) {
  }
  return 0;
}
