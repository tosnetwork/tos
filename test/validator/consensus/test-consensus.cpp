/*
 * Copyright (c) 2025-2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include <atomic>
#include <array>
#include <cstdio>

#include "adnl/utils.hpp"
#include "auto/tl/tos_api.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "block/mc-config.h"
#include "block/validator-set.h"
#include "consensus/candidate-relay-policy.h"
#include "consensus/simplex/bus.h"
#include "consensus/simplex/candidate-retention.h"
#include "consensus/simplex/completed-lru.h"
#include "consensus/simplex/finalized-slot-dedup.h"
#include "consensus/simplex/votes.h"
#include "consensus/utils.h"
#include "overlay/overlays.h"
#include "td/actor/BusRuntime.h"
#include "td/actor/coro_utils.h"
#include "td/db/MemoryKeyValue.h"
#include "td/utils/OptionParser.h"
#include "td/utils/Random.h"
#include "td/utils/port/signals.h"
#include "tos/quorum.h"
#include "validator/consensus/candidate-codec.h"
#include "validator/finality-cache-policy.h"
#include "validator/impl/accept-block.hpp"
#include "validator/manager-resource-policy.h"
#include "vm/boc-compression.h"
#include "vm/boc.h"
#include "vm/cells/MerkleUpdate.h"

#include "block-auto.h"

using namespace tos;
using namespace tos::validator;
using namespace tos::validator::consensus;
namespace validatorsession = tos::validator::consensus;

namespace {
td::Bits256 from_hex(td::Slice s) {
  td::Bits256 x;
  CHECK(x.from_hex(s) == 256);
  return x;
}

td::Ref<vm::Cell> gen_shard_state(BlockSeqno seqno) {
  return vm::CellBuilder().store_long(0xabcdabcdU, 32).store_long(seqno, 32).finalize_novm();
}

td::Result<std::pair<double, double>> parse_range(td::Slice s) {
  auto pos = s.find(':');
  if (pos == td::Slice::npos) {
    double x = td::to_double(s);
    return std::make_pair(x, x);
  }
  double x = td::to_double(s.substr(0, pos));
  double y = td::to_double(s.substr(pos + 1, s.size()));
  if (x > y) {
    return td::Status::Error(PSTRING() << "invalid range " << s);
  }
  return std::make_pair(x, y);
}

template <typename T>
td::Result<std::pair<T, T>> parse_int_range(td::Slice s) {
  auto pos = s.find(':');
  if (pos == td::Slice::npos) {
    TRY_RESULT(x, td::to_integer_safe<T>(s));
    return std::make_pair(x, x);
  }
  TRY_RESULT(x, td::to_integer_safe<T>(s.substr(0, pos)));
  TRY_RESULT(y, td::to_integer_safe<T>(s.substr(pos + 1, s.size())));
  if (x > y) {
    return td::Status::Error(PSTRING() << "invalid range " << s);
  }
  return std::make_pair(x, y);
}

Ref<vm::Cell> make_ext_blk_ref(BlockIdExt block_id, LogicalTime lt) {
  vm::CellBuilder cb;
  cb.store_long_bool(lt, 64);
  cb.store_long_bool(block_id.seqno(), 32);
  cb.store_bits_bool(block_id.root_hash);
  cb.store_bits_bool(block_id.file_hash);
  return cb.finalize_novm();
}

CatchainSeqno CC_SEQNO = 123;
BlockIdExt MIN_MC_BLOCK_ID{masterchainId, shardIdAll, 0,
                           from_hex("AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDAAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD"),
                           from_hex("0123456012345601234560123456012345601234560123456777777701234567")};
td::Bits256 SESSION_ID = from_hex("00001234000012340000123400001234aaaaaaaabbbbbbbbcccccccceeeeeeee");

ShardIdFull SHARD{basechainId, shardIdAll};
BlockIdExt FIRST_PARENT{basechainId, shardIdAll, 0, td::Bits256(gen_shard_state(0)->get_hash().bits()),
                        from_hex("89abcde89abcde89abcde89abcde89abcde89abcde89abcdefffffff89abcdef")};

std::pair<double, double> NET_PING = {0.05, 0.1};
double NET_LOSS = 0.0;

size_t N_NODES = 8;
size_t N_DOUBLE_NODES = 0;

double DURATION = 60.0;
td::uint32 TARGET_RATE_MS = 1000;
td::uint32 SLOTS_PER_LEADER_WINDOW = 4;
BlockSeqno MIN_FINALIZED_BLOCKS = 0;

std::pair<double, double> GREMLIN_PERIOD = {-1.0, -1.0};
std::pair<double, double> GREMLIN_DOWNTIME = {1.0, 1.0};
std::pair<size_t, size_t> GREMLIN_N = {1, 1};
size_t GREMLIN_TIMES = 1000000000;
bool GREMLIN_KILLS_LEADER = false;

std::pair<double, double> NET_GREMLIN_PERIOD = {-1.0, -1.0};
std::pair<double, double> NET_GREMLIN_DOWNTIME = {10.0, 10.0};
std::pair<size_t, size_t> NET_GREMLIN_N = {1, 1};
size_t NET_GREMLIN_TIMES = 1000000000;
bool NET_GREMLIN_KILLS_LEADER = false;

size_t ADAPTIVE_BYZANTINE_N = 0;
double ADAPTIVE_BYZANTINE_PERIOD = 0.5;
bool MALICIOUS_OBSERVER_ATTACK = false;
bool RELAY_LOOP_TEST = false;
// The validator index that relays other validators' signed votes over its own transport,
// or -1 for none. The bytes are passed on unmodified: a vote carries no signer field, so all
// a receiver has to attribute it by is the transport it arrived over -- and that must not be
// what decides whose vote it is.
int BYZANTINE_RELAY_NODE = -1;
bool QUERY_ABUSE_TEST = false;
// Publish two finalizations of candidates the resolver has never seen, so that a
// concurrency limit set to one refuses the second at the door. Requires
// TOS_SIMPLEX_FINALIZED_INFLIGHT_MAX=1 to be set for the run; without it nothing is refused
// and the probe fails, which is the intended behaviour of a probe whose pressure is missing.
bool FINALIZATION_RETRY_PROBE = false;
// This scenario deliberately stops production while more agreed certificates are
// pending than the resolver may hold. Its progress requirement is therefore one
// accepted block after the backlog clears, rather than the general three-block
// continuity requirement. The backlog transition and absence of production while
// throttled are asserted separately, so the lower progress count cannot make the
// scenario pass without exercising backpressure and recovery.
bool FINALIZATION_BACKPRESSURE_TEST = false;
bool EMPTY_CHAIN_RESTART_TEST = false;
bool VOTE_JOURNAL_TEST = false;
bool PQ_FINALITY_E2E_TEST = false;
// Requires the resolver to keep, report and stop retrying a finalization that failed in a
// way retrying cannot mend, and to stop the group rather than run ahead of it. Needs
// TOS_SIMPLEX_INJECT_PERMANENT_FINALIZATION_FAILURE set: production does not
// deterministically produce that class of failure.
bool PERMANENT_FINALIZATION_TEST = false;
std::atomic<bool> EMPTY_CHAIN_MANAGER_ANCHOR_UNAVAILABLE = false;
// Model cold-start replay: the first N manager anchor reads time out, then recover.
std::atomic<size_t> EMPTY_CHAIN_MANAGER_ANCHOR_TRANSIENT_FAILURES = 0;
// The session origin is a separate dependency from a finalized nonzero anchor.
std::atomic<size_t> EMPTY_CHAIN_ORIGIN_TRANSIENT_FAILURES = 0;
std::atomic<size_t> EMPTY_CHAIN_ORIGIN_FAILURES = 0;
bool EMPTY_CHAIN_ORIGIN_PERMANENTLY_UNAVAILABLE = false;
size_t C05_GENESIS_FAULT_BUDGET = 0;
std::array<std::atomic<size_t>, 4> C05_GENESIS_FAULTS{};
std::array<std::atomic<double>, 4> C05_LAST_FAULT_TIME{};
struct C05SimultaneousObservation {
  std::mutex mutex;
  std::optional<CandidateId> first_candidate;
  BlockIdExt first_block;
  double candidate_time = 0;
  simplex::NotarCertRef notar_cert;
  double notar_cert_time = 0;
};
C05SimultaneousObservation C05_SIMULTANEOUS_OBSERVATION;
// Production restarts an active group from its current accepted chain tip.
bool RESTART_FROM_LAST_ACCEPTED_BLOCK = false;

// Adversity that was configured but never fired turns a scenario into a quiet no-op: the
// post-quantum gate finishes in well under a second, sooner than a gremlin period. These
// count what actually happened so the gate can wait for it and refuse to pass without it.
std::atomic<size_t> INJECTED_PACKET_LOSSES = 0;
std::atomic<size_t> INJECTED_NODE_KILLS = 0;
std::atomic<size_t> INJECTED_NETWORK_CUTS = 0;
std::atomic<size_t> EMPTY_CHAIN_MANAGER_ANCHOR_FAILURES = 0;
// Candidates produced anywhere in the network. Read twice, a settle window apart, it says
// whether collation has actually stopped.
std::atomic<size_t> CANDIDATES_GENERATED = 0;
std::atomic<size_t> BYZANTINE_RELAYS_SENT = 0;
// Times a node reported that more agreed certificates were waiting to be finalized than its
// resolver will hold, and candidates produced by a node while it was in that state. The
// second is the backpressure itself: a node that is behind on finality must not add to it.
std::atomic<size_t> BACKLOG_OVER_LIMIT_REPORTS = 0;
std::atomic<size_t> BACKLOG_CLEARED_REPORTS = 0;
std::atomic<size_t> CANDIDATES_WHILE_BACKLOGGED = 0;
double CATCH_UP_DOWNTIME = -1.0;

std::pair<double, double> DB_DELAY = {0.0, 0.0};
std::pair<double, double> COLLATION_TIME = {0.0, 0.0};
std::pair<double, double> VALIDATION_TIME = {0.0, 0.0};

class TestSimplexBus : public simplex::Bus {
 public:
  using Parent = simplex::Bus;
  size_t instance_idx = 0;
};

class TestOverlayNode;

class TestOverlay : public td::actor::Actor {
 public:
  void register_node(size_t idx, size_t instance_idx, td::actor::ActorId<TestOverlayNode> node) {
    Instance& inst = get_inst(idx, instance_idx);
    CHECK(inst.actor.empty());
    inst.actor = std::move(node);
  }

  void unregister_node(size_t idx, size_t instance_idx) {
    Instance& inst = get_inst(idx, instance_idx);
    CHECK(!inst.actor.empty());
    inst.actor = {};
  }

  td::actor::Task<> set_instance_disabled(size_t idx, size_t instance_idx, bool value) {
    get_inst(idx, instance_idx).disabled = value;
    LOG(ERROR) << "Node #" << idx << "." << instance_idx << ": " << (value ? "disable" : "enable") << " network";
    co_return td::Unit{};
  }

  td::actor::Task<> set_adaptive_byzantine_nodes(std::vector<size_t> nodes, td::uint64 epoch) {
    adaptive_byzantine_nodes_.clear();
    adaptive_byzantine_nodes_.insert(nodes.begin(), nodes.end());
    adaptive_byzantine_epoch_ = epoch;
    co_return td::Unit{};
  }

  td::actor::Task<> send_message(PeerValidator src, size_t src_instance_idx, size_t dst_idx, td::BufferSlice message);
  td::actor::Task<> send_candidate(PeerValidator src, size_t src_instance_idx, size_t dst_idx, CandidateRef candidate);
  td::actor::Task<td::BufferSlice> send_query(PeerValidator src, size_t src_instance_idx, size_t dst_idx,
                                              td::BufferSlice message);

 private:
  struct Instance {
    td::actor::ActorId<TestOverlayNode> actor;
    bool disabled = false;
  };
  std::vector<std::vector<Instance>> nodes_;
  std::set<size_t> adaptive_byzantine_nodes_;
  td::uint64 adaptive_byzantine_epoch_ = 0;

  Instance& get_inst(size_t idx, size_t instance_idx) {
    if (nodes_.size() <= idx) {
      nodes_.resize(idx + 1);
    }
    if (nodes_[idx].size() <= instance_idx) {
      nodes_[idx].resize(instance_idx + 1);
    }
    return nodes_[idx][instance_idx];
  }

  td::actor::Task<> before_receive(size_t src_idx, size_t src_instance_idx, size_t dst_idx, bool no_loss) {
    if (get_inst(src_idx, src_instance_idx).disabled) {
      co_return td::Status::Error("src is disabled");
    }
    if (!no_loss && td::Random::fast(0.0, 1.0) < NET_LOSS) {
      ++INJECTED_PACKET_LOSSES;
      co_return td::Status::Error("packet lost");
    }
    co_await td::actor::coro_sleep(td::Timestamp::in(td::Random::fast(NET_PING.first, NET_PING.second)));
    co_return td::Unit{};
  }

  bool drop_byzantine_forward(size_t src_idx, size_t dst_idx, td::uint64 kind) const {
    if (!adaptive_byzantine_nodes_.contains(src_idx)) {
      return false;
    }
    // Retain one deterministic third of the destinations.  The selected
    // sources and retained peer subset rotate every epoch, modelling an
    // adaptive omission attacker without relying on nondeterministic loss.
    return (src_idx + dst_idx + adaptive_byzantine_epoch_ + kind) % 3 != 0;
  }
};

td::actor::ActorOwn<TestOverlay> test_overlay;

class TestOverlayNode : public td::actor::SpawnsWith<Bus>, public td::actor::ConnectsTo<Bus> {
 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();

  void start_up() override {
    instance_idx_ = dynamic_cast<const TestSimplexBus&>(*owning_bus()).instance_idx;
    td::actor::send_closure(test_overlay, &TestOverlay::register_node, owning_bus()->local_id->idx.value(),
                            instance_idx_, actor_id(this));
  }

  void tear_down() override {
    td::actor::send_closure(test_overlay, &TestOverlay::unregister_node, owning_bus()->local_id->idx.value(),
                            instance_idx_);
    for (auto& [_, query] : active_queries_) {
      td::actor::send_closure(query, &Query::set_result, td::Status::Error(ErrorCode::cancelled, "cancelled"));
    }
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const StopRequested>) {
    stop();
  }

  template <>
  void handle(BusHandle bus, std::shared_ptr<const OutgoingProtocolMessage> message) {
    for (size_t i = 0; i < bus->validator_set.size(); ++i) {
      if (bus->local_id->idx.value() != i) {
        td::actor::ask(test_overlay, &TestOverlay::send_message, *bus->local_id, instance_idx_, i,
                       message->message.data.clone())
            .detach_silent();
      }
    }
  }

  template <>
  void handle(BusHandle bus, std::shared_ptr<const CandidateGenerated> event) {
    for (size_t i = 0; i < bus->validator_set.size(); ++i) {
      if (bus->local_id->idx.value() != i) {
        td::actor::ask(test_overlay, &TestOverlay::send_candidate, *bus->local_id, instance_idx_, i, event->candidate)
            .detach_silent();
      }
    }
  }

  template <>
  td::actor::Task<ProtocolMessage> process(BusHandle bus, std::shared_ptr<OutgoingOverlayRequest> message) {
    size_t destination;
    if (message->destination) {
      destination = SIZE_MAX;
      for (const auto& peer : bus->validator_set) {
        if (peer.adnl_id == *message->destination) {
          destination = peer.idx.value();
          break;
        }
      }
      CHECK(destination != SIZE_MAX);
    } else {
      destination = td::Random::fast(0, static_cast<int>(bus->validator_set.size()) - 2);
      if (destination >= bus->local_id->idx.value()) {
        ++destination;
      }
    }
    auto [task, promise] = td::actor::StartedTask<ProtocolMessage>::make_bridge();
    auto query = td::actor::create_actor<Query>("q", std::move(promise), message->timeout).release();
    size_t idx = next_query_idx_++;
    active_queries_[idx] = query;
    td::actor::send_closure(test_overlay, &TestOverlay::send_query, *bus->local_id, instance_idx_, destination,
                            message->request.data.clone(),
                            td::PromiseCreator::lambda([query](td::Result<td::BufferSlice> R) {
                              if (R.is_ok()) {
                                td::actor::send_closure(query, &Query::set_result, ProtocolMessage{R.move_as_ok()});
                              }
                            }));
    auto result = co_await std::move(task).wrap();
    active_queries_.erase(idx);
    co_return result;
  }

  void receive_message(PeerValidator src, td::BufferSlice data) {
    auto& bus = *owning_bus();
    // Pass another validator's signed message on as this node's own, byte for byte. The
    // transport is genuinely this node's and authenticates correctly; the signature inside
    // is somebody else's. Nothing about the message is forged, which is the point: the only
    // thing that could make it count as this node's vote is the transport it came over.
    if (BYZANTINE_RELAY_NODE >= 0 && bus.local_id->idx.value() == static_cast<size_t>(BYZANTINE_RELAY_NODE) &&
        src.idx.value() != bus.local_id->idx.value()) {
      ++BYZANTINE_RELAYS_SENT;
      for (size_t i = 0; i < bus.validator_set.size(); ++i) {
        if (i != bus.local_id->idx.value() && i != src.idx.value()) {
          td::actor::ask(test_overlay, &TestOverlay::send_message, *bus.local_id, instance_idx_, i, data.clone())
              .detach_silent();
        }
      }
    }
    owning_bus().publish<IncomingProtocolMessage>(src.idx, src.adnl_id, std::move(data));
  }

  void receive_candidate(CandidateRef candidate) {
    owning_bus().publish<CandidateReceived>(candidate);
    if (RELAY_LOOP_TEST) {
      // Model a candidate returning through a second transport/relay path.
      // CandidateBroadcastRelay must still emit it at most once.
      owning_bus().publish<CandidateReceived>(candidate);
    }
  }

  td::actor::Task<td::BufferSlice> receive_query(PeerValidator src, td::BufferSlice query) {
    auto request = std::make_shared<IncomingOverlayRequest>(src.idx, src.adnl_id, std::move(query));
    auto response = co_await owning_bus().publish(std::move(request)).wrap();
    if (response.is_ok()) {
      co_return std::move(response.move_as_ok().data);
    }
    co_return create_serialize_tl_object<tos_api::consensus_requestError>();
  }

 private:
  class Query : public td::actor::Actor {
   public:
    Query(td::Promise<ProtocolMessage> promise, td::Timestamp timeout)
        : promise_(std::move(promise)), timeout_(timeout) {
    }

    void start_up() override {
      alarm_timestamp() = timeout_;
    }

    void set_result(td::Result<ProtocolMessage> R) {
      promise_.set_result(std::move(R));
      stop();
    }

    void alarm() override {
      set_result(td::Status::Error(ErrorCode::timeout, "timeout"));
    }

   private:
    td::Promise<ProtocolMessage> promise_;
    td::Timestamp timeout_;
  };

  size_t instance_idx_ = 0;
  std::map<size_t, td::actor::ActorId<Query>> active_queries_;
  size_t next_query_idx_ = 0;
};

td::actor::Task<> TestOverlay::send_message(PeerValidator src, size_t src_instance_idx, size_t dst_idx,
                                            td::BufferSlice message) {
  if (drop_byzantine_forward(src.idx.value(), dst_idx, 0)) {
    co_return td::Status::Error("adaptive Byzantine protocol-message omission");
  }
  co_await before_receive(src.idx.value(), src_instance_idx, dst_idx, false);
  for (const auto& instance : nodes_[dst_idx]) {
    if (instance.actor.empty() || instance.disabled) {
      continue;
    }
    td::actor::send_closure(instance.actor, &TestOverlayNode::receive_message, src, message.clone());
  }
  co_return td::Unit{};
}

td::actor::Task<> TestOverlay::send_candidate(PeerValidator src, size_t src_instance_idx, size_t dst_idx,
                                              CandidateRef candidate) {
  if (drop_byzantine_forward(src.idx.value(), dst_idx, 1)) {
    co_return td::Status::Error("adaptive Byzantine candidate omission");
  }
  co_await before_receive(src.idx.value(), src_instance_idx, dst_idx, true);
  for (const auto& instance : nodes_[dst_idx]) {
    if (instance.actor.empty() || instance.disabled) {
      continue;
    }
    td::actor::send_closure(instance.actor, &TestOverlayNode::receive_candidate, candidate);
  }
  co_return td::Unit{};
}

td::actor::Task<td::BufferSlice> TestOverlay::send_query(PeerValidator src, size_t src_instance_idx, size_t dst_idx,
                                                         td::BufferSlice message) {
  if (drop_byzantine_forward(src.idx.value(), dst_idx, 2)) {
    co_return td::Status::Error("adaptive Byzantine query omission");
  }
  if (nodes_[dst_idx].empty()) {
    co_return td::Status::Error("no instances");
  }
  auto dst_instance_idx = (size_t)td::Random::fast(0, (int)nodes_[dst_idx].size() - 1);
  const auto& instance = nodes_[dst_idx][dst_instance_idx];
  co_await before_receive(src.idx.value(), src_instance_idx, dst_idx, true);
  if (instance.actor.empty() || instance.disabled) {
    co_return td::Status::Error("instance is stopped/disabled");
  }
  auto response = co_await td::actor::ask(instance.actor, &TestOverlayNode::receive_query, src, std::move(message));
  co_await before_receive(dst_idx, dst_instance_idx, src.idx.value(), true);
  co_return response;
}

class TestConsensus;

class TestManagerFacade : public ManagerFacade {
 public:
  explicit TestManagerFacade(size_t node_idx, size_t instance_idx, Ref<block::ValidatorSet> validator_set,
                             td::actor::ActorId<TestConsensus> test_consensus)
      : node_idx_(node_idx)
      , instance_idx_(instance_idx)
      , validator_set_(validator_set)
      , test_consensus_(test_consensus) {
  }

  td::actor::Task<GeneratedCandidate> collate_block(CollateParams params,
                                                    td::CancellationToken cancellation_token) override {
    CHECK(params.prev.size() == 1);
    uint32_t prev_seqno = params.prev[0].seqno();
    LOG(WARNING) << "Collate block #" << prev_seqno + 1;
    CHECK(params.shard == SHARD);
    CHECK(params.min_masterchain_block_id == MIN_MC_BLOCK_ID);

    CHECK(params.prev_block_state_roots.size() == 1 &&
          params.prev_block_state_roots[0]->get_hash() == gen_shard_state(prev_seqno)->get_hash());
    if (prev_seqno != 0) {
      CHECK(params.prev_block_data.size() == 1 && params.prev_block_data[0]->block_id() == params.prev[0]);
    }
    double gen_utime = params.utime ? params.utime.value() : td::Clocks::system();

    block::gen::BlockInfo::Record info;
    info.version = 0;
    info.not_master = !SHARD.is_masterchain();
    info.after_merge = info.before_split = info.after_split = false;
    info.want_split = info.want_merge = false;
    info.key_block = info.vert_seqno_incr = false;
    info.flags = 0;
    info.seq_no = prev_seqno + 1;
    info.vert_seq_no = 0;

    vm::CellBuilder cb;
    block::ShardId{SHARD}.serialize(cb);
    info.shard = cb.as_cellslice_ref();

    info.gen_utime = (UnixTime)gen_utime;
    info.start_lt = (LogicalTime)info.seq_no * 1000;
    info.end_lt = (LogicalTime)info.seq_no * 1000 + 1;
    info.gen_validator_list_hash_short = validator_set_->get_validator_set_hash();
    info.gen_catchain_seqno = validator_set_->get_catchain_seqno();
    info.min_ref_mc_seqno = MIN_MC_BLOCK_ID.seqno();
    info.prev_key_block_seqno = MIN_MC_BLOCK_ID.seqno();
    if (!SHARD.is_masterchain()) {
      info.master_ref = make_ext_blk_ref(MIN_MC_BLOCK_ID, 0);
    }
    info.prev_ref = make_ext_blk_ref(params.prev[0], (LogicalTime)prev_seqno * 1000 + 1);
    td::Ref<vm::Cell> block_info;
    CHECK(block::gen::pack_cell(block_info, info));

    td::Ref<vm::Cell> value_flow = vm::CellBuilder{}.finalize_novm();
    td::Ref<vm::Cell> merkle_update =
        vm::CellBuilder::create_merkle_update(gen_shard_state(prev_seqno), gen_shard_state(prev_seqno + 1));

    td::Bits256 rand_data;
    td::Random::secure_bytes(rand_data.as_slice());
    td::Ref<vm::Cell> block_extra = vm::CellBuilder{}.store_bytes(rand_data.as_slice()).finalize_novm();

    td::Ref<vm::Cell> block_root = vm::CellBuilder{}
                                       .store_long(0x11ef55aa, 32)
                                       .store_long(-111, 32)
                                       .store_ref(block_info)
                                       .store_ref(value_flow)
                                       .store_ref(merkle_update)
                                       .store_ref(block_extra)
                                       .finalize_novm();
    td::BufferSlice data = vm::std_boc_serialize(block_root, 31).move_as_ok();

    std::vector<td::Ref<vm::Cell>> collated_roots;
    // consensus_extra_data#638eb292 flags:# gen_utime_ms:uint64 = ConsensusExtraData;
    auto cell = vm::CellBuilder{}
                    .store_long(0x638eb292, 32)
                    .store_long(0, 32)
                    .store_long((td::uint64)(gen_utime * 1000.0), 64)
                    .finalize_novm();
    collated_roots.push_back(std::move(cell));
    td::BufferSlice collated_data = co_await vm::std_boc_serialize_multi(collated_roots, 2);

    co_await td::actor::coro_sleep(td::Timestamp::in(td::Random::fast(COLLATION_TIME.first, COLLATION_TIME.second)));

    BlockCandidate candidate(
        params.creator,
        BlockIdExt(BlockId(params.shard, prev_seqno + 1), block_root->get_hash().bits(), td::sha256_bits256(data)),
        td::sha256_bits256(collated_data), data.clone(), collated_data.clone());
    CHECK(params.skip_store_candidate);
    co_return GeneratedCandidate{.candidate = std::move(candidate), .is_cached = false, .self_collated = true};
  }

  td::actor::Task<ValidateCandidateResult> validate_block_candidate(BlockCandidate candidate, ValidateParams params,
                                                                    td::Timestamp timeout) override {
    CHECK(params.prev.size() == 1);
    uint32_t prev_seqno = params.prev[0].seqno();
    LOG(WARNING) << "Validate block #" << candidate.id.seqno();
    CHECK(params.prev[0].shard_full() == SHARD);
    CHECK(candidate.id.shard_full() == SHARD);
    CHECK(candidate.id.seqno() == prev_seqno + 1);
    CHECK(params.prev_block_state_roots.size() == 1 &&
          params.prev_block_state_roots[0]->get_hash() == gen_shard_state(prev_seqno)->get_hash());
    co_await td::actor::coro_sleep(td::Timestamp::in(td::Random::fast(VALIDATION_TIME.first, VALIDATION_TIME.second)));
    co_return CandidateAccept{.ok_from_utime = co_await get_candidate_gen_utime_exact(candidate)};
  }

  td::actor::Task<> accept_block(BlockIdExt id, td::Ref<BlockData> data, size_t creator_idx,
                                 td::Ref<block::BlockSignatureSet> signatures, ValidatorSessionId expected_session_id,
                                 int block_broadcast_mode, int finality_broadcast_mode, bool send_shard_block_desc,
                                 bool apply) override;

  td::actor::Task<td::Ref<vm::Cell>> wait_block_state_root(BlockIdExt block_id, td::Timestamp timeout) override;
  td::actor::Task<td::Ref<BlockData>> wait_block_data(BlockIdExt block_id, td::Timestamp timeout) override;
  void send_block_candidate_broadcast(BlockIdExt id, td::BufferSlice data, int mode) override;

 private:
  size_t node_idx_;
  size_t instance_idx_;
  Ref<block::ValidatorSet> validator_set_;
  td::actor::ActorId<TestConsensus> test_consensus_;
};

// ===== What the end-to-end gate observes =====
//
// A node publishes FinalizationObserved the moment a finality certificate is agreed and
// every signature in it has been verified against the key the validator set records. That
// is exactly where this build ends. Everything past it -- a block signature set, an accepted
// block, a finalized-block marker -- belongs to the carrier work and must not happen in this build, so
// the gate keeps the certificate itself rather than a count, and checks it independently.
struct ObservedFinalization {
  size_t node_idx = 0;
  size_t instance_idx = 0;
  CandidateId id;
  simplex::FinalCertRef cert;
};

std::mutex finality_log_mutex;
std::vector<ObservedFinalization> finality_log;

// Only the end-to-end gate reads this, and only that run is short enough for it to be
// bounded. A stress scenario finalizes for as long as it runs, so it does not record.
void record_finalization(ObservedFinalization observation) {
  if (!PQ_FINALITY_E2E_TEST) {
    return;
  }
  std::scoped_lock lock(finality_log_mutex);
  finality_log.push_back(std::move(observation));
}

std::vector<ObservedFinalization> read_finality_log() {
  std::scoped_lock lock(finality_log_mutex);
  return finality_log;
}

class TestFinalityObserver : public td::actor::SpawnsWith<simplex::Bus>, public td::actor::ConnectsTo<simplex::Bus> {
 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();

  void start_up() override {
    instance_idx_ = dynamic_cast<const TestSimplexBus&>(*owning_bus()).instance_idx;
  }

  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const StopRequested>) {
    stop();
  }

  template <>
  void handle(simplex::BusHandle bus, std::shared_ptr<const simplex::FinalizationObserved> event) {
    if (!bus->local_id.has_value()) {
      return;
    }
    record_finalization(ObservedFinalization{bus->local_id->idx.value(), instance_idx_, event->id, event->certificate});
  }

  // Candidates this network has put into the round, counted across every node. It is how the
  // gate can say that collation stopped, rather than that no further block was accepted --
  // which would be true of a build that never had a carrier whether it stopped or not.
  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const CandidateGenerated> event) {
    ++CANDIDATES_GENERATED;
    if (C05_GENESIS_FAULT_BUDGET != 0 && !event->candidate->is_empty() &&
        event->candidate->block_id().seqno() == 1) {
      std::scoped_lock lock(C05_SIMULTANEOUS_OBSERVATION.mutex);
      if (!C05_SIMULTANEOUS_OBSERVATION.first_candidate) {
        C05_SIMULTANEOUS_OBSERVATION.first_candidate = event->candidate->id;
        C05_SIMULTANEOUS_OBSERVATION.first_block = event->candidate->block_id();
        C05_SIMULTANEOUS_OBSERVATION.candidate_time = td::Time::now();
      }
    }
    if (backlogged_) {
      ++CANDIDATES_WHILE_BACKLOGGED;
    }
  }

  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const simplex::NotarizationObserved> event) {
    if (C05_GENESIS_FAULT_BUDGET == 0) {
      return;
    }
    std::scoped_lock lock(C05_SIMULTANEOUS_OBSERVATION.mutex);
    if (C05_SIMULTANEOUS_OBSERVATION.first_candidate == event->id &&
        C05_SIMULTANEOUS_OBSERVATION.notar_cert.is_null()) {
      C05_SIMULTANEOUS_OBSERVATION.notar_cert = event->certificate;
      C05_SIMULTANEOUS_OBSERVATION.notar_cert_time = td::Time::now();
    }
  }

  // Whether this node is currently holding more agreed certificates than it will, which is
  // the state in which it is supposed to stop producing.
  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const FinalizationBacklog> event) {
    if (event->over_limit) {
      ++BACKLOG_OVER_LIMIT_REPORTS;
    } else if (backlogged_) {
      ++BACKLOG_CLEARED_REPORTS;
    }
    backlogged_ = event->over_limit;
  }

 private:
  size_t instance_idx_ = 0;
  bool backlogged_ = false;
};

class TestDbImpl : public consensus::Db {
 public:
  struct DbInner {
    std::map<td::BufferSlice, td::BufferSlice> map;
    std::mutex mutex;
    size_t finalized_latest_get_count = 0;
    size_t finalized_latest_found_count = 0;
    // TL constructor id -> how many further writes of that record to reject.
    std::map<td::uint32, size_t> fail_writes_of;
    size_t failed_write_count = 0;
  };

  explicit TestDbImpl(std::shared_ptr<DbInner> db) : db_(std::move(db)) {
    std::scoped_lock lock(db_->mutex);
    for (auto& [key, value] : db_->map) {
      snapshot_.emplace(key.clone(), value.clone());
    }
  }
  ~TestDbImpl() override = default;

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
    td::uint32 prefix2 = prefix + 1;
    td::BufferSlice end{(const char*)&prefix2, 4};
    for (auto it = snapshot_.lower_bound(begin); it != snapshot_.end() && it->first < end; ++it) {
      result.emplace_back(it->first.clone(), it->second.clone());
    }
    return result;
  }
  td::actor::Task<std::optional<td::BufferSlice>> get_latest(td::BufferSlice key) const override {
    std::scoped_lock lock(db_->mutex);
    td::int32 tag = 0;
    if (key.size() >= sizeof(tag)) {
      std::memcpy(&tag, key.data(), sizeof(tag));
    }
    const bool is_finalized_block = tag == tos_api::consensus_simplex_db_key_finalizedBlock::ID;
    if (is_finalized_block) {
      ++db_->finalized_latest_get_count;
    }
    auto it = db_->map.find(key);
    if (it == db_->map.end()) {
      co_return std::nullopt;
    }
    if (is_finalized_block) {
      ++db_->finalized_latest_found_count;
    }
    co_return it->second.clone();
  }
  td::actor::Task<> set(td::BufferSlice key, td::BufferSlice value) override {
    co_await td::actor::coro_sleep(td::Timestamp::in(td::Random::fast(DB_DELAY.first, DB_DELAY.second)));
    std::scoped_lock lock(db_->mutex);
    // A full disk, a closing database: the write returns an error and nothing is stored.
    // The two vote-journal writes are the only ones whose failure is consensus-significant,
    // so failure injection is addressed at a TL constructor rather than at a key.
    td::uint32 tag = 0;
    if (value.size() >= sizeof(tag)) {
      std::memcpy(&tag, value.data(), sizeof(tag));
    }
    auto it = db_->fail_writes_of.find(tag);
    if (it != db_->fail_writes_of.end() && it->second > 0) {
      --it->second;
      ++db_->failed_write_count;
      co_return td::Status::Error("injected database write failure");
    }
    db_->map[std::move(key)] = std::move(value);
    co_return td::Unit{};
  }
  td::actor::Task<> close() override {
    co_return td::Unit{};
  }

 private:
  std::map<td::BufferSlice, td::BufferSlice> snapshot_;
  std::shared_ptr<DbInner> db_;
};

class TestConsensus : public td::actor::Actor {
 private:
  struct Instance;

 public:
  td::actor::Task<> run() {
    auto result = co_await run_inner().wrap();
    if (result.is_error()) {
      LOG(FATAL) << "Test consensus error: " << result.move_as_error();
    }
    LOG(WARNING) << "Test finished";
    std::exit(0);
  }

  td::actor::Task<> on_block_accepted(size_t node_idx, size_t instance_idx, td::Ref<BlockData> block,
                                      size_t creator_idx, td::Ref<block::BlockSignatureSet> signatures) {
    BlockIdExt block_id = block->block_id();
    if (PQ_FINALITY_E2E_TEST && signatures->is_final()) {
      accepted_carriers_.push_back({block_id, signatures});
    }
    if (signatures->is_final()) {
      if (signatures->is_pq()) {
        signatures
            ->check_pq_signatures_under_carried_session_for_test(validator_set_, block_id, block::FinalityRole::Final)
            .ensure();
      } else {
        signatures->check_signatures(validator_set_, block_id).ensure();
      }
    } else {
      CHECK(!SHARD.is_masterchain());
      if (signatures->is_pq()) {
        signatures
            ->check_pq_signatures_under_carried_session_for_test(validator_set_, block_id, block::FinalityRole::Approve)
            .ensure();
      } else {
        signatures->check_approve_signatures(validator_set_, block_id).ensure();
      }
    }
    BlockSeqno seqno = block_id.seqno();
    if (accepted_blocks_.contains(seqno)) {
      LOG_CHECK(accepted_blocks_[seqno]->block_id() == block_id) << "Accepted different blocks for seqno " << seqno;
    } else {
      accepted_blocks_[seqno] = block;
    }
    Instance& inst = nodes_[node_idx].instances[instance_idx];
    inst.last_accepted_block = std::max(inst.last_accepted_block, seqno);
    if (last_accepted_block_.seqno() < seqno && signatures->is_final()) {
      last_accepted_block_ = block_id;
      last_accepted_block_leader_idx_ = creator_idx;
      if (!EMPTY_CHAIN_RESTART_TEST) {
        for (Node& node : nodes_) {
          for (Instance& inst : node.instances) {
            if (inst.status == Instance::Running) {
              inst.bus.publish<BlockFinalizedInMasterchain>(block_id);
            }
          }
        }
      }
    }
    co_return td::Unit{};
  }

  void on_candidate_relay(size_t node_idx, size_t instance_idx, BlockIdExt block_id) {
    auto key = std::make_tuple(node_idx, instance_idx, block_id);
    auto& count = candidate_relay_counts_[key];
    ++count;
    ++candidate_relay_total_;
    if (count > 1) {
      relay_loop_detected_ = true;
      LOG(ERROR) << "Candidate relay emitted duplicate block " << block_id.to_str() << " from node #" << node_idx << "."
                 << instance_idx;
    }
  }

  td::actor::Task<> wait_block_accepted(BlockIdExt block_id) {
    if (block_id == FIRST_PARENT) {
      co_return td::Unit{};
    }
    td::Timestamp timeout = td::Timestamp::in(10.0);
    while (!timeout.is_in_past()) {
      auto it = accepted_blocks_.find(block_id.seqno());
      if (it != accepted_blocks_.end() && it->second->block_id() == block_id) {
        co_return td::Unit{};
      }
      co_await td::actor::coro_sleep(td::Timestamp::in(0.1));
    }
    co_return td::Status::Error(ErrorCode::timeout, "timeout");
  }

  td::actor::Task<td::Ref<vm::Cell>> wait_block_state_root(BlockIdExt block_id) {
    co_await wait_block_accepted(block_id);
    co_return gen_shard_state(block_id.seqno());
  }

  td::actor::Task<td::Ref<BlockData>> wait_block_data(BlockIdExt block_id) {
    CHECK(block_id != FIRST_PARENT);
    co_await wait_block_accepted(block_id);
    auto it = accepted_blocks_.find(block_id.seqno());
    CHECK(it != accepted_blocks_.end());
    CHECK(it->second->block_id() == block_id);
    co_return it->second;
  }

  size_t longest_consecutive_accepted_block_run() const {
    size_t longest = 0;
    size_t current = 0;
    std::optional<BlockSeqno> previous;
    for (const auto& [seqno, block] : accepted_blocks_) {
      (void)block;
      current = previous.has_value() && seqno == *previous + 1 ? current + 1 : 1;
      longest = std::max(longest, current);
      previous = seqno;
    }
    return longest;
  }

 private:
  td::actor::Task<> run_inner() {
    keyring_ = keyring::Keyring::create("");

    for (size_t i = 0; i < N_NODES; ++i) {
      Node node;

      PrivateKey node_pk{privkeys::Ed25519::random()};
      node.public_key = node_pk.compute_public_key();
      node.node_id = node.public_key.compute_short_id();
      td::actor::send_closure(keyring_, &keyring::Keyring::add_key, std::move(node_pk), true, [](td::Result<>) {});

      PrivateKey adnl_pk{privkeys::Ed25519::random()};
      node.adnl_id_full = adnl::AdnlNodeIdFull{adnl_pk.compute_public_key()};
      node.adnl_id = node.adnl_id_full.compute_short_id();
      td::actor::send_closure(keyring_, &keyring::Keyring::add_key, std::move(adnl_pk), true, [](td::Result<>) {});

      node.weight = 11;

      // A distinct post-quantum consensus key per node, seeded deterministically off its
      // Ed25519 node id so the run is reproducible.
      std::string seed(32, '\0');
      std::memcpy(seed.data(), node.node_id.bits256_value().data(), 32);
      node.pq_store =
          std::make_shared<const tos::pq::ValidatorPQKeyStore>(tos::pq::ValidatorPQKeyStore::from_seed(seed).value());

      nodes_.push_back(std::move(node));
    }

    std::vector<ValidatorDescr> validator_descrs;
    for (size_t idx = 0; idx < nodes_.size(); ++idx) {
      Node& node = nodes_[idx];
      const auto validator_id = tos::ValidatorId{node.node_id.bits256_value()};
      const auto& consensus_key = node.pq_store->consensus_key();
      tos::ConsensusKeyId key_id;
      std::memcpy(key_id.value.data(), consensus_key.key_id.data(), 32);
      validator_descrs.push_back(ValidatorDescr(validator_id, /*algorithm_id=*/1, key_id, consensus_key.public_key,
                                                node.weight, node.adnl_id.bits256_value()));
      validators_.push_back(PeerValidator{.validator_id = validator_id,
                                          .idx = PeerValidatorId((int)idx),
                                          .consensus_key = consensus_key,
                                          .transport_key_id = node.adnl_id.pubkey_hash(),
                                          .adnl_id = node.adnl_id,
                                          .weight = node.weight});
      total_weight_ += node.weight;
    }
    validator_set_ = td::Ref<block::ValidatorSet>{true, CC_SEQNO, SHARD, std::move(validator_descrs)};

    test_overlay = td::actor::create_actor<TestOverlay>("test-overlay");

    for (size_t idx = 0; idx < N_NODES; ++idx) {
      Node& node = nodes_[idx];
      size_t n_instances = idx < N_DOUBLE_NODES ? 2 : 1;
      for (size_t i = 0; i < n_instances; ++i) {
        Instance inst;
        inst.db_inner = std::make_shared<TestDbImpl::DbInner>();
        node.instances.push_back(std::move(inst));
      }
    }

    for (size_t idx = 0; idx < N_NODES; ++idx) {
      for (size_t i = 0; i < nodes_[idx].instances.size(); ++i) {
        start_instance(idx, i);
      }
    }

    if (GREMLIN_PERIOD.first >= 0.0) {
      run_gremlin().start().detach();
    }
    if (NET_GREMLIN_PERIOD.first >= 0.0) {
      run_net_gremlin().start().detach();
    }
    if (ADAPTIVE_BYZANTINE_N != 0) {
      run_adaptive_byzantine().start().detach();
    }
    if (MALICIOUS_OBSERVER_ATTACK) {
      run_malicious_observer_attack().start().detach();
    }
    if (QUERY_ABUSE_TEST) {
      run_query_abuse_test().start().detach();
    }
    if (CATCH_UP_DOWNTIME >= 0.0) {
      run_catch_up_test().start().detach();
    }
    if (EMPTY_CHAIN_RESTART_TEST) {
      run_empty_chain_restart_test().start().detach();
    }
    if (VOTE_JOURNAL_TEST) {
      run_vote_journal_test().start().detach();
    }
    if (PQ_FINALITY_E2E_TEST) {
      run_pq_finality_e2e_test().start().detach();
    }
    if (PERMANENT_FINALIZATION_TEST) {
      run_permanent_finalization_test().start().detach();
    }

    if (!EMPTY_CHAIN_RESTART_TEST && !VOTE_JOURNAL_TEST && !PQ_FINALITY_E2E_TEST) {
      run_write_status().start().detach();
    }

    if (EMPTY_CHAIN_RESTART_TEST) {
      auto deadline = td::Timestamp::in(DURATION);
      while (((!empty_chain_restart_completed_ && empty_chain_restart_error_.empty()) ||
              (PQ_FINALITY_E2E_TEST && !pq_finality_completed_ && pq_finality_error_.empty())) &&
             !deadline.is_in_past()) {
        co_await td::actor::coro_sleep(td::Timestamp::in(0.05));
      }
      if (!empty_chain_restart_completed_ && empty_chain_restart_error_.empty()) {
        empty_chain_restart_error_ = "timed out waiting for the empty-chain restart test";
      }
      if (PQ_FINALITY_E2E_TEST && !pq_finality_completed_ && pq_finality_error_.empty()) {
        pq_finality_error_ = "timed out waiting for the post-quantum finality end-to-end test";
      }
    } else if (VOTE_JOURNAL_TEST) {
      auto deadline = td::Timestamp::in(DURATION);
      while (!vote_journal_completed_ && vote_journal_error_.empty() && !deadline.is_in_past()) {
        co_await td::actor::coro_sleep(td::Timestamp::in(0.05));
      }
      if (!vote_journal_completed_ && vote_journal_error_.empty()) {
        vote_journal_error_ = "timed out waiting for the vote journal test";
      }
    } else if (CATCH_UP_DOWNTIME >= 0.0 && PQ_FINALITY_E2E_TEST) {
      auto deadline = td::Timestamp::in(DURATION);
      while (((!catch_up_completed_ && catch_up_error_.empty()) ||
              (!pq_finality_completed_ && pq_finality_error_.empty())) &&
             !deadline.is_in_past()) {
        co_await td::actor::coro_sleep(td::Timestamp::in(0.05));
      }
      if (!catch_up_completed_ && catch_up_error_.empty()) {
        catch_up_error_ = "timed out waiting for the state-resolver catch-up test";
      }
      if (!pq_finality_completed_ && pq_finality_error_.empty()) {
        pq_finality_error_ = "timed out waiting for the post-quantum finality end-to-end test";
      }
    } else if (PQ_FINALITY_E2E_TEST) {
      auto deadline = td::Timestamp::in(DURATION);
      while (!pq_finality_completed_ && pq_finality_error_.empty() && !deadline.is_in_past()) {
        co_await td::actor::coro_sleep(td::Timestamp::in(0.05));
      }
      if (!pq_finality_completed_ && pq_finality_error_.empty()) {
        pq_finality_error_ = "timed out waiting for the post-quantum finality end-to-end test";
      }
    } else {
      co_await td::actor::coro_sleep(td::Timestamp::in(DURATION));
    }

    co_return co_await finalize();
  }

  td::actor::Task<> run_write_status() {
    while (!finishing_) {
      std::string s;
      for (auto& n : nodes_) {
        for (auto& inst : n.instances) {
          s += "-X"[inst.status == Instance::Running];
        }
      }
      LOG(ERROR) << s;
      co_await td::actor::coro_sleep(td::Timestamp::in(1.0));
    }
    co_return td::Unit{};
  }

  void start_instance(size_t node_idx, size_t instance_idx) {
    Node& node = nodes_[node_idx];
    Instance& inst = node.instances[instance_idx];
    CHECK(inst.status == Instance::Stopped);
    auto& runtime = inst.runtime;
    BlockAccepter::register_in(runtime);
    BlockProducer::register_in(runtime);
    BlockValidator::register_in(runtime);
    CandidateBroadcastRelay::register_in(runtime);
    runtime.register_actor<TestOverlayNode>("PrivateOverlay");
    runtime.register_actor<TestFinalityObserver>("FinalityObserver");
    simplex::CandidateResolver::register_in(runtime);
    simplex::Consensus::register_in(runtime);
    simplex::Pool::register_in(runtime);
    simplex::StateResolver::register_in(runtime);
    simplex::Db::register_in(runtime);
    simplex::DefaultCollatorSchedule::provide_for(runtime);

    inst.manager_facade =
        td::actor::create_actor<TestManagerFacade>(PSTRING() << "ManagerFacade." << node_idx << "." << instance_idx,
                                                   node_idx, instance_idx, validator_set_, actor_id(this));
    auto [stop_task, stop_promise] = td::actor::StartedTask<>::make_bridge();
    auto bus = std::make_shared<TestSimplexBus>();
    inst.stop_waiter = std::move(stop_task);
    bus->instance_idx = instance_idx;
    bus->stop_promise = std::move(stop_promise);
    bus->shard = SHARD;
    bus->manager = inst.manager_facade.get();
    bus->keyring = keyring_.get();
    bus->pq_signer = nodes_[node_idx].pq_store;
    bus->validator_opts = ValidatorManagerOptions::create(BlockIdExt{}, BlockIdExt{});
    bus->validator_set = validators_;
    for (const auto& validator : validators_) {
      bus->all_validators.push_back(validator.adnl_id);
    }
    bus->total_weight = total_weight_;
    bus->local_id = validators_[node_idx];
    bus->local_adnl_id = nodes_[node_idx].adnl_id;
    bus->config = NewConsensusConfig{
        .max_block_size = 1 << 20,
        .max_collated_data_size = 1 << 20,
        .protocol_version = 2,
        .slots_per_leader_window = SLOTS_PER_LEADER_WINDOW,
        .noncritical_params = {.target_rate{TARGET_RATE_MS}},
    };
    bus->session_id = SESSION_ID;
    bus->cc_seqno = CC_SEQNO;
    bus->validator_set_hash = validator_set_->get_validator_set_hash();
    bus->db = std::make_unique<TestDbImpl>(inst.db_inner);
    inst.bus = runtime.start(std::static_pointer_cast<simplex::Bus>(bus),
                             PSTRING() << "consensus." << node_idx << "." << instance_idx);
    inst.status = Instance::Running;
    inst.bus.publish<BlockFinalizedInMasterchain>(last_accepted_block_);
    if (RESTART_FROM_LAST_ACCEPTED_BLOCK && inst.started_before) {
      CHECK(!accepted_blocks_.empty());
      const auto& [seqno, block] = *accepted_blocks_.rbegin();
      CHECK(seqno > FIRST_PARENT.seqno());
      LOG(WARNING) << "Restarting node #" << node_idx << "." << instance_idx << " from last accepted block "
                   << block->block_id().to_str();
      inst.bus.publish<Start>(
          td::make_ref<ChainState>(ChainState::NormalTip{block, gen_shard_state(seqno)}, MIN_MC_BLOCK_ID));
    } else {
      inst.bus.publish<Start>(
          td::make_ref<ChainState>(ChainState::ZerostateTip{FIRST_PARENT, gen_shard_state(0)}, MIN_MC_BLOCK_ID));
    }
    inst.started_before = true;
    LOG(ERROR) << "Starting node #" << node_idx << "." << instance_idx;
  }

  td::actor::Task<> stop_instance(size_t node_idx, size_t instance_idx) {
    Node& node = nodes_[node_idx];
    Instance& inst = node.instances[instance_idx];
    if (inst.status == Instance::Stopped) {
      co_return td::Unit{};
    }
    if (inst.status == Instance::Stopping) {
      auto [task, promise] = td::actor::StartedTask<>::make_bridge();
      inst.extra_stop_waiters.push_back(std::move(promise));
      co_return co_await std::move(task);
    }
    LOG(ERROR) << "Stopping node #" << node_idx << "." << instance_idx;
    inst.bus.publish<StopRequested>();
    inst.bus = {};
    inst.status = Instance::Stopping;
    co_await std::move(*inst.stop_waiter);
    //std::move(inst.stop_waiter.value()).detach();
    //co_await td::actor::coro_sleep(td::Timestamp::in(0.5));
    inst.status = Instance::Stopped;
    inst.runtime = {};
    LOG(ERROR) << "Stopped node #" << node_idx << "." << instance_idx;
    for (auto& promise : inst.extra_stop_waiters) {
      promise.set_value(td::Unit{});
    }
    inst.extra_stop_waiters.clear();
    co_return td::Unit{};
  }

  td::actor::Task<> run_gremlin() {
    for (size_t i = 0; i < GREMLIN_TIMES && !finishing_; ++i) {
      co_await td::actor::coro_sleep(td::Timestamp::in(td::Random::fast(GREMLIN_PERIOD.first, GREMLIN_PERIOD.second)));
      int cnt = td::Random::fast((int)GREMLIN_N.first, (int)GREMLIN_N.second);
      for (int i = 0; i < cnt; ++i) {
        run_gremlin_once().start().detach();
      }
    }
    co_return td::Unit{};
  }

  td::actor::Task<> run_gremlin_once() {
    if (finishing_) {
      co_return td::Unit{};
    }
    size_t kill_node_idx = 0, kill_inst_idx = 0;
    int cnt = 0;
    for (size_t node_idx = 0; node_idx < N_NODES; ++node_idx) {
      if (GREMLIN_KILLS_LEADER &&
          (!last_accepted_block_leader_idx_ || last_accepted_block_leader_idx_.value() != node_idx)) {
        continue;
      }
      for (size_t inst_idx = 0; inst_idx < nodes_[node_idx].instances.size(); ++inst_idx) {
        if (nodes_[node_idx].instances[inst_idx].status == Instance::Running) {
          ++cnt;
          if (td::Random::fast(1, cnt) == 1) {
            kill_node_idx = node_idx;
            kill_inst_idx = inst_idx;
          }
        }
      }
    }
    if (cnt == 0) {
      co_return td::Unit{};
    }
    co_await stop_instance(kill_node_idx, kill_inst_idx);
    // Counted once the node is actually down, so "it happened" is not "it was started".
    ++INJECTED_NODE_KILLS;
    co_await td::actor::coro_sleep(
        td::Timestamp::in(td::Random::fast(GREMLIN_DOWNTIME.first, GREMLIN_DOWNTIME.second)));
    if (finishing_) {
      co_return td::Unit{};
    }
    start_instance(kill_node_idx, kill_inst_idx);
    co_return td::Unit{};
  }

  td::actor::Task<> run_net_gremlin() {
    for (size_t i = 0; i < NET_GREMLIN_TIMES && !finishing_; ++i) {
      co_await td::actor::coro_sleep(
          td::Timestamp::in(td::Random::fast(NET_GREMLIN_PERIOD.first, NET_GREMLIN_PERIOD.second)));
      int cnt = td::Random::fast((int)NET_GREMLIN_N.first, (int)NET_GREMLIN_N.second);
      for (int i = 0; i < cnt; ++i) {
        run_net_gremlin_once().start().detach();
      }
    }
    co_return td::Unit{};
  }

  td::actor::Task<> run_net_gremlin_once() {
    if (finishing_) {
      co_return td::Unit{};
    }
    size_t selected_node_idx = 0, selected_inst_idx = 0;
    int cnt = 0;
    for (size_t node_idx = 0; node_idx < N_NODES; ++node_idx) {
      if (NET_GREMLIN_KILLS_LEADER &&
          (!last_accepted_block_leader_idx_ || last_accepted_block_leader_idx_.value() != node_idx)) {
        continue;
      }
      for (size_t inst_idx = 0; inst_idx < nodes_[node_idx].instances.size(); ++inst_idx) {
        if (!nodes_[node_idx].instances[inst_idx].net_gremlin_active) {
          ++cnt;
          if (td::Random::fast(1, cnt) == 1) {
            selected_node_idx = node_idx;
            selected_inst_idx = inst_idx;
          }
        }
      }
    }
    if (cnt == 0) {
      co_return td::Unit{};
    }
    nodes_[selected_node_idx].instances[selected_inst_idx].net_gremlin_active = true;
    co_await td::actor::ask(test_overlay, &TestOverlay::set_instance_disabled, selected_node_idx, selected_inst_idx,
                            true);
    // Counted once the network is actually cut, for the same reason.
    ++INJECTED_NETWORK_CUTS;
    co_await td::actor::coro_sleep(
        td::Timestamp::in(td::Random::fast(NET_GREMLIN_DOWNTIME.first, NET_GREMLIN_DOWNTIME.second)));
    co_await td::actor::ask(test_overlay, &TestOverlay::set_instance_disabled, selected_node_idx, selected_inst_idx,
                            false);
    nodes_[selected_node_idx].instances[selected_inst_idx].net_gremlin_active = false;
    co_return td::Unit{};
  }

  td::actor::Task<> run_adaptive_byzantine() {
    td::uint64 epoch = 0;
    while (!finishing_) {
      std::vector<size_t> selected;
      if (last_accepted_block_leader_idx_) {
        selected.push_back(*last_accepted_block_leader_idx_);
      }
      for (size_t offset = 0; selected.size() < ADAPTIVE_BYZANTINE_N && offset < N_NODES; ++offset) {
        size_t candidate = (epoch + offset) % N_NODES;
        if (std::find(selected.begin(), selected.end(), candidate) == selected.end()) {
          selected.push_back(candidate);
        }
      }
      co_await td::actor::ask(test_overlay, &TestOverlay::set_adaptive_byzantine_nodes, selected, epoch);
      ++adaptive_byzantine_epochs_;
      ++epoch;
      co_await td::actor::coro_sleep(td::Timestamp::in(ADAPTIVE_BYZANTINE_PERIOD));
    }
    co_return td::Unit{};
  }

  td::actor::Task<> run_malicious_observer_attack() {
    // Wait until Pool has consumed Start, then inject a syntactically valid
    // vote from an authenticated overlay member that has no validator
    // identity.  Repeating it also exercises the temporary-ban fast path.
    co_await td::actor::coro_sleep(td::Timestamp::in(0.2));
    td::Bits256 observer_bits;
    td::Random::secure_bytes(observer_bits.as_slice());
    auto observer = adnl::AdnlNodeIdShort{observer_bits};
    td::BufferSlice fake_signature(64);
    std::memset(fake_signature.data(), 0x5a, fake_signature.size());
    auto vote = create_serialize_tl_object<simplex::tl::vote>(simplex::SkipVote{0}.to_tl(), std::move(fake_signature));
    for (int repeat = 0; repeat < 2; ++repeat) {
      for (auto& node : nodes_) {
        for (auto& inst : node.instances) {
          if (inst.status == Instance::Running) {
            inst.bus.publish<IncomingProtocolMessage>(std::nullopt, observer, vote.clone());
            ++malicious_observer_messages_;
          }
        }
      }
      co_await td::actor::coro_sleep(td::Timestamp::in(0.05));
    }
    co_return td::Unit{};
  }

  td::actor::Task<> run_query_abuse_test() {
    // A private-overlay observer may query candidates, but one ADNL identity
    // must not exceed candidate_resolve_rate_limit within the one-second
    // window.
    co_await td::actor::coro_sleep(td::Timestamp::in(0.2));
    td::Bits256 observer_bits;
    td::Random::secure_bytes(observer_bits.as_slice());
    auto observer = adnl::AdnlNodeIdShort{observer_bits};
    auto& bus = nodes_[0].instances[0].bus;
    const auto limit = bus->config.noncritical_params.candidate_resolve_rate_limit;
    for (td::uint32 index = 0; index < limit + 3; ++index) {
      CandidateId id{.slot = 1000000 + index, .hash = td::Bits256{}};
      auto data = create_serialize_tl_object<tos_api::consensus_simplex_requestCandidate>(id.to_tl(), true, true);
      auto request = std::make_shared<IncomingOverlayRequest>(std::nullopt, observer, std::move(data));
      auto result = co_await bus.publish(std::move(request)).wrap();
      if (result.is_ok()) {
        ++query_abuse_accepted_;
      } else {
        ++query_abuse_rejected_;
      }
    }
    // The requested ids are far outside any live slot; serving them must not
    // leave permanent per-id state behind. Count only entries at or above the
    // injected slot base so legitimate in-flight consensus state (low slots)
    // does not mask a regression: this must be zero.
    query_abuse_tracked_states_ = co_await bus.publish(std::make_shared<simplex::QueryResolverTrackedStateCount>(
        simplex::QueryResolverTrackedStateCount{.min_slot = 1000000}));
    query_abuse_completed_ = true;
    co_return td::Unit{};
  }

  td::actor::Task<> run_catch_up_test() {
    // Keep one validator fully offline while the remaining quorum advances,
    // then restart it with its existing DB. Tiny cache limits in the CTest
    // command force StateResolver to use both completed-entry eviction and
    // the live finalized-key lookup while replaying the missing history.
    co_await td::actor::coro_sleep(td::Timestamp::in(0.5));
    catch_up_node_idx_ = N_NODES - 1;
    auto& instance = nodes_[catch_up_node_idx_].instances[0];
    const BlockSeqno stopped_at = instance.last_accepted_block;
    co_await stop_instance(catch_up_node_idx_, 0);
    co_await td::actor::coro_sleep(td::Timestamp::in(CATCH_UP_DOWNTIME));
    catch_up_target_ = last_accepted_block_.seqno();
    if (catch_up_target_ < stopped_at + 8) {
      catch_up_error_ = PSTRING() << "chain advanced only " << (catch_up_target_ - stopped_at)
                                  << " blocks during catch-up downtime";
      co_return td::Unit{};
    }

    start_instance(catch_up_node_idx_, 0);
    catch_up_restarted_ = true;
    while (!finishing_) {
      if (instance.last_accepted_block >= catch_up_target_) {
        catch_up_completed_ = true;
        co_return td::Unit{};
      }
      co_await td::actor::coro_sleep(td::Timestamp::in(0.05));
    }
    co_return td::Unit{};
  }

  size_t candidate_record_count(const Instance& instance) const {
    std::scoped_lock lock(instance.db_inner->mutex);
    const td::uint32 prefix = tos_api::consensus_simplex_db_key_candidate::ID;
    size_t result = 0;
    for (const auto& [key, _] : instance.db_inner->map) {
      if (key.size() >= sizeof(prefix) && std::memcmp(key.data(), &prefix, sizeof(prefix)) == 0) {
        ++result;
      }
    }
    return result;
  }

  size_t trailing_empty_candidate_count(const Instance& instance) const {
    std::vector<td::BufferSlice> serialized_candidates;
    {
      std::scoped_lock lock(instance.db_inner->mutex);
      const td::uint32 prefix = tos_api::consensus_simplex_db_key_candidate::ID;
      for (const auto& [key, value] : instance.db_inner->map) {
        if (key.size() >= sizeof(prefix) && std::memcmp(key.data(), &prefix, sizeof(prefix)) == 0) {
          serialized_candidates.push_back(value.clone());
        }
      }
    }

    std::map<CandidateId, CandidateRef> candidates;
    for (const auto& serialized : serialized_candidates) {
      auto candidate = Candidate::deserialize(serialized, *instance.bus).move_as_ok();
      candidates.emplace(candidate->id, std::move(candidate));
    }
    if (candidates.empty()) {
      return 0;
    }

    size_t result = 0;
    auto candidate = candidates.rbegin()->second;
    while (candidate->is_empty()) {
      ++result;
      CHECK(candidate->parent_id.has_value());
      auto it = candidates.find(*candidate->parent_id);
      CHECK(it != candidates.end());
      candidate = it->second;
    }
    return result;
  }

  // ===== The post-quantum round and its persisted finality carrier =====

  // Check a finality certificate the way a peer would, without reusing the code that
  // produced it: every signature verified against the key the validator set records for
  // that signer, no signer counted twice, and the weight behind it at or above the quorum.
  std::string certificate_defect(const simplex::FinalCertRef& cert) const {
    auto signed_bytes = serialize_tl_object(cert->vote.to_tl(), true);
    std::set<size_t> signers;
    ValidatorWeight weight = 0;
    for (const auto& [validator, signature] : cert->signatures) {
      auto idx = validator.value();
      if (idx >= validators_.size()) {
        return PSTRING() << "signer index " << idx << " is outside the validator set";
      }
      if (!signers.insert(idx).second) {
        return PSTRING() << "signer " << idx << " appears twice in the certificate";
      }
      if (signature.size() != tos::pq::mldsa44_signature_bytes) {
        return PSTRING() << "signer " << idx << " contributed a " << signature.size() << "-byte signature";
      }
      if (!validators_[idx].check_signature(SESSION_ID, signed_bytes, signature)) {
        return PSTRING() << "signer " << idx << "'s signature does not verify under its post-quantum key";
      }
      if (!tos::checked_add_validator_weight(weight, validators_[idx].weight)) {
        return "the certificate's signer weight overflows";
      }
    }
    if (weight < tos::quorum_threshold(total_weight_)) {
      return PSTRING() << "the certificate carries weight " << weight << ", below the quorum threshold "
                       << tos::quorum_threshold(total_weight_);
    }
    return {};
  }

  td::actor::Task<> run_pq_finality_e2e_test() {
    auto fail = [&](std::string message) { pq_finality_error_ = std::move(message); };

    struct Adversity {
      bool configured;
      std::function<bool()> happened;
      const char* name;
    };
    const std::vector<Adversity> adversities = {
        {NET_LOSS > 0.0, [] { return INJECTED_PACKET_LOSSES.load() > 0; }, "packet loss"},
        {GREMLIN_PERIOD.first >= 0.0, [] { return INJECTED_NODE_KILLS.load() > 0; }, "a node restart"},
        {NET_GREMLIN_PERIOD.first >= 0.0, [] { return INJECTED_NETWORK_CUTS.load() > 0; }, "a network partition"},
        {MALICIOUS_OBSERVER_ATTACK, [this] { return malicious_observer_messages_ > 0; }, "the malicious observer"},
        {RELAY_LOOP_TEST, [this] { return candidate_relay_total_ > 0; }, "candidate relay traffic"},
        {ADAPTIVE_BYZANTINE_N != 0, [this] { return adaptive_byzantine_epochs_ >= 2; },
         "an adaptive Byzantine rotation"},
        {QUERY_ABUSE_TEST, [this] { return query_abuse_completed_; }, "the candidate query flood"},
        {BYZANTINE_RELAY_NODE >= 0, [] { return BYZANTINE_RELAYS_SENT.load() > 0; },
         "a validator relaying another's signed vote"},
        {FINALIZATION_BACKPRESSURE_TEST,
         [] { return BACKLOG_OVER_LIMIT_REPORTS.load() > 0 && BACKLOG_CLEARED_REPORTS.load() > 0; },
         "a finalization backlog activation and recovery"},
    };
    auto deadline = td::Timestamp::in(DURATION * 0.8);
    for (const auto& adversity : adversities) {
      if (!adversity.configured) {
        continue;
      }
      while (!adversity.happened() && !deadline.is_in_past()) {
        co_await td::actor::coro_sleep(td::Timestamp::in(0.02));
      }
      if (!adversity.happened()) {
        fail(PSTRING() << "this scenario configures " << adversity.name << ", but it never happened");
        co_return td::Unit{};
      }
    }

    const size_t required_consecutive_accepted_blocks = FINALIZATION_BACKPRESSURE_TEST ? 1 : 3;
    while ((read_finality_log().empty() || accepted_carriers_.empty() ||
            longest_consecutive_accepted_block_run() < required_consecutive_accepted_blocks) &&
           !deadline.is_in_past()) {
      co_await td::actor::coro_sleep(td::Timestamp::in(0.05));
    }
    if (read_finality_log().empty()) {
      fail("no verified FinalCert was observed");
      co_return td::Unit{};
    }
    if (accepted_carriers_.empty()) {
      fail("a verified FinalCert never reached the post-quantum block-signature carrier");
      co_return td::Unit{};
    }
    const auto consecutive_accepted_blocks = longest_consecutive_accepted_block_run();
    if (consecutive_accepted_blocks < required_consecutive_accepted_blocks) {
      fail(PSTRING() << "post-quantum finality accepted only " << consecutive_accepted_blocks
                     << " consecutive blocks, expected at least " << required_consecutive_accepted_blocks);
      co_return td::Unit{};
    }
    if (FINALIZATION_BACKPRESSURE_TEST && CANDIDATES_WHILE_BACKLOGGED.load() != 0) {
      fail(PSTRING() << "the network produced " << CANDIDATES_WHILE_BACKLOGGED.load()
                     << " candidate(s) while finalization backpressure was active");
      co_return td::Unit{};
    }
    if (FINALIZATION_BACKPRESSURE_TEST) {
      LOG(WARNING) << "Finalization backpressure scenario: over-limit reports=" << BACKLOG_OVER_LIMIT_REPORTS.load()
                   << "; cleared reports=" << BACKLOG_CLEARED_REPORTS.load()
                   << "; candidates while throttled=" << CANDIDATES_WHILE_BACKLOGGED.load()
                   << "; consecutive accepted blocks after recovery=" << consecutive_accepted_blocks;
    }

    size_t independently_verified_proofs = 0;
    for (const auto& item : accepted_carriers_) {
      const block::PQFinalityVerificationContext context{validator_set_, item.block_id, SESSION_ID};
      auto verified = block::verify_pq_finality(context, *item.signatures, block::FinalityRole::Final);
      if (verified.is_error()) {
        fail(PSTRING() << "accepted proof " << item.block_id.to_str()
                       << " failed independent trusted-context verification: " << verified.error());
        co_return td::Unit{};
      }
      ++independently_verified_proofs;
    }

    std::optional<AcceptedCarrier> accepted;
    simplex::FinalCertRef certificate;
    for (const auto& item : accepted_carriers_) {
      auto slot = item.signatures->pq_slot();
      auto candidate_data = item.signatures->pq_candidate_data();
      if (slot.is_error() || candidate_data.is_error()) {
        continue;
      }
      auto candidate_hash = td::sha256_bits256(candidate_data.ok().as_slice());
      auto item_pairs = item.signatures->export_pq_signatures();
      if (item_pairs.is_error()) {
        continue;
      }
      std::map<ValidatorId, td::Slice> item_by_id;
      for (const auto& pair : item_pairs.ok()) {
        item_by_id.emplace(pair.validator_id, pair.signature.as_slice());
      }
      for (const auto& observed : read_finality_log()) {
        if (observed.id.slot != slot.ok() || observed.id.hash != candidate_hash ||
            observed.cert->vote.id != observed.id || observed.cert->signatures.size() != item_by_id.size()) {
          continue;
        }
        bool exact_certificate = true;
        for (const auto& [signer_index, signature] : observed.cert->signatures) {
          const auto index = signer_index.value();
          if (index >= validators_.size()) {
            exact_certificate = false;
            break;
          }
          auto pair = item_by_id.find(validators_[index].validator_id);
          if (pair == item_by_id.end() || pair->second != signature.as_slice()) {
            exact_certificate = false;
            break;
          }
        }
        if (!exact_certificate) {
          continue;
        }
        accepted = item;
        certificate = observed.cert;
        break;
      }
      if (accepted.has_value()) {
        break;
      }
    }
    if (certificate.is_null()) {
      fail("no observed FinalCert matches an accepted post-quantum carrier's candidate and exact signature bytes");
      co_return td::Unit{};
    }
    if (auto defect = certificate_defect(certificate); !defect.empty()) {
      fail(PSTRING() << "the accepted FinalCert is defective: " << defect);
      co_return td::Unit{};
    }

    auto carried = accepted->signatures->export_pq_signatures().move_as_ok();
    auto persisted_cell = accepted->signatures->serialize(validator_set_).move_as_ok();
    auto persisted_boc = vm::std_boc_serialize(persisted_cell, 31).move_as_ok();
    auto roundtrip_store = std::make_shared<TestDbImpl::DbInner>();
    TestDbImpl roundtrip_db(roundtrip_store);
    td::BufferSlice roundtrip_key("pq-finality-carrier-roundtrip");
    co_await roundtrip_db.set(roundtrip_key.clone(), persisted_boc.clone());
    auto loaded_boc = co_await roundtrip_db.get_latest(roundtrip_key.clone());
    if (!loaded_boc.has_value()) {
      fail("the database round trip did not return the post-quantum carrier");
      co_return td::Unit{};
    }
    auto loaded_cell = vm::std_boc_deserialize(loaded_boc->as_slice()).move_as_ok();
    auto db_roundtrip = block::BlockSignatureSet::fetch(loaded_cell, validator_set_).move_as_ok();
    auto db_pairs = db_roundtrip->export_pq_signatures().move_as_ok();

    vm::CellBuilder proof_builder;
    td::Ref<vm::Cell> proof_cell;
    auto proof_payload = vm::CellBuilder{}.finalize_novm();
    if (!proof_builder.store_long_bool(0xc3, 8)) {
      fail("could not store the BlockProof constructor");
      co_return td::Unit{};
    }
    if (!block::tlb::t_BlockIdExt.pack(proof_builder, accepted->block_id)) {
      fail("could not store the BlockProof block id");
      co_return td::Unit{};
    }
    if (!proof_builder.store_ref_bool(std::move(proof_payload))) {
      fail("could not store the BlockProof payload");
      co_return td::Unit{};
    }
    if (!proof_builder.store_bool_bool(true)) {
      fail("could not store the BlockProof signature presence bit");
      co_return td::Unit{};
    }
    if (!proof_builder.store_ref_bool(persisted_cell)) {
      fail("could not store the BlockProof signature set");
      co_return td::Unit{};
    }
    if (!proof_builder.finalize_to(proof_cell)) {
      fail("could not finalize the BlockProof round-trip fixture");
      co_return td::Unit{};
    }
    block::gen::BlockProof::Record proof;
    if (!block::gen::t_BlockProof.cell_unpack(proof_cell, proof) || proof.signatures.is_null() ||
        proof.signatures->size_refs() != 1) {
      fail("could not load the post-quantum carrier from BlockProof");
      co_return td::Unit{};
    }
    auto proof_set = block::BlockSignatureSet::fetch(proof.signatures->prefetch_ref(), validator_set_).move_as_ok();
    auto proof_pairs = proof_set->export_pq_signatures().move_as_ok();

    auto by_id = [](const std::vector<block::PQBlockSignature>& pairs) {
      std::map<ValidatorId, td::Slice> result;
      for (const auto& pair : pairs) {
        result.emplace(pair.validator_id, pair.signature.as_slice());
      }
      return result;
    };
    auto carried_by_id = by_id(carried);
    auto db_by_id = by_id(db_pairs);
    auto proof_by_id = by_id(proof_pairs);
    size_t compared = 0;
    auto wanted_vote = serialize_tl_object(simplex::Vote{certificate->vote}.to_tl(), true);
    for (const auto& [signer_index, cert_bytes] : certificate->signatures) {
      const auto index = signer_index.value();
      if (index >= nodes_.size()) {
        fail(PSTRING() << "FinalCert signer " << index << " is outside the node set");
        co_return td::Unit{};
      }
      auto journal = own_vote_journal(nodes_[index].instances[0]);
      td::Slice journal_bytes;
      for (const auto& entry : journal) {
        if (entry.is_signed && serialize_tl_object(entry.vote, true).as_slice() == wanted_vote.as_slice()) {
          journal_bytes = entry.signature.as_slice();
        }
      }
      const auto validator_id = validators_[index].validator_id;
      auto carrier_it = carried_by_id.find(validator_id);
      auto db_it = db_by_id.find(validator_id);
      auto proof_it = proof_by_id.find(validator_id);
      if (journal_bytes.empty() || carrier_it == carried_by_id.end() || db_it == db_by_id.end() ||
          proof_it == proof_by_id.end()) {
        fail(PSTRING() << "signer " << index << " is missing from exact-byte source(s): journal="
                       << !journal_bytes.empty() << " carrier=" << (carrier_it != carried_by_id.end())
                       << " db=" << (db_it != db_by_id.end()) << " block-proof=" << (proof_it != proof_by_id.end()));
        co_return td::Unit{};
      }
      if (journal_bytes != cert_bytes.as_slice() || cert_bytes.as_slice() != carrier_it->second ||
          carrier_it->second != db_it->second || db_it->second != proof_it->second) {
        fail(PSTRING() << "EXACT_SIGNATURE_BYTES_MISMATCH signer=" << index
                       << " journal/final-cert/carrier/db/block-proof are not byte-identical");
        co_return td::Unit{};
      }
      ++compared;
    }
    if (compared == 0) {
      fail("the accepted carrier contained no signatures to compare");
      co_return td::Unit{};
    }
    LOG(WARNING) << "PQ finality carrier: compared " << compared
                 << " signature(s) byte-for-byte across journal, FinalCert, #13 carrier, database round trip and "
                    "BlockProof; carrier-missing count=0; longest consecutive accepted run="
                 << consecutive_accepted_blocks
                 << "; independently verified accepted proofs=" << independently_verified_proofs;
    if (C05_GENESIS_FAULT_BUDGET != 0) {
      if (N_NODES != 4 || (C05_GENESIS_FAULT_BUDGET != 3 && C05_GENESIS_FAULT_BUDGET != 24) ||
          NewConsensusConfig{}.noncritical_params.first_block_timeout != std::chrono::milliseconds(1000)) {
        fail("C05 simultaneous control is not a four-node, three/24-fault, one-second-timeout run");
        co_return td::Unit{};
      }
      std::optional<CandidateId> target;
      BlockIdExt target_block;
      simplex::NotarCertRef notar_cert;
      double candidate_time = 0;
      double cert_time = 0;
      {
        std::scoped_lock lock(C05_SIMULTANEOUS_OBSERVATION.mutex);
        target = C05_SIMULTANEOUS_OBSERVATION.first_candidate;
        target_block = C05_SIMULTANEOUS_OBSERVATION.first_block;
        notar_cert = C05_SIMULTANEOUS_OBSERVATION.notar_cert;
        candidate_time = C05_SIMULTANEOUS_OBSERVATION.candidate_time;
        cert_time = C05_SIMULTANEOUS_OBSERVATION.notar_cert_time;
      }
      if (!target || target_block.seqno() != 1 || !accepted_blocks_.contains(1)) {
        fail("C05 injected first candidate or later recovery block was not observed");
        co_return td::Unit{};
      }
      if (C05_GENESIS_FAULT_BUDGET == 24) {
        if (!notar_cert.is_null() || accepted_blocks_.at(1)->block_id() == target_block) {
          fail("C05 over-budget first candidate was notarized or accepted after its skip window");
          co_return td::Unit{};
        }
        for (const auto& observed : read_finality_log()) {
          if (observed.id == *target) {
            fail("C05 over-budget first candidate received a late FinalCert");
            co_return td::Unit{};
          }
        }
        auto wanted_vote = serialize_tl_object(simplex::Vote{simplex::NotarizeVote{*target}}.to_tl(), true);
        for (size_t node = 1; node < 4; ++node) {
          if (C05_GENESIS_FAULTS[node].load() != 24 ||
              C05_LAST_FAULT_TIME[node].load() - candidate_time <= 1.0) {
            fail(PSTRING() << "C05 node " << node << " did not remain unavailable beyond the one-second window");
            co_return td::Unit{};
          }
          for (const auto& entry : own_vote_journal(nodes_[node].instances[0])) {
            if (entry.is_signed && serialize_tl_object(entry.vote, true).as_slice() == wanted_vote.as_slice()) {
              fail(PSTRING() << "C05 node " << node << " signed a late vote for the over-budget first candidate");
              co_return td::Unit{};
            }
          }
        }
        LOG(WARNING) << "C05_SIMULTANEOUS_OVER_BUDGET_OK: three nodes each missed 24 parent-state reads beyond "
                        "the one-second first-block window; original candidate had no late vote, NotarCert, "
                        "FinalCert or acceptance; a later candidate was accepted";
        pq_finality_completed_ = true;
        co_return td::Unit{};
      }
      if (notar_cert.is_null() || accepted_blocks_.at(1)->block_id() != target_block) {
        fail("C05 recovered first candidate did not reach a NotarCert and accepted block");
        co_return td::Unit{};
      }
      if (cert_time <= candidate_time || cert_time - candidate_time >= 1.0) {
        fail(PSTRING() << "C05 first candidate's NotarCert was not observed inside the one-second window: "
                       << (cert_time - candidate_time));
        co_return td::Unit{};
      }
      auto wanted_vote = serialize_tl_object(simplex::Vote{notar_cert->vote}.to_tl(), true);
      size_t faulted_signers_in_cert = 0;
      for (const auto& [signer, signature] : notar_cert->signatures) {
        (void)signature;
        faulted_signers_in_cert += signer.value() > 0 && signer.value() < 4;
      }
      if (faulted_signers_in_cert < 2) {
        fail("C05 first NotarCert did not include a quorum contribution from faulted nodes");
        co_return td::Unit{};
      }
      for (size_t node = 1; node < 4; ++node) {
        if (C05_GENESIS_FAULTS[node].load() != 3) {
          fail(PSTRING() << "C05 node " << node << " did not exhaust its three injected parent-state misses");
          co_return td::Unit{};
        }
        size_t signed_votes = 0;
        for (const auto& entry : own_vote_journal(nodes_[node].instances[0])) {
          signed_votes += entry.is_signed && serialize_tl_object(entry.vote, true).as_slice() == wanted_vote.as_slice();
        }
        if (signed_votes != 1) {
          fail(PSTRING() << "C05 node " << node << " had " << signed_votes
                         << " signed notarize votes for the recovered candidate, expected one");
          co_return td::Unit{};
        }
      }
      bool finalized_target = false;
      for (const auto& observed : read_finality_log()) {
        finalized_target |= observed.id == *target;
      }
      if (!finalized_target) {
        fail("C05 recovered first candidate never reached FinalCert");
        co_return td::Unit{};
      }
      LOG(WARNING) << "C05_SIMULTANEOUS_RECOVERY_OK: three nodes each exhausted three parent-state reads; "
                      "each persisted one signed notarize vote; first NotarCert after "
                   << (cert_time - candidate_time) * 1000.0 << " ms; first FinalCert and block accepted";
    }
    pq_finality_completed_ = true;
    co_return td::Unit{};
  }

  // ===== A failure retrying cannot mend =====
  //
  // Every finalization failure used to be treated as transient, which is
  // not a policy but the absence of one: it commits a node to retrying a protocol violation
  // for as long as it lives. The resolver now classifies, and this is the branch nothing in
  // production cannot reach deterministically -- so it is injected, and what is required of it
  // is the three things that make the classification worth having.
  //
  // The certificate is kept, because it is still evidence a quorum agreed. It is not
  // retried, because retrying is what the classification says is pointless here. And the
  // group stops producing, because a chain must not run ahead of a finality that is not
  // coming.
  td::actor::Task<> run_permanent_finalization_test() {
    auto fail = [&](std::string message) { permanent_finalization_error_ = std::move(message); };

    auto first_stalled =
        [&]() -> td::actor::Task<std::optional<std::pair<size_t, simplex::QueryFinalizationState::Result>>> {
      for (size_t node_idx = 0; node_idx < N_NODES; ++node_idx) {
        for (auto& instance : nodes_[node_idx].instances) {
          if (instance.status != Instance::Running) {
            continue;
          }
          auto seen = co_await instance.bus.publish(std::make_shared<simplex::QueryFinalizationState>(0));
          if (seen.finalizations_stalled_permanently > 0) {
            co_return std::make_pair(node_idx, seen);
          }
        }
      }
      co_return std::nullopt;
    };

    auto deadline = td::Timestamp::in(DURATION * 0.5);
    std::optional<std::pair<size_t, simplex::QueryFinalizationState::Result>> stalled;
    while (!stalled.has_value() && !deadline.is_in_past()) {
      stalled = co_await first_stalled();
      if (!stalled.has_value()) {
        co_await td::actor::coro_sleep(td::Timestamp::in(0.05));
      }
    }
    if (!stalled.has_value()) {
      fail("no node reported a finalization it cannot retry, so the injected failure never reached the seam");
      co_return td::Unit{};
    }
    const size_t node_idx = stalled->first;
    const auto first = stalled->second;

    if (first.pending_finalizations == 0) {
      fail(PSTRING() << "node " << node_idx
                     << " reported a finalization it cannot retry but is holding none; a certificate a quorum "
                     << "agreed on must be kept even when converting it cannot be retried");
      co_return td::Unit{};
    }

    // Not retried: over a window in which a retryable failure would have been tried several
    // times, neither the attempt count nor the stalled count moves.
    auto candidates_before = CANDIDATES_GENERATED.load();
    co_await td::actor::coro_sleep(td::Timestamp::in(std::min(DURATION * 0.1, 3.0)));
    auto later =
        co_await nodes_[node_idx].instances[0].bus.publish(std::make_shared<simplex::QueryFinalizationState>(0));

    if (later.finalization_retries > first.finalization_retries) {
      fail(PSTRING() << "node " << node_idx << " retried " << (later.finalization_retries - first.finalization_retries)
                     << " finalization(s) after classifying one as beyond retrying");
      co_return td::Unit{};
    }
    if (CANDIDATES_GENERATED.load() != candidates_before) {
      fail(PSTRING() << "the network produced " << (CANDIDATES_GENERATED.load() - candidates_before)
                     << " candidates while a node held a certificate it cannot finalize; the group has to stop "
                     << "rather than run further ahead of a finality that is not coming");
      co_return td::Unit{};
    }

    LOG(WARNING) << "Permanent finalization: node " << node_idx << " is holding " << later.pending_finalizations
                 << " certificate(s) it cannot convert, has not retried them, and the network produced no further "
                 << "candidate while it held them";
    permanent_finalization_completed_ = true;
    co_return td::Unit{};
  }

  // ===== This node's own vote journal =====
  //
  // The property under test is not "the node persists its votes". It is that the first
  // signature bytes allowed to become observable are already durable, and that from then on
  // those exact bytes are what comes back. ML-DSA-44 signing is randomized, so a node that
  // signs again after a restart produces a second valid signature for a vote a peer may
  // already hold inside a certificate.
  struct JournalledVote {
    td::BufferSlice key;
    td::BufferSlice value;
    bool is_signed = false;
    td::int64 seqno = 0;
    td::BufferSlice signature;
    tos_api::consensus_simplex_UnsignedVote* vote = nullptr;  // owned by `parsed`
    tl_object_ptr<tos_api::consensus_simplex_db_Vote> parsed;
  };

  // Every record this node wrote about a vote of its own, in journal order. Certificates
  // share the key prefix and are deliberately excluded: they are peers' signatures, not
  // this node's commitment.
  std::vector<JournalledVote> own_vote_journal(const Instance& instance) const {
    std::vector<std::pair<td::BufferSlice, td::BufferSlice>> raw;
    {
      std::scoped_lock lock(instance.db_inner->mutex);
      const td::uint32 prefix = tos_api::consensus_simplex_db_key_vote::ID;
      for (const auto& [key, value] : instance.db_inner->map) {
        if (key.size() >= sizeof(prefix) && std::memcmp(key.data(), &prefix, sizeof(prefix)) == 0) {
          raw.emplace_back(key.clone(), value.clone());
        }
      }
    }

    std::vector<JournalledVote> result;
    for (auto& [key, value] : raw) {
      auto parsed_r = fetch_tl_object<tos_api::consensus_simplex_db_Vote>(value, true);
      if (parsed_r.is_error()) {
        continue;
      }
      JournalledVote entry;
      entry.key = key.clone();
      entry.value = value.clone();
      entry.parsed = parsed_r.move_as_ok();
      bool is_own_vote = false;
      auto intent_fn = [&](tos_api::consensus_simplex_db_ourVoteIntent& record) {
        is_own_vote = true;
        entry.seqno = record.seqno_;
        entry.vote = record.vote_.get();
      };
      auto signed_fn = [&](tos_api::consensus_simplex_db_ourSignedVote& record) {
        is_own_vote = true;
        entry.is_signed = true;
        entry.seqno = record.seqno_;
        entry.signature = record.signature_.clone();
        entry.vote = record.vote_.get();
      };
      auto cert_fn = [&](tos_api::consensus_simplex_db_cert&) {};
      tos_api::downcast_call(*entry.parsed, td::overloaded(intent_fn, signed_fn, cert_fn));
      if (is_own_vote) {
        result.push_back(std::move(entry));
      }
    }
    std::sort(result.begin(), result.end(),
              [](const JournalledVote& a, const JournalledVote& b) { return a.seqno < b.seqno; });
    return result;
  }

  // Certificates this node stored. With a single validator its own vote reaches the quorum
  // immediately, so a certificate record appearing is proof that a vote was applied to the
  // pool -- which is what must not happen before the signed record is committed.
  size_t stored_certificate_count(const Instance& instance) const {
    auto journal = own_vote_journal(instance);
    std::scoped_lock lock(instance.db_inner->mutex);
    const td::uint32 prefix = tos_api::consensus_simplex_db_key_vote::ID;
    size_t total = 0;
    for (const auto& [key, _] : instance.db_inner->map) {
      if (key.size() >= sizeof(prefix) && std::memcmp(key.data(), &prefix, sizeof(prefix)) == 0) {
        ++total;
      }
    }
    return total - journal.size();
  }

  // Records that hold a signature now and did not before. Each one cost exactly one call to
  // the signer, which is what makes the signer count comparable to the journal.
  static size_t count_newly_signed(const std::vector<JournalledVote>& before,
                                   const std::vector<JournalledVote>& after) {
    std::map<td::Slice, bool> signed_before;
    for (const auto& entry : before) {
      signed_before.emplace(entry.key.as_slice(), entry.is_signed);
    }
    size_t newly_signed = 0;
    for (const auto& entry : after) {
      if (!entry.is_signed) {
        continue;
      }
      auto it = signed_before.find(entry.key.as_slice());
      if (it == signed_before.end() || !it->second) {
        ++newly_signed;
      }
    }
    return newly_signed;
  }

  void arm_write_failures(const Instance& instance, td::uint32 tl_constructor_id, size_t count) const {
    std::scoped_lock lock(instance.db_inner->mutex);
    instance.db_inner->fail_writes_of[tl_constructor_id] = count;
  }

  size_t failed_write_count(const Instance& instance) const {
    std::scoped_lock lock(instance.db_inner->mutex);
    return instance.db_inner->failed_write_count;
  }

  void overwrite_journal_record(const Instance& instance, td::Slice key, td::BufferSlice value) const {
    std::scoped_lock lock(instance.db_inner->mutex);
    auto it = instance.db_inner->map.find(td::BufferSlice{key});
    CHECK(it != instance.db_inner->map.end());
    it->second = std::move(value);
  }

  void put_journal_record(const Instance& instance, td::BufferSlice key, td::BufferSlice value) const {
    std::scoped_lock lock(instance.db_inner->mutex);
    instance.db_inner->map[std::move(key)] = std::move(value);
  }

  void erase_journal_record(const Instance& instance, td::Slice key) const {
    std::scoped_lock lock(instance.db_inner->mutex);
    instance.db_inner->map.erase(td::BufferSlice{key});
  }

  td::actor::Task<> run_vote_journal_test() {
    auto& instance = nodes_[0].instances[0];
    const auto& store = *nodes_[0].pq_store;

    auto fail = [&](std::string message) { vote_journal_error_ = std::move(message); };

    // --- Phase 1: what the node journalled about its own votes is signed and verifiable ---
    //
    // Stopping the node is itself a crash point, so a vote whose intent was committed when
    // the stop arrived is legitimately left as an intent; that is the state the journal
    // exists to express, and phase 3 shows how it recovers. What must hold here is that
    // every record the node did finish carries a signature it can prove is its own.
    // Two is the minimum complete local vote pair: notarize and finalize one candidate.
    // It is also every shape the later phases need -- one record to compare byte for byte
    // across a restart, and one to downgrade to an intent and watch be signed again.
    constexpr size_t REQUIRED_VOTES = 2;
    auto signed_count = [&] {
      auto journal = own_vote_journal(instance);
      return std::count_if(journal.begin(), journal.end(), [](const JournalledVote& v) { return v.is_signed; });
    };
    auto deadline = td::Timestamp::in(DURATION * 0.4);
    while (static_cast<size_t>(signed_count()) < REQUIRED_VOTES && !deadline.is_in_past()) {
      co_await td::actor::coro_sleep(td::Timestamp::in(0.01));
    }
    co_await stop_instance(0, 0);

    auto before = own_vote_journal(instance);
    std::vector<const JournalledVote*> before_signed;
    size_t before_intents = 0;
    for (const auto& entry : before) {
      if (!entry.is_signed) {
        ++before_intents;
        continue;
      }
      if (entry.signature.size() != tos::pq::mldsa44_signature_bytes) {
        fail(PSTRING() << "a journalled signature is " << entry.signature.size() << " bytes");
        co_return td::Unit{};
      }
      if (!validators_[0].check_signature(SESSION_ID, serialize_tl_object(entry.vote, true), entry.signature)) {
        fail("a journalled signature does not verify under this node's consensus key");
        co_return td::Unit{};
      }
      before_signed.push_back(&entry);
    }
    if (before_signed.size() < REQUIRED_VOTES) {
      fail(PSTRING() << "the node journalled only " << before_signed.size() << " signed votes of its own, out of "
                     << before.size() << " records");
      co_return td::Unit{};
    }

    // --- Phase 2: a restart replays the stored bytes and signs nothing again ---
    //
    // New votes are blocked for the duration by rejecting every intent write, so that the
    // signer count over this window belongs to the replay and nothing else. Without that,
    // a vote signed just before the stop with its signed-record write still pending is a
    // legitimate outcome that is indistinguishable from a stray signature, and the count
    // would have to be loosened until it stopped proving anything. Phase 4 is what
    // establishes that a rejected intent really does stop a vote from being signed.
    arm_write_failures(instance, tos_api::consensus_simplex_db_ourVoteIntent::ID, 1000);
    auto signatures_before = store.consensus_signatures_produced();
    start_instance(0, 0);
    co_await td::actor::coro_sleep(td::Timestamp::in(std::min(DURATION * 0.2, 1.0)));
    co_await stop_instance(0, 0);
    arm_write_failures(instance, tos_api::consensus_simplex_db_ourVoteIntent::ID, 0);

    auto after = own_vote_journal(instance);
    std::map<td::Slice, const JournalledVote*> after_by_key;
    for (const auto& entry : after) {
      after_by_key.emplace(entry.key.as_slice(), &entry);
    }
    for (const auto* entry : before_signed) {
      auto it = after_by_key.find(entry->key.as_slice());
      if (it == after_by_key.end()) {
        fail(PSTRING() << "a journalled vote disappeared across the restart, seqno " << entry->seqno);
        co_return td::Unit{};
      }
      // Byte identity of the whole record, which covers the signature inside it.
      if (it->second->value.as_slice() != entry->value.as_slice()) {
        fail(PSTRING() << "a journalled vote was rewritten across the restart, seqno " << entry->seqno);
        co_return td::Unit{};
      }
    }
    // Replaying an already-signed vote must not reach the signer at all. With no new vote
    // able to start, every signature this window produced must have turned some record from
    // an intent into a signed one, and every such record must have cost exactly one
    // signature. An equality, not a bound: a record that was already signed accounts for
    // nothing, so re-signing one breaks it in one direction and a lost signature breaks it
    // in the other.
    auto newly_signed = count_newly_signed(before, after);
    auto signatures_made = store.consensus_signatures_produced() - signatures_before;
    if (signatures_made != newly_signed) {
      fail(PSTRING() << "the restart produced " << signatures_made << " signatures while " << newly_signed
                     << " records became signed; replay must sign exactly the intents it recovered");
      co_return td::Unit{};
    }

    // --- Phase 3: a crash between the intent and the signature is re-signed exactly once ---
    // The crash window is reproduced by putting the journal back into the state it would
    // have been left in: the decision committed, the signature not. Nothing could have
    // observed that vote, so signing it again introduces no second object.
    const JournalledVote* newest_signed = nullptr;
    for (const auto& entry : after) {
      if (entry.is_signed) {
        newest_signed = &entry;
      }
    }
    if (newest_signed == nullptr) {
      fail("no signed vote survived the restart to downgrade");
      co_return td::Unit{};
    }
    auto downgraded_key = newest_signed->key.clone();
    auto downgraded_seqno = newest_signed->seqno;
    auto original_record = newest_signed->value.clone();
    auto original_signature = newest_signed->signature.clone();
    auto downgraded_vote_tl = serialize_tl_object(take_unsigned_vote(original_record.as_slice()), true);
    overwrite_journal_record(instance, downgraded_key.as_slice(),
                             create_serialize_tl_object<tos_api::consensus_simplex_db_ourVoteIntent>(
                                 take_unsigned_vote(original_record), downgraded_seqno));
    if (erase_certificates_over_vote(instance, downgraded_vote_tl.as_slice()) == 0) {
      // Not a formality. A single validator is its own quorum, so the vote being downgraded
      // is inside a stored certificate; finding none means the record picked is not the one
      // this phase believes it picked, and the recovery below would prove nothing.
      fail("the downgraded vote was in no stored certificate, so the crash window was not reconstructed");
      co_return td::Unit{};
    }

    // New votes are blocked here for the same reason as in phase 2: the signer count is
    // only evidence while nothing else can reach the signer.
    arm_write_failures(instance, tos_api::consensus_simplex_db_ourVoteIntent::ID, 1000);
    auto before_resign = own_vote_journal(instance);
    signatures_before = store.consensus_signatures_produced();
    auto journalled_before = before_resign.size();
    start_instance(0, 0);
    auto resign_deadline = td::Timestamp::in(std::min(DURATION * 0.2, 1.0));
    while (!resign_deadline.is_in_past()) {
      auto current = own_vote_journal(instance);
      auto it = std::find_if(current.begin(), current.end(),
                             [&](const JournalledVote& v) { return v.key.as_slice() == downgraded_key.as_slice(); });
      if (it != current.end() && it->is_signed) {
        break;
      }
      co_await td::actor::coro_sleep(td::Timestamp::in(0.01));
    }
    co_await stop_instance(0, 0);
    arm_write_failures(instance, tos_api::consensus_simplex_db_ourVoteIntent::ID, 0);

    auto resigned = own_vote_journal(instance);
    auto resigned_it = std::find_if(resigned.begin(), resigned.end(), [&](const JournalledVote& v) {
      return v.key.as_slice() == downgraded_key.as_slice();
    });
    if (resigned_it == resigned.end() || !resigned_it->is_signed) {
      fail("an intent-only vote was not signed and committed on restart");
      co_return td::Unit{};
    }
    if (!validators_[0].check_signature(SESSION_ID, serialize_tl_object(resigned_it->vote, true),
                                        resigned_it->signature)) {
      fail("the re-signed vote does not verify under this node's consensus key");
      co_return td::Unit{};
    }
    // Randomized signing: the replacement must be a different object, which is exactly why
    // this may only happen for a signature that never escaped.
    if (resigned_it->signature.as_slice() == original_signature.as_slice()) {
      fail("the re-signed vote reproduced the original signature byte for byte");
      co_return td::Unit{};
    }
    if (resigned.size() != journalled_before) {
      fail(PSTRING() << "the journal changed size while only recovering an intent: " << journalled_before << " -> "
                     << resigned.size() << " records");
      co_return td::Unit{};
    }
    auto resign_newly_signed = count_newly_signed(before_resign, resigned);
    auto resign_signatures = store.consensus_signatures_produced() - signatures_before;
    // Exactly the intents that were recovered, no more and no fewer. The downgraded record
    // is one of them, so this is at least one.
    if (resign_signatures != resign_newly_signed || resign_signatures < 1) {
      fail(PSTRING() << "recovering intents produced " << resign_signatures << " signatures while "
                     << resign_newly_signed << " records became signed");
      co_return td::Unit{};
    }

    // --- Phase 4: an intent that will not commit means nothing is signed ---
    // The decision must be durable before the key is used at all. With every intent write
    // rejected, a node that respected only the second write would still sign and still
    // commit a signed record; a node that respects the first writes nothing and signs
    // nothing.
    arm_write_failures(instance, tos_api::consensus_simplex_db_ourVoteIntent::ID, 1000);
    signatures_before = store.consensus_signatures_produced();
    journalled_before = own_vote_journal(instance).size();
    auto failures_before = failed_write_count(instance);
    start_instance(0, 0);
    co_await td::actor::coro_sleep(td::Timestamp::in(std::min(DURATION * 0.15, 1.0)));
    co_await stop_instance(0, 0);

    if (failed_write_count(instance) <= failures_before) {
      fail("no intent write was rejected; the injected failure never reached the journal");
      co_return td::Unit{};
    }
    auto after_intent_failures = own_vote_journal(instance);
    if (after_intent_failures.size() != journalled_before) {
      fail(PSTRING() << "a vote was journalled although its intent write failed: " << journalled_before << " -> "
                     << after_intent_failures.size() << " records");
      co_return td::Unit{};
    }
    if (store.consensus_signatures_produced() != signatures_before) {
      fail("a vote was signed although its intent write failed");
      co_return td::Unit{};
    }
    arm_write_failures(instance, tos_api::consensus_simplex_db_ourVoteIntent::ID, 0);

    // --- Phase 5: a signed record that will not commit is never applied ---
    // Signing is allowed here; using the signature is not. With one validator, a vote that
    // reaches the pool meets the quorum at once and a certificate is stored, so a stored
    // certificate is the observable proof that a signature was used. The signer count
    // rising is the positive control that this phase exercised the path at all.
    arm_write_failures(instance, tos_api::consensus_simplex_db_ourSignedVote::ID, 1000);
    signatures_before = store.consensus_signatures_produced();
    auto certificates_before = stored_certificate_count(instance);
    failures_before = failed_write_count(instance);
    start_instance(0, 0);
    co_await td::actor::coro_sleep(td::Timestamp::in(std::min(DURATION * 0.15, 1.0)));
    co_await stop_instance(0, 0);

    if (failed_write_count(instance) <= failures_before) {
      fail("no signed-vote write was rejected; the injected failure never reached the journal");
      co_return td::Unit{};
    }
    if (store.consensus_signatures_produced() == signatures_before) {
      fail("no vote was signed while signed-vote writes were failing; the phase proved nothing");
      co_return td::Unit{};
    }
    auto certificates_after = stored_certificate_count(instance);
    if (certificates_after != certificates_before) {
      fail(PSTRING() << "a vote was applied although its signed record was not committed; stored certificates "
                     << certificates_before << " -> " << certificates_after);
      co_return td::Unit{};
    }
    arm_write_failures(instance, tos_api::consensus_simplex_db_ourSignedVote::ID, 0);

    // --- Phase 6: a record of our own that its key does not bind also stops the group ---
    // The signature inside is genuine, so verifying it proves nothing; what is broken is
    // the key/value binding. Skipping such a record would drop the vote out of the dedup
    // set and let the node decide and sign it again, which is the same failure as accepting
    // a signature it cannot verify. Three shapes are checked: a valid record filed under
    // another vote's key, a record whose body cannot be read at all, and an intact record
    // under a key that cannot be read.
    auto journal_before_binding = own_vote_journal(instance);
    std::vector<const JournalledVote*> binding_signed;
    for (const auto& entry : journal_before_binding) {
      if (entry.is_signed) {
        binding_signed.push_back(&entry);
      }
    }
    if (binding_signed.size() < 2) {
      fail("not enough signed records to build a key/value binding mismatch");
      co_return td::Unit{};
    }
    auto misfiled_key = binding_signed[0]->key.clone();
    auto misfiled_original = binding_signed[0]->value.clone();
    auto other_record = binding_signed[1]->value.clone();

    // A key that carries the vote-record prefix, so it is still enumerated, but cannot be
    // parsed. It is added alongside the real records rather than replacing one.
    td::BufferSlice unreadable_key(4 + 32 + 1);
    const td::uint32 key_prefix = tos_api::consensus_simplex_db_key_vote::ID;
    std::memcpy(unreadable_key.as_slice().data(), &key_prefix, sizeof(key_prefix));
    std::memset(unreadable_key.as_slice().data() + sizeof(key_prefix), 0x5a,
                unreadable_key.size() - sizeof(key_prefix));

    for (int shape = 0; shape < 3; ++shape) {
      if (shape == 0) {
        // A valid signed record, filed under a different vote's key.
        overwrite_journal_record(instance, misfiled_key.as_slice(), other_record.clone());
      } else if (shape == 1) {
        // The constructor tag says this is one of ours; the body is unreadable.
        td::BufferSlice unreadable(8);
        const td::uint32 tag = tos_api::consensus_simplex_db_ourSignedVote::ID;
        std::memcpy(unreadable.as_slice().data(), &tag, sizeof(tag));
        std::memset(unreadable.as_slice().data() + sizeof(tag), 0xff, unreadable.size() - sizeof(tag));
        overwrite_journal_record(instance, misfiled_key.as_slice(), std::move(unreadable));
      } else {
        // A perfectly good record of our own, under a key that cannot be read. The record
        // is intact, so only the key says it is lost.
        overwrite_journal_record(instance, misfiled_key.as_slice(), misfiled_original.clone());
        put_journal_record(instance, unreadable_key.clone(), other_record.clone());
      }

      signatures_before = store.consensus_signatures_produced();
      journalled_before = own_vote_journal(instance).size();
      start_instance(0, 0);
      co_await td::actor::coro_sleep(td::Timestamp::in(std::min(DURATION * 0.15, 1.0)));
      co_await stop_instance(0, 0);

      if (own_vote_journal(instance).size() != journalled_before) {
        fail(PSTRING() << "the group kept voting with a journal record its key does not bind (shape " << shape
                       << "): " << journalled_before << " -> " << own_vote_journal(instance).size() << " records");
        co_return td::Unit{};
      }
      if (store.consensus_signatures_produced() != signatures_before) {
        fail(PSTRING() << "the group signed a vote with a journal record its key does not bind (shape " << shape
                       << ")");
        co_return td::Unit{};
      }
    }
    overwrite_journal_record(instance, misfiled_key.as_slice(), std::move(misfiled_original));
    erase_journal_record(instance, unreadable_key.as_slice());

    // --- Phase 7: a signature this node cannot verify as its own stops the group ---
    // The node must not paper over it by signing again: it cannot know what it already
    // told the network, and a fresh signature would be a second object for that vote.
    auto journal_for_corruption = own_vote_journal(instance);
    const JournalledVote* to_corrupt = nullptr;
    for (const auto& entry : journal_for_corruption) {
      if (entry.is_signed) {
        to_corrupt = &entry;
      }
    }
    if (to_corrupt == nullptr) {
      fail("no signed vote survived to corrupt");
      co_return td::Unit{};
    }
    auto corrupted = to_corrupt->value.clone();
    auto corrupt_key = to_corrupt->key.clone();
    auto corrupt_signature = to_corrupt->signature.clone();
    corrupt_signature.as_slice()[0] = static_cast<char>(corrupt_signature.as_slice()[0] ^ 0x01);
    overwrite_journal_record(instance, corrupt_key.as_slice(),
                             create_serialize_tl_object<tos_api::consensus_simplex_db_ourSignedVote>(
                                 take_unsigned_vote(corrupted), to_corrupt->seqno, std::move(corrupt_signature)));

    signatures_before = store.consensus_signatures_produced();
    journalled_before = own_vote_journal(instance).size();
    start_instance(0, 0);
    co_await td::actor::coro_sleep(td::Timestamp::in(std::min(DURATION * 0.2, 1.0)));
    co_await stop_instance(0, 0);

    auto quiescent = own_vote_journal(instance);
    if (quiescent.size() != journalled_before) {
      fail(PSTRING() << "the group kept voting with an unusable journal: " << journalled_before << " -> "
                     << quiescent.size() << " records");
      co_return td::Unit{};
    }
    if (store.consensus_signatures_produced() != signatures_before) {
      fail("the group signed a vote with an unusable journal");
      co_return td::Unit{};
    }

    LOG(WARNING) << "Vote journal: " << before_signed.size() << " signed records replayed byte-for-byte, "
                 << before_intents << " intents left by the stop, a failed intent write stopped signing, a failed "
                 << "signed write stopped application, one intent-only vote re-signed once, and an unverifiable "
                 << "record stopped the group";
    vote_journal_completed_ = true;
    co_return td::Unit{};
  }

  // Move the unsigned vote out of a serialized journal record, whichever state it is in.
  // Remove every cached certificate that carries this exact vote. A crash between the vote
  // decision and its signature means the signature never existed, so nothing could have put
  // it into a certificate either -- and a journal holding an intent while the certificate
  // built from that vote's signature is still on disk is a state no crash could produce.
  // Leaving one behind also finalizes the vote's slot at startup, which prunes the slot the
  // recovered intent belongs to, so the recovery being tested never even starts.
  size_t erase_certificates_over_vote(const Instance& instance, td::Slice unsigned_vote) const {
    std::vector<td::BufferSlice> to_erase;
    {
      std::scoped_lock lock(instance.db_inner->mutex);
      const td::uint32 prefix = tos_api::consensus_simplex_db_key_vote::ID;
      for (const auto& [key, value] : instance.db_inner->map) {
        if (key.size() < sizeof(prefix) || std::memcmp(key.data(), &prefix, sizeof(prefix)) != 0) {
          continue;
        }
        auto parsed = fetch_tl_object<tos_api::consensus_simplex_db_Vote>(value.as_slice(), true);
        if (parsed.is_error()) {
          continue;
        }
        bool carries_the_vote = false;
        tos_api::downcast_call(
            *parsed.ok(), td::overloaded([&](tos_api::consensus_simplex_db_ourVoteIntent&) {},
                                         [&](tos_api::consensus_simplex_db_ourSignedVote&) {},
                                         [&](tos_api::consensus_simplex_db_cert& r) {
                                           carries_the_vote =
                                               serialize_tl_object(r.cert_->vote_, true).as_slice() == unsigned_vote;
                                         }));
        if (carries_the_vote) {
          to_erase.push_back(key.clone());
        }
      }
    }
    for (const auto& key : to_erase) {
      erase_journal_record(instance, key.as_slice());
    }
    return to_erase.size();
  }

  static tl_object_ptr<tos_api::consensus_simplex_UnsignedVote> take_unsigned_vote(td::Slice record) {
    auto parsed = fetch_tl_object<tos_api::consensus_simplex_db_Vote>(record, true).move_as_ok();
    tl_object_ptr<tos_api::consensus_simplex_UnsignedVote> vote;
    tos_api::downcast_call(
        *parsed, td::overloaded([&](tos_api::consensus_simplex_db_ourVoteIntent& r) { vote = std::move(r.vote_); },
                                [&](tos_api::consensus_simplex_db_ourSignedVote& r) { vote = std::move(r.vote_); },
                                [&](tos_api::consensus_simplex_db_cert&) {}));
    CHECK(vote);
    return vote;
  }

  td::actor::Task<> run_empty_chain_restart_test() {
    // Keep the manager's masterchain-finalized watermark at genesis.  After
    // the first few real blocks, BlockProducer will therefore finalize only
    // empty candidates.  Build a chain longer than the production admission
    // limit, restart with a cold StateResolver, and require candidate
    // production to resume.
    constexpr size_t EMPTY_CHAIN_LENGTH = 4096 + 32;
    auto& instance = nodes_[0].instances[0];
    auto build_deadline = td::Timestamp::in(DURATION * 0.75);
    while (candidate_record_count(instance) < EMPTY_CHAIN_LENGTH && !build_deadline.is_in_past()) {
      co_await td::actor::coro_sleep(td::Timestamp::in(0.01));
    }
    auto before_restart = candidate_record_count(instance);
    if (before_restart < EMPTY_CHAIN_LENGTH) {
      empty_chain_restart_error_ = PSTRING() << "built only " << before_restart << " candidates before the restart";
      co_return td::Unit{};
    }
    auto empty_chain_length = trailing_empty_candidate_count(instance);
    if (empty_chain_length <= 4096) {
      empty_chain_restart_error_ = PSTRING() << "built only " << empty_chain_length
                                             << " consecutive empty candidates before the restart";
      co_return td::Unit{};
    }

    // The production incident also had a finalized full-candidate anchor
    // whose block/state lookup timed out during cold-start replay. Force that
    // condition so the resolver must reconstruct the anchor from candidate
    // data instead of restarting the entire 4096+ ancestor walk.
    EMPTY_CHAIN_MANAGER_ANCHOR_UNAVAILABLE = true;
    co_await stop_instance(0, 0);
    auto stopped_count = candidate_record_count(instance);
    start_instance(0, 0);

    if (EMPTY_CHAIN_ORIGIN_PERMANENTLY_UNAVAILABLE) {
      // A missing exact predecessor is an unavailable session, not a usable
      // restart tip. Require the real resolver to reach its third read, then
      // observe a stable no-production window. This is deliberately a
      // fail-closed assertion; it does not claim eventual liveness.
      auto origin_deadline = td::Timestamp::in(DURATION * 0.2);
      while (EMPTY_CHAIN_ORIGIN_FAILURES < 3 && !origin_deadline.is_in_past()) {
        co_await td::actor::coro_sleep(td::Timestamp::in(0.01));
      }
      if (EMPTY_CHAIN_ORIGIN_FAILURES < 3 || EMPTY_CHAIN_MANAGER_ANCHOR_FAILURES == 0) {
        empty_chain_restart_error_ = PSTRING() << "permanent origin injection did not reach replay: origin reads="
                                               << EMPTY_CHAIN_ORIGIN_FAILURES
                                               << " anchor failures=" << EMPTY_CHAIN_MANAGER_ANCHOR_FAILURES;
        co_return td::Unit{};
      }
      if (candidate_record_count(instance) != stopped_count) {
        empty_chain_restart_error_ = "candidate production resumed with the exact origin unavailable";
        co_return td::Unit{};
      }
      co_await td::actor::coro_sleep(td::Timestamp::in(1.0));
      auto after_window = candidate_record_count(instance);
      if (after_window != stopped_count) {
        empty_chain_restart_error_ = PSTRING() << "candidate production resumed with the exact origin unavailable: "
                                               << stopped_count << " -> " << after_window;
        co_return td::Unit{};
      }
      LOG(WARNING) << "C03_PERMANENT_ORIGIN_FAIL_CLOSED_OK: origin reads=" << EMPTY_CHAIN_ORIGIN_FAILURES
                   << " anchor failures=" << EMPTY_CHAIN_MANAGER_ANCHOR_FAILURES
                   << " candidate records=" << stopped_count << " -> " << after_window;
      std::fprintf(stderr,
                   "C03_PERMANENT_ORIGIN_FAIL_CLOSED_OK: origin reads=%zu anchor failures=%zu candidate records=%zu -> %zu\n",
                   EMPTY_CHAIN_ORIGIN_FAILURES.load(), EMPTY_CHAIN_MANAGER_ANCHOR_FAILURES.load(), stopped_count,
                   after_window);
      std::fflush(stderr);
      empty_chain_restart_completed_ = true;
      co_return td::Unit{};
    }

    const size_t RECOVERY_CANDIDATES = SLOTS_PER_LEADER_WINDOW * 2;
    auto recovery_deadline = td::Timestamp::in(DURATION * 0.25);
    while (candidate_record_count(instance) < stopped_count + RECOVERY_CANDIDATES && !recovery_deadline.is_in_past()) {
      co_await td::actor::coro_sleep(td::Timestamp::in(0.01));
    }
    auto after_restart = candidate_record_count(instance);
    if (after_restart < stopped_count + RECOVERY_CANDIDATES) {
      empty_chain_restart_error_ = PSTRING() << "candidate production did not resume after resolving " << stopped_count
                                             << " persisted candidates; count after restart=" << after_restart;
      co_return td::Unit{};
    }

    // Several state resolutions may already be in flight when the restarted
    // producer first reaches the finalized anchor. Each one starts the
    // manager's state and block-data lookups in parallel, so the exact failure
    // count is scheduler-dependent (2, 4, 6, ...). Let that startup burst
    // drain, then verify the completed state-cache entry prevents any further
    // anchor lookups while candidate production continues.
    co_await td::actor::coro_sleep(td::Timestamp::in(0.25));
    auto settled_anchor_failures = EMPTY_CHAIN_MANAGER_ANCHOR_FAILURES.load();
    if (settled_anchor_failures == 0) {
      empty_chain_restart_error_ = "missing-manager-anchor fallback was not exercised";
      co_return td::Unit{};
    }

    auto settled_candidate_count = candidate_record_count(instance);
    auto cache_reuse_target = settled_candidate_count + RECOVERY_CANDIDATES;
    auto cache_reuse_deadline = td::Timestamp::in(DURATION * 0.1);
    while (candidate_record_count(instance) < cache_reuse_target && !cache_reuse_deadline.is_in_past()) {
      co_await td::actor::coro_sleep(td::Timestamp::in(0.01));
    }
    auto after_cache_reuse = candidate_record_count(instance);
    if (after_cache_reuse < cache_reuse_target) {
      empty_chain_restart_error_ =
          PSTRING() << "candidate production stalled while checking completed-ancestor cache reuse; records "
                    << settled_candidate_count << " -> " << after_cache_reuse;
      co_return td::Unit{};
    }

    co_await td::actor::coro_sleep(td::Timestamp::in(0.25));
    auto final_anchor_failures = EMPTY_CHAIN_MANAGER_ANCHOR_FAILURES.load();
    if (EMPTY_CHAIN_MANAGER_ANCHOR_TRANSIENT_FAILURES != 0 &&
        final_anchor_failures != EMPTY_CHAIN_MANAGER_ANCHOR_TRANSIENT_FAILURES) {
      empty_chain_restart_error_ = PSTRING() << "expected exactly " << EMPTY_CHAIN_MANAGER_ANCHOR_TRANSIENT_FAILURES
                                             << " transient manager-anchor failures, observed " << final_anchor_failures;
      co_return td::Unit{};
    }
    if (final_anchor_failures != settled_anchor_failures) {
      empty_chain_restart_error_ =
          PSTRING() << "manager anchor failures increased after startup requests settled: " << settled_anchor_failures
                    << " -> " << final_anchor_failures << "; completed-ancestor cache was not reused";
      co_return td::Unit{};
    }
    if (EMPTY_CHAIN_ORIGIN_FAILURES != EMPTY_CHAIN_ORIGIN_TRANSIENT_FAILURES) {
      empty_chain_restart_error_ = PSTRING() << "expected " << EMPTY_CHAIN_ORIGIN_TRANSIENT_FAILURES
                                             << " transient session-origin failures, observed "
                                             << EMPTY_CHAIN_ORIGIN_FAILURES;
      co_return td::Unit{};
    }
    LOG(WARNING) << "Long empty-chain restart recovered after " << empty_chain_length
                 << " consecutive empty candidates: records " << stopped_count << " -> " << after_cache_reuse
                 << ", startup anchor failures=" << settled_anchor_failures;
    empty_chain_restart_completed_ = true;
    co_return td::Unit{};
  }

  td::actor::Task<> finalize() {
    finishing_ = true;
    LOG(WARNING) << "TEST FINISHED";
    std::vector<td::actor::Task<>> tasks;
    for (size_t idx = 0; idx < N_NODES; ++idx) {
      for (size_t i = 0; i < nodes_[idx].instances.size(); ++i) {
        tasks.push_back(stop_instance(idx, i));
      }
    }
    co_await td::actor::all(std::move(tasks));
    LOG(WARNING) << "TEST RESULTS:";
    for (size_t idx = 0; idx < N_NODES; ++idx) {
      for (size_t inst_idx = 0; inst_idx < nodes_[idx].instances.size(); ++inst_idx) {
        Instance& inst = nodes_[idx].instances[inst_idx];
        LOG(WARNING) << "Node #" << idx << " instance #" << inst_idx << " : synced up to block "
                     << inst.last_accepted_block;
      }
    }
    if (last_accepted_block_.seqno() < MIN_FINALIZED_BLOCKS) {
      co_return td::Status::Error(PSTRING() << "finalized only " << last_accepted_block_.seqno()
                                            << " blocks, expected at least " << MIN_FINALIZED_BLOCKS);
    }
    if (MALICIOUS_OBSERVER_ATTACK && malicious_observer_messages_ == 0) {
      co_return td::Status::Error("malicious observer attack was not injected");
    }
    if (ADAPTIVE_BYZANTINE_N != 0 && adaptive_byzantine_epochs_ < 2) {
      co_return td::Status::Error("adaptive Byzantine membership did not rotate");
    }
    if (RELAY_LOOP_TEST && relay_loop_detected_) {
      co_return td::Status::Error("candidate relay loop was not deduplicated");
    }
    if (RELAY_LOOP_TEST && candidate_relay_total_ == 0) {
      co_return td::Status::Error("candidate relay path was not exercised");
    }
    if (QUERY_ABUSE_TEST &&
        (!query_abuse_completed_ ||
         query_abuse_accepted_ != NewConsensusConfig{}.noncritical_params.candidate_resolve_rate_limit ||
         query_abuse_rejected_ != 3)) {
      co_return td::Status::Error(PSTRING() << "candidate query rate limit was not enforced: accepted="
                                            << query_abuse_accepted_ << " rejected=" << query_abuse_rejected_);
    }
    if (QUERY_ABUSE_TEST && query_abuse_tracked_states_ != 0) {
      co_return td::Status::Error(PSTRING()
                                  << "candidate requests for untracked ids grew the resolver state map: tracked_states="
                                  << query_abuse_tracked_states_);
    }
    if (CATCH_UP_DOWNTIME >= 0.0) {
      if (!catch_up_error_.empty()) {
        co_return td::Status::Error(catch_up_error_);
      }
      if (!catch_up_restarted_ || !catch_up_completed_) {
        co_return td::Status::Error(PSTRING() << "catch-up node did not reach restart target " << catch_up_target_
                                              << " (restarted=" << catch_up_restarted_
                                              << ", completed=" << catch_up_completed_ << ")");
      }
      const auto caught_up_height = nodes_[catch_up_node_idx_].instances[0].last_accepted_block;
      if (caught_up_height + 2 < last_accepted_block_.seqno()) {
        co_return td::Status::Error(PSTRING() << "catch-up node ended at " << caught_up_height
                                              << " while network finalized " << last_accepted_block_.seqno());
      }
      size_t finalized_latest_get_count = 0;
      size_t finalized_latest_found_count = 0;
      for (const auto& node : nodes_) {
        for (const auto& instance : node.instances) {
          std::scoped_lock lock(instance.db_inner->mutex);
          finalized_latest_get_count += instance.db_inner->finalized_latest_get_count;
          finalized_latest_found_count += instance.db_inner->finalized_latest_found_count;
        }
      }
      if (finalized_latest_found_count == 0) {
        co_return td::Status::Error("catch-up test never recovered an evicted finalized ID through live DB lookup");
      }
      LOG(WARNING) << "StateResolver live DB lookup coverage: gets=" << finalized_latest_get_count
                   << " found=" << finalized_latest_found_count;
    }
    if (EMPTY_CHAIN_RESTART_TEST) {
      if (!empty_chain_restart_error_.empty()) {
        co_return td::Status::Error(empty_chain_restart_error_);
      }
      if (!empty_chain_restart_completed_) {
        co_return td::Status::Error("long empty-chain restart did not complete");
      }
    }
    if (VOTE_JOURNAL_TEST) {
      if (!vote_journal_error_.empty()) {
        co_return td::Status::Error(vote_journal_error_);
      }
      if (!vote_journal_completed_) {
        co_return td::Status::Error("the vote journal test did not complete");
      }
    }
    if (PQ_FINALITY_E2E_TEST) {
      if (!pq_finality_error_.empty()) {
        co_return td::Status::Error(pq_finality_error_);
      }
      if (!pq_finality_completed_) {
        co_return td::Status::Error("the post-quantum finality end-to-end test did not complete");
      }
    }
    if (PERMANENT_FINALIZATION_TEST) {
      if (!permanent_finalization_error_.empty()) {
        co_return td::Status::Error(permanent_finalization_error_);
      }
      if (!permanent_finalization_completed_) {
        co_return td::Status::Error("the permanent-finalization test did not complete");
      }
    }
    co_return td::Unit{};
  }

  struct Instance {
    td::actor::Runtime runtime;
    td::actor::ActorOwn<TestManagerFacade> manager_facade;
    simplex::BusHandle bus;
    bool started_before = false;

    BlockSeqno last_accepted_block = FIRST_PARENT.seqno();
    std::shared_ptr<TestDbImpl::DbInner> db_inner;

    enum Status { Stopped, Running, Stopping };
    Status status = Stopped;
    td::optional<td::actor::StartedTask<>> stop_waiter;
    std::vector<td::Promise<td::Unit>> extra_stop_waiters;

    bool net_gremlin_active = false;
  };
  struct Node {
    PublicKey public_key;
    PublicKeyHash node_id;
    adnl::AdnlNodeIdFull adnl_id_full;
    adnl::AdnlNodeIdShort adnl_id;
    ValidatorWeight weight = 0;
    // The node's post-quantum consensus key: what it signs Simplex messages with and what
    // the set records for it. The Ed25519 keys above stay for the transport/overlay layer.
    std::shared_ptr<const tos::pq::ValidatorPQKeyStore> pq_store;
    std::vector<Instance> instances;
  };
  std::vector<Node> nodes_;
  td::Ref<block::ValidatorSet> validator_set_;
  std::vector<PeerValidator> validators_;
  ValidatorWeight total_weight_ = 0;

  td::actor::ActorOwn<keyring::Keyring> keyring_;

  std::map<BlockSeqno, td::Ref<BlockData>> accepted_blocks_;
  BlockIdExt last_accepted_block_ = FIRST_PARENT;
  td::optional<size_t> last_accepted_block_leader_idx_;
  std::map<std::tuple<size_t, size_t, BlockIdExt>, size_t> candidate_relay_counts_;
  size_t candidate_relay_total_ = 0;
  size_t malicious_observer_messages_ = 0;
  size_t adaptive_byzantine_epochs_ = 0;
  bool relay_loop_detected_ = false;
  size_t query_abuse_accepted_ = 0;
  size_t catch_up_node_idx_ = 0;
  BlockSeqno catch_up_target_ = 0;
  bool catch_up_restarted_ = false;
  bool catch_up_completed_ = false;
  std::string catch_up_error_;
  size_t query_abuse_rejected_ = 0;
  size_t query_abuse_tracked_states_ = 0;
  bool query_abuse_completed_ = false;
  bool empty_chain_restart_completed_ = false;
  std::string empty_chain_restart_error_;
  bool vote_journal_completed_ = false;
  std::string vote_journal_error_;
  bool pq_finality_completed_ = false;
  std::string pq_finality_error_;
  bool permanent_finalization_completed_ = false;
  std::string permanent_finalization_error_;
  struct AcceptedCarrier {
    BlockIdExt block_id;
    td::Ref<block::BlockSignatureSet> signatures;
  };
  std::vector<AcceptedCarrier> accepted_carriers_;
  bool finishing_ = false;
};

td::actor::Task<> TestManagerFacade::accept_block(BlockIdExt id, td::Ref<BlockData> data, size_t creator_idx,
                                                  td::Ref<block::BlockSignatureSet> signatures,
                                                  ValidatorSessionId expected_session_id, int block_broadcast_mode,
                                                  int finality_broadcast_mode, bool send_shard_block_desc, bool apply) {
  if (signatures->is_pq() && signatures->pq_session_id().move_as_ok() != expected_session_id) {
    co_return td::Status::Error("manager facade received a PQ carrier for an unexpected session");
  }
  auto prepared = prepare_accepted_block_signatures(validator_set_, signatures, id, expected_session_id);
  if (prepared.is_error()) {
    co_return prepared.move_as_error();
  }
  if (signatures->is_final() && prepared.ok().is_null()) {
    co_return td::Status::Error("accept block did not materialize final signatures");
  }
  CHECK(id.shard_full() == SHARD);
  CHECK(!send_shard_block_desc);
  LOG(WARNING) << "Accept block #" << id.seqno() << " (" << (signatures->is_final() ? "final" : "notarize")
               << " signatures), creator_idx=" << creator_idx;
  CHECK(id == data->block_id());
  if (signatures->is_final()) {
    auto encoded =
        create_serialize_tl_object<tos_api::tosNode_blockFinalityBroadcast>(create_tl_block_id(id), signatures->tl());
    auto decoded = fetch_tl_object<tos_api::tosNode_Broadcast>(std::move(encoded), true).move_as_ok();
    CHECK(decoded->get_id() == tos_api::tosNode_blockFinalityBroadcast::ID);
    auto finality = move_tl_object_as<tos_api::tosNode_blockFinalityBroadcast>(decoded);
    CHECK(create_block_id(finality->id_) == id);
    auto decoded_signatures = block::BlockSignatureSet::fetch_node_checked(finality->signature_set_).move_as_ok();
    CHECK(decoded_signatures->is_final());
    CHECK(decoded_signatures->get_catchain_seqno() == signatures->get_catchain_seqno());
    CHECK(decoded_signatures->get_validator_set_hash() == signatures->get_validator_set_hash());
    decoded_signatures
        ->check_pq_signatures_under_carried_session_for_test(validator_set_, id, block::FinalityRole::Final)
        .ensure();
    auto tampered_id = id;
    tampered_id.id.seqno++;
    CHECK(decoded_signatures
              ->check_pq_signatures_under_carried_session_for_test(validator_set_, tampered_id,
                                                                   block::FinalityRole::Final)
              .is_error());

    auto tampered_signature_tl = signatures->tl();
    CHECK(tampered_signature_tl->get_id() == tos_api::tosNode_signatureSet_simplexPq::ID);
    auto* tampered_signature = static_cast<tos_api::tosNode_signatureSet_simplexPq*>(tampered_signature_tl.get());
    CHECK(!tampered_signature->signatures_.empty());
    CHECK(!tampered_signature->signatures_.front()->signature_.empty());
    auto original_signature = tampered_signature->signatures_.front()->signature_.as_slice();
    td::BufferSlice tampered_signature_bytes(original_signature.size());
    std::memcpy(tampered_signature_bytes.data(), original_signature.data(), original_signature.size());
    tampered_signature_bytes.data()[0] ^= 0x01;
    tampered_signature->signatures_.front()->signature_ = std::move(tampered_signature_bytes);
    auto tampered_signature_set = block::BlockSignatureSet::fetch_node_checked(tampered_signature_tl).move_as_ok();
    CHECK(tampered_signature_set
              ->check_pq_signatures_under_carried_session_for_test(validator_set_, id, block::FinalityRole::Final)
              .is_error());

    auto wrong_validator_set_tl = signatures->tl();
    auto* wrong_validator_set = static_cast<tos_api::tosNode_signatureSet_simplexPq*>(wrong_validator_set_tl.get());
    wrong_validator_set->validator_set_hash_ ^= 0x01;
    auto wrong_validator_set_signatures =
        block::BlockSignatureSet::fetch_node_checked(wrong_validator_set_tl).move_as_ok();
    CHECK(wrong_validator_set_signatures
              ->check_pq_signatures_under_carried_session_for_test(validator_set_, id, block::FinalityRole::Final)
              .is_error());
  }
  td::actor::ask(test_consensus_, &TestConsensus::on_block_accepted, node_idx_, instance_idx_, data, creator_idx,
                 signatures)
      .detach();
  co_return td::Unit{};
}

td::actor::Task<td::Ref<vm::Cell>> TestManagerFacade::wait_block_state_root(BlockIdExt block_id,
                                                                            td::Timestamp timeout) {
  if (C05_GENESIS_FAULT_BUDGET != 0 && block_id == FIRST_PARENT && node_idx_ > 0 && node_idx_ < 4 &&
      C05_GENESIS_FAULTS[node_idx_].load() < C05_GENESIS_FAULT_BUDGET) {
    auto failure = ++C05_GENESIS_FAULTS[node_idx_];
    C05_LAST_FAULT_TIME[node_idx_] = td::Time::now();
    LOG(WARNING) << "C05_SIMULTANEOUS_STATE_FAULT node=" << node_idx_ << " read=" << failure;
    co_return td::Status::Error(ErrorCode::notready, "injected simultaneous parent-state miss");
  }
  if (EMPTY_CHAIN_MANAGER_ANCHOR_UNAVAILABLE && block_id.seqno() == 0 &&
      (EMPTY_CHAIN_ORIGIN_PERMANENTLY_UNAVAILABLE ||
       EMPTY_CHAIN_ORIGIN_FAILURES < EMPTY_CHAIN_ORIGIN_TRANSIENT_FAILURES)) {
    ++EMPTY_CHAIN_ORIGIN_FAILURES;
    co_return td::Status::Error(ErrorCode::notready, "simulated session origin not ready");
  }
  if (EMPTY_CHAIN_MANAGER_ANCHOR_UNAVAILABLE && block_id.seqno() != 0 &&
      (EMPTY_CHAIN_MANAGER_ANCHOR_TRANSIENT_FAILURES == 0 ||
       EMPTY_CHAIN_MANAGER_ANCHOR_FAILURES < EMPTY_CHAIN_MANAGER_ANCHOR_TRANSIENT_FAILURES)) {
    ++EMPTY_CHAIN_MANAGER_ANCHOR_FAILURES;
    co_return td::Status::Error(ErrorCode::timeout, "simulated missing finalized anchor state");
  }
  co_return co_await td::actor::ask(test_consensus_, &TestConsensus::wait_block_state_root, block_id);
}

td::actor::Task<td::Ref<BlockData>> TestManagerFacade::wait_block_data(BlockIdExt block_id, td::Timestamp timeout) {
  if (EMPTY_CHAIN_MANAGER_ANCHOR_UNAVAILABLE && block_id.seqno() != 0 &&
      (EMPTY_CHAIN_MANAGER_ANCHOR_TRANSIENT_FAILURES == 0 ||
       EMPTY_CHAIN_MANAGER_ANCHOR_FAILURES < EMPTY_CHAIN_MANAGER_ANCHOR_TRANSIENT_FAILURES)) {
    ++EMPTY_CHAIN_MANAGER_ANCHOR_FAILURES;
    co_return td::Status::Error(ErrorCode::timeout, "simulated missing finalized anchor data");
  }
  co_return co_await td::actor::ask(test_consensus_, &TestConsensus::wait_block_data, block_id);
}

void TestManagerFacade::send_block_candidate_broadcast(BlockIdExt id, td::BufferSlice data, int mode) {
  td::actor::send_closure(test_consensus_, &TestConsensus::on_candidate_relay, node_idx_, instance_idx_, id);
}

td::BufferSlice make_large_candidate_boc(td::uint32 leaf_count, td::uint32 salt, bool multi_root,
                                         td::Bits256& root_hash) {
  std::vector<td::Ref<vm::Cell>> level;
  level.reserve(leaf_count);
  for (td::uint32 i = 0; i < leaf_count; ++i) {
    level.push_back(vm::CellBuilder().store_long(i ^ salt, 32).store_zeroes(900).finalize());
  }
  while (level.size() > 1) {
    std::vector<td::Ref<vm::Cell>> next;
    next.reserve((level.size() + 3) / 4);
    for (size_t i = 0; i < level.size(); i += 4) {
      vm::CellBuilder parent;
      for (size_t j = i; j < std::min(i + 4, level.size()); ++j) {
        CHECK(parent.store_ref_bool(level[j]));
      }
      next.push_back(parent.finalize());
    }
    level = std::move(next);
  }
  root_hash = td::Bits256{level.front()->get_hash().bits()};
  if (multi_root) {
    return vm::std_boc_serialize_multi({level.front()}, 2).move_as_ok();
  }
  return vm::std_boc_serialize(level.front(), 31).move_as_ok();
}

void test_configured_maximum_candidate() {
  constexpr size_t max_part_size = 4U * 1024U * 1024U;
  constexpr int max_envelope_size = 8U * 1024U * 1024U + 1024U;
  constexpr size_t max_slack = 384U * 1024U;

  td::Bits256 block_root_hash;
  td::Bits256 collated_root_hash;
  auto block_data = make_large_candidate_boc(32000, 0x13579bdf, false, block_root_hash);
  auto collated_data = make_large_candidate_boc(32000, 0x2468ace0, true, collated_root_hash);
  CHECK(block_data.size() <= max_part_size);
  CHECK(collated_data.size() <= max_part_size);
  CHECK(max_part_size - block_data.size() < max_slack);
  CHECK(max_part_size - collated_data.size() < max_slack);

  size_t decompressed_size = 0;
  auto compressed = validatorsession::compress_candidate_data(block_data, collated_data, decompressed_size,
                                                              "configured-maximum-test", block_root_hash)
                        .move_as_ok();
  CHECK(decompressed_size <= static_cast<size_t>(max_envelope_size));

  auto src = from_hex("3333333333333333333333333333333333333333333333333333333333333333");
  auto envelope = create_serialize_tl_object<tos_api::validatorSession_compressedCandidate>(
      0, src, 10, block_root_hash, static_cast<int>(decompressed_size), compressed.clone());
  auto decoded = validatorsession::deserialize_candidate(envelope, true, max_envelope_size).move_as_ok();
  CHECK(decoded->data_.as_slice() == block_data.as_slice());
  CHECK(decoded->collated_data_.as_slice() == collated_data.as_slice());
  CHECK(validatorsession::deserialize_candidate(envelope, true, static_cast<int>(decompressed_size) - 1).is_error());
}

void test_candidate_relay_eviction() {
  constexpr size_t capacity = 256;
  CandidateRelayDeduplicator deduplicator{capacity};
  std::vector<BlockIdExt> block_ids;
  block_ids.reserve(capacity + 1);
  for (size_t index = 0; index <= capacity; ++index) {
    block_ids.emplace_back(BlockId{SHARD, static_cast<BlockSeqno>(1000000 + index)}, td::Bits256{}, td::Bits256{});
    CHECK(deduplicator.should_relay(block_ids.back()));
  }

  CHECK(!deduplicator.should_relay(block_ids.back()));
  CHECK(deduplicator.should_relay(block_ids.front()));
  CHECK(!deduplicator.should_relay(block_ids.front()));
  CHECK(deduplicator.should_relay(block_ids[1]));
}

void test_validator_manager_resource_policy() {
  using Active = BoundedActiveOperations<int>;
  Active active{2};
  CHECK(active.try_start(1) == Active::StartResult::Started);
  CHECK(active.try_start(1) == Active::StartResult::AlreadyActive);
  CHECK(active.try_start(2) == Active::StartResult::Started);
  CHECK(active.try_start(3) == Active::StartResult::Full);
  CHECK(active.size() == 2);
  active.finish(1);
  CHECK(active.try_start(3) == Active::StartResult::Started);
  active.finish(2);
  active.finish(3);
  CHECK(active.size() == 0);

  using Idempotent = BoundedIdempotentOperations<int>;
  Idempotent operations{/* max_in_flight = */ 2, /* max_processed = */ 3};
  CHECK(operations.try_start(10) == Idempotent::StartResult::Started);
  CHECK(operations.try_start(10) == Idempotent::StartResult::AlreadyInFlight);
  operations.finish_failure(10);
  CHECK(operations.try_start(10) == Idempotent::StartResult::Started);
  CHECK(!operations.finish_success(10).has_value());
  CHECK(operations.try_start(10) == Idempotent::StartResult::AlreadyProcessed);

  CHECK(operations.try_start(20) == Idempotent::StartResult::Started);
  CHECK(operations.try_start(30) == Idempotent::StartResult::Started);
  CHECK(operations.try_start(40) == Idempotent::StartResult::Full);
  CHECK(operations.prune_in_flight([](int key) { return key == 20; }) == 1);
  CHECK(!operations.finish_failure_if_present(20));
  CHECK(operations.try_start(40) == Idempotent::StartResult::Started);
  CHECK(!operations.finish_success(30).has_value());
  CHECK(!operations.finish_success(40).has_value());

  CHECK(operations.try_start(50) == Idempotent::StartResult::Started);
  auto evicted = operations.finish_success(50);
  CHECK(evicted.has_value() && *evicted == 10);
  CHECK(!operations.is_processed(10));
  CHECK(operations.is_processed(20) == false);
  CHECK(operations.is_processed(30));
  CHECK(operations.is_processed(40));
  CHECK(operations.is_processed(50));

  operations.prune_processed([](int key) { return key >= 40; });
  CHECK(operations.processed_size() == 1);
  CHECK(operations.is_processed(30));
  CHECK(!operations.is_processed(40));
  CHECK(!operations.is_processed(50));
}

void test_state_resolver_completed_lru() {
  simplex::CompletedLru<int> lru{3};
  CHECK(lru.capacity() == 3);
  CHECK(!lru.touch(1).has_value());
  CHECK(!lru.touch(2).has_value());
  CHECK(!lru.touch(3).has_value());
  CHECK(lru.size() == 3);

  // A hit makes 1 most-recent, so inserting 4 must evict 2.
  CHECK(!lru.touch(1).has_value());
  auto evicted = lru.touch(4);
  CHECK(evicted.has_value() && *evicted == 2);
  CHECK(lru.contains(1));
  CHECK(!lru.contains(2));
  CHECK(lru.contains(3));
  CHECK(lru.contains(4));

  // Explicit removal is used by resolver failure paths.
  lru.erase(3);
  CHECK(lru.size() == 2);
  CHECK(!lru.contains(3));
  CHECK(!lru.touch(5).has_value());
  evicted = lru.touch(6);
  CHECK(evicted.has_value() && *evicted == 1);
  CHECK(lru.size() == lru.capacity());
}

void test_state_resolver_inflight_admission() {
  simplex::InflightAdmission admission{3};
  CHECK(admission.capacity() == 3);
  CHECK(admission.count() == 0);

  CHECK(admission.try_admit());
  CHECK(admission.try_admit());
  CHECK(admission.try_admit());
  CHECK(admission.count() == 3);

  // At capacity: a new distinct id must be rejected rather than silently
  // growing the underlying map past its configured bound.
  CHECK(!admission.try_admit());
  CHECK(!admission.try_admit());
  CHECK(admission.count() == 3);

  // Releasing (an in-flight resolution completing, success or failure) frees
  // exactly one slot for the next admission.
  admission.release();
  CHECK(admission.count() == 2);
  CHECK(admission.try_admit());
  CHECK(admission.count() == 3);
  CHECK(!admission.try_admit());

  admission.release();
  admission.release();
  admission.release();
  CHECK(admission.count() == 0);
  CHECK(admission.try_admit());
  CHECK(admission.try_admit());
  CHECK(admission.count() == 2);
}

void test_merkle_exact_parent_height_control() {
  // The recovered failures expected old state N but applied the update to
  // N-1. An exact ancestor supplies N; omitting its transition supplies N-1.
  for (BlockSeqno expected : {BlockSeqno{5}, BlockSeqno{23}}) {
    auto exact_parent_state = gen_shard_state(expected);
    auto skipped_base_state = gen_shard_state(expected - 1);
    auto next_state = gen_shard_state(expected + 1);
    auto update = vm::CellBuilder::create_merkle_update(exact_parent_state, next_state);

    auto correct = vm::MerkleUpdate::apply(exact_parent_state, update);
    CHECK(correct.is_ok());
    CHECK(correct.move_as_ok()->get_hash() == next_state->get_hash());

    CHECK(vm::MerkleUpdate::apply(skipped_base_state, update).is_error());
  }
}

void test_candidate_resolver_retention() {
  using State = simplex::CandidateEvictionState;

  simplex::CandidateRetentionPolicy policy{4};
  CHECK(policy.first_retained_slot() == 0);
  policy.observe_finalized(10);
  CHECK(policy.latest_finalized_slot() == 10);
  CHECK(policy.first_retained_slot() == 7);

  std::map<CandidateId, State> states;
  for (td::uint32 slot = 4; slot <= 11; ++slot) {
    states.emplace(CandidateId{slot, {}}, State{});
  }
  states.find(CandidateId{5, {}})->second.active_operations = 1;
  states.find(CandidateId{6, {}})->second.candidate_durable = false;

  auto can_evict = [](const State& state) { return state.can_evict(); };
  CHECK(simplex::prune_candidate_states(states, policy.first_retained_slot(), can_evict) == 1);
  CHECK(!states.contains(CandidateId{4, {}}));
  CHECK(states.contains(CandidateId{5, {}}));
  CHECK(states.contains(CandidateId{6, {}}));
  CHECK(states.contains(CandidateId{7, {}}));

  // Entries protected by an in-flight operation or incomplete persistence
  // survive the first pass and are removed by a later pass once safe.
  states.find(CandidateId{5, {}})->second.active_operations = 0;
  states.find(CandidateId{6, {}})->second.candidate_durable = true;
  CHECK(simplex::prune_candidate_states(states, policy.first_retained_slot(), can_evict) == 2);
  CHECK(states.size() == 5);

  // Older finalization notifications cannot move the window backwards.
  policy.observe_finalized(9);
  CHECK(policy.first_retained_slot() == 7);
  policy.observe_finalized(20);
  CHECK(policy.first_retained_slot() == 17);
  CHECK(simplex::prune_candidate_states(states, policy.first_retained_slot(), can_evict) == 5);
  CHECK(states.empty());
}

void test_candidate_resolver_interleaving() {
  using State = simplex::CandidateEvictionState;
  auto can_evict = [](const State& state) { return state.can_evict(); };
  // Deterministic same-tick interleaving:
  //   1. finalization moves the entry outside the retained window while a
  //      network resolution coroutine still owns a reference;
  //   2. the response arrives, but candidate/certificate persistence and
  //      waiter resumption complete in separate turns;
  //   3. only the final completion turn makes the entry erasable.
  simplex::CandidateRetentionPolicy interleaving_policy{2};
  std::map<CandidateId, State> interleaved;
  const CandidateId old_id{8, {}};
  const CandidateId boundary_id{9, {}};
  auto& old = interleaved[old_id];
  old.active_operations = 1;
  interleaved[boundary_id] = {};

  interleaving_policy.observe_finalized(10);
  CHECK(interleaving_policy.first_retained_slot() == 9);
  CHECK(simplex::prune_candidate_states(interleaved, interleaving_policy.first_retained_slot(), can_evict) == 0);

  // Network response returned, but both payloads still need durable storage.
  old.active_operations = 0;
  old.candidate_durable = false;
  old.notar_durable = false;
  old.notar_store_in_flight = true;
  CHECK(simplex::prune_candidate_states(interleaved, interleaving_policy.first_retained_slot(), can_evict) == 0);

  // Candidate persistence completed in the same scheduler tick; the detached
  // certificate store and resolution waiter still protect the map entry.
  old.candidate_durable = true;
  old.notar_store_in_flight = false;
  old.resolve_waiters = 1;
  CHECK(simplex::prune_candidate_states(interleaved, interleaving_policy.first_retained_slot(), can_evict) == 0);

  old.notar_durable = true;
  old.resolve_waiters = 0;
  old.store_waiters = 1;
  CHECK(simplex::prune_candidate_states(interleaved, interleaving_policy.first_retained_slot(), can_evict) == 0);

  old.store_waiters = 0;
  CHECK(simplex::prune_candidate_states(interleaved, interleaving_policy.first_retained_slot(), can_evict) == 1);
  CHECK(!interleaved.contains(old_id));
  CHECK(interleaved.contains(boundary_id));
}

void test_simplex_db_finalized_slot_dedup() {
  simplex::FinalizedSlotDedup<int> dedup;
  CHECK(dedup.insert(10, 100));
  CHECK(dedup.insert(10, 101));
  CHECK(dedup.insert(11, 110));
  CHECK(dedup.insert(13, 130));
  CHECK(!dedup.insert(99, 100));
  CHECK(dedup.size() == 4);
  CHECK(dedup.slot_count() == 3);

  CHECK(dedup.prune_through(10) == 2);
  CHECK(!dedup.contains(100));
  CHECK(!dedup.contains(101));
  CHECK(dedup.contains(110));
  CHECK(dedup.contains(130));
  CHECK(dedup.size() == 2);
  CHECK(dedup.slot_count() == 2);

  // Older and repeated finalization notifications are idempotent.
  CHECK(dedup.prune_through(9) == 0);
  CHECK(dedup.prune_through(10) == 0);
  CHECK(!dedup.insert(10, 102));
  CHECK(!dedup.insert(8, 80));
  CHECK(dedup.size() == 2);
  CHECK(dedup.prune_through(12) == 1);
  CHECK(dedup.size() == 1);
  CHECK(dedup.contains(130));

  CHECK(dedup.insert(14, 140));
  CHECK(dedup.prune_through(20) == 2);
  CHECK(dedup.size() == 0);
  CHECK(dedup.slot_count() == 0);
}

}  // namespace

int main(int argc, char* argv[]) {
  {
    auto authorized = from_hex("1111111111111111111111111111111111111111111111111111111111111111");
    auto unauthorized = from_hex("2222222222222222222222222222222222222222222222222222222222222222");
    std::map<PublicKeyHash, td::uint32> keys{{PublicKeyHash{authorized}, 1024}};
    overlay::OverlayPrivacyRules rules{1024, overlay::CertificateFlags::AllowFec, std::move(keys)};
    CHECK(rules.check_rules(PublicKeyHash{authorized}, 512, true, true) == overlay::BroadcastCheckResult::Allowed);
    CHECK(rules.check_rules(PublicKeyHash{authorized}, 2048, true, true) == overlay::BroadcastCheckResult::Forbidden);
    CHECK(rules.check_rules(PublicKeyHash{unauthorized}, 512, true, true) == overlay::BroadcastCheckResult::Forbidden);
    CHECK(rules.check_rules(PublicKeyHash{unauthorized}, 512, true, false) == overlay::BroadcastCheckResult::NeedCheck);
    CHECK(rules.check_rules(PublicKeyHash{unauthorized}, 2048, false, false) ==
          overlay::BroadcastCheckResult::Forbidden);
  }

  CHECK(pending_finality_admission(false, false, false, false, false) == PendingFinalityAdmission::Replace);
  CHECK(pending_finality_admission(false, false, false, false, true) == PendingFinalityAdmission::Replace);
  CHECK(pending_finality_admission(true, true, false, false, false) == PendingFinalityAdmission::Keep);
  CHECK(pending_finality_admission(true, true, false, true, true) == PendingFinalityAdmission::Replace);
  CHECK(pending_finality_admission(true, true, true, false, false) == PendingFinalityAdmission::Keep);
  // Equal-strength unverified finals coexist until trusted block context can
  // identify the first cryptographically valid candidate.
  CHECK(pending_finality_admission(true, false, true, false, true) == PendingFinalityAdmission::Append);

  CHECK(NewConsensusConfig{}.noncritical_params.target_rate == std::chrono::milliseconds{400});
  CHECK(NewConsensusConfig{}.protocol_version_supported());
  CHECK(!NewConsensusConfig{}.enable_block_sync());
  CHECK(NewConsensusConfig{.protocol_version = 1}.protocol_version_supported());
  CHECK(NewConsensusConfig{.protocol_version = 1}.enable_block_sync());
  CHECK(NewConsensusConfig{.protocol_version = 2}.protocol_version_supported());
  CHECK(NewConsensusConfig{.protocol_version = 2}.enable_plumtree_broadcast());
  CHECK(!NewConsensusConfig{.protocol_version = 3}.protocol_version_supported());

  auto wrap_config_param30 = [](td::Ref<vm::Cell> simplex) {
    vm::CellBuilder all;
    CHECK(all.store_long_bool(0x10, 8));
    CHECK(all.store_bool_bool(true));
    CHECK(all.store_ref_bool(simplex));
    CHECK(all.store_bool_bool(true));
    CHECK(all.store_ref_bool(std::move(simplex)));

    vm::Dictionary config_dict{32};
    CHECK(config_dict.set_ref(td::BitArray<32>{30}, all.finalize()));
    return std::move(config_dict).extract_root_cell();
  };

  auto decode_config_param30 = [&](td::Ref<vm::Cell> simplex) {
    block::Config config{wrap_config_param30(std::move(simplex))};
    CHECK(config.unpack().is_ok());
    return config.get_new_consensus_config(masterchainId);
  };

  auto decode_config_param29 = []<typename Record>(const Record& record) {
    td::Ref<vm::Cell> cell;
    CHECK(block::gen::t_ConsensusConfig.cell_pack(cell, record));
    vm::Dictionary config_dict{32};
    CHECK(config_dict.set_ref(td::BitArray<32>{29}, std::move(cell)));
    block::Config config{std::move(config_dict).extract_root_cell()};
    CHECK(config.unpack().is_ok());
    return config.get_consensus_config();
  };

  auto check_common_consensus_config = [](const ValidatorSessionConfig& config) {
    CHECK(config.round_candidates == 3);
    CHECK(config.next_candidate_delay == 2.0);
    CHECK(config.catchain_opts.idle_timeout == 16.0);
    CHECK(config.max_round_attempts == 3);
    CHECK(config.round_attempt_duration == 8);
    CHECK(config.catchain_opts.max_deps == 4);
    CHECK(config.max_block_size == 2U * 1024U * 1024U);
    CHECK(config.max_collated_data_size == 3U * 1024U * 1024U);
  };

  {
    block::gen::ConsensusConfig::Record_consensus_config encoded{
        .round_candidates = 3,
        .next_candidate_delay_ms = 2000,
        .consensus_timeout_ms = 16000,
        .fast_attempts = 3,
        .attempt_duration = 8,
        .catchain_max_deps = 4,
        .max_block_bytes = 2U * 1024U * 1024U,
        .max_collated_bytes = 3U * 1024U * 1024U,
    };
    auto decoded = decode_config_param29(encoded);
    check_common_consensus_config(decoded);
    CHECK(!decoded.new_catchain_ids);
    CHECK(decoded.proto_version == 0);
    CHECK(!decoded.use_quic);
  }

  {
    block::gen::ConsensusConfig::Record_consensus_config_new encoded{
        .flags = 0,
        .new_catchain_ids = true,
        .round_candidates = 3,
        .next_candidate_delay_ms = 2000,
        .consensus_timeout_ms = 16000,
        .fast_attempts = 3,
        .attempt_duration = 8,
        .catchain_max_deps = 4,
        .max_block_bytes = 2U * 1024U * 1024U,
        .max_collated_bytes = 3U * 1024U * 1024U,
    };
    auto decoded = decode_config_param29(encoded);
    check_common_consensus_config(decoded);
    CHECK(decoded.new_catchain_ids);
    CHECK(decoded.proto_version == 0);
    CHECK(!decoded.use_quic);
  }

  {
    block::gen::ConsensusConfig::Record_consensus_config_v3 encoded{
        .flags = 0,
        .new_catchain_ids = true,
        .round_candidates = 3,
        .next_candidate_delay_ms = 2000,
        .consensus_timeout_ms = 16000,
        .fast_attempts = 3,
        .attempt_duration = 8,
        .catchain_max_deps = 4,
        .max_block_bytes = 2U * 1024U * 1024U,
        .max_collated_bytes = 3U * 1024U * 1024U,
        .proto_version = 5,
    };
    auto decoded = decode_config_param29(encoded);
    check_common_consensus_config(decoded);
    CHECK(decoded.new_catchain_ids);
    CHECK(decoded.proto_version == 5);
    CHECK(!decoded.use_quic);
  }

  {
    block::gen::ConsensusConfig::Record_consensus_config_v4 encoded{
        .flags = 0,
        .use_quic = true,
        .new_catchain_ids = true,
        .round_candidates = 3,
        .next_candidate_delay_ms = 2000,
        .consensus_timeout_ms = 16000,
        .fast_attempts = 3,
        .attempt_duration = 8,
        .catchain_max_deps = 4,
        .max_block_bytes = 2U * 1024U * 1024U,
        .max_collated_bytes = 3U * 1024U * 1024U,
        .proto_version = 6,
        .catchain_max_blocks_coeff = 7,
    };
    auto decoded = decode_config_param29(encoded);
    check_common_consensus_config(decoded);
    CHECK(decoded.new_catchain_ids);
    CHECK(decoded.proto_version == 6);
    CHECK(decoded.use_quic);
    CHECK(decoded.catchain_opts.max_block_height_coeff == 1400);
  }

  {
    block::gen::NewConsensusConfig::Record_simplex_config encoded{
        .flags = 0,
        .use_quic = false,
        .target_rate_ms = 400,
        .slots_per_leader_window = 4,
        .first_block_timeout_ms = 1000,
        .max_leader_window_desync = 250,
    };
    td::Ref<vm::Cell> cell;
    CHECK(block::gen::t_NewConsensusConfig.cell_pack(cell, encoded));

    block::gen::NewConsensusConfig::Record_simplex_config decoded;
    CHECK(block::gen::t_NewConsensusConfig.cell_unpack(cell, decoded));
    CHECK(decoded.flags == encoded.flags);
    CHECK(decoded.use_quic == encoded.use_quic);
    CHECK(decoded.target_rate_ms == encoded.target_rate_ms);
    CHECK(decoded.slots_per_leader_window == encoded.slots_per_leader_window);
    CHECK(decoded.first_block_timeout_ms == encoded.first_block_timeout_ms);
    CHECK(decoded.max_leader_window_desync == encoded.max_leader_window_desync);
  }

  {
    vm::CellBuilder empty_dictionary;
    CHECK(empty_dictionary.store_bool_bool(false));
    block::gen::NewConsensusConfig::Record_simplex_config_v2 encoded{
        .flags = 0,
        .protocol_version = 2,
        .use_quic = true,
        .slots_per_leader_window = 4,
        .noncritical_params = vm::load_cell_slice_ref(empty_dictionary.finalize()),
    };
    td::Ref<vm::Cell> cell;
    CHECK(block::gen::t_NewConsensusConfig.cell_pack(cell, encoded));

    block::gen::NewConsensusConfig::Record_simplex_config_v2 decoded;
    CHECK(block::gen::t_NewConsensusConfig.cell_unpack(cell, decoded));
    CHECK(decoded.flags == 0);
    CHECK(decoded.protocol_version == 2);
    CHECK(decoded.use_quic);
    CHECK(decoded.slots_per_leader_window == 4);
    CHECK(NewConsensusConfig{.protocol_version = decoded.protocol_version}.protocol_version_supported());
    CHECK(td::Bits256{cell->get_hash().bits()} ==
          from_hex("3ED02F907E6EC7625EC062FF3B88B46CBA4E39681821D5ED1A976B2BCEFB2C43"));

    auto loaded = decode_config_param30(cell);
    CHECK(loaded);
    CHECK(loaded.value().protocol_version == 2);
    CHECK(loaded.value().slots_per_leader_window == 4);
  }

  {
    vm::CellBuilder empty_dictionary;
    CHECK(empty_dictionary.store_bool_bool(false));
    block::gen::NewConsensusConfig::Record_simplex_config_v2 reserved_flags{
        .flags = 1,
        .protocol_version = 0,
        .use_quic = false,
        .slots_per_leader_window = 4,
        .noncritical_params = vm::load_cell_slice_ref(empty_dictionary.finalize()),
    };
    td::Ref<vm::Cell> cell;
    CHECK(block::gen::t_NewConsensusConfig.cell_pack(cell, reserved_flags));
    CHECK(!decode_config_param30(std::move(cell)));
  }

  {
    vm::CellBuilder empty_dictionary;
    CHECK(empty_dictionary.store_bool_bool(false));
    block::gen::NewConsensusConfig::Record_simplex_config_v2 future{
        .flags = 0,
        .protocol_version = 3,
        .use_quic = false,
        .slots_per_leader_window = 4,
        .noncritical_params = vm::load_cell_slice_ref(empty_dictionary.finalize()),
    };
    td::Ref<vm::Cell> cell;
    CHECK(block::gen::t_NewConsensusConfig.cell_pack(cell, future));
    auto loaded = decode_config_param30(std::move(cell));
    CHECK(loaded);
    CHECK(loaded.value().protocol_version == 3);
    CHECK(!loaded.value().protocol_version_supported());
  }

  {
    auto truncated = vm::CellBuilder().store_long(0x22, 8).store_long(0, 5).finalize();
    block::gen::NewConsensusConfig::Record_simplex_config_v2 decoded;
    CHECK(!block::gen::t_NewConsensusConfig.cell_unpack(truncated, decoded));
    CHECK(!decode_config_param30(std::move(truncated)));
  }

  {
    vm::CellBuilder invalid_slots;
    CHECK(invalid_slots.store_long_bool(0x22, 8));
    CHECK(invalid_slots.store_long_bool(0, 5));
    CHECK(invalid_slots.store_long_bool(0, 2));
    CHECK(invalid_slots.store_bool_bool(false));
    CHECK(invalid_slots.store_long_bool(0, 32));
    CHECK(invalid_slots.store_bool_bool(false));
    auto cell = invalid_slots.finalize();
    block::gen::NewConsensusConfig::Record_simplex_config_v2 decoded;
    CHECK(!block::gen::t_NewConsensusConfig.cell_unpack(cell, decoded));
    CHECK(!decode_config_param30(std::move(cell)));
  }

  {
    auto block_root = vm::CellBuilder().store_long(0x12345678, 32).store_long(0xabcdef, 24).finalize();
    auto collated_root = vm::CellBuilder().store_long(0x87654321, 32).finalize();
    auto block_data = vm::std_boc_serialize(block_root, 31).move_as_ok();
    auto collated_data = vm::std_boc_serialize_multi({collated_root}, 2).move_as_ok();
    auto src = from_hex("1111111111111111111111111111111111111111111111111111111111111111");
    auto root_hash = td::Bits256{block_root->get_hash().bits()};

    auto candidate = create_tl_object<tos_api::validatorSession_candidate>(src, 7, root_hash, block_data.clone(),
                                                                           collated_data.clone());

    auto raw = validatorsession::serialize_candidate(candidate, false).move_as_ok();
    auto raw_decoded = validatorsession::deserialize_candidate(raw, false, static_cast<int>(raw.size())).move_as_ok();
    CHECK(raw_decoded->src_ == src);
    CHECK(raw_decoded->round_ == 7);
    CHECK(raw_decoded->root_hash_ == root_hash);
    CHECK(raw_decoded->data_.as_slice() == block_data.as_slice());
    CHECK(raw_decoded->collated_data_.as_slice() == collated_data.as_slice());
    CHECK(validatorsession::deserialize_candidate(raw, true, static_cast<int>(raw.size())).is_error());

    size_t decompressed_size = 0;
    auto compressed =
        validatorsession::compress_candidate_data(block_data, collated_data, decompressed_size, "test", root_hash)
            .move_as_ok();
    CHECK(decompressed_size <= static_cast<size_t>(std::numeric_limits<int>::max()));
    auto compressed_envelope = create_serialize_tl_object<tos_api::validatorSession_compressedCandidate>(
        0, src, 7, root_hash, static_cast<int>(decompressed_size), compressed.clone());
    const int legacy_limit = static_cast<int>(std::max(decompressed_size, static_cast<size_t>(compressed.size())));
    auto legacy_decoded = validatorsession::deserialize_candidate(compressed_envelope, true, legacy_limit).move_as_ok();
    CHECK(legacy_decoded->data_.as_slice() == block_data.as_slice());
    CHECK(legacy_decoded->collated_data_.as_slice() == collated_data.as_slice());
    CHECK(validatorsession::deserialize_candidate(compressed_envelope, true, static_cast<int>(decompressed_size) - 1)
              .is_error());
    CHECK(validatorsession::deserialize_candidate(compressed_envelope, false, legacy_limit).is_error());

    auto maximal_declaration = create_serialize_tl_object<tos_api::validatorSession_compressedCandidate>(
        0, src, 7, root_hash, std::numeric_limits<int>::max(), compressed.clone());
    CHECK(validatorsession::deserialize_candidate(maximal_declaration, true, legacy_limit).is_error());

    td::BufferSlice overlong_compressed(17);
    std::memset(overlong_compressed.data(), 0, overlong_compressed.size());
    auto overlong_envelope = create_serialize_tl_object<tos_api::validatorSession_compressedCandidate>(
        0, src, 7, root_hash, 1, std::move(overlong_compressed));
    CHECK(validatorsession::deserialize_candidate(overlong_envelope, true, 16).is_error());

    td::BufferSlice invalid_lz4(8);
    std::memset(invalid_lz4.data(), 0xff, invalid_lz4.size());
    auto invalid_lz4_envelope = create_serialize_tl_object<tos_api::validatorSession_compressedCandidate>(
        0, src, 7, root_hash, 1024, std::move(invalid_lz4));
    CHECK(validatorsession::deserialize_candidate(invalid_lz4_envelope, true, 1024).is_error());

    auto wrong_size = create_serialize_tl_object<tos_api::validatorSession_compressedCandidate>(
        0, src, 7, root_hash, static_cast<int>(decompressed_size) - 1, compressed.clone());
    CHECK(validatorsession::deserialize_candidate(wrong_size, true, legacy_limit).is_error());

    td::BufferSlice with_trailing_byte(compressed.size() + 1);
    std::memcpy(with_trailing_byte.data(), compressed.data(), compressed.size());
    with_trailing_byte.data()[compressed.size()] = '\0';
    auto trailing = create_serialize_tl_object<tos_api::validatorSession_compressedCandidate>(
        0, src, 7, root_hash, static_cast<int>(decompressed_size), std::move(with_trailing_byte));
    CHECK(validatorsession::deserialize_candidate(trailing, true, legacy_limit + 1).is_error());

    auto truncated = compressed.clone();
    truncated.truncate(truncated.size() - 1);
    auto truncated_envelope = create_serialize_tl_object<tos_api::validatorSession_compressedCandidate>(
        0, src, 7, root_hash, static_cast<int>(decompressed_size), std::move(truncated));
    CHECK(validatorsession::deserialize_candidate(truncated_envelope, true, legacy_limit).is_error());

    auto improved =
        vm::boc_compress({block_root, collated_root}, vm::CompressionAlgorithm::ImprovedStructureLZ4).move_as_ok();
    auto improved_envelope = create_serialize_tl_object<tos_api::validatorSession_compressedCandidateV2>(
        0, src, 7, root_hash, improved.clone());
    auto improved_decoded = validatorsession::deserialize_candidate(improved_envelope, true, 1 << 20).move_as_ok();
    CHECK(improved_decoded->data_.as_slice() == block_data.as_slice());
    CHECK(improved_decoded->collated_data_.as_slice() == collated_data.as_slice());
    CHECK(validatorsession::deserialize_candidate(improved_envelope, true, static_cast<int>(improved.size()) - 1)
              .is_error());

    auto corrupt_improved = improved.clone();
    corrupt_improved.data()[corrupt_improved.size() / 2] ^= 0x5a;
    auto corrupt_improved_envelope = create_serialize_tl_object<tos_api::validatorSession_compressedCandidateV2>(
        0, src, 7, root_hash, std::move(corrupt_improved));
    CHECK(validatorsession::deserialize_candidate(corrupt_improved_envelope, true, 1 << 20).is_error());

    auto baseline = vm::boc_compress({block_root, collated_root}, vm::CompressionAlgorithm::BaselineLZ4).move_as_ok();
    auto baseline_envelope = create_serialize_tl_object<tos_api::validatorSession_compressedCandidateV2>(
        0, src, 7, root_hash, std::move(baseline));
    auto baseline_decoded = validatorsession::deserialize_candidate(baseline_envelope, true, 1 << 20).move_as_ok();
    CHECK(baseline_decoded->data_.as_slice() == block_data.as_slice());
    CHECK(baseline_decoded->collated_data_.as_slice() == collated_data.as_slice());

    td::BufferSlice empty_improved;
    auto empty_improved_envelope = create_serialize_tl_object<tos_api::validatorSession_compressedCandidateV2>(
        0, src, 7, root_hash, std::move(empty_improved));
    CHECK(validatorsession::deserialize_candidate(empty_improved_envelope, true, 1 << 20).is_error());

    td::BufferSlice unknown_algorithm(1);
    unknown_algorithm.data()[0] = static_cast<char>(0x7f);
    auto unknown_algorithm_envelope = create_serialize_tl_object<tos_api::validatorSession_compressedCandidateV2>(
        0, src, 7, root_hash, std::move(unknown_algorithm));
    CHECK(validatorsession::deserialize_candidate(unknown_algorithm_envelope, true, 1 << 20).is_error());

    auto stateful = vm::boc_compress({block_root}, vm::CompressionAlgorithm::ImprovedStructureLZ4WithState, block_root)
                        .move_as_ok();
    auto stateful_envelope = create_serialize_tl_object<tos_api::validatorSession_compressedCandidateV2>(
        0, src, 7, root_hash, std::move(stateful));
    CHECK(validatorsession::deserialize_candidate(stateful_envelope, true, 1 << 20).is_error());
  }

  {
    auto invalid = create_serialize_tl_object<tos_api::validatorSession_compressedCandidate>(
        0, td::Bits256{}, 0, td::Bits256{}, -1, td::BufferSlice{});
    CHECK(validatorsession::deserialize_candidate(invalid, true, 1024).is_error());
    CHECK(validatorsession::deserialize_candidate(invalid, true, -1).is_error());
  }

  {
    std::vector<td::Ref<vm::Cell>> level;
    level.reserve(4096);
    for (td::uint32 i = 0; i < 4096; ++i) {
      level.push_back(vm::CellBuilder().store_long(i, 32).store_zeroes(900).finalize());
    }
    while (level.size() > 1) {
      std::vector<td::Ref<vm::Cell>> next;
      next.reserve((level.size() + 3) / 4);
      for (size_t i = 0; i < level.size(); i += 4) {
        vm::CellBuilder parent;
        for (size_t j = i; j < std::min(i + 4, level.size()); ++j) {
          CHECK(parent.store_ref_bool(level[j]));
        }
        next.push_back(parent.finalize());
      }
      level = std::move(next);
    }

    auto large_block_data = vm::std_boc_serialize(level.front(), 31).move_as_ok();
    auto collated_root = vm::CellBuilder().store_long(0xc011a7ed, 32).finalize();
    auto collated_data = vm::std_boc_serialize_multi({collated_root}, 2).move_as_ok();
    auto root_hash = td::Bits256{level.front()->get_hash().bits()};
    size_t decompressed_size = 0;
    auto compressed = validatorsession::compress_candidate_data(large_block_data, collated_data, decompressed_size,
                                                                "compression-ratio-test", root_hash)
                          .move_as_ok();
    CHECK(decompressed_size > 400U * 1024U);
    CHECK(compressed.size() * 8U < decompressed_size);
    CHECK(decompressed_size <= static_cast<size_t>(std::numeric_limits<int>::max()));

    auto src = from_hex("2222222222222222222222222222222222222222222222222222222222222222");
    auto envelope = create_serialize_tl_object<tos_api::validatorSession_compressedCandidate>(
        0, src, 9, root_hash, static_cast<int>(decompressed_size), compressed.clone());
    const int exact_limit = static_cast<int>(std::max(decompressed_size, static_cast<size_t>(compressed.size())));
    auto decoded = validatorsession::deserialize_candidate(envelope, true, exact_limit).move_as_ok();
    CHECK(decoded->data_.as_slice() == large_block_data.as_slice());
    CHECK(decoded->collated_data_.as_slice() == collated_data.as_slice());
    CHECK(validatorsession::deserialize_candidate(envelope, true, static_cast<int>(decompressed_size) - 1).is_error());

    auto oversized_declaration = create_serialize_tl_object<tos_api::validatorSession_compressedCandidate>(
        0, src, 9, root_hash, exact_limit + 1, compressed.clone());
    CHECK(validatorsession::deserialize_candidate(oversized_declaration, true, exact_limit).is_error());
  }

  SET_VERBOSITY_LEVEL(verbosity_WARNING);
  td::set_default_failure_signal_handler().ensure();

  bool run_configured_maximum_candidate_test = false;
  bool run_candidate_relay_eviction_test = false;
  bool run_state_resolver_cache_unit_test = false;
  bool run_state_resolver_inflight_admission_unit_test = false;
  bool run_merkle_exact_parent_height_control_test = false;
  bool run_candidate_resolver_retention_unit_test = false;
  bool run_candidate_resolver_interleaving_unit_test = false;
  bool run_simplex_db_finalized_slot_dedup_unit_test = false;
  bool run_validator_manager_resource_policy_unit_test = false;
  td::OptionParser p;
  p.set_description("test consensus");
  p.add_option('h', "help", "prints_help", [&]() {
    std::cout << (PSLICE() << p).c_str();
    std::exit(2);
  });
  p.add_option('v', "verbosity", "set verbosity level", [&](td::Slice arg) {
    int v = VERBOSITY_NAME(FATAL) + (td::to_integer<int>(arg));
    SET_VERBOSITY_LEVEL(v);
  });
  p.add_option('\0', "configured-maximum-candidate-test",
               "test a compressed candidate near the configured block and collated-data limits",
               [&]() { run_configured_maximum_candidate_test = true; });
  p.add_checked_option('d', "duration", "test duration in seconds (default: 60)", [&](td::Slice arg) {
    DURATION = td::to_double(arg);
    if (DURATION < 0.0) {
      return td::Status::Error(PSTRING() << "invalid duration value " << arg);
    }
    return td::Status::OK();
  });
  p.add_option('m', "masterchain", "masterchain consensus (default is shardchain)", [&]() {
    SHARD = ShardIdFull{masterchainId};
    FIRST_PARENT.id.workchain = masterchainId;
    FIRST_PARENT.id.shard = shardIdAll;
    MIN_MC_BLOCK_ID = FIRST_PARENT;
  });
  p.add_checked_option('n', "n-nodes", "number of nodes (default: 8)", [&](td::Slice arg) {
    TRY_RESULT_ASSIGN(N_NODES, td::to_integer_safe<td::uint32>(arg));
    if (N_NODES == 0) {
      return td::Status::Error(PSTRING() << "invalid n-nodes value " << arg);
    }
    return td::Status::OK();
  });
  p.add_checked_option('\0', "n-double-nodes", "number of nodes with two instances (default: 0)", [&](td::Slice arg) {
    TRY_RESULT_ASSIGN(N_DOUBLE_NODES, td::to_integer_safe<td::uint32>(arg));
    return td::Status::OK();
  });
  p.add_checked_option('\0', "target-rate-ms", "target block rate in milliseconds (default: 1000)", [&](td::Slice arg) {
    TRY_RESULT_ASSIGN(TARGET_RATE_MS, td::to_integer_safe<td::uint32>(arg));
    return td::Status::OK();
  });
  p.add_checked_option('\0', "slots-per-leader-window", "slots per leader window (default: 4)", [&](td::Slice arg) {
    TRY_RESULT_ASSIGN(SLOTS_PER_LEADER_WINDOW, td::to_integer_safe<td::uint32>(arg));
    return td::Status::OK();
  });
  p.add_checked_option('\0', "min-finalized-blocks", "minimum finalized height required for success (default: 0)",
                       [&](td::Slice arg) {
                         TRY_RESULT_ASSIGN(MIN_FINALIZED_BLOCKS, td::to_integer_safe<BlockSeqno>(arg));
                         return td::Status::OK();
                       });
  p.add_checked_option('\0', "net-ping", "network ping (range, default: 0.05:0.1)", [&](td::Slice arg) {
    TRY_RESULT_ASSIGN(NET_PING, parse_range(arg));
    if (NET_PING.first < 0.0) {
      return td::Status::Error(PSTRING() << "invalid ping value " << arg);
    }
    return td::Status::OK();
  });
  p.add_checked_option('\0', "net-loss", "packet loss probability (default: 0)", [&](td::Slice arg) {
    NET_LOSS = td::to_double(arg);
    if (NET_LOSS < 0.0 || NET_LOSS > 1.0) {
      return td::Status::Error(PSTRING() << "invalid loss value " << arg);
    }
    return td::Status::OK();
  });

  p.add_checked_option('\0', "gremlin-period", "gremlin period (range, default: no gremlin)", [&](td::Slice arg) {
    TRY_RESULT_ASSIGN(GREMLIN_PERIOD, parse_range(arg));
    if (GREMLIN_PERIOD.first < 0.0 || GREMLIN_PERIOD.second <= 0.0) {
      return td::Status::Error(PSTRING() << "invalid gremlin period value " << arg);
    }
    return td::Status::OK();
  });
  p.add_checked_option('\0', "gremlin-downtime", "gremlin downtime duration (range, default: 1)", [&](td::Slice arg) {
    TRY_RESULT_ASSIGN(GREMLIN_DOWNTIME, parse_range(arg));
    if (GREMLIN_DOWNTIME.first < 0.0) {
      return td::Status::Error(PSTRING() << "invalid gremlin downtime value " << arg);
    }
    return td::Status::OK();
  });
  p.add_checked_option('\0', "gremlin-n", "how many nodes gremlin restarts at once (range, default: 1)",
                       [&](td::Slice arg) {
                         TRY_RESULT_ASSIGN(GREMLIN_N, parse_int_range<size_t>(arg));
                         return td::Status::OK();
                       });
  p.add_checked_option('\0', "gremlin-times", "how many times gremlin runs (default: unlimited)", [&](td::Slice arg) {
    TRY_RESULT_ASSIGN(GREMLIN_TIMES, td::to_integer_safe<size_t>(arg));
    return td::Status::OK();
  });
  p.add_option('\0', "gremlin-kills-leader", "gremlin always restarts the current leader",
               [&]() { GREMLIN_KILLS_LEADER = true; });

  p.add_checked_option('\0', "net-gremlin-period", "network gremlin period (range, default: no gremlin)",
                       [&](td::Slice arg) {
                         TRY_RESULT_ASSIGN(NET_GREMLIN_PERIOD, parse_range(arg));
                         if (NET_GREMLIN_PERIOD.first < 0.0 || NET_GREMLIN_PERIOD.second <= 0.0) {
                           return td::Status::Error(PSTRING() << "invalid net gremlin period value " << arg);
                         }
                         return td::Status::OK();
                       });
  p.add_checked_option('\0', "net-gremlin-downtime", "network gremlin downtime duration (range, default: 10)",
                       [&](td::Slice arg) {
                         TRY_RESULT_ASSIGN(NET_GREMLIN_DOWNTIME, parse_range(arg));
                         if (NET_GREMLIN_DOWNTIME.first < 0.0) {
                           return td::Status::Error(PSTRING() << "invalid network gremlin downtime value " << arg);
                         }
                         return td::Status::OK();
                       });
  p.add_checked_option('\0', "net-gremlin-n", "how many nodes network gremlin disables at once (range, default: 1)",
                       [&](td::Slice arg) {
                         TRY_RESULT_ASSIGN(NET_GREMLIN_N, parse_int_range<size_t>(arg));
                         return td::Status::OK();
                       });
  p.add_checked_option('\0', "net-gremlin-times", "how many times network gremlin runs (default: unlimited)",
                       [&](td::Slice arg) {
                         TRY_RESULT_ASSIGN(NET_GREMLIN_TIMES, td::to_integer_safe<size_t>(arg));
                         return td::Status::OK();
                       });
  p.add_option('\0', "net-gremlin-kills-leader", "network gremlin always disables the current leader",
               [&]() { NET_GREMLIN_KILLS_LEADER = true; });
  p.add_checked_option('\0', "adaptive-byzantine-n",
                       "number of adaptively selected nodes that selectively omit forwarding (default: 0)",
                       [&](td::Slice arg) {
                         TRY_RESULT_ASSIGN(ADAPTIVE_BYZANTINE_N, td::to_integer_safe<size_t>(arg));
                         return td::Status::OK();
                       });
  p.add_checked_option('\0', "adaptive-byzantine-period",
                       "seconds between adaptive Byzantine-set rotations (default: 0.5)", [&](td::Slice arg) {
                         ADAPTIVE_BYZANTINE_PERIOD = td::to_double(arg);
                         if (ADAPTIVE_BYZANTINE_PERIOD <= 0.0) {
                           return td::Status::Error(PSTRING() << "invalid adaptive Byzantine period " << arg);
                         }
                         return td::Status::OK();
                       });
  p.add_option('\0', "malicious-observer-attack",
               "inject repeated protocol votes from a member with no validator identity",
               [&]() { MALICIOUS_OBSERVER_ATTACK = true; });
  p.add_option('\0', "relay-loop-test", "duplicate candidate arrival events and require candidate-relay deduplication",
               [&]() { RELAY_LOOP_TEST = true; });
  p.add_option('\0', "query-abuse-test", "flood candidate queries from one observer and require rate limiting",
               [&]() { QUERY_ABUSE_TEST = true; });
  p.add_option('\0', "empty-chain-restart-test",
               "restart after more than 4096 consecutive empty candidates and require recovery",
               [&]() { EMPTY_CHAIN_RESTART_TEST = true; });
  p.add_option('\0', "vote-journal-test", "restart across the two-phase own-vote journal and require exact-byte replay",
               [&]() { VOTE_JOURNAL_TEST = true; });
  p.add_option('\0', "permanent-finalization-test",
               "require a finalization that cannot be retried to be kept, reported and to stop the group",
               [&]() { PERMANENT_FINALIZATION_TEST = true; });
  p.add_checked_option('\0', "byzantine-relay-node",
                       "the validator that relays other validators' signed votes over its own transport",
                       [&](td::Slice arg) {
                         TRY_RESULT_ASSIGN(BYZANTINE_RELAY_NODE, td::to_integer_safe<int>(arg));
                         if (BYZANTINE_RELAY_NODE < 0) {
                           return td::Status::Error(PSTRING() << "invalid byzantine-relay-node value " << arg);
                         }
                         return td::Status::OK();
                       });
  p.add_option('\0', "finalization-retry-probe",
               "refuse a finalization with the concurrency limit and require it to be tried again",
               [&]() { FINALIZATION_RETRY_PROBE = true; });
  p.add_option('\0', "finalization-backpressure-test",
               "require finalization backlog throttling, recovery, and one accepted block after recovery",
               [&]() { FINALIZATION_BACKPRESSURE_TEST = true; });
  p.add_option('\0', "pq-finality-e2e-test",
               "require an agreed post-quantum finality certificate on every node, and nothing past it",
               [&]() { PQ_FINALITY_E2E_TEST = true; });
  p.add_option('\0', "candidate-relay-eviction-test", "fill the candidate-relay LRU and verify oldest-entry eviction",
               [&]() { run_candidate_relay_eviction_test = true; });
  p.add_option('\0', "state-resolver-cache-unit-test",
               "verify completed-entry LRU ordering, bounds and failure removal",
               [&]() { run_state_resolver_cache_unit_test = true; });
  p.add_option('\0', "state-resolver-inflight-admission-unit-test",
               "verify in-flight resolution admission control bounds concurrent pending entries",
               [&]() { run_state_resolver_inflight_admission_unit_test = true; });
  p.add_option('\0', "merkle-exact-parent-height-control-test",
               "verify the recovered N/N-1 Merkle base-state mismatch shape",
               [&]() { run_merkle_exact_parent_height_control_test = true; });
  p.add_option('\0', "candidate-resolver-retention-unit-test",
               "verify finalized-window pruning and in-flight retention",
               [&]() { run_candidate_resolver_retention_unit_test = true; });
  p.add_option('\0', "candidate-resolver-interleaving-unit-test",
               "verify finalization/network/persistence eviction interleavings",
               [&]() { run_candidate_resolver_interleaving_unit_test = true; });
  p.add_option('\0', "simplex-db-finalized-slot-dedup-unit-test",
               "verify finalized-slot pruning for persisted vote and certificate hashes",
               [&]() { run_simplex_db_finalized_slot_dedup_unit_test = true; });
  p.add_option('\0', "validator-manager-resource-policy-unit-test",
               "verify bounded manager operation admission and exact-key idempotence",
               [&]() { run_validator_manager_resource_policy_unit_test = true; });
  p.add_checked_option('\0', "catch-up-downtime",
                       "stop one validator for this many seconds, then require it to catch up", [&](td::Slice arg) {
                         CATCH_UP_DOWNTIME = td::to_double(arg);
                         if (CATCH_UP_DOWNTIME < 0.0) {
                           return td::Status::Error(PSTRING() << "invalid catch-up downtime " << arg);
                         }
                         return td::Status::OK();
                       });
  p.add_checked_option('\0', "db-delay", "delay before db values are stored to disk (range, default: 0)",
                       [&](td::Slice arg) {
                         TRY_RESULT_ASSIGN(DB_DELAY, parse_range(arg));
                         if (DB_DELAY.first < 0.0) {
                           return td::Status::Error(PSTRING() << "invalid db delay value " << arg);
                         }
                         return td::Status::OK();
                       });
  p.add_checked_option('\0', "collation-time", "time it takes to collate a block (range, default: 0)",
                       [&](td::Slice arg) {
                         TRY_RESULT_ASSIGN(COLLATION_TIME, parse_range(arg));
                         if (COLLATION_TIME.first < 0.0) {
                           return td::Status::Error(PSTRING() << "invalid collation time " << arg);
                         }
                         return td::Status::OK();
                       });
  p.add_checked_option('\0', "validation-time", "time it takes to validate a block (range, default: 0)",
                       [&](td::Slice arg) {
                         TRY_RESULT_ASSIGN(VALIDATION_TIME, parse_range(arg));
                         if (VALIDATION_TIME.first < 0.0) {
                           return td::Status::Error(PSTRING() << "invalid validation time " << arg);
                         }
                         return td::Status::OK();
                       });

  p.run(argc, argv).ensure();
  if (const char* value = std::getenv("TOS_TEST_RESTART_FROM_LAST_ACCEPTED_BLOCK");
      value != nullptr && std::string_view(value) == "1") {
    RESTART_FROM_LAST_ACCEPTED_BLOCK = true;
  }
  if (const char* value = std::getenv("TOS_TEST_ANCHOR_TRANSIENT_FAILURES"); value != nullptr) {
    auto parsed = td::to_integer_safe<size_t>(td::Slice(value));
    LOG_CHECK(parsed.is_ok() && parsed.ok() > 0) << "TOS_TEST_ANCHOR_TRANSIENT_FAILURES must be a positive integer";
    EMPTY_CHAIN_MANAGER_ANCHOR_TRANSIENT_FAILURES = parsed.ok();
  }
  if (const char* value = std::getenv("TOS_TEST_ORIGIN_TRANSIENT_FAILURES"); value != nullptr) {
    auto parsed = td::to_integer_safe<size_t>(td::Slice(value));
    LOG_CHECK(parsed.is_ok() && parsed.ok() > 0) << "TOS_TEST_ORIGIN_TRANSIENT_FAILURES must be a positive integer";
    EMPTY_CHAIN_ORIGIN_TRANSIENT_FAILURES = parsed.ok();
  }
  if (const char* value = std::getenv("TOS_TEST_ORIGIN_PERMANENTLY_UNAVAILABLE");
      value != nullptr && std::string_view(value) == "1") {
    EMPTY_CHAIN_ORIGIN_PERMANENTLY_UNAVAILABLE = true;
  }
  if (const char* value = std::getenv("TOS_TEST_C05_SIMULTANEOUS_FAULTS"); value != nullptr) {
    auto parsed = td::to_integer_safe<size_t>(td::Slice(value));
    LOG_CHECK(parsed.is_ok() && parsed.ok() > 0) << "TOS_TEST_C05_SIMULTANEOUS_FAULTS must be positive";
    C05_GENESIS_FAULT_BUDGET = parsed.ok();
  }
  LOG(WARNING) << "C03 harness switches: restart_from_last_accepted_block=" << RESTART_FROM_LAST_ACCEPTED_BLOCK
               << " anchor_transient_failures=" << EMPTY_CHAIN_MANAGER_ANCHOR_TRANSIENT_FAILURES.load()
               << " origin_transient_failures=" << EMPTY_CHAIN_ORIGIN_TRANSIENT_FAILURES.load()
               << " origin_permanently_unavailable=" << EMPTY_CHAIN_ORIGIN_PERMANENTLY_UNAVAILABLE;
  if (run_configured_maximum_candidate_test) {
    test_configured_maximum_candidate();
    return 0;
  }
  if (run_candidate_relay_eviction_test) {
    test_candidate_relay_eviction();
    return 0;
  }
  if (run_state_resolver_cache_unit_test) {
    test_state_resolver_completed_lru();
    return 0;
  }
  if (run_state_resolver_inflight_admission_unit_test) {
    test_state_resolver_inflight_admission();
    return 0;
  }
  if (run_merkle_exact_parent_height_control_test) {
    test_merkle_exact_parent_height_control();
    return 0;
  }
  if (run_candidate_resolver_retention_unit_test) {
    test_candidate_resolver_retention();
    return 0;
  }
  if (run_candidate_resolver_interleaving_unit_test) {
    test_candidate_resolver_interleaving();
    return 0;
  }
  if (run_simplex_db_finalized_slot_dedup_unit_test) {
    test_simplex_db_finalized_slot_dedup();
    return 0;
  }
  if (run_validator_manager_resource_policy_unit_test) {
    test_validator_manager_resource_policy();
    return 0;
  }
  CHECK(N_DOUBLE_NODES <= N_NODES);
  CHECK(ADAPTIVE_BYZANTINE_N < N_NODES);
  CHECK(CATCH_UP_DOWNTIME < 0.0 || N_NODES >= 4);
  CHECK(!EMPTY_CHAIN_RESTART_TEST || N_NODES == 1);
  CHECK(!VOTE_JOURNAL_TEST || N_NODES == 1);
  if (EMPTY_CHAIN_RESTART_TEST) {
    // Thousands of per-candidate WARNING lines dominate this stress test's
    // runtime and do not add coverage.
    SET_VERBOSITY_LEVEL(verbosity_ERROR);
  }

  td::actor::Scheduler scheduler({7});
  td::actor::ActorOwn<TestConsensus> test;

  scheduler.run_in_context([&] {
    test = td::actor::create_actor<TestConsensus>("test-consensus");
    td::actor::ask(test, &TestConsensus::run).detach();
  });
  while (scheduler.run(1)) {
  }

  return 0;
}
