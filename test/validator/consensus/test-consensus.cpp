/*
 * Copyright (c) 2025-2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "adnl/utils.hpp"
#include "auto/tl/tos_api.h"
#include "block/block.h"
#include "block/mc-config.h"
#include "block/validator-set.h"
#include "consensus/simplex/bus.h"
#include "consensus/utils.h"
#include "td/actor/BusRuntime.h"
#include "td/actor/coro_utils.h"
#include "td/db/MemoryKeyValue.h"
#include "td/utils/OptionParser.h"
#include "td/utils/Random.h"
#include "td/utils/port/signals.h"
#include "validator-session/candidate-serializer.h"
#include "vm/boc-compression.h"
#include "vm/boc.h"

#include "block-auto.h"

using namespace tos;
using namespace tos::validator;
using namespace tos::validator::consensus;

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
    Instance &inst = get_inst(idx, instance_idx);
    CHECK(inst.actor.empty());
    inst.actor = std::move(node);
  }

  void unregister_node(size_t idx, size_t instance_idx) {
    Instance &inst = get_inst(idx, instance_idx);
    CHECK(!inst.actor.empty());
    inst.actor = {};
  }

  td::actor::Task<> set_instance_disabled(size_t idx, size_t instance_idx, bool value) {
    get_inst(idx, instance_idx).disabled = value;
    LOG(ERROR) << "Node #" << idx << "." << instance_idx << ": " << (value ? "disable" : "enable") << " network";
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

  Instance &get_inst(size_t idx, size_t instance_idx) {
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
      co_return td::Status::Error("packet lost");
    }
    co_await td::actor::coro_sleep(td::Timestamp::in(td::Random::fast(NET_PING.first, NET_PING.second)));
    co_return td::Unit{};
  }
};

td::actor::ActorOwn<TestOverlay> test_overlay;

class TestOverlayNode : public td::actor::SpawnsWith<Bus>, public td::actor::ConnectsTo<Bus> {
 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();

  void start_up() override {
    instance_idx_ = dynamic_cast<const TestSimplexBus &>(*owning_bus()).instance_idx;
    td::actor::send_closure(test_overlay, &TestOverlay::register_node, owning_bus()->local_id->idx.value(),
                            instance_idx_, actor_id(this));
  }

  void tear_down() override {
    td::actor::send_closure(test_overlay, &TestOverlay::unregister_node, owning_bus()->local_id->idx.value(),
                            instance_idx_);
    for (auto &[_, query] : active_queries_) {
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
    td::actor::send_closure(test_overlay, &TestOverlay::send_query, *bus->local_id, instance_idx_,
                            destination, message->request.data.clone(),
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
    owning_bus().publish<IncomingProtocolMessage>(src.idx, src.adnl_id, std::move(data));
  }

  void receive_candidate(CandidateRef candidate) {
    owning_bus().publish<CandidateReceived>(candidate);
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
  co_await before_receive(src.idx.value(), src_instance_idx, dst_idx, false);
  for (const auto &instance : nodes_[dst_idx]) {
    if (instance.actor.empty() || instance.disabled) {
      continue;
    }
    td::actor::send_closure(instance.actor, &TestOverlayNode::receive_message, src, message.clone());
  }
  co_return td::Unit{};
}

td::actor::Task<> TestOverlay::send_candidate(PeerValidator src, size_t src_instance_idx, size_t dst_idx,
                                              CandidateRef candidate) {
  co_await before_receive(src.idx.value(), src_instance_idx, dst_idx, true);
  for (const auto &instance : nodes_[dst_idx]) {
    if (instance.actor.empty() || instance.disabled) {
      continue;
    }
    td::actor::send_closure(instance.actor, &TestOverlayNode::receive_candidate, candidate);
  }
  co_return td::Unit{};
}

td::actor::Task<td::BufferSlice> TestOverlay::send_query(PeerValidator src, size_t src_instance_idx, size_t dst_idx,
                                                         td::BufferSlice message) {
  if (nodes_[dst_idx].empty()) {
    co_return td::Status::Error("no instances");
  }
  auto dst_instance_idx = (size_t)td::Random::fast(0, (int)nodes_[dst_idx].size() - 1);
  const auto &instance = nodes_[dst_idx][dst_instance_idx];
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
                                 td::Ref<block::BlockSignatureSet> signatures, int block_broadcast_mode,
                                 int finality_broadcast_mode, bool apply) override;

  td::actor::Task<td::Ref<vm::Cell>> wait_block_state_root(BlockIdExt block_id, td::Timestamp timeout) override;
  td::actor::Task<td::Ref<BlockData>> wait_block_data(BlockIdExt block_id, td::Timestamp timeout) override;

 private:
  size_t node_idx_;
  size_t instance_idx_;
  Ref<block::ValidatorSet> validator_set_;
  td::actor::ActorId<TestConsensus> test_consensus_;
};

class TestDbImpl : public consensus::Db {
 public:
  struct DbInner {
    std::map<td::BufferSlice, td::BufferSlice> map;
    std::mutex mutex;
  };

  explicit TestDbImpl(std::shared_ptr<DbInner> db) : db_(std::move(db)) {
    std::scoped_lock lock(db_->mutex);
    for (auto &[key, value] : db_->map) {
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
    td::BufferSlice begin{(const char *)&prefix, 4};
    td::uint32 prefix2 = prefix + 1;
    td::BufferSlice end{(const char *)&prefix2, 4};
    for (auto it = snapshot_.lower_bound(begin); it != snapshot_.end() && it->first < end; ++it) {
      result.emplace_back(it->first.clone(), it->second.clone());
    }
    return result;
  }
  td::actor::Task<> set(td::BufferSlice key, td::BufferSlice value) override {
    co_await td::actor::coro_sleep(td::Timestamp::in(td::Random::fast(DB_DELAY.first, DB_DELAY.second)));
    std::scoped_lock lock(db_->mutex);
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
    if (signatures->is_final()) {
      signatures->check_signatures(validator_set_, block_id).ensure();
    } else {
      CHECK(!SHARD.is_masterchain());
      signatures->check_approve_signatures(validator_set_, block_id).ensure();
    }
    BlockSeqno seqno = block_id.seqno();
    if (accepted_blocks_.contains(seqno)) {
      LOG_CHECK(accepted_blocks_[seqno]->block_id() == block_id) << "Accepted different blocks for seqno " << seqno;
    } else {
      accepted_blocks_[seqno] = block;
    }
    Instance &inst = nodes_[node_idx].instances[instance_idx];
    inst.last_accepted_block = std::max(inst.last_accepted_block, seqno);
    if (last_accepted_block_.seqno() < seqno && signatures->is_final()) {
      last_accepted_block_ = block_id;
      last_accepted_block_leader_idx_ = creator_idx;
      for (Node &node : nodes_) {
        for (Instance &inst : node.instances) {
          if (inst.status == Instance::Running) {
            inst.bus.publish<BlockFinalizedInMasterchain>(block_id);
          }
        }
      }
    }
    co_return td::Unit{};
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

      nodes_.push_back(std::move(node));
    }

    std::vector<ValidatorDescr> validator_descrs;
    for (size_t idx = 0; idx < nodes_.size(); ++idx) {
      Node &node = nodes_[idx];
      validator_descrs.push_back(ValidatorDescr(Ed25519_PublicKey{node.public_key.ed25519_value().raw()}, node.weight,
                                                node.adnl_id.bits256_value()));
      validators_.push_back(PeerValidator{.idx = PeerValidatorId((int)idx),
                                          .key = node.public_key,
                                          .short_id = node.node_id,
                                          .adnl_id = node.adnl_id,
                                          .weight = node.weight});
      total_weight_ += node.weight;
    }
    validator_set_ = td::Ref<block::ValidatorSet>{true, CC_SEQNO, SHARD, std::move(validator_descrs)};

    test_overlay = td::actor::create_actor<TestOverlay>("test-overlay");

    for (size_t idx = 0; idx < N_NODES; ++idx) {
      Node &node = nodes_[idx];
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

    run_write_status().start().detach();

    co_await td::actor::coro_sleep(td::Timestamp::in(DURATION));

    co_return co_await finalize();
  }

  td::actor::Task<> run_write_status() {
    while (!finishing_) {
      std::string s;
      for (auto &n : nodes_) {
        for (auto &inst : n.instances) {
          s += "-X"[inst.status == Instance::Running];
        }
      }
      LOG(ERROR) << s;
      co_await td::actor::coro_sleep(td::Timestamp::in(1.0));
    }
    co_return td::Unit{};
  }

  void start_instance(size_t node_idx, size_t instance_idx) {
    Node &node = nodes_[node_idx];
    Instance &inst = node.instances[instance_idx];
    CHECK(inst.status == Instance::Stopped);
    auto &runtime = inst.runtime;
    BlockAccepter::register_in(runtime);
    BlockProducer::register_in(runtime);
    BlockValidator::register_in(runtime);
    runtime.register_actor<TestOverlayNode>("PrivateOverlay");
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
    bus->validator_opts = ValidatorManagerOptions::create(BlockIdExt{}, BlockIdExt{});
    bus->validator_set = validators_;
    bus->total_weight = total_weight_;
    bus->local_id = validators_[node_idx];
    bus->config = NewConsensusConfig{
        .max_block_size = 1 << 20,
        .max_collated_data_size = 1 << 20,
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
    inst.bus.publish<Start>(
        td::make_ref<ChainState>(ChainState::ZerostateTip{FIRST_PARENT, gen_shard_state(0)}, MIN_MC_BLOCK_ID));
    LOG(ERROR) << "Starting node #" << node_idx << "." << instance_idx;
  }

  td::actor::Task<> stop_instance(size_t node_idx, size_t instance_idx) {
    Node &node = nodes_[node_idx];
    Instance &inst = node.instances[instance_idx];
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
    for (auto &promise : inst.extra_stop_waiters) {
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
    co_await td::actor::coro_sleep(
        td::Timestamp::in(td::Random::fast(NET_GREMLIN_DOWNTIME.first, NET_GREMLIN_DOWNTIME.second)));
    co_await td::actor::ask(test_overlay, &TestOverlay::set_instance_disabled, selected_node_idx, selected_inst_idx,
                            false);
    nodes_[selected_node_idx].instances[selected_inst_idx].net_gremlin_active = false;
    co_return td::Unit{};
  }

  td::actor::Task<> finalize() {
    finishing_ = true;
    LOG(WARNING) << "TEST FINISHED";
    std::vector<td::actor::Task<>> tasks;
    for (size_t idx = 0; idx < N_NODES; ++idx) {
      for (size_t i = 0; i < nodes_[i].instances.size(); ++i) {
        tasks.push_back(stop_instance(idx, i));
      }
    }
    co_await td::actor::all(std::move(tasks));
    LOG(WARNING) << "TEST RESULTS:";
    for (size_t idx = 0; idx < N_NODES; ++idx) {
      for (size_t inst_idx = 0; inst_idx < nodes_[idx].instances.size(); ++inst_idx) {
        Instance &inst = nodes_[idx].instances[inst_idx];
        LOG(WARNING) << "Node #" << idx << " instance #" << inst_idx << " : synced up to block "
                     << inst.last_accepted_block;
      }
    }
    if (last_accepted_block_.seqno() < MIN_FINALIZED_BLOCKS) {
      co_return td::Status::Error(
          PSTRING() << "finalized only " << last_accepted_block_.seqno() << " blocks, expected at least "
                    << MIN_FINALIZED_BLOCKS);
    }
    co_return td::Unit{};
  }

  struct Instance {
    td::actor::Runtime runtime;
    td::actor::ActorOwn<TestManagerFacade> manager_facade;
    simplex::BusHandle bus;

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
  bool finishing_ = false;
};

td::actor::Task<> TestManagerFacade::accept_block(BlockIdExt id, td::Ref<BlockData> data, size_t creator_idx,
                                                  td::Ref<block::BlockSignatureSet> signatures,
                                                  int block_broadcast_mode, int finality_broadcast_mode, bool apply) {
  CHECK(id.shard_full() == SHARD);
  LOG(WARNING) << "Accept block #" << id.seqno() << " (" << (signatures->is_final() ? "final" : "notarize")
               << " signatures), creator_idx=" << creator_idx;
  CHECK(id == data->block_id());
  if (signatures->is_final()) {
    auto encoded = create_serialize_tl_object<tos_api::tosNode_blockFinalityBroadcast>(
        create_tl_block_id(id), signatures->tl());
    auto decoded = fetch_tl_object<tos_api::tosNode_Broadcast>(std::move(encoded), true).move_as_ok();
    CHECK(decoded->get_id() == tos_api::tosNode_blockFinalityBroadcast::ID);
    auto finality = move_tl_object_as<tos_api::tosNode_blockFinalityBroadcast>(decoded);
    CHECK(create_block_id(finality->id_) == id);
    auto decoded_signatures = block::BlockSignatureSet::fetch(finality->signature_set_);
    CHECK(decoded_signatures.not_null());
    CHECK(decoded_signatures->is_final());
    CHECK(decoded_signatures->get_catchain_seqno() == signatures->get_catchain_seqno());
    CHECK(decoded_signatures->get_validator_set_hash() == signatures->get_validator_set_hash());
    decoded_signatures->check_signatures(validator_set_, id).ensure();
    auto tampered_id = id;
    tampered_id.id.seqno++;
    CHECK(decoded_signatures->check_signatures(validator_set_, tampered_id).is_error());
  }
  td::actor::ask(test_consensus_, &TestConsensus::on_block_accepted, node_idx_, instance_idx_, data, creator_idx,
                 signatures)
      .detach();
  co_return td::Unit{};
}

td::actor::Task<td::Ref<vm::Cell>> TestManagerFacade::wait_block_state_root(BlockIdExt block_id,
                                                                            td::Timestamp timeout) {
  co_return co_await td::actor::ask(test_consensus_, &TestConsensus::wait_block_state_root, block_id);
}

td::actor::Task<td::Ref<BlockData>> TestManagerFacade::wait_block_data(BlockIdExt block_id, td::Timestamp timeout) {
  co_return co_await td::actor::ask(test_consensus_, &TestConsensus::wait_block_data, block_id);
}

td::BufferSlice make_large_candidate_boc(td::uint32 leaf_count, td::uint32 salt, bool multi_root,
                                         td::Bits256 &root_hash) {
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
  auto decoded =
      validatorsession::deserialize_candidate(envelope, true, max_envelope_size).move_as_ok();
  CHECK(decoded->data_.as_slice() == block_data.as_slice());
  CHECK(decoded->collated_data_.as_slice() == collated_data.as_slice());
  CHECK(validatorsession::deserialize_candidate(envelope, true, static_cast<int>(decompressed_size) - 1)
            .is_error());
}

}  // namespace

int main(int argc, char *argv[]) {
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

    auto candidate = create_tl_object<tos_api::validatorSession_candidate>(
        src, 7, root_hash, block_data.clone(), collated_data.clone());

    auto raw = validatorsession::serialize_candidate(candidate, false).move_as_ok();
    auto raw_decoded =
        validatorsession::deserialize_candidate(raw, false, static_cast<int>(raw.size())).move_as_ok();
    CHECK(raw_decoded->src_ == src);
    CHECK(raw_decoded->round_ == 7);
    CHECK(raw_decoded->root_hash_ == root_hash);
    CHECK(raw_decoded->data_.as_slice() == block_data.as_slice());
    CHECK(raw_decoded->collated_data_.as_slice() == collated_data.as_slice());
    CHECK(validatorsession::deserialize_candidate(raw, true, static_cast<int>(raw.size())).is_error());

    size_t decompressed_size = 0;
    auto compressed = validatorsession::compress_candidate_data(block_data, collated_data, decompressed_size,
                                                                 "test", root_hash)
                          .move_as_ok();
    CHECK(decompressed_size <= static_cast<size_t>(std::numeric_limits<int>::max()));
    auto compressed_envelope = create_serialize_tl_object<tos_api::validatorSession_compressedCandidate>(
        0, src, 7, root_hash, static_cast<int>(decompressed_size), compressed.clone());
    const int legacy_limit =
        static_cast<int>(std::max(decompressed_size, static_cast<size_t>(compressed.size())));
    auto legacy_decoded =
        validatorsession::deserialize_candidate(compressed_envelope, true, legacy_limit).move_as_ok();
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
    auto improved_decoded =
        validatorsession::deserialize_candidate(improved_envelope, true, 1 << 20).move_as_ok();
    CHECK(improved_decoded->data_.as_slice() == block_data.as_slice());
    CHECK(improved_decoded->collated_data_.as_slice() == collated_data.as_slice());
    CHECK(validatorsession::deserialize_candidate(improved_envelope, true,
                                                  static_cast<int>(improved.size()) - 1)
              .is_error());

    auto corrupt_improved = improved.clone();
    corrupt_improved.data()[corrupt_improved.size() / 2] ^= 0x5a;
    auto corrupt_improved_envelope = create_serialize_tl_object<tos_api::validatorSession_compressedCandidateV2>(
        0, src, 7, root_hash, std::move(corrupt_improved));
    CHECK(validatorsession::deserialize_candidate(corrupt_improved_envelope, true, 1 << 20).is_error());

    auto baseline =
        vm::boc_compress({block_root, collated_root}, vm::CompressionAlgorithm::BaselineLZ4).move_as_ok();
    auto baseline_envelope = create_serialize_tl_object<tos_api::validatorSession_compressedCandidateV2>(
        0, src, 7, root_hash, std::move(baseline));
    auto baseline_decoded =
        validatorsession::deserialize_candidate(baseline_envelope, true, 1 << 20).move_as_ok();
    CHECK(baseline_decoded->data_.as_slice() == block_data.as_slice());
    CHECK(baseline_decoded->collated_data_.as_slice() == collated_data.as_slice());

    td::BufferSlice empty_improved;
    auto empty_improved_envelope = create_serialize_tl_object<tos_api::validatorSession_compressedCandidateV2>(
        0, src, 7, root_hash, std::move(empty_improved));
    CHECK(validatorsession::deserialize_candidate(empty_improved_envelope, true, 1 << 20).is_error());

    td::BufferSlice unknown_algorithm(1);
    unknown_algorithm.data()[0] = static_cast<char>(0x7f);
    auto unknown_algorithm_envelope =
        create_serialize_tl_object<tos_api::validatorSession_compressedCandidateV2>(
            0, src, 7, root_hash, std::move(unknown_algorithm));
    CHECK(validatorsession::deserialize_candidate(unknown_algorithm_envelope, true, 1 << 20).is_error());

    auto stateful = vm::boc_compress({block_root}, vm::CompressionAlgorithm::ImprovedStructureLZ4WithState,
                                     block_root)
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
    const int exact_limit =
        static_cast<int>(std::max(decompressed_size, static_cast<size_t>(compressed.size())));
    auto decoded = validatorsession::deserialize_candidate(envelope, true, exact_limit).move_as_ok();
    CHECK(decoded->data_.as_slice() == large_block_data.as_slice());
    CHECK(decoded->collated_data_.as_slice() == collated_data.as_slice());
    CHECK(validatorsession::deserialize_candidate(envelope, true, static_cast<int>(decompressed_size) - 1)
              .is_error());

    auto oversized_declaration = create_serialize_tl_object<tos_api::validatorSession_compressedCandidate>(
        0, src, 9, root_hash, exact_limit + 1, compressed.clone());
    CHECK(validatorsession::deserialize_candidate(oversized_declaration, true, exact_limit).is_error());
  }

  SET_VERBOSITY_LEVEL(verbosity_WARNING);
  td::set_default_failure_signal_handler().ensure();

  bool run_configured_maximum_candidate_test = false;
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
  if (run_configured_maximum_candidate_test) {
    test_configured_maximum_candidate();
    return 0;
  }
  CHECK(N_DOUBLE_NODES <= N_NODES);

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
