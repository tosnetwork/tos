/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
// Actor-level regression: a state resolution that has to replay several finalized full
// candidates gets every payload the node-wide budget dropped back from the consensus database,
// asks no peer for any of them, and ends on the same state as with the default budget.
//
// One validator node runs the production CandidateResolver, StateResolver and Db actors. The
// stand-ins are the validator manager, which knows only the zerostate, the block accepter, which
// accepts every FinalizeBlock, the private overlay, which counts every candidate request and
// answers none, and the database backend, which counts candidate payload reads.
//
// Scenario:
//   1. A chain of CHAIN_LENGTH full candidates on the zerostate is stored and notarized, then
//      finalized slot by slot, oldest first, as a running group finalizes them. No payload is
//      read back from the database on the way, so the walk below is its first reader.
//   2. Once every finalization has settled and nothing holds an entry, the cache is checked:
//      in mode `low-budget` the allowance has room for one payload, so every ancestor payload
//      has been dropped from memory while its entry stays tracked and durable; in mode
//      `default-budget` every payload is still cached.
//   3. ResolveState(newest) runs the production ancestor walk. The newest candidate is
//      finalized but the manager has no state for it, so the walk reconstructs it from
//      candidate data: it resolves every ancestor back to the zerostate and applies them all.
//
// Expected, in both modes: the resolution succeeds with the state after the newest candidate,
// whose root is the known root that candidate's Merkle update produces; no candidate request
// ever reaches the overlay. In `low-budget` the walk reads exactly the dropped payloads from
// the database; in `default-budget`, the reference run, it reads none.

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
#include "consensus/simplex/candidate-payload-budget.h"
#include "consensus/simplex/certificate.h"
#include "consensus/simplex/votes.h"
#include "consensus/utils.h"
#include "crypto/pq/consensus-pq-signer.h"
#include "td/actor/BusRuntime.h"
#include "td/actor/coro_utils.h"
#include "td/utils/port/signals.h"
#include "vm/boc.h"

#include "block-auto.h"

using namespace tos;
using namespace tos::validator;
using namespace tos::validator::consensus;

namespace {

constexpr td::uint32 SLOTS_PER_LEADER_WINDOW = 4;
constexpr size_t VALIDATORS = 4;
// Five full candidates: the walk replays four ancestors behind the newest one.
constexpr size_t CHAIN_LENGTH = 5;
constexpr double STEP_TIMEOUT = 20.0;
constexpr double GEN_UTIME_BASE = 1'700'000'000.0;

const CatchainSeqno CC_SEQNO = 123;

td::Bits256 fill(unsigned char byte) {
  td::Bits256 value;
  std::memset(value.data(), byte, 32);
  return value;
}

// The shard state after block `seqno`: each candidate's Merkle update turns the state of its
// predecessor into this one, so the state after the newest candidate is known in advance.
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

// A failed assertion of the scenario itself, as opposed to a precondition of the fixture.
void require(bool condition, const std::string& what) {
  if (!condition) {
    finish(3, "REPLAY_FAILED: " + what);
  }
}

void precondition(bool condition, const std::string& what) {
  if (!condition) {
    finish(1, "REPLAY_PRECONDITION_FAILED: " + what);
  }
}

bool is_key_of(td::Slice key, td::int32 constructor) {
  if (key.size() < 4) {
    return false;
  }
  td::int32 id = 0;
  std::memcpy(&id, key.data(), 4);
  return id == constructor;
}

enum class Mode { LowBudget, DefaultBudget };

// ===== What the test observes =====

std::atomic<size_t> overlay_requests{0};
std::atomic<size_t> db_payload_reads{0};
std::atomic<size_t> finalized_blocks{0};
std::atomic<size_t> zerostate_requests{0};

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

  // Counted and never answered: a candidate the node cannot read locally stays unresolved.
  template <>
  td::actor::Task<ProtocolMessage> process(simplex::BusHandle, std::shared_ptr<OutgoingOverlayRequest>) {
    overlay_requests.fetch_add(1);
    co_return ProtocolMessage{create_serialize_tl_object<tos_api::consensus_requestError>()};
  }
};

class AcceptingAccepter : public td::actor::SpawnsWith<simplex::Bus>, public td::actor::ConnectsTo<simplex::Bus> {
 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();

  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const StopRequested>) {
    stop();
  }

  template <>
  td::actor::Task<> process(simplex::BusHandle, std::shared_ptr<FinalizeBlock>) {
    finalized_blocks.fetch_add(1);
    co_return td::Unit{};
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
    if (is_key_of(key.as_slice(), tos_api::consensus_simplex_db_key_candidate::ID)) {
      db_payload_reads.fetch_add(1);
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

  bool holds(td::Slice key, td::Slice value) const {
    auto stored = get(key);
    return stored.has_value() && stored->as_slice() == value;
  }

 private:
  mutable std::mutex mutex_;
  std::map<td::BufferSlice, td::BufferSlice> map_;
};

// The validator manager: it has the zerostate and nothing else, so a finalized candidate's own
// state is not available and the resolver has to rebuild it from candidate data.
class ZerostateManager : public ManagerFacade {
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
      zerostate_requests.fetch_add(1);
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
  double gen_utime = GEN_UTIME_BASE + seqno;

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

// The charge of one candidate of the chain, computed from a candidate built the same way. Every
// candidate of the chain has the same shape; the driver checks the limit against the real ones.
td::uint64 one_charge() {
  auto block = make_block(1, FIRST_PARENT);
  auto id = CandidateHashData::create_full(block, std::nullopt).build_id_with(0);
  // A signature of the size every fixture signer produces.
  auto store = tos::pq::ValidatorPQKeyStore::from_seed(std::string(32, static_cast<char>(0x60)));
  CHECK(store.has_value());
  auto signature = store->sign_consensus("x");
  CHECK(signature.has_value());
  auto candidate = td::make_ref<Candidate>(id, std::nullopt, PeerValidatorId{0}, std::move(block),
                                           td::BufferSlice(signature->signature));
  return simplex::compact_candidate_charge(*candidate);
}

using Cache = simplex::QueryCandidatePayloadCache::Result;

std::string describe(const Cache& c) {
  return PSTRING() << "limit=" << c.node_limit << " charged=" << c.node_charged_bytes << " peak=" << c.node_charged_peak
                   << " retired=" << c.node_retired_bytes << "/" << c.node_retired_payloads << " entries=" << c.entries
                   << " cached=" << c.cached_payloads << "/" << c.cached_bytes << " admitted=" << c.admitted_payloads
                   << " dropped=" << c.dropped_payloads << " not_cached=" << c.not_cached_payloads
                   << " db_reads=" << c.db_payload_reads << " misses=" << c.db_payload_read_misses
                   << " invalid=" << c.db_payload_read_invalid << " revocations=" << c.durability_revocations
                   << " errors=" << c.node_accounting_errors;
}

class Driver : public td::actor::Actor {
 public:
  explicit Driver(Mode mode) : mode_(mode) {
  }

  td::actor::Task<> run() {
    auto result = co_await run_inner().wrap();
    if (result.is_error()) {
      finish(1, "REPLAY_HARNESS_FAILED: " + result.error().to_string());
    }
    co_return td::Unit{};
  }

 private:
  Mode mode_;
  std::vector<std::shared_ptr<const tos::pq::ValidatorPQKeyStore>> signers_;
  td::actor::Runtime runtime_;
  td::actor::ActorOwn<ZerostateManager> manager_;
  simplex::BusHandle bus_;
  std::shared_ptr<simplex::Bus> bus_ptr_;
  const MemoryDb* db_ = nullptr;
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

  // Full candidates in consecutive slots from slot 0, each on the one before, the oldest on the
  // zerostate.
  std::vector<CandidateRef> make_chain(size_t count) {
    std::vector<CandidateRef> result;
    BlockIdExt prev = FIRST_PARENT;
    ParentId parent = std::nullopt;
    for (size_t i = 0; i < count; ++i) {
      auto block = make_block(static_cast<BlockSeqno>(i) + 1, prev);
      auto slot = static_cast<td::uint32>(i);
      auto id = CandidateHashData::create_full(block, parent).build_id_with(slot);
      auto leader = bus_ptr_->collator_schedule->expected_collator_for(slot);
      auto signature = sign(leader.value(), serialize_tl_object(id.to_tl(), true).as_slice());
      auto candidate = td::make_ref<Candidate>(id, parent, leader, std::move(block), std::move(signature));
      prev = candidate->block_id();
      parent = candidate->id;
      result.push_back(candidate);
    }
    return result;
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

  td::actor::Task<Cache> cache(std::optional<CandidateId> id = std::nullopt) {
    co_return co_await bus_.publish<simplex::QueryCandidatePayloadCache>(id);
  }

  // True once every finalization started so far has settled, the first `finalized` candidates
  // of the chain reached the accepter, and no operation holds any entry of the chain.
  td::actor::Task<bool> quiescent(const std::vector<CandidateRef>& chain, size_t finalized) {
    auto finality = co_await bus_.publish<simplex::QueryFinalizationState>(td::uint32{0});
    if (finality.finalizations_started < finalized ||
        finality.finalizations_started != finality.finalizations_settled || finalized_blocks.load() != finalized) {
      co_return false;
    }
    for (const auto& candidate : chain) {
      auto entry = co_await cache(candidate->id);
      if (entry.id_active_operations != 0) {
        co_return false;
      }
    }
    co_return true;
  }

  td::BufferSlice payload_key(const CandidateId& id) const {
    return create_serialize_tl_object<tos_api::consensus_simplex_db_key_candidate>(id.to_tl());
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
    runtime_.register_actor<AcceptingAccepter>("AcceptingAccepter");
    simplex::CandidateResolver::register_in(runtime_);
    simplex::StateResolver::register_in(runtime_);
    simplex::Db::register_in(runtime_);
    simplex::DefaultCollatorSchedule::provide_for(runtime_);

    manager_ = td::actor::create_actor<ZerostateManager>("ZerostateManager");
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
    auto db = std::make_unique<MemoryDb>();
    db_ = db.get();
    bus->db = std::move(db);
    bus->pq_signer = signers_.at(target_);
    bus->local_id = validators.at(target_);
    bus->local_adnl_id = validators.at(target_).adnl_id;
    bus_ptr_ = bus;

    bus_ = runtime_.start(std::static_pointer_cast<simplex::Bus>(bus), "replay-target");
    bus_.publish<Start>(
        td::make_ref<ChainState>(ChainState::ZerostateTip{FIRST_PARENT, gen_shard_state(0)}, MIN_MC_BLOCK_ID));
  }

  td::actor::Task<> run_inner() {
    start_node();
    const bool low = mode_ == Mode::LowBudget;
    const char* name = low ? "low-budget" : "default-budget";
    auto chain = make_chain(CHAIN_LENGTH);
    const auto& newest = chain.back();

    // The allowance the resolver read from the environment: room for exactly one payload of
    // this chain, or the production default.
    {
      auto state = co_await cache();
      td::uint64 smallest = simplex::compact_candidate_charge(*chain.front());
      td::uint64 largest = smallest;
      for (const auto& candidate : chain) {
        smallest = std::min(smallest, simplex::compact_candidate_charge(*candidate));
        largest = std::max(largest, simplex::compact_candidate_charge(*candidate));
      }
      emit(PSTRING() << "REPLAY_LIMIT mode=" << name << " limit=" << state.node_limit << " charge=" << smallest << ".."
                     << largest);
      if (low) {
        precondition(state.node_limit >= largest && state.node_limit < 2 * smallest,
                     "the low budget does not hold exactly one payload of the chain");
      } else {
        precondition(
            state.node_limit == simplex::DEFAULT_CANDIDATE_CACHE_BYTES && state.node_limit >= largest * CHAIN_LENGTH,
            "the default budget is not in effect or does not hold the chain");
      }
    }

    // 1. Store and notarize the chain, then finalize it slot by slot, oldest first, each
    //    finalization settled before the next. Each one resolves only its own candidate, which
    //    is still in memory, and finds its parent already finalized, so no payload is read back
    //    before the replay: the walk below is the first reader of every dropped payload.
    for (const auto& candidate : chain) {
      co_await bus_.publish<simplex::StoreCandidate>(candidate);
      bus_.publish<simplex::NotarizationObserved>(candidate->id, make_cert(simplex::NotarizeVote{candidate->id}));
    }
    for (size_t i = 0; i < chain.size(); ++i) {
      bus_.publish<simplex::FinalizationObserved>(chain[i]->id, make_cert(simplex::FinalizeVote{chain[i]->id}));
      // 2. Every finalization settled and nothing holds an entry, so what is resident after
      //    the last one is what the budget left.
      auto deadline = td::Timestamp::in(STEP_TIMEOUT);
      while (!co_await quiescent(chain, i + 1)) {
        precondition(!deadline.is_in_past(),
                     PSTRING() << "the finalization of slot " << chain[i]->id.slot << " did not settle");
        co_await td::actor::coro_sleep(td::Timestamp::in(0.005));
      }
    }
    for (const auto& candidate : chain) {
      precondition(db_->holds(payload_key(candidate->id).as_slice(), candidate->serialize().as_slice()),
                   PSTRING() << "the payload of slot " << candidate->id.slot << " is not in the database");
    }
    {
      auto finality = co_await bus_.publish<simplex::QueryFinalizationState>(td::uint32{0});
      require(finality.finalization_retries == 0 && finality.finalizations_stalled == 0,
              "a finalization of the chain failed");
    }
    const auto before = co_await cache();
    emit(PSTRING() << "REPLAY_BEFORE mode=" << name << " " << describe(before)
                   << " overlay_requests=" << overlay_requests.load());
    std::vector<CandidateId> dropped_ancestors;
    for (size_t i = 0; i < chain.size(); ++i) {
      auto entry = co_await cache(chain[i]->id);
      precondition(entry.id_tracked && entry.id_durable,
                   PSTRING() << "slot " << chain[i]->id.slot << " lost its tracking or durability state");
      emit(PSTRING() << "REPLAY_ENTRY slot=" << chain[i]->id.slot << " resident=" << entry.id_payload_resident
                     << " cached=" << entry.id_payload_cached);
      if (!entry.id_payload_resident) {
        precondition(i + 1 < chain.size(), "the newest payload was dropped");
        dropped_ancestors.push_back(chain[i]->id);
      }
    }
    if (low) {
      // The budget is what took them: every ancestor's payload is gone from memory, counted
      // as a drop, and at most one payload is cached.
      precondition(dropped_ancestors.size() == chain.size() - 1, PSTRING() << "expected all " << chain.size() - 1
                                                                           << " ancestor payloads dropped, found "
                                                                           << dropped_ancestors.size());
      precondition(before.dropped_payloads >= dropped_ancestors.size(),
                   "the resolver did not count the ancestors' payloads as dropped");
      precondition(before.cached_payloads <= 1, "more than one payload is cached under the low budget");
    } else {
      precondition(dropped_ancestors.empty() && before.dropped_payloads == 0 && before.cached_payloads == chain.size(),
                   "the default budget dropped a payload of the chain");
    }
    precondition(overlay_requests.load() == 0, "a candidate was requested from the network before the replay");
    precondition(before.db_payload_reads == 0 && db_payload_reads.load() == 0,
                 "a payload was read back from the database before the replay");

    // 3. The production ancestor walk, from the newest candidate back to the zerostate.
    const size_t store_reads_before = db_payload_reads.load();
    const size_t zerostate_before = zerostate_requests.load();
    auto resolve = bus_.publish<simplex::ResolveState>(ParentId{newest->id}).start();
    const bool completed = co_await wait_until([&] { return resolve.await_ready(); });
    // Checked first: a dropped payload fetched from a peer is exactly the failure this test
    // exists for, whatever the resolution did afterwards.
    require(overlay_requests.load() == 0,
            PSTRING() << overlay_requests.load() << " candidate requests reached the network during the replay");
    require(completed, "the state resolution did not complete");
    auto resolved = co_await std::move(resolve).wrap();
    require(resolved.is_ok(), "the state resolution failed: " + (resolved.is_ok() ? "" : resolved.error().to_string()));

    const auto after = co_await cache();
    const size_t store_reads = db_payload_reads.load() - store_reads_before;
    const td::uint64 resolver_reads = after.db_payload_reads - before.db_payload_reads;
    const auto roots = resolved.ok().state->state();
    const auto expected_root = gen_shard_state(static_cast<BlockSeqno>(chain.size()))->get_hash();
    emit(PSTRING() << "REPLAY_AFTER mode=" << name << " " << describe(after)
                   << " overlay_requests=" << overlay_requests.load() << " walk_db_reads=" << resolver_reads
                   << " store_payload_reads=" << store_reads
                   << " zerostate_requests=" << zerostate_requests.load() - zerostate_before);
    emit(PSTRING() << "REPLAY_ROOT mode=" << name
                   << " root=" << (roots.size() == 1 ? roots[0]->get_hash().to_hex() : std::string("<not one root>"))
                   << " expected=" << expected_root.to_hex());

    // The state after the newest candidate, rebuilt from the zerostate.
    require(roots.size() == 1 && roots[0]->get_hash() == expected_root,
            "the replayed state root is not the state after the newest candidate");
    auto block_ids = resolved.ok().state->block_ids();
    require(block_ids.size() == 1 && block_ids[0] == newest->block_id(),
            "the replayed state is not the state of the newest candidate's block");
    require(resolved.ok().gen_utime_exact.has_value() &&
                *resolved.ok().gen_utime_exact == GEN_UTIME_BASE + static_cast<double>(chain.size()),
            "the replayed state has the wrong generation time");
    require(zerostate_requests.load() - zerostate_before == 1, "the walk did not replay from the zerostate");

    // Where the payloads came from: in the low budget exactly the dropped ancestors were read
    // back from the database, and in the reference run nothing was.
    require(resolver_reads == dropped_ancestors.size() && store_reads == dropped_ancestors.size(),
            PSTRING() << "the walk read " << resolver_reads << " payloads (the store saw " << store_reads << "), "
                      << dropped_ancestors.size() << " were dropped");
    if (low) {
      require(resolver_reads > 0, "no dropped payload was read from the database");
    }
    require(after.db_payload_read_misses == before.db_payload_read_misses &&
                after.db_payload_read_invalid == before.db_payload_read_invalid &&
                after.durability_revocations == before.durability_revocations,
            "a database payload read during the replay did not find a valid record");
    require(after.node_charged_bytes <= after.node_limit && after.node_charged_peak <= after.node_limit &&
                after.node_accounting_errors == 0 && after.node_live_over_charge == 0,
            "the payload budget was exceeded or misaccounted");
    finish(0, low ? "REPLAY_LOW_BUDGET_OK" : "REPLAY_DEFAULT_BUDGET_OK");
  }
};

}  // namespace

int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(verbosity_WARNING);
  td::set_default_failure_signal_handler().ensure();
  const std::string name = argc == 2 ? argv[1] : "";
  Mode mode;
  if (name == "low-budget") {
    mode = Mode::LowBudget;
    // Room for one payload of the chain and a quarter more, never two.
    auto charge = one_charge();
    setenv("TOS_SIMPLEX_CANDIDATE_CACHE_BYTES", std::to_string(charge + charge / 4).c_str(), 1);
  } else if (name == "default-budget") {
    mode = Mode::DefaultBudget;
    unsetenv("TOS_SIMPLEX_CANDIDATE_CACHE_BYTES");
  } else {
    std::fprintf(stderr, "usage: %s low-budget|default-budget\n", argv[0]);
    return 2;
  }
  // The overlay stand-in never answers, so one network attempt is enough to see that the node
  // fell back to the network; the default would retry for minutes before the walk fails.
  setenv("TOS_SIMPLEX_CANDIDATE_RESOLVE_MAX_ATTEMPTS", "1", 1);
  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<Driver> driver;
  scheduler.run_in_context([&] {
    driver = td::actor::create_actor<Driver>("replay-driver", mode);
    td::actor::ask(driver, &Driver::run).detach();
  });
  while (scheduler.run(1)) {
  }
  return 1;
}
