/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
// Actor-level tests of the candidate resolver's node-wide payload budget.
//
// Each node runs the production CandidateResolver on its own bus, over a database backend whose
// payload reads, certificate reads and payload writes the driver can hold, fail or corrupt, and
// a private-overlay stand-in that counts every candidate request and answers it only when told
// to. Candidates are real signed candidates with distinct block data. Every mode runs in its own
// child process, so the process-wide allowance starts empty with the limit the mode sets.
//
//   bound              entries stay inside the window while the byte limit drops payloads
//   rehydrate          a dropped payload comes back from the database with no network request
//   pinned-resolve     a resolve suspended in its database read while the slot is finalized
//                      and the allowance is taken: the result is complete, then let go
//   pinned-reply       a peer request holding a cached payload keeps it through pressure
//   pinned-rehydrate   a request that ends first does not let go of a payload another uses
//   reenforce          rehydrations and late stores without new finalizations stay bounded
//   oversized          a payload larger than the whole allowance is never cached
//   persist-cancelled  a store that is cancelled keeps the payload, reported non-durable
//   persist-failed     the same for a store that fails
//   external-ref       a payload dropped while held elsewhere stays charged until released,
//                      and a second copy of it is charged as a second allocation
//   revoke-missing     a missing, an undecodable and a mismatched record revoke durability;
//   revoke-corrupt     the payload comes back from the network, is written again, and is
//   revoke-mismatch    read from the database afterwards
//   stale-read         a read that started before a successful store does not revoke it
//   refill-missing     a payload refilled in memory while a read finds the record missing
//   refill-corrupt     or bad does not stop the revocation, and the record is written again
//   shared-budget      two sessions together stay under the one allowance
//   concurrent         rehydrations in two sessions released at once stay under it
//   session-exit       a session that ends returns its charge once, keeps retired ones charged
//   session-overlap    a new session gets no fresh allowance while the old one holds it
//   stop-cold-reads    the group stops with two reads holding slots in held database reads
//                      and a store waiting on a held write
//   stop-slot-waiter   ... with every slot held and a local and a remote reader queued
//   stop-coalesced     ... with readers waiting on another reader's read and on a resolve
//   stop-bytes-guard   ... while a repair write is held with the read buffer counted
//   stop-notar-write   ... while a notarization certificate write is held
//   external-slice     a payload held only through a clone of its data stays charged
//   cold-same-id       concurrent cold reads of one candidate are one database read
//   cold-many          concurrent cold reads of many candidates are bounded and never wrong

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
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
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
#include "vm/boc.h"

#include "block-auto.h"

using namespace tos;
using namespace tos::validator;
using namespace tos::validator::consensus;

namespace {

constexpr td::uint32 SLOTS_PER_LEADER_WINDOW = 4;
constexpr size_t VALIDATORS = 4;
constexpr double STEP_TIMEOUT = 20.0;
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

void require(bool condition, const std::string& what) {
  if (!condition) {
    finish(3, "BUDGET_FAILED: " + what);
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

// Holds database operations until the driver releases them. A held operation waits on a promise
// the driver completes from its own actor, so it stays pending however the resolver that issued
// it ends, and completes when released even after that resolver is gone, as a real database
// write or read does.
struct Gate {
  std::mutex mutex;
  bool held = false;
  std::vector<td::Promise<td::Unit>> pending;
  std::atomic<int> entered{0};

  void hold() {
    std::scoped_lock lock(mutex);
    held = true;
  }
  // The operation waits on the returned task, or does not wait at all.
  std::optional<td::actor::StartedTask<td::Unit>> enter() {
    std::scoped_lock lock(mutex);
    if (!held) {
      return std::nullopt;
    }
    auto [task, promise] = td::actor::StartedTask<td::Unit>::make_bridge();
    pending.push_back(std::move(promise));
    entered.fetch_add(1);
    return std::move(task);
  }
  int waiting() {
    std::scoped_lock lock(mutex);
    return static_cast<int>(pending.size());
  }
  void release() {
    std::vector<td::Promise<td::Unit>> released;
    {
      std::scoped_lock lock(mutex);
      held = false;
      released = std::exchange(pending, {});
    }
    for (auto& p : released) {
      p.set_value(td::Unit{});
    }
  }
};

// The database records of one node, with the controls the driver uses on them.
struct MemoryStorage {
  std::mutex mutex;
  std::map<td::BufferSlice, td::BufferSlice> map;
  Gate payload_reads_gate;
  Gate notar_reads_gate;
  Gate payload_writes_gate;
  Gate notar_writes_gate;
  std::atomic<int> payload_reads{0};
  // Held operations whose coroutine frame has been created and destroyed. A frame is destroyed
  // on completion or, once its resolver is gone, wherever the completion is routed; equal counts
  // mean no held operation is left anywhere.
  std::atomic<int> held_ops_started{0};
  std::atomic<int> held_ops_finished{0};

  int held_reads() {
    return payload_reads_gate.waiting() + notar_reads_gate.waiting();
  }
  // 0: writes succeed; 1: candidate writes are cancelled; 2: candidate writes fail.
  std::atomic<int> fail_payload_writes{0};

  std::optional<td::BufferSlice> get(td::Slice key) {
    std::scoped_lock lock(mutex);
    auto it = map.find(td::BufferSlice{key});
    if (it == map.end()) {
      return std::nullopt;
    }
    return it->second.clone();
  }

  void put(td::Slice key, td::Slice value) {
    std::scoped_lock lock(mutex);
    map[td::BufferSlice{key}] = td::BufferSlice{value};
  }

  void erase(td::Slice key) {
    std::scoped_lock lock(mutex);
    map.erase(td::BufferSlice{key});
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

  // The value is taken when the read starts: a held read returns what the record was then,
  // as a read that was issued before a later write does.
  // Ends with the held operation's frame, wherever that is destroyed. It owns the storage, so it
  // stays valid after the bus and this database are gone.
  struct HeldOperation {
    std::shared_ptr<MemoryStorage> storage;
    explicit HeldOperation(std::shared_ptr<MemoryStorage> s) : storage(std::move(s)) {
      storage->held_ops_started.fetch_add(1);
    }
    HeldOperation(const HeldOperation&) = delete;
    HeldOperation& operator=(const HeldOperation&) = delete;
    ~HeldOperation() {
      storage->held_ops_finished.fetch_add(1);
    }
  };

  td::actor::Task<std::optional<td::BufferSlice>> get_latest(td::BufferSlice key) const override {
    auto storage = storage_;
    auto value = storage->get(key.as_slice());
    const bool payload = is_key_of(key.as_slice(), tos_api::consensus_simplex_db_key_candidate::ID);
    const bool notar = is_key_of(key.as_slice(), tos_api::consensus_simplex_db_key_candidateResolver_notarCert::ID);
    if (payload) {
      storage->payload_reads.fetch_add(1);
    }
    if (payload || notar) {
      auto wait = (payload ? storage->payload_reads_gate : storage->notar_reads_gate).enter();
      if (wait.has_value()) {
        HeldOperation held{storage};
        auto released = co_await std::move(*wait).wrap();
        if (released.is_error()) {
          co_return released.move_as_error();
        }
      }
    }
    co_return std::move(value);
  }

  td::actor::Task<> set(td::BufferSlice key, td::BufferSlice value) override {
    const bool payload = is_key_of(key.as_slice(), tos_api::consensus_simplex_db_key_candidate::ID);
    const bool notar = is_key_of(key.as_slice(), tos_api::consensus_simplex_db_key_candidateResolver_notarCert::ID);
    auto storage = storage_;
    if (payload || notar) {
      auto wait = (payload ? storage->payload_writes_gate : storage->notar_writes_gate).enter();
      if (wait.has_value()) {
        HeldOperation held{storage};
        auto released = co_await std::move(*wait).wrap();
        if (released.is_error()) {
          co_return released.move_as_error();
        }
      }
    }
    if (payload) {
      int mode = storage->fail_payload_writes.load();
      if (mode == 1) {
        co_return td::Status::Error(ErrorCode::cancelled, "candidate write cancelled by the test");
      }
      if (mode == 2) {
        co_return td::Status::Error(ErrorCode::error, "candidate write failed by the test");
      }
    }
    storage->put(key.as_slice(), value.as_slice());
    co_return td::Unit{};
  }

  td::actor::Task<> close() override {
    co_return td::Unit{};
  }

 private:
  std::shared_ptr<MemoryStorage> storage_;
};

// What the private overlay stand-in sees and may answer with.
struct Network {
  std::mutex mutex;
  std::map<CandidateId, size_t> requests;
  std::map<CandidateId, td::BufferSlice> served;
  std::atomic<bool> serving{false};

  size_t requests_for(const CandidateId& id) {
    std::scoped_lock lock(mutex);
    auto it = requests.find(id);
    return it == requests.end() ? 0 : it->second;
  }
  size_t total_requests() {
    std::scoped_lock lock(mutex);
    size_t total = 0;
    for (const auto& [_, count] : requests) {
      total += count;
    }
    return total;
  }
};

Network network;

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
    if (request.is_error()) {
      co_return ProtocolMessage{create_serialize_tl_object<tos_api::consensus_requestError>()};
    }
    auto id = CandidateId::from_tl(request.ok()->id_);
    std::scoped_lock lock(network.mutex);
    ++network.requests[id];
    auto it = network.served.find(id);
    if (!network.serving.load() || it == network.served.end() || !request.ok()->want_candidate_ ||
        request.ok()->want_notar_) {
      co_return ProtocolMessage{create_serialize_tl_object<tos_api::consensus_requestError>()};
    }
    co_return ProtocolMessage{
        create_serialize_tl_object<tos_api::consensus_simplex_candidateAndCert>(it->second.clone(), td::BufferSlice())};
  }
};

// `padding_bytes` adds about that many bytes of distinct cells to the collated data, for a
// candidate larger than the others.
BlockCandidate make_block(BlockSeqno seqno, const BlockIdExt& prev, size_t padding_bytes = 0) {
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

  auto extra = vm::CellBuilder{}
                   .store_long(0x638eb292, 32)
                   .store_long(0, 32)
                   .store_long((td::uint64)(gen_utime * 1000.0), 64)
                   .finalize_novm();
  std::vector<td::Ref<vm::Cell>> collated_roots{extra};
  if (padding_bytes > 0) {
    // A chain of full cells, each with its own contents so none is deduplicated.
    constexpr size_t CELL_BYTES = 127;
    td::Ref<vm::Cell> padding;
    for (size_t i = 0; i * CELL_BYTES < padding_bytes; ++i) {
      vm::CellBuilder builder;
      builder.store_long(seqno, 32).store_long(static_cast<td::int64>(i), 64);
      for (size_t j = 12; j < CELL_BYTES; ++j) {
        builder.store_long(static_cast<td::int64>((i * 131 + j * 7 + seqno) & 0xff), 8);
      }
      if (padding.not_null()) {
        builder.store_ref(padding);
      }
      padding = builder.finalize_novm();
    }
    collated_roots.push_back(padding);
  }
  td::BufferSlice collated_data = vm::std_boc_serialize_multi(collated_roots, 2).move_as_ok();

  return BlockCandidate(ValidatorId{fill(0x99)},
                        BlockIdExt(BlockId(SHARD, seqno), block_root->get_hash().bits(), td::sha256_bits256(data)),
                        td::sha256_bits256(collated_data), data.clone(), collated_data.clone());
}

std::string serialized(const CandidateRef& candidate) {
  return candidate->serialize().as_slice().str();
}

bool same_contents(const CandidateRef& a, const CandidateRef& b) {
  return a->id == b->id && serialized(a) == serialized(b);
}

using Cache = simplex::QueryCandidatePayloadCache::Result;

std::string describe(const Cache& c) {
  return PSTRING() << "limit=" << c.node_limit << " charged=" << c.node_charged_bytes << " peak=" << c.node_charged_peak
                   << " retired=" << c.node_retired_bytes << "/" << c.node_retired_payloads
                   << " refused=" << c.node_refused_reservations << " errors=" << c.node_accounting_errors
                   << " live_over_charge=" << c.node_live_over_charge << " entries=" << c.entries
                   << " cached=" << c.cached_payloads << "/" << c.cached_bytes << " admitted=" << c.admitted_payloads
                   << "/" << c.admitted_bytes << " dropped=" << c.dropped_payloads
                   << " not_cached=" << c.not_cached_payloads << " pinned=" << c.pinned_bytes
                   << " nondurable=" << c.nondurable_bytes << " nonfinalized=" << c.nonfinalized_bytes
                   << " db_reads=" << c.db_payload_reads << " misses=" << c.db_payload_read_misses
                   << " invalid=" << c.db_payload_read_invalid << " coalesced=" << c.coalesced_reads
                   << " revocations=" << c.durability_revocations << " cold_in_flight=" << c.cold_reads_in_flight
                   << "/peak " << c.cold_reads_in_flight_peak << " cold_waiters=" << c.cold_read_waiters << "/peak "
                   << c.cold_read_waiters_peak << " cold_bytes=" << c.cold_read_bytes_in_flight << "/peak "
                   << c.cold_read_bytes_peak << " cold_refused=" << c.cold_reads_refused;
}

enum class Mode {
  Bound,
  Rehydrate,
  PinnedResolve,
  PinnedReply,
  PinnedRehydrate,
  Reenforce,
  Oversized,
  PersistCancelled,
  PersistFailed,
  ExternalRef,
  RevokeMissing,
  RevokeCorrupt,
  RevokeMismatch,
  StaleRead,
  RefillMissing,
  RefillCorrupt,
  SharedBudget,
  Concurrent,
  SessionExit,
  SessionOverlap,
  StopColdReads,
  StopSlotWaiter,
  StopCoalesced,
  StopBytesGuard,
  StopNotarWrite,
  ExternalSlice,
  ColdSameId,
  ColdMany,
  OversizedKeepsCache,
};

struct Node {
  std::shared_ptr<td::actor::Runtime> runtime;
  simplex::BusHandle bus;
  std::shared_ptr<simplex::Bus> bus_ptr;
  std::shared_ptr<std::atomic<bool>> destroyed;
  std::shared_ptr<MemoryStorage> storage = std::make_shared<MemoryStorage>();
  bool running = false;
};

// The outcome of a request the driver started without waiting for it.
struct Outcome {
  bool done = false;
  // How many times the request completed, and the error code it completed with.
  int completions = 0;
  int code = 0;
  bool ok = false;
  bool matched = false;
  std::string error;
  CandidateRef candidate;
};

class Driver : public td::actor::Actor {
 public:
  explicit Driver(Mode mode) : mode_(mode) {
  }

  td::actor::Task<> run() {
    auto result = co_await run_inner().wrap();
    if (result.is_error()) {
      finish(1, "BUDGET_HARNESS_FAILED: " + result.error().to_string());
    }
    co_return td::Unit{};
  }

 private:
  Mode mode_;
  std::vector<std::shared_ptr<const tos::pq::ValidatorPQKeyStore>> signers_;
  std::vector<PeerValidator> validators_;
  std::vector<Node> nodes_;
  size_t target_ = 1;
  td::uint32 next_source_ = 1;

  td::BufferSlice sign(const Node& node, size_t signer, td::Slice inner) const {
    auto envelope =
        create_serialize_tl_object<tos_api::consensus_dataToSign>(node.bus_ptr->session_id, td::BufferSlice(inner));
    auto signature =
        signers_.at(signer)->sign_consensus(std::string_view(envelope.as_slice().data(), envelope.as_slice().size()));
    CHECK(signature.has_value());
    return td::BufferSlice(signature->signature);
  }

  template <typename VoteT>
  simplex::CertificateRef<VoteT> make_cert(const Node& node, const VoteT& vote) {
    auto inner = serialize_tl_object(vote.to_tl(), true);
    std::vector<simplex::tl::VoteSignatureRef> signatures;
    for (size_t i = 0; i < VALIDATORS; ++i) {
      if (i != target_) {
        signatures.push_back(
            create_tl_object<simplex::tl::voteSignature>(static_cast<td::int32>(i), sign(node, i, inner.as_slice())));
      }
    }
    auto set = create_tl_object<simplex::tl::voteSignatureSet>(std::move(signatures));
    auto cert = simplex::Certificate<VoteT>::from_tl(std::move(*set), vote, *node.bus_ptr);
    CHECK(cert.is_ok());
    return cert.move_as_ok();
  }

  // A chain of candidates in consecutive slots, starting at `first_slot`. `seqno_base` keeps the
  // block data, and with it the ids, of different nodes apart. The last candidate gets
  // `last_padding_bytes` of extra collated data.
  std::vector<CandidateRef> make_chain(const Node& node, size_t count, td::uint32 first_slot = 0,
                                       BlockSeqno seqno_base = 0, size_t last_padding_bytes = 0) {
    std::vector<CandidateRef> result;
    BlockIdExt prev = FIRST_PARENT;
    ParentId parent = std::nullopt;
    for (size_t i = 0; i < count; ++i) {
      auto block =
          make_block(seqno_base + static_cast<BlockSeqno>(i) + 1, prev, i + 1 == count ? last_padding_bytes : 0);
      td::uint32 slot = first_slot + static_cast<td::uint32>(i);
      auto id = CandidateHashData::create_full(block, parent).build_id_with(slot);
      auto leader = node.bus_ptr->collator_schedule->expected_collator_for(slot);
      auto signature = sign(node, leader.value(), serialize_tl_object(id.to_tl(), true).as_slice());
      auto candidate = td::make_ref<Candidate>(id, parent, leader, std::move(block), std::move(signature));
      prev = candidate->block_id();
      parent = candidate->id;
      result.push_back(candidate);
    }
    return result;
  }

  td::uint64 charge(const CandidateRef& candidate) const {
    return simplex::compact_candidate_charge(*candidate);
  }

  td::BufferSlice payload_key(const CandidateId& id) const {
    return create_serialize_tl_object<tos_api::consensus_simplex_db_key_candidate>(id.to_tl());
  }

  bool persisted(const Node& node, const CandidateRef& candidate) const {
    auto value = node.storage->get(payload_key(candidate->id).as_slice());
    return value.has_value() && value->as_slice() == candidate->serialize().as_slice();
  }

  template <typename F>
  td::actor::Task<bool> wait_until(F condition, double timeout = STEP_TIMEOUT) {
    auto deadline = td::Timestamp::in(timeout);
    while (!condition()) {
      if (deadline.is_in_past()) {
        co_return false;
      }
      co_await td::actor::coro_sleep(td::Timestamp::in(0.002));
    }
    co_return true;
  }

  template <typename F>
  td::actor::Task<bool> wait_cache(size_t node, F condition, std::optional<CandidateId> id = std::nullopt,
                                   double timeout = STEP_TIMEOUT) {
    auto deadline = td::Timestamp::in(timeout);
    while (true) {
      auto state = co_await cache(node, id);
      if (condition(state)) {
        co_return true;
      }
      if (deadline.is_in_past()) {
        co_return false;
      }
      co_await td::actor::coro_sleep(td::Timestamp::in(0.002));
    }
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

  // Starts node `index`: the production candidate resolver over the node's database, with the
  // overlay stand-in. Different nodes are different sessions.
  void start_node(size_t index) {
    if (validators_.empty()) {
      make_validators();
    }
    if (nodes_.size() <= index) {
      nodes_.resize(index + 1);
    }
    auto& node = nodes_[index];
    node.runtime = std::make_shared<td::actor::Runtime>();
    node.runtime->register_actor<OverlayStub>("PrivateOverlay");
    simplex::CandidateResolver::register_in(*node.runtime);
    simplex::DefaultCollatorSchedule::provide_for(*node.runtime);

    auto bus = std::make_shared<simplex::Bus>();
    bus->shard = SHARD;
    bus->validator_set = validators_;
    for (const auto& validator : validators_) {
      bus->all_validators.push_back(validator.adnl_id);
    }
    bus->total_weight = static_cast<ValidatorWeight>(validators_.size());
    bus->config = NewConsensusConfig{
        .max_block_size = 1 << 20,
        .max_collated_data_size = 1 << 20,
        .protocol_version = 2,
        .slots_per_leader_window = SLOTS_PER_LEADER_WINDOW,
    };
    bus->session_id = fill(static_cast<unsigned char>(0x42 + index));
    bus->cc_seqno = CC_SEQNO;
    bus->validator_set_hash = 0;
    bus->db = std::make_unique<MemoryDb>(node.storage);
    auto destroyed = std::make_shared<std::atomic<bool>>(false);
    bus->stop_promise = td::PromiseCreator::lambda([destroyed](td::Result<td::Unit>) { destroyed->store(true); });
    node.destroyed = destroyed;
    bus->pq_signer = signers_.at(target_);
    bus->local_id = validators_.at(target_);
    bus->local_adnl_id = validators_.at(target_).adnl_id;
    node.bus_ptr = bus;
    node.bus = node.runtime->start(std::static_pointer_cast<simplex::Bus>(bus), PSTRING() << "budget-node-" << index);
    node.running = true;
  }

  td::actor::Task<> stop_node(size_t index) {
    auto& node = nodes_.at(index);
    auto destroyed = node.destroyed;
    node.bus.publish<StopRequested>();
    node.bus = {};
    node.bus_ptr.reset();
    node.running = false;
    if (!co_await wait_until([&] { return destroyed->load(); })) {
      finish(1, "BUDGET_PRECONDITION_FAILED: the stopped node's bus was never released");
    }
    node.runtime.reset();
    co_return td::Unit{};
  }

  td::actor::Task<Cache> cache(size_t node, std::optional<CandidateId> id = std::nullopt) {
    co_return co_await nodes_.at(node).bus.publish<simplex::QueryCandidatePayloadCache>(id);
  }

  td::actor::Task<size_t> entries(size_t node) {
    co_return co_await nodes_.at(node).bus.publish<simplex::QueryResolverTrackedStateCount>(0);
  }

  td::actor::Task<> store(size_t node, const CandidateRef& candidate) {
    co_await nodes_.at(node).bus.publish<simplex::StoreCandidate>(candidate);
    co_return td::Unit{};
  }

  void notarize(size_t node, const CandidateRef& candidate) {
    auto& n = nodes_.at(node);
    n.bus.publish<simplex::NotarizationObserved>(candidate->id, make_cert(n, simplex::NotarizeVote{candidate->id}));
  }

  td::actor::Task<> finalize(size_t node, const CandidateRef& candidate) {
    auto& n = nodes_.at(node);
    n.bus.publish<simplex::FinalizationObserved>(candidate->id, make_cert(n, simplex::FinalizeVote{candidate->id}));
    // A query is answered after the event before it.
    co_await cache(node);
    co_return td::Unit{};
  }

  // Stores, notarizes and finalizes a chain, all its slots by one finalization of the last.
  td::actor::Task<> store_and_finalize(size_t node, const std::vector<CandidateRef>& chain, bool notarized = true) {
    for (const auto& candidate : chain) {
      co_await store(node, candidate);
      if (notarized) {
        notarize(node, candidate);
      }
    }
    co_await finalize(node, chain.back());
    co_return td::Unit{};
  }

  td::actor::Task<CandidateRef> resolve(size_t node, const CandidateRef& expected) {
    auto result = co_await nodes_.at(node).bus.publish<simplex::ResolveCandidate>(expected->id).wrap();
    if (result.is_error()) {
      finish(3, "BUDGET_FAILED: resolve " + std::to_string(expected->id.slot) + ": " + result.error().to_string());
    }
    require(same_contents(result.ok().candidate, expected),
            PSTRING() << "resolve of slot " << expected->id.slot << " returned different contents");
    co_return result.move_as_ok().candidate;
  }

  adnl::AdnlNodeIdShort next_source() {
    td::Bits256 value = td::Bits256::zero();
    auto n = next_source_++;
    std::memcpy(value.data(), &n, sizeof(n));
    value.data()[31] = 0x5a;
    return adnl::AdnlNodeIdShort{value};
  }

  // A peer's request for the candidate, and the candidate in the reply, if any.
  td::actor::Task<std::optional<CandidateRef>> peer_request(size_t node, const CandidateRef& expected,
                                                            bool want_notar = false) {
    auto& n = nodes_.at(node);
    auto request =
        create_serialize_tl_object<tos_api::consensus_simplex_requestCandidate>(expected->id.to_tl(), true, want_notar);
    auto reply =
        co_await n.bus.publish<IncomingOverlayRequest>(std::nullopt, next_source(), ProtocolMessage{std::move(request)})
            .wrap();
    if (reply.is_error()) {
      co_return reply.move_as_error();
    }
    auto tl = fetch_tl_object<tos_api::consensus_simplex_candidateAndCert>(reply.ok().data, true);
    if (tl.is_error()) {
      co_return tl.move_as_error();
    }
    if (tl.ok()->candidate_.empty()) {
      co_return std::optional<CandidateRef>{};
    }
    auto bus = nodes_.at(node).bus_ptr;
    if (!bus) {
      co_return td::Status::Error("the node stopped");
    }
    auto candidate = Candidate::deserialize(tl.ok()->candidate_, *bus);
    if (candidate.is_error()) {
      co_return candidate.move_as_error();
    }
    co_return std::optional<CandidateRef>{candidate.move_as_ok()};
  }

  td::actor::Task<> peer_request_into(size_t node, CandidateRef expected, std::shared_ptr<Outcome> outcome,
                                      bool want_notar = false) {
    auto result = co_await peer_request(node, expected, want_notar).wrap();
    outcome->done = true;
    ++outcome->completions;
    if (result.is_error()) {
      outcome->code = result.error().code();
      outcome->error = result.error().to_string();
      co_return td::Unit{};
    }
    outcome->ok = true;
    if (result.ok().has_value()) {
      outcome->candidate = *result.ok();
      outcome->matched = same_contents(outcome->candidate, expected);
    }
    co_return td::Unit{};
  }

  td::actor::Task<> resolve_into(size_t node, CandidateRef expected, std::shared_ptr<Outcome> outcome) {
    auto result = co_await nodes_.at(node).bus.publish<simplex::ResolveCandidate>(expected->id).wrap();
    outcome->done = true;
    ++outcome->completions;
    if (result.is_error()) {
      outcome->code = result.error().code();
      outcome->error = result.error().to_string();
      co_return td::Unit{};
    }
    outcome->ok = true;
    outcome->candidate = result.ok().candidate;
    outcome->matched = same_contents(outcome->candidate, expected);
    co_return td::Unit{};
  }

  td::actor::Task<> store_into(size_t node, CandidateRef candidate, std::shared_ptr<Outcome> outcome) {
    auto result = co_await nodes_.at(node).bus.publish<simplex::StoreCandidate>(candidate).wrap();
    outcome->done = true;
    ++outcome->completions;
    if (result.is_error()) {
      outcome->code = result.error().code();
      outcome->error = result.error().to_string();
      co_return td::Unit{};
    }
    outcome->ok = true;
    co_return td::Unit{};
  }

  td::actor::Task<std::optional<CandidateRef>> must_serve(size_t node, const CandidateRef& expected) {
    auto served = co_await peer_request(node, expected).wrap();
    require(served.is_ok(), PSTRING() << "peer request for slot " << expected->id.slot
                                      << " failed: " << (served.is_ok() ? "" : served.error().to_string()));
    require(served.ok().has_value() && same_contents(*served.ok(), expected),
            PSTRING() << "peer request for slot " << expected->id.slot << " was not answered with its contents");
    co_return served.move_as_ok();
  }

  // The bound itself: what is charged node-wide never exceeds the limit, and neither do the
  // cached bytes of all running sessions together with the retired ones.
  td::actor::Task<Cache> check_bound(const std::string& where) {
    td::uint64 aggregate = 0;
    Cache last;
    for (size_t i = 0; i < nodes_.size(); ++i) {
      if (!nodes_[i].running) {
        continue;
      }
      last = co_await cache(i);
      aggregate = simplex::saturating_add(aggregate, last.cached_bytes);
      emit(PSTRING() << "BUDGET_STATE " << where << " node=" << i << " " << describe(last));
    }
    aggregate = simplex::saturating_add(aggregate, last.node_retired_bytes);
    emit(PSTRING() << "BUDGET_BOUND " << where << " aggregate=" << aggregate << " limit=" << last.node_limit);
    require(last.node_charged_bytes <= last.node_limit, where + ": the node-wide charge exceeds the limit");
    require(last.node_charged_peak <= last.node_limit, where + ": the node-wide charge once exceeded the limit");
    require(aggregate <= last.node_limit, where + ": the sessions together hold more than the limit");
    require(last.node_accounting_errors == 0, where + ": the allowance saw an accounting error");
    require(last.node_live_over_charge == 0, where + ": a charge was returned while its allocation was alive");
    for (size_t i = 0; i < nodes_.size(); ++i) {
      if (nodes_[i].running) {
        auto state = co_await cache(i);
        require(state.pins_released_off_actor == 0, where + ": a pin was released off the resolver actor");
      }
    }
    co_return last;
  }

  td::actor::Task<> run_inner() {
    start_node(0);
    switch (mode_) {
      case Mode::Bound:
        co_return co_await run_bound(false);
      case Mode::Rehydrate:
        co_return co_await run_bound(true);
      case Mode::PinnedResolve:
        co_return co_await run_pinned_resolve();
      case Mode::PinnedReply:
        co_return co_await run_pinned_reply();
      case Mode::PinnedRehydrate:
        co_return co_await run_pinned_rehydrate();
      case Mode::Reenforce:
        co_return co_await run_reenforce();
      case Mode::Oversized:
        co_return co_await run_oversized();
      case Mode::PersistCancelled:
        co_return co_await run_persist_failure(1);
      case Mode::PersistFailed:
        co_return co_await run_persist_failure(2);
      case Mode::ExternalRef:
        co_return co_await run_external_ref();
      case Mode::RevokeMissing:
      case Mode::RevokeCorrupt:
      case Mode::RevokeMismatch:
        co_return co_await run_revoke();
      case Mode::RefillMissing:
        co_return co_await run_refill(false);
      case Mode::RefillCorrupt:
        co_return co_await run_refill(true);
      case Mode::StaleRead:
        co_return co_await run_stale_read();
      case Mode::SharedBudget:
        co_return co_await run_shared_budget();
      case Mode::Concurrent:
        co_return co_await run_concurrent();
      case Mode::SessionExit:
        co_return co_await run_session_exit();
      case Mode::SessionOverlap:
        co_return co_await run_session_overlap();
      case Mode::StopColdReads:
        co_return co_await run_stop_cold_reads();
      case Mode::StopSlotWaiter:
        co_return co_await run_stop_slot_waiter();
      case Mode::StopCoalesced:
        co_return co_await run_stop_coalesced();
      case Mode::StopBytesGuard:
        co_return co_await run_stop_bytes_guard();
      case Mode::StopNotarWrite:
        co_return co_await run_stop_notar_write();
      case Mode::ExternalSlice:
        co_return co_await run_external_slice();
      case Mode::ColdSameId:
        co_return co_await run_cold_same_id();
      case Mode::ColdMany:
        co_return co_await run_cold_many();
      case Mode::OversizedKeepsCache:
        co_return co_await run_keeps_cache(false);
    }
    co_return td::Unit{};
  }

  // The limit, read by the resolver from the environment, is checked against the charges of
  // the mode's candidates, so every mode states the room it needs in candidates.
  td::actor::Task<td::uint64> limit_in_charges(const std::vector<CandidateRef>& chain, double charges) {
    auto state = co_await cache(0);
    td::uint64 largest = 0;
    for (const auto& candidate : chain) {
      largest = std::max(largest, charge(candidate));
    }
    td::uint64 smallest = charge(chain.front());
    for (const auto& candidate : chain) {
      smallest = std::min(smallest, charge(candidate));
    }
    emit(PSTRING() << "BUDGET_LIMIT limit=" << state.node_limit << " charge=" << smallest << ".." << largest);
    if (static_cast<double>(state.node_limit) < static_cast<double>(largest) * (charges - 0.5) ||
        static_cast<double>(state.node_limit) >= static_cast<double>(smallest) * (charges + 0.5)) {
      finish(1, PSTRING() << "BUDGET_PRECONDITION_FAILED: the limit does not hold " << charges << " candidates");
    }
    co_return state.node_limit;
  }

  // Eight finalized slots inside the entry window with room for three payloads.
  td::actor::Task<> run_bound(bool rehydrate) {
    auto chain = make_chain(nodes_[0], 8);
    co_await limit_in_charges(chain, 3);
    co_await store_and_finalize(0, chain);
    for (const auto& candidate : chain) {
      require(persisted(nodes_[0], candidate), "a candidate was not persisted");
    }
    auto state = co_await check_bound("bound");
    require(co_await entries(0) == chain.size(), "an entry was erased inside the window");
    require(state.admitted_bytes > 0, "no payload bytes were cached");
    require(state.dropped_payloads > 0, "no payload was dropped");
    require(state.cached_payloads == 3, PSTRING() << "expected 3 cached payloads, found " << state.cached_payloads);
    for (size_t i = 0; i < chain.size(); ++i) {
      auto entry = co_await cache(0, chain[i]->id);
      require(entry.id_tracked && entry.id_durable, "an entry lost its tracking state");
      require(entry.id_payload_resident == (i >= 5), PSTRING() << "slot " << i << " residency is wrong");
    }
    if (!rehydrate) {
      finish(0, "BUDGET_BOUND_OK");
    }

    // The oldest payload was dropped. A notarized entry resolves from the database alone.
    auto before = co_await cache(0);
    auto resolved = co_await resolve(0, chain[0]);
    auto served = co_await must_serve(0, chain[1]);
    auto after = co_await check_bound("rehydrate");
    emit(PSTRING() << "BUDGET_REHYDRATE overlay_requests=" << network.total_requests()
                   << " db_reads=" << after.db_payload_reads - before.db_payload_reads);
    require(network.total_requests() == 0, "a dropped payload was requested from the network");
    require(after.db_payload_reads == before.db_payload_reads + 2, "the payloads were not read from the database");
    require(same_contents(resolved, chain[0]) && served.has_value(), "the rehydrated contents differ");
    auto entry = co_await cache(0, chain[0]->id);
    require(!entry.id_payload_resident, "the older rehydrated payload stayed resident");
    finish(0, "BUDGET_REHYDRATE_OK");
  }

  // A resolve that rehydrates from a held database read while its own slot is finalized and
  // the allowance is taken by newer payloads: the result must be complete when the resolve
  // returns, and the payload let go only after its last pin.
  td::actor::Task<> run_pinned_resolve() {
    auto chain = make_chain(nodes_[0], 3);
    co_await limit_in_charges(chain, 1);
    // Slot 0's record is in the database from an earlier run of this node; the resolver holds
    // only its notarization.
    nodes_[0].storage->put(payload_key(chain[0]->id).as_slice(), chain[0]->serialize().as_slice());
    notarize(0, chain[0]);
    co_await store(0, chain[1]);
    co_await store(0, chain[2]);
    auto entry = co_await cache(0, chain[0]->id);
    require(entry.id_tracked && !entry.id_payload_resident, "slot 0 was resident before the test");

    nodes_[0].storage->payload_reads_gate.hold();
    auto outcome = std::make_shared<Outcome>();
    resolve_into(0, chain[0], outcome).start().detach();
    if (!co_await wait_until([&] { return nodes_[0].storage->held_reads() == 1; })) {
      finish(1, "BUDGET_PRECONDITION_FAILED: the resolve never reached its database read");
    }
    // While the resolve is suspended, its slot and the newer ones are finalized, and the newest
    // payload takes the whole allowance.
    co_await finalize(0, chain[2]);
    auto during = co_await cache(0, chain[2]->id);
    require(during.id_payload_cached, "the newer payload was not cached");
    nodes_[0].storage->payload_reads_gate.release();
    if (!co_await wait_until([&] { return outcome->done; })) {
      finish(1, "BUDGET_PRECONDITION_FAILED: the resolve never returned");
    }
    emit(PSTRING() << "BUDGET_PINNED_RESOLVE ok=" << outcome->ok << " matched=" << outcome->matched
                   << " error=" << outcome->error);
    require(outcome->ok && outcome->matched, "the resolve returned without the exact candidate");
    co_await check_bound("pinned-resolve");
    if (!co_await wait_cache(0, [](const Cache& c) { return c.pinned_bytes == 0; })) {
      finish(3, "BUDGET_FAILED: the rehydrated payload was never let go");
    }
    entry = co_await cache(0, chain[0]->id);
    require(!entry.id_payload_resident, "the rehydrated payload stayed resident after its last pin");
    require(network.total_requests() == 0, "the resolve asked the network");
    finish(0, "BUDGET_PINNED_RESOLVE_OK");
  }

  // Two peer requests for one dropped candidate: the first rehydrates it and then waits in its
  // certificate read; the second is answered from the rehydrated payload and ends first. Its
  // end must not let go of the payload the first one is still serving, although the allowance
  // has no room for it.
  td::actor::Task<> run_pinned_rehydrate() {
    auto chain = make_chain(nodes_[0], 2);
    co_await limit_in_charges(chain, 1);
    const auto& t = chain[0];
    co_await store_and_finalize(0, chain, /*notarized=*/false);
    auto entry = co_await cache(0, t->id);
    require(!entry.id_payload_resident, "slot 0 was resident before the test");

    nodes_[0].storage->notar_reads_gate.hold();
    auto first = std::make_shared<Outcome>();
    peer_request_into(0, t, first, /*want_notar=*/true).start().detach();
    if (!co_await wait_until([&] { return nodes_[0].storage->held_reads() == 1; })) {
      finish(1, "BUDGET_PRECONDITION_FAILED: the first request never reached its certificate read");
    }
    co_await must_serve(0, t);
    auto during = co_await cache(0, t->id);
    nodes_[0].storage->notar_reads_gate.release();
    if (!co_await wait_until([&] { return first->done; })) {
      finish(1, "BUDGET_PRECONDITION_FAILED: the first request never returned");
    }
    emit(PSTRING() << "BUDGET_PINNED_REHYDRATE during resident=" << during.id_payload_resident
                   << " first ok=" << first->ok << " matched=" << first->matched << " error=" << first->error);
    require(during.id_payload_resident, "the rehydrated payload was let go while a request still used it");
    require(first->ok && first->matched, "the first request lost the candidate it was serving");
    co_await check_bound("pinned-rehydrate");
    entry = co_await cache(0, t->id);
    require(!entry.id_payload_resident, "the rehydrated payload stayed resident after its last pin");
    finish(0, "BUDGET_PINNED_REHYDRATE_OK");
  }

  // A peer request holds a cached payload while its certificate read is held; a newer payload
  // that needs the room must not take it from under the request.
  td::actor::Task<> run_pinned_reply() {
    auto chain = make_chain(nodes_[0], 3);
    co_await limit_in_charges(chain, 1);
    co_await store(0, chain[0]);
    co_await store(0, chain[1]);
    co_await finalize(0, chain[1]);
    auto entry = co_await cache(0, chain[1]->id);
    require(entry.id_payload_cached, "slot 1 was not cached");

    nodes_[0].storage->notar_reads_gate.hold();
    auto outcome = std::make_shared<Outcome>();
    peer_request_into(0, chain[1], outcome, /*want_notar=*/true).start().detach();
    if (!co_await wait_until([&] { return nodes_[0].storage->held_reads() == 1; })) {
      finish(1, "BUDGET_PRECONDITION_FAILED: the request never reached its certificate read");
    }
    co_await store(0, chain[2]);
    co_await finalize(0, chain[2]);
    auto during = co_await cache(0, chain[1]->id);
    emit(PSTRING() << "BUDGET_PINNED_REPLY during resident=" << during.id_payload_resident
                   << " cached=" << during.id_payload_cached);
    nodes_[0].storage->notar_reads_gate.release();
    if (!co_await wait_until([&] { return outcome->done; })) {
      finish(1, "BUDGET_PRECONDITION_FAILED: the request never returned");
    }
    emit(PSTRING() << "BUDGET_PINNED_REPLY ok=" << outcome->ok << " matched=" << outcome->matched
                   << " error=" << outcome->error);
    require(during.id_payload_resident, "a payload in use was dropped");
    require(outcome->ok && outcome->matched, "the reply lost the candidate it was serving");
    co_await check_bound("pinned-reply");
    finish(0, "BUDGET_PINNED_REPLY_OK");
  }

  // With no new finalization, rehydrations and late stores add payload bytes only through the
  // last pin, which enforces the limit again.
  td::actor::Task<> run_reenforce() {
    auto chain = make_chain(nodes_[0], 8);
    co_await limit_in_charges(chain, 2);
    std::vector<CandidateRef> finalized(chain.begin(), chain.begin() + 6);
    co_await store_and_finalize(0, finalized);
    co_await check_bound("reenforce-initial");
    auto before = co_await cache(0);
    for (size_t i = 0; i < 4; ++i) {
      co_await must_serve(0, chain[i]);
      // Built before the await: a PSTRING temporary uses a thread-local stack allocator and must
      // not live across a suspension.
      std::string where = PSTRING() << "reenforce-rehydrate-" << i;
      co_await check_bound(where);
    }
    auto after = co_await cache(0);
    require(after.db_payload_reads == before.db_payload_reads + 4, "the rehydrations did not read the database");
    require(after.cached_payloads == 2, "the rehydrations changed what is cached");
    require(after.pinned_bytes == 0 && after.nondurable_bytes == 0 && after.nonfinalized_bytes == 0,
            "a rehydrated payload stayed outside the cache");

    // A late store for a slot already finalized and dropped adds its payload again.
    co_await store(0, chain[3]);
    co_await check_bound("reenforce-late-store-old");
    auto late = co_await cache(0, chain[3]->id);
    require(!late.id_payload_resident, "a late store of an old slot stayed resident");
    // A store for a slot not yet finalized is held outside the cache until it is finalized.
    co_await store(0, chain[6]);
    auto pending = co_await cache(0);
    require(pending.nonfinalized_bytes > 0, "a non-finalized payload was not reported");
    co_await finalize(0, chain[6]);
    auto final_state = co_await check_bound("reenforce-late-store-new");
    require(final_state.nonfinalized_bytes == 0, "the finalized payload was not moved to the cache");
    auto newest = co_await cache(0, chain[6]->id);
    require(newest.id_payload_cached, "the newest payload was not cached");
    finish(0, "BUDGET_REENFORCE_OK");
  }

  td::actor::Task<> run_oversized() {
    auto chain = make_chain(nodes_[0], 1);
    auto state = co_await cache(0);
    require(state.node_limit < charge(chain[0]), "the limit is not below one payload");
    co_await store_and_finalize(0, chain);
    auto after = co_await check_bound("oversized");
    require(after.admitted_payloads == 0 && after.cached_bytes == 0, "an oversized payload was cached");
    require(after.not_cached_payloads >= 1, "the oversized payload was not refused");
    auto entry = co_await cache(0, chain[0]->id);
    require(entry.id_tracked && !entry.id_payload_resident, "the oversized payload stayed resident");
    co_await must_serve(0, chain[0]);
    co_await check_bound("oversized-served");
    finish(0, "BUDGET_OVERSIZED_OK");
  }

  // Node 0's older payloads are cached and could be dropped to make room: durable, finalized,
  // unused, inside the retention window, and nothing dropped yet.
  td::actor::Task<Cache> require_droppable(std::vector<CandidateRef> older, std::string where) {
    auto state = co_await check_bound(where);
    require(state.cached_payloads == older.size(), where + ": the older payloads are not all cached");
    require(state.dropped_payloads == 0, where + ": a payload was dropped before the test");
    require(state.pinned_bytes == 0 && state.cold_reads_in_flight == 0, where + ": a payload is in use");
    for (const auto& candidate : older) {
      auto entry = co_await cache(0, candidate->id);
      require(entry.id_tracked && entry.id_payload_cached && entry.id_durable && entry.id_active_operations == 0,
              where + ": an older payload is not cached, durable and unused");
      require(persisted(nodes_[0], candidate), where + ": an older payload is not in the database");
    }
    co_return state;
  }

  // The older payloads are still cached and nothing was dropped since `before`.
  td::actor::Task<Cache> require_kept(std::vector<CandidateRef> older, Cache before, std::string where) {
    auto state = co_await check_bound(where);
    emit(PSTRING() << "BUDGET_KEPT " << where << " " << describe(state));
    require(state.cached_payloads == older.size(), where + ": an older cached payload was dropped");
    require(state.dropped_payloads == before.dropped_payloads, where + ": the drop count changed");
    for (const auto& candidate : older) {
      auto entry = co_await cache(0, candidate->id);
      require(entry.id_tracked && entry.id_payload_cached, where + ": an older payload is no longer cached");
    }
    co_return state;
  }

  // A finalized payload that cannot be cached however many of the session's older payloads
  // are dropped must leave them cached. Without `competing` the payload is larger than the
  // whole allowance. With it, another session holds part of the allowance throughout, and
  // the payload fits under the limit but not in the free room together with everything the
  // session could drop.
  td::actor::Task<> run_keeps_cache(bool competing) {
    std::string mode = competing ? "unreachable-room-keeps-cache" : "oversized-keeps-cache";
    auto small = charge(make_chain(nodes_[0], 1)[0]);
    auto chain = make_chain(nodes_[0], 3, 0, 0, 2 * small);
    std::vector<CandidateRef> older(chain.begin(), chain.begin() + 2);
    const auto& large = chain[2];
    std::vector<CandidateRef> other;
    td::uint64 limit = 0;
    if (competing) {
      start_node(1);
      other = make_chain(nodes_[1], 2, 0, 100);
      std::vector<CandidateRef> smalls = older;
      smalls.insert(smalls.end(), other.begin(), other.end());
      limit = co_await limit_in_charges(smalls, 4);
      co_await store_and_finalize(1, other);
      auto held = co_await cache(1);
      require(held.cached_payloads == other.size(), "the other session did not cache its payloads");
    } else {
      limit = co_await limit_in_charges(older, 2);
    }
    co_await store_and_finalize(0, older);
    auto before = co_await require_droppable(older, mode + "-setup");
    // The room dropping every older payload of this session could reach at best.
    auto reachable = simplex::saturating_add(simplex::saturating_sub(before.node_limit, before.node_charged_bytes),
                                             before.cached_bytes);
    emit(PSTRING() << "BUDGET_KEEPS_CACHE " << mode << " limit=" << limit << " small=" << small
                   << " large=" << charge(large) << " reachable=" << reachable);
    require(before.node_retired_payloads == 0, "a retired payload holds room before the test");
    if (competing) {
      auto held = co_await cache(1);
      require(before.node_charged_bytes == before.cached_bytes + held.cached_bytes,
              "the charge is not this session's and the other session's cached payloads");
      require(charge(large) <= limit, "the payload does not fit under the limit");
      require(reachable < charge(large), "dropping the older payloads would make room");
    } else {
      require(charge(large) > limit, "the payload is not larger than the allowance");
    }

    co_await store(0, large);
    notarize(0, large);
    co_await finalize(0, large);
    require(persisted(nodes_[0], large), "the large payload was not persisted");
    auto entry = co_await cache(0, large->id);
    require(entry.id_tracked && entry.id_durable && !entry.id_payload_resident,
            "the large payload is not tracked as durable and let go");
    auto finalized = co_await require_kept(older, before, mode + "-finalized");
    require(finalized.not_cached_payloads == before.not_cached_payloads + 1, "the large payload was not refused");
    require(finalized.admitted_payloads == before.admitted_payloads, "the large payload was cached");

    // The large payload is served from the database; that read caches nothing and drops nothing.
    co_await must_serve(0, large);
    auto served = co_await require_kept(older, before, mode + "-served");
    require(served.db_payload_reads == finalized.db_payload_reads + 1,
            "the large payload was not read from the database");
    entry = co_await cache(0, large->id);
    require(!entry.id_payload_resident, "the large payload stayed resident after it was served");

    // The older payloads are served from the cache.
    for (const auto& candidate : older) {
      co_await must_serve(0, candidate);
    }
    auto reread = co_await require_kept(older, before, mode + "-reread");
    require(reread.db_payload_reads == served.db_payload_reads, "an older payload was read from the database");
    require(network.total_requests() == 0, "a payload was requested from the network");
    if (competing) {
      auto held = co_await cache(1);
      require(held.cached_payloads == other.size() && held.dropped_payloads == 0,
              "the other session's payloads were dropped");
    }
    finish(0, competing ? "BUDGET_UNREACHABLE_ROOM_KEEPS_CACHE_OK" : "BUDGET_OVERSIZED_KEEPS_CACHE_OK");
  }

  td::actor::Task<> run_persist_failure(int failure) {
    auto chain = make_chain(nodes_[0], 1);
    nodes_[0].storage->fail_payload_writes = failure;
    auto stored = co_await nodes_[0].bus.publish<simplex::StoreCandidate>(chain[0]).wrap();
    require(stored.is_error(), "a failed write was reported as stored");
    notarize(0, chain[0]);
    co_await finalize(0, chain[0]);
    auto state = co_await check_bound("persist-failure");
    auto entry = co_await cache(0, chain[0]->id);
    emit(PSTRING() << "BUDGET_PERSIST_FAILURE error=" << stored.error() << " " << describe(state));
    require(entry.id_payload_resident && !entry.id_payload_cached && !entry.id_durable,
            "a payload that is not durable must stay resident and uncached");
    require(state.nondurable_bytes > 0 && state.cached_bytes == 0, "the non-durable payload was not reported");

    // Once a write succeeds, the payload becomes durable and is cached.
    nodes_[0].storage->fail_payload_writes = 0;
    co_await resolve(0, chain[0]);
    auto repaired = co_await check_bound("persist-repaired");
    entry = co_await cache(0, chain[0]->id);
    require(persisted(nodes_[0], chain[0]) && entry.id_durable && entry.id_payload_cached,
            "the repaired payload was not cached");
    require(repaired.nondurable_bytes == 0, "the repaired payload is still reported non-durable");
    finish(0, "BUDGET_PERSIST_FAILURE_OK");
  }

  // A payload is held outside the resolver, dropped, and then copied into the cache once more
  // while the first copy is still alive.
  td::actor::Task<> run_external_ref() {
    auto chain = make_chain(nodes_[0], 3);
    co_await limit_in_charges(chain, 2);
    const auto& a = chain[0];
    const auto& b = chain[1];
    const auto& c = chain[2];
    co_await store(0, a);
    co_await store(0, b);
    co_await store(0, c);
    notarize(0, b);
    notarize(0, c);
    co_await finalize(0, b);
    auto state = co_await check_bound("external-initial");
    require(state.cached_payloads == 2, "slots 0 and 1 were not cached");

    // The resolver hands out its cached copy of B.
    auto external = co_await resolve(0, b);
    require(external->get_refcnt() >= 2, "the cached copy should be held by the resolver and the test");

    // A peer request pins A (no certificate in memory, its read held), so the room C needs
    // can only come from B, which the test still holds.
    nodes_[0].storage->notar_reads_gate.hold();
    auto pin = std::make_shared<Outcome>();
    peer_request_into(0, a, pin, /*want_notar=*/true).start().detach();
    if (!co_await wait_until([&] { return nodes_[0].storage->held_reads() == 1; })) {
      finish(1, "BUDGET_PRECONDITION_FAILED: the request on A never reached its certificate read");
    }
    co_await finalize(0, c);
    auto dropped = co_await cache(0, b->id);
    emit(PSTRING() << "BUDGET_EXTERNAL after drop " << describe(dropped)
                   << " b_resident=" << dropped.id_payload_resident << " external_refcnt=" << external->get_refcnt());
    require(!dropped.id_payload_resident, "the resolver kept the dropped payload");
    require(same_contents(external, b), "the external reference no longer holds the contents");
    require(dropped.node_retired_payloads == 1 && dropped.node_retired_bytes == charge(b),
            "the dropped payload held elsewhere is not charged as retired");
    nodes_[0].storage->notar_reads_gate.release();
    if (!co_await wait_until([&] { return pin->done; })) {
      finish(1, "BUDGET_PRECONDITION_FAILED: the request on A never returned");
    }
    require(pin->ok && pin->matched, "the pinned request lost A");

    // A second copy of B while the first is alive: two allocations, two charges.
    co_await must_serve(0, b);
    auto twice = co_await check_bound("external-second-copy");
    auto entry = co_await cache(0, b->id);
    require(entry.id_payload_cached, "the second copy of B was not cached");
    require(twice.node_retired_payloads == 1 && twice.node_charged_bytes == 2 * charge(b),
            "the two copies of B are not charged as two allocations");

    // Sweeps before the last holder lets go keep the charge.
    co_await must_serve(0, a);
    auto still = co_await check_bound("external-held");
    require(still.node_retired_payloads == 1, "the retired copy was released while still held");

    external = {};
    co_await must_serve(0, a);
    auto released = co_await check_bound("external-released");
    require(released.node_retired_payloads == 0 && released.node_retired_bytes == 0,
            "the retired copy stayed charged after its last holder let go");
    finish(0, "BUDGET_EXTERNAL_OK");
  }

  td::actor::Task<> run_revoke() {
    auto chain = make_chain(nodes_[0], 2);
    co_await limit_in_charges(chain, 1);
    const auto& a = chain[0];
    co_await store_and_finalize(0, chain);
    auto entry = co_await cache(0, a->id);
    require(entry.id_durable && !entry.id_payload_resident, "A was not dropped as durable");

    auto key = payload_key(a->id);
    const char* injected = "missing";
    if (mode_ == Mode::RevokeMissing) {
      nodes_[0].storage->erase(key.as_slice());
    } else if (mode_ == Mode::RevokeCorrupt) {
      injected = "corrupt";
      nodes_[0].storage->put(key.as_slice(), td::Slice("not a candidate record"));
    } else {
      injected = "mismatch";
      nodes_[0].storage->put(key.as_slice(), chain[1]->serialize().as_slice());
    }
    {
      std::scoped_lock lock(network.mutex);
      network.served[a->id] = a->serialize();
    }
    network.serving = true;

    co_await resolve(0, a);
    auto repaired = co_await check_bound(std::string("revoke-") + injected);
    entry = co_await cache(0, a->id);
    emit(PSTRING() << "BUDGET_REVOKE " << injected << " overlay_requests=" << network.requests_for(a->id)
                   << " revocations=" << repaired.durability_revocations << " persisted=" << persisted(nodes_[0], a));
    require(repaired.durability_revocations == 1, "the bad record did not revoke durability");
    require(network.requests_for(a->id) >= 1, "the candidate was not fetched from the network");
    require(persisted(nodes_[0], a), "the candidate was not written again");
    require(entry.id_durable && !entry.id_payload_resident, "the repaired payload was not dropped as durable");

    // The repaired record is what the database serves now, without the network.
    network.serving = false;
    auto requests = network.requests_for(a->id);
    co_await resolve(0, a);
    require(network.requests_for(a->id) == requests, "the repaired record was not read from the database");
    co_await check_bound("revoke-reread");
    finish(0, "BUDGET_REVOKE_OK");
  }

  // A read that found no record is still running when a store writes it; the read's answer is
  // older than the store and must not revoke it.
  td::actor::Task<> run_stale_read() {
    auto chain = make_chain(nodes_[0], 2);
    co_await limit_in_charges(chain, 1);
    const auto& a = chain[0];
    notarize(0, a);
    nodes_[0].storage->payload_reads_gate.hold();
    auto outcome = std::make_shared<Outcome>();
    resolve_into(0, a, outcome).start().detach();
    if (!co_await wait_until([&] { return nodes_[0].storage->held_reads() == 1; })) {
      finish(1, "BUDGET_PRECONDITION_FAILED: the resolve never reached its database read");
    }
    co_await store(0, a);
    require(persisted(nodes_[0], a), "the store did not write the record");
    nodes_[0].storage->payload_reads_gate.release();
    if (!co_await wait_until([&] { return outcome->done; })) {
      finish(1, "BUDGET_PRECONDITION_FAILED: the resolve never returned");
    }
    require(outcome->ok && outcome->matched, "the resolve did not return A");
    co_await finalize(0, a);
    // The store resumed the resolve before the held read returned, so the resolve task can
    // still be in that read, pinning A, when its slot is finalized; A is then cached when the
    // task's pin is released. Wait for exactly that: the read done and no pin left on A.
    auto early = co_await cache(0, a->id);
    emit(PSTRING() << "BUDGET_STALE_READ_EARLY cold_in_flight=" << early.cold_reads_in_flight
                   << " pins=" << early.id_active_operations << " cached=" << early.id_payload_cached);
    if (!co_await wait_cache(
            0, [](const Cache& c) { return c.cold_reads_in_flight == 0 && c.id_active_operations == 0; }, a->id)) {
      finish(1, "BUDGET_PRECONDITION_FAILED: the stale read never completed or its pin was never released");
    }
    auto state = co_await check_bound("stale-read");
    auto entry = co_await cache(0, a->id);
    emit(PSTRING() << "BUDGET_STALE_READ revocations=" << state.durability_revocations
                   << " durable=" << entry.id_durable << " cached=" << entry.id_payload_cached
                   << " pins=" << entry.id_active_operations);
    require(state.durability_revocations == 0, "a stale read revoked a newer store");
    require(entry.id_durable && entry.id_payload_cached,
            "A is not cached as durable after the read completed and its last pin was released");

    // A is dropped for B and comes back from the database alone.
    co_await store(0, chain[1]);
    co_await finalize(0, chain[1]);
    entry = co_await cache(0, a->id);
    require(!entry.id_payload_resident, "A was not dropped");
    co_await resolve(0, a);
    require(network.total_requests() == 0, "A was requested from the network");
    finish(0, "BUDGET_STALE_READ_OK");
  }

  // Two sessions, each under the limit alone, more than it together.
  td::actor::Task<> run_shared_budget() {
    start_node(1);
    auto first = make_chain(nodes_[0], 2);
    auto second = make_chain(nodes_[1], 2, 0, 100);
    std::vector<CandidateRef> all = first;
    all.insert(all.end(), second.begin(), second.end());
    co_await limit_in_charges(all, 3);
    co_await store_and_finalize(0, first);
    co_await store_and_finalize(1, second);
    auto state = co_await check_bound("shared-budget");
    auto other = co_await cache(0);
    require(state.not_cached_payloads + other.not_cached_payloads + state.dropped_payloads + other.dropped_payloads > 0,
            "nothing was refused or dropped");
    for (const auto& candidate : first) {
      co_await must_serve(0, candidate);
    }
    for (const auto& candidate : second) {
      co_await must_serve(1, candidate);
    }
    co_await check_bound("shared-budget-served");
    finish(0, "BUDGET_SHARED_OK");
  }

  // Rehydrations in both sessions, held at the database and released at once, so their last
  // pins end interleaved; then nothing more happens and the state must stay put.
  td::actor::Task<> run_concurrent() {
    start_node(1);
    auto first = make_chain(nodes_[0], 4);
    auto second = make_chain(nodes_[1], 4, 0, 100);
    std::vector<CandidateRef> all = first;
    all.insert(all.end(), second.begin(), second.end());
    co_await limit_in_charges(all, 3);
    co_await store_and_finalize(0, first);
    co_await store_and_finalize(1, second);
    co_await check_bound("concurrent-initial");

    std::vector<std::pair<size_t, CandidateRef>> cold;
    for (size_t node = 0; node < 2; ++node) {
      for (const auto& candidate : node == 0 ? first : second) {
        auto entry = co_await cache(node, candidate->id);
        if (!entry.id_payload_resident) {
          cold.emplace_back(node, candidate);
        }
      }
    }
    require(cold.size() >= 4, "too few dropped payloads to rehydrate");
    nodes_[0].storage->payload_reads_gate.hold();
    nodes_[1].storage->payload_reads_gate.hold();
    std::vector<std::shared_ptr<Outcome>> outcomes;
    for (auto& [node, candidate] : cold) {
      outcomes.push_back(std::make_shared<Outcome>());
      peer_request_into(node, candidate, outcomes.back()).start().detach();
    }
    const int expected_held = static_cast<int>(cold.size());
    if (!co_await wait_until(
            [&] { return nodes_[0].storage->held_reads() + nodes_[1].storage->held_reads() == expected_held; })) {
      finish(1, "BUDGET_PRECONDITION_FAILED: the rehydrations did not all reach their reads");
    }
    nodes_[0].storage->payload_reads_gate.release();
    nodes_[1].storage->payload_reads_gate.release();
    if (!co_await wait_until(
            [&] { return std::all_of(outcomes.begin(), outcomes.end(), [](const auto& o) { return o->done; }); })) {
      finish(1, "BUDGET_PRECONDITION_FAILED: a rehydration never returned");
    }
    for (const auto& outcome : outcomes) {
      require(outcome->ok && outcome->matched, "a rehydration returned the wrong contents: " + outcome->error);
    }
    auto settled = co_await check_bound("concurrent-released");
    co_await settle(0.3);
    auto later = co_await check_bound("concurrent-later");
    require(later.node_charged_bytes == settled.node_charged_bytes, "the charge kept moving with nothing happening");
    for (size_t node = 0; node < 2; ++node) {
      auto state = co_await cache(node);
      require(state.pinned_bytes == 0 && state.cold_reads_in_flight == 0, "a rehydrated payload is still held");
    }
    finish(0, "BUDGET_CONCURRENT_OK");
  }

  // A session ends with a cached payload held by the test and a cold read in flight.
  td::actor::Task<> run_session_exit() {
    start_node(1);
    auto first = make_chain(nodes_[0], 4);
    auto second = make_chain(nodes_[1], 3, 0, 100);
    std::vector<CandidateRef> all = first;
    all.insert(all.end(), second.begin(), second.end());
    co_await limit_in_charges(all, 3);
    co_await store_and_finalize(0, first);
    auto external = co_await resolve(0, first.back());
    co_await check_bound("exit-before");
    auto before = co_await cache(0);
    require(before.cached_payloads == 3, "the first session did not cache");
    auto oldest = co_await cache(0, first.front()->id);
    require(!oldest.id_payload_resident, "the oldest payload of the first session was not dropped");

    nodes_[0].storage->payload_reads_gate.hold();
    auto cold = std::make_shared<Outcome>();
    peer_request_into(0, first.front(), cold).start().detach();
    if (!co_await wait_until([&] { return nodes_[0].storage->held_reads() == 1; })) {
      finish(1, "BUDGET_PRECONDITION_FAILED: the cold read never started");
    }
    auto destroyed = nodes_[0].destroyed;
    nodes_[0].bus.publish<StopRequested>();
    nodes_[0].bus = {};
    nodes_[0].bus_ptr.reset();
    nodes_[0].running = false;
    co_await settle(0.2);
    nodes_[0].storage->payload_reads_gate.release();
    if (!co_await wait_until([&] { return destroyed->load(); })) {
      finish(3, "BUDGET_FAILED: the stopped session was never released");
    }
    nodes_[0].runtime.reset();
    co_await settle(0.1);
    emit(PSTRING() << "BUDGET_EXIT cold_done=" << cold->done << " ok=" << cold->ok << " error=" << cold->error);

    // Only the copy the test holds is still charged, once.
    auto after = co_await check_bound("exit-after");
    require(after.node_retired_payloads == 1 && after.node_charged_bytes == charge(first.back()),
            "the ended session left a charge other than the held copy");
    co_await store_and_finalize(1, second);
    co_await check_bound("exit-second-session");
    external = {};
    co_await must_serve(1, second.front());
    auto released = co_await check_bound("exit-released");
    require(released.node_retired_payloads == 0, "the held copy stayed charged after it was released");
    require(released.node_accounting_errors == 0, "a charge was returned twice");
    finish(0, "BUDGET_EXIT_OK");
  }

  // A new session starts while the old one holds the whole allowance.
  td::actor::Task<> run_session_overlap() {
    auto first = make_chain(nodes_[0], 3);
    co_await limit_in_charges(first, 3);
    co_await store_and_finalize(0, first);
    auto full = co_await check_bound("overlap-old-full");
    require(full.cached_payloads == 3, "the old session did not fill the allowance");

    start_node(1);
    auto second = make_chain(nodes_[1], 2, 0, 100);
    co_await store_and_finalize(1, second);
    auto fresh = co_await cache(1);
    co_await check_bound("overlap-both");
    require(fresh.cached_payloads == 0 && fresh.not_cached_payloads == 2,
            "the new session was given a fresh allowance");
    for (const auto& candidate : second) {
      co_await must_serve(1, candidate);
    }

    co_await stop_node(0);
    auto later = make_chain(nodes_[1], 1, 2, 200);
    co_await store_and_finalize(1, later);
    auto after = co_await check_bound("overlap-old-gone");
    require(after.cached_payloads >= 1, "the new session could not cache after the old one ended");
    require(after.node_accounting_errors == 0, "a charge was returned twice");
    finish(0, "BUDGET_OVERLAP_OK");
  }

  // ---- Stopping a group while its resolver has database work pending ----

  // Guards that must find their group stopped and skip their cleanup, by kind.
  struct StopExpectation {
    size_t pins = 0;
    size_t slots = 0;
    size_t loaders = 0;
    size_t remote_waits = 0;
    size_t bytes = 0;
  };

  static size_t kind_index(simplex::ResolverStopCleanup kind) {
    return static_cast<size_t>(kind);
  }

  td::actor::Task<size_t> pins_on(size_t node, const std::vector<CandidateRef>& candidates) {
    size_t pins = 0;
    for (const auto& candidate : candidates) {
      auto entry = co_await cache(node, candidate->id);
      pins += entry.id_active_operations;
    }
    co_return pins;
  }

  // Stops the node while held database operations are pending, and waits for the resolver's
  // tear-down while they still are. Then releases them from here, as a database completes its
  // work whether or not the resolver that asked is still there, and waits until every held
  // operation's frame, every request and the bus itself are gone. Every guard must have found
  // its group stopped and skipped its cleanup, exactly as many of each kind as were live at the
  // stop, none may have reached actor state, and every waiter must have completed once, with
  // `cancelled`.
  td::actor::Task<> stop_with_pending(size_t index, StopExpectation expected,
                                      std::vector<std::shared_ptr<Outcome>> outcomes, const std::string& where) {
    auto& node = nodes_.at(index);
    auto storage = node.storage;
    auto destroyed = node.destroyed;
    const int pending = storage->held_ops_started.load() - storage->held_ops_finished.load();
    if (pending <= 0) {
      finish(1, "BUDGET_PRECONDITION_FAILED: " + where + ": no database operation is pending at the stop");
    }
    const auto before = simplex::candidate_resolver_stop_counts_for_test();
    node.bus.publish<StopRequested>();
    node.bus = {};
    node.bus_ptr.reset();
    node.running = false;
    if (!co_await wait_until(
            [&] { return simplex::candidate_resolver_stop_counts_for_test().teardowns == before.teardowns + 1; })) {
      finish(1, "BUDGET_PRECONDITION_FAILED: " + where + ": the resolver was never torn down");
    }
    const int pending_after_teardown = storage->held_ops_started.load() - storage->held_ops_finished.load();
    emit(PSTRING() << "BUDGET_STOP " << where << " torn_down pending_db_ops=" << pending_after_teardown);
    if (pending_after_teardown != pending) {
      finish(1, "BUDGET_PRECONDITION_FAILED: " + where + ": a held operation ended before the tear-down");
    }

    storage->payload_reads_gate.release();
    storage->notar_reads_gate.release();
    storage->payload_writes_gate.release();
    storage->notar_writes_gate.release();

    const std::array<size_t, 5> want{expected.pins, expected.remote_waits, expected.slots, expected.loaders,
                                     expected.bytes};
    auto skipped_delta = [&](size_t i) {
      return simplex::candidate_resolver_stop_counts_for_test().skipped[i] - before.skipped[i];
    };
    auto all_skipped = [&] {
      for (size_t i = 0; i < want.size(); ++i) {
        if (skipped_delta(i) < want[i]) {
          return false;
        }
      }
      return true;
    };
    bool cleaned = co_await wait_until([&] {
      return storage->held_ops_finished.load() == storage->held_ops_started.load() && destroyed->load() &&
             std::all_of(outcomes.begin(), outcomes.end(), [](const auto& o) { return o->done; }) && all_skipped();
    });
    const auto after = simplex::candidate_resolver_stop_counts_for_test();
    std::string counts;
    for (size_t i = 0; i < want.size(); ++i) {
      counts += PSTRING() << " kind" << i << "=skipped:" << after.skipped[i] - before.skipped[i] << "/want:" << want[i]
                          << ",attempted:" << after.attempted[i] - before.attempted[i];
    }
    emit(PSTRING() << "BUDGET_STOP " << where << " cleaned=" << cleaned
                   << " db_ops=" << storage->held_ops_finished.load() << "/" << storage->held_ops_started.load()
                   << " bus_destroyed=" << destroyed->load() << counts);
    for (size_t i = 0; i < want.size(); ++i) {
      require(after.attempted[i] == before.attempted[i],
              PSTRING() << where << ": cleanup of kind " << i << " reached actor state after the stop");
    }
    require(cleaned, where + ": a frame, request or the bus outlived the stop");
    for (size_t i = 0; i < want.size(); ++i) {
      require(after.skipped[i] - before.skipped[i] == want[i],
              PSTRING() << where << ": " << after.skipped[i] - before.skipped[i] << " guards of kind " << i
                        << " ran after the stop, " << want[i] << " expected");
    }
    for (size_t i = 0; i < outcomes.size(); ++i) {
      const auto& o = outcomes[i];
      emit(PSTRING() << "BUDGET_STOP " << where << " waiter " << i << " completions=" << o->completions
                     << " code=" << o->code << " error=" << o->error);
      require(o->completions == 1, PSTRING()
                                       << where << ": waiter " << i << " completed " << o->completions << " times");
      require(!o->ok && o->code == ErrorCode::cancelled,
              PSTRING() << where << ": waiter " << i << " did not end with cancelled: " << o->error);
    }
    auto budget = simplex::node_candidate_payload_budget().snapshot();
    require(budget.accounting_errors == 0 && budget.live_over_charge == 0,
            where + ": the allowance saw an accounting error at the stop");
    node.runtime.reset();
    co_return td::Unit{};
  }

  // Two local resolves of distinct dropped candidates, each holding a read slot in its database
  // read, and two stores of a third candidate: the first in its held write, the second waiting
  // on it.
  td::actor::Task<> run_stop_cold_reads() {
    auto chain = make_chain(nodes_[0], 4);
    co_await limit_in_charges(chain, 1);
    co_await store_and_finalize(0, std::vector<CandidateRef>(chain.begin(), chain.begin() + 3));
    const auto& a = chain[0];
    const auto& b = chain[1];
    const auto& d = chain[3];
    nodes_[0].storage->payload_reads_gate.hold();
    nodes_[0].storage->payload_writes_gate.hold();
    std::vector<std::shared_ptr<Outcome>> outcomes;
    for (const auto& target : {a, b}) {
      outcomes.push_back(std::make_shared<Outcome>());
      resolve_into(0, target, outcomes.back()).start().detach();
    }
    for (int i = 0; i < 2; ++i) {
      outcomes.push_back(std::make_shared<Outcome>());
      store_into(0, d, outcomes.back()).start().detach();
    }
    if (!co_await wait_cache(0, [&](const Cache& c) {
          return c.cold_reads_in_flight == 2 && nodes_[0].storage->payload_reads_gate.waiting() == 2 &&
                 nodes_[0].storage->payload_writes_gate.waiting() == 1;
        })) {
      finish(1, "BUDGET_PRECONDITION_FAILED: the reads did not both hold slots, or the store is not held");
    }
    auto d_entry = co_await cache(0, d->id);
    if (d_entry.id_active_operations != 2) {
      finish(1, "BUDGET_PRECONDITION_FAILED: the second store is not waiting on the first");
    }
    StopExpectation expected;
    expected.pins = co_await pins_on(0, {a, b, d});
    expected.slots = 2;
    expected.loaders = 2;
    co_await stop_with_pending(0, expected, outcomes, "stop-cold-reads");
    finish(0, "BUDGET_STOP_COLD_READS_OK");
  }

  // Every read slot held, and a local and a remote reader queued for one.
  td::actor::Task<> run_stop_slot_waiter() {
    auto chain = make_chain(nodes_[0], 7);
    co_await limit_in_charges(chain, 1);
    co_await store_and_finalize(0, chain);
    auto limits = co_await cache(0);
    const size_t slots = limits.cold_read_concurrency;
    nodes_[0].storage->payload_reads_gate.hold();
    std::vector<std::shared_ptr<Outcome>> outcomes;
    std::vector<CandidateRef> involved;
    for (size_t i = 0; i <= slots; ++i) {
      outcomes.push_back(std::make_shared<Outcome>());
      resolve_into(0, chain[i], outcomes.back()).start().detach();
      involved.push_back(chain[i]);
    }
    // The resolves start their reads from scheduled tasks; the peer request comes once they
    // hold every slot and the last one is queued, so it is the one queued behind them.
    if (!co_await wait_cache(
            0, [&](const Cache& c) { return c.cold_reads_in_flight == slots && c.cold_read_waiters == 1; })) {
      finish(1, "BUDGET_PRECONDITION_FAILED: the local resolves did not take every slot and queue one");
    }
    outcomes.push_back(std::make_shared<Outcome>());
    peer_request_into(0, chain[slots + 1], outcomes.back()).start().detach();
    involved.push_back(chain[slots + 1]);
    if (!co_await wait_cache(0, [&](const Cache& c) {
          return c.cold_reads_in_flight == slots && c.cold_read_waiters == 2 && c.remote_cold_read_waiters == 1 &&
                 nodes_[0].storage->payload_reads_gate.waiting() == static_cast<int>(slots);
        })) {
      auto state = co_await cache(0);
      finish(1, PSTRING() << "BUDGET_PRECONDITION_FAILED: the slots are not all held with a local and a remote "
                             "reader queued: held="
                          << nodes_[0].storage->payload_reads_gate.waiting() << " " << describe(state)
                          << " remote_waiters=" << state.remote_cold_read_waiters);
    }
    StopExpectation expected;
    expected.pins = co_await pins_on(0, involved);
    expected.slots = slots;
    expected.loaders = slots + 2;
    expected.remote_waits = 2;
    co_await stop_with_pending(0, expected, outcomes, "stop-slot-waiter");
    finish(0, "BUDGET_STOP_SLOT_WAITER_OK");
  }

  // Two reads holding slots, a peer request waiting on the first one's read and a second local
  // resolve of the same candidate waiting on the first resolve.
  td::actor::Task<> run_stop_coalesced() {
    auto chain = make_chain(nodes_[0], 3);
    co_await limit_in_charges(chain, 1);
    co_await store_and_finalize(0, chain);
    const auto& a = chain[0];
    const auto& b = chain[1];
    nodes_[0].storage->payload_reads_gate.hold();
    std::vector<std::shared_ptr<Outcome>> outcomes;
    for (const auto& target : {a, b}) {
      outcomes.push_back(std::make_shared<Outcome>());
      resolve_into(0, target, outcomes.back()).start().detach();
    }
    if (!co_await wait_cache(0, [&](const Cache& c) { return c.cold_reads_in_flight == 2; })) {
      finish(1, "BUDGET_PRECONDITION_FAILED: the reads did not both hold slots");
    }
    auto before = co_await cache(0);
    outcomes.push_back(std::make_shared<Outcome>());
    peer_request_into(0, a, outcomes.back()).start().detach();
    outcomes.push_back(std::make_shared<Outcome>());
    resolve_into(0, a, outcomes.back()).start().detach();
    if (!co_await wait_cache(0, [&](const Cache& c) {
          return c.coalesced_reads == before.coalesced_reads + 1 && c.remote_cold_read_waiters == 1;
        })) {
      finish(1, "BUDGET_PRECONDITION_FAILED: the peer request did not wait on the running read");
    }
    auto a_entry = co_await cache(0, a->id);
    if (a_entry.id_active_operations != 4) {
      finish(1, "BUDGET_PRECONDITION_FAILED: the second resolve is not waiting on the first");
    }
    StopExpectation expected;
    expected.pins = co_await pins_on(0, {a, b});
    expected.slots = 2;
    expected.loaders = 2;
    expected.remote_waits = 1;
    co_await stop_with_pending(0, expected, outcomes, "stop-coalesced");
    finish(0, "BUDGET_STOP_COALESCED_OK");
  }

  // A read that found another candidate's record, while a late store put the payload back: the
  // stop comes while the repair write is held, with the read's buffer still counted.
  td::actor::Task<> run_stop_bytes_guard() {
    auto chain = make_chain(nodes_[0], 2);
    co_await limit_in_charges(chain, 1);
    const auto& a = chain[0];
    co_await store_and_finalize(0, chain);
    nodes_[0].storage->put(payload_key(a->id).as_slice(), chain[1]->serialize().as_slice());
    nodes_[0].storage->payload_reads_gate.hold();
    std::vector<std::shared_ptr<Outcome>> outcomes;
    outcomes.push_back(std::make_shared<Outcome>());
    peer_request_into(0, a, outcomes.back()).start().detach();
    if (!co_await wait_until([&] { return nodes_[0].storage->payload_reads_gate.waiting() == 1; })) {
      finish(1, "BUDGET_PRECONDITION_FAILED: the read never started");
    }
    co_await store(0, a);
    nodes_[0].storage->payload_writes_gate.hold();
    nodes_[0].storage->payload_reads_gate.release();
    if (!co_await wait_cache(0, [&](const Cache& c) {
          return nodes_[0].storage->payload_writes_gate.waiting() == 1 && c.cold_read_bytes_in_flight > 0 &&
                 c.durability_revocations == 1;
        })) {
      finish(1, "BUDGET_PRECONDITION_FAILED: the repair write is not held with the read buffer counted");
    }
    StopExpectation expected;
    expected.pins = co_await pins_on(0, {a});
    expected.slots = 1;
    expected.loaders = 1;
    expected.bytes = 1;
    co_await stop_with_pending(0, expected, outcomes, "stop-bytes-guard");
    finish(0, "BUDGET_STOP_BYTES_GUARD_OK");
  }

  // A notarization certificate write held across the stop. Its task has no guard; the stop must
  // leave nothing that touches the resolver when the write completes.
  td::actor::Task<> run_stop_notar_write() {
    auto chain = make_chain(nodes_[0], 1);
    nodes_[0].storage->notar_writes_gate.hold();
    notarize(0, chain[0]);
    if (!co_await wait_until([&] { return nodes_[0].storage->notar_writes_gate.waiting() == 1; })) {
      finish(1, "BUDGET_PRECONDITION_FAILED: the certificate write never started");
    }
    co_await stop_with_pending(0, StopExpectation{}, {}, "stop-notar-write");
    finish(0, "BUDGET_STOP_NOTAR_WRITE_OK");
  }

  // A payload dropped while the only thing left holding it is a clone of its block data: the
  // allowance keeps its charge until the clone is gone.
  td::actor::Task<> run_external_slice() {
    auto chain = make_chain(nodes_[0], 3);
    co_await limit_in_charges(chain, 2);
    const auto& a = chain[0];
    co_await store_and_finalize(0, std::vector<CandidateRef>(chain.begin(), chain.begin() + 2));
    auto entry = co_await cache(0, a->id);
    require(entry.id_payload_cached, "A was not cached");
    td::BufferSlice clone;
    {
      auto cached = co_await resolve(0, a);
      clone = std::get<BlockCandidate>(cached->block).data.clone();
    }
    // Only the clone remains outside the resolver: the resolved reference was dropped above.
    co_await store(0, chain[2]);
    co_await finalize(0, chain[2]);
    auto dropped = co_await cache(0, a->id);
    emit(PSTRING() << "BUDGET_EXTERNAL_SLICE after drop " << describe(dropped));
    require(!dropped.id_payload_resident, "A was not dropped");
    require(dropped.node_retired_payloads == 1 && dropped.node_retired_bytes == charge(a),
            "a payload held only through a clone of its data is not charged as retired");
    co_await must_serve(0, chain[1]);
    auto still = co_await check_bound("external-slice-held");
    require(still.node_retired_payloads == 1, "the retired charge was released while a data clone is alive");
    require(clone.as_slice() == std::get<BlockCandidate>(a->block).data.as_slice(), "the clone lost its contents");
    clone = td::BufferSlice();
    co_await must_serve(0, chain[1]);
    auto released = co_await check_bound("external-slice-released");
    require(released.node_retired_payloads == 0 && released.node_retired_bytes == 0,
            "the retired charge stayed after the last clone was released");
    finish(0, "BUDGET_EXTERNAL_SLICE_OK");
  }

  // Concurrent cold reads of one dropped candidate, local and remote, are one database read,
  // and the peer requests waiting on it are held to the waiting allowance: the ones beyond it
  // are refused as busy, a local resolve still waits, and every answer is the candidate.
  td::actor::Task<> run_cold_same_id() {
    auto chain = make_chain(nodes_[0], 2);
    co_await limit_in_charges(chain, 1);
    co_await store_and_finalize(0, chain);
    const auto& a = chain[0];
    auto before = co_await cache(0);
    const int reads_before = nodes_[0].storage->payload_reads.load();
    const size_t allowance = before.cold_read_max_remote_waiters;
    // One reader runs the read; the allowance waits on it; the rest are beyond it.
    const size_t beyond = 8;
    const size_t remote = 1 + allowance + beyond;

    nodes_[0].storage->payload_reads_gate.hold();
    std::vector<std::shared_ptr<Outcome>> outcomes;
    for (size_t i = 0; i < remote; ++i) {
      outcomes.push_back(std::make_shared<Outcome>());
      peer_request_into(0, a, outcomes.back()).start().detach();
    }
    auto local = std::make_shared<Outcome>();
    resolve_into(0, a, local).start().detach();
    // Every reader has arrived once it is reading, waiting for a read slot, waiting for the read
    // of another reader, or refused.
    const size_t readers = remote + 1;
    if (!co_await wait_cache(0, [&](const Cache& c) {
          return c.coalesced_reads - before.coalesced_reads + c.cold_reads_in_flight + c.cold_read_waiters +
                     (c.cold_reads_refused - before.cold_reads_refused) ==
                 readers;
        })) {
      auto state = co_await cache(0);
      finish(1, "BUDGET_PRECONDITION_FAILED: the readers did not all arrive: " + describe(state));
    }
    auto during = co_await cache(0);
    emit(PSTRING() << "BUDGET_COLD_SAME held=" << nodes_[0].storage->held_reads()
                   << " remote_waiters=" << during.remote_cold_read_waiters << "/peak "
                   << during.remote_cold_read_waiters_peak << " " << describe(during));
    require(nodes_[0].storage->held_reads() == 1 && during.cold_reads_in_flight == 1,
            "more than one database read ran");
    require(during.remote_cold_read_waiters == allowance && during.remote_cold_read_waiters_peak == allowance,
            "the peer requests waiting on the read exceeded their allowance");
    require(during.cold_reads_refused == before.cold_reads_refused + beyond,
            "the peer requests beyond the allowance were not refused");
    require(during.coalesced_reads == before.coalesced_reads + allowance + 1,
            "the allowed readers and the local resolve were not coalesced");
    nodes_[0].storage->payload_reads_gate.release();
    if (!co_await wait_until([&] {
          return local->done && std::all_of(outcomes.begin(), outcomes.end(), [](const auto& o) { return o->done; });
        })) {
      finish(1, "BUDGET_PRECONDITION_FAILED: a reader never returned");
    }
    require(local->ok && local->matched, "the local resolve got the wrong answer: " + local->error);
    size_t served = 0;
    for (const auto& outcome : outcomes) {
      if (outcome->ok) {
        require(outcome->matched, "a coalesced reader got the wrong answer");
        ++served;
      }
    }
    require(served == 1 + allowance, "a peer request inside the allowance was not served");
    auto after = co_await check_bound("cold-same-id");
    require(after.remote_cold_read_waiters == 0, "a refused or served peer request is still counted as waiting");
    require(nodes_[0].storage->payload_reads.load() == reads_before + 1, "the readers were not coalesced");
    require(after.db_payload_reads == before.db_payload_reads + 1, "the resolver counted more than one read");
    require(after.cold_reads_in_flight_peak <= after.cold_read_concurrency, "the cold reads exceeded their limit");
    // A refused peer asks again and is served.
    co_await must_serve(0, a);
    finish(0, "BUDGET_COLD_SAME_OK");
  }

  // A record goes missing or bad after the candidate was stored and dropped. While a read of it
  // runs, a late store puts the payload back in memory without writing, as the entry still
  // believes the record durable. The read must still revoke that belief and the record must be
  // written again before the payload can be dropped.
  td::actor::Task<> run_refill(bool corrupt) {
    auto chain = make_chain(nodes_[0], 2);
    co_await limit_in_charges(chain, 1);
    const auto& a = chain[0];
    co_await store_and_finalize(0, chain);
    auto entry = co_await cache(0, a->id);
    require(entry.id_durable && !entry.id_payload_resident, "A was not dropped as durable");
    auto key = payload_key(a->id);
    if (corrupt) {
      nodes_[0].storage->put(key.as_slice(), td::Slice("not a candidate record"));
    } else {
      nodes_[0].storage->erase(key.as_slice());
    }

    nodes_[0].storage->payload_reads_gate.hold();
    auto reply = std::make_shared<Outcome>();
    peer_request_into(0, a, reply).start().detach();
    if (!co_await wait_until([&] { return nodes_[0].storage->held_reads() == 1; })) {
      finish(1, "BUDGET_PRECONDITION_FAILED: the read never started");
    }
    co_await store(0, a);
    require(!persisted(nodes_[0], a), "the late store wrote the record; the sequence did not happen");
    nodes_[0].storage->payload_reads_gate.release();
    if (!co_await wait_until([&] { return reply->done; })) {
      finish(1, "BUDGET_PRECONDITION_FAILED: the request never returned");
    }
    require(reply->ok && reply->matched, "the request did not get the refilled candidate");
    auto state = co_await check_bound(corrupt ? "refill-corrupt" : "refill-missing");
    entry = co_await cache(0, a->id);
    emit(PSTRING() << "BUDGET_REFILL revocations=" << state.durability_revocations
                   << " persisted=" << persisted(nodes_[0], a) << " durable=" << entry.id_durable
                   << " resident=" << entry.id_payload_resident);
    require(state.durability_revocations == 1, "the bad record did not revoke durability");
    require(persisted(nodes_[0], a), "the record was not written again before the payload could be dropped");
    require(entry.id_durable && !entry.id_payload_resident, "the repaired payload was not dropped as durable");

    // The repaired record is read without the network.
    notarize(0, a);
    co_await resolve(0, a);
    require(network.total_requests() == 0, "the candidate was requested from the network");
    finish(0, "BUDGET_REFILL_OK");
  }

  // Concurrent cold reads of many dropped candidates under a held database: bounded reads, a
  // bounded queue, the excess refused as busy, and every answer the right candidate.
  td::actor::Task<> run_cold_many() {
    auto chain = make_chain(nodes_[0], 48);
    co_await limit_in_charges(chain, 1);
    co_await store_and_finalize(0, chain, /*notarized=*/false);
    auto limits = co_await cache(0);
    const size_t requests = chain.size() - 1;
    const size_t admitted = limits.cold_read_concurrency + limits.cold_read_max_remote_waiters;
    require(requests > admitted, "the mode does not exceed the cold-read queue");

    td::uint64 largest_record = 0;
    for (const auto& candidate : chain) {
      largest_record = std::max<td::uint64>(largest_record, candidate->serialize().size());
    }
    nodes_[0].storage->payload_reads_gate.hold();
    std::vector<std::shared_ptr<Outcome>> outcomes;
    for (size_t i = 0; i < requests; ++i) {
      outcomes.push_back(std::make_shared<Outcome>());
      peer_request_into(0, chain[i], outcomes.back()).start().detach();
    }
    // Every request has arrived once it is reading, waiting for a read slot, or refused.
    if (!co_await wait_cache(0, [&](const Cache& c) {
          return c.cold_reads_in_flight + c.cold_read_waiters + c.cold_reads_refused == requests;
        })) {
      auto state = co_await cache(0);
      finish(1, "BUDGET_PRECONDITION_FAILED: the cold reads did not all arrive: " + describe(state));
    }
    auto during = co_await cache(0);
    emit(PSTRING() << "BUDGET_COLD_MANY during held=" << nodes_[0].storage->held_reads() << " " << describe(during));
    require(during.cold_reads_in_flight == during.cold_read_concurrency &&
                nodes_[0].storage->held_reads() == static_cast<int>(during.cold_read_concurrency),
            "more database reads ran than the limit");
    require(during.cold_read_waiters == during.cold_read_max_remote_waiters, "the read queue exceeded its limit");
    require(during.cold_reads_refused == requests - admitted, "the requests beyond the queue were not refused");
    nodes_[0].storage->payload_reads_gate.release();
    if (!co_await wait_until(
            [&] { return std::all_of(outcomes.begin(), outcomes.end(), [](const auto& o) { return o->done; }); })) {
      finish(1, "BUDGET_PRECONDITION_FAILED: a cold read never returned");
    }
    size_t served = 0;
    size_t busy = 0;
    for (size_t i = 0; i < outcomes.size(); ++i) {
      const auto& outcome = outcomes[i];
      if (outcome->ok) {
        require(outcome->matched, PSTRING() << "slot " << i << " was answered with the wrong contents");
        ++served;
      } else {
        ++busy;
        // A refused peer asks again later and is served.
        co_await must_serve(0, chain[i]);
      }
    }
    auto after = co_await check_bound("cold-many");
    emit(PSTRING() << "BUDGET_COLD_MANY served=" << served << " busy=" << busy << " largest_record=" << largest_record
                   << " " << describe(after));
    require(served == admitted && busy == requests - admitted, "the queue did not bound the cold reads");
    require(after.cold_reads_in_flight_peak == after.cold_read_concurrency,
            "the read limit was not reached or exceeded");
    require(after.cold_read_waiters_peak == after.cold_read_max_remote_waiters, "the queue limit was exceeded");
    require(after.cold_read_bytes_peak <= after.cold_read_concurrency * largest_record,
            "the cold-read buffers exceeded the read limit");
    require(after.cold_reads_in_flight == 0 && after.cold_read_waiters == 0, "a cold read is still held");
    finish(0, "BUDGET_COLD_MANY_OK");
  }
};

struct ModeSpec {
  const char* name;
  Mode mode;
  // The limit in candidate charges, or 0 for a limit below one candidate.
  double charges;
  // Scheduler threads. The stop modes use more, so frames destroyed after a stop can be
  // destroyed on different threads at once.
  int workers = 2;
};

const ModeSpec MODES[] = {
    {"bound", Mode::Bound, 3},
    {"rehydrate", Mode::Rehydrate, 3},
    {"pinned-resolve", Mode::PinnedResolve, 1},
    {"pinned-reply", Mode::PinnedReply, 1},
    {"pinned-rehydrate", Mode::PinnedRehydrate, 1},
    {"reenforce", Mode::Reenforce, 2},
    {"oversized", Mode::Oversized, 0},
    {"persist-cancelled", Mode::PersistCancelled, 2},
    {"persist-failed", Mode::PersistFailed, 2},
    {"external-ref", Mode::ExternalRef, 2},
    {"revoke-missing", Mode::RevokeMissing, 1},
    {"revoke-corrupt", Mode::RevokeCorrupt, 1},
    {"revoke-mismatch", Mode::RevokeMismatch, 1},
    {"stale-read", Mode::StaleRead, 1},
    {"refill-missing", Mode::RefillMissing, 1},
    {"refill-corrupt", Mode::RefillCorrupt, 1},
    {"shared-budget", Mode::SharedBudget, 3},
    {"concurrent", Mode::Concurrent, 3},
    {"session-exit", Mode::SessionExit, 3},
    {"session-overlap", Mode::SessionOverlap, 3},
    {"stop-cold-reads", Mode::StopColdReads, 1, 4},
    {"stop-slot-waiter", Mode::StopSlotWaiter, 1, 4},
    {"stop-coalesced", Mode::StopCoalesced, 1, 4},
    {"stop-bytes-guard", Mode::StopBytesGuard, 1, 4},
    {"stop-notar-write", Mode::StopNotarWrite, 1, 4},
    {"external-slice", Mode::ExternalSlice, 2},
    {"cold-same-id", Mode::ColdSameId, 1},
    {"cold-many", Mode::ColdMany, 1},
    {"oversized-keeps-cache", Mode::OversizedKeepsCache, 2},
};

// Every candidate the modes build has the same shape, so one candidate's charge sets the
// limit. It is computed from a candidate built the same way, not assumed.
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

int run_mode(const ModeSpec& spec) {
  auto charge = one_charge();
  td::uint64 limit =
      spec.charges == 0 ? charge - 1 : static_cast<td::uint64>(static_cast<double>(charge) * spec.charges) + charge / 4;
  setenv("TOS_SIMPLEX_CANDIDATE_CACHE_BYTES", std::to_string(limit).c_str(), 1);
  td::actor::Scheduler scheduler({spec.workers});
  td::actor::ActorOwn<Driver> driver;
  scheduler.run_in_context([&] {
    driver = td::actor::create_actor<Driver>("budget-driver", spec.mode);
    td::actor::ask(driver, &Driver::run).detach();
  });
  while (scheduler.run(1)) {
  }
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
    std::printf("BUDGET_MODE %s %s (status %d)\n", spec.name, ok ? "PASS" : "FAIL", status);
    std::fflush(stdout);
    failed += ok ? 0 : 1;
  }
  std::printf("BUDGET_SUMMARY %d of %zu modes failed\n", failed, std::size(MODES));
  return failed == 0 ? 0 : 1;
}
