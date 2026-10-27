/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
// Actor-level regression: the own-decision log keeps a restarted validator from signing a
// decision that conflicts with one it may already have signed, whatever happened to its
// session journal, and fences a session whose log lost decisions its journal still holds.
//
// One validator node runs the production Consensus, Pool, BlockProducer, CandidateResolver,
// StateResolver, BlockValidator and Db actors, with an admission from a real SigningLedger
// on real files. The stand-ins are the validator manager (which collates a different block on
// every call), the private overlay and the session database backend, which survives a
// restart unless a mode loses or rolls back part of it. No peer certificate is delivered,
// so the node stays in window 0. Every signature the node makes is counted by its signer,
// and every vote it commits is recorded by identity.
//
// Modes (the node is validator 1 unless stated; validator 0 leads window 0):
//   journal-loss            the node notarizes candidate A for slot 0, crashes and loses its
//                           whole session journal; after the restart the leader equivocates
//                           with candidate B for slot 0. The node signs notarize(A) again and
//                           never notarize(B).
//   journal-loss-without-log the same with no decision log: the node signs notarize(B). This is
//                           the conflict the log exists to prevent, shown to happen.
//   intact-restart          a restart with the journal intact replays notarize(A) from its bytes
//                           and signs nothing for it again.
//   log-rollback            the decision log is cut back in place to before notarize(A) while
//                           the journal keeps it: the session is fenced and signs nothing.
//   window-journal-rollback (the node leads window 0) after producing in window 0, the
//                           journal's window record is lost while the decision log keeps the
//                           window: the restarted node announces window 0 again and produces
//                           nothing in it.
//   window-log-rollback     (the node leads window 0) the decision log loses its window record
//                           in place while the journal keeps its window record: the restarted
//                           node does not announce window 0 again, so it produces nothing in
//                           it. The journal's record is the protection that survives here.
//   window-log-rollback-without-journal-record
//                           the same with the journal's window record lost too: the node
//                           produces a second, different candidate for window 0. This is the
//                           in-place rollback of both stores the log does not claim to catch.
//   log-rollback-leader     (the node leads window 0) the log is cut back to nothing in place
//                           while the journal keeps the node's votes, and the journal's window
//                           record is lost: the session is fenced and the restarted leader
//                           signs no candidate and no vote.

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
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
const td::Bits256 SESSION = fill(0x42);

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
  JournalLoss,
  JournalLossWithoutLog,
  IntactRestart,
  LogRollback,
  WindowJournalRollback,
  WindowLogRollback,
  WindowLogRollbackWithoutJournalRecord,
  LogRollbackLeader,
};

bool uses_log(Mode mode) {
  return mode != Mode::JournalLossWithoutLog;
}

bool target_leads(Mode mode) {
  return mode == Mode::WindowJournalRollback || mode == Mode::WindowLogRollback ||
         mode == Mode::WindowLogRollbackWithoutJournalRecord || mode == Mode::LogRollbackLeader;
}

// ===== The session database backend, shared by both lives =====

struct Storage {
  std::mutex mutex;
  std::map<td::BufferSlice, td::BufferSlice> map;
};

Storage storage;

td::int32 tag_of(td::Slice value) {
  td::int32 tag = 0;
  if (value.size() >= sizeof(tag)) {
    std::memcpy(&tag, value.data(), sizeof(tag));
  }
  return tag;
}

void lose_journal() {
  std::scoped_lock lock(storage.mutex);
  storage.map.clear();
}

void lose_pool_state() {
  std::scoped_lock lock(storage.mutex);
  std::erase_if(storage.map, [](const auto& kv) {
    return tag_of(kv.second.as_slice()) == tos_api::consensus_simplex_db_poolState::ID;
  });
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
    std::scoped_lock lock(storage.mutex);
    storage.map[std::move(key)] = std::move(value);
    co_return td::Unit{};
  }
  td::actor::Task<> close() override {
    co_return td::Unit{};
  }

 private:
  std::map<td::BufferSlice, td::BufferSlice> snapshot_;
};

// ===== What the test observes =====

struct Signed {
  size_t life;
  std::string vote;
  int kind;  // 0 notarize, 1 finalize, 2 skip
  td::uint32 slot;
  std::string candidate;
};

struct ProducedCandidate {
  size_t life;
  td::uint32 slot;
  std::string id;
};

std::mutex observed_mutex;
std::vector<Signed> signed_votes;
std::vector<ProducedCandidate> produced;
std::atomic<size_t> current_life{0};

void record_signed(const simplex::Vote& vote) {
  Signed s{current_life.load(), PSTRING() << vote, 2, vote.referenced_slot(), {}};
  if (auto n = std::get_if<simplex::NotarizeVote>(&vote.vote)) {
    s.kind = 0;
    s.candidate = n->id.hash.to_hex();
  } else if (auto f = std::get_if<simplex::FinalizeVote>(&vote.vote)) {
    s.kind = 1;
    s.candidate = f->id.hash.to_hex();
  }
  emit(PSTRING() << "DLR_SIGNED life=" << s.life << " " << s.vote);
  std::scoped_lock lock(observed_mutex);
  signed_votes.push_back(std::move(s));
}

// Every vote committed with a signature, over all lives: per slot at most one notarize
// candidate, at most one finalize candidate equal to it, never skip and finalize together.
std::optional<std::string> conflicting_votes() {
  std::scoped_lock lock(observed_mutex);
  std::map<td::uint32, std::set<std::string>> notar, final_votes;
  std::set<td::uint32> skips;
  for (const auto& s : signed_votes) {
    if (s.kind == 0) {
      notar[s.slot].insert(s.candidate);
    } else if (s.kind == 1) {
      final_votes[s.slot].insert(s.candidate);
    } else {
      skips.insert(s.slot);
    }
  }
  for (const auto& [slot, ids] : notar) {
    if (ids.size() > 1) {
      return PSTRING() << "two notarize votes signed for slot " << slot;
    }
  }
  for (const auto& [slot, ids] : final_votes) {
    if (ids.size() > 1) {
      return PSTRING() << "two finalize votes signed for slot " << slot;
    }
    if (skips.contains(slot)) {
      return PSTRING() << "skip and finalize signed for slot " << slot;
    }
    if (notar.contains(slot) && notar[slot] != ids) {
      return PSTRING() << "finalize differs from notarize for slot " << slot;
    }
  }
  return std::nullopt;
}

size_t signed_count(size_t life, const std::string& vote) {
  std::scoped_lock lock(observed_mutex);
  return static_cast<size_t>(std::count_if(signed_votes.begin(), signed_votes.end(),
                                           [&](const Signed& s) { return s.life == life && s.vote == vote; }));
}

std::optional<std::string> conflicting_candidates() {
  std::scoped_lock lock(observed_mutex);
  std::map<td::uint32, std::set<std::string>> by_slot;
  for (const auto& c : produced) {
    by_slot[c.slot].insert(c.id);
  }
  for (const auto& [slot, ids] : by_slot) {
    if (ids.size() > 1) {
      return PSTRING() << ids.size() << " different candidates signed for slot " << slot;
    }
  }
  return std::nullopt;
}

size_t produced_in(size_t life) {
  std::scoped_lock lock(observed_mutex);
  return static_cast<size_t>(
      std::count_if(produced.begin(), produced.end(), [&](const ProducedCandidate& c) { return c.life == life; }));
}

class ObserverActor : public td::actor::SpawnsWith<simplex::Bus>, public td::actor::ConnectsTo<simplex::Bus> {
 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();

  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const StopRequested>) {
    stop();
  }

  // Published by the bus only after the signed record was committed.
  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const simplex::PersistOwnSignedVote> event) {
    record_signed(event->vote);
  }

  template <>
  void handle(simplex::BusHandle, std::shared_ptr<const CandidateGenerated> event) {
    const auto& id = event->candidate->id;
    emit(PSTRING() << "DLR_CANDIDATE life=" << current_life.load() << " slot=" << id.slot
                   << " id=" << id.hash.to_hex());
    std::scoped_lock lock(observed_mutex);
    produced.push_back(ProducedCandidate{current_life.load(), id.slot, id.hash.to_hex()});
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

class CollatingManager : public ManagerFacade {
 public:
  td::actor::Task<GeneratedCandidate> collate_block(CollateParams params, td::CancellationToken) override {
    CHECK(params.prev.size() == 1);
    auto prev = params.prev[0];
    double gen_utime = params.utime ? params.utime.value() : td::Clocks::system();
    auto candidate = make_block(prev.seqno() + 1, prev, 1000 + ++collations, gen_utime);
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

// Rewrites the decision log in place, keeping its file (and so its binding), with only the
// records `keep` selects, re-chained so that the log itself is valid: a rollback the log's
// own checks cannot see.
void rewrite_log_in_place(const std::string& path, const std::function<bool(const signing::Decision&)>& keep) {
  const int fd = ::open(path.c_str(), O_RDWR | O_CLOEXEC);
  CHECK(fd >= 0);
  auto loaded = signing::load_log(fd, SESSION);
  CHECK(loaded.is_ok());
  std::string bytes;
  auto chain = signing::chain_start(SESSION);
  std::int64_t seq = 0;
  for (const auto& [_, decision] : loaded.ok().decisions) {
    if (!keep(decision)) {
      continue;
    }
    std::array<unsigned char, 16> next{};
    bytes += signing::encode_record(decision, seq++, chain, next);
    chain = next;
  }
  CHECK(::ftruncate(fd, 0) == 0);
  CHECK(::pwrite(fd, bytes.data(), bytes.size(), 0) == static_cast<ssize_t>(bytes.size()));
  CHECK(::fsync(fd) == 0);
  ::close(fd);
  emit(PSTRING() << "DLR_LOG_REWRITTEN records=" << seq);
}

class Driver : public td::actor::Actor {
 public:
  explicit Driver(Mode mode) : mode_(mode), target_(target_leads(mode) ? 0 : 1) {
  }

  td::actor::Task<> run() {
    auto result = co_await run_inner().wrap();
    if (result.is_error()) {
      finish(1, "DLR_HARNESS_FAILED: " + result.error().to_string());
    }
    co_return td::Unit{};
  }

 private:
  Mode mode_;
  size_t target_;
  std::string ledger_dir_;
  std::vector<std::shared_ptr<const tos::pq::ValidatorPQKeyStore>> signers_;
  std::vector<PeerValidator> validators_;
  std::unique_ptr<td::actor::Runtime> runtime_;
  td::actor::ActorOwn<CollatingManager> manager_;
  td::actor::ActorOwn<signing::SigningLedger> ledger_;
  simplex::BusHandle bus_;
  std::shared_ptr<simplex::Bus> bus_ptr_;
  std::optional<td::actor::StartedTask<>> stopped_;

  td::BufferSlice sign(size_t signer, td::Slice inner) const {
    auto envelope = create_serialize_tl_object<tos_api::consensus_dataToSign>(SESSION, td::BufferSlice(inner));
    auto signature =
        signers_.at(signer)->sign_consensus(std::string_view(envelope.as_slice().data(), envelope.as_slice().size()));
    CHECK(signature.has_value());
    return td::BufferSlice(signature->signature);
  }

  // A candidate for slot 0 from its leader, validator 0, built on the zerostate.
  CandidateRef leader_candidate(td::uint64 nonce) {
    auto block = make_block(1, FIRST_PARENT, nonce, 1'700'000'000.0);
    auto id = CandidateHashData::create_full(block, std::nullopt).build_id_with(0);
    auto signature = sign(0, serialize_tl_object(id.to_tl(), true).as_slice());
    return td::make_ref<Candidate>(id, std::nullopt, PeerValidatorId{0}, std::move(block), std::move(signature));
  }

  std::string notar_text(const CandidateRef& candidate) {
    return PSTRING() << simplex::Vote{simplex::NotarizeVote{candidate->id}};
  }

  std::uint64_t signatures_made() const {
    return signers_.at(target_)->consensus_signatures_produced();
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

  void require(bool condition, const std::string& what) {
    if (!condition) {
      finish(4, "DLR_ASSERTION_FAILED: " + what);
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
    std::string pattern = "/tmp/tos-decision-log-restart-XXXXXX";
    char* made = ::mkdtemp(pattern.data());
    CHECK(made != nullptr);
    ledger_dir_ = std::string(made) + "/consensus/signing-ledger";
    if (uses_log(mode_)) {
      CHECK(signing::create_ledger(ledger_dir_, validators_.at(target_).validator_id.value).is_ok());
    }
  }

  std::string log_path() const {
    return ledger_dir_ + "/log." + SESSION.to_hex();
  }

  // One life of the node: a new ledger actor (as after a process restart), its admission,
  // then the group.
  td::actor::Task<> start_node() {
    ++current_life;
    std::shared_ptr<const signing::Admission> admission;
    if (uses_log(mode_)) {
      ledger_ =
          td::actor::create_actor<signing::SigningLedger>(PSTRING() << "ledger" << current_life.load(), ledger_dir_);
      admission = co_await td::actor::ask(ledger_.get(), &signing::SigningLedger::admit,
                                          validators_.at(target_).validator_id.value, SESSION);
      emit(PSTRING() << "DLR_ADMISSION life=" << current_life.load() << " fenced=" << admission->fenced
                     << " decisions=" << admission->decisions.size()
                     << (admission->fenced ? " reason=" + admission->reason : std::string()));
    }
    runtime_ = std::make_unique<td::actor::Runtime>();
    auto& runtime = *runtime_;
    runtime.register_actor<OverlayStub>("PrivateOverlay");
    runtime.register_actor<ObserverActor>("DlrObserver");
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
    bus->session_id = SESSION;
    bus->cc_seqno = CC_SEQNO;
    bus->validator_set_hash = 0;
    bus->db = std::make_unique<MemoryDb>();
    bus->signing_admission = admission;
    auto [stopped, stop_promise] = td::actor::StartedTask<>::make_bridge();
    bus->stop_promise = std::move(stop_promise);
    stopped_.emplace(std::move(stopped));
    bus_ptr_ = bus;
    bus->pq_signer = signers_.at(target_);
    bus->local_id = validators_.at(target_);
    bus->local_adnl_id = validators_.at(target_).adnl_id;

    bus_ = runtime.start(std::static_pointer_cast<simplex::Bus>(bus), PSTRING() << "dlr-life" << current_life.load());
    bus_.publish<Start>(
        td::make_ref<ChainState>(ChainState::ZerostateTip{FIRST_PARENT, gen_shard_state(0)}, MIN_MC_BLOCK_ID));
    emit(PSTRING() << "DLR_START life=" << current_life.load());
    co_return td::Unit{};
  }

  td::actor::Task<> stop_node() {
    bus_.publish<StopRequested>();
    bus_ = {};
    bus_ptr_.reset();
    co_await std::move(*stopped_);
    stopped_.reset();
    runtime_.reset();
    ledger_.reset();
    co_await settle(0.1);
    emit("DLR_STOPPED");
    co_return td::Unit{};
  }

  td::actor::Task<> run_inner() {
    make_validators();
    switch (mode_) {
      case Mode::JournalLoss:
      case Mode::JournalLossWithoutLog:
        co_return co_await run_journal_loss();
      case Mode::IntactRestart:
        co_return co_await run_intact_restart();
      case Mode::LogRollback:
        co_return co_await run_log_rollback();
      case Mode::WindowJournalRollback:
      case Mode::WindowLogRollback:
      case Mode::WindowLogRollbackWithoutJournalRecord:
        co_return co_await run_window_rollback();
      case Mode::LogRollbackLeader:
        co_return co_await run_log_rollback_leader();
    }
    co_return td::Unit{};
  }

  // Life 1: the node notarizes candidate A for slot 0.
  td::actor::Task<CandidateRef> notarize_a() {
    co_await start_node();
    auto a = leader_candidate(1);
    bus_.publish<CandidateReceived>(a);
    if (!co_await wait_until([&] { return signed_count(1, notar_text(a)) == 1; })) {
      finish(1, "DLR_PRECONDITION_FAILED: candidate A was not notarized");
    }
    co_return a;
  }

  td::actor::Task<> run_journal_loss() {
    auto a = co_await notarize_a();
    co_await stop_node();
    lose_journal();
    co_await start_node();
    // The leader equivocates: another candidate for slot 0.
    auto b = leader_candidate(2);
    bus_.publish<CandidateReceived>(b);
    co_await settle(1.5);
    const bool b_signed = signed_count(2, notar_text(b)) > 0;
    if (mode_ == Mode::JournalLossWithoutLog) {
      // The control: without the log nothing remembers notarize(A).
      require(b_signed && conflicting_votes().has_value(),
              "without the decision log the node did not sign the conflicting notarize; the scenario proves nothing");
      co_await stop_node();
      pass("DLR_OK journal-loss-without-log: " + *conflicting_votes());
    }
    require(!b_signed, "the node notarized B after losing its journal");
    if (auto conflict = conflicting_votes()) {
      finish(4, "DLR_CONFLICT: " + *conflict);
    }
    require(signed_count(2, notar_text(a)) == 1, "notarize(A), whose bytes were lost, was signed again once");
    co_await stop_node();
    pass("DLR_OK journal-loss");
  }

  td::actor::Task<> run_intact_restart() {
    auto a = co_await notarize_a();
    co_await stop_node();
    co_await start_node();
    co_await settle(1.0);
    require(signed_count(2, notar_text(a)) == 0, "notarize(A) was signed again although its bytes were kept");
    if (auto conflict = conflicting_votes()) {
      finish(4, "DLR_CONFLICT: " + *conflict);
    }
    co_await stop_node();
    pass("DLR_OK intact-restart");
  }

  td::actor::Task<> run_log_rollback() {
    auto a = co_await notarize_a();
    co_await stop_node();
    rewrite_log_in_place(log_path(), [](const signing::Decision&) { return false; });
    const auto before = signatures_made();
    co_await start_node();
    auto b = leader_candidate(2);
    bus_.publish<CandidateReceived>(b);
    co_await settle(1.5);
    require(signatures_made() == before, "a session whose log lost a decision its journal holds signed something");
    require(signed_count(2, notar_text(b)) == 0, "the node notarized B");
    co_await stop_node();
    pass("DLR_OK log-rollback");
  }

  // A fenced session signs no candidate either: the leader's log is cut back in place to
  // nothing while its journal keeps its votes, and its window record is lost too, so the
  // restarted leader announces window 0 again.
  td::actor::Task<> run_log_rollback_leader() {
    co_await start_node();
    if (!co_await wait_until([] { return produced_in(1) > 0; })) {
      finish(1, "DLR_PRECONDITION_FAILED: the leader produced nothing in window 0");
    }
    co_await settle(1.0);
    co_await stop_node();
    rewrite_log_in_place(log_path(), [](const signing::Decision&) { return false; });
    lose_pool_state();
    const auto before = signatures_made();
    co_await start_node();
    co_await settle(2.0);
    const auto again = produced_in(2);
    const auto made = signatures_made() - before;
    co_await stop_node();
    require(again == 0, PSTRING() << "a fenced session produced " << again << " candidates");
    require(made == 0, PSTRING() << "a fenced session made " << made << " signatures");
    pass("DLR_OK log-rollback-leader");
  }

  td::actor::Task<> run_window_rollback() {
    co_await start_node();
    if (!co_await wait_until([] { return produced_in(1) > 0; })) {
      finish(1, "DLR_PRECONDITION_FAILED: the leader produced nothing in window 0");
    }
    co_await settle(1.0);
    co_await stop_node();
    if (mode_ == Mode::WindowJournalRollback) {
      lose_pool_state();
    } else {
      rewrite_log_in_place(log_path(),
                           [](const signing::Decision& d) { return d.kind != signing::DecisionKind::LeaderWindow; });
      if (mode_ == Mode::WindowLogRollbackWithoutJournalRecord) {
        lose_pool_state();
      }
    }
    co_await start_node();
    co_await settle(2.0);
    const auto again = produced_in(2);
    const auto conflict = conflicting_candidates();
    co_await stop_node();
    if (mode_ == Mode::WindowLogRollbackWithoutJournalRecord) {
      require(again > 0 && conflict.has_value(),
              "with both window records rolled back the leader did not produce again; the control proves nothing");
      pass("DLR_OK window-log-rollback-without-journal-record: " + *conflict);
    }
    require(again == 0, PSTRING() << "the restarted leader produced " << again << " candidates in window 0");
    require(!conflict.has_value(), "two different candidates for one slot");
    pass(mode_ == Mode::WindowJournalRollback ? "DLR_OK window-journal-rollback" : "DLR_OK window-log-rollback");
  }
};

}  // namespace

int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(verbosity_WARNING);
  const std::vector<std::pair<std::string, Mode>> modes = {
      {"journal-loss", Mode::JournalLoss},
      {"journal-loss-without-log", Mode::JournalLossWithoutLog},
      {"intact-restart", Mode::IntactRestart},
      {"log-rollback", Mode::LogRollback},
      {"window-journal-rollback", Mode::WindowJournalRollback},
      {"window-log-rollback", Mode::WindowLogRollback},
      {"window-log-rollback-without-journal-record", Mode::WindowLogRollbackWithoutJournalRecord},
      {"log-rollback-leader", Mode::LogRollbackLeader},
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
    driver = td::actor::create_actor<Driver>("dlr-driver", *mode);
    td::actor::ask(driver, &Driver::run).detach();
  });
  while (scheduler.run(1)) {
  }
  return 0;
}
