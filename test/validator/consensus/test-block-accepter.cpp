/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
// The production block accepter as a running actor: a finalized block is
// reported accepted (a BlockAccepted trace event) exactly when the manager
// accepted it, and never after a cancelled or a permanently failed
// acceptance, or after the accepter was stopped.
//
// A consensus bus runs the production BlockAccepter and an observer that
// counts BlockAccepted events by candidate. The manager facade is a stand-in
// whose acceptance result the test scripts and whose calls it counts, so a
// negative case cannot pass because the accepter never asked. Each case
// publishes FinalizeBlock for a fresh candidate carrying a real serialized
// block, and checks what the publisher got back and how many BlockAccepted
// events were delivered once delivery has drained:
//
//   success    the manager accepts: the publisher gets OK, exactly one event;
//   cancelled  the manager answers cancelled: the publisher gets cancelled,
//              no event;
//   permanent  the manager answers a permanent error: the publisher gets it,
//              no event;
//   stopped    the manager holds the acceptance; StopRequested is published
//              and the accepter is seen stopped; only then does the manager
//              accept. The late success must not resume the stopped accepter:
//              the publisher gets cancelled and no event is delivered.

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

#include "block/block-parse.h"
#include "block/block.h"
#include "common/errorcode.h"
#include "td/actor/BusRuntime.h"
#include "td/actor/coro_utils.h"
#include "td/utils/logging.h"
#include "validator/consensus/bus.h"
#include "validator/consensus/stats.h"
#include "vm/boc.h"

#include "block-auto.h"

using namespace tos;
using namespace tos::validator;
using namespace tos::validator::consensus;

namespace {

constexpr double STEP_TIMEOUT = 10.0;
// How long delivery is given to drain before a count is final.
constexpr double DRAIN = 0.5;
const CatchainSeqno CC_SEQNO = 77;

td::Bits256 fill(unsigned char byte) {
  td::Bits256 value;
  std::memset(value.data(), byte, 32);
  return value;
}

const ShardIdFull SHARD{basechainId, shardIdAll};
const BlockIdExt MIN_MC_BLOCK_ID{masterchainId, shardIdAll, 0, fill(0xa1), fill(0xa2)};

[[noreturn]] void finish(int code, const std::string& line) {
  std::printf("%s\n", line.c_str());
  std::fflush(stdout);
  std::fflush(stderr);
  std::_Exit(code);
}

[[noreturn]] void fail(const std::string& message) {
  finish(1, "BLOCK_ACCEPTER_FAILURE: " + message);
}

td::Ref<vm::Cell> gen_shard_state(BlockSeqno seqno) {
  return vm::CellBuilder().store_long(0xabcdabcdU, 32).store_long(seqno, 32).finalize_novm();
}

td::Ref<vm::Cell> make_ext_blk_ref(BlockIdExt block_id, LogicalTime lt) {
  vm::CellBuilder cb;
  cb.store_long_bool(lt, 64);
  cb.store_long_bool(block_id.seqno(), 32);
  cb.store_bits_bool(block_id.root_hash);
  cb.store_bits_bool(block_id.file_hash);
  return cb.finalize_novm();
}

// A block the accepter's own parser accepts.
BlockCandidate make_block(BlockSeqno seqno) {
  BlockSeqno prev_seqno = seqno - 1;
  BlockIdExt prev{basechainId, shardIdAll, prev_seqno, fill(static_cast<unsigned char>(0x40 + prev_seqno)),
                  fill(static_cast<unsigned char>(0x50 + prev_seqno))};
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
  info.gen_utime = static_cast<UnixTime>(gen_utime);
  info.start_lt = static_cast<LogicalTime>(seqno) * 1000;
  info.end_lt = static_cast<LogicalTime>(seqno) * 1000 + 1;
  info.gen_validator_list_hash_short = 0;
  info.gen_catchain_seqno = CC_SEQNO;
  info.min_ref_mc_seqno = MIN_MC_BLOCK_ID.seqno();
  info.prev_key_block_seqno = MIN_MC_BLOCK_ID.seqno();
  info.master_ref = make_ext_blk_ref(MIN_MC_BLOCK_ID, 0);
  info.prev_ref = make_ext_blk_ref(prev, static_cast<LogicalTime>(prev_seqno) * 1000 + 1);
  td::Ref<vm::Cell> block_info;
  if (!block::gen::pack_cell(block_info, info)) {
    fail("cannot pack the block info");
  }

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
  auto data = vm::std_boc_serialize(block_root, 31);
  if (data.is_error()) {
    fail("cannot serialize the block: " + data.error().to_string());
  }
  auto collated = vm::std_boc_serialize_multi({vm::CellBuilder{}.store_long(seqno, 32).finalize_novm()}, 2);
  if (collated.is_error()) {
    fail("cannot serialize the collated data: " + collated.error().to_string());
  }
  auto block_data = data.move_as_ok();
  auto collated_data = collated.move_as_ok();
  return BlockCandidate(
      ValidatorId{fill(0x99)},
      BlockIdExt(BlockId(SHARD, seqno), block_root->get_hash().bits(), td::sha256_bits256(block_data)),
      td::sha256_bits256(collated_data), block_data.clone(), collated_data.clone());
}

CandidateRef make_candidate(td::uint32 slot) {
  auto block = make_block(slot + 1);
  auto id = CandidateHashData::create_full(block, std::nullopt).build_id_with(slot);
  return td::make_ref<Candidate>(id, std::nullopt, PeerValidatorId{0}, std::move(block), td::BufferSlice("unsigned"));
}

// ===== What the test observes =====

struct Observations {
  std::mutex mutex;
  std::map<CandidateId, size_t> accepted_events;  // BlockAccepted events by the full candidate id
  size_t accept_calls = 0;
  std::optional<td::actor::StartedTask<td::Unit>::ExternalPromise> held;
};

Observations observations;

size_t accepted_events(const CandidateRef& candidate) {
  std::scoped_lock lock(observations.mutex);
  auto it = observations.accepted_events.find(candidate->id);
  return it == observations.accepted_events.end() ? 0 : it->second;
}

size_t accept_calls() {
  std::scoped_lock lock(observations.mutex);
  return observations.accept_calls;
}

bool is_held() {
  std::scoped_lock lock(observations.mutex);
  return observations.held.has_value();
}

// Counts every BlockAccepted trace event. It deliberately ignores
// StopRequested, so it still sees an event an accepter that failed to stop
// would publish.
class AcceptedObserver : public td::actor::SpawnsWith<Bus>, public td::actor::ConnectsTo<Bus> {
 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();

  template <>
  void handle(BusHandle, std::shared_ptr<const TraceEvent> event) {
    auto accepted = dynamic_cast<const stats::BlockAccepted*>(event->event.get());
    if (accepted == nullptr) {
      return;
    }
    std::scoped_lock lock(observations.mutex);
    observations.accepted_events[accepted->id()]++;
  }
};

enum class Reply { accept, cancelled, permanent, hold };

// The manager: answers each acceptance as the test scripted it.
class ScriptedManager : public ManagerFacade {
 public:
  void set_reply(Reply reply) {
    reply_ = reply;
  }

  // Completes a held acceptance successfully.
  void accept_held() {
    std::optional<td::actor::StartedTask<td::Unit>::ExternalPromise> held;
    {
      std::scoped_lock lock(observations.mutex);
      held = std::move(observations.held);
      observations.held.reset();
    }
    if (!held) {
      fail("no acceptance is held");
    }
    held->set_value(td::Unit{});
  }

  td::actor::Task<GeneratedCandidate> collate_block(CollateParams, td::CancellationToken) override {
    co_return td::Status::Error("this manager does not collate");
  }

  td::actor::Task<ValidateCandidateResult> validate_block_candidate(BlockCandidate, ValidateParams,
                                                                    td::Timestamp) override {
    co_return td::Status::Error("this manager does not validate");
  }

  td::actor::Task<> accept_block(BlockIdExt, td::Ref<BlockData>, size_t, td::Ref<block::BlockSignatureSet>,
                                 ValidatorSessionId, int, int, bool, bool) override {
    {
      std::scoped_lock lock(observations.mutex);
      ++observations.accept_calls;
    }
    switch (reply_) {
      case Reply::accept:
        co_return td::Unit{};
      case Reply::cancelled:
        co_return td::Status::Error(ErrorCode::cancelled, "acceptance cancelled");
      case Reply::permanent:
        co_return td::Status::Error(ErrorCode::error, "acceptance failed permanently");
      case Reply::hold: {
        auto [task, promise] = td::actor::StartedTask<td::Unit>::make_bridge();
        {
          std::scoped_lock lock(observations.mutex);
          observations.held.emplace(std::move(promise));
        }
        co_return co_await std::move(task);
      }
    }
    co_return td::Status::Error("unknown scripted reply");
  }

  td::actor::Task<td::Ref<vm::Cell>> wait_block_state_root(BlockIdExt, td::Timestamp,
                                                           std::optional<CandidateId>) override {
    co_return td::Status::Error(ErrorCode::notready, "no state");
  }

  td::actor::Task<td::Ref<BlockData>> wait_block_data(BlockIdExt, td::Timestamp) override {
    co_return td::Status::Error(ErrorCode::notready, "no block data");
  }

 private:
  Reply reply_ = Reply::accept;
};

class Driver : public td::actor::Actor {
 public:
  td::actor::Task<> run() {
    auto result = co_await run_inner().wrap();
    if (result.is_error()) {
      fail("harness: " + result.error().to_string());
    }
    finish(0, "BLOCK_ACCEPTER_OK");
  }

 private:
  td::actor::Runtime runtime_;
  td::actor::ActorOwn<ScriptedManager> manager_;
  BusHandle bus_;

  void start_bus() {
    runtime_.register_actor<AcceptedObserver>("AcceptedObserver");
    BlockAccepter::register_in(runtime_);

    manager_ = td::actor::create_actor<ScriptedManager>("ScriptedManager");
    auto bus = std::make_shared<Bus>();
    bus->shard = SHARD;
    bus->manager = manager_.get();
    PeerValidator local{.validator_id = ValidatorId{fill(0x70)},
                        .idx = PeerValidatorId{0},
                        .consensus_key = {},
                        .transport_key_id = {},
                        .adnl_id = adnl::AdnlNodeIdShort{fill(0x90)},
                        .weight = 1};
    bus->validator_set = {local};
    bus->total_weight = 1;
    bus->cc_seqno = CC_SEQNO;
    bus->validator_set_hash = 0;
    // A validator, so the accepter is spawned.
    bus->local_id = local;
    bus->local_adnl_id = local.adnl_id;
    bus->session_id = fill(0x42);
    bus->stop_promise = [](td::Result<td::Unit>) {};
    bus_ = runtime_.start(bus, "accepter-test");
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

  td::actor::Task<> drain() {
    co_await td::actor::coro_sleep(td::Timestamp::in(DRAIN));
    co_return td::Unit{};
  }

  // True once the accepter actor has processed its stop. The actor runtime
  // marks an actor closed when it stops; a closed actor runs no further
  // message, including the resumption of a coroutine suspended in it. The
  // actor object itself may outlive this while a suspended coroutine still
  // references it, so its destruction is not the signal.
  bool accepter_stopped() const {
    auto node = bus_.node_for_diagnostics().lock();
    if (!node) {
      fail("the bus tree node is gone");
    }
    bool found = false;
    bool alive = false;
    for (const auto& owned : node->owned_actors) {
      auto info = owned.id.actor_info_ptr();
      if (!info || !td::ends_with(td::Slice(info->get_name()), td::Slice("BlockAccepter"))) {
        continue;
      }
      found = true;
      alive = alive || owned.id.is_alive();
    }
    if (!found) {
      fail("the bus has no BlockAccepter actor");
    }
    return !alive;
  }

  // Publishes FinalizeBlock for `candidate` and requires that the accepter
  // asked the manager once and that the publisher got `expected_code`
  // (0 for success).
  td::actor::Task<> finalize(const CandidateRef& candidate, Reply reply, int expected_code, const std::string& what) {
    td::actor::send_closure(manager_, &ScriptedManager::set_reply, reply);
    auto calls_before = accept_calls();
    auto result = co_await bus_.publish<FinalizeBlock>(candidate, td::Ref<block::BlockSignatureSet>{}).wrap();
    if (accept_calls() != calls_before + 1) {
      fail(PSTRING() << what << ": the accepter asked the manager " << accept_calls() - calls_before
                     << " times, not once");
    }
    if (expected_code == 0) {
      if (result.is_error()) {
        fail(what + ": the publisher got " + result.error().to_string());
      }
    } else if (result.is_ok() || result.error().code() != expected_code) {
      fail(PSTRING() << what << ": the publisher got " << (result.is_ok() ? "OK" : result.error().to_string())
                     << ", not error " << expected_code);
    }
    co_return td::Unit{};
  }

  td::actor::Task<> run_inner() {
    start_bus();

    // Success: exactly one BlockAccepted, counted after delivery has drained,
    // so a duplicate delivered late is seen.
    auto accepted = make_candidate(1);
    co_await finalize(accepted, Reply::accept, 0, "success");
    if (!co_await wait_until([&] { return accepted_events(accepted) >= 1; })) {
      fail("success: no BlockAccepted for an accepted block");
    }
    co_await drain();
    if (accepted_events(accepted) != 1) {
      fail(PSTRING() << "success: " << accepted_events(accepted) << " BlockAccepted events, not one");
    }
    std::printf("  ok: an accepted block is reported accepted once\n");

    auto cancelled = make_candidate(2);
    co_await finalize(cancelled, Reply::cancelled, ErrorCode::cancelled, "cancelled");
    co_await drain();
    if (accepted_events(cancelled) != 0) {
      fail("cancelled: a cancelled acceptance was reported accepted");
    }
    std::printf("  ok: a cancelled acceptance is not reported accepted\n");

    auto permanent = make_candidate(3);
    co_await finalize(permanent, Reply::permanent, ErrorCode::error, "permanent");
    co_await drain();
    if (accepted_events(permanent) != 0) {
      fail("permanent: a failed acceptance was reported accepted");
    }
    std::printf("  ok: a permanently failed acceptance is not reported accepted\n");

    // Stopped: the acceptance is held while the accepter stops, and succeeds
    // only after the accepter is seen stopped.
    auto stopped = make_candidate(4);
    td::actor::send_closure(manager_, &ScriptedManager::set_reply, Reply::hold);
    auto calls_before = accept_calls();
    auto pending = bus_.publish<FinalizeBlock>(stopped, td::Ref<block::BlockSignatureSet>{}).start();
    if (!co_await wait_until([] { return is_held(); })) {
      fail("stopped: the accepter never asked the manager");
    }
    bus_.publish<StopRequested>();
    bool accepter_closed = co_await wait_until([&] { return accepter_stopped(); }, 5.0);
    // Whether or not it stopped, the late success is delivered, so a failure
    // below says what an accepter that outlived its stop did with it.
    td::actor::send_closure(manager_, &ScriptedManager::accept_held);
    auto result = co_await std::move(pending).wrap();
    co_await drain();
    if (!accepter_closed) {
      fail(PSTRING() << "stopped: the accepter outlived StopRequested; after the late success the publisher got "
                     << (result.is_ok() ? "OK" : result.error().to_string()) << " and " << accepted_events(stopped)
                     << " BlockAccepted events were delivered");
    }
    if (accept_calls() != calls_before + 1) {
      fail("stopped: the accepter did not ask the manager exactly once");
    }
    if (result.is_ok() || result.error().code() != ErrorCode::cancelled) {
      fail("stopped: the publisher got " + (result.is_ok() ? std::string("OK") : result.error().to_string()) +
           ", not cancelled");
    }
    if (accepted_events(stopped) != 0) {
      fail("stopped: a stopped accepter reported a late success as accepted");
    }
    std::printf("  ok: a stopped accepter does not report a late success\n");
    co_return td::Unit{};
  }
};

}  // namespace

int main() {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(ERROR));
  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<Driver> driver;
  scheduler.run_in_context([&] {
    driver = td::actor::create_actor<Driver>("accepter-driver");
    td::actor::ask(driver, &Driver::run).detach();
  });
  // The driver ends the process; this loop only runs the scheduler.
  while (scheduler.run(1)) {
  }
  fail("the scheduler stopped before the driver finished");
}
