/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <future>
#include <mutex>
#include <pthread.h>
#include <stdexcept>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

#include "td/actor/actor.h"
#include "validator-engine/control-getter-executor.h"
#include "vm/vm.h"

#include "control-getter-fixture.h"

namespace cg = tos::control_getter;
using namespace getter_fixture;
std::atomic<int> checks{0};
std::atomic<int> failures{0};
std::string zero_path;
std::string fixture_path;
void check(const char* name, bool ok) {
  ++checks;
  if (!ok) {
    ++failures;
    std::fprintf(stderr, "CONTROL_GETTER_FAIL %s\n", name);
  }
}

struct Gate {
  std::mutex mutex;
  std::condition_variable changed;
  bool open{false};
  void release() {
    {
      std::lock_guard lock(mutex);
      open = true;
    }
    changed.notify_all();
  }
  bool wait() {
    std::unique_lock lock(mutex);
    return changed.wait_for(lock, std::chrono::seconds(20), [&] { return open; });
  }
  ~Gate() {
    release();
  }
};
bool eventually(const std::function<bool()>& condition) {
  const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(10);
  while (!condition()) {
    if (std::chrono::steady_clock::now() >= end) {
      return false;
    }
    std::this_thread::yield();
  }
  return true;
}

void executor_test() {
  auto executor = must(cg::Executor::create(), "create executor");
  std::vector<std::unique_ptr<cg::Executor::Admission>> jobs;
  for (int index = 0; index < 10; ++index) {
    jobs.push_back(must(executor->admit(), "reserve ten jobs"));
  }
  auto counts = executor->counts();
  check("executor-reservations-2-8", counts.active == 2 && counts.queued == 8);
  auto rejected = executor->admit();
  check("executor-eleventh-busy", rejected.is_error() && rejected.error().message() == "control getter executor busy");
  Gate gate;
  std::atomic<int> started{0};
  std::atomic<int> finished{0};
  std::atomic<int> wrong_thread{0};
  const auto caller = std::this_thread::get_id();
  for (int index = 0; index < 10; ++index) {
    jobs[static_cast<std::size_t>(index)]
        ->dispatch(
            [&, index] {
              if (std::this_thread::get_id() == caller) {
                ++wrong_thread;
              }
              ++started;
              if (index < 2 && !gate.wait()) {
                return td::Status::Error("test gate timed out");
              }
              return td::Status::OK();
            },
            [&](td::Status result) {
              check("executor-job-success", result.is_ok());
              ++finished;
            })
        .ensure();
  }
  check("executor-two-running", eventually([&] { return started.load() == 2; }));
  auto repeated = jobs[0]->dispatch([] { return td::Status::OK(); }, [](td::Status) {});
  check("executor-second-dispatch-refused",
        repeated.is_error() && repeated.message() == "control getter admission already dispatched");
  jobs[0]->cancel();
  jobs[1].reset();
  counts = executor->counts();
  check("executor-cancel-keeps-reservation", counts.active == 2 && counts.queued == 8);
  rejected = executor->admit();
  check("executor-cancel-still-busy",
        rejected.is_error() && rejected.error().message() == "control getter executor busy");
  gate.release();
  check("executor-all-complete", eventually([&] { return finished.load() == 10; }));
  check("executor-off-caller", wrong_thread.load() == 0);
  check("executor-releases-all", eventually([&] {
          auto c = executor->counts();
          return c.active == 0 && c.queued == 0;
        }));
  auto exception = must(executor->admit(), "exception job");
  std::atomic<bool> exception_reported{false};
  exception
      ->dispatch([]() -> td::Status { throw std::runtime_error("test exception"); },
                 [&](td::Status result) {
                   exception_reported = result.is_error() && result.message() == "control getter worker exception";
                 })
      .ensure();
  check("executor-exception-reported", eventually([&] { return exception_reported.load(); }));
  executor->shutdown();
  rejected = executor->admit();
  check("executor-shutdown-refuses",
        rejected.is_error() && rejected.error().message() == "control getter executor stopped");
}

void shutdown_test() {
  auto executor = must(cg::Executor::create(), "shutdown executor");
  auto running = must(executor->admit(), "running admission");
  auto preparing = must(executor->admit(), "preparing admission");
  auto queued = must(executor->admit(), "queued admission");
  Gate gate;
  std::atomic<bool> started{false};
  std::atomic<int> completions{0};
  std::atomic<bool> queued_ran{false};
  running
      ->dispatch(
          [&] {
            started = true;
            return gate.wait() ? td::Status::OK() : td::Status::Error("gate timeout");
          },
          [&](td::Status) { ++completions; })
      .ensure();
  check("shutdown-running-started", eventually([&] { return started.load(); }));
  queued
      ->dispatch(
          [&] {
            queued_ran = true;
            return td::Status::OK();
          },
          [&](td::Status result) {
            check("shutdown-queued-cancelled",
                  result.is_error() && result.message() == "control getter admission cancelled");
            ++completions;
          })
      .ensure();
  std::atomic<bool> stopped{false};
  std::thread closer([&] {
    executor->shutdown();
    stopped = true;
  });
  check("shutdown-refuses-before-complete", eventually([&] {
          auto result = executor->admit();
          return result.is_error() && result.error().message() == "control getter executor stopped";
        }));
  check("shutdown-waits-running", !stopped.load());
  gate.release();
  closer.join();
  check("shutdown-pending-not-run", !queued_ran.load() && completions.load() == 2);
  check("shutdown-completed", stopped.load());
}

void limits_test() {
  cg::GasBudget budget{100};
  check("gas-exact", budget.charge(100).is_ok() && budget.used() == 100);
  auto error = budget.charge(1);
  check("gas-one-over",
        error.is_error() && error.message() == "control getter aggregate gas limit exceeded" && budget.used() == 100);
  check("gas-negative", budget.charge(-1).is_error());
  cg::ReplyBudget reply;
  check("reply-wrapper-included", reply.reserve(64).is_ok() && reply.reserve(8 * 1024 * 1024 - 64).is_ok());
  error = reply.reserve(1);
  check("reply-one-over", error.is_error() && error.message() == "control getter reply byte limit exceeded");
  error = reply.reserve(std::numeric_limits<std::size_t>::max());
  check("reply-size-overflow", error.is_error());
  auto list = [](std::size_t count) {
    vm::StackEntry tail;
    for (std::size_t index = 0; index < count; ++index) {
      tail = vm::StackEntry::cons(td::make_refint(1), std::move(tail));
    }
    return tail;
  };
  std::size_t visits = 0;
  auto visit = [&](const vm::StackEntry&) {
    ++visits;
    return td::Status::OK();
  };
  check("list-exact-4096", cg::walk_cons(list(4096), cg::kMaxConfigProposals, visit).is_ok() && visits == 4096);
  visits = 0;
  error = cg::walk_cons(list(4097), cg::kMaxConfigProposals, visit);
  check("list-one-over-before-visit",
        error.is_error() && error.message() == "control getter list count limit exceeded" && visits == 4096);
  check("list-number-not-null", cg::walk_cons(vm::StackEntry{td::make_refint(0)}, 4, visit).is_error());
  check("list-extra-field",
        cg::walk_cons(vm::StackEntry{vm::make_tuple_ref(td::make_refint(1), vm::StackEntry{}, td::make_refint(2))}, 4,
                      visit)
            .is_error());
  check("list-arity", cg::walk_cons(vm::StackEntry{vm::make_tuple_ref(td::make_refint(1))}, 4, visit).is_error());
  visits = 0;
  check("list-null-empty", cg::walk_cons(vm::StackEntry{}, 0, visit).is_ok() && visits == 0);
  error = cg::walk_cons(list(2), 4, [](const vm::StackEntry&) { return td::Status::Error("visitor refusal"); });
  check("list-visitor-refused", error.is_error() && error.message() == "visitor refusal");
}

struct Ping final : td::actor::Actor {
  explicit Ping(std::atomic<bool>* answered) : answered_(answered) {
  }
  void ping() {
    *answered_ = true;
  }
  std::atomic<bool>* answered_;
};
void actor_test() {
  auto executor = must(cg::Executor::create(), "actor executor");
  auto admission = must(executor->admit(), "actor admission");
  Gate gate;
  std::atomic<bool> started{false};
  std::atomic<bool> done{false};
  std::atomic<bool> answered{false};
  td::actor::Scheduler scheduler{std::vector<td::actor::Scheduler::NodeInfo>{1}};
  td::actor::ActorOwn<Ping> actor;
  scheduler.run_in_context([&] { actor = td::actor::create_actor<Ping>("control-ping", &answered); });
  admission
      ->dispatch(
          [&] {
            started = true;
            return gate.wait() ? td::Status::OK() : td::Status::Error("gate timeout");
          },
          [&](td::Status) { done = true; })
      .ensure();
  check("actor-getter-started", eventually([&] { return started.load(); }));
  scheduler.run_in_context([&] { td::actor::send_closure(actor.get(), &Ping::ping); });
  for (int pass = 0; pass < 100 && !answered.load(); ++pass) {
    scheduler.run(0.001);
  }
  check("actor-ping-while-getter-running", answered.load() && !done.load());
  gate.release();
  check("actor-getter-finishes", eventually([&] { return done.load(); }));
  scheduler.run_in_context([&] { actor.reset(); });
}

void vm_test() {
  auto code =
      must(fift::compile_asm("DROP c4 PUSH CTOS 32 LDU DROP DUP INC NEWC 32 STU ENDC c4 POP"), "mutable test code");
  auto data = vm::CellBuilder{}.store_long(7, 32).finalize_novm();
  auto state = control_fixture::production_build(zero_path, fixture_path, fixture_path + "/config-code.boc", 17, true,
                                                 {}, {}, code, data);
  auto snapshot = must(cg::Snapshot::create(state.id, state.root), "VM snapshot");
  auto account = must(snapshot->account(filled(0x77)), "VM account");
  cg::GasBudget budget{cg::kElectorStateGasLimit};
  for (int run = 0; run < 2; ++run) {
    auto status = cg::run(*snapshot, account, cg::Getter::Participants, {}, budget, [&](const vm::Stack& stack) {
      check("vm-private-c4-reset", stack.depth() == 1 && stack[0].is_int() && stack[0].as_int()->to_long() == 7);
      return td::Status::OK();
    });
    check("vm-private-c4-success", status.is_ok());
  }
  check("vm-original-roots",
        snapshot->state_root()->get_hash() == state.root->get_hash() && account.data->get_hash() == data->get_hash());
  bool decoded = false;
  cg::GasBudget tiny{0};
  cg::RunStats stats;
  auto status = cg::run(
      *snapshot, account, cg::Getter::Participants, {}, tiny,
      [&](const vm::Stack&) {
        decoded = true;
        return td::Status::OK();
      },
      &stats);
  check("vm-aggregate-only-refused", status.is_error() &&
                                         status.message() == "control getter aggregate gas limit exceeded" &&
                                         stats.exit_code == 0 && !decoded);
  auto missing = snapshot->account(filled(0x88));
  check("snapshot-missing-account",
        missing.is_error() && missing.error().message() == "control getter account is missing");
  auto wrong = state.id;
  ++wrong.id.seqno;
  auto other = cg::Snapshot::create(wrong, state.root);
  check("snapshot-other-height",
        other.is_error() && other.error().message() == "control getter snapshot block identity mismatch");

  auto changed = control_fixture::production_build(zero_path, fixture_path, fixture_path + "/config-code.boc", 17, true,
                                                   {}, {}, code, vm::CellBuilder{}.store_long(9, 32).finalize_novm());
  auto changed_snapshot = must(cg::Snapshot::create(changed.id, changed.root), "other snapshot");
  cg::GasBudget other_budget{cg::kElectorStateGasLimit};
  bool mixed_decoded = false;
  auto mixed = cg::run(*changed_snapshot, account, cg::Getter::Participants, {}, other_budget, [&](const vm::Stack&) {
    mixed_decoded = true;
    return td::Status::OK();
  });
  check("vm-mixed-snapshot-refused",
        mixed.is_error() && mixed.message() == "control getter account belongs to another snapshot" && !mixed_decoded);
  auto spin = must(fift::compile_asm("DROP <{ 0 PUSHINT DROP }> PUSHCONT AGAIN"), "gas exhaustion code");
  auto spun = control_fixture::production_build(zero_path, fixture_path, fixture_path + "/config-code.boc", 17, true,
                                                {}, {}, spin, data);
  auto spun_snapshot = must(cg::Snapshot::create(spun.id, spun.root), "gas snapshot");
  auto spun_account = must(spun_snapshot->account(filled(0x77)), "gas account");
  decoded = false;
  cg::GasBudget ample{cg::kConfigProposalsGasLimit};
  status = cg::run(
      *spun_snapshot, spun_account, cg::Getter::ReturnedStake, {td::make_refint(1)}, ample,
      [&](const vm::Stack&) {
        decoded = true;
        return td::Status::OK();
      },
      &stats);
  check("vm-per-run-gas-refused",
        status.is_error() && status.message() == "control getter per-run gas limit exceeded" && !decoded);
  check("vm-failed-root-unchanged", spun_snapshot->state_root()->get_hash() == spun.root->get_hash());
}

void context_test() {
  auto state = control_fixture::production_build(zero_path, fixture_path, fixture_path + "/config-code.boc");
  auto snapshot = must(cg::Snapshot::create(state.id, state.root), "context snapshot");
  auto account = must(snapshot->account(filled(0x77)), "context account");
  // Context-sensitive bytecode is supplied through a real account in the state.
  cg::GasBudget gas{cg::kElectorStateGasLimit};
  auto status = cg::run(*snapshot, account, cg::Getter::Participants, {}, gas, [&](const vm::Stack& stack) {
    check("context-now", stack.depth() == 4 && stack[3].is_int() && stack[3].as_int()->to_long() == state.now);
    check("context-lt", stack[2].is_int() && stack[2].as_int()->to_long() == static_cast<long long>(state.lt));
    auto balance = stack[1].as_tuple();
    check("context-wide-balance",
          balance.not_null() && balance->at(0).as_int() == account.balance.tomis && balance->at(1).is_cell());
    return td::Status::OK();
  });
  check("context-run", status.is_ok());
  auto library = must(fift::compile_asm("DROP 17 PUSHINT"), "library code");
  auto referenced = library_reference(library);
  for (bool available : {false, true}) {
    auto fixture = control_fixture::production_build(zero_path, fixture_path, fixture_path + "/config-code.boc", 17,
                                                     available, {}, {}, referenced);
    auto snap = must(cg::Snapshot::create(fixture.id, fixture.root), "library snapshot");
    auto guest = must(snap->account(filled(0x77)), "library account");
    cg::GasBudget budget{cg::kElectorStateGasLimit};
    bool decoded = false;
    auto result = cg::run(*snap, guest, cg::Getter::Participants, {}, budget, [&](const vm::Stack& stack) {
      decoded = true;
      check("library-value", stack.depth() == 1 && stack[0].as_int()->to_long() == 17);
      return td::Status::OK();
    });
    check(available ? "library-present" : "library-missing-refused",
          available ? result.is_ok() && decoded : result.is_error() && !decoded);
  }
  // An all-zero signature under a strong public key must fail verification.
  std::string signature(128, '0');
  auto signing =
      must(fift::compile_asm("DROP 0 PUSHINT x{" + signature +
                             "} PUSHSLICE "
                             "0xd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a PUSHINT CHKSIGNU"),
           "signature test code");
  auto fixture = control_fixture::production_build(zero_path, fixture_path, fixture_path + "/config-code.boc", 17, true,
                                                   {}, {}, signing);
  auto snap = must(cg::Snapshot::create(fixture.id, fixture.root), "signature snapshot");
  auto guest = must(snap->account(filled(0x77)), "signature account");
  cg::GasBudget budget{cg::kElectorStateGasLimit};
  status = cg::run(*snap, guest, cg::Getter::Participants, {}, budget, [&](const vm::Stack& stack) {
    check("signature-check-enabled", stack.depth() == 1 && stack[0].is_int() && stack[0].as_int()->to_long() == 0);
    return td::Status::OK();
  });
  check("signature-run", status.is_ok());

  auto failing = must(fift::compile_asm("DROP 11 THROW"), "failed getter code");
  auto failed = control_fixture::production_build(zero_path, fixture_path, fixture_path + "/config-code.boc", 17, true,
                                                  {}, {}, failing);
  auto failed_snapshot = must(cg::Snapshot::create(failed.id, failed.root), "failed getter snapshot");
  auto failed_account = must(failed_snapshot->account(filled(0x77)), "failed getter account");
  cg::GasBudget failed_budget{cg::kElectorStateGasLimit};
  bool accepted = false;
  status =
      cg::run(*failed_snapshot, failed_account, cg::Getter::Participants, {}, failed_budget, [&](const vm::Stack&) {
        accepted = true;
        return td::Status::OK();
      });
  check("vm-exit-refused", status.is_error() && status.message() == "control getter VM exit 11" && !accepted);
  // Sending an action only changes the private VM's c5; it is never executed.
  auto sending = must(fift::compile_asm("DROP NEWC ENDC 0 PUSHINT SENDRAWMSG 7 PUSHINT"), "action test code");
  auto sent = control_fixture::production_build(zero_path, fixture_path, fixture_path + "/config-code.boc", 17, true,
                                                {}, {}, sending);
  auto sent_snapshot = must(cg::Snapshot::create(sent.id, sent.root), "action snapshot");
  auto sent_account = must(sent_snapshot->account(filled(0x77)), "action account");
  cg::GasBudget sent_budget{cg::kElectorStateGasLimit};
  status = cg::run(*sent_snapshot, sent_account, cg::Getter::Participants, {}, sent_budget,
                   [](const vm::Stack&) { return td::Status::OK(); });
  check("actions-discarded", status.is_ok() && sent_snapshot->state_root()->get_hash() == sent.root->get_hash());
}

void* deep_drop(void*) {
  vm::StackEntry root;
  for (int index = 0; index < 200000; ++index) {
    root = vm::StackEntry::cons(td::make_refint(1), std::move(root));
  }
  root.clear();
  return nullptr;
}
void deletion_test() {
  pid_t child = fork();
  require(child >= 0, "fork deletion test");
  if (child == 0) {
    pthread_attr_t attributes;
    if (pthread_attr_init(&attributes) != 0 || pthread_attr_setstacksize(&attributes, 256 * 1024) != 0) {
      _exit(2);
    }
    pthread_t thread;
    if (pthread_create(&thread, &attributes, deep_drop, nullptr) != 0) {
      _exit(2);
    }
    if (pthread_join(thread, nullptr) != 0 || pthread_attr_destroy(&attributes) != 0) {
      _exit(2);
    }
    _exit(0);
  }
  int status = 0;
  require(waitpid(child, &status, 0) == child, "deletion child reaped");
  check("deep-drop-small-stack", WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(ERROR));
  vm::init_vm().ensure();
  require(argc == 4, "usage: test-control-getter ZEROSTATE FIXTURES CASE");
  zero_path = argv[1];
  fixture_path = argv[2];
  std::string selected = argv[3];
  if (selected == "executor") {
    executor_test();
  }
  if (selected == "shutdown") {
    shutdown_test();
  }
  if (selected == "limits") {
    limits_test();
  }
  if (selected == "actor") {
    actor_test();
  }
  if (selected == "vm") {
    vm_test();
  }
  if (selected == "context") {
    context_test();
  }
  if (selected == "delete") {
    deletion_test();
  }
  require(checks.load() > 0, "selected test executes assertions");
  std::printf("CONTROL_GETTER_RESULT checks=%d failures=%d\n", checks.load(), failures.load());
  return failures.load() == 0 ? 0 : 1;
}
