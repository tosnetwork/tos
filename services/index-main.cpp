/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#include <filesystem>
#include <iostream>
#include <thread>

#include "block/block-auto.h"
#include "td/utils/OptionParser.h"
#include "td/utils/misc.h"
#include "td/utils/port/signals.h"
#include "validator-engine/wallet-index-writer.h"
#include "validator-engine/wallet-index.h"
#include "validator/db/archive-slice.hpp"
#include "validator/validator-options.hpp"

#include "index-prefetch.h"
#include "index-progress.h"
#include "index-reader.h"
#include "index-replay-loop.h"
#include "index-verify.h"

int main(int argc, char** argv) {
  using namespace tos;
  using namespace tos::services;
  SET_VERBOSITY_LEVEL(verbosity_WARNING);
  std::string source, data;
  uint32_t ceiling = 0;
  bool allow_partial = false;
  td::IPAddress listen;
  listen.init_host_port("127.0.0.1:8081").ensure();
  td::OptionParser parser;
  parser.set_description("Standalone wallet index. Requires a local archive node database mounted read-only.");
  parser.add_option('h', "help", "show help", [&] {
    std::cout << (PSTRING() << parser);
    std::exit(0);
  });
  parser.add_option('\0', "source-db", "read-only node database root", [&](td::Slice v) { source = v.str(); });
  parser.add_option('\0', "data-dir", "separate writable service directory", [&](td::Slice v) { data = v.str(); });
  parser.add_checked_option('\0', "listen", "internal HTTP address (loopback only)",
                            [&](td::Slice v) { return listen.init_host_port(v.str()); });
  parser.add_checked_option('\0', "replay-ceiling",
                            "replay no further than this masterchain block (for measurement and comparison; the "
                            "index is never ready while it stops short of the source tip)",
                            [&](td::Slice v) -> td::Status {
                              TRY_RESULT(value, td::to_integer_safe<uint32_t>(v));
                              if (value == 0)
                                return td::Status::Error("replay ceiling must be positive");
                              ceiling = value;
                              return td::Status::OK();
                            });
  parser.add_option('\0', "allow-partial-verification",
                    "serve an index imported from an untrusted snapshot once it is partly verified against this "
                    "node, flagging every answer the node's chain does not yet vouch for (default: serve only a "
                    "fully verified index)",
                    [&] { allow_partial = true; });
  auto parsed = parser.run(argc, argv);
  if (parsed.is_error() || source.empty() || data.empty() || !json_rpc::is_loopback_bind_address(listen)) {
    LOG(ERROR) << "specify --source-db and --data-dir and a loopback --listen";
    return 2;
  }
  std::error_code error;
  auto source_path = std::filesystem::canonical(source, error);
  if (error || !std::filesystem::exists(source_path / "celldb", error)) {
    LOG(ERROR) << "source must be an existing node database";
    return 2;
  }
  auto data_path = std::filesystem::weakly_canonical(data, error);
  auto nested = [](const auto& a, const auto& b) {
    auto relative = b.lexically_relative(a);
    return relative.empty() || *relative.begin() != "..";
  };
  if (error || nested(source_path, data_path) || nested(data_path, source_path)) {
    LOG(ERROR) << "source and service directories must not overlap";
    return 2;
  }
  std::filesystem::create_directories(data_path, error);
  if (error) {
    LOG(ERROR) << "cannot create service directory";
    return 2;
  }
  for (auto name : {"index", "secondary"}) {
    auto path = std::filesystem::weakly_canonical(data_path / name, error);
    if (error || !nested(data_path, path) || nested(source_path, path)) {
      LOG(ERROR) << "service subdirectories must stay inside data-dir";
      return 2;
    }
  }
  auto index = tos_wallet_index::WalletIndexDb::open((data_path / "index").string());
  if (index.is_error()) {
    LOG(ERROR) << index.error();
    return 2;
  }
  // An index imported from an untrusted snapshot is never served before it
  // has been checked against this node's own chain (services/index-verify.h).
  ServingGate gate(allow_partial);
  bool prepared = false;
  // The block pass over the verified window has finished (stage 4a).
  bool pass_done = false;
  // A fresh index is not served until the source has shown whether it holds
  // masterchain block 1 (a fresh replay) or not (a build from the window).
  bool deciding = false;
  // The index is being built from the window's blocks (stage 4c).
  bool building = false;
  {
    using tos_wallet_index::VerificationState;
    auto state = index.ok()->get_verification_state();
    if (state.is_error()) {
      LOG(ERROR) << "cannot read the index verification state: " << state.error();
      return 2;
    }
    auto record = index.ok()->verification_record();
    if (record.is_error()) {
      LOG(ERROR) << "cannot read the index verification record: " << record.error();
      return 2;
    }
    gate.set(state.ok());
    auto fresh = index.ok()->is_fresh();
    auto build = index.ok()->build_record();
    if (fresh.is_error() || build.is_error()) {
      LOG(ERROR) << "cannot read the index's state: " << (fresh.is_error() ? fresh.error() : build.error());
      return 2;
    }
    if (build.ok()) {
      // A build that did not finish: it resumes, never served meanwhile.
      building = true;
      gate.set(VerificationState::Quarantined);
      gate.hold("build: resuming");
    } else if (fresh.ok()) {
      deciding = true;
      gate.set(VerificationState::Quarantined);
      gate.hold("deciding between a replay from block 1 and a build");
    }
    if (record.ok()) {
      const auto& stored = record.ok().value();
      prepared = true;
      gate.set_horizon(stored.horizon_seqno, stored.horizon_time, stored.unverified);
    }
    if (state.ok() == VerificationState::Refused) {
      LOG(ERROR) << "the index was imported from an untrusted snapshot and was refused by its verification "
                    "against this node; import another snapshot into a fresh directory";
      return 2;
    }
    if (state.ok() == VerificationState::Partial) {
      auto done = block_pass_done(*index.ok());
      if (done.is_error()) {
        LOG(ERROR) << "cannot read the block pass record: " << done.error();
        return 2;
      }
      pass_done = done.ok();
      gate.hold(pass_done ? "ownership: resuming" : "blocks: resuming");
      LOG(WARNING) << "the index was imported from an untrusted snapshot and is partly verified against this node; "
                   << (allow_partial ? "serving it with unverified answers flagged"
                                     : "not serving it until it is fully verified")
                   << " while its verification continues";
    }
    if (state.ok() == VerificationState::Quarantined) {
      LOG(WARNING) << "the index was imported from an untrusted snapshot: verifying it against this node before "
                      "serving";
    }
  }
  Progress progress;
  progress.ceiling = ceiling;
  ReplayStats stats;
  auto source_core = SourceCore::create(SourceLimits{});
  if (source_core.is_error()) {
    LOG(ERROR) << source_core.error();
    return 2;
  }
  auto core = source_core.move_as_ok();
  // Before anything listens: the first /readyz after a restart reports the
  // durable cursor, not 0.
  auto loaded = load_checkpoint_progress(*index.ok(), progress);
  if (loaded.is_error()) {
    LOG(WARNING) << "cannot read the replay checkpoint before serving: " << loaded;
  }
  tos_wallet_index::set_wallet_index_db(index.move_as_ok());
  td::set_default_failure_signal_handler().ensure();
  td::set_signal_handler(td::SignalType::Quit, request_stop).ensure();
  td::actor::Scheduler scheduler({4});
  td::actor::ActorOwn<validator::RootDb> db;
  td::actor::ActorOwn<JsonRpcServer> server;
  td::actor::ActorOwn<SourceInbox> inbox;
  auto started = td::Time::now();
  auto stats_snapshot = [&] {
    return stats.snapshot(td::Time::now() - started, validator::archive_slice_opens(),
                          validator::archive_slice_closes(), &core->counters());
  };
  scheduler.run_in_context([&] {
    vm::init_vm().ensure();
    auto options = validator::ValidatorManagerOptions::create(BlockIdExt{}, BlockIdExt{});
    options.write().set_secondary_working_dir((data_path / "secondary").string());
    options.write().set_disable_rocksdb_stats(true);
    options.write().set_celldb_cache_size(128u << 20);
    options.write().set_max_open_archive_files(128);
    db = td::actor::create_actor<validator::RootDb>("index-source", td::actor::ActorId<validator::ValidatorManager>{},
                                                    source_path.string(), options, td::DbOpenMode::db_secondary);
    inbox = SourceInbox::create(core);
    JsonRpcServer::Options rpc;
    rpc.index_only = true;
    rpc.trust_proxy_headers = true;
    rpc.readonly = true;
    // Never ready while replay is held at the verified head, even when that
    // head is still the source tip.
    // Never ready either while history would fail closed: a nonzero window
    // base without its block's record.
    rpc.index_ready = [&] {
      auto* db = tos_wallet_index::wallet_index_db();
      return gate.serving() && !gate.held() && progress.is_ready(td::Time::now()) && db != nullptr &&
             db->history_window().is_ok();
    };
    rpc.index_progress = [&] { return progress.json(td::Time::now()); };
    rpc.index_readyz_body = [&] {
      auto body = progress.readyz_json(td::Time::now(), stats_snapshot());
      body.pop_back();
      return body + gate.json_fields() + "}";
    };
    rpc.index_serving = [&] { return gate.serving(); };
    rpc.index_partial = [&] { return gate.partial(); };
    server = JsonRpcServer::create({}, std::move(rpc));
    td::actor::send_closure(server, &JsonRpcServer::listen, listen);
  });
  IndexReader reader(db.get(), core, std::chrono::seconds(30), &stats);
  // Set by the replay thread when verification decides the service stops.
  std::atomic<int> exit_code{0};
  auto stop_with = [&](int code) {
    exit_code = code;
    request_stop(0);
  };
  std::thread worker([&] {
    auto verify_source = make_reader_verify_source(reader);
    std::string waiting;
    // The writer's state fetcher is pinned to the verified head's states.
    bool pinned_to_head = false;
    // A verification step failed. A terminal error stops the service; any
    // other is retried after a delay that grows to a cap, visible in /readyz
    // and logged at a bounded rate. Returns false when the service stops.
    auto verification_failed = [&](const td::Status& error, const char* step) {
      if (is_terminal_verify_error(error)) {
        LOG(ERROR) << "cannot verify the imported index " << step << ": " << error.message();
        stop_with(1);
        return false;
      }
      if (gate.retry.failed(error.message(), td::Time::now(), static_cast<uint32_t>(td::Clocks::system()))) {
        LOG(WARNING) << "imported index verification paused " << step << " (attempt " << gate.retry.attempts()
                     << "): " << error.message();
      }
      while (!stop_requested.load() && td::Time::now() < gate.retry.next_attempt()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
      return !stop_requested.load();
    };
    // Joined, with every interval it read ahead released, before this
    // thread ends and so before the source scheduler is torn down.
    Prefetcher prefetcher(reader, Prefetcher::Options{});
    prefetcher.start();
    ReplayLoop replay(reader, prefetcher, progress, stats, ceiling, *verify_source);
    // A nonzero base without its block's record (written before records
    // existed) gets its record from this node's block, retried with a backoff
    // while replay goes on; until then history reads fail closed and /readyz
    // is not ready.
    WindowBaseBackfill backfill;
    std::string backfill_error;
    // Periodic operator line: where replay time went in the last interval.
    constexpr double kStatsLogInterval = 60.0;
    auto logged = stats_snapshot();
    double fds_sampled_at = 0;
    tos_wallet_index::set_wc0_index_state_fetcher(
        [&](const td::Bits256& address, auto done) { done(replay.newest(address)); });
    while (!stop_requested.load()) {
      auto now = td::Time::now();
      if (backfill.owed()) {
        auto backfilled = backfill.step(*tos_wallet_index::wallet_index_db(), *verify_source, now);
        if (backfilled.is_error() && backfilled.message().str() != backfill_error) {
          backfill_error = backfilled.message().str();
          LOG(WARNING) << "the window base has no record yet: " << backfill_error;
        }
      }
      if (now - fds_sampled_at >= 1.0) {
        stats.open_fds = count_open_fds();
        fds_sampled_at = now;
      }
      if (now - started - logged.uptime_s >= kStatsLogInterval) {
        auto current = stats_snapshot();
        LOG(WARNING) << replay_stats_log_line(current, logged);
        logged = current;
      }
      auto* index_db = tos_wallet_index::wallet_index_db();
      if (deciding) {
        // A node that has applied no masterchain block yet does not hold
        // block 1 either: the decision waits for its first one.
        auto tip = verify_source->tip();
        if (tip.is_ok() && (!tip.ok().is_masterchain() || tip.ok().seqno() == 0)) {
          tip = td::Status::Error("the source has applied no masterchain block yet");
        }
        if (tip.is_error()) {
          if (stop_requested.load() ||
              !verification_failed(tip.error(), "while waiting for the source's first block")) {
            break;
          }
          continue;
        }
        auto first = verify_source->masterchain_block(1);
        if (first.is_error()) {
          if (stop_requested.load() || !verification_failed(first.error(), "while looking for masterchain block 1")) {
            break;
          }
          continue;
        }
        gate.retry.succeeded();
        deciding = false;
        if (first.ok()) {
          // A replay from block 1 builds a fully verified index by itself.
          gate.release();
          gate.set(tos_wallet_index::VerificationState::Full);
        } else {
          building = true;
          LOG(WARNING) << "the source does not hold masterchain block 1: building the index from the window's blocks";
        }
        continue;
      }
      if (building) {
        auto outcome = run_build_step(*index_db, *verify_source, VerifyLimits{}, &stop_requested);
        if (outcome.is_error()) {
          if (stop_requested.load() || !verification_failed(outcome.error(), "building from the window's blocks")) {
            break;
          }
          continue;
        }
        gate.retry.succeeded();
        auto& done = outcome.ok();
        if (done.step == VerifyStep::Working) {
          gate.hold(done.reason);
          continue;
        }
        auto published = index_db->verification_record();
        if (published.is_error() || !published.ok()) {
          LOG(ERROR) << "the built index has no verification record after its publication";
          stop_with(1);
          break;
        }
        const auto& stored = published.ok().value();
        gate.set_horizon(stored.horizon_seqno, stored.horizon_time, stored.unverified);
        building = false;
        prepared = true;
        pass_done = true;
        gate.hold("ownership: starting");
        gate.set(tos_wallet_index::VerificationState::Partial);
        LOG(WARNING) << "the index was " << done.reason << "; deriving ownership at that head, replay held";
        continue;
      }
      auto action = next_service_action(gate.state(), prepared, pass_done);
      if (action == ServiceAction::Stop) {
        stop_with(2);
        break;
      }
      if (action == ServiceAction::HoldForOwnership) {
        // Ownership derived at the verified head, replay still held.
        auto outcome = run_ownership_step(*index_db, *verify_source, VerifyLimits{}, &stop_requested);
        if (outcome.is_error()) {
          if (stop_requested.load() || !verification_failed(outcome.error(), "deriving ownership at the head")) {
            break;
          }
          continue;
        }
        gate.retry.succeeded();
        auto& done = outcome.ok();
        if (done.step == VerifyStep::Working) {
          gate.hold(done.reason);
          if (done.drain) {
            if (!pinned_to_head) {
              // Every retry of the token work reads the verified head's
              // states, and no state the writer cached before.
              auto checkpoint = index_db->replay_checkpoint();
              if (checkpoint.is_error() || !checkpoint.ok()) {
                LOG(ERROR) << "cannot read the verified head to pin its states";
                stop_with(1);
                break;
              }
              auto states = verify_source->head_states(checkpoint.ok().value().committed);
              if (states.is_error()) {
                if (!verification_failed(states.error(), "pinning the head's states")) {
                  break;
                }
                continue;
              }
              pin_writer_to_head(states.move_as_ok());
              pinned_to_head = true;
            }
            if (!tos_wallet_index::drain_wc0_ownership(&stop_requested)) {
              for (int i = 0; i < 10 && !stop_requested.load(); ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
          }
          continue;
        }
        // Full: replay resumes, its token work against its own newest states.
        tos_wallet_index::release_wc0_index_state();
        tos_wallet_index::set_wc0_index_state_fetcher(
            [&](const td::Bits256& address, auto done_fetch) { done_fetch(replay.newest(address)); });
        pinned_to_head = false;
        gate.set(tos_wallet_index::VerificationState::Full);
        gate.release();
        LOG(WARNING) << "the imported index is " << done.reason;
        continue;
      }
      if (action == ServiceAction::Prepare) {
        // Nothing is replayed onto an imported index before its rows have
        // their place in the window from this node's own blocks.
        auto outcome = prepare_quarantined_index(*index_db, *verify_source);
        if (outcome.is_error()) {
          if (!verification_failed(outcome.error(), "while placing its rows in the window")) {
            break;
          }
          continue;
        }
        gate.retry.succeeded();
        auto& done = outcome.ok();
        if (done.step == VerifyStep::Wait) {
          if (done.reason != waiting) {
            LOG(WARNING) << "imported index verification waits: " << done.reason;
            waiting = done.reason;
          }
          for (int i = 0; i < 50 && !stop_requested.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
          continue;
        }
        if (done.step == VerifyStep::Refused) {
          gate.set(tos_wallet_index::VerificationState::Refused);
          LOG(ERROR) << "the imported index is refused: " << done.reason;
          stop_with(2);
          break;
        }
        auto record = index_db->verification_record();
        if (record.is_error() || !record.ok()) {
          LOG(ERROR) << "the imported index has no verification record after its preparation";
          stop_with(1);
          break;
        }
        const auto& stored = record.ok().value();
        gate.set_horizon(stored.horizon_seqno, stored.horizon_time, 0);
        prepared = true;
        LOG(WARNING) << "imported index prepared: " << done.kept << " rows in the window from masterchain block "
                     << stored.base << ", " << done.dropped << " older rows dropped; replaying to the node's head";
      }
      if (action == ServiceAction::BlockPass) {
        // Replay, its drain and its pruning are held at the verified head
        // while the window's blocks are checked: the pass compares against
        // exactly the index as verified there.
        auto outcome = run_block_pass_step(*index_db, *verify_source, VerifyLimits{}, &stop_requested);
        if (outcome.is_error()) {
          if (stop_requested.load() || !verification_failed(outcome.error(), "over the window's blocks")) {
            break;
          }
          continue;
        }
        gate.retry.succeeded();
        auto& done = outcome.ok();
        if (done.step == VerifyStep::Refused) {
          gate.set(tos_wallet_index::VerificationState::Refused);
          LOG(ERROR) << "the imported index is refused by the window's blocks: " << done.reason;
          stop_with(2);
          break;
        }
        if (done.step == VerifyStep::Working) {
          gate.hold(done.reason);
          continue;
        }
        pass_done = true;
        gate.hold("ownership: starting");
        LOG(WARNING) << "the window's blocks match the imported index; deriving ownership at the head, replay "
                        "held";
        continue;
      }
      auto status = replay.step();
      if (status.is_error()) {
        progress.ready = false;
        LOG(WARNING) << "replay paused: " << status;
      }
      if (status.is_ok() && gate.state() == tos_wallet_index::VerificationState::Quarantined && progress.ready.load()) {
        auto checkpoint = index_db->replay_checkpoint();
        if (checkpoint.is_error() || !checkpoint.ok()) {
          LOG(ERROR) << "cannot read the replay checkpoint to verify the imported index at";
          stop_with(1);
          break;
        }
        auto head = checkpoint.ok().value().committed;
        auto outcome = verify_index_at_head(*index_db, *verify_source, head);
        if (outcome.is_error()) {
          if (!verification_failed(outcome.error(), "at the node's head")) {
            break;
          }
          continue;
        }
        gate.retry.succeeded();
        auto& done = outcome.ok();
        if (done.step == VerifyStep::Refused) {
          gate.set(tos_wallet_index::VerificationState::Refused);
          LOG(ERROR) << "the imported index is refused at masterchain block " << head.seqno() << ": " << done.reason;
          stop_with(2);
          break;
        }
        auto record = index_db->verification_record();
        if (record.is_error() || !record.ok()) {
          LOG(ERROR) << "the imported index has no verification record after its check";
          stop_with(1);
          break;
        }
        const auto& stored = record.ok().value();
        gate.set_horizon(stored.horizon_seqno, stored.horizon_time, stored.unverified);
        // Held before it is Partial, so it is never ready in between.
        gate.hold("blocks: starting");
        gate.set(tos_wallet_index::VerificationState::Partial);
        LOG(WARNING) << "the imported index is partly verified at masterchain block " << head.seqno() << ": "
                     << done.unverified << " accounts need the window's blocks, and ownership is not yet derived";
      }
      if (status.is_error() || replay.idle()) {
        for (int i = 0; i < (status.is_error() ? 50 : 10) && !stop_requested.load(); ++i)
          std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
    }
    tos_wallet_index::set_wc0_index_state_fetcher(nullptr);
  });
  // Source requests wake the scheduler themselves; this loop only notices a
  // stop requested by a signal.
  while (scheduler.run(0.05)) {
    if (stop_requested.load()) {
      core->shutdown();
      scheduler.stop();
    }
  }
  stop_requested = true;
  core->shutdown();
  worker.join();
  tos_wallet_index::release_wc0_index_state();
  tos_wallet_index::set_wallet_index_db(nullptr);
  if (exit_code.load() != 0) {
    return exit_code.load();
  }
  return reader.timed_out() ? 1 : 0;
}
