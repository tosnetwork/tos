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

int main(int argc, char** argv) {
  using namespace tos;
  using namespace tos::services;
  SET_VERBOSITY_LEVEL(verbosity_WARNING);
  std::string source, data;
  uint32_t ceiling = 0;
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
  {
    // An index imported from an untrusted snapshot is never served before it
    // has been checked against this node's own chain.
    auto state = index.ok()->get_verification_state();
    if (state.is_error()) {
      LOG(ERROR) << "cannot read the index verification state: " << state.error();
      return 2;
    }
    if (state.ok() != tos_wallet_index::VerificationState::Full) {
      LOG(ERROR) << "the index was imported from an untrusted snapshot and is not verified against this node; "
                    "this build cannot verify it yet, so it refuses to serve it";
      return 2;
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
    rpc.index_ready = [&] { return progress.is_ready(td::Time::now()); };
    rpc.index_progress = [&] { return progress.json(td::Time::now()); };
    rpc.index_readyz_body = [&] { return progress.readyz_json(td::Time::now(), stats_snapshot()); };
    server = JsonRpcServer::create({}, std::move(rpc));
    td::actor::send_closure(server, &JsonRpcServer::listen, listen);
  });
  IndexReader reader(db.get(), core, std::chrono::seconds(30), &stats);
  std::thread worker([&] {
    // Joined, with every interval it read ahead released, before this
    // thread ends and so before the source scheduler is torn down.
    Prefetcher prefetcher(reader, Prefetcher::Options{});
    prefetcher.start();
    ReplayLoop replay(reader, prefetcher, progress, stats, ceiling);
    // Periodic operator line: where replay time went in the last interval.
    constexpr double kStatsLogInterval = 60.0;
    auto logged = stats_snapshot();
    double fds_sampled_at = 0;
    tos_wallet_index::set_wc0_index_state_fetcher(
        [&](const td::Bits256& address, auto done) { done(replay.newest(address)); });
    while (!stop_requested.load()) {
      auto now = td::Time::now();
      if (now - fds_sampled_at >= 1.0) {
        stats.open_fds = count_open_fds();
        fds_sampled_at = now;
      }
      if (now - started - logged.uptime_s >= kStatsLogInterval) {
        auto current = stats_snapshot();
        LOG(WARNING) << replay_stats_log_line(current, logged);
        logged = current;
      }
      auto status = replay.step();
      if (status.is_error()) {
        progress.ready = false;
        LOG(WARNING) << "replay paused: " << status;
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
  return reader.timed_out() ? 1 : 0;
}
