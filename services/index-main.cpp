/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#include <filesystem>
#include <iostream>
#include <sys/resource.h>
#include <thread>

#include "block/block-auto.h"
#include "td/utils/OptionParser.h"
#include "td/utils/port/signals.h"
#include "validator-engine/wallet-index-writer.h"
#include "validator-engine/wallet-index.h"
#include "validator/db/archive-slice.hpp"
#include "validator/validator-options.hpp"

#include "index-reader.h"
#include "index-replay.h"
#include "source-admission.h"

namespace tos::services {
namespace {
using namespace tos_wallet_index;
struct Progress {
  std::atomic<uint32_t> cursor{0}, tip{0};
  std::atomic<bool> ready{false};
  std::atomic<double> checked_at{0};
  bool is_ready() const {
    return ready.load() && td::Time::now() - checked_at.load() <= 5.0;
  }
  std::string json() const {
    return "{\"masterchain_seqno\":" + std::to_string(cursor.load()) +
           ",\"source_seqno\":" + std::to_string(tip.load()) + ",\"caught_up\":" + (is_ready() ? "true" : "false") +
           "}";
  }
};

class Replay {
 public:
  Replay(IndexReader& reader, Progress& progress) : reader_(reader), progress_(progress) {
  }
  bool idle() const {
    return progress_.ready.load() && !background_progress_;
  }
  td::Status step() {
    background_progress_ = false;
    TRY_RESULT(tip, reader_.tip());
    if (!tip.is_masterchain() || !tip.seqno())
      return td::Status::Error("source has no applied masterchain block");
    progress_.tip = tip.seqno();
    if (checkpoint_.committed != tip)
      progress_.ready = false;
    TRY_RESULT(top, reader_.handle(tip));
    TRY_RESULT(top_root, reader_.block(top));
    TRY_RESULT(heads, index_shard_heads(top_root));
    heads_ = std::move(heads);
    auto db = wallet_index_db();
    if (!initialized_) {
      TRY_RESULT(anchor, reader_.masterchain(1));
      TRY_STATUS(db->initialize_replay(anchor->id()));
      TRY_RESULT(stored, db->replay_checkpoint());
      CHECK(stored);
      checkpoint_ = stored.value();
      if (checkpoint_.committed.seqno()) {
        TRY_RESULT(committed, reader_.masterchain(checkpoint_.committed.seqno()));
        if (committed->id() != checkpoint_.committed)
          return td::Status::Error("source differs from committed replay chain");
      }
      initialized_ = true;
      progress_.cursor = checkpoint_.committed.seqno();
    }
    if (checkpoint_.committed.seqno() > tip.seqno())
      return td::Status::Error("source is behind durable index progress");
    if (checkpoint_.committed.seqno() < tip.seqno()) {
      auto next = checkpoint_.committed.seqno() + 1;
      TRY_RESULT(master, reader_.masterchain(next));
      if (!master->is_applied())
        return td::Status::Error("masterchain block not applied");
      if (next > 1 && (!master->inited_prev() || master->one_prev(true) != checkpoint_.committed)) {
        return td::Status::Error("noncontiguous masterchain replay");
      }
      TRY_RESULT(root, reader_.block(master));
      TRY_RESULT(todo, index_shard_heads(root));
      TRY_RESULT(blocks, replay_interval(std::move(todo), next, [&](BlockIdExt id) { return reader_.handle(id); }));
      for (auto& handle : blocks) {
        if (stop_requested.load())
          return td::Status::Error("replay interrupted");
        TRY_RESULT(block, reader_.block(handle));
        auto result = wc0_index_block(std::move(block), {}, handle->id(), true);
        if (result != Wc0IndexResult::Done) {
          if (drain_wc0_index(&stop_requested) && result == Wc0IndexResult::AtPendingCap)
            return td::Status::OK();
          return td::Status::Error("index block not committed; retrying from checkpoint");
        }
      }
      auto committed = checkpoint_;
      committed.committed = master->id();
      {
        std::lock_guard<std::mutex> guard(db->write_mutex());
        TRY_STATUS(db->commit_replay_checkpoint(committed));
      }
      checkpoint_ = committed;
      progress_.cursor = committed.committed.seqno();
    }
    if (stop_requested.load())
      return td::Status::Error("replay interrupted");
    background_progress_ = drain_wc0_index(&stop_requested);
    // HTTP handlers independently report the persisted token backlog. This
    // flag only says the block replay has reached the observed source tip.
    progress_.checked_at = td::Time::now();
    progress_.ready = checkpoint_.committed == tip;
    return td::Status::OK();
  }
  td::Result<Wc0NewestState> newest(const td::Bits256& address) {
    for (auto id : heads_) {
      if (!wallet_index_state_contains(id.shard_full(), address))
        continue;
      TRY_RESULT(handle, reader_.handle(id));
      TRY_RESULT(root, reader_.state(handle));
      block::gen::ShardStateUnsplit::Record state;
      if (!tlb::unpack_cell(root, state))
        return td::Status::Error("invalid latest shard state");
      return Wc0NewestState{id, state.gen_lt, std::move(root)};
    }
    return td::Status::Error("source has no shard for this account");
  }

 private:
  IndexReader& reader_;
  Progress& progress_;
  bool initialized_ = false;
  bool background_progress_ = false;
  WalletIndexDb::ReplayCheckpoint checkpoint_;
  std::vector<BlockIdExt> heads_;
};
}  // namespace
}  // namespace tos::services

int main(int argc, char** argv) {
  using namespace tos;
  using namespace tos::services;
  SET_VERBOSITY_LEVEL(verbosity_WARNING);
  std::string source, data;
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
  size_t archive_open_files = 128;
  size_t archive_keep_recent = 2;
  parser.add_checked_option('\0', "archive-open-files",
                            "target for descriptors held by older source archive slices (default 128)",
                            [&](td::Slice v) -> td::Status {
                              TRY_RESULT(value, td::to_integer_safe<size_t>(v));
                              if (value == 0 || value > 1000000)
                                return td::Status::Error("archive-open-files must be between 1 and 1000000");
                              archive_open_files = value;
                              return td::Status::OK();
                            });
  parser.add_checked_option('\0', "archive-keep-recent",
                            "most recently read source archive slices kept open past that target (default 2; 0 "
                            "closes a slice that exceeds the target after every read)",
                            [&](td::Slice v) -> td::Status {
                              TRY_RESULT(value, td::to_integer_safe<size_t>(v));
                              if (value > 16)
                                return td::Status::Error("archive-keep-recent must be between 0 and 16");
                              archive_keep_recent = value;
                              return td::Status::OK();
                            });
  parser.add_checked_option('\0', "listen", "internal HTTP address (loopback only)",
                            [&](td::Slice v) { return listen.init_host_port(v.str()); });
  auto parsed = parser.run(argc, argv);
  if (parsed.is_error()) {
    LOG(ERROR) << parsed.error();
    return 2;
  }
  if (source.empty() || data.empty() || !json_rpc::is_loopback_bind_address(listen)) {
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
  // Descriptors: slices kept open past the target are bounded by a budget
  // derived from the descriptor limit, which is raised to its hard maximum.
  // The budget leaves a margin for sockets and other files opened between
  // checks; a limit too low for the target plus that headroom is refused here,
  // and every source read is admitted against the budget at run time.
  constexpr rlim_t kDescriptorMargin = 256;
  constexpr rlim_t kMinimumHeadroom = 1024;
  struct rlimit limit{};
  if (getrlimit(RLIMIT_NOFILE, &limit) != 0) {
    LOG(ERROR) << "cannot read the descriptor limit";
    return 2;
  }
  if (limit.rlim_cur < limit.rlim_max) {
    auto raised = limit;
    raised.rlim_cur = limit.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &raised) == 0) {
      limit = raised;
    }
  }
  auto required = static_cast<rlim_t>(archive_open_files) + kDescriptorMargin + kMinimumHeadroom;
  if (limit.rlim_cur == RLIM_INFINITY || limit.rlim_cur < required) {
    if (limit.rlim_cur != RLIM_INFINITY) {
      LOG(ERROR) << "the descriptor limit " << limit.rlim_cur << " is below " << required << " (--archive-open-files "
                 << archive_open_files << " plus headroom); raise LimitNOFILE";
      return 2;
    }
    limit.rlim_cur = static_cast<rlim_t>(1) << 20;
  }
  auto descriptor_budget = static_cast<size_t>(limit.rlim_cur - kDescriptorMargin);
  validator::set_archive_descriptor_budget(descriptor_budget);
  auto index = tos_wallet_index::WalletIndexDb::open((data_path / "index").string());
  if (index.is_error()) {
    LOG(ERROR) << index.error();
    return 2;
  }
  tos_wallet_index::set_wallet_index_db(index.move_as_ok());
  td::set_default_failure_signal_handler().ensure();
  td::set_signal_handler(td::SignalType::Quit, request_stop).ensure();
  td::actor::Scheduler scheduler({4});
  td::actor::ActorOwn<validator::RootDb> db;
  td::actor::ActorOwn<JsonRpcServer> server;
  Progress progress;
  scheduler.run_in_context([&] {
    vm::init_vm().ensure();
    auto options = validator::ValidatorManagerOptions::create(BlockIdExt{}, BlockIdExt{});
    options.write().set_secondary_working_dir((data_path / "secondary").string());
    options.write().set_disable_rocksdb_stats(true);
    options.write().set_celldb_cache_size(128u << 20);
    options.write().set_max_open_archive_files(archive_open_files);
    options.write().set_archive_lru_keep_most_recent(archive_keep_recent);
    options.write().set_archive_descriptor_budget(descriptor_budget);
    db = td::actor::create_actor<validator::RootDb>("index-source", td::actor::ActorId<validator::ValidatorManager>{},
                                                    source_path.string(), options, td::DbOpenMode::db_secondary);
    JsonRpcServer::Options rpc;
    rpc.index_only = true;
    rpc.trust_proxy_headers = true;
    rpc.readonly = true;
    rpc.index_ready = [&] { return progress.is_ready(); };
    rpc.index_progress = [&] { return progress.json(); };
    server = JsonRpcServer::create({}, std::move(rpc));
    td::actor::send_closure(server, &JsonRpcServer::listen, listen);
  });
  IndexReader reader(db.get());
  reader.set_admission([] { return admit_source_request(); });
  std::atomic<bool> descriptor_shortage{false};
  std::thread worker([&] {
    Replay replay(reader, progress);
    tos_wallet_index::set_wc0_index_state_fetcher(
        [&](const td::Bits256& address, auto done) { done(replay.newest(address)); });
    ShortageTracker shortages;
    while (!stop_requested.load()) {
      auto status = replay.step();
      if (status.is_error()) {
        progress.ready = false;
        LOG(WARNING) << "replay paused: " << status;
      }
      // A refused source read or slice open does not always surface as its
      // own error (the archive falls back to other packages first), so the
      // process-wide refusal record decides whether replay is blocked.
      auto refusals = validator::archive_descriptor_refusals();
      if (status.is_error() && shortages.observe(refusals)) {
        LOG(ERROR) << "replay stopped: too few file descriptors (" << refusals.last_message
                   << "); the cursor is durable, restart after raising the limit";
        descriptor_shortage = true;
        stop_requested = true;
        break;
      }
      if (status.is_ok()) {
        shortages.progressed(refusals);
      }
      if (status.is_error() || replay.idle()) {
        for (int i = 0; i < (status.is_error() ? 50 : 10) && !stop_requested.load(); ++i)
          std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
    }
    tos_wallet_index::set_wc0_index_state_fetcher(nullptr);
  });
  while (scheduler.run(0.01)) {
    scheduler.run_in_context([&] { reader.dispatch(); });
    if (stop_requested.load())
      scheduler.stop();
  }
  stop_requested = true;
  worker.join();
  tos_wallet_index::release_wc0_index_state();
  tos_wallet_index::set_wallet_index_db(nullptr);
  if (descriptor_shortage.load()) {
    return 3;
  }
  return reader.timed_out() ? 1 : 0;
}
