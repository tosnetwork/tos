/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Real TCP ADNL clients, DownloadState/DownloadShardState actors and actor-local
// RocksDB CellDb imports. Peer selection and archive services are deterministic
// fixtures; the retry, download, verification, cleanup and root-store paths are
// production code. Trusted proof metadata is supplied by the fixture manager.
#include <algorithm>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <netinet/in.h>
#include <optional>
#include <signal.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "adnl/adnl-ext-client.h"
#include "adnl/adnl.h"
#include "auto/tl/tos_api.hpp"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "keyring/keyring.h"
#include "quic/quic-sender.h"
#include "td/actor/actor.h"
#include "td/utils/Time.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/Stat.h"
#include "td/utils/port/path.h"
#include "tos/tos-tl.hpp"
#include "validator/db/celldb.hpp"
#include "validator/db/rootdb.hpp"
#include "validator/downloaders/download-state.hpp"
#include "validator/fabric.h"
#include "validator/impl/applied-ext-message-cleanup.hpp"
#include "validator/impl/ext-message-pool.hpp"
#include "validator/manager.hpp"
#include "validator/net/download-state.hpp"
#include "validator/state-download-buffer.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/dict.h"

namespace {
using namespace tos;
using namespace tos::validator;
namespace budget = tos::validator::fullnode;

[[noreturn]] void fail(const std::string& message) {
  std::fprintf(stderr, "STATE_DOWNLOAD_RECOVERY_FAILURE: %s\n", message.c_str());
  std::fflush(stderr);
  std::exit(1);
}
void require(bool condition, const std::string& message) {
  if (!condition) {
    fail(message);
  }
}
template <class T>
T must(td::Result<T> result, const std::string& message) {
  if (result.is_error()) {
    fail(message + ": " + result.error().to_string());
  }
  return result.move_as_ok();
}
void must(td::Status result, const std::string& message) {
  if (result.is_error()) {
    fail(message + ": " + result.to_string());
  }
}

td::Bits256 hash_file(const std::string& path) {
  auto fd = must(td::FileFd::open(path, td::FileFd::Read), "hash file open");
  td::Sha256State hash;
  hash.init();
  td::BufferSlice scratch(1U << 20);
  for (;;) {
    auto got = must(fd.read(scratch.as_slice()), "hash file read");
    if (got == 0) {
      break;
    }
    hash.feed(scratch.as_slice().truncate(got));
  }
  td::Bits256 result;
  hash.extract(result.as_slice());
  return result;
}

struct Fixture {
  std::string path;
  td::uint64 size{0};
  td::Bits256 file_hash;
  td::Bits256 root_hash;
};

// A legitimate large library DAG makes a structurally valid shard state take
// the default OnDisk path. Wrong-source data remains a valid BoC/state; its
// root differs from the trusted expected root, without an exhaustion payload.
std::array<Fixture, 2> fixtures(const std::string& root, const std::string& genesis_path) {
  auto bytes = must(td::read_file(genesis_path), "genesis fixture");
  auto genesis = must(vm::std_boc_deserialize(bytes.as_slice()), "genesis BoC");
  BlockIdExt zero{masterchainId, shardIdAll, 0, td::Bits256{genesis->get_hash().bits()},
                  td::sha256_bits256(bytes.as_slice())};
  block::gen::ShardStateUnsplit::Record state;
  require(tlb::unpack_cell(genesis, state), "genesis header");
  std::vector<td::Ref<vm::Cell>> level;
  constexpr td::uint32 leaves = 524288;
  level.reserve(leaves);
  for (td::uint32 i = 0; i < leaves; ++i) {
    vm::CellBuilder leaf;
    std::array<char, 120> data{};
    for (std::size_t j = 0; j < data.size(); ++j) {
      data[j] = static_cast<char>((i >> ((j % 4) * 8)) ^ j);
    }
    require(leaf.store_bytes_bool(data.data(), data.size()), "library leaf");
    level.push_back(leaf.finalize_novm());
  }
  while (level.size() > 1) {
    std::vector<td::Ref<vm::Cell>> next;
    next.reserve(level.size() / 2);
    for (std::size_t i = 0; i < level.size(); i += 2) {
      next.push_back(vm::CellBuilder{}.store_ref(level[i]).store_ref(level[i + 1]).finalize_novm());
    }
    level = std::move(next);
  }
  auto library = level.front();
  vm::Dictionary publishers(256);
  td::Bits256 publisher;
  publisher.as_array().fill(0x33);
  require(publishers.set_builder(publisher.cbits(), 256, vm::CellBuilder{}), "nonempty library publishers");
  vm::CellBuilder descriptor;
  require(descriptor.store_long_bool(0, 2) && descriptor.store_ref_bool(library) &&
              descriptor.append_cellslice_bool(vm::load_cell_slice(std::move(publishers).extract_root_cell())),
          "library descriptor");
  vm::Dictionary libraries{state.r1.libraries->prefetch_ref(), 256};
  require(libraries.set(library->get_hash().bits(), 256, vm::load_cell_slice_ref(descriptor.finalize_novm())),
          "library dictionary");
  vm::CellBuilder libraries_field;
  require(libraries_field.store_maybe_ref(std::move(libraries).extract_root_cell()), "libraries field");
  state.r1.libraries = vm::load_cell_slice_ref(libraries_field.finalize_novm());
  state.seq_no = 1;
  state.gen_lt += 100;
  block::gen::McStateExtra::Record extra;
  require(tlb::unpack_cell(state.custom->prefetch_ref(), extra), "masterchain extra");
  vm::AugmentedDictionary prev{extra.r1.prev_blocks, 32, block::tlb::aug_OldMcBlocksInfo};
  vm::CellBuilder reference;
  require(reference.store_long_bool(0, 64) && reference.store_long_bool(0, 32) &&
              reference.store_bits_bool(zero.root_hash.cbits(), 256) &&
              reference.store_bits_bool(zero.file_hash.cbits(), 256),
          "zerostate reference");
  auto reference_slice = reference.as_cellslice_ref();
  vm::CellBuilder entry;
  require(entry.store_bool_bool(true) && entry.append_cellslice_bool(reference_slice), "previous state");
  td::BitArray<32> zero_seqno;
  zero_seqno.set_zero();
  require(prev.set(zero_seqno.cbits(), 32, entry.as_cellslice_ref()), "previous state dictionary");
  extra.r1.prev_blocks = prev.get_root();
  extra.r1.after_key_block = false;
  vm::CellBuilder last_key;
  require(last_key.store_bool_bool(true) && last_key.append_cellslice_bool(reference_slice), "last key block");
  extra.r1.last_key_block = last_key.as_cellslice_ref();
  td::Ref<vm::Cell> extra_cell;
  require(tlb::pack_cell(extra_cell, extra), "masterchain extra pack");
  state.custom = vm::CellBuilder{}.store_long(1, 1).store_ref(extra_cell).as_cellslice_ref();
  std::array<Fixture, 2> result;
  for (std::size_t i = 0; i < result.size(); ++i) {
    state.gen_utime += 1;
    td::Ref<vm::Cell> cell;
    require(tlb::pack_cell(cell, state), "state header pack");
    BlockIdExt id{masterchainId, shardIdAll, 1, td::Bits256{cell->get_hash().bits()}, td::Bits256{}};
    auto parsed = must(create_shard_state(id, cell), "valid control shard state");
    require(parsed->root_hash() == id.root_hash, "valid control root");
    auto serialized = must(vm::std_boc_serialize(cell, vm::BagOfCells::WithIndex), "indexed control serialize");
    auto& out = result[i];
    out.path = root + "/source-" + std::to_string(i) + ".boc";
    out.size = serialized.size();
    out.root_hash = id.root_hash;
    out.file_hash = td::sha256_bits256(serialized.as_slice());
    auto fd = must(td::FileFd::open(out.path, td::FileFd::Write | td::FileFd::Create | td::FileFd::Truncate),
                   "source file open");
    must(fd.write_all(serialized.as_slice()), "source file write");
    must(fd.sync(), "source file sync");
    require(out.size > budget::persistent_state_heap_threshold_bytes() &&
                out.size < budget::persistent_state_budget_config().max_returned_dag_bytes_per_parse,
            "actual fixture must pass the default OnDisk size gates");
    std::printf("FIXTURE source=%zu bytes=%llu sha256=%s root=%s\n", i, static_cast<unsigned long long>(out.size),
                out.file_hash.to_hex().c_str(), out.root_hash.to_hex().c_str());
    std::fflush(stdout);
  }
  return result;
}

std::size_t temporary_files(const std::string& root) {
  return static_cast<std::size_t>(
      std::distance(std::filesystem::directory_iterator(root), std::filesystem::directory_iterator{}));
}
void require_budgets_released() {
  require(budget::testing::test_get_persistent_state_download_bytes() == 0, "download reservation leaked");
  require(budget::testing::test_get_persistent_state_processing_bytes() == 0, "processing reservation leaked");
  require(budget::testing::test_get_persistent_state_spool_bytes() == 0, "spool reservation leaked");
}

td::uint16 port() {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  require(fd >= 0, "reserve TCP socket");
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  require(::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0, "reserve TCP port");
  socklen_t size = sizeof(address);
  require(::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &size) == 0, "read TCP port");
  auto result = ntohs(address.sin_port);
  require(::close(fd) == 0, "close reserved socket");
  return result;
}
struct Peer {
  Fixture fixture;
  bool interrupt{false};
  std::atomic<td::uint64> bytes_sent{0};
  std::atomic<td::uint64> slices{0};
};
class Serve final : public adnl::Adnl::Callback {
 public:
  explicit Serve(std::shared_ptr<Peer> peer) : peer_(std::move(peer)) {
  }
  void receive_query(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, td::BufferSlice data,
                     td::Promise<td::BufferSlice> promise) override {
    require(data.size() >= 4, "wrapped TCP query");
    data.confirm_read(4);
    auto function = must(fetch_tl_object<tos_api::Function>(std::move(data), true), "TCP query decode");
    switch (function->get_id()) {
      case tos_api::tosNode_preparePersistentState::ID:
        promise.set_value(create_serialize_tl_object<tos_api::tosNode_preparedState>());
        break;
      case tos_api::tosNode_getPersistentStateSizeV2::ID:
        promise.set_value(create_serialize_tl_object<tos_api::tosNode_persistentStateSize>(peer_->fixture.size));
        break;
      case tos_api::tosNode_downloadPersistentStateSliceV2::ID: {
        auto& query = static_cast<tos_api::tosNode_downloadPersistentStateSliceV2&>(*function);
        require(query.offset_ >= 0 && query.max_size_ > 0 && query.max_size_ <= (2LL << 20), "bounded slice request");
        auto offset = static_cast<td::uint64>(query.offset_);
        require(offset <= peer_->fixture.size, "slice offset");
        auto count = static_cast<std::size_t>(std::min<td::uint64>(query.max_size_, peer_->fixture.size - offset));
        if (peer_->interrupt && offset > 0) {
          count = 0;  // Ordinary premature EOF, not a resource-exhaustion fixture.
        }
        td::BufferSlice answer(count);
        if (count > 0) {
          auto fd = must(td::FileFd::open(peer_->fixture.path, td::FileFd::Read), "peer source open");
          require(must(fd.pread(answer.as_slice(), static_cast<td::int64>(offset)), "peer source read") == count,
                  "peer full slice read");
        }
        peer_->bytes_sent.fetch_add(count);
        peer_->slices.fetch_add(1);
        promise.set_value(std::move(answer));
        break;
      }
      default:
        promise.set_error(td::Status::Error("unexpected test query"));
    }
  }

 private:
  std::shared_ptr<Peer> peer_;
};
class Ready final : public adnl::AdnlExtClient::Callback {
 public:
  explicit Ready(std::shared_ptr<std::atomic<bool>> flag) : flag_(std::move(flag)) {
  }
  void on_ready() override {
    flag_->store(true);
  }
  void on_stop_ready() override {
    flag_->store(false);
  }

 private:
  std::shared_ptr<std::atomic<bool>> flag_;
};

struct Evidence {
  std::atomic<int> attempts{0};
  std::atomic<int> imports{0};
  std::atomic<int> rejected{0};
  std::atomic<int> stored{0};
  std::atomic<bool> cleaned{false};
  std::array<vm::StreamingBocImportStats, 2> reads;
  std::string tempfile_dir;
  std::string last_file;
  std::string archive_file;
  bool interrupt{false};
  td::uint64 size{0};
  td::Bits256 wrong_root;
  td::Bits256 good_root;
};

// Only service routing is replaced. The real DownloadShardState owns the
// reservations/file, handles import rejection, delays retry and resumes.
class Manager final : public ValidatorManagerImpl {
 public:
  Manager(BlockIdExt id, std::string path, td::actor::ActorId<CellDb> cells,
          std::array<td::actor::ActorId<adnl::AdnlExtClient>, 2> sources, std::array<std::shared_ptr<Peer>, 2> peers,
          std::shared_ptr<Evidence> evidence)
      : ValidatorManagerImpl(ValidatorManagerOptions::create(id, id), std::move(path), {}, {}, {}, {}, {})
      , cells_(cells)
      , sources_(sources)
      , peers_(std::move(peers))
      , evidence_(std::move(evidence)) {
    handle_ = create_empty_block_handle(id);
    handle_->set_state_root_hash(evidence_->good_root);
    handle_->set_proof();  // This fixture starts at an already-attested state root.
  }
  void start_up() override {
  }
  void get_block_handle(BlockIdExt, bool, td::Promise<BlockHandle> promise) override {
    promise.set_value(BlockHandle{handle_});
  }
  void get_persistent_state(BlockIdExt, BlockIdExt, PersistentStateType,
                            td::Promise<td::BufferSlice> promise) override {
    promise.set_error(td::Status::Error(ErrorCode::notready, "download required"));
  }
  void register_stats_provider(
      td::uint64, std::string,
      std::function<void(td::Promise<std::vector<std::pair<std::string, std::string>>>)>) override {
  }
  void unregister_stats_provider(td::uint64) override {
  }
  void send_get_persistent_state_request(BlockIdExt id, BlockIdExt mc, PersistentStateType type, td::uint32 priority,
                                         td::Promise<budget::DownloadedPersistentState> promise) override {
    int attempt = evidence_->attempts.fetch_add(1);
    require(attempt < 2, "retry must recover within two selected sources");
    if (attempt == 1) {
      // Observe production cleanup BEFORE the valid source can replace state.
      require_budgets_released();
      require(temporary_files(evidence_->tempfile_dir) == 0, "failed import/download left temporary resources");
      require(evidence_->last_file.empty() || !std::filesystem::exists(evidence_->last_file),
              "failed download file retained");
      require(evidence_->interrupt || evidence_->rejected.load() == 1, "retry before root rejection");
      evidence_->cleaned.store(true);
    }
    if (attempt == 1) {
      auto evidence = evidence_;
      auto self = actor_id(this);
      td::actor::send_closure(
          cells_, &CellDb::get_cell_db_reader,
          td::PromiseCreator::lambda([self, evidence, id, mc, type, priority, attempt, promise = std::move(promise)](
                                         td::Result<std::shared_ptr<vm::CellDbReader>> result) mutable {
            auto reader = must(std::move(result), "reader after rejection");
            require(reader->load_cell(evidence->wrong_root.as_slice()).is_error(),
                    "rejected root visible before recovery");
            require(reader->load_cell(evidence->good_root.as_slice()).is_error(), "valid root stored before recovery");
            td::actor::send_closure(self, &Manager::download_selected_source, id, mc, type, priority, attempt,
                                    std::move(promise));
          }));
    } else {
      download_selected_source(id, mc, type, priority, attempt, std::move(promise));
    }
  }
  void download_selected_source(BlockIdExt id, BlockIdExt mc, PersistentStateType type, td::uint32 priority,
                                int attempt, td::Promise<budget::DownloadedPersistentState> promise) {
    auto peer = peers_[static_cast<std::size_t>(attempt)];
    auto evidence = evidence_;
    auto P = td::PromiseCreator::lambda(
        [peer, evidence, promise = std::move(promise)](td::Result<budget::DownloadedPersistentState> result) mutable {
          if (result.is_ok()) {
            auto& state = result.ok();
            require(state.is_file(), "download must use OnDisk");
            require(state.size() == peer->fixture.size && peer->bytes_sent.load() == peer->fixture.size,
                    "complete delivery before import");
            require(hash_file(state.file().path) == peer->fixture.file_hash, "received file SHA256 mismatch");
            evidence->last_file = state.file().path;
            std::printf("DELIVERY mode=OnDisk bytes=%llu sha256=%s\n", static_cast<unsigned long long>(state.size()),
                        peer->fixture.file_hash.to_hex().c_str());
            std::fflush(stdout);
          }
          promise.set_result(std::move(result));
        });
    td::actor::create_actor<budget::DownloadState>(
        "network-download", id, mc, type, adnl::AdnlNodeIdShort{}, overlay::OverlayIdShort{}, adnl::AdnlNodeIdShort{},
        priority, td::Timestamp::in(120), actor_id(this), td::actor::ActorId<adnl::AdnlSenderInterface>{},
        td::actor::ActorId<overlay::Overlays>{}, td::actor::ActorId<adnl::Adnl>{},
        sources_[static_cast<std::size_t>(attempt)], std::move(P))
        .release();
  }
  void import_persistent_state_streaming(PersistentStateImportRequest request,
                                         td::Promise<PersistentStateImportResult> promise) override {
    int index = evidence_->imports.fetch_add(1);
    require(index < 2, "bounded import count");
    require(budget::testing::test_get_persistent_state_download_bytes() == request.file_size,
            "download budget not held during import");
    require(budget::testing::test_get_persistent_state_processing_bytes() == request.file_size,
            "processing budget not held during import");
    request.opts.stats = &evidence_->reads[static_cast<std::size_t>(index)];
    auto evidence = evidence_;
    auto P = td::PromiseCreator::lambda(
        [evidence, promise = std::move(promise)](td::Result<PersistentStateImportResult> result) mutable {
          if (result.is_error()) {
            require(result.error().to_string().find("root hash mismatch") != std::string::npos,
                    "specific root rejection: " + result.error().to_string());
            evidence->rejected.fetch_add(1);
          }
          promise.set_result(std::move(result));
        });
    td::actor::send_closure(cells_, &CellDb::import_persistent_state_streaming, std::move(request), std::move(P));
  }
  void store_persistent_state_file_gen(BlockIdExt, BlockIdExt, PersistentStateType,
                                       std::function<td::Status(td::FileFd&)> write,
                                       td::Promise<td::Unit> promise) override {
    require(budget::testing::test_get_persistent_state_processing_bytes() == evidence_->size,
            "processing released before archive handoff");
    auto opened =
        td::FileFd::open(evidence_->archive_file, td::FileFd::Write | td::FileFd::Create | td::FileFd::Truncate);
    if (opened.is_error()) {
      promise.set_error(opened.move_as_error());
      return;
    }
    auto fd = opened.move_as_ok();
    auto status = write(fd);
    if (status.is_ok()) {
      status = fd.sync();
    }
    promise.set_result(std::move(status));
  }
  void set_block_state(BlockHandle handle, td::Ref<ShardState> state, vm::StoreCellHint hint,
                       td::Promise<td::Ref<ShardState>> promise) override {
    auto evidence = evidence_;
    auto P = td::PromiseCreator::lambda(
        [handle, state, evidence, promise = std::move(promise)](td::Result<td::Ref<vm::DataCell>> result) mutable {
          if (result.is_error()) {
            promise.set_error(result.move_as_error());
            return;
          }
          require(td::Bits256{result.ok()->get_hash().bits()} == evidence->good_root, "canonical root identity");
          handle->set_state_boc();
          evidence->stored.fetch_add(1);
          promise.set_value(std::move(state));
        });
    td::actor::send_closure(cells_, &CellDb::store_cell, handle->id(), state->root_cell(), hint, std::move(P));
  }
  void archive(BlockHandle handle, td::Promise<td::Unit> promise) override {
    handle->set_handle_moved_to_archive();
    handle->set_moved_to_archive();
    handle->flushed_upto(handle->version());
    promise.set_value(td::Unit{});
  }

 private:
  BlockHandle handle_;
  td::actor::ActorId<CellDb> cells_;
  std::array<td::actor::ActorId<adnl::AdnlExtClient>, 2> sources_;
  std::array<std::shared_ptr<Peer>, 2> peers_;
  std::shared_ptr<Evidence> evidence_;
};

// Supply a retention policy for CellDb's real RootDb GC queries. These tests
// retain the newly recovered canonical state; they do not simulate chain TTL.
class RetentionPolicy final : public ValidatorManagerImpl {
 public:
  RetentionPolicy() : ValidatorManagerImpl(ValidatorManagerOptions::create({}, {}), "", {}, {}, {}, {}, {}) {
  }
  void start_up() override {
  }
  void allow_block_state_gc(BlockIdExt, td::Promise<bool> promise) override {
    promise.set_value(false);
  }
};
class RootServices final : public RootDb {
 public:
  using RootDb::RootDb;
  void start_up() override {
  }
};

td::Ref<ValidatorManagerOptions> cell_options() {
  auto options = ValidatorManagerOptions::create({}, {}, false, 0, 0, 0, 0, 0, 0, true);
  options.write().set_disable_rocksdb_stats(true);
  options.write().set_celldb_compress_depth(0);
  options.write().set_celldb_v2(false);
  options.write().set_celldb_disable_bloom_filter(true);
  return options;
}

void verify_reopened(const std::string& path, const std::array<Fixture, 2>& fixture) {
  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<CellDb> cells;
  td::actor::ActorOwn<RetentionPolicy> policy;
  td::actor::ActorOwn<RootServices> roots;
  std::atomic<bool> checked{false};
  scheduler.run_in_context([&] {
    policy = td::actor::create_actor<RetentionPolicy>("retention-policy");
    roots = td::actor::create_actor<RootServices>("root-services", policy.get(), path, cell_options());
    cells = td::actor::create_actor<CellDb>("reopened-cell-db", roots.get(), path, cell_options());
    td::actor::send_closure(
        cells, &CellDb::get_cell_db_reader,
        td::PromiseCreator::lambda([&](td::Result<std::shared_ptr<vm::CellDbReader>> result) {
          auto reader = must(std::move(result), "reopened reader");
          require(reader->load_cell(fixture[0].root_hash.as_slice()).is_error(), "rejected root persisted");
          auto recovered = must(reader->load_cell(fixture[1].root_hash.as_slice()), "reopened accepted root");
          require(td::Bits256{recovered->get_hash().bits()} == fixture[1].root_hash, "reopened root identity");
          checked.store(true);
        }));
  });
  auto deadline = td::Timestamp::in(120);
  while (!checked.load()) {
    require(!deadline.is_in_past(), "deadline: database reopen");
    scheduler.run(0.01);
  }
  scheduler.run_in_context([&] {
    cells.reset();
    roots.reset();
    policy.reset();
    td::actor::SchedulerContext::get().stop();
  });
  scheduler.run();
  std::printf("REOPEN accepted_root=%s rejected_root_absent=1\n", fixture[1].root_hash.to_hex().c_str());
  std::fflush(stdout);
}

void run_case(const std::string& root, const std::array<Fixture, 2>& fixture, bool interrupt) {
  const auto pid = ::getpid();
  auto case_root = root + (interrupt ? "/interrupted" : "/rejected");
  auto tempfile_root = case_root + "/temp";
  auto evidence = std::make_shared<Evidence>();
  evidence->tempfile_dir = tempfile_root + "/persistent-state";
  evidence->archive_file = case_root + "/accepted.boc";
  evidence->interrupt = interrupt;
  evidence->size = fixture[1].size;
  evidence->wrong_root = fixture[0].root_hash;
  evidence->good_root = fixture[1].root_hash;
  must(td::mkpath(evidence->tempfile_dir + "/", 0700), "temporary directory");
  budget::set_persistent_state_tempfile_dir(tempfile_root);
  require_budgets_released();
  td::actor::Scheduler scheduler({2});
  auto wait = [&](const auto& condition, const char* label) {
    auto deadline = td::Timestamp::in(180);
    while (!condition()) {
      require(!deadline.is_in_past(), std::string("deadline: ") + label);
      scheduler.run(0.01);
    }
  };
  td::actor::ActorOwn<keyring::Keyring> keys;
  td::actor::ActorOwn<adnl::Adnl> adnl_node;
  td::actor::ActorOwn<CellDb> cells;
  td::actor::ActorOwn<RetentionPolicy> policy;
  td::actor::ActorOwn<RootServices> roots;
  std::array<td::actor::ActorOwn<adnl::AdnlExtServer>, 2> servers;
  std::array<td::actor::ActorOwn<adnl::AdnlExtClient>, 2> clients;
  std::array<std::shared_ptr<std::atomic<bool>>, 2> ready;
  std::array<std::shared_ptr<Peer>, 2> peers;
  auto options = cell_options();
  scheduler.run_in_context([&] {
    keys = keyring::Keyring::create(case_root + "/keys");
    adnl_node = adnl::Adnl::create(case_root, keys.get());
    policy = td::actor::create_actor<RetentionPolicy>("retention-policy");
    roots = td::actor::create_actor<RootServices>("root-services", policy.get(), case_root, options);
    cells = td::actor::create_actor<CellDb>("cell-db", roots.get(), case_root + "/cells/", options);
  });
  for (std::size_t i = 0; i < 2; ++i) {
    peers[i] = std::make_shared<Peer>();
    peers[i]->fixture = fixture[i];
    peers[i]->interrupt = interrupt && i == 0;
    auto private_key = PrivateKey{privkeys::Ed25519::random()};
    auto public_id = adnl::AdnlNodeIdFull{private_key.compute_public_key()};
    auto listener_port = port();
    std::atomic<bool> installed{false};
    scheduler.run_in_context([&] {
      td::actor::send_closure(keys, &keyring::Keyring::add_key, std::move(private_key), false,
                              td::PromiseCreator::lambda([&](td::Result<td::Unit> result) {
                                must(std::move(result), "test peer key install");
                                installed.store(true);
                              }));
    });
    wait([&] { return installed.load(); }, "key install");
    std::atomic<bool> listening{false};
    scheduler.run_in_context([&] {
      td::actor::send_closure(adnl_node, &adnl::Adnl::add_id, public_id, adnl::AdnlAddressList{}, td::uint8{0});
      td::actor::send_closure(adnl_node, &adnl::Adnl::subscribe, public_id.compute_short_id(),
                              adnl::Adnl::int_to_bytestring(tos_api::tosNode_query::ID),
                              std::make_unique<Serve>(peers[i]));
      td::actor::send_closure(
          adnl_node, &adnl::Adnl::create_ext_server, std::vector<adnl::AdnlNodeIdShort>{public_id.compute_short_id()},
          std::vector<td::uint16>{listener_port},
          td::PromiseCreator::lambda([&, i](td::Result<td::actor::ActorOwn<adnl::AdnlExtServer>> result) {
            servers[i] = must(std::move(result), "test listener create");
            td::actor::send_closure(servers[i], &adnl::AdnlExtServer::wait_listening,
                                    td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
                                      must(std::move(outcome), "test listener bind");
                                      listening.store(true);
                                    }));
          }));
    });
    wait([&] { return listening.load(); }, "listener bind");
    td::IPAddress address;
    must(address.init_host_port("127.0.0.1", listener_port), "loopback address");
    ready[i] = std::make_shared<std::atomic<bool>>(false);
    scheduler.run_in_context(
        [&] { clients[i] = adnl::AdnlExtClient::create(public_id, address, std::make_unique<Ready>(ready[i])); });
    wait([&] { return ready[i]->load(); }, "client ready");
  }
  BlockIdExt id{masterchainId, shardIdAll, 1, fixture[1].root_hash, fixture[1].file_hash};
  td::actor::ActorOwn<Manager> manager;
  std::atomic<bool> done{false};
  std::optional<td::Result<td::Ref<ShardState>>> outcome;
  scheduler.run_in_context([&] {
    manager = td::actor::create_actor<Manager>(
        "fixture-services", id, case_root, cells.get(),
        std::array<td::actor::ActorId<adnl::AdnlExtClient>, 2>{clients[0].get(), clients[1].get()}, peers, evidence);
    td::actor::create_actor<DownloadShardState>("state-sync", id, id, 0, 1, manager.get(), td::Timestamp::in(600),
                                                td::PromiseCreator::lambda([&](td::Result<td::Ref<ShardState>> result) {
                                                  outcome.emplace(std::move(result));
                                                  done.store(true);
                                                }))
        .release();
  });
  wait([&] { return done.load(); }, "source recovery");
  require(outcome.has_value() && outcome->is_ok(), "successful recovery outcome");
  require(outcome->ok()->root_hash() == fixture[1].root_hash, "recovered trusted state root");
  wait(
      [&] {
        return budget::testing::test_get_persistent_state_download_bytes() == 0 &&
               budget::testing::test_get_persistent_state_processing_bytes() == 0 &&
               budget::testing::test_get_persistent_state_spool_bytes() == 0 &&
               temporary_files(evidence->tempfile_dir) == 0;
      },
      "success cleanup");
  require(evidence->attempts.load() == 2 && evidence->cleaned.load(), "bounded retry and failure cleanup");
  require(evidence->imports.load() == (interrupt ? 1 : 2), "actual import entry count");
  require(evidence->rejected.load() == (interrupt ? 0 : 1) && evidence->stored.load() == 1,
          "reject before canonical store");
  require(hash_file(evidence->archive_file) == fixture[1].file_hash, "archive hash equality");
  std::atomic<bool> idle{false};
  auto idle_deadline = td::Timestamp::in(30);
  while (!idle.load()) {
    require(!idle_deadline.is_in_past(), "GC lease or import job retained after recovery");
    std::atomic<bool> sampled{false};
    scheduler.run_in_context([&] {
      td::actor::send_closure(
          cells, &CellDb::prepare_stats,
          td::PromiseCreator::lambda([&](td::Result<std::vector<std::pair<std::string, std::string>>> result) {
            auto stats = must(std::move(result), "resource lifecycle stats");
            auto value = [&](const char* key) {
              for (const auto& entry : stats) {
                if (entry.first == key) {
                  return entry.second;
                }
              }
              return std::string{};
            };
            const auto inflight = value("streaming_import.inflight");
            idle.store(value("streaming_import.committed") == "1" &&
                       value("streaming_import.failed") == (interrupt ? "0" : "1") &&
                       value("streaming_import.gc_pause_count") == "0" &&
                       value("streaming_import.rollback_queue_size") == "0" &&
                       (inflight == "0" || inflight == "false"));
            sampled.store(true);
          }));
    });
    wait([&] { return sampled.load(); }, "lifecycle stats sample");
    scheduler.run(0.05);
  }
  for (int i = 0; i < evidence->imports.load(); ++i) {
    const auto& read = evidence->reads[static_cast<std::size_t>(i)];
    require(read.cell_read_calls > 0 && read.peak_scratch_bytes == vm::kStreamingBocScratchBytes,
            "bounded native importer scratch and nonzero work");
  }
  require(::getpid() == pid && ::kill(pid, 0) == 0, "same process remained alive");
  std::printf(
      "RECOVERY case=%s attempts=2 imports=%d rejected=%d canonical_stores=1 pid=%ld scratch_bytes=%zu budgets=0 "
      "tempfiles=0 gc_pause=0 rollback_queue=0\n",
      interrupt ? "interrupted-download" : "root-rejected", evidence->imports.load(), evidence->rejected.load(),
      static_cast<long>(pid), vm::kStreamingBocScratchBytes);
  std::fflush(stdout);
  outcome.reset();
  scheduler.run_in_context([&] {
    manager.reset();
    for (auto& client : clients) {
      client.reset();
    }
    for (auto& server : servers) {
      server.reset();
    }
    cells.reset();
    roots.reset();
    policy.reset();
    adnl_node.reset();
    keys.reset();
    td::actor::SchedulerContext::get().stop();
  });
  scheduler.run();
  require_budgets_released();
}
}  // namespace

int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(verbosity_ERROR);
  require(argc >= 2 && argc <= 3,
          "usage: test-state-download-recovery genesis.boc [--root-recovery|--download-recovery]");
  require(argc == 2 || std::string(argv[2]) == "--root-recovery" || std::string(argv[2]) == "--download-recovery",
          "unknown case selector");
  auto root = std::string("/tmp/tos-state-download-recovery-") + std::to_string(::getpid());
  must(td::mkpath(root + "/", 0700), "test root");
  auto config = budget::persistent_state_budget_config();
  require(!config.enable_true_cell_db_streaming_import && config.max_returned_dag_bytes_per_parse == (512ULL << 20),
          "unmodified download/import defaults");
  // This deliberately wide library has many tiny branch cells. Its CellDb
  // spool plus rollback serialization exceeds the default source-size ratio.
  // Supply an explicit test configuration for disk amplification while keeping
  // the normal OnDisk, returned-DAG and absolute disk/memory caps unchanged.
  config.spool_reservation_ratio_percent = 500;
  must(budget::configure_persistent_state_budgets(config), "fixture disk amplification configuration");
  std::printf("CONFIG spool_ratio_percent=500 true_streaming=0 returned_dag_limit=%llu\n",
              static_cast<unsigned long long>(config.max_returned_dag_bytes_per_parse));
  std::fflush(stdout);
  auto input = fixtures(root, argv[1]);
  if (argc == 2 || std::string(argv[2]) == "--download-recovery") {
    run_case(root, input, true);
    verify_reopened(root + "/interrupted/cells/", input);
  }
  if (argc == 2 || std::string(argv[2]) == "--root-recovery") {
    run_case(root, input, false);
    verify_reopened(root + "/rejected/cells/", input);
  }
  must(td::rmrf(root), "test cleanup");
  std::puts("STATE_DOWNLOAD_RECOVERY_PASSED");
}
