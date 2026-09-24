// N01: real Manager/RootDb persistence seam, without a node network.
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <spawn.h>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/wait.h>

#include "block/block-db.h"
#include "td/actor/actor.h"
#include "td/utils/port/path.h"
#include "validator/consensus/bus.h"
#include "validator/consensus/db-path.h"
#include "vm/boc.h"
#include "n5-manager-db-fixture.h"

using namespace tos;
using namespace tos::validator;

extern char **environ;

namespace {

constexpr char journal_key[] = "n5-fixture-root-marker";
constexpr char journal_value[] = "n5-fixture-durable-write";

std::string consensus_path(const std::string &root, ValidatorSessionId session_id) {
  return consensus::consensus_db_root(root) +
         consensus::consensus_db_dir_name(ShardIdFull{masterchainId}, 0, session_id, "") + "/db/";
}

class N5ConsensusDbWriter final : public td::actor::Actor {
 public:
  explicit N5ConsensusDbWriter(std::string path) : db_(consensus::open_rocksdb_consensus_db(std::move(path))) {
  }

  void write(td::Promise<td::Unit> promise) {
    write_inner(std::move(promise)).start().detach();
  }

 private:
  td::actor::Task<> write_inner(td::Promise<td::Unit> promise) {
    auto result = co_await db_->set(td::BufferSlice(td::Slice(journal_key)),
                                    td::BufferSlice(td::Slice(journal_value))).wrap();
    if (result.is_error()) {
      promise.set_error(result.move_as_error());
      co_return td::Unit{};
    }
    auto closed = co_await db_->close().wrap();
    if (closed.is_error()) {
      promise.set_error(closed.move_as_error());
      co_return td::Unit{};
    }
    promise.set_value(td::Unit());
    co_return td::Unit{};
  }

  std::unique_ptr<consensus::Db> db_;
};

bool write_consensus_marker(const std::string &path) {
  td::actor::Scheduler scheduler({1});
  td::actor::ActorOwn<N5ConsensusDbWriter> writer;
  std::optional<td::Result<td::Unit>> result;
  scheduler.run_in_context([&] {
    writer = td::actor::create_actor<N5ConsensusDbWriter>("n5-consensus-journal", path);
    td::actor::send_closure(writer, &N5ConsensusDbWriter::write,
                            td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
                              result.emplace(std::move(outcome));
                            }));
  });
  auto deadline = td::Timestamp::in(30.0);
  while (!result.has_value() && !deadline.is_in_past()) {
    scheduler.run(0.01);
  }
  const bool ok = result.has_value() && result->is_ok();
  if (!ok) {
    std::cerr << "N5_CONSENSUS_DB_FIXTURE_FAILED: "
              << (result.has_value() ? result->error().to_string() : "writer timeout") << '\n';
  }
  scheduler.run_in_context([&] { writer.reset(); });
  scheduler.stop();
  return ok;
}

bool read_consensus_marker(const std::string &path, bool expect_present) {
  // DbImpl constructs a KeyValueAsync actor, so even snapshot-only reads must
  // open it inside an actor scheduler. This is the same actor boundary Bridge
  // uses when it creates its bus and journal.
  td::actor::Scheduler scheduler({1});
  bool matched = false;
  scheduler.run_in_context([&] {
    auto db = consensus::open_rocksdb_consensus_db(path);
    auto value = db->get(td::Slice(journal_key));
    matched = expect_present ? value.has_value() && value->as_slice() == td::Slice(journal_value)
                             : !value.has_value();
  });
  scheduler.run(0.01);
  scheduler.stop();
  return matched;
}

bool run_actor(BlockIdExt id, td::Ref<MasterchainStateQ> state, td::BufferSlice boc,
               const std::string &root, bool write, bool expect_present,
               std::string *failure_out = nullptr) {
  td::actor::Scheduler scheduler({1});
  td::actor::ActorOwn<N5ManagerDbFixture> manager;
  std::optional<td::Result<td::Unit>> result;
  scheduler.run_in_context([&] {
    manager = td::actor::create_actor<N5ManagerDbFixture>("n5-manager-db", id, root);
    auto done = td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
      result.emplace(std::move(outcome));
    });
    if (write) {
      td::actor::send_closure(manager, &N5ManagerDbFixture::seed_zerostate, id, state, std::move(boc),
                              std::move(done));
    } else {
      td::actor::send_closure(manager, &N5ManagerDbFixture::read_zerostate, id, id.root_hash,
                              expect_present, std::move(done));
    }
  });
  auto deadline = td::Timestamp::in(30.0);
  while (!result.has_value() && !deadline.is_in_past()) {
    scheduler.run(0.01);
  }
  const bool ok = result.has_value() && result->is_ok();
  if (!ok) {
    auto failure = result.has_value() ? result->error().to_string() : "actor timeout";
    if (failure_out) {
      *failure_out = std::move(failure);
    } else {
      std::cerr << "N5_MANAGER_DB_FIXTURE_FAILED: " << failure << '\n';
    }
  }
  scheduler.run_in_context([&] { manager.reset(); });
  scheduler.stop();
  return ok;
}

bool cold_child(char *program, const char *boc_path, const std::string &root, std::string mode) {
  char *args[] = {program, mode.data(), const_cast<char *>(boc_path),
                  const_cast<char *>(root.c_str()), nullptr};
  pid_t pid = -1;
  const int spawn_error = posix_spawn(&pid, program, nullptr, nullptr, args, environ);
  if (spawn_error != 0) {
    std::cerr << "N5_MANAGER_DB_FIXTURE_FAILED: posix_spawn error=" << spawn_error << '\n';
    return false;
  }
  int status = 0;
  if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    std::cerr << "N5_MANAGER_DB_FIXTURE_FAILED: cold child status=" << status << '\n';
    return false;
  }
  return true;
}

}  // namespace

int main(int argc, char **argv) {
  const bool child = argc == 4 && (std::string_view(argv[1]) == "--reopen-present" ||
                                    std::string_view(argv[1]) == "--reopen-absent" ||
                                    std::string_view(argv[1]) == "--reopen-missing-control" ||
                                    std::string_view(argv[1]) == "--write");
  if (!(argc == 2 || child)) {
    std::cerr << "usage: n5-manager-db-fixture-test GENESIS_BOC | --write|--reopen-present|--reopen-absent|--reopen-missing-control GENESIS_BOC ROOT\n";
    return 2;
  }
  const char *boc_path = child ? argv[2] : argv[1];
  std::ifstream input(boc_path, std::ios::binary);
  std::ostringstream bytes;
  bytes << input.rdbuf();
  if (!input) {
    std::cerr << "N5_MANAGER_DB_FIXTURE_FAILED: genesis read\n";
    return 1;
  }
  td::BufferSlice boc{bytes.str()};
  auto root_result = vm::std_boc_deserialize(boc.as_slice());
  if (root_result.is_error()) {
    std::cerr << "N5_MANAGER_DB_FIXTURE_FAILED: genesis BOC parse\n";
    return 1;
  }
  auto root_cell = root_result.move_as_ok();
  auto id = BlockIdExt{masterchainId, shardIdAll, 0, td::Bits256(root_cell->get_hash().bits()),
                       block::compute_file_hash(boc)};
  auto state_result = MasterchainStateQ::fetch(id, boc.clone(), root_cell);
  if (state_result.is_error()) {
    std::cerr << "N5_MANAGER_DB_FIXTURE_FAILED: genesis state parse\n";
    return 1;
  }
  auto state = state_result.move_as_ok();
  const ValidatorSessionId session_id = id.root_hash;
  if (child) {
    if (std::string_view(argv[1]) == "--write") {
      if (!run_actor(id, state, std::move(boc), argv[3], true, true) ||
          !write_consensus_marker(consensus_path(argv[3], session_id))) {
        return 1;
      }
      std::cout << "N5_DUAL_DB_WRITER_EXIT_OK root=" << argv[3] << '\n';
      return 0;
    }
    const bool present = std::string_view(argv[1]) == "--reopen-present";
    if (std::string_view(argv[1]) == "--reopen-missing-control") {
      std::string failure;
      const bool accepted = run_actor(id, state, std::move(boc), argv[3], false, true, &failure);
      if (accepted || failure.find("N5 persisted handle: block handle not in db") == std::string::npos ||
          !read_consensus_marker(consensus_path(argv[3], session_id), false)) {
        std::cerr << "N5_MANAGER_DB_FIXTURE_FAILED: wrong-root control did not fail on the exact missing handle\n";
        return 1;
      }
      std::cout << "N5_MANAGER_DB_WRONG_ROOT_REJECTED reason=missing-handle journal=absent\n";
      return 0;
    }
    if (!run_actor(id, state, std::move(boc), argv[3], false, present)) {
      return 1;
    }
    if (!read_consensus_marker(consensus_path(argv[3], session_id), present)) {
      std::cerr << "N5_CONSENSUS_DB_FIXTURE_FAILED: journal marker presence differs from DB-root expectation\n";
      return 1;
    }
    std::cout << (present ? "N5_MANAGER_DB_COLD_READ_OK" : "N5_MANAGER_DB_EMPTY_ROOT_OK")
              << " root=" << argv[3] << " state=" << id.root_hash.to_hex() << '\n';
    std::cout << (present ? "N5_CONSENSUS_DB_COLD_READ_OK" : "N5_CONSENSUS_DB_EMPTY_ROOT_OK")
              << " path=" << consensus_path(argv[3], session_id) << '\n';
    return 0;
  }
  auto persisted_root = td::mkdtemp("", "n5-manager-persist-");
  auto empty_root = td::mkdtemp("", "n5-manager-empty-");
  if (persisted_root.is_error() || empty_root.is_error()) {
    std::cerr << "N5_MANAGER_DB_FIXTURE_FAILED: temp DB root creation\n";
    return 1;
  }
  auto persisted = persisted_root.move_as_ok();
  auto empty = empty_root.move_as_ok();
  // Both roots see the same static genesis file. Only the first receives
  // production RootDb writes, so a cross-root read must stay absent.
  for (const auto &db_root : {persisted, empty}) {
    std::filesystem::create_directories(db_root + "/static");
    std::ofstream static_zero(db_root + "/static/" + id.file_hash.to_hex(), std::ios::binary);
    const auto static_boc = bytes.str();
    static_zero.write(static_boc.data(), static_cast<std::streamsize>(static_boc.size()));
    if (!static_zero) {
      std::cerr << "N5_MANAGER_DB_FIXTURE_FAILED: static genesis write\n";
      return 1;
    }
  }
  std::cout << "N5_MANAGER_DB_WRITTEN_ROOT=" << persisted << '\n';
  std::cout << "N5_MANAGER_DB_EMPTY_ROOT=" << empty << '\n';
  std::cout << "N5_CONSENSUS_DB_WRITTEN_PATH=" << consensus_path(persisted, session_id) << '\n';
  if (!cold_child(argv[0], boc_path, persisted, "--write") ||
      !cold_child(argv[0], boc_path, persisted, "--reopen-present") ||
      !cold_child(argv[0], boc_path, empty, "--reopen-absent")) {
    return 1;
  }
  // A positive read deliberately pointed at the unwritten root must fail.
  // Otherwise a fixture could appear to pass while reading from a global
  // cache, static file or the wrong DB path.
  if (!cold_child(argv[0], boc_path, empty, "--reopen-missing-control")) {
    std::cerr << "N5_MANAGER_DB_FIXTURE_FAILED: wrong-root control failed for an unexpected reason\n";
    return 1;
  }
  std::cout << "N5_MANAGER_DB_SAME_ROOT_REOPEN_OK state=" << id.root_hash.to_hex() << '\n';
  return 0;
}
