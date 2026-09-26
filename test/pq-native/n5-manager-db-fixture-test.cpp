// N01: real Manager/RootDb persistence seam, without a node network.
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <spawn.h>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/wait.h>
#include <vector>

#include "block/block-db.h"
#include "crypto/pq/consensus-pq-signer.h"
#include "td/actor/actor.h"
#include "td/utils/crypto.h"
#include "td/utils/port/path.h"
#include "validator/consensus/bus.h"
#include "validator/consensus/db-path.h"
#include "validator/consensus/simplex/bus.h"
#include "validator/consensus/simplex/certificate.h"
#include "tl-utils/tl-utils.hpp"
#include "vm/boc.h"
#include "n5-manager-db-fixture.h"

using namespace tos;
using namespace tos::validator;

extern char **environ;

namespace {

namespace sx = tos::validator::consensus::simplex;

td::Bits256 fill_byte(unsigned char byte) {
  td::Bits256 value;
  std::memset(value.data(), byte, 32);
  return value;
}

struct FinalCertFixture {
  sx::CertificateRef<sx::Vote> cert;
  td::BufferSlice inner_tl;
  td::Bits256 hash;
};

std::shared_ptr<sx::Bus> make_trusted_bus(ValidatorSessionId session_id) {
  auto trusted = std::make_shared<sx::Bus>();
  trusted->session_id = session_id;
  trusted->shard = ShardIdFull{masterchainId};
  for (size_t index = 0; index < 4; ++index) {
    auto store = pq::ValidatorPQKeyStore::from_seed(std::string(32, static_cast<char>(0x40 + index)));
    if (!store) {
      return {};
    }
    auto adnl = adnl::AdnlNodeIdShort{fill_byte(static_cast<unsigned char>(0x90 + index))};
    trusted->validator_set.push_back(consensus::PeerValidator{
        .validator_id = ValidatorId{fill_byte(static_cast<unsigned char>(0x70 + index))},
        .idx = consensus::PeerValidatorId{index},
        .consensus_key = store->consensus_key(),
        .transport_key_id = adnl.pubkey_hash(),
        .adnl_id = adnl,
        .weight = 1,
    });
    ++trusted->total_weight;
  }
  return trusted;
}

std::optional<FinalCertFixture> make_verified_finalcert(const sx::Bus& trusted) {
  std::vector<pq::ValidatorPQKeyStore> stores;
  for (size_t index = 0; index < trusted.validator_set.size(); ++index) {
    auto store = pq::ValidatorPQKeyStore::from_seed(std::string(32, static_cast<char>(0x40 + index)));
    if (!store) {
      return std::nullopt;
    }
    stores.push_back(std::move(*store));
  }
  sx::FinalizeVote vote{consensus::CandidateId{1, fill_byte(0x31)}};
  auto vote_tl = serialize_tl_object(vote.to_tl(), true);
  auto envelope = create_serialize_tl_object<tos_api::consensus_dataToSign>(trusted.session_id, vote_tl.clone());
  std::vector<sx::tl::VoteSignatureRef> signatures;
  for (size_t index = 0; index < stores.size(); ++index) {
    const auto signed_bytes = std::string_view(envelope.data(), envelope.size());
    auto signature = stores[index].sign_consensus(signed_bytes);
    if (!signature) {
      return std::nullopt;
    }
    signatures.push_back(create_tl_object<sx::tl::voteSignature>(static_cast<int>(index),
                                                                 td::BufferSlice(signature->signature)));
  }
  auto cert_tl = create_tl_object<sx::tl::certificate>(
      vote.to_tl(), create_tl_object<sx::tl::voteSignatureSet>(std::move(signatures)));
  auto verified = sx::Certificate<sx::Vote>::from_tl(std::move(*cert_tl), trusted);
  if (verified.is_error()) {
    std::cerr << "N5_FINALCERT_FIXTURE_FAILED: production certificate verification: "
              << verified.error().to_string() << '\n';
    return std::nullopt;
  }
  auto cert = verified.move_as_ok();
  auto inner_tl = serialize_tl_object(cert->to_tl(), true);
  auto hash = sha256_bits256(inner_tl.as_slice());
  return FinalCertFixture{std::move(cert), std::move(inner_tl), hash};
}

std::string consensus_path(const std::string &root, ValidatorSessionId session_id) {
  return consensus::consensus_db_root(root) +
         consensus::consensus_db_dir_name(ShardIdFull{masterchainId}, 0, session_id, "") + "/db/";
}

class N5FinalCertPublisher final : public td::actor::Actor {
 public:
  void write(sx::BusHandle bus, sx::CertificateRef<sx::Vote> cert,
             td::Promise<td::Unit> promise) {
    write_inner(std::move(bus), std::move(cert), std::move(promise)).start().detach();
  }

 private:
  td::actor::Task<> write_inner(sx::BusHandle bus, sx::CertificateRef<sx::Vote> cert,
                               td::Promise<td::Unit> promise) {
    // This invokes simplex/db.cpp::process(SaveCertificate), including its
    // production db_key_vote(hash(inner TL)) / db_cert(inner TL) write.
    auto result = co_await bus.publish<sx::SaveCertificate>(std::move(cert)).wrap();
    if (result.is_error()) {
      promise.set_error(result.move_as_error());
      co_return td::Unit{};
    }
    auto closed = co_await bus->db->close().wrap();
    if (closed.is_error()) {
      promise.set_error(closed.move_as_error());
      co_return td::Unit{};
    }
    promise.set_value(td::Unit());
    co_return td::Unit{};
  }
};

bool write_finalcert_journal(const std::string &path, ValidatorSessionId session_id,
                             const FinalCertFixture &fixture) {
  td::actor::Scheduler scheduler({1});
  td::actor::Runtime runtime;
  sx::Db::register_in(runtime);
  td::actor::ActorOwn<N5FinalCertPublisher> publisher;
  sx::BusHandle bus;
  std::optional<td::Result<td::Unit>> result;
  scheduler.run_in_context([&] {
    auto trusted = make_trusted_bus(session_id);
    if (!trusted) {
      result.emplace(td::Status::Error("N5 FinalCert descriptor fixture failed"));
      return;
    }
    trusted->db = consensus::open_rocksdb_consensus_db(path);
    bus = runtime.start(std::move(trusted), "n5-finalcert-journal");
    publisher = td::actor::create_actor<N5FinalCertPublisher>("n5-finalcert-publisher");
    td::actor::send_closure(publisher, &N5FinalCertPublisher::write, bus, fixture.cert,
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
    std::cerr << "N5_FINALCERT_JOURNAL_FAILED: "
              << (result.has_value() ? result->error().to_string() : "writer timeout") << '\n';
  }
  scheduler.run_in_context([&] { publisher.reset(); bus = {}; });
  scheduler.stop();
  return ok;
}

bool read_finalcert_journal(const std::string &path, ValidatorSessionId session_id,
                            td::Slice expected_inner_tl, bool expect_present,
                            std::string *failure_out = nullptr) {
  // DbImpl constructs a KeyValueAsync actor, so even snapshot-only reads must
  // open it inside an actor scheduler. This is the same actor boundary Bridge
  // uses when it creates its bus and journal.
  td::actor::Scheduler scheduler({1});
  bool matched = false;
  std::string failure;
  scheduler.run_in_context([&] {
    auto db = consensus::open_rocksdb_consensus_db(path);
    auto expected_hash = sha256_bits256(expected_inner_tl);
    auto key = create_serialize_tl_object<tos_api::consensus_simplex_db_key_vote>(expected_hash);
    auto value = db->get(key.as_slice());
    if (!value) {
      matched = !expect_present;
      failure = "FinalCert journal key absent";
      return;
    }
    if (!expect_present) {
      failure = "unexpected FinalCert journal key in empty root";
      return;
    }
    auto parsed = fetch_tl_object<tos_api::consensus_simplex_db_cert>(*value, true);
    if (parsed.is_error() || !parsed.ok()->cert_) {
      failure = "FinalCert journal value is not db_cert";
      return;
    }
    auto recovered = serialize_tl_object(parsed.ok()->cert_, true);
    if (recovered.as_slice() != expected_inner_tl || sha256_bits256(recovered.as_slice()) != expected_hash) {
      failure = "FinalCert journal TL or key hash differs from writer certificate";
      return;
    }
    auto trusted = make_trusted_bus(session_id);
    if (!trusted) {
      failure = "FinalCert descriptor fixture failed on reopen";
      return;
    }
    auto verified = sx::Certificate<sx::Vote>::from_tl(std::move(*parsed.ok()->cert_), *trusted);
    if (verified.is_error() ||
        !std::holds_alternative<sx::FinalizeVote>(verified.ok()->vote.vote)) {
      failure = "recovered FinalCert fails production certificate verification";
      return;
    }
    matched = true;
    std::cout << "N5_FINALCERT_JOURNAL_COLD_READ_OK session=" << session_id.to_hex()
              << " key_hash=" << expected_hash.to_hex() << " tl_bytes=" << recovered.size() << '\n';
  });
  scheduler.run(0.01);
  scheduler.stop();
  if (!matched && failure_out) {
    *failure_out = std::move(failure);
  } else if (!matched) {
    std::cerr << "N5_FINALCERT_JOURNAL_FAILED: " << failure << '\n';
  }
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

bool cold_child(char *program, const char *boc_path, const std::string &root,
                const std::string &expected_path, std::string mode) {
  char *args[] = {program, mode.data(), const_cast<char *>(boc_path),
                  const_cast<char *>(root.c_str()), const_cast<char *>(expected_path.c_str()), nullptr};
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
  const bool child = argc == 5 && (std::string_view(argv[1]) == "--reopen-present" ||
                                    std::string_view(argv[1]) == "--reopen-absent" ||
                                    std::string_view(argv[1]) == "--reopen-missing-control" ||
                                    std::string_view(argv[1]) == "--write");
  if (!(argc == 2 || child)) {
    std::cerr << "usage: n5-manager-db-fixture-test GENESIS_BOC | --write|--reopen-present|--reopen-absent|--reopen-missing-control GENESIS_BOC ROOT EXPECTED_FINALCERT_TL\n";
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
      auto trusted = make_trusted_bus(session_id);
      auto fixture = trusted ? make_verified_finalcert(*trusted) : std::nullopt;
      if (!fixture) {
        std::cerr << "N5_FINALCERT_FIXTURE_FAILED: cannot construct a verified PQ FinalCert\n";
        return 1;
      }
      std::ofstream expected(argv[4], std::ios::binary);
      expected.write(fixture->inner_tl.data(), static_cast<std::streamsize>(fixture->inner_tl.size()));
      expected.close();
      if (!expected) {
        std::cerr << "N5_FINALCERT_FIXTURE_FAILED: cannot retain original certificate TL\n";
        return 1;
      }
      if (!run_actor(id, state, std::move(boc), argv[3], true, true) ||
          !write_finalcert_journal(consensus_path(argv[3], session_id), session_id, *fixture)) {
        return 1;
      }
      std::cout << "N5_FINALCERT_PUBLISH_RETURNED session=" << session_id.to_hex()
                << " key_hash=" << fixture->hash.to_hex()
                << " tl_bytes=" << fixture->inner_tl.size() << '\n';
      std::cout << "N5_DUAL_DB_WRITER_EXIT_OK root=" << argv[3] << '\n';
      return 0;
    }
    const bool present = std::string_view(argv[1]) == "--reopen-present";
    std::ifstream expected_file(argv[4], std::ios::binary);
    std::ostringstream expected_bytes;
    expected_bytes << expected_file.rdbuf();
    if (!expected_file || expected_bytes.str().empty()) {
      std::cerr << "N5_FINALCERT_FIXTURE_FAILED: retained certificate TL is missing\n";
      return 1;
    }
    const auto expected_data = expected_bytes.str();
    const auto expected_tl = td::Slice(expected_data);
    if (std::string_view(argv[1]) == "--reopen-missing-control") {
      std::string failure;
      const bool accepted = run_actor(id, state, std::move(boc), argv[3], false, true, &failure);
      if (accepted || failure.find("N5 persisted handle: block handle not in db") == std::string::npos ||
          !read_finalcert_journal(consensus_path(argv[3], session_id), session_id, expected_tl, false)) {
        std::cerr << "N5_MANAGER_DB_FIXTURE_FAILED: wrong-root control did not fail on the exact missing handle\n";
        return 1;
      }
      std::string cert_failure;
      if (read_finalcert_journal(consensus_path(argv[3], session_id), session_id,
                                 expected_tl, true, &cert_failure) ||
          cert_failure != "FinalCert journal key absent") {
        std::cerr << "N5_FINALCERT_JOURNAL_FAILED: wrong-root positive read did not fail on the exact key\n";
        return 1;
      }
      std::cout << "N5_MANAGER_DB_WRONG_ROOT_REJECTED reason=missing-handle finalcert=absent\n";
      return 0;
    }
    if (!run_actor(id, state, std::move(boc), argv[3], false, present)) {
      return 1;
    }
    if (!read_finalcert_journal(consensus_path(argv[3], session_id), session_id, expected_tl, present)) {
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
  const auto expected_path = persisted + ".expected-finalcert.tl";
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
  std::cout << "N5_FINALCERT_EXPECTED_TL=" << expected_path << '\n';
  if (!cold_child(argv[0], boc_path, persisted, expected_path, "--write") ||
      !cold_child(argv[0], boc_path, persisted, expected_path, "--reopen-present") ||
      !cold_child(argv[0], boc_path, empty, expected_path, "--reopen-absent")) {
    return 1;
  }
  // A positive read deliberately pointed at the unwritten root must fail.
  // Otherwise a fixture could appear to pass while reading from a global
  // cache, static file or the wrong DB path.
  if (!cold_child(argv[0], boc_path, empty, expected_path, "--reopen-missing-control")) {
    std::cerr << "N5_MANAGER_DB_FIXTURE_FAILED: wrong-root control failed for an unexpected reason\n";
    return 1;
  }
  std::cout << "N5_MANAGER_DB_SAME_ROOT_REOPEN_OK state=" << id.root_hash.to_hex() << '\n';
  return 0;
}
