#include <atomic>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "keyring/keyring.hpp"
#include "td/utils/Time.h"
using tos::keyring::Keyring;
namespace fs = std::filesystem;
void check(bool okay, const char* label) {
  if (!okay)
    throw std::runtime_error(label);
}
template <class T>
T value(td::Result<T> result, const char* label) {
  check(result.is_ok(), label);
  return result.move_as_ok();
}
template <class T>
void denied(td::Result<T> result, const char* label, const char* code = "keyring-validator-auth-key") {
  check(result.is_error() && result.error().message() == td::Slice(code), label);
}
tos::PrivateKey key(unsigned seed) {
  td::Bits256 raw;
  raw.set_zero();
  raw.as_slice()[0] = static_cast<char>(seed);
  return tos::PrivateKey(tos::privkeys::Ed25519(raw));
}
void wait(td::actor::Scheduler& scheduler, std::atomic<bool>& done) {
  auto deadline = td::Timestamp::in(10);
  while (!done.load(std::memory_order_acquire)) {
    scheduler.run(0.05);
    if (deadline.is_in_past()) {
      std::cerr << "HARNESS: actor timed out\n";
      std::exit(2);
    }
  }
}
struct Runner {
  td::actor::Scheduler scheduler{{1}};
  td::actor::ActorOwn<Keyring> ring;
  explicit Runner(const fs::path& path) {
    scheduler.run_in_context([&] { ring = Keyring::create(path.string()); });
  }
  ~Runner() {
    scheduler.run_in_context([&] {
      ring.reset();
      td::actor::SchedulerContext::get().stop();
    });
    while (scheduler.run(0.05)) {
    }
  }
  template <class T, class Method, class... Args>
  td::Result<T> call(Method method, Args&&... args) {
    std::optional<td::Result<T>> result;
    std::atomic<bool> done{false};
    scheduler.run_in_context([&] {
      td::actor::send_closure(ring, method, std::forward<Args>(args)...,
                              td::PromiseCreator::lambda([&](td::Result<T> answer) {
                                result.emplace(std::move(answer));
                                done.store(true, std::memory_order_release);
                              }));
    });
    wait(scheduler, done);
    return std::move(*result);
  }
};
using Pair = std::pair<td::BufferSlice, tos::PublicKey>;
using Batch = std::vector<td::Result<td::BufferSlice>>;
std::vector<td::BufferSlice> messages() {
  std::vector<td::BufferSlice> result;
  result.emplace_back("one");
  result.emplace_back("two");
  return result;
}
void check_signature(const tos::PublicKey& pub, td::Slice bytes, td::Slice signature) {
  auto verifier = value(pub.create_encryptor(), "positive-verifier");
  check(verifier->check_signature(bytes, signature).is_ok(), "positive-signature");
}
void private_refusals(Runner& r, const tos::PrivateKey& secret, const char* code = "keyring-validator-auth-key") {
  auto pub = secret.compute_public_key();
  auto id = pub.compute_short_id();
  auto encryptor = value(pub.create_encryptor(), "positive-encryptor");
  auto encrypted = value(encryptor->encrypt("payload"), "positive-encryption");
  denied(r.call<td::BufferSlice>(&Keyring::sign_message, id, td::BufferSlice("payload")), "keyring-sign", code);
  denied(r.call<Pair>(&Keyring::sign_add_get_public_key, id, td::BufferSlice("payload")), "keyring-sign-public", code);
  denied(r.call<Batch>(&Keyring::sign_messages, id, messages()), "keyring-sign-batch", code);
  denied(r.call<td::BufferSlice>(&Keyring::decrypt_message, id, std::move(encrypted)), "keyring-decrypt", code);
  denied(r.call<tos::PrivateKey>(&Keyring::export_private_key, id), "keyring-export", code);
  denied(r.call<std::vector<tos::PrivateKey>>(&Keyring::export_all_private_keys), "keyring-export-all", code);
  denied(r.call<td::Unit>(&Keyring::add_key, secret, false), "keyring-reimport", code);
  denied(r.call<td::Unit>(&Keyring::add_key, secret, true), "keyring-temp-reimport", code);
  denied(r.call<td::Unit>(&Keyring::del_key, id), "keyring-delete", code);
}
// Both production methods execute in one actor turn. The real asynchronous
// decryptor cannot deliver its result to this actor before protection is queued.
class BarrierKeyring final : public tos::keyring::KeyringImpl {
 public:
  using KeyringImpl::KeyringImpl;
  void probe(tos::PublicKeyHash id, tos::PublicKeyHash designated, td::Promise<unsigned> done) {
    auto completed = std::make_shared<unsigned>(0);
    sign_message(id, td::BufferSlice("barrier"),
                 td::PromiseCreator::lambda([completed](td::Result<td::BufferSlice> result) {
                   if (result.is_ok() && result.ok().size() == 64)
                     *completed |= 1;
                 }));
    protect_validator_auth_key(
        designated,
        td::PromiseCreator::lambda([completed, done = std::move(done)](td::Result<td::Unit> result) mutable {
          done.set_value(result.is_ok() ? *completed : 0);
        }));
    export_private_key(id, td::PromiseCreator::lambda([completed](td::Result<tos::PrivateKey> result) {
                         if (result.is_error() && result.error().message() == "keyring-isolation-barrier")
                           *completed |= 2;
                       }));
    export_all_private_keys(td::PromiseCreator::lambda([completed](td::Result<std::vector<tos::PrivateKey>> result) {
      if (result.is_error() && result.error().message() == "keyring-isolation-barrier")
        *completed |= 4;
    }));
  }
};
void barrier(const fs::path& dir, unsigned designated) {
  td::actor::Scheduler scheduler({1});
  td::actor::ActorOwn<BarrierKeyring> ring;
  std::atomic<bool> added{false}, finished{false};
  unsigned passed = 0;
  scheduler.run_in_context([&] {
    ring = td::actor::create_actor<BarrierKeyring>("barrier-keyring", dir.string());
    td::actor::send_closure(ring, &Keyring::add_key, key(9), false,
                            td::PromiseCreator::lambda([&](td::Result<td::Unit> result) {
                              passed = result.is_ok();
                              added = true;
                            }));
  });
  wait(scheduler, added);
  check(passed, "barrier-key-import");
  scheduler.run_in_context([&] {
    td::actor::send_closure(ring, &BarrierKeyring::probe, key(9).compute_short_id(), key(designated).compute_short_id(),
                            td::PromiseCreator::lambda([&](td::Result<unsigned> result) {
                              passed = result.is_ok() ? result.ok() : 0;
                              finished = true;
                            }));
  });
  wait(scheduler, finished);
  scheduler.run_in_context([&] {
    ring.reset();
    td::actor::SchedulerContext::get().stop();
  });
  while (scheduler.run(0.05)) {
  }
  check(passed & 1, "keyring-drain-barrier");
  check(passed & 2, "keyring-private-barrier");
  check(passed & 4, "keyring-bulk-barrier");
}

void join(pid_t child) {
  int status = 0;
  if (::waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    std::cerr << "HARNESS: child failed\n";
    std::exit(2);
  }
}
void competing_process(const fs::path& base, const char* executable) {
  auto db = base / "concurrent";
  {
    Runner initial(db);
    value(initial.call<td::Unit>(&Keyring::add_key, key(1), false), "concurrent-import");
  }
  int ready[2], release[2];
  check(::pipe(ready) == 0 && ::pipe(release) == 0, "process-pipes");
  auto rd = std::to_string(ready[1]), wr = std::to_string(release[0]), path = db.string();
  auto child = ::fork();
  check(child >= 0, "process-fork");
  if (child == 0) {
    ::close(ready[0]);
    ::close(release[1]);
    ::execl(executable, executable, "--hold", path.c_str(), rd.c_str(), wr.c_str(), nullptr);
    ::_exit(2);
  }
  ::close(ready[1]);
  ::close(release[0]);
  char byte = 0;
  check(::read(ready[0], &byte, 1) == 1 && byte == 'R', "process-ready");
  ::close(ready[0]);
  bool denied_conflict = false, stopped = false;
  {
    Runner r(db);
    value(r.call<tos::PrivateKey>(&Keyring::export_private_key, key(1).compute_short_id()), "concurrent-legacy-read");
    auto conflict = r.call<td::Unit>(&Keyring::protect_validator_auth_key, key(1).compute_short_id());
    denied_conflict = conflict.is_error() && conflict.error().message() == "keyring-isolation-writer-conflict";
    auto future = r.call<tos::PrivateKey>(&Keyring::export_private_key, key(1).compute_short_id());
    stopped = future.is_error() && future.error().message() == "keyring-isolation-unavailable";
  }
  check(::write(release[1], "X", 1) == 1, "process-release");
  ::close(release[1]);
  join(child);
  check(denied_conflict, "keyring-concurrent-writer");
  check(stopped, "keyring-upgrade-stopped");
  Runner r(db);
  value(r.call<td::Unit>(&Keyring::protect_validator_auth_key, key(1).compute_short_id()), "quiescent-protection");
  child = ::fork();
  check(child >= 0, "protected-process-fork");
  if (child == 0) {
    ::execl(executable, executable, "--refused", path.c_str(), nullptr);
    ::_exit(2);
  }
  int status = 0;
  check(::waitpid(child, &status, 0) == child, "protected-process-wait");
  if (!WIFEXITED(status) || WEXITSTATUS(status) > 1) {
    std::cerr << "HARNESS: protected child failed\n";
    std::exit(2);
  }
  check(WEXITSTATUS(status) == 0, "keyring-other-process-refused");
}
int main(int argc, char** argv) {
  try {
    SET_VERBOSITY_LEVEL(verbosity_ERROR);
    if (argc == 5 && std::string(argv[1]) == "--hold") {
      Runner r(argv[2]);
      value(r.call<tos::PrivateKey>(&Keyring::export_private_key, key(1).compute_short_id()), "child-legacy-read");
      int ready = std::stoi(argv[3]), release = std::stoi(argv[4]);
      char byte = 0;
      if (::write(ready, "R", 1) != 1 || ::read(release, &byte, 1) != 1 || byte != 'X')
        return 2;
      ::close(ready);
      ::close(release);
      return 0;
    }
    if (argc == 3 && std::string(argv[1]) == "--refused") {
      Runner r(argv[2]);
      auto result =
          r.call<td::BufferSlice>(&Keyring::sign_message, key(1).compute_short_id(), td::BufferSlice("payload"));
      return result.is_error() && result.error().message() == "keyring-isolation-unavailable" ? 0 : 1;
    }
    check(argc == 2, "fresh-directory-required");
    fs::path base = argv[1];
    check(fs::create_directory(base), "fresh-directory-required");
    ::chmod(base.c_str(), 0700);
    auto db = base / "keys";
    auto protected_key = key(1), network_key = key(2);
    auto id = protected_key.compute_short_id(), network_id = network_key.compute_short_id();
    auto ledger = db / "validator-auth-guard/keys";
    {
      Runner r(db);
      value(r.call<td::Unit>(&Keyring::add_key, protected_key, false), "positive-import");
      value(r.call<td::Unit>(&Keyring::add_key, network_key, false), "positive-network-import");
      auto sig =
          value(r.call<td::BufferSlice>(&Keyring::sign_message, id, td::BufferSlice("payload")), "positive-sign");
      check_signature(protected_key.compute_public_key(), "payload", sig.as_slice());
      auto pair = value(r.call<Pair>(&Keyring::sign_add_get_public_key, id, td::BufferSlice("payload")),
                        "positive-sign-public");
      check_signature(pair.second, "payload", pair.first.as_slice());
      auto batch = value(r.call<Batch>(&Keyring::sign_messages, id, messages()), "positive-batch");
      check(batch.size() == 2, "positive-batch-size");
      check_signature(pair.second, "one", value(std::move(batch[0]), "positive-batch-one").as_slice());
      check_signature(pair.second, "two", value(std::move(batch[1]), "positive-batch-two").as_slice());
      auto encryptor = value(pair.second.create_encryptor(), "positive-encryptor");
      auto encrypted = value(encryptor->encrypt("payload"), "positive-encryption");
      auto plain =
          value(r.call<td::BufferSlice>(&Keyring::decrypt_message, id, std::move(encrypted)), "positive-decrypt");
      check(plain.as_slice() == "payload", "positive-plaintext");
      check(
          value(r.call<tos::PrivateKey>(&Keyring::export_private_key, id), "positive-export").compute_short_id() == id,
          "positive-export-key");
      check(value(r.call<std::vector<tos::PrivateKey>>(&Keyring::export_all_private_keys), "positive-bulk").size() == 2,
            "positive-bulk-count");
      value(r.call<td::Unit>(&Keyring::protect_validator_auth_key, id), "protect-known-key");
      private_refusals(r, protected_key);
      auto bytes = fs::file_size(ledger);
      value(r.call<td::Unit>(&Keyring::protect_validator_auth_key, id), "idempotent-protection");
      check(fs::file_size(ledger) == bytes, "idempotent-protection-log");
      check(value(r.call<tos::PublicKey>(&Keyring::get_public_key, id), "protected-public").compute_short_id() == id,
            "protected-public-key");
      value(r.call<tos::PublicKey>(&Keyring::add_key_short, id), "protected-short-metadata");
      value(r.call<td::Unit>(&Keyring::check_key, id), "protected-check-metadata");
      auto network_sig = value(r.call<td::BufferSlice>(&Keyring::sign_message, network_id, td::BufferSlice("network")),
                               "network-sign");
      check_signature(network_key.compute_public_key(), "network", network_sig.as_slice());
      value(r.call<tos::PrivateKey>(&Keyring::export_private_key, network_id), "network-export");
      value(r.call<td::Unit>(&Keyring::del_key, network_id), "network-delete");
      value(r.call<td::Unit>(&Keyring::add_key, network_key, false), "network-reimport");
    }
    {
      Runner r(db);
      denied(r.call<tos::PrivateKey>(&Keyring::export_private_key, id), "keyring-restart");
      private_refusals(r, protected_key);
    }
    for (auto damage :
         {"corrupt", "missing", "permissions", "hardlink", "symlink", "directory-permissions", "parent-permissions"}) {
      auto copy = base / damage;
      fs::copy(db, copy, fs::copy_options::recursive);
      auto file = copy / "validator-auth-guard/keys";
      if (std::string(damage) == "corrupt") {
        std::ofstream out(file, std::ios::binary | std::ios::app);
        out.put('x');
      }
      if (std::string(damage) == "missing")
        fs::remove(file);
      if (std::string(damage) == "permissions")
        ::chmod(file.c_str(), 0644);
      if (std::string(damage) == "directory-permissions")
        ::chmod(file.parent_path().c_str(), 0755);
      if (std::string(damage) == "parent-permissions")
        ::chmod(copy.c_str(), 0777);
      if (std::string(damage) == "hardlink")
        fs::create_hard_link(file, copy / "linked");
      if (std::string(damage) == "symlink") {
        fs::rename(file, copy / "moved");
        fs::create_symlink(fs::absolute(copy / "moved"), file);
      }
      Runner r(copy);
      denied(r.call<tos::PrivateKey>(&Keyring::export_private_key, network_id), "keyring-storage-closed",
             "keyring-isolation-unavailable");
      private_refusals(r, protected_key, "keyring-isolation-unavailable");
    }
    for (auto damage : {"record-tag", "record-length", "record-duplicate"}) {
      auto copy = base / damage;
      fs::copy(db, copy, fs::copy_options::recursive);
      auto file = copy / "validator-auth-guard/keys";
      fs::remove(file);
      tos::auth::Bytes record{'P', '0', 'K', 1};
      auto raw = id.as_slice();
      record.insert(record.end(), raw.ubegin(), raw.uend());
      if (std::string(damage) == "record-tag")
        record[3] = 2;
      if (std::string(damage) == "record-length")
        record.pop_back();
      {
        auto opened = tos::auth::DurableLog::open(file.string(), true, [](const auto&, auto) { return true; });
        check(opened.ok(), "record-fixture-open");
        auto& log = opened.value();
        check(log->append(record).ok(), "record-fixture-append");
        if (std::string(damage) == "record-duplicate")
          check(log->append(record).ok(), "record-fixture-duplicate");
      }
      Runner r(copy);
      denied(r.call<tos::PrivateKey>(&Keyring::export_private_key, network_id), damage,
             "keyring-isolation-unavailable");
    }
    {
      auto copy = base / "replacement";
      fs::copy(db, copy, fs::copy_options::recursive);
      Runner r(copy);
      value(r.call<tos::PrivateKey>(&Keyring::export_private_key, network_id), "replacement-baseline");
      auto file = copy / "validator-auth-guard/keys";
      fs::rename(file, copy / "old");
      fs::copy_file(copy / "old", file);
      denied(r.call<tos::PrivateKey>(&Keyring::export_private_key, network_id), "keyring-ledger-replacement",
             "keyring-isolation-unavailable");
    }
    {
      Runner r(fs::path{});
      value(r.call<td::Unit>(&Keyring::add_key, protected_key, true), "ephemeral-key");
      denied(r.call<td::Unit>(&Keyring::protect_validator_auth_key, id), "keyring-persistence-required",
             "keyring-isolation-persistence-required");
    }
    {
      auto copy = base / "writable-parent";
      Runner r(copy);
      value(r.call<td::Unit>(&Keyring::add_key, protected_key, false), "writable-parent-import");
      check(::chmod(copy.c_str(), 0777) == 0, "writable-parent-mode");
      denied(r.call<td::Unit>(&Keyring::protect_validator_auth_key, id), "keyring-parent-writable",
             "keyring-isolation-unavailable");
    }
    barrier(base / "barrier", 9);
    barrier(base / "other-key-barrier", 10);
    competing_process(base, argv[0]);
    std::cout << "PASS native Keyring private operations, persistence, fail-closed recovery and drain barrier\n";
  } catch (const std::exception& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
