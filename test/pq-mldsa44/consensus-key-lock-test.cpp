/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// The engine's exclusive hold on a consensus key file.
//
// Each case asks a second, freshly executed process (this binary in its child mode, so it
// shares nothing with this one but the kernel) to load the key while this process holds
// it in some way, and reads its verdict from the exit status:
//   0  the child loaded the key
//   3  the child was refused because another process holds the file
//   4  the child was refused for another reason
#undef NDEBUG  // the build is Release, and an assert that is compiled out proves nothing
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <variant>
#include <vector>

#include "consensus-key-file.h"
#include "consensus-key-lock.h"

using namespace tos::pq;

namespace {

constexpr int kLoaded = 0;
constexpr int kHeldElsewhere = 3;
constexpr int kOtherRefusal = 4;

std::string scratch_directory() {
  std::string pattern = "/tmp/tos-consensus-key-lock-XXXXXX";
  char* made = mkdtemp(pattern.data());
  assert(made != nullptr);
  return std::string(made);
}

std::shared_ptr<const ValidatorPQKeyStore> load(const std::string& path) {
  auto loaded = load_locked_consensus_key(path, 0);
  if (std::holds_alternative<std::string>(loaded)) {
    std::fprintf(stderr, "unexpected refusal for %s: %s\n", path.c_str(), std::get<std::string>(loaded).c_str());
    std::abort();
  }
  return std::get<std::shared_ptr<const ValidatorPQKeyStore>>(loaded);
}

// What a separate process gets when it loads `path` now.
int child_verdict(const std::string& path) {
  const pid_t pid = ::fork();
  assert(pid >= 0);
  if (pid == 0) {
    ::execl("/proc/self/exe", "test-consensus-key-lock", "--child", path.c_str(), static_cast<char*>(nullptr));
    std::_Exit(99);
  }
  int status = 0;
  assert(::waitpid(pid, &status, 0) == pid);
  assert(WIFEXITED(status));
  return WEXITSTATUS(status);
}

int run_child(const std::string& path) {
  auto loaded = load_locked_consensus_key(path, 0);
  if (std::holds_alternative<std::shared_ptr<const ValidatorPQKeyStore>>(loaded)) {
    return kLoaded;
  }
  const auto& reason = std::get<std::string>(loaded);
  std::fprintf(stderr, "child refused: %s\n", reason.c_str());
  return reason.find("another process holds") != std::string::npos ? kHeldElsewhere : kOtherRefusal;
}

void copy_file(const std::string& from, const std::string& to) {
  std::ifstream in(from, std::ios::binary);
  std::string bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  {
    std::ofstream out(to, std::ios::binary);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  }
  assert(::chmod(to.c_str(), 0600) == 0);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc == 3 && std::string(argv[1]) == "--child") {
    return run_child(argv[2]);
  }

  const std::string dir = scratch_directory();
  const std::string key = dir + "/consensus.key";
  assert(std::holds_alternative<ConsensusPQKey>(create_consensus_key(key)));

  // Nobody holds it: a process loads it, and the identity it derives is the file's.
  assert(child_verdict(key) == kLoaded);

  {
    // Held here: a second process is refused, and says why.
    auto store = load(key);
    assert(child_verdict(key) == kHeldElsewhere);

    // The same inode under another name is the same key file.
    const std::string link = dir + "/hard-link.key";
    assert(::link(key.c_str(), link.c_str()) == 0);
    assert(child_verdict(link) == kHeldElsewhere);

    // A copy of the seed is another file. The lock does not reach it; that is the stated
    // scope, not a property this test can make true.
    const std::string copy = dir + "/copy.key";
    copy_file(key, copy);
    assert(child_verdict(copy) == kLoaded);

    // Loading the same file again in this process neither conflicts with this process's own
    // lock nor creates a second one.
    auto again = load(link);
    assert(again->consensus_key().key_id == store->consensus_key().key_id);

    // Dropping one of the two loads leaves the other's lock in place.
    store.reset();
    assert(child_verdict(key) == kHeldElsewhere);

    // A signer copied out (as a validator group holds one) keeps the file locked after the
    // load it came from is gone: the lock is released only with the last signer.
    std::shared_ptr<const ValidatorPQKeyStore> group_copy = again;
    again.reset();
    assert(child_verdict(key) == kHeldElsewhere);
    assert(group_copy->sign_consensus("still signing").has_value());
    group_copy.reset();
    ::unlink(link.c_str());
    ::unlink(copy.c_str());
  }

  // Every signer is gone, so the file is free again.
  assert(child_verdict(key) == kLoaded);

  // Load, remove, load again within one process, many times: no self-conflict, no leak of
  // a held lock past its last signer.
  for (int i = 0; i < 64; ++i) {
    auto first = load(key);
    auto second = load(key);
    assert(child_verdict(key) == kHeldElsewhere);
    first.reset();
    second.reset();
  }
  assert(child_verdict(key) == kLoaded);

  // The deadline is the store's own, as for every engine-loaded key.
  {
    auto loaded = load_locked_consensus_key(key, 1);
    assert(std::holds_alternative<std::shared_ptr<const ValidatorPQKeyStore>>(loaded));
    assert(std::get<std::shared_ptr<const ValidatorPQKeyStore>>(loaded)->expire_at() == 1);
  }

  // A key file the shared rules refuse is refused here too, and takes no lock.
  {
    const std::string loose = dir + "/loose.key";
    copy_file(key, loose);
    assert(::chmod(loose.c_str(), 0644) == 0);
    auto loaded = load_locked_consensus_key(loose, 0);
    assert(std::holds_alternative<std::string>(loaded));
    ::unlink(loose.c_str());
  }

  // Filesystems: local ones are supported, network, cluster and userspace ones are refused.
  for (std::uint64_t local :
       {0xEF53ULL, 0x58465342ULL, 0x9123683EULL, 0x01021994ULL, 0x858458F6ULL, 0x794C7630ULL, 0xF2F52010ULL}) {
    assert(consensus_key_lock_supported_filesystem(local));
  }
  for (std::uint64_t remote : {0x6969ULL, 0x517BULL, 0xFF534D42ULL, 0xFE534D42ULL, 0x01021997ULL, 0x65735546ULL,
                               0x00C36400ULL, 0x01161970ULL, 0x7461636FULL, 0x5346414FULL}) {
    assert(!consensus_key_lock_supported_filesystem(remote));
  }
  // A key on a refused filesystem is refused before anything is read. /proc is one the
  // engine never uses for a key, and the only refused filesystem a test can reach without
  // mounting one.
  {
    auto loaded = load_locked_consensus_key("/proc/self/stat", 0);
    assert(std::holds_alternative<std::string>(loaded));
    assert(std::get<std::string>(loaded).find("filesystem") != std::string::npos);
  }

  ::unlink(key.c_str());
  ::rmdir(dir.c_str());
  std::printf("consensus-key-lock: ok\n");
  return 0;
}
