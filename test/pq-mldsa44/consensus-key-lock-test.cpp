/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// The engine's exclusive hold on a consensus key file.
//
// Each case asks a second, freshly executed process (this binary in its child mode, so it
// shares nothing with this one but the kernel) to load the key while this process holds
// it in some way, and reads its verdict from the exit status:
//   0  the child loaded the key
//   3  the child was refused because another process holds the file
//   4  the child was refused for another reason
//
// Two cases go through this process's own open(2), which the test interposes below: the
// key file is swapped for another one around any second open of its path during a load, so
// a loader that judged one descriptor and read the path again would read the other file.
#undef NDEBUG  // the build is Release, and an assert that is compiled out proves nothing
#include <atomic>
#include <cassert>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <fstream>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <variant>
#include <vector>

#include "consensus-key-file.h"
#include "consensus-key-lock.h"

using namespace tos::pq;

namespace {

// The swap: while armed, every open of `swap_path` is counted, and the second one is made
// while the file at that path is `swap_other`: renamed in just for that open and renamed
// back right after, so the path names the original file again before and after it.
struct SwapControl {
  std::atomic<bool> armed{false};
  std::atomic<int> opens{0};
  char path[512] = {};
  char other[512] = {};
  char saved[512] = {};
};
SwapControl swap_control;

using OpenFn = int (*)(const char*, int, ...);

OpenFn real_open(const char* name) {
  auto fn = reinterpret_cast<OpenFn>(::dlsym(RTLD_NEXT, name));
  if (fn == nullptr) {
    std::abort();
  }
  return fn;
}

int interposed_open(const char* real_name, const char* path, int flags, mode_t mode) {
  static OpenFn open_fn = real_open(real_name);
  if (!swap_control.armed.load() || std::strcmp(path, swap_control.path) != 0) {
    return open_fn(path, flags, mode);
  }
  if (swap_control.opens.fetch_add(1) + 1 != 2) {
    return open_fn(path, flags, mode);
  }
  assert(::rename(swap_control.path, swap_control.saved) == 0);
  assert(::rename(swap_control.other, swap_control.path) == 0);
  const int fd = open_fn(path, flags, mode);
  assert(::rename(swap_control.path, swap_control.other) == 0);
  assert(::rename(swap_control.saved, swap_control.path) == 0);
  return fd;
}

}  // namespace

extern "C" int open(const char* path, int flags, ...) {
  mode_t mode = 0;
  if ((flags & O_CREAT) != 0) {
    va_list args;
    va_start(args, flags);
    mode = static_cast<mode_t>(va_arg(args, int));
    va_end(args);
  }
  return interposed_open("open", path, flags, mode);
}

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

// A process that loads `path` and keeps it until its standard input closes. Returns its
// pid and the pipe whose closing releases it, once it has the key.
std::pair<pid_t, int> hold_elsewhere(const std::string& path) {
  int to_child[2];
  int from_child[2];
  assert(::pipe(to_child) == 0 && ::pipe(from_child) == 0);
  const pid_t pid = ::fork();
  assert(pid >= 0);
  if (pid == 0) {
    ::dup2(to_child[0], 0);
    ::dup2(from_child[1], 1);
    ::close(to_child[1]);
    ::close(from_child[0]);
    ::execl("/proc/self/exe", "test-consensus-key-lock", "--hold", path.c_str(), static_cast<char*>(nullptr));
    std::_Exit(99);
  }
  ::close(to_child[0]);
  ::close(from_child[1]);
  char ready = 0;
  assert(::read(from_child[0], &ready, 1) == 1 && ready == 'y');
  ::close(from_child[0]);
  return {pid, to_child[1]};
}

int run_hold(const std::string& path) {
  auto loaded = load_locked_consensus_key(path, 0);
  if (!std::holds_alternative<std::shared_ptr<const ValidatorPQKeyStore>>(loaded)) {
    return kOtherRefusal;
  }
  const char ready = 'y';
  if (::write(1, &ready, 1) != 1) {
    return kOtherRefusal;
  }
  char byte = 0;
  while (::read(0, &byte, 1) > 0) {
  }
  return kLoaded;
}

// The child's verdict on `path`, or -1 if it has not answered within `seconds`.
int child_verdict_within(const std::string& path, int seconds) {
  const pid_t pid = ::fork();
  assert(pid >= 0);
  if (pid == 0) {
    ::execl("/proc/self/exe", "test-consensus-key-lock", "--child", path.c_str(), static_cast<char*>(nullptr));
    std::_Exit(99);
  }
  for (int waited = 0; waited < seconds * 100; ++waited) {
    int status = 0;
    const pid_t done = ::waitpid(pid, &status, WNOHANG);
    if (done == pid) {
      assert(WIFEXITED(status));
      return WEXITSTATUS(status);
    }
    ::usleep(10'000);
  }
  ::kill(pid, SIGKILL);
  ::waitpid(pid, nullptr, 0);
  return -1;
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
  if (argc == 3 && std::string(argv[1]) == "--hold") {
    return run_hold(argv[2]);
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

  // The file read is the file locked. Another key, B, is held by another process. The key
  // file's path is swapped to B around any second open of it during a load and swapped
  // back at once, so a check of the path afterwards still finds the original file. A loader
  // that locked one descriptor and read the path again would load B, a key another engine
  // signs with; this one opens the path once and reads through the locked descriptor.
  {
    const std::string other = dir + "/other.key";
    auto other_created = create_consensus_key(other);
    assert(std::holds_alternative<ConsensusPQKey>(other_created));
    const auto other_key_id = std::get<ConsensusPQKey>(other_created).key_id;
    auto [holder_pid, release] = hold_elsewhere(other);
    assert(child_verdict(other) == kHeldElsewhere);

    std::snprintf(swap_control.path, sizeof(swap_control.path), "%s", key.c_str());
    std::snprintf(swap_control.other, sizeof(swap_control.other), "%s", other.c_str());
    std::snprintf(swap_control.saved, sizeof(swap_control.saved), "%s.saved", key.c_str());
    swap_control.opens = 0;
    swap_control.armed = true;
    auto loaded = load_locked_consensus_key(key, 0);
    swap_control.armed = false;
    const int opens = swap_control.opens.load();
    assert(std::holds_alternative<std::shared_ptr<const ValidatorPQKeyStore>>(loaded));
    const auto& store = std::get<std::shared_ptr<const ValidatorPQKeyStore>>(loaded);
    std::fprintf(stderr, "swap control: %d open(s) of the key path during the load\n", opens);
    assert(store->consensus_key().key_id != other_key_id);
    assert(opens == 1);

    ::close(release);
    int status = 0;
    assert(::waitpid(holder_pid, &status, 0) == holder_pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == kLoaded);
    ::unlink(other.c_str());
  }

  // A FIFO at the key path is refused at once, not waited on until something writes to it.
  {
    const std::string fifo = dir + "/fifo.key";
    assert(::mkfifo(fifo.c_str(), 0600) == 0);
    assert(child_verdict_within(fifo, 5) == kOtherRefusal);
    ::unlink(fifo.c_str());
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
