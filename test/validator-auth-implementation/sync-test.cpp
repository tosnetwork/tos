#include <cerrno>
#include <dlfcn.h>
#include <filesystem>
#include <iostream>
#include <unistd.h>

#include "validator/auth/durable-log.h"
static bool fail_sync = false;
extern "C" int fsync(int fd) {
  if (fail_sync) {
    errno = EIO;
    return -1;
  }
  using Sync = int (*)(int);
  auto real = reinterpret_cast<Sync>(dlsym(RTLD_NEXT, "fsync"));
  if (!real) {
    errno = ENOSYS;
    return -1;
  }
  return real(fd);
}
int main(int argc, char** argv) {
  using namespace tos::auth;
  if (argc != 2)
    return 2;
  auto log = DurableLog::open(argv[1], true,
                              [](const LogFrontier&, std::span<const std::uint8_t>) { return Result<bool>(true); });
  if (!log.ok()) {
    std::cerr << "BASELINE: " << log.error().code << '\n';
    return 2;
  }
  fail_sync = true;
  if (log.value()->append(Bytes{1}).ok()) {
    std::cerr << "ASSERTION: sync-before-success\n";
    return 1;
  }
  fail_sync = false;
  if (log.value()->append(Bytes{2}).ok()) {
    std::cerr << "ASSERTION: stopped-after-ambiguous-sync\n";
    return 1;
  }
  std::cout << "PASS: injected real fsync failure stops this log without retry\n";
  return 0;
}
