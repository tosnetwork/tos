// Checks the diagnostic channel where it is unavailable (anything but Linux):
// starting it must fail without opening a descriptor, starting a thread or
// publishing a producer. The unavailable implementation is selected on Linux
// so the check runs here.
#define TOS_DIAGNOSTIC_IPC_FORCE_UNSUPPORTED 1
#include <cstdio>
#include <cstdlib>
#include <dirent.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include "metrics/diagnostic-ipc.h"

namespace {

int count_entries(const char *path) {
  DIR *dir = opendir(path);
  if (dir == nullptr)
    return -1;
  int count = 0;
  while (readdir(dir) != nullptr)
    ++count;
  closedir(dir);
  return count;
}

int fail(const char *what) {
  std::fprintf(stderr, "diagnostic-ipc-unsupported: %s\n", what);
  return 1;
}

}  // namespace

int main() {
  static_assert(TOS_DIAGNOSTIC_IPC_SUPPORTED == 0, "the unavailable implementation must be selected");
  char directory[] = "/tmp/tos-diagnostic-unsupported-XXXXXX";
  if (mkdtemp(directory) == nullptr)
    return fail("cannot create a private directory");
  // A request that the Linux channel would accept: private directory, own pid.
  const std::string path = std::string(directory) + "/diagnostic.sock";
  const int fds_before = count_entries("/proc/self/fd");
  const int threads_before = count_entries("/proc/self/task");
  {
    tos::health::DiagnosticIpc ipc(path, getpid(), {}, 1);
    if (ipc.start())
      return fail("start() succeeded on the unavailable channel");
    if (tos::health::diagnostic_producer.load() != nullptr)
      return fail("a producer was published");
    if (count_entries("/proc/self/fd") != fds_before)
      return fail("a descriptor was opened");
    if (count_entries("/proc/self/task") != threads_before)
      return fail("a thread was started");
    ipc.stop();
  }
  struct stat st{};
  if (lstat(path.c_str(), &st) == 0)
    return fail("a socket file was created");
  rmdir(directory);
  std::puts("diagnostic-ipc-unsupported: ok");
  return 0;
}
