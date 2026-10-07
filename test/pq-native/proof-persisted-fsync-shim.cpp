/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Test-only filesystem failure injection. Never linked into production libraries.
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
static int directory_syncs = 0;
static int inject_fsync(int fd) {
  using Function = int (*)(int);
#if defined(__APPLE__)
  // dyld excludes the interposing image itself from replacement bindings.
  static Function original = &::fsync;
#else
  static auto original = reinterpret_cast<Function>(dlsym(RTLD_NEXT, "fsync"));
#endif
  char path[4096]{};
  bool found = false;
#if defined(__APPLE__)
  found = fcntl(fd, F_GETPATH, path) == 0;
#else
  char link[64]; std::snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
  const auto n = readlink(link, path, sizeof(path) - 1);
  found = n > 0;
  if (found) path[n] = 0;
#endif
  const char *prefix = std::getenv("PROOF_PERSIST_FAULT_DIR");
  struct stat st{};
  if (found && prefix && std::strncmp(path, prefix, std::strlen(prefix)) == 0 &&
      fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) && ++directory_syncs == 2) {
    errno = EIO; return -1;
  }
  return original ? original(fd) : -1;
}
#if defined(__APPLE__)
__attribute__((used, section("__DATA,__interpose")))
static const struct { const void *replacement; const void *original; } entries[] = {
  {reinterpret_cast<const void *>(&inject_fsync), reinterpret_cast<const void *>(&fsync)}
};
#else
extern "C" int fsync(int fd) { return inject_fsync(fd); }
#endif
