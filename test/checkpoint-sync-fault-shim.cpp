/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Test-only LD_PRELOAD shim for the consensus cleanup checkpoint's uncertain
// writes. While the file named by CHECKPOINT_FAULT_TRIGGER exists, fsync and
// fdatasync of any file under CHECKPOINT_FAULT_DIR fail with EIO, after the
// data has already been written to the file (so a synced RocksDB write fails
// at its WAL sync, as on a failing disk). Each failed call is appended to
// CHECKPOINT_FAULT_LOG as "<call> <path>". Nothing else is changed, and nothing
// fails while the trigger file is absent. It is never linked into a node.
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

bool path_of(int fd, char* out, std::size_t size) {
  char link[64];
  std::snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
  auto length = ::readlink(link, out, size - 1);
  if (length <= 0) {
    return false;
  }
  out[length] = '\0';
  return true;
}

bool armed() {
  const char* trigger = std::getenv("CHECKPOINT_FAULT_TRIGGER");
  struct stat info{};
  return trigger != nullptr && ::stat(trigger, &info) == 0;
}

bool watched(int fd, char* path, std::size_t size) {
  const char* prefix = std::getenv("CHECKPOINT_FAULT_DIR");
  return prefix != nullptr && path_of(fd, path, size) && std::strncmp(path, prefix, std::strlen(prefix)) == 0;
}

void record(const char* call, const char* path) {
  const char* log = std::getenv("CHECKPOINT_FAULT_LOG");
  if (log == nullptr) {
    return;
  }
  if (FILE* file = std::fopen(log, "a")) {
    std::fprintf(file, "%s %s\n", call, path);
    std::fclose(file);
  }
}

template <class F>
F next(const char* name) {
  return reinterpret_cast<F>(::dlsym(RTLD_NEXT, name));
}

bool fail(const char* call, int fd) {
  char path[4096];
  if (!armed() || !watched(fd, path, sizeof(path))) {
    return false;
  }
  record(call, path);
  errno = EIO;
  return true;
}

}  // namespace

extern "C" int fsync(int fd) {
  static auto real = next<int (*)(int)>("fsync");
  if (fail("fsync", fd)) {
    return -1;
  }
  return real(fd);
}

extern "C" int fdatasync(int fd) {
  static auto real = next<int (*)(int)>("fdatasync");
  if (fail("fdatasync", fd)) {
    return -1;
  }
  return real(fd);
}
