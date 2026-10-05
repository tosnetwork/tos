/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Test-only LD_PRELOAD shim for the live-state commit path of tos-proof-verify.
// It records fsync, close and rename on paths under PROOF_VERIFY_FS_DIR into
// PROOF_VERIFY_FS_LOG, and fails a directory fsync when PROOF_VERIFY_FAIL_DIR_FSYNC
// is set. It is never linked into the verifier.
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

thread_local bool recording = false;

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

bool watched(const char* path) {
  const char* prefix = std::getenv("PROOF_VERIFY_FS_DIR");
  return prefix != nullptr && path != nullptr && std::strncmp(path, prefix, std::strlen(prefix)) == 0;
}

void record(const char* operation, const char* first, const char* second = "") {
  const char* log = std::getenv("PROOF_VERIFY_FS_LOG");
  if (log == nullptr || recording) {
    return;
  }
  recording = true;
  if (FILE* file = std::fopen(log, "a")) {
    std::fprintf(file, "%s %s %s\n", operation, first, second);
    std::fclose(file);
  }
  recording = false;
}

template <class F>
F next(const char* name) {
  return reinterpret_cast<F>(::dlsym(RTLD_NEXT, name));
}

}  // namespace

extern "C" int fsync(int fd) {
  static auto real = next<int (*)(int)>("fsync");
  char path[4096];
  struct stat info{};
  if (path_of(fd, path, sizeof(path)) && watched(path)) {
    const bool directory = ::fstat(fd, &info) == 0 && S_ISDIR(info.st_mode);
    record(directory ? "fsync-dir" : "fsync", path);
    if (directory && std::getenv("PROOF_VERIFY_FAIL_DIR_FSYNC") != nullptr) {
      errno = EIO;
      return -1;
    }
  }
  return real(fd);
}

extern "C" int close(int fd) {
  static auto real = next<int (*)(int)>("close");
  char path[4096];
  if (!recording && path_of(fd, path, sizeof(path)) && watched(path)) {
    record("close", path);
  }
  return real(fd);
}

extern "C" int rename(const char* from, const char* to) {
  static auto real = next<int (*)(const char*, const char*)>("rename");
  if (watched(to)) {
    record("rename", from, to);
  }
  return real(from, to);
}
