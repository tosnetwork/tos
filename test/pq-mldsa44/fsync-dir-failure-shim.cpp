/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Test-only LD_PRELOAD shim: while TOS_TEST_FAIL_DIR_FSYNC is set, fsync on a directory
// fails with EIO and fsync on anything else is the real one. It lets a test reach the
// one failure a tool can meet after its rename has already put a file in place.
//
// A long-running process (the validator engine) also flushes directories that have
// nothing to do with the case under test, so it is armed differently: with
// TOS_TEST_FAIL_DIR_FSYNC_WHEN naming a file, directory fsync fails only while that file
// exists, and the test creates it just before the operation it means to fail.
#include <cerrno>
#include <cstdlib>
#include <dlfcn.h>
#include <sys/stat.h>

extern "C" int fsync(int fd) {
  using real_fsync_t = int (*)(int);
  static real_fsync_t real = reinterpret_cast<real_fsync_t>(dlsym(RTLD_NEXT, "fsync"));
  struct stat st{};
  const char* trigger = std::getenv("TOS_TEST_FAIL_DIR_FSYNC_WHEN");
  struct stat armed{};
  const bool fail =
      std::getenv("TOS_TEST_FAIL_DIR_FSYNC") != nullptr || (trigger != nullptr && ::stat(trigger, &armed) == 0);
  if (fail && ::fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)) {
    errno = EIO;
    return -1;
  }
  if (real == nullptr) {
    errno = ENOSYS;
    return -1;
  }
  return real(fd);
}
