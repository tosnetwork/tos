/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
/* Test-only LD_PRELOAD shim: counts fsync and fdatasync calls on files under the
 * path prefix in TOS_FSYNC_COUNT_PREFIX, then performs the real call. The test
 * reads and resets the count through the two functions below, found with
 * dlsym, and fails when they are missing, so a run without the shim cannot
 * pass by counting nothing. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static atomic_long tos_fsync_count;

static int tos_fsync_matches(int fd) {
  const char *prefix = getenv("TOS_FSYNC_COUNT_PREFIX");
  if (prefix == NULL || prefix[0] == '\0') {
    return 0;
  }
  char link[64];
  char path[4096];
  snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
  ssize_t length = readlink(link, path, sizeof(path) - 1);
  if (length < 0) {
    return 0;
  }
  path[length] = '\0';
  return strncmp(path, prefix, strlen(prefix)) == 0;
}

int fsync(int fd) {
  static int (*real_fsync)(int);
  if (real_fsync == NULL) {
    real_fsync = (int (*)(int))dlsym(RTLD_NEXT, "fsync");
  }
  if (tos_fsync_matches(fd)) {
    atomic_fetch_add(&tos_fsync_count, 1);
  }
  return real_fsync(fd);
}

int fdatasync(int fd) {
  static int (*real_fdatasync)(int);
  if (real_fdatasync == NULL) {
    real_fdatasync = (int (*)(int))dlsym(RTLD_NEXT, "fdatasync");
  }
  if (tos_fsync_matches(fd)) {
    atomic_fetch_add(&tos_fsync_count, 1);
  }
  return real_fdatasync(fd);
}

long tos_fsync_count_for_testing(void) {
  return atomic_load(&tos_fsync_count);
}

void tos_fsync_reset_for_testing(void) {
  atomic_store(&tos_fsync_count, 0);
}
