/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
/*
 * Makes fsync and fdatasync slow for files whose path contains a given
 * substring, as if those files sat on a slow disk. Loaded with LD_PRELOAD into
 * a node under test; nothing else about the node changes.
 *
 *   TOS_SLOW_SYNC_PATH    substring of the file path to slow down (required)
 *   TOS_SLOW_SYNC_MS      delay added to each matching sync, in milliseconds
 *   TOS_SLOW_SYNC_REPORT  file that receives "<matching syncs> <other syncs>"
 *                         at exit, so a run can prove the delay was applied
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static unsigned long slowed;
static unsigned long passed;

static void report(void);

static int matches(int fd) {
  const char *want = getenv("TOS_SLOW_SYNC_PATH");
  if (want == NULL || *want == '\0') {
    return 0;
  }
  char link[64];
  char path[4096];
  snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
  ssize_t n = readlink(link, path, sizeof(path) - 1);
  if (n < 0) {
    return 0;
  }
  path[n] = '\0';
  return strstr(path, want) != NULL;
}

static void delay(int fd) {
  if (!matches(fd)) {
    __atomic_fetch_add(&passed, 1, __ATOMIC_RELAXED);
    return;
  }
  __atomic_fetch_add(&slowed, 1, __ATOMIC_RELAXED);
  // Reported as it happens: a node stopped by a signal runs no destructors.
  report();
  const char *ms_text = getenv("TOS_SLOW_SYNC_MS");
  long ms = ms_text != NULL ? atol(ms_text) : 0;
  if (ms <= 0) {
    return;
  }
  struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
  while (nanosleep(&ts, &ts) != 0) {
  }
}

int fsync(int fd) {
  static int (*real)(int);
  if (real == NULL) {
    real = (int (*)(int))dlsym(RTLD_NEXT, "fsync");
  }
  delay(fd);
  return real(fd);
}

int fdatasync(int fd) {
  static int (*real)(int);
  if (real == NULL) {
    real = (int (*)(int))dlsym(RTLD_NEXT, "fdatasync");
  }
  delay(fd);
  return real(fd);
}

__attribute__((destructor)) static void report(void) {
  /* Several threads may sync at once; the last writer wins, which is enough. */
  const char *report_path = getenv("TOS_SLOW_SYNC_REPORT");
  if (report_path == NULL || *report_path == '\0') {
    return;
  }
  FILE *f = fopen(report_path, "w");
  if (f == NULL) {
    return;
  }
  fprintf(f, "%lu %lu\n", __atomic_load_n(&slowed, __ATOMIC_RELAXED), __atomic_load_n(&passed, __ATOMIC_RELAXED));
  fclose(f);
}
