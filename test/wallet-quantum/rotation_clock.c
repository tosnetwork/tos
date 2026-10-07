/* Public CLI fixture only. Never linked into a release binary.
 * Move the fixture's wall clock across an LMS slot without changing monotonic
 * time, the protocol slot length, production clock code or journal guards. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static time_t fixture_offset(void) {
  const char *path = getenv("TOS_TEST_CLOCK_OFFSET_FILE");
  if (!path)
    return 0;
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    _exit(81);
  char value[32] = {0};
  ssize_t size = read(fd, value, sizeof(value) - 1);
  close(fd);
  if (size <= 0 || size >= (ssize_t)sizeof(value) - 1)
    _exit(82);
  char *end = NULL;
  long seconds = strtol(value, &end, 10);
  if (*end != '\0' || seconds < 0 || seconds > 86400)
    _exit(83);
  return (time_t)seconds;
}

int clock_gettime(clockid_t clock, struct timespec *value) {
  static int (*real_clock_gettime)(clockid_t, struct timespec *);
  if (!real_clock_gettime)
    real_clock_gettime = dlsym(RTLD_NEXT, "clock_gettime");
  if (!real_clock_gettime)
    _exit(84);
  int result = real_clock_gettime(clock, value);
  if (result == 0 && (clock == CLOCK_REALTIME || clock == CLOCK_REALTIME_COARSE))
    value->tv_sec += fixture_offset();
  return result;
}

time_t time(time_t *result) {
  struct timespec now;
  if (clock_gettime(CLOCK_REALTIME, &now) != 0)
    return (time_t)-1;
  if (result)
    *result = now.tv_sec;
  return now.tv_sec;
}

int gettimeofday(struct timeval *value, void *zone) {
  static int (*real_gettimeofday)(struct timeval *, void *);
  if (!real_gettimeofday)
    real_gettimeofday = dlsym(RTLD_NEXT, "gettimeofday");
  if (!real_gettimeofday)
    _exit(85);
  int result = real_gettimeofday(value, zone);
  if (result == 0)
    value->tv_sec += fixture_offset();
  return result;
}
