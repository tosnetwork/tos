/* Pins time() to TOS_FIXED_CLOCK for one process, so recorded live proof
 * material can be re-verified at the moment it was recorded. Test use only:
 * loaded with LD_PRELOAD by a wrapper the test itself provisions as the
 * verifier executable. */
#include <stdlib.h>
#include <time.h>

time_t time(time_t* out) {
  const char* fixed = getenv("TOS_FIXED_CLOCK");
  time_t value = fixed ? (time_t)strtoll(fixed, NULL, 10) : (time_t)0;
  if (out) {
    *out = value;
  }
  return value;
}
