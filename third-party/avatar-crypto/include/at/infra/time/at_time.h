#ifndef HEADER_at_include_at_infra_time_at_time_h
#define HEADER_at_include_at_infra_time_at_time_h

#include "at/infra/log/at_log.h"

AT_PROTOTYPES_BEGIN

/* TOS-aligned time helpers.
   All values are Unix epoch based (UTC). */

static inline ulong
at_get_current_time_in_nanos( void ) {
  return (ulong)at_log_wallclock();
}

static inline ulong
at_get_current_time_in_millis( void ) {
  return at_get_current_time_in_nanos() / 1000000UL;
}

static inline ulong
at_get_current_time_in_seconds( void ) {
  return at_get_current_time_in_nanos() / 1000000000UL;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_include_at_infra_time_at_time_h */
