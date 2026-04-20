#ifndef HEADER_at_src_tango_tempo_at_tempo_h
#define HEADER_at_src_tango_tempo_at_tempo_h

/* APIs for measuring time and tick intervals. */

#include "at_tango_base.h"
#include "at/infra/rng/at_rng.h"

AT_PROTOTYPES_BEGIN

/* at_tempo_wallclock_model returns an estimate of t0, the minimum cost
   of at_get_current_time_in_nanos() in ticks.  If opt_tau is non_NULL,
   on return, *opt_tau will contain an estimate of typical jitter
   associated with at_get_current_time_in_nanos(). */

double
at_tempo_wallclock_model( double * opt_tau );

/* at_tempo_tickcount_model does the same as at_tempo_wallclock model
   for at_tickcount().  The model parameter units will be in ticks
   instead of nanoseconds. */

double
at_tempo_tickcount_model( double * opt_tau );

/* at_tempo_set_tick_per_ns explicitly sets the return values of
   at_tempo_tick_per_ns below, subsequent calls to that function will
   return the values given here. */

void
at_tempo_set_tick_per_ns( double _mu,
                          double _sigma );

/* at_tempo_tick_per_ns is the same as the above but gives an estimate
   of the rate at_tickcount() ticks relative to
   at_get_current_time_in_nanos() (this is in Ghz). */

double
at_tempo_tick_per_ns( double * opt_sigma );

/* at_tempo_observe_pair observes at_get_current_time_in_nanos() and
   at_tickcount() at the "same time". */

long
at_tempo_observe_pair( long * opt_now,
                       long * opt_tic );

/* at_tempo_lazy_default returns a target interval between housekeeping
   events in ns (laziness) for a producer / consumer that has a maximum
   credits of cr_max / lag behind the producer of lag_max.

   We use 1+floor( 9*cr_max/4 )) ~ 2.25 cr_max to keep things simple.
   We also saturate cr_max to keep the returned value in [1,2^31] ns
   for all cr_max. */

AT_FN_CONST static inline long
at_tempo_lazy_default( ulong cr_max ) {
  return at_long_if( cr_max>954437176UL, (long)INT_MAX, (long)(1UL+((9UL*cr_max)>>2)) );
}

/* at_tempo_async_min picks a reasonable minimum interval in ticks
   between housekeeping events.  On success, returns positive integer
   power of two in [1,2^31].  On failure, returns zero (logs details). */

ulong
at_tempo_async_min( long  lazy,
                    ulong event_cnt,
                    float tick_per_ns );

/* at_tempo_async_reload returns a quality random number very quickly in
   [async_min,2*async_min).  Assumes async_min is an integer power of 2
   in [1,2^31].  Consumes exactly 1 rng slot.  This is typically used to
   randomize the timing of background task processing to avoid auto
   synchronization anomalies. */

static inline ulong
at_tempo_async_reload( at_rng_t * rng,
                       ulong      async_min ) {
  return async_min + (((ulong)at_rng_uint( rng )) & (async_min-1UL));
}

AT_PROTOTYPES_END

#endif /* HEADER_at_src_tango_tempo_at_tempo_h */
