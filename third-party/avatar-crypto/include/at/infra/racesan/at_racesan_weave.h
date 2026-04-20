#ifndef HEADER_at_src_util_racesan_at_racesan_weave_h
#define HEADER_at_src_util_racesan_at_racesan_weave_h

/* at_racesan_weave.h tests interleavings of concurrent algorithms. */

#include "at_racesan_async.h"

#define AT_RACESAN_WEAVE_MAX (16UL)

struct at_racesan_weave {
  at_racesan_async_t * async[ AT_RACESAN_WEAVE_MAX ];
  uint                 async_cnt;

  at_racesan_async_t * rem[ AT_RACESAN_WEAVE_MAX ];
  uint                 rem_cnt;
};

typedef struct at_racesan_weave at_racesan_weave_t;

AT_PROTOTYPES_BEGIN

at_racesan_weave_t *
at_racesan_weave_new( at_racesan_weave_t * weave );

void *
at_racesan_weave_delete( at_racesan_weave_t * weave );

void
at_racesan_weave_add( at_racesan_weave_t * weave,
                      at_racesan_async_t * async );

void
at_racesan_weave_exec_rand( at_racesan_weave_t * weave,
                            ulong                seed,
                            ulong                step_max );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_util_racesan_at_racesan_weave_h */