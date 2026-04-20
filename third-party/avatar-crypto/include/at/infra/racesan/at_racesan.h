#ifndef HEADER_at_src_util_racesan_at_racesan_h
#define HEADER_at_src_util_racesan_at_racesan_h

/* at_racesan.h provides test utils for deterministically simulating
   data races.  Practically just a mechanism to inject callbacks into
   instrumented production code (with appropriate compiler hacks to
   invalidate registers/locals).

   See README.md for usage. */

#include "at_racesan_base.h"

/* AT_RACESAN_HOOKS_MAX is the max number of active racesan hooks */

#define AT_RACESAN_HOOKS_LG_MAX (7)
#define AT_RACESAN_HOOKS_MAX    (1UL<<AT_RACESAN_HOOKS_LG_MAX) /* 128 */

typedef void
at_racesan_hook_fn_t( void * ctx,
                      ulong  name_hash );

struct at_racesan_hook_map {
  ulong                  name_hash;
  at_racesan_hook_fn_t * hook;
};

typedef struct at_racesan_hook_map at_racesan_hook_map_t;

struct at_racesan {
  void * hook_ctx;

  at_racesan_hook_fn_t * default_hook;
  at_racesan_hook_map_t  hook_map[ AT_RACESAN_HOOKS_MAX ];
};

typedef struct at_racesan at_racesan_t;

AT_PROTOTYPES_BEGIN

at_racesan_t *
at_racesan_new( at_racesan_t * obj,
                void *         ctx );

void *
at_racesan_delete( at_racesan_t * obj );

/* at_racesan_inject injects a callback into an at_racesan_hook trace
   point.  Useful for fault injection. */

void
at_racesan_inject( at_racesan_t *      obj,
                   char const *        hook,
                   at_racesan_hook_fn_t * callback );

/* at_racesan_inject_default injects a default callback that's called
   by any at_racesan_hook trace points. */

void
at_racesan_inject_default( at_racesan_t *      obj,
                           at_racesan_hook_fn_t * callback );

void
at_racesan_enter( at_racesan_t * racesan );

void
at_racesan_exit( void );

AT_PROTOTYPES_END

static inline void
at_racesan_private_cleanup( int * unused ) {
  (void)unused;
  at_racesan_exit();
}

#define AT_RACESAN_INJECT_BEGIN( _rs )        \
  do {                                        \
    at_racesan_t * __rs = (_rs);              \
    at_racesan_enter( __rs );                 \
    __attribute__((cleanup(at_racesan_private_cleanup))) int __dummy; \
    do {                                      \

#define AT_RACESAN_INJECT_END \
    } while(0); \
  } while(0)

#endif /* HEADER_at_src_util_racesan_at_racesan_h */