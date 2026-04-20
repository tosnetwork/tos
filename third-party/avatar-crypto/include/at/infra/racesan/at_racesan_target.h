#ifndef HEADER_at_src_util_racesan_at_racesan_target_h
#define HEADER_at_src_util_racesan_at_racesan_target_h

/* at_racesan_target.h provides macros to instrument a shared memory
   concurrent algorithm with racesan.  These are zero cost if racesan
   is disabled (default in production). */

#include "at_racesan_base.h"

#if AT_HAS_RACESAN

/* To instrument an algorithm with racesan, call at_racesan_hook at
   critical sections.  For example:

     at_racesan_hook( "load_pre" );
     ulong x = AT_VOLATILE_CONST( *p );
     at_racesan_hook( "load_post" );
     x++;
     AT_VOLATILE_CONST( *p ) = x;
     at_racesan_hook( "store_post" ); */

void
at_racesan_hook_private( ulong        name_hash,
                         char const * file,
                         int          line );

#define at_racesan_hook( name ) at_racesan_hook_private( at_racesan_strhash( (name), sizeof( name )-1UL ), __FILE__, __LINE__ )

#else

#define at_racesan_hook( ... )

#endif /* AT_HAS_RACESAN */

AT_PROTOTYPES_BEGIN

/* racesan instrumentation is set up per thread. */
extern AT_TL at_racesan_t * at_racesan_g;

AT_PROTOTYPES_END

#endif /* HEADER_at_src_util_racesan_at_racesan_target_h */