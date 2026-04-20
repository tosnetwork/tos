#ifndef HEADER_at_src_util_racesan_at_racesan_base_h
#define HEADER_at_src_util_racesan_at_racesan_base_h

#include "at/infra/at_util_base.h"

#ifndef AT_HAS_RACESAN
#define AT_HAS_RACESAN 0
#endif

/* FIXME Check for AT_HAS_UCONTEXT */

struct at_racesan;
typedef struct at_racesan at_racesan_t;

AT_PROTOTYPES_BEGIN

/* at_racesan_strhash is a FNV-1a for 64-bit implementation of string
   hashing.  Used to hash racesan hook names to integers.  The compiler
   can typically evaluate the following at compile time:

     ulong x = at_racesan_strhash( "hello", sizeof("hello")-1 );
     ... x is resolved at compile time ... */

static inline ulong
at_racesan_strhash( char const * s,
                    ulong        len ) {
  ulong x = 0xCBF29CE484222325UL;
  for( ; len; len--, s++ ) {
    x ^= (ulong)(uchar)( *s );
    x *= 0x100000001B3UL;
  }
  return x;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_src_util_racesan_at_racesan_base_h */