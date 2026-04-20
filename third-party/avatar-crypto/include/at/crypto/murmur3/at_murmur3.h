#ifndef HEADER_at_ballet_murmur3_at_murmur3_h
#define HEADER_at_ballet_murmur3_at_murmur3_h

/* at_murmur3 provides APIs for Murmur3 hashing of messages.
   MurmurHash3 implementation for TBPF syscall dispatch */

#include "at/infra/at_util_base.h"
#include "at/infra/at_util.h"

AT_PROTOTYPES_BEGIN

/* at_murmur3_32 computes the Murmur3-32 hash given a hash seed and a
   contiguous memory region to serve as input of size sz.  data points
   to the first byte of the input and may be freed on return.  Returns
   the hash digest as a 32-bit integer.  Is idempotent (Guaranteed to
   return the same hash given the same seed and input byte stream) */

AT_FN_PURE uint
at_murmur3_32( void const * data,
               ulong        sz,
               uint         seed );

/* at_pchash computes the hash of a program counter suitable for use as
   the call instruction immediate.  Equivalent to at_murmur3_32 with
   zero seed and pc serialized to little-endian ulong. */

static inline uint
at_pchash( uint pc ) {
  uint x = pc;
  x *= 0xcc9e2d51U;
  x  = at_uint_rotate_left( x, 15 );
  x *= 0x1b873593U;
  x  = at_uint_rotate_left( x, 13 );
  x *= 5;
  x += 0xe6546b64U;
  x  = at_uint_rotate_left( x, 13 );
  x *= 5;
  x += 0xe6546b64U;
  x ^= 8;
  x ^= x >> 16;
  x *= 0x85ebca6bU;
  x ^= x >> 13;
  x *= 0xc2b2ae35U;
  x ^= x >> 16;
  return x;
}

/* Inverse of the above.  E.g.:
     at_pchash_inverse( at_pchash( (uint)x ) )==(uint)x
   and:
     at_pchash( at_pchash_inverse( (uint)x ) )==(uint)x */

static inline uint
at_pchash_inverse( uint hash ) {
  uint x = hash;
  x ^= x >> 16;
  x *= 0x7ed1b41dU;
  x ^= (x >> 13) ^ (x >> 26);
  x *= 0xa5cb9243U;
  x ^= x >> 16;
  x ^= 8;
  x -= 0xe6546b64U;
  x *= 0xcccccccdU;
  x  = at_uint_rotate_right( x, 13 );
  x -= 0xe6546b64U;
  x *= 0xcccccccdU;
  x  = at_uint_rotate_right( x, 13 );
  x *= 0x56ed309bU;
  x  = at_uint_rotate_right( x, 15 );
  x *= 0xdee13bb1U;
  return x;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_ballet_murmur3_at_murmur3_h */