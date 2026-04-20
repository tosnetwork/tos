#ifndef HEADER_at_src_util_bits_at_sat_h
#define HEADER_at_src_util_bits_at_sat_h

#include "at_bits.h"

/* Set of primitives for saturating math operations, mimicking the behaviour
   of Rust's primitive `saturating_add`, `saturating_sub`, `saturating_mul` operations.
   These saturate at the boundaries of the integer representation, instead of overflowing
   or underflowing.

   Note that this is a placeholder API, and the implementations will be optimised and
   hardened in the future.  The intent of this is to provide an abstraction for saturating
   operations which can be used throughout the codebase, providing a single place to optimize
   these. */

AT_PROTOTYPES_BEGIN

#if AT_HAS_INT128

AT_FN_CONST static inline __uint128_t
at_uint128_sat_add( __uint128_t x, __uint128_t y ) {
  __uint128_t res = x + y;
  return at_uint128_if( res < x, UINT128_MAX, res );
}

AT_FN_CONST static inline __uint128_t
at_uint128_sat_mul( __uint128_t x, __uint128_t y ) {
  __uint128_t res = x * y;
  uchar overflow = ( x != 0 ) && ( y != 0 ) && ( ( res < x ) || ( res < y ) || ( ( res / x ) != y ) );
  return at_uint128_if( overflow, UINT128_MAX, res );
}

AT_FN_CONST static inline __uint128_t
at_uint128_sat_sub( __uint128_t x, __uint128_t y ) {
  __uint128_t res = x - y;
  return at_uint128_if( res > x, 0, res );
}

#endif /* AT_HAS_INT128 */

AT_FN_CONST static inline ulong
at_ulong_sat_add( ulong x, ulong y ) {
  ulong res;
  int cf = __builtin_uaddl_overflow ( x, y, &res );
  return at_ulong_if( cf, ULONG_MAX, res );
}

AT_FN_CONST static inline ulong
at_ulong_sat_mul( ulong x, ulong y ) {
  ulong res;
  int cf = __builtin_umull_overflow ( x, y, &res );
  return at_ulong_if( cf, ULONG_MAX, res );
}

AT_FN_CONST static inline ulong
at_ulong_sat_sub( ulong x, ulong y ) {
  ulong res;
  int cf = __builtin_usubl_overflow ( x, y, &res );
  return at_ulong_if( cf, 0UL, res );
}

AT_FN_CONST static inline long
at_long_sat_add( long x, long y ) {
  long res;
  int cf = __builtin_saddl_overflow ( x, y, &res );
  /* https://stackoverflow.com/a/56531252
     x + y overflows => x, y have the same sign
     we can use either to determine the result,
     with the trick described in the SO answe.
     We chose x because it works also for sub. */
  return at_long_if( cf, (long)((ulong)x >> 63) + LONG_MAX, res );
}

AT_FN_CONST static inline long
at_long_sat_sub( long x, long y ) {
  long res;
  int cf = __builtin_ssubl_overflow ( x, y, &res );
  return at_long_if( cf, (long)((ulong)x >> 63) + LONG_MAX, res );
}

/* at_long_sat_mul is left as an exercise to the reader */

AT_FN_CONST static inline uint
at_uint_sat_add( uint x, uint y ) {
  uint res;
  int cf = __builtin_uadd_overflow ( x, y, &res );
  return at_uint_if( cf, UINT_MAX, res );
}

AT_FN_CONST static inline uint
at_uint_sat_mul( uint x, uint y ) {
  uint res;
  int cf = __builtin_umul_overflow ( x, y, &res );
  return at_uint_if( cf, UINT_MAX, res );
}

AT_FN_CONST static inline uint
at_uint_sat_sub( uint x, uint y ) {
  uint res;
  int cf = __builtin_usub_overflow ( x, y, &res );
  return at_uint_if( cf, 0U, res );
}

AT_FN_CONST static inline ushort
at_ushort_sat_add( ushort x, ushort y ) {
  uint res = x+y;
  return at_ushort_if( res>USHORT_MAX, USHORT_MAX, (ushort)res );
}

AT_FN_CONST static inline ushort
at_ushort_sat_mul( ushort x, ushort y ) {
  uint res = x*y;
  return at_ushort_if( res>USHORT_MAX, USHORT_MAX, (ushort)res );
}

AT_FN_CONST static inline double
at_double_sat_add( double x, double y ) {
  // What does rust do here?
  return x + y;
}

AT_FN_CONST static inline double
at_double_sat_mul( double x, double y ) {
  // What does rust do here?
  return x * y;
}

AT_FN_CONST static inline double
at_double_sat_sub( double x, double y ) {
  // What does rust do here?
  return x - y;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_src_util_bits_at_sat_h */