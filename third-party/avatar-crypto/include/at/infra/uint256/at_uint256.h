#include "at/infra/bits/at_bits.h"

#ifndef HEADER_at_src_infra_uint256_at_uint256_h
#define HEADER_at_src_infra_uint256_at_uint256_h

/* Implementation of uint256. */

#include <stdint.h>
#include "../at_util_base.h"
#include "at/crypto/at_crypto_base.h"

/* Align at most at 32 bytes.
   This way a struct containing multiple at_uint256_t doesn't waste space
   (e.g., on avx512 AT_ALIGNED would be 64, causing each at_uint256_t to
   consume 64 bytes instead of 32).
   Note: AT_ALIGNED implies AT_UINT256_ALIGNED, so a struct containing 1+
   at_uint256_t can be simply defined as AT_ALIGNED, and it's also implicitly
   AT_UINT256_ALIGNED. */
#if AT_ALIGN > 32
#define AT_UINT256_ALIGNED __attribute__((aligned(32)))
#else
#define AT_UINT256_ALIGNED AT_ALIGNED
#endif

/* at_uint256_t represents a uint256 as a buffer of 32 bytes,
   or equivalently (on little endian platforms) an array of 4 uint64_t.
   Note: We use uint64_t instead of ulong for compatibility with fiat-crypto,
   which uses uint64_t. On some platforms (macOS), ulong and uint64_t are
   different types even though both are 64-bit. */
union AT_UINT256_ALIGNED at_uint256 {
  uint64_t limbs[4];
  uchar buf[32];
};
typedef union at_uint256 at_uint256_t;

/* at_uint256_bswap swaps 32 bytes. Useful to convert from/to
   little and big endian. */
static inline at_uint256_t *
at_uint256_bswap( at_uint256_t *       r,
                  at_uint256_t const * a ) {
  uint64_t r3 = at_ulong_bswap( a->limbs[0] );
  uint64_t r2 = at_ulong_bswap( a->limbs[1] );
  uint64_t r1 = at_ulong_bswap( a->limbs[2] );
  uint64_t r0 = at_ulong_bswap( a->limbs[3] );
  r->limbs[3] = r3;
  r->limbs[2] = r2;
  r->limbs[1] = r1;
  r->limbs[0] = r0;
  return r;
}

/* at_ulong_n_bswap swaps 8*n bytes (n must be even).
   Useful to convert from/to little and big endian.
   This is written with a loop for readability, the compiler optimizes it away. */
static inline void
at_ulong_n_bswap( uint64_t       r[], /* size n uint64_t, i.e. 8*n bytes */
                  uint64_t const n    /* must be even */ ) {
  /* note: this only works for even n */
  for( uint64_t j=0; j<n/2; j++ ) {
    uint64_t aj = at_ulong_bswap( r[j] );
    uint64_t bj = at_ulong_bswap( r[n-1-j] );
    r[j] = bj;
    r[n-1-j] = aj;
  }
}

/* at_uint256_eq returns 1 is a == b, 0 otherwise. */
static inline int
at_uint256_eq( at_uint256_t const * a,
               at_uint256_t const * b ) {
  return ( a->limbs[0] == b->limbs[0] )
      && ( a->limbs[1] == b->limbs[1] )
      && ( a->limbs[2] == b->limbs[2] )
      && ( a->limbs[3] == b->limbs[3] );
}

/* at_uint256_cmp returns 0 is a == b, -1 if a < b, 1 if a > b. */
static inline int
at_uint256_cmp( at_uint256_t const * a,
                at_uint256_t const * b ) {
  for( int i=3; i>=0; i-- ) {
    if( a->limbs[i] != b->limbs[i] ) {
      return a->limbs[i] > b->limbs[i] ? 1 : -1;
    }
  }
  return 0;
}

/* at_uint256_bit returns the i-th bit of a.
   Important: the return value is 0, non-zero, it's NOT 0, 1. */
static inline uint64_t
at_uint256_bit( at_uint256_t const * a,
                int                  i ) {
  return a->limbs[i / 64] & (UINT64_C(1) << (i % 64));
}

/* at_uint256_is_zero returns 1 if a == 0, 0 otherwise. */
static inline int
at_uint256_is_zero( at_uint256_t const * a ) {
  return ( a->limbs[0] == 0 )
      && ( a->limbs[1] == 0 )
      && ( a->limbs[2] == 0 )
      && ( a->limbs[3] == 0 );
}

/* at_uint256_sub computes r = a - b.
   Returns 1 if there was a borrow (underflow), 0 otherwise. */
static inline int
at_uint256_sub( at_uint256_t *       r,
                at_uint256_t const * a,
                at_uint256_t const * b ) {
  int borrow = 0;
  for( int i = 0; i < 4; i++ ) {
    uint64_t bi = b->limbs[i] + (uint64_t)borrow;
    borrow = ( bi < b->limbs[i] ) || ( a->limbs[i] < bi );
    r->limbs[i] = a->limbs[i] - bi;
  }
  return borrow;
}

/* at_uint256_mul computes r = a * b (lower 256 bits of 512-bit result).
   Note: r may alias a or b. */
static inline at_uint256_t *
at_uint256_mul( at_uint256_t *       r,
                at_uint256_t const * a,
                at_uint256_t const * b ) {
  uint64_t res[4] = { 0, 0, 0, 0 };

  for( int i = 0; i < 4; i++ ) {
    uint64_t carry = 0;
    for( int j = 0; j < 4 - i; j++ ) {
#if AT_HAS_INT128
      uint128 prod = (uint128)a->limbs[i] * (uint128)b->limbs[j] +
                     (uint128)res[i + j] + (uint128)carry;
      res[i + j] = (uint64_t)prod;
      carry = (uint64_t)( prod >> 64 );
#else
      /* Fallback without uint128 */
      uint64_t al = a->limbs[i] & 0xFFFFFFFF;
      uint64_t ah = a->limbs[i] >> 32;
      uint64_t bl = b->limbs[j] & 0xFFFFFFFF;
      uint64_t bh = b->limbs[j] >> 32;

      uint64_t ll = al * bl;
      uint64_t lh = al * bh;
      uint64_t hl = ah * bl;
      uint64_t hh = ah * bh;

      uint64_t mid = lh + hl;
      uint64_t mid_carry = ( mid < lh ) ? UINT64_C(1) << 32 : 0;

      uint64_t lo = ll + ( mid << 32 );
      uint64_t lo_carry = ( lo < ll ) ? 1 : 0;
      uint64_t hi = hh + ( mid >> 32 ) + mid_carry + lo_carry;

      uint64_t sum = res[i + j] + lo;
      uint64_t sum_carry = ( sum < res[i + j] ) ? 1 : 0;
      sum += carry;
      sum_carry += ( sum < carry ) ? 1 : 0;

      res[i + j] = sum;
      carry = hi + sum_carry;
#endif
    }
  }

  r->limbs[0] = res[0];
  r->limbs[1] = res[1];
  r->limbs[2] = res[2];
  r->limbs[3] = res[3];
  return r;
}

/* at_uint256_shl computes r = a << shift.
   shift must be in [0, 255]. */
static inline at_uint256_t *
at_uint256_shl( at_uint256_t *       r,
                at_uint256_t const * a,
                int                  shift ) {
  if( shift == 0 ) {
    *r = *a;
    return r;
  }
  if( shift >= 256 ) {
    r->limbs[0] = r->limbs[1] = r->limbs[2] = r->limbs[3] = 0;
    return r;
  }

  int limb_shift = shift / 64;
  int bit_shift = shift % 64;

  if( bit_shift == 0 ) {
    for( int i = 3; i >= limb_shift; i-- ) {
      r->limbs[i] = a->limbs[i - limb_shift];
    }
    for( int i = limb_shift - 1; i >= 0; i-- ) {
      r->limbs[i] = 0;
    }
  } else {
    for( int i = 3; i > limb_shift; i-- ) {
      r->limbs[i] = ( a->limbs[i - limb_shift] << bit_shift ) |
                    ( a->limbs[i - limb_shift - 1] >> ( 64 - bit_shift ) );
    }
    r->limbs[limb_shift] = a->limbs[0] << bit_shift;
    for( int i = limb_shift - 1; i >= 0; i-- ) {
      r->limbs[i] = 0;
    }
  }
  return r;
}

/* at_uint256_shr computes r = a >> shift.
   shift must be in [0, 255]. */
static inline at_uint256_t *
at_uint256_shr( at_uint256_t *       r,
                at_uint256_t const * a,
                int                  shift ) {
  if( shift == 0 ) {
    *r = *a;
    return r;
  }
  if( shift >= 256 ) {
    r->limbs[0] = r->limbs[1] = r->limbs[2] = r->limbs[3] = 0;
    return r;
  }

  int limb_shift = shift / 64;
  int bit_shift = shift % 64;

  if( bit_shift == 0 ) {
    for( int i = 0; i < 4 - limb_shift; i++ ) {
      r->limbs[i] = a->limbs[i + limb_shift];
    }
    for( int i = 4 - limb_shift; i < 4; i++ ) {
      r->limbs[i] = 0;
    }
  } else {
    for( int i = 0; i < 3 - limb_shift; i++ ) {
      r->limbs[i] = ( a->limbs[i + limb_shift] >> bit_shift ) |
                    ( a->limbs[i + limb_shift + 1] << ( 64 - bit_shift ) );
    }
    r->limbs[3 - limb_shift] = a->limbs[3] >> bit_shift;
    for( int i = 4 - limb_shift; i < 4; i++ ) {
      r->limbs[i] = 0;
    }
  }
  return r;
}

/* at_uint256_divmod computes q = a / b and r = a % b.
   Returns 0 on success, 1 if b == 0 (division by zero).
   Either q or rem may be NULL if not needed. */
static inline int
at_uint256_divmod( at_uint256_t *       q,
                   at_uint256_t *       rem,
                   at_uint256_t const * a,
                   at_uint256_t const * b ) {
  /* Check for division by zero */
  if( at_uint256_is_zero( b ) ) {
    return 1;
  }

  /* Handle a < b case */
  if( at_uint256_cmp( a, b ) < 0 ) {
    if( q ) {
      q->limbs[0] = q->limbs[1] = q->limbs[2] = q->limbs[3] = 0;
    }
    if( rem ) {
      *rem = *a;
    }
    return 0;
  }

  /* Handle a == b case */
  if( at_uint256_cmp( a, b ) == 0 ) {
    if( q ) {
      q->limbs[0] = 1;
      q->limbs[1] = q->limbs[2] = q->limbs[3] = 0;
    }
    if( rem ) {
      rem->limbs[0] = rem->limbs[1] = rem->limbs[2] = rem->limbs[3] = 0;
    }
    return 0;
  }

  /* Binary long division */
  at_uint256_t quotient = { .limbs = { 0, 0, 0, 0 } };
  at_uint256_t remainder = { .limbs = { 0, 0, 0, 0 } };

  /* Find the highest bit of a */
  int highest_bit = 255;
  while( highest_bit >= 0 && !at_uint256_bit( a, highest_bit ) ) {
    highest_bit--;
  }

  for( int i = highest_bit; i >= 0; i-- ) {
    /* remainder = remainder << 1 */
    at_uint256_shl( &remainder, &remainder, 1 );

    /* remainder.bit[0] = a.bit[i] */
    if( at_uint256_bit( a, i ) ) {
      remainder.limbs[0] |= 1;
    }

    /* if remainder >= b */
    if( at_uint256_cmp( &remainder, b ) >= 0 ) {
      at_uint256_sub( &remainder, &remainder, b );
      quotient.limbs[i / 64] |= UINT64_C(1) << ( i % 64 );
    }
  }

  if( q ) {
    *q = quotient;
  }
  if( rem ) {
    *rem = remainder;
  }
  return 0;
}

/* ---- Hex conversion (reverse-byte order, Bitcoin convention) -----------

   The hex representation shows bytes in REVERSE order so that a value
   stored little-endian displays with the most-significant digit first
   (natural numeric reading order).

   Example: buf = {0x12, 0x34, ..., 0xAB} → hex "ab...3412"             */

/* Internal hex digit helpers */

static inline int
at_uint256_hex_digit_( char c ) {
  if( c >= '0' && c <= '9' ) return c - '0';
  if( c >= 'a' && c <= 'f' ) return c - 'a' + 10;
  if( c >= 'A' && c <= 'F' ) return c - 'A' + 10;
  return -1;
}

/* at_uint256_get_hex writes the 64-char reverse-byte hex string
   into out (must hold at least 65 bytes).  Returns out. */

static inline char *
at_uint256_get_hex( char                     * out,
                    at_uint256_t const       * a ) {
  static char const hex_chars[] = "0123456789abcdef";
  for( int i = 0; i < 32; i++ ) {
    uchar b = a->buf[ 31 - i ];
    out[ i * 2     ] = hex_chars[ b >> 4 ];
    out[ i * 2 + 1 ] = hex_chars[ b & 0x0F ];
  }
  out[ 64 ] = '\0';
  return out;
}

/* at_uint256_from_hex parses a 64-char reverse-byte hex string
   into a uint256.  Returns 0 on success, -1 on error. */

static inline int
at_uint256_from_hex( at_uint256_t * out,
                     char const   * hex,
                     ulong          hex_len ) {
  if( hex_len != 64UL ) return -1;

  at_memset( out->buf, 0, 32UL );

  ulong  digits = hex_len;
  uchar * p    = out->buf;
  uchar * pend = out->buf + 32;

  while( digits > 0UL && p < pend ) {
    int lo = at_uint256_hex_digit_( hex[ --digits ] );
    if( lo < 0 ) return -1;
    int hi = 0;
    if( digits > 0UL ) {
      hi = at_uint256_hex_digit_( hex[ --digits ] );
      if( hi < 0 ) return -1;
    }
    *p++ = (uchar)( ( hi << 4 ) | lo );
  }
  return 0;
}

#include "./at_uint256_mul.h"

#endif /* HEADER_at_src_infra_uint256_at_uint256_h */