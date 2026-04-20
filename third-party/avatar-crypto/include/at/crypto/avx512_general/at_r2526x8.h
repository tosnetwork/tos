#ifndef HEADER_at_src_crypto_ed25519_avx512_general_at_r2526x8_h
#define HEADER_at_src_crypto_ed25519_avx512_general_at_r2526x8_h

/* AVX-512F field arithmetic for GF(2^255-19) using radix-2^25.5 representation.

   This implementation processes 8 field elements in parallel using AVX-512F
   SIMD instructions (WITHOUT requiring IFMA/VPMADD52). The representation uses
   10 limbs with alternating 26/25 bit sizes (radix 2^25.5).

   This is the AVX-512F (non-IFMA) version that scales up the AVX2 algorithm
   from 4-way to 8-way parallelism. It targets Skylake-X and Cascade Lake CPUs
   which have AVX-512F but NOT AVX-512 IFMA.

   Limb layout: [26, 25, 26, 25, 26, 25, 26, 25, 26, 25] bits
   Total: 26*5 + 25*5 = 130 + 125 = 255 bits

   Each __m512i vector holds 8 corresponding limbs from 8 different field
   elements. This enables SIMD parallelism across 8 elements.

   Memory layout:
     limb[0]: [e0_l0, e1_l0, e2_l0, e3_l0, e4_l0, e5_l0, e6_l0, e7_l0]
     limb[1]: [e0_l1, e1_l1, e2_l1, e3_l1, e4_l1, e5_l1, e6_l1, e7_l1]
     ...
     limb[9]: [e0_l9, e1_l9, e2_l9, e3_l9, e4_l9, e5_l9, e6_l9, e7_l9]

   Key Instruction: _mm512_mul_epu32 (wwl_mul_ll) for 32x32->64 bit multiply
   This is the same algorithm as AVX2, just using 512-bit vectors. */

#if AT_HAS_AVX512_GENERAL

#include "at/infra/simd/at_avx512.h"
#include "at/crypto/at_crypto_base.h"

/* Constants for the reduced radix representation */
#define AT_R2526X8_BASE0 26  /* Limbs 0, 2, 4, 6, 8 have 26 bits */
#define AT_R2526X8_BASE1 25  /* Limbs 1, 3, 5, 7, 9 have 25 bits */
#define AT_R2526X8_NUM_LIMBS 10

/* Masks for the limb sizes */
#define AT_R2526X8_MASK26 ((1UL << 26) - 1)  /* 0x3FFFFFF */
#define AT_R2526X8_MASK25 ((1UL << 25) - 1)  /* 0x1FFFFFF */

/* Reduction factor: 2^255 mod p = 19 */
#define AT_R2526X8_TIMES19 19UL

/* A at_r2526x8_t represents 8 GF(p) elements in parallel, where p = 2^255-19,
   using a reduced radix representation with alternating 26/25 bit limbs.

   Each limb[i] holds 8 corresponding limbs from 8 different field elements.
   This is the "interleaved" or "zipped" representation for SIMD processing. */
typedef struct at_r2526x8 {
  wwl_t limb[AT_R2526X8_NUM_LIMBS];  /* 10 __m512i vectors */
} at_r2526x8_t;

AT_PROTOTYPES_BEGIN

/* ========================================================================
   Constants
   ======================================================================== */

/* 2P constants for subtraction bias (to avoid negative numbers).
   Pattern: even limbs are 26-bit, odd limbs are 25-bit.
   limb[0]: 2*(2^26 - 19) = 0x7FFFFDA (special for -19)
   limb[even]: 2*(2^26 - 1) = 0x7FFFFFE for 26-bit limbs
   limb[odd]:  2*(2^25 - 1) = 0x3FFFFFE for 25-bit limbs */
static const ulong AT_R2526X8_2P[AT_R2526X8_NUM_LIMBS] = {
  0x7FFFFDA,  /* limb 0: 26-bit, -19 adjust */
  0x3FFFFFE,  /* limb 1: 25-bit */
  0x7FFFFFE,  /* limb 2: 26-bit */
  0x3FFFFFE,  /* limb 3: 25-bit */
  0x7FFFFFE,  /* limb 4: 26-bit */
  0x3FFFFFE,  /* limb 5: 25-bit */
  0x7FFFFFE,  /* limb 6: 26-bit */
  0x3FFFFFE,  /* limb 7: 25-bit */
  0x7FFFFFE,  /* limb 8: 26-bit */
  0x3FFFFFE   /* limb 9: 25-bit */
};

/* ========================================================================
   Basic Operations
   ======================================================================== */

/* at_r2526x8_zero returns a vector of 8 zero field elements. */
static inline at_r2526x8_t
at_r2526x8_zero( void ) {
  at_r2526x8_t r;
  wwl_t z = wwl_zero();
  for( int i = 0; i < AT_R2526X8_NUM_LIMBS; i++ ) {
    r.limb[i] = z;
  }
  return r;
}

/* at_r2526x8_copy copies src to dst. */
static inline void
at_r2526x8_copy( at_r2526x8_t *       dst,
                  at_r2526x8_t const * src ) {
  for( int i = 0; i < AT_R2526X8_NUM_LIMBS; i++ ) {
    dst->limb[i] = src->limb[i];
  }
}

/* ========================================================================
   Addition and Subtraction
   ======================================================================== */

/* at_r2526x8_add computes c = a + b (element-wise for 8 elements).
   Does NOT reduce the result. */
static inline at_r2526x8_t
at_r2526x8_add( at_r2526x8_t const * a,
                 at_r2526x8_t const * b ) {
  at_r2526x8_t c;
  for( int i = 0; i < AT_R2526X8_NUM_LIMBS; i++ ) {
    c.limb[i] = wwl_add( a->limb[i], b->limb[i] );
  }
  return c;
}

/* at_r2526x8_sub computes c = a - b (element-wise for 8 elements).
   Uses 2P bias to avoid negative numbers. Does NOT reduce the result. */
static inline at_r2526x8_t
at_r2526x8_sub( at_r2526x8_t const * a,
                 at_r2526x8_t const * b ) {
  at_r2526x8_t c;
  for( int i = 0; i < AT_R2526X8_NUM_LIMBS; i++ ) {
    wwl_t p2 = wwl_bcast( (long)AT_R2526X8_2P[i] );
    c.limb[i] = wwl_add( a->limb[i], wwl_sub( p2, b->limb[i] ) );
  }
  return c;
}

/* at_r2526x8_neg computes c = -a (element-wise for 8 elements).
   Uses 2P bias. */
static inline at_r2526x8_t
at_r2526x8_neg( at_r2526x8_t const * a ) {
  at_r2526x8_t c;
  for( int i = 0; i < AT_R2526X8_NUM_LIMBS; i++ ) {
    wwl_t p2 = wwl_bcast( (long)AT_R2526X8_2P[i] );
    c.limb[i] = wwl_sub( p2, a->limb[i] );
  }
  return c;
}

/* ========================================================================
   Carry Propagation / Compression
   ======================================================================== */

/* at_r2526x8_compress performs carry propagation to reduce limbs back
   to their proper bit ranges. This is needed after multiplication.

   After compression:
     - Even limbs (0,2,4,6,8) are in [0, 2^26)
     - Odd limbs (1,3,5,7,9) are in [0, 2^25)
   with possible overflow into the next limb. */
static inline at_r2526x8_t
at_r2526x8_compress( at_r2526x8_t const * a ) {
  wwl_t const mask26 = wwl_bcast( (long)AT_R2526X8_MASK26 );
  wwl_t const mask25 = wwl_bcast( (long)AT_R2526X8_MASK25 );

  /* Load limbs */
  wwl_t c0 = a->limb[0];
  wwl_t c1 = a->limb[1];
  wwl_t c2 = a->limb[2];
  wwl_t c3 = a->limb[3];
  wwl_t c4 = a->limb[4];
  wwl_t c5 = a->limb[5];
  wwl_t c6 = a->limb[6];
  wwl_t c7 = a->limb[7];
  wwl_t c8 = a->limb[8];
  wwl_t c9 = a->limb[9];

  wwl_t h;

  /* Carry propagation: c0 -> c1 -> c2 -> ... -> c9 -> c0 */
  h = wwl_shru( c0, AT_R2526X8_BASE0 );
  c0 = wwl_and( c0, mask26 );
  c1 = wwl_add( c1, h );

  h = wwl_shru( c1, AT_R2526X8_BASE1 );
  c1 = wwl_and( c1, mask25 );
  c2 = wwl_add( c2, h );

  h = wwl_shru( c2, AT_R2526X8_BASE0 );
  c2 = wwl_and( c2, mask26 );
  c3 = wwl_add( c3, h );

  h = wwl_shru( c3, AT_R2526X8_BASE1 );
  c3 = wwl_and( c3, mask25 );
  c4 = wwl_add( c4, h );

  h = wwl_shru( c4, AT_R2526X8_BASE0 );
  c4 = wwl_and( c4, mask26 );
  c5 = wwl_add( c5, h );

  h = wwl_shru( c5, AT_R2526X8_BASE1 );
  c5 = wwl_and( c5, mask25 );
  c6 = wwl_add( c6, h );

  h = wwl_shru( c6, AT_R2526X8_BASE0 );
  c6 = wwl_and( c6, mask26 );
  c7 = wwl_add( c7, h );

  h = wwl_shru( c7, AT_R2526X8_BASE1 );
  c7 = wwl_and( c7, mask25 );
  c8 = wwl_add( c8, h );

  h = wwl_shru( c8, AT_R2526X8_BASE0 );
  c8 = wwl_and( c8, mask26 );
  c9 = wwl_add( c9, h );

  /* Final carry from c9 wraps around to c0 with factor 19 */
  h = wwl_shru( c9, AT_R2526X8_BASE1 );
  c9 = wwl_and( c9, mask25 );
  /* c0 += 19 * h using shift-and-add: 19 = 16 + 2 + 1 */
  c0 = wwl_add( c0, wwl_add( wwl_add( wwl_shl( h, 4 ), wwl_shl( h, 1 ) ), h ) );

  /* One more carry from c0 to c1 */
  h = wwl_shru( c0, AT_R2526X8_BASE0 );
  c0 = wwl_and( c0, mask26 );
  c1 = wwl_add( c1, h );

  /* Store results */
  at_r2526x8_t r;
  r.limb[0] = c0;
  r.limb[1] = c1;
  r.limb[2] = c2;
  r.limb[3] = c3;
  r.limb[4] = c4;
  r.limb[5] = c5;
  r.limb[6] = c6;
  r.limb[7] = c7;
  r.limb[8] = c8;
  r.limb[9] = c9;
  return r;
}

/* ========================================================================
   Multiplication (Schoolbook)
   ======================================================================== */

/* at_r2526x8_intmul computes c = a * b using schoolbook multiplication.
   Result is NOT reduced - use compress() after. */
void
at_r2526x8_intmul( at_r2526x8_t *       c,
                    at_r2526x8_t const * a,
                    at_r2526x8_t const * b );

/* at_r2526x8_mul computes c = a * b with compression. */
static inline at_r2526x8_t
at_r2526x8_mul( at_r2526x8_t const * a,
                 at_r2526x8_t const * b ) {
  at_r2526x8_t c;
  at_r2526x8_intmul( &c, a, b );
  return at_r2526x8_compress( &c );
}

/* ========================================================================
   Squaring
   ======================================================================== */

/* at_r2526x8_intsqr computes c = a^2 using optimized squaring.
   Result is NOT reduced - use compress() after. */
void
at_r2526x8_intsqr( at_r2526x8_t *       c,
                    at_r2526x8_t const * a );

/* at_r2526x8_sqr computes c = a^2 with compression. */
static inline at_r2526x8_t
at_r2526x8_sqr( at_r2526x8_t const * a ) {
  at_r2526x8_t c;
  at_r2526x8_intsqr( &c, a );
  return at_r2526x8_compress( &c );
}

/* ========================================================================
   Pack/Unpack (Zip/Unzip) Operations
   ======================================================================== */

/* Forward declarations for scalar type - defined in at_f25519.h */
struct at_f25519;
typedef struct at_f25519 at_f25519_scalar_t;

/* at_r2526x8_zip packs 8 scalar field elements into SIMD form. */
void
at_r2526x8_zip( at_r2526x8_t *             out,
                 at_f25519_scalar_t const *  e0,
                 at_f25519_scalar_t const *  e1,
                 at_f25519_scalar_t const *  e2,
                 at_f25519_scalar_t const *  e3,
                 at_f25519_scalar_t const *  e4,
                 at_f25519_scalar_t const *  e5,
                 at_f25519_scalar_t const *  e6,
                 at_f25519_scalar_t const *  e7 );

/* at_r2526x8_unzip unpacks SIMD form back to 8 scalar field elements. */
void
at_r2526x8_unzip( at_f25519_scalar_t *       e0,
                   at_f25519_scalar_t *       e1,
                   at_f25519_scalar_t *       e2,
                   at_f25519_scalar_t *       e3,
                   at_f25519_scalar_t *       e4,
                   at_f25519_scalar_t *       e5,
                   at_f25519_scalar_t *       e6,
                   at_f25519_scalar_t *       e7,
                   at_r2526x8_t const *      in );

AT_PROTOTYPES_END

#endif /* AT_HAS_AVX512_GENERAL */

#endif /* HEADER_at_src_crypto_ed25519_avx512_general_at_r2526x8_h */
