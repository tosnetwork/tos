#ifndef HEADER_at_src_ballet_ed25519_at_f25519_h
#define HEADER_at_src_ballet_ed25519_at_f25519_h

/* at_f25519.h provides the public field API for the base field of curve25519.

   Most operations in this API should be assumed to take a variable amount
   of time depending on inputs, and thus should not be exposed to secret data.

   Constant-time operations are made explicit. */

#include "at_crypto_base.h"

#define AT_25519_INLINE static inline

/* at_f25519_t is the type of a field element, i.e. an integer
   mod p = 2^255 - 19.

   Implementation selection (in order of preference):
   - AT_HAS_AVX512_IFMA: AVX-512 IFMA (Ice Lake+) - fastest, uses VPMADD52
   - AT_HAS_AVX512_GENERAL: AVX-512F (Skylake-X, Cascade Lake) - 8-way parallelism
   - AT_HAS_AVX: AVX2 (Haswell+) - 4-way parallelism, radix-2^25.5
   - Otherwise: Reference implementation (portable)
*/

#if AT_HAS_AVX512_IFMA
  /* AVX-512 IFMA implementation (Ice Lake+ only)
     Uses radix-2^43 representation with VPMADD52 instructions */
  #include "avx512_ifma/at_f25519.h"
#elif AT_HAS_AVX512_GENERAL
  /* AVX-512F implementation (Skylake-X, Cascade Lake)
     Uses radix-2^25.5 representation with 8-way parallelism
     Same algorithm as AVX2, but scales up from 4-way to 8-way */
  #include "avx512_general/at_f25519.h"
#elif AT_HAS_AVX
  /* AVX2 implementation (Haswell+ without AVX-512)
     Uses radix-2^25.5 representation with 4-way parallelism */
  #include "avx2/at_f25519.h"
#else
  /* Reference implementation (portable) */
  #include "at_f25519_ref.h"
#endif

/* Include RNG for at_f25519_rng_unsafe (test function) */
#include "at/infra/rng/at_rng.h"

/* field constants. these are imported from table/at_f25519_table_{arch}.c.
   they are (re)defined here to avoid breaking compilation when the table needs
   to be rebuilt.
   Note: AVX-512 General provides its own definitions via macros, so skip here. */
#if !AT_HAS_AVX512_GENERAL
static const at_f25519_t at_f25519_zero[1];
static const at_f25519_t at_f25519_one[1];
static const at_f25519_t at_f25519_minus_one[1];
static const at_f25519_t at_f25519_two[1];
static const at_f25519_t at_f25519_nine[1];
static const at_f25519_t at_f25519_k[1];
static const at_f25519_t at_f25519_minus_k[1];
static const at_f25519_t at_f25519_d[1];
static const at_f25519_t at_f25519_sqrtm1[1];
static const at_f25519_t at_f25519_invsqrt_a_minus_d[1];
static const at_f25519_t at_f25519_one_minus_d_sq[1];
static const at_f25519_t at_f25519_d_minus_one_sq[1];
static const at_f25519_t at_f25519_sqrt_ad_minus_one[1];
#endif

AT_PROTOTYPES_BEGIN

/* at_f25519_mul computes r = a * b, and returns r. */
at_f25519_t *
at_f25519_mul( at_f25519_t *       r,
               at_f25519_t const * a,
               at_f25519_t const * b );

/* at_f25519_sqr computes r = a^2, and returns r. */
at_f25519_t *
at_f25519_sqr( at_f25519_t *       r,
               at_f25519_t const * a );

/* at_f25519_add computes r = a + b, and returns r. */
at_f25519_t *
at_f25519_add( at_f25519_t *       r,
               at_f25519_t const * a,
               at_f25519_t const * b );

/* at_f25519_add computes r = a - b, and returns r. */
at_f25519_t *
at_f25519_sub( at_f25519_t *       r,
               at_f25519_t const * a,
               at_f25519_t const * b );

/* at_f25519_add_nr computes r = a + b, and returns r.
   Note: this does NOT reduce the result mod p.
   It can be used before mul, sqr. */
at_f25519_t *
at_f25519_add_nr( at_f25519_t * r,
                  at_f25519_t const * a,
                  at_f25519_t const * b );

/* at_f25519_sub_nr computes r = a - b, and returns r.
   Note: this does NOT reduce the result mod p.
   It can be used before mul, sqr. */
at_f25519_t *
at_f25519_sub_nr( at_f25519_t * r,
                  at_f25519_t const * a,
                  at_f25519_t const * b );

/* at_f25519_add computes r = -a, and returns r. */
at_f25519_t *
at_f25519_neg( at_f25519_t *       r,
               at_f25519_t const * a );

/* at_f25519_mul_121666 computes r = a * k, k=121666, and returns r. */
at_f25519_t *
at_f25519_mul_121666( at_f25519_t *       r,
                      at_f25519_t const * a );

/* at_f25519_frombytes deserializes a 32-byte buffer buf into a
   at_f25519_t element r, and returns r.
   buf is in little endian form, we accept non-canonical elements
   unlike RFC 8032. */
at_f25519_t *
at_f25519_frombytes( at_f25519_t * r,
                     uchar const   buf[ 32 ] );

/* at_f25519_tobytes serializes a at_f25519_t element a into
   a 32-byte buffer out, and returns out.
   out is in little endian form, according to RFC 8032
   (we don't output non-canonical elements). */
uchar *
at_f25519_tobytes( uchar               out[ 32 ],
                   at_f25519_t const * a );

/* at_f25519_set copies r = a, and returns r. */
at_f25519_t *
at_f25519_set( at_f25519_t *       r,
               at_f25519_t const * a );

/* at_f25519_is_zero returns 1 if a == 0, 0 otherwise. */
int
at_f25519_is_zero( at_f25519_t const * a );

/* at_f25519_if sets r = a0 if cond, else r = a1, equivalent to:
   r = cond ? a0 : a1.
   Note: this is constant time. */
at_f25519_t *
at_f25519_if( at_f25519_t *       r,
              int const           cond, /* 0, 1 */
              at_f25519_t const * a0,
              at_f25519_t const * a1 );

/* at_f25519_rng generates a random at_f25519_t element.
   Note: insecure, for tests only. */
at_f25519_t *
at_f25519_rng_unsafe( at_f25519_t * r,
                      at_rng_t *    rng );

/*
 * Derived
 * Note: AVX-512 General provides its own implementations, so skip here.
 */

#if !AT_HAS_AVX512_GENERAL
/* at_f25519_eq returns 1 if a == b, 0 otherwise. */
AT_25519_INLINE int
at_f25519_eq( at_f25519_t const * a,
              at_f25519_t const * b ) {
  at_f25519_t r[1];
  at_f25519_sub( r, a, b );
  return at_f25519_is_zero( r );
}

/* at_f25519_is_nonzero returns 1 (true) if a != 0, 0 if a == 0. */
AT_25519_INLINE int
at_f25519_is_nonzero( at_f25519_t const * a ) {
  return !at_f25519_is_zero( a );
}

/* at_f25519_sgn returns the sign of a (lsb). */
AT_25519_INLINE int
at_f25519_sgn( at_f25519_t const * a ) {
  //TODO: make it faster (unless inlining already optimizes out unnecessary code)
  uchar buf[32];
  at_f25519_tobytes( buf, a );
  return buf[0] & 1;
}

/* at_f25519_abs sets r = |a|. */
AT_25519_INLINE at_f25519_t *
at_f25519_abs( at_f25519_t *       r,
               at_f25519_t const * a ) {
  at_f25519_t neg_a[1];
  at_f25519_neg( neg_a, a );
  return at_f25519_if( r, at_f25519_sgn(a), neg_a, a );
}

/* at_f25519_abs sets r = -|a|. */
AT_25519_INLINE at_f25519_t *
at_f25519_neg_abs( at_f25519_t *       r,
                   at_f25519_t const * a ) {
  at_f25519_t neg_a[1];
  at_f25519_neg( neg_a, a );
  return at_f25519_if( r, at_f25519_sgn(a), a, neg_a );
}
#endif /* !AT_HAS_AVX512_GENERAL */

/*
 * Inv & Sqrt
 */

/* at_f25519_inv computes r = 1/a, and returns r. */
at_f25519_t *
at_f25519_inv( at_f25519_t *       r,
               at_f25519_t const * a );

/* at_f25519_pow22523 computes r = a^(2^252-3), and returns r. */
at_f25519_t *
at_f25519_pow22523( at_f25519_t *       r,
                    at_f25519_t const * a );

/* at_f25519_sqrt_ratio computes r = sqrt(u/v) if it exists.
   Returns 1 on success (is a square), 0 on failure (no square root). */
int
at_f25519_sqrt_ratio( at_f25519_t *       r,
                      at_f25519_t const * u,
                      at_f25519_t const * v );

/* at_f25519_sqrt_ratio computes r = 1/sqrt(v),
   returns 0 on success, 1 on failure.
   Note: AVX-512 General provides its own inline definition. */
#if !AT_HAS_AVX512_GENERAL
AT_25519_INLINE int
at_f25519_inv_sqrt( at_f25519_t *       r,
                    at_f25519_t const * v ) {
  return at_f25519_sqrt_ratio( r, at_f25519_one, v );
}
#endif

/*
 * Vectorized
 */

/* at_f25519_muln computes r_i = a_i * b_i */
void
at_f25519_mul2( at_f25519_t * r1, at_f25519_t const * a1, at_f25519_t const * b1,
                at_f25519_t * r2, at_f25519_t const * a2, at_f25519_t const * b2 );

void
at_f25519_mul3( at_f25519_t * r1, at_f25519_t const * a1, at_f25519_t const * b1,
                at_f25519_t * r2, at_f25519_t const * a2, at_f25519_t const * b2,
                at_f25519_t * r3, at_f25519_t const * a3, at_f25519_t const * b3 );

void
at_f25519_mul4( at_f25519_t * r1, at_f25519_t const * a1, at_f25519_t const * b1,
                at_f25519_t * r2, at_f25519_t const * a2, at_f25519_t const * b2,
                at_f25519_t * r3, at_f25519_t const * a3, at_f25519_t const * b3,
                at_f25519_t * r4, at_f25519_t const * a4, at_f25519_t const * b4 );

/* at_f25519_sqrn computes r_i = a_i^2 */
void
at_f25519_sqr2( at_f25519_t * r1, at_f25519_t const * a1,
                at_f25519_t * r2, at_f25519_t const * a2 );

void
at_f25519_sqr3( at_f25519_t * r1, at_f25519_t const * a1,
                at_f25519_t * r2, at_f25519_t const * a2,
                at_f25519_t * r3, at_f25519_t const * a3 );

void
at_f25519_sqr4( at_f25519_t * r1, at_f25519_t const * a1,
                at_f25519_t * r2, at_f25519_t const * a2,
                at_f25519_t * r3, at_f25519_t const * a3,
                at_f25519_t * r4, at_f25519_t const * a4 );

/* at_f25519_pow22523 computes r = a^(2^252-3), and returns r. */
at_f25519_t *
at_f25519_pow22523_2( at_f25519_t * r1, at_f25519_t const * a1,
                      at_f25519_t * r2, at_f25519_t const * a2 );

/* at_f25519_sqrt_ratio computes r = (u * v^3) * (u * v^7)^((p-5)/8),
   returns 0 on success, 1 on failure. */
int
at_f25519_sqrt_ratio2( at_f25519_t * r1, at_f25519_t const * u1, at_f25519_t const * v1,
                       at_f25519_t * r2, at_f25519_t const * u2, at_f25519_t const * v2 );

/* at_f25519_debug prints the element a, for debugging purposes. */
void
at_f25519_debug( char const *        name,
                 at_f25519_t const * a );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_ballet_ed25519_at_f25519_h */