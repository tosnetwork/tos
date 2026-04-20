#ifndef HEADER_at_src_ballet_ed25519_at_curve25519_h
#error "Do not include this directly; use at_curve25519.h"
#endif

/* at_curve25519.h provides the public Curve25519 API.

   Most operations in this API should be assumed to take a variable
   amount of time depending on inputs.  (And thus should not be exposed
   to secret data).

   Const time operations are made explicit, see at_curve25519_secure.c */

#include "at_crypto_base.h"
#include "at_f25519.h"
#include "at_curve25519_scalar.h"

/* CURVE25519_PRECOMP_XY turns on/off the precomputation of (Y-X), (Y+X)
   in precomputation tables. */
#define CURVE25519_PRECOMP_XY 1

/* struct at_curve25519_edwards (aka at_curve25519_edwards_t) represents
   a point in Extended Twisted Edwards Coordinates.
   https://eprint.iacr.org/2008/522 */
struct at_curve25519_edwards {
  at_f25519_t X[1];
  at_f25519_t Y[1];
  at_f25519_t T[1];
  at_f25519_t Z[1];
};
typedef struct at_curve25519_edwards at_curve25519_edwards_t;

typedef at_curve25519_edwards_t at_ed25519_point_t;
typedef at_curve25519_edwards_t at_ristretto255_point_t;

#if AT_HAS_AVX512_IFMA
#include "table/at_curve25519_table_ifma.c"
#else
#include "table/at_curve25519_table_ref.c"
#endif

AT_PROTOTYPES_BEGIN

/* at_ed25519_point_set sets r = 0 (point at infinity). */
AT_25519_INLINE at_ed25519_point_t *
at_ed25519_point_set_zero( at_ed25519_point_t * r ) {
  at_f25519_set( r->X, at_f25519_zero );
  at_f25519_set( r->Y, at_f25519_one );
  at_f25519_set( r->Z, at_f25519_one );
  at_f25519_set( r->T, at_f25519_zero );
  return r;
}

/* at_ed25519_point_set_zero_precomputed sets r = 0 (point at infinity). */
AT_25519_INLINE at_ed25519_point_t *
at_ed25519_point_set_zero_precomputed( at_ed25519_point_t * r ) {
#if CURVE25519_PRECOMP_XY
  at_f25519_set( r->X, at_f25519_one );  /* Y-X = 1-0 = 1 */
  at_f25519_set( r->Y, at_f25519_one );  /* Y+X = 1+0 = 1 */
  at_f25519_set( r->Z, at_f25519_one );  /* Z = 1 */
  at_f25519_set( r->T, at_f25519_zero ); /* kT = 0 */
  return r;
#else
  return at_ed25519_point_set_zero( r );
#endif
}

/* at_ed25519_point_set sets r = a. */
AT_25519_INLINE at_ed25519_point_t * AT_FN_NO_ASAN
at_ed25519_point_set( at_ed25519_point_t *       r,
                      at_ed25519_point_t const * a ) {
  at_f25519_set( r->X, a->X );
  at_f25519_set( r->Y, a->Y );
  at_f25519_set( r->Z, a->Z );
  at_f25519_set( r->T, a->T );
  return r;
}

/* at_ed25519_point_from sets r = (x : y : z : t). */
AT_25519_INLINE at_ed25519_point_t *
at_ed25519_point_from( at_ed25519_point_t * r,
                       at_f25519_t const *  x,
                       at_f25519_t const *  y,
                       at_f25519_t const *  z,
                       at_f25519_t const *  t ) {
  at_f25519_set( r->X, x );
  at_f25519_set( r->Y, y );
  at_f25519_set( r->Z, z );
  at_f25519_set( r->T, t );
  return r;
}

/* at_ed25519_point_from sets (x : y : z : t) = a. */
AT_25519_INLINE void
at_ed25519_point_to( at_f25519_t *  x,
                     at_f25519_t *  y,
                     at_f25519_t *  z,
                     at_f25519_t *  t,
                     at_ed25519_point_t const * a ) {
  at_f25519_set( x, a->X );
  at_f25519_set( y, a->Y );
  at_f25519_set( z, a->Z );
  at_f25519_set( t, a->T );
}

/* at_ed25519_point_sub sets r = -a. */
AT_25519_INLINE at_ed25519_point_t *
at_ed25519_point_neg( at_ed25519_point_t *       r,
                      at_ed25519_point_t const * a ) {
  at_f25519_neg( r->X, a->X );
  at_f25519_set( r->Y, a->Y );
  at_f25519_set( r->Z, a->Z );
  at_f25519_neg( r->T, a->T );
  return r;
}

/* at_ed25519_point_is_zero returns 1 if a == 0 (point at infinity), 0 otherwise. */
AT_25519_INLINE int
at_ed25519_point_is_zero( at_ed25519_point_t const * a ) {
  return at_f25519_is_zero( a->X ) & at_f25519_eq( a->Y, a->Z );
}

/* at_ed25519_point_eq returns 1 if a == b, 0 otherwise. */
AT_25519_INLINE int
at_ed25519_point_eq( at_ed25519_point_t const * a,
                     at_ed25519_point_t const * b ) {
  at_f25519_t x1[1], x2[1], y1[1], y2[1];
  at_f25519_mul( x1, b->X, a->Z );
  at_f25519_mul( x2, a->X, b->Z );
  at_f25519_mul( y1, b->Y, a->Z );
  at_f25519_mul( y2, a->Y, b->Z );
  return at_f25519_eq( x1, x2 ) & at_f25519_eq( y1, y2 );
}

/* at_ed25519_point_eq returns 1 if a == b, 0 otherwise.
   b is a point with Z==1, e.g. a decompressed point. */
AT_25519_INLINE int
at_ed25519_point_eq_z1( at_ed25519_point_t const * a,
                        at_ed25519_point_t const * b ) { /* b.Z == 1, e.g. a decompressed point */
  at_f25519_t x1[1], y1[1];
  at_f25519_mul( x1, b->X, a->Z );
  at_f25519_mul( y1, b->Y, a->Z );
  return at_f25519_eq( x1, a->X ) & at_f25519_eq( y1, a->Y );
}

/* at_curve25519_into_precomputed transforms a point into
   precomputed table format, e.g. replaces T -> kT to save
   1mul in the dbl-and-add loop. */
AT_25519_INLINE void
at_curve25519_into_precomputed( at_ed25519_point_t * r ) {
#if CURVE25519_PRECOMP_XY
  at_f25519_t add[1], sub[1];
  at_f25519_add_nr( add, r->Y, r->X );
  at_f25519_sub_nr( sub, r->Y, r->X );
  at_f25519_set( r->X, sub );
  at_f25519_set( r->Y, add );
#endif
  at_f25519_mul( r->T, r->T, at_f25519_k );
}

/* at_ed25519_point_add_final_mul computes just the final mul step in point add.
   See at_ed25519_point_add_with_opts. */
AT_25519_INLINE at_ed25519_point_t *
at_ed25519_point_add_final_mul( at_ed25519_point_t * restrict r,
                                at_ed25519_point_t const *    a ) {
  at_f25519_t const *r1 = a->X;
  at_f25519_t const *r2 = a->Y;
  at_f25519_t const *r3 = a->Z;
  at_f25519_t const *r4 = a->T;

  at_f25519_mul4( r->X, r1, r2,
                  r->Y, r3, r4,
                  r->Z, r2, r3,
                  r->T, r1, r4 );
  return r;
}

/* at_ed25519_point_add_final_mul_projective computes just the final mul step
   in point add, assuming the result is projective (X, Y, Z), i.e. ignoring T.
   This is useful because dbl only needs (X, Y, Z) in input, so we can save 1mul.
   See at_ed25519_point_add_with_opts. */
AT_25519_INLINE at_ed25519_point_t *
at_ed25519_point_add_final_mul_projective( at_ed25519_point_t * restrict r,
                                           at_ed25519_point_t const *    a ) {
  at_f25519_mul3( r->X, a->X, a->Y,
                  r->Y, a->Z, a->T,
                  r->Z, a->Y, a->Z );
  return r;
}

/* Dedicated dbl
   https://eprint.iacr.org/2008/522
   Sec 4.4.
   This uses sqr instead of mul. */
AT_25519_INLINE at_ed25519_point_t *
at_ed25519_partial_dbl( at_ed25519_point_t *       r,
                        at_ed25519_point_t const * a ) {
  at_f25519_t r1[1], r2[1], r3[1], r4[1];
  at_f25519_t r5[1];

  at_f25519_add_nr( r1, a->X, a->Y );

  at_f25519_sqr4( r2, a->X,
                  r3, a->Y,
                  r4, a->Z,
                  r5, r1 );

  /* important: reduce mod p (these values are used in add/sub) */
  at_f25519_add( r4, r4, r4 );
  at_f25519_add( r->T, r2, r3 );
  at_f25519_sub( r->Z, r2, r3 );

  at_f25519_add_nr( r->Y, r4, r->Z );
  at_f25519_sub_nr( r->X, r->T, r5 );
  return r;
}

AT_25519_INLINE at_ed25519_point_t * AT_FN_NO_ASAN
at_ed25519_point_dbln( at_ed25519_point_t *       r,
                       at_ed25519_point_t const * a,
                       int                        n ) {
  at_ed25519_point_t t[1];
  at_ed25519_partial_dbl( t, a );
  for( uchar i=1; i<n; i++ ) {
    at_ed25519_point_add_final_mul_projective( r, t );
    at_ed25519_partial_dbl( t, r );
  }
  return at_ed25519_point_add_final_mul( r, t );
}

AT_PROTOTYPES_END