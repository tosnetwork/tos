#ifndef HEADER_at_src_ballet_ed25519_at_ristretto255_h
#define HEADER_at_src_ballet_ed25519_at_ristretto255_h

/* at_ristretto255.h provides the public ristretto255 group element
   API.

   All operations in this API should be assumed to take a variable
   amount of time depending on inputs.  (And thus should not be exposed
   to secret data) */

#include "at_curve25519.h"

/* at_ristretto255 provides APIs for the ristretto255 prime order group */

static const uchar at_ristretto255_compressed_zero[ 32 ] = {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* at_ristretto255_point_t is a opaque handle to a ristretto255 group
   element.  Although it is the same type as an Ed25519 group element,
   it is unsafe to mix Ed25519 point and ristretto point APIs. */

typedef at_ed25519_point_t at_ristretto255_point_t;

#define at_ristretto255_point_set_zero         at_ed25519_point_set_zero
#define at_ristretto255_point_set              at_ed25519_point_set
#define at_ristretto255_point_add              at_ed25519_point_add
#define at_ristretto255_point_sub              at_ed25519_point_sub
#define at_ristretto255_point_is_zero          at_ed25519_point_is_zero
#define at_ristretto255_scalar_validate        at_ed25519_scalar_validate
#define at_ristretto255_scalar_mul             at_ed25519_scalar_mul
#define at_ristretto255_multi_scalar_mul       at_ed25519_multi_scalar_mul
#define at_ristretto255_multi_scalar_mul_straus at_ed25519_multi_scalar_mul_straus
#define at_ristretto255_point_decompress       at_ristretto255_point_frombytes
#define at_ristretto255_point_compress         at_ristretto255_point_tobytes

AT_PROTOTYPES_BEGIN

uchar *
at_ristretto255_point_tobytes( uchar                           buf[ 32 ],
                               at_ristretto255_point_t const * p );

/* at_ristretto255_point_frombytes decompresses a 32-byte array into
   an element of the ristretto group h.
   It returns p on success, NULL on failure. */

at_ristretto255_point_t *
at_ristretto255_point_frombytes( at_ristretto255_point_t * p,
                                  uchar const              buf[ 32 ] );

/* at_ristretto255_point_validate checks if a 32-byte array represents
   a valid element of the ristretto group h.
   It returns 1 on success, 0 on failure. */

static inline int
at_ristretto255_point_validate( uchar const buf[ 32 ] ) {
  at_ristretto255_point_t t[1];
  return !!at_ristretto255_point_frombytes( t, buf );
}

/* at_ristretto255_point_eq checks if two elements of the ristretto group
   p and q are equal.
   It returns 1 on success, 0 on failure. */

static inline int
at_ristretto255_point_eq( at_ristretto255_point_t * const p,
                          at_ristretto255_point_t * const q ) {
  // https://ristretto.group/details/equality.html
  at_f25519_t cmp[2];
  at_f25519_t x[2], y[2], _z[2], _t[2];
  at_ed25519_point_to( &x[0], &y[0], &_z[0], &_t[0], p );
  at_ed25519_point_to( &x[1], &y[1], &_z[1], &_t[1], q );

  at_f25519_mul( &cmp[ 0 ], &x[0], &y[1] );
  at_f25519_mul( &cmp[ 1 ], &x[1], &y[0] );
  int xx = at_f25519_eq( &cmp[ 0 ], &cmp[ 1 ] );

  at_f25519_mul( &cmp[ 0 ], &x[0], &x[1] );
  at_f25519_mul( &cmp[ 1 ], &y[0], &y[1] );
  int yy = at_f25519_eq( &cmp[ 0 ], &cmp[ 1 ] );

  return xx | yy;
}

/* at_ristretto255_point_eq_neg checks if two elements of the ristretto group
   p and q are such that -p == q. This uses just 1 extra neg.
   It returns 1 on success, 0 on failure. */

static inline int
at_ristretto255_point_eq_neg( at_ristretto255_point_t * const p,
                              at_ristretto255_point_t * const q ) {
  // https://ristretto.group/details/equality.html
  at_f25519_t neg[1];
  at_f25519_t cmp[2];
  at_f25519_t x[2], y[2], _z[2], _t[2];
  at_ed25519_point_to( &x[0], &y[0], &_z[0], &_t[0], p );
  at_ed25519_point_to( &x[1], &y[1], &_z[1], &_t[1], q );

  at_f25519_neg( neg, &x[0] );
  at_f25519_mul( &cmp[ 0 ], neg, &y[1] );
  at_f25519_mul( &cmp[ 1 ], &x[1], &y[0] );
  int xx = at_f25519_eq( &cmp[ 0 ], &cmp[ 1 ] );

  at_f25519_mul( &cmp[ 0 ], neg, &x[1] );
  at_f25519_mul( &cmp[ 1 ], &y[0], &y[1] );
  int yy = at_f25519_eq( &cmp[ 0 ], &cmp[ 1 ] );

  return xx | yy;
}

/* at_ristretto255_hash_to_curve computes an element h of the ristretto group
   given an array s of 64-byte of uniformly random input (e.g., the output of a
   hash function).
   This function behaves like a random oracle.
   It returns h. */

at_ristretto255_point_t *
at_ristretto255_hash_to_curve( at_ristretto255_point_t * h,
                               uchar const               s[ 64 ] );

/* at_ristretto255_map_to_curve implements the elligato2 map for curve25519,
   and computes an element h of the ristretto group given an array s of 32-byte 
   of uniformly random input (e.g., the output of a hash function).
   This function does NOT behave like a random oracle, and is intended for
   internal use.
   It returns h. */

at_ristretto255_point_t *
at_ristretto255_map_to_curve( at_ristretto255_point_t * h,
                              uchar const               s[ 32 ] );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_ballet_ed25519_at_ristretto255_h */