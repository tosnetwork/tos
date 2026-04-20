#ifndef HEADER_at_src_ballet_bn254_at_bn254_internal_h
#define HEADER_at_src_ballet_bn254_at_bn254_internal_h

#include "./at_bn254.h"

/* Base field */

typedef at_uint256_t at_bn254_fp_t;

/* Extension fields */

struct AT_ALIGNED at_bn254_fp2 {
  at_bn254_fp_t el[2];
};
typedef struct at_bn254_fp2 at_bn254_fp2_t;

struct AT_ALIGNED at_bn254_fp6 {
  at_bn254_fp2_t el[3];
};
typedef struct at_bn254_fp6 at_bn254_fp6_t;

struct AT_ALIGNED at_bn254_fp12 {
  at_bn254_fp6_t el[2];
};
typedef struct at_bn254_fp12 at_bn254_fp12_t;

/* Point on G1, Jacobian coordinates */
struct AT_ALIGNED at_bn254_g1 {
  at_bn254_fp_t X;
  at_bn254_fp_t Y;
  at_bn254_fp_t Z;
};
typedef struct at_bn254_g1 at_bn254_g1_t;

/* Point on G2, Jacobian coordinates */
struct AT_ALIGNED at_bn254_g2 {
  at_bn254_fp2_t X;
  at_bn254_fp2_t Y;
  at_bn254_fp2_t Z;
};
typedef struct at_bn254_g2 at_bn254_g2_t;

/* Field utilities */

/* const 1. Montgomery.
   0x0e0a77c19a07df2f666ea36f7879462c0a78eb28f5c70b3dd35d438dc58f0d9d */
extern const at_bn254_fp_t at_bn254_const_one_mont[1];

static inline int
at_bn254_fp_is_zero( at_bn254_fp_t const * r ) {
  return r->limbs[0] == 0UL
      && r->limbs[1] == 0UL
      && r->limbs[2] == 0UL
      && r->limbs[3] == 0UL;
}

static inline int
at_bn254_fp_is_one( at_bn254_fp_t const * r ) {
  return r->limbs[0] == at_bn254_const_one_mont->limbs[0]
      && r->limbs[1] == at_bn254_const_one_mont->limbs[1]
      && r->limbs[2] == at_bn254_const_one_mont->limbs[2]
      && r->limbs[3] == at_bn254_const_one_mont->limbs[3];
}

static inline at_bn254_fp_t *
at_bn254_fp_set_zero( at_bn254_fp_t * r ) {
  r->limbs[0] = 0UL;
  r->limbs[1] = 0UL;
  r->limbs[2] = 0UL;
  r->limbs[3] = 0UL;
  return r;
}

static inline at_bn254_fp_t *
at_bn254_fp_set_one( at_bn254_fp_t * r ) {
  r->limbs[0] = at_bn254_const_one_mont->limbs[0];
  r->limbs[1] = at_bn254_const_one_mont->limbs[1];
  r->limbs[2] = at_bn254_const_one_mont->limbs[2];
  r->limbs[3] = at_bn254_const_one_mont->limbs[3];
  return r;
}

/* Extension fields utilities */

static inline int
at_bn254_fp2_is_zero( at_bn254_fp2_t const * a ) {
  return at_bn254_fp_is_zero( &a->el[0] )
      && at_bn254_fp_is_zero( &a->el[1] );
}

static inline int
at_bn254_fp2_is_one( at_bn254_fp2_t const * a ) {
  return at_bn254_fp_is_one ( &a->el[0] )
      && at_bn254_fp_is_zero( &a->el[1] );
}

static inline at_bn254_fp2_t *
at_bn254_fp2_set_zero( at_bn254_fp2_t * r ) {
  at_bn254_fp_set_zero( &r->el[0] );
  at_bn254_fp_set_zero( &r->el[1] );
  return r;
}

static inline at_bn254_fp2_t *
at_bn254_fp2_set_one( at_bn254_fp2_t * r ) {
  at_bn254_fp_set_one ( &r->el[0] );
  at_bn254_fp_set_zero( &r->el[1] );
  return r;
}

/* Fp6 */

static inline int
at_bn254_fp6_is_zero( at_bn254_fp6_t const * a ) {
  return at_bn254_fp2_is_zero( &a->el[0] )
      && at_bn254_fp2_is_zero( &a->el[1] )
      && at_bn254_fp2_is_zero( &a->el[2] );
}

static inline int
at_bn254_fp6_is_one( at_bn254_fp6_t const * a ) {
  return at_bn254_fp2_is_one ( &a->el[0] )
      && at_bn254_fp2_is_zero( &a->el[1] )
      && at_bn254_fp2_is_zero( &a->el[2] );
}

static inline at_bn254_fp6_t *
at_bn254_fp6_set_zero( at_bn254_fp6_t * r ) {
  at_bn254_fp2_set_zero( &r->el[0] );
  at_bn254_fp2_set_zero( &r->el[1] );
  at_bn254_fp2_set_zero( &r->el[2] );
  return r;
}

static inline at_bn254_fp6_t *
at_bn254_fp6_set_one( at_bn254_fp6_t * r ) {
  at_bn254_fp2_set_one ( &r->el[0] );
  at_bn254_fp2_set_zero( &r->el[1] );
  at_bn254_fp2_set_zero( &r->el[2] );
  return r;
}

/* Fp12 */

// static inline int
// at_bn254_fp12_is_zero( at_bn254_fp12_t const * a ) {
//   return at_bn254_fp6_is_zero( &a->el[0] )
//       && at_bn254_fp6_is_zero( &a->el[1] );
// }

static inline int
at_bn254_fp12_is_one( at_bn254_fp12_t const * a ) {
  return at_bn254_fp6_is_one ( &a->el[0] )
      && at_bn254_fp6_is_zero( &a->el[1] );
}

// static inline at_bn254_fp12_t *
// at_bn254_fp12_set_zero( at_bn254_fp12_t * r ) {
//   at_bn254_fp6_set_zero( &r->el[0] );
//   at_bn254_fp6_set_zero( &r->el[1] );
//   return r;
// }

static inline at_bn254_fp12_t *
at_bn254_fp12_set_one( at_bn254_fp12_t * r ) {
  at_bn254_fp6_set_one ( &r->el[0] );
  at_bn254_fp6_set_zero( &r->el[1] );
  return r;
}

at_bn254_fp12_t *
at_bn254_fp12_mul( at_bn254_fp12_t * r,
                   at_bn254_fp12_t const * a,
                   at_bn254_fp12_t const * b );

at_bn254_fp12_t *
at_bn254_fp12_inv( at_bn254_fp12_t * r,
                   at_bn254_fp12_t const * a );

at_bn254_fp12_t *
at_bn254_final_exp( at_bn254_fp12_t *       r,
                    at_bn254_fp12_t * const x );

at_bn254_fp12_t *
at_bn254_miller_loop( at_bn254_fp12_t *   r,
                      at_bn254_g1_t const p[],
                      at_bn254_g2_t const q[],
                      ulong               sz );

#endif /* HEADER_at_src_ballet_bn254_at_bn254_internal_h */