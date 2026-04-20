#ifndef HEADER_at_src_ballet_bn254_at_bn254_scalar_h
#define HEADER_at_src_ballet_bn254_at_bn254_scalar_h

/* Implementation of the BN254 scalar field, based on fiat-crypto.

   This covers 2 main use cases:
   - scalar validation, used e.g. in BN254 point scalar mul
   - scalar arithmetic, used e.g. to compute Poseidon hash

   The primary consumer is Avatar VM syscalls.
   Therefore, input is little endian and already aligned. */

#include "at_crypto_base.h"
#include "at/infra/uint256/at_uint256.h"
#include "fiat-crypto/bn254_scalar_64.c"

/* The implementation is based on fiat-crypto.
   Unfortunately mul is dramatically slow on gcc, so we reimplemented
   it in ballet/bigint/uint256_mul.h, based on uint128.
   When uint128 is not available we fall back on fiat-crypto. */
#define USE_FIAT_CRYPTO_MUL !AT_HAS_INT128

/* at_bn254_scalar represents a scalar as a buffer of 32 bytes,
   or equivalently (on little endian platforms) an array of 4 ulong. */
typedef at_uint256_t at_bn254_scalar_t;

/* const r, used to validate a scalar field element.
   NOT Montgomery.
   0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001 */
static const at_bn254_scalar_t at_bn254_const_r[1] = {{{
  UINT64_C(0x43e1f593f0000001), UINT64_C(0x2833e84879b97091),
  UINT64_C(0xb85045b68181585d), UINT64_C(0x30644e72e131a029),
}}};

/* const 1/r for CIOS mul */
static const uint64_t at_bn254_const_r_inv = UINT64_C(0xC2E1F593EFFFFFFF);

AT_PROTOTYPES_BEGIN

/* at_bn254_scalar_validate validates that the input scalar s
   is between 0 and r-1, included.
   This function works on 32-byte input buffer with no memory
   copies (assuming both platform and input are little endian). */
static inline int
at_bn254_scalar_validate( at_bn254_scalar_t const * s ) {
  return at_uint256_cmp( s, at_bn254_const_r ) < 0;
}

static inline at_bn254_scalar_t *
at_bn254_scalar_from_mont( at_bn254_scalar_t *       r,
                           at_bn254_scalar_t const * a ) {
  fiat_bn254_scalar_from_montgomery( r->limbs, a->limbs );
  return r;
}

static inline at_bn254_scalar_t *
at_bn254_scalar_to_mont( at_bn254_scalar_t *       r,
                         at_bn254_scalar_t const * a ) {
  fiat_bn254_scalar_to_montgomery( r->limbs, a->limbs );
  return r;
}

static inline at_bn254_scalar_t *
at_bn254_scalar_add( at_bn254_scalar_t *       r,
                     at_bn254_scalar_t const * a,
                     at_bn254_scalar_t const * b ) {
  fiat_bn254_scalar_add( r->limbs, a->limbs, b->limbs );
  return r;
}

#if USE_FIAT_CRYPTO_MUL

static inline at_bn254_scalar_t *
at_bn254_scalar_mul( at_bn254_scalar_t *       r,
                     at_bn254_scalar_t const * a,
                     at_bn254_scalar_t const * b ) {
  fiat_bn254_scalar_mul( r->limbs, a->limbs, b->limbs );
  return r;
}

static inline at_bn254_scalar_t *
at_bn254_scalar_sqr( at_bn254_scalar_t *       r,
                     at_bn254_scalar_t const * a ) {
  fiat_bn254_scalar_square( r->limbs, a->limbs );
  return r;
}

#else

AT_UINT256_FP_MUL_IMPL(at_bn254_scalar, at_bn254_const_r, at_bn254_const_r_inv)

static inline at_bn254_scalar_t *
at_bn254_scalar_sqr( at_bn254_scalar_t *       r,
                     at_bn254_scalar_t const * a ) {
  return at_bn254_scalar_mul( r, a, a );
}

#endif

AT_PROTOTYPES_END

#endif /* HEADER_at_src_ballet_bn254_at_bn254_scalar_h */