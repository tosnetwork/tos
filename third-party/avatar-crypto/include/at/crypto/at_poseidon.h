#ifndef HEADER_at_src_ballet_bn254_at_poseidon_h
#define HEADER_at_src_ballet_bn254_at_poseidon_h

/* Implementation of the Poseidon hash function over BN254 scalar field.
   Based on Rust light-poseidon v0.2.0:
   https://github.com/Lightprotocol/light-poseidon/blob/v0.2.0/light-poseidon/src/lib.rs#L377
   That is in turn based on Circom v2.0.x:
   https://github.com/iden3/circomlib/blob/v2.0.5/circuits/poseidon.circom */

#include "at_crypto_base.h"
#include "./at_bn254_scalar.h"

#define AT_POSEIDON_HASH_SZ   (32UL)
#define AT_POSEIDON_MAX_WIDTH (12UL)

/* Hash result. Actually a value in the bn254 field */
struct at_poseidon_hash_result {
  uchar v[ AT_POSEIDON_HASH_SZ ];
};
typedef struct at_poseidon_hash_result at_poseidon_hash_result_t;

struct AT_ALIGNED at_poseidon {
  at_bn254_scalar_t state[ 1+AT_POSEIDON_MAX_WIDTH ];
  ulong             cnt;        /* How many elements have been appended total */
  int               big_endian; /* 0 little endian, 1 big endian */
};
typedef struct at_poseidon at_poseidon_t;

struct at_poseidon_par {
  at_bn254_scalar_t * ark;
  at_bn254_scalar_t * mds;
};
typedef struct at_poseidon_par at_poseidon_par_t;

AT_PROTOTYPES_BEGIN

/* at_poseidon_init starts a Poseidon calculation.
   pos is assumed to be a current local join to a Poseidon calculation
   state with no other concurrent operation that would modify the state
   while this is executing.  Any preexisting state for an in-progress or
   recently completed calculation will be discarded.
   if big_endian>0 treats all inputs (append) and output (fini) as big endian,
   otherwise treats them all as little endian.
   Returns pos (on return, pos will have the state of a new in-progress
   calculation). */

at_poseidon_t *
at_poseidon_init( at_poseidon_t * pos,
                  int const       big_endian );

/* at_poseidon_append adds sz bytes locally pointed to by data an
   in-progress Poseidon calculation.
   out is assumed to be valid (i.e. is a current local join to a Poseidon
   calculation state with no other concurrent operations that would modify
   the state while this is executing). out==NULL is ok to allow chaining:
     at_poseidon_append( at_poseidon_append( ... ) )
   data points to the first of the sz bytes, and will be unmodified while
   this is running with no interest retained after return (data==NULL is fine if sz==0).
   data represents a bn254 scalar, i.e. a 256-bit bigint modulo a prime.
   If data is not exactly 32-byte long (sz!=32), then data is padded with 0s
   during conversion.
   Returns out on success, NULL in case of error:
   - if pos==NULL
   - if data >= modulus (including sz > 32)
   - if at_poseidon_append is called more than 12 times on the same pos

   Note: unlike other hash functions, each call to at_poseidon_append
   attempts to append a new scalar to the current state.
   This implementation is modeled around Rust light-poseidon, that in
   turn is modeled around Circom implementation.
   It supports hashing a max of AT_POSEIDON_MAX_WIDTH elements. */

at_poseidon_t *
at_poseidon_append( at_poseidon_t * pos,
                    uchar const *   data,
                    ulong           sz,
                    int             enforce_padding );

/* at_poseidon_fini finishes a Poseidon calculation.
   out is assumed to be valid (i.e. is a current local join to a Poseidon
   calculation state with no other concurrent operations that would modify
   the state while this is executing). out==NULL is ok to allow chaining:
     at_poseidon_fini( at_poseidon_append( ... ) )
   hash points to the first byte of a 32-byte memory region where the
   result of the calculation should be stored.
   Returns hash, or NULL if pos==NULL (on return, there will be no calculation
   in-progress on pos and 32-byte buffer pointed to by hash will be populated
   with the calculation result). */

uchar *
at_poseidon_fini( at_poseidon_t * pos,
                  uchar           hash[ AT_POSEIDON_HASH_SZ ] );

/* Hash a series of bytes. */
static inline int
at_poseidon_hash( at_poseidon_hash_result_t * result,
                  uchar const *               bytes,
                  ulong                       bytes_len,
                  int const                   big_endian ) {
  at_poseidon_t pos[1];
  at_poseidon_init( pos, big_endian );
  for( ulong i=0; i<bytes_len/32; i++ ) {
    at_poseidon_append( pos, &bytes[i*32], 32, 1 );
  }
  return !at_poseidon_fini( pos, at_type_pun(result) );
}

AT_PROTOTYPES_END

#endif /* HEADER_at_src_ballet_bn254_at_poseidon_h */