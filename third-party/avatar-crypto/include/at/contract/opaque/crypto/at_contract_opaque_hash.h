#ifndef HEADER_at_contract_opaque_crypto_at_contract_opaque_hash_h
#define HEADER_at_contract_opaque_crypto_at_contract_opaque_hash_h

#include "at/contract/opaque/at_contract_opaque_mod.h"
#include "at/infra/uint256/at_uint256.h"

AT_PROTOTYPES_BEGIN

int
at_contract_opaque_hash_from_bytes( at_contract_opaque_hash_t * out,
                                    uchar const *              bytes,
                                    ulong                      bytes_sz );

int
at_contract_opaque_hash_to_bytes( at_contract_opaque_hash_t const * hash,
                                  uchar                            out[32] );

int
at_contract_opaque_hash_from_array( at_contract_opaque_hash_t * out,
                                    uchar const *              values,
                                    ulong                      values_cnt );

int
at_contract_opaque_hash_to_array( at_contract_opaque_hash_t const * hash,
                                  uchar *                          out,
                                  ulong                            out_cnt );

int
at_contract_opaque_hash_from_u256( at_contract_opaque_hash_t * out,
                                   at_uint256_t const *       value );

int
at_contract_opaque_hash_to_u256( at_contract_opaque_hash_t const * hash,
                                 at_uint256_t *                  out );

int
at_contract_opaque_hash_to_hex( at_contract_opaque_hash_t const * hash,
                                char *                            out,
                                ulong                             out_sz );

int
at_contract_opaque_hash_from_hex( at_contract_opaque_hash_t * out,
                                  char const *               hex );

void
at_contract_opaque_hash_zero( at_contract_opaque_hash_t * out );

void
at_contract_opaque_hash_max( at_contract_opaque_hash_t * out );

int
at_contract_opaque_hash_blake3( uchar const *              data,
                                ulong                      data_sz,
                                at_contract_opaque_hash_t *out );

/* Name kept for TOS parity with hash.rs (sha256_fn uses Sha3_256). */
int
at_contract_opaque_hash_sha256( uchar const *              data,
                                ulong                      data_sz,
                                at_contract_opaque_hash_t *out );

AT_PROTOTYPES_END

#endif /* HEADER_at_contract_opaque_crypto_at_contract_opaque_hash_h */
