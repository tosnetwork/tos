#ifndef HEADER_at_contract_opaque_at_contract_opaque_address_h
#define HEADER_at_contract_opaque_at_contract_opaque_address_h

#include "at/contract/opaque/at_contract_opaque_mod.h"

AT_PROTOTYPES_BEGIN

int
at_contract_opaque_address_from_string( char const *                  string,
                                        at_contract_opaque_address_t *out );

int
at_contract_opaque_address_to_string( at_contract_opaque_address_t const * address,
                                      char *                               out,
                                      ulong                                out_sz );

int
at_contract_opaque_address_is_mainnet( at_contract_opaque_address_t const * address );

int
at_contract_opaque_address_is_normal( at_contract_opaque_address_t const * address );

int
at_contract_opaque_address_public_key_bytes( at_contract_opaque_address_t const * address,
                                             uchar                                 out[32] );

AT_PROTOTYPES_END

#endif /* HEADER_at_contract_opaque_at_contract_opaque_address_h */
