#ifndef HEADER_at_contract_opaque_crypto_at_contract_opaque_signature_h
#define HEADER_at_contract_opaque_crypto_at_contract_opaque_signature_h

#include "at/contract/opaque/at_contract_opaque_mod.h"
#include "at/contract/opaque/at_contract_opaque_address.h"

AT_PROTOTYPES_BEGIN

int
at_contract_opaque_signature_from_bytes( at_contract_opaque_signature_t * out,
                                         uchar const *                   bytes,
                                         ulong                           bytes_sz );

int
at_contract_opaque_signature_to_bytes( at_contract_opaque_signature_t const * sig,
                                       uchar                                  out[64] );

int
at_contract_opaque_signature_verify( at_contract_opaque_signature_t const * sig,
                                     at_contract_opaque_address_t const *   address,
                                     uchar const *                          data,
                                     ulong                                  data_sz,
                                     int *                                  valid_out );

AT_PROTOTYPES_END

#endif /* HEADER_at_contract_opaque_crypto_at_contract_opaque_signature_h */
