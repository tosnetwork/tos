#ifndef HEADER_at_contract_opaque_storage_at_contract_opaque_storage_h
#define HEADER_at_contract_opaque_storage_at_contract_opaque_storage_h

#include "at/contract/opaque/at_contract_opaque_mod.h"

AT_PROTOTYPES_BEGIN

#define AT_CONTRACT_OPAQUE_STORAGE_MAX_KEY_SIZE   (256UL)
#define AT_CONTRACT_OPAQUE_STORAGE_MAX_VALUE_SIZE (4096UL)

ulong
at_contract_opaque_storage_store_gas_cost( ulong key_sz,
                                           ulong value_sz );

int
at_contract_opaque_storage_load( at_contract_opaque_context_t const * ctx,
                                 uchar const *                       key,
                                 ulong                               key_sz,
                                 int *                               found_out,
                                 uchar **                            value_out,
                                 ulong *                             value_sz_out,
                                 at_alloc_t *                        alloc );

int
at_contract_opaque_storage_has( at_contract_opaque_context_t const * ctx,
                                uchar const *                       key,
                                ulong                               key_sz,
                                int *                               found_out );

int
at_contract_opaque_storage_store( at_contract_opaque_context_t const * ctx,
                                  uchar const *                       key,
                                  ulong                               key_sz,
                                  uchar const *                       value,
                                  ulong                               value_sz,
                                  int *                               prev_found_out,
                                  uchar **                            prev_value_out,
                                  ulong *                             prev_value_sz_out,
                                  at_alloc_t *                        alloc );

int
at_contract_opaque_storage_delete( at_contract_opaque_context_t const * ctx,
                                   uchar const *                       key,
                                   ulong                               key_sz,
                                   int *                               prev_found_out,
                                   uchar **                            prev_value_out,
                                   ulong *                             prev_value_sz_out,
                                   at_alloc_t *                        alloc );

AT_PROTOTYPES_END

#endif /* HEADER_at_contract_opaque_storage_at_contract_opaque_storage_h */
