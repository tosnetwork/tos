#ifndef HEADER_at_contract_opaque_storage_at_contract_opaque_read_only_storage_h
#define HEADER_at_contract_opaque_storage_at_contract_opaque_read_only_storage_h

#include "at/contract/opaque/at_contract_opaque_mod.h"

AT_PROTOTYPES_BEGIN

typedef struct {
  uchar contract[32];
} at_contract_opaque_read_only_storage_t;

int
at_contract_opaque_read_only_storage_new( at_contract_opaque_context_t const *       ctx,
                                          uchar const                                contract[32],
                                          at_contract_opaque_read_only_storage_t *    out );

int
at_contract_opaque_read_only_storage_load(
    at_contract_opaque_context_t const *       ctx,
    at_contract_opaque_read_only_storage_t const * storage,
    uchar const *                              key,
    ulong                                      key_sz,
    int *                                      found_out,
    uchar **                                   value_out,
    ulong *                                    value_sz_out,
    at_alloc_t *                               alloc );

int
at_contract_opaque_read_only_storage_has(
    at_contract_opaque_context_t const *       ctx,
    at_contract_opaque_read_only_storage_t const * storage,
    uchar const *                              key,
    ulong                                      key_sz,
    int *                                      found_out );

AT_PROTOTYPES_END

#endif /* HEADER_at_contract_opaque_storage_at_contract_opaque_read_only_storage_h */
