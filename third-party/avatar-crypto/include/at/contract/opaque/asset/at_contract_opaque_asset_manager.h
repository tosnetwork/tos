#ifndef HEADER_at_contract_opaque_asset_at_contract_opaque_asset_manager_h
#define HEADER_at_contract_opaque_asset_at_contract_opaque_asset_manager_h

#include "at/contract/opaque/asset/at_contract_opaque_asset.h"

AT_PROTOTYPES_BEGIN

#define AT_CONTRACT_OPAQUE_ASSET_TICKER_LEN (8UL)

int
at_contract_opaque_asset_create( at_contract_opaque_context_t const * ctx,
                                 ulong                                id,
                                 char const *                         name,
                                 char const *                         ticker,
                                 uchar                                decimals,
                                 int                                  has_max_supply,
                                 ulong                                max_supply,
                                 int *                                created_out,
                                 at_contract_opaque_asset_t *         asset_out );

int
at_contract_opaque_asset_get_by_id( at_contract_opaque_context_t const * ctx,
                                    ulong                                id,
                                    int *                                found_out,
                                    at_contract_opaque_asset_t *         asset_out );

int
at_contract_opaque_asset_get_by_hash( at_contract_opaque_context_t const * ctx,
                                      uchar const                          hash[32],
                                      int *                                found_out,
                                      at_contract_opaque_asset_t *         asset_out );

AT_PROTOTYPES_END

#endif /* HEADER_at_contract_opaque_asset_at_contract_opaque_asset_manager_h */
