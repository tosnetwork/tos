#ifndef HEADER_at_contract_opaque_asset_at_contract_opaque_asset_h
#define HEADER_at_contract_opaque_asset_at_contract_opaque_asset_h

#include "at/contract/opaque/at_contract_opaque_mod.h"

AT_PROTOTYPES_BEGIN

typedef struct {
  uchar hash[32];
} at_contract_opaque_asset_t;

int
at_contract_opaque_asset_get_max_supply( at_contract_opaque_context_t const * ctx,
                                         at_contract_opaque_asset_t const *   asset,
                                         int *                                 found_out,
                                         ulong *                               value_out );

int
at_contract_opaque_asset_get_contract_hash( at_contract_opaque_context_t const * ctx,
                                            at_contract_opaque_asset_t const *   asset,
                                            int *                                 found_out,
                                            uchar                                 contract_out[32] );

int
at_contract_opaque_asset_get_contract_id( at_contract_opaque_context_t const * ctx,
                                          at_contract_opaque_asset_t const *   asset,
                                          int *                                 found_out,
                                          ulong *                               id_out );

int
at_contract_opaque_asset_get_supply( at_contract_opaque_context_t const * ctx,
                                     at_contract_opaque_asset_t const *   asset,
                                     ulong *                               supply_out );

int
at_contract_opaque_asset_get_name( at_contract_opaque_context_t const * ctx,
                                   at_contract_opaque_asset_t const *   asset,
                                   char const **                         name_out );

int
at_contract_opaque_asset_get_hash( at_contract_opaque_asset_t const * asset,
                                   uchar                               hash_out[32] );

int
at_contract_opaque_asset_get_ticker( at_contract_opaque_context_t const * ctx,
                                     at_contract_opaque_asset_t const *   asset,
                                     char const **                         ticker_out );

int
at_contract_opaque_asset_is_read_only( at_contract_opaque_context_t const * ctx,
                                       at_contract_opaque_asset_t const *   asset,
                                       int *                                 read_only_out );

int
at_contract_opaque_asset_transfer_ownership( at_contract_opaque_context_t const * ctx,
                                             at_contract_opaque_asset_t const *   asset,
                                             uchar const                          new_contract[32],
                                             int *                                changed_out );

int
at_contract_opaque_asset_mint( at_contract_opaque_context_t const * ctx,
                               at_contract_opaque_asset_t const *   asset,
                               ulong                                 amount,
                               int *                                 minted_out );

AT_PROTOTYPES_END

#endif /* HEADER_at_contract_opaque_asset_at_contract_opaque_asset_h */
