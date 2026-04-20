#ifndef HEADER_at_contract_at_contract_provider_h
#define HEADER_at_contract_at_contract_provider_h

#include "at/contract/at_contract_base.h"
#include "at/contract/at_contract_cache.h"
#include "at/core/storage/at_store.h"

AT_PROTOTYPES_BEGIN

typedef struct at_contract_provider at_contract_provider_t;

typedef struct {
  /* Backing store and a default read upper-bound topoheight. */
  at_store_t * store;
  ulong        maximum_topoheight;
} at_contract_provider_store_ctx_t;

struct at_contract_provider {
  int (*get_contract_balance_for_asset)( void *       ctx,
                                         uchar const  contract[32],
                                         uchar const  asset[32],
                                         ulong        topoheight,
                                         int *        found_out,
                                         ulong *      found_topo_out,
                                         ulong *      balance_out );
  int (*get_account_balance_for_asset)( void *       ctx,
                                        uchar const  key[32],
                                        uchar const  asset[32],
                                        ulong        topoheight,
                                        int *        found_out,
                                        ulong *      found_topo_out,
                                        ulong *      balance_out );
  int (*asset_exists)( void *      ctx,
                       uchar const asset[32],
                       ulong       topoheight,
                       int *       exists_out );
  int (*load_asset_data)( void *                    ctx,
                          uchar const               asset[32],
                          ulong                     topoheight,
                          int *                     found_out,
                          ulong *                   found_topo_out,
                          at_contract_asset_data_t *data_out );
  int (*load_asset_supply)( void *       ctx,
                            uchar const  asset[32],
                            ulong        topoheight,
                            int *        found_out,
                            ulong *      found_topo_out,
                            ulong *      supply_out );
  int (*account_exists)( void *       ctx,
                         uchar const  key[32],
                         ulong        topoheight,
                         int *        exists_out );
  int (*load_contract_module)( void *        ctx,
                               uchar const   contract[32],
                               ulong         topoheight,
                               uchar **      module_out,
                               ulong *       module_sz_out,
                               ulong *       found_topo_out );
  int (*load_contract_data)( void *        ctx,
                             uchar const   contract[32],
                             uchar const * key,
                             ulong         key_sz,
                             ulong         topoheight,
                             int *         found_out,
                             ulong *       found_topo_out,
                             int *         has_value_out,
                             uchar **      value_out,
                             ulong *       value_sz_out,
                             at_alloc_t *  alloc );
  int (*load_contract_data_latest_topoheight)( void *        ctx,
                                               uchar const   contract[32],
                                               uchar const * key,
                                               ulong         key_sz,
                                               ulong         topoheight,
                                               int *         found_out,
                                               ulong *       found_topo_out );
  int (*has_contract)( void *       ctx,
                       uchar const  contract[32],
                       ulong        topoheight,
                       int *        exists_out );
  void * ctx;
};

void
at_contract_provider_init_store( at_contract_provider_t *           provider,
                                 at_contract_provider_store_ctx_t * ctx );

int
at_contract_provider_get_contract_balance_for_asset( at_contract_provider_t const * provider,
                                                     uchar const                    contract[32],
                                                     uchar const                    asset[32],
                                                     ulong                          topoheight,
                                                     int *                          found_out,
                                                     ulong *                        found_topo_out,
                                                     ulong *                        balance_out );

int
at_contract_provider_get_account_balance_for_asset( at_contract_provider_t const * provider,
                                                    uchar const                    key[32],
                                                    uchar const                    asset[32],
                                                    ulong                          topoheight,
                                                    int *                          found_out,
                                                    ulong *                        found_topo_out,
                                                    ulong *                        balance_out );

int
at_contract_provider_asset_exists( at_contract_provider_t const * provider,
                                   uchar const                   asset[32],
                                   ulong                         topoheight,
                                   int *                         exists_out );

int
at_contract_provider_load_asset_data( at_contract_provider_t const * provider,
                                      uchar const                   asset[32],
                                      ulong                         topoheight,
                                      int *                         found_out,
                                      ulong *                       found_topo_out,
                                      at_contract_asset_data_t *    data_out );

int
at_contract_provider_load_asset_supply( at_contract_provider_t const * provider,
                                        uchar const                   asset[32],
                                        ulong                         topoheight,
                                        int *                         found_out,
                                        ulong *                       found_topo_out,
                                        ulong *                       supply_out );

int
at_contract_provider_account_exists( at_contract_provider_t const * provider,
                                     uchar const                   key[32],
                                     ulong                         topoheight,
                                     int *                         exists_out );

int
at_contract_provider_load_contract_module( at_contract_provider_t const * provider,
                                           uchar const                   contract[32],
                                           ulong                         topoheight,
                                           uchar **                      module_out,
                                           ulong *                       module_sz_out,
                                           ulong *                       found_topo_out );

int
at_contract_provider_load_contract_data( at_contract_provider_t const * provider,
                                         uchar const                   contract[32],
                                         uchar const *                 key,
                                         ulong                         key_sz,
                                         ulong                         topoheight,
                                         int *                         found_out,
                                         ulong *                       found_topo_out,
                                         int *                         has_value_out,
                                         uchar **                      value_out,
                                         ulong *                       value_sz_out,
                                         at_alloc_t *                  alloc );

int
at_contract_provider_load_contract_data_latest_topoheight( at_contract_provider_t const * provider,
                                                           uchar const                   contract[32],
                                                           uchar const *                 key,
                                                           ulong                         key_sz,
                                                           ulong                         topoheight,
                                                           int *                         found_out,
                                                           ulong *                       found_topo_out );

int
at_contract_provider_has_contract( at_contract_provider_t const * provider,
                                   uchar const                   contract[32],
                                   ulong                         topoheight,
                                   int *                         exists_out );

AT_PROTOTYPES_END

#endif /* HEADER_at_contract_at_contract_provider_h */
