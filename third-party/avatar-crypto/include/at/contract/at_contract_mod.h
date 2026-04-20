#ifndef HEADER_at_contract_at_contract_mod_h
#define HEADER_at_contract_at_contract_mod_h

#include "at/block/at_block.h"
#include "at/contract/at_contract_base.h"
#include "at/contract/at_contract_cache.h"
#include "at/contract/at_contract_output.h"
#include "at/contract/at_contract_provider.h"
#include "at/contract/at_contract_random.h"
#include "at/infra/alloc/at_alloc.h"
#include "at/transaction/at_txn_contract.h"

AT_PROTOTYPES_BEGIN

/* Mirror of Rust TransferOutput from contract/mod.rs. */
typedef at_contract_transfer_output_t at_contract_transfer_output_t;

typedef struct {
  uchar account[32];
  uchar asset[32];
  ulong amount;
} at_contract_tracker_transfer_t;

typedef struct {
  at_contract_tracker_transfer_t * transfers;
  ulong                            transfers_cnt;
  ulong                            transfers_cap;
  uchar (*                         assets_created)[32];
  ulong                            assets_created_cnt;
  ulong                            assets_created_cap;
} at_contract_event_tracker_t;

typedef struct {
  uchar                       asset[32];
  int                         has_value;
  at_contract_asset_changes_t value;
} at_contract_asset_cache_entry_t;

typedef struct {
  int                                debug_mode;
  at_contract_deterministic_random_t random;
  int                                has_random;
  int                                mainnet;
  uchar                              contract[32];
  ulong                              topoheight;
  uchar                              block_hash[32];
  at_block_t const *                 block;
  uchar                              tx_hash[32];
  at_contract_deposit_t const *      deposits;
  ulong                              deposits_cnt;
  at_contract_cache_t                cache;
  at_contract_vm_output_t *          outputs;
  ulong                              outputs_cnt;
  ulong                              outputs_cap;
  at_contract_event_tracker_t        tracker;
  at_contract_cache_t const *        global_caches;
  uchar const (*                     global_cache_contracts)[32];
  ulong                              global_caches_cnt;
  at_contract_asset_cache_entry_t *  assets;
  ulong                              assets_cnt;
  ulong                              assets_cap;
  at_alloc_t *                       alloc;
} at_contract_chain_state_t;

int
at_contract_chain_state_init( at_contract_chain_state_t *     state,
                              at_alloc_t *                    alloc,
                              int                             debug_mode,
                              int                             mainnet,
                              uchar const                     contract[32],
                              ulong                           topoheight,
                              uchar const                     block_hash[32],
                              at_block_t const *              block,
                              uchar const                     tx_hash[32],
                              at_contract_deposit_t const *   deposits,
                              ulong                           deposits_cnt,
                              at_contract_cache_t const *     global_caches,
                              uchar const (*                  global_cache_contracts)[32],
                              ulong                           global_caches_cnt );

void
at_contract_chain_state_fini( at_contract_chain_state_t * state );

int
at_contract_chain_state_add_output( at_contract_chain_state_t *      state,
                                    at_contract_vm_output_t const *   output );

int
at_contract_chain_state_get_deposit_for_asset( at_contract_chain_state_t const * state,
                                               uchar const                       asset[32],
                                               int *                             found_out,
                                               ulong *                           amount_out );

int
at_contract_event_tracker_add_transfer( at_contract_event_tracker_t * tracker,
                                        uchar const                   account[32],
                                        uchar const                   asset[32],
                                        ulong                         amount,
                                        at_alloc_t *                  alloc );

int
at_contract_event_tracker_add_asset_created( at_contract_event_tracker_t * tracker,
                                             uchar const                   asset[32],
                                             at_alloc_t *                  alloc );

int
at_contract_get_balance_from_provider( at_contract_provider_t const * provider,
                                       ulong                         topoheight,
                                       uchar const                   contract[32],
                                       uchar const                   asset[32],
                                       int *                         found_out,
                                       at_contract_versioned_state_t *state_out,
                                       ulong *                       balance_out );

int
at_contract_get_balance_from_cache( at_contract_provider_t const *   provider,
                                    at_contract_chain_state_t *      state,
                                    uchar const                      asset[32],
                                    at_contract_cache_balance_entry_t ** entry_out );

int
at_contract_get_asset_from_provider( at_contract_provider_t const * provider,
                                     ulong                         topoheight,
                                     uchar const                   asset[32],
                                     int *                         found_out,
                                     at_contract_asset_changes_t *  out );

int
at_contract_get_optional_asset_from_cache( at_contract_provider_t const *    provider,
                                           at_contract_chain_state_t *       state,
                                           uchar const                       asset[32],
                                           at_contract_asset_cache_entry_t **entry_out );

int
at_contract_get_asset_from_cache( at_contract_provider_t const *   provider,
                                  at_contract_chain_state_t *      state,
                                  uchar const                      asset[32],
                                  at_contract_asset_changes_t **   changes_out );

int
at_contract_get_asset_changes_for_hash( at_contract_chain_state_t const * state,
                                        uchar const                       hash[32],
                                        at_contract_asset_changes_t const ** changes_out );

int
at_contract_get_asset_changes_for_hash_mut( at_contract_chain_state_t * state,
                                            uchar const                hash[32],
                                            at_contract_asset_changes_t ** changes_out );

AT_PROTOTYPES_END

#endif /* HEADER_at_contract_at_contract_mod_h */
