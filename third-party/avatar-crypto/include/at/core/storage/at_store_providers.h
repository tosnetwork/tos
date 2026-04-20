#ifndef HEADER_at_store_providers_h
#define HEADER_at_store_providers_h

/* at_store_providers.h - High-level storage provider helpers
   These functions mirror TOS RocksDB provider traits in C form. */

#include "at/core/storage/at_store.h"
#include "at/account/at_account.h"
#include "at/account/at_delegation.h"
#include "at/account/at_multisig.h"
#include "at/uno/at_uno_balance.h"
#include "at/core/blockdag/at_blockdag.h"
#include "at/core/blockdag/at_difficulty.h"
#include "at/block/at_block.h"
#include "at/core/storage/at_store_snapshot_mod.h"

AT_PROTOTYPES_BEGIN

/* ==========================================================================
   Delegation Provider
   ==========================================================================
*/

int at_store_get_delegation_record( at_store_t * store,
                                    uchar const delegator[32],
                                    uint record_index,
                                    at_delegated_freeze_record_t * record_out,
                                    int * found_out );

int at_store_set_delegation_record( at_store_t * store,
                                    uchar const delegator[32],
                                    uint record_index,
                                    at_delegated_freeze_record_t const * record );

int at_store_delete_delegation_record( at_store_t * store,
                                       uchar const delegator[32],
                                       uint record_index );

int at_store_get_delegator_state( at_store_t * store,
                                  uchar const delegator[32],
                                  at_delegator_state_t * state_out );

int at_store_set_delegator_state( at_store_t * store,
                                  uchar const delegator[32],
                                  at_delegator_state_t const * state );

int at_store_delete_delegator_state( at_store_t * store,
                                     uchar const delegator[32] );

int at_store_list_delegation_records( at_store_t * store,
                                      ulong skip,
                                      ulong limit,
                                      uchar (*delegators_out)[32],
                                      uint * record_indices_out,
                                      at_delegated_freeze_record_t * records_out,
                                      ulong * out_count );

/* ==========================================================================
   Energy Provider
   ==========================================================================
*/

int at_store_get_energy_resource( at_store_t * store,
                                  uchar const pubkey[32],
                                  at_energy_resource_t * resource_out,
                                  int * found_out );

int at_store_get_energy_resource_at_max_topoheight( at_store_t * store,
                                                    uchar const pubkey[32],
                                                    ulong maximum_topoheight,
                                                    at_energy_resource_t * resource_out,
                                                    ulong * topo_out,
                                                    int * found_out );

int at_store_set_energy_resource( at_store_t * store,
                                  uchar const pubkey[32],
                                  ulong topoheight,
                                  at_energy_resource_t const * resource );

int at_store_delete_versioned_energy_at_topoheight( at_store_t * store,
                                                    ulong topoheight );

int at_store_delete_versioned_energy_above_topoheight( at_store_t * store,
                                                       ulong topoheight );

int at_store_delete_versioned_energy_below_topoheight( at_store_t * store,
                                                       ulong topoheight,
                                                       int keep_last );

/* ==========================================================================
   MultiSig Provider
   ==========================================================================
*/

int at_store_get_multisig( at_store_t * store,
                           uchar const pubkey[32],
                           at_versioned_multisig_t * config_out,
                           int * found_out );

int at_store_get_last_topoheight_for_multisig( at_store_t * store,
                                               uchar const pubkey[32],
                                               ulong * topoheight_out,
                                               int * found_out );

int at_store_get_multisig_at_topo( at_store_t * store,
                                   uchar const pubkey[32],
                                   ulong topoheight,
                                   at_versioned_multisig_t * config_out,
                                   int * found_out );

int at_store_get_multisig_at_max_topoheight( at_store_t * store,
                                             uchar const pubkey[32],
                                             ulong maximum_topoheight,
                                             ulong * topo_out,
                                             at_versioned_multisig_t * config_out,
                                             int * found_out );

int at_store_delete_last_topoheight_for_multisig( at_store_t * store,
                                                  uchar const pubkey[32] );

int at_store_has_multisig( at_store_t * store,
                           uchar const pubkey[32],
                           int * has_out );

int at_store_has_multisig_at_exact_topoheight( at_store_t * store,
                                               uchar const pubkey[32],
                                               ulong topoheight,
                                               int * has_out );

int at_store_get_last_multisig( at_store_t * store,
                                uchar const pubkey[32],
                                ulong * topo_out,
                                at_versioned_multisig_t * config_out );

int at_store_set_multisig( at_store_t * store,
                           uchar const pubkey[32],
                           at_versioned_multisig_t const * config,
                           ulong topoheight );

int at_store_set_last_multisig_to( at_store_t * store,
                                   uchar const pubkey[32],
                                   ulong topoheight,
                                   at_versioned_multisig_t const * config );

/* ==========================================================================
   UNO Balance Provider
   ==========================================================================
*/

int at_store_get_uno_balance( at_store_t * store,
                              uchar const pubkey[32],
                              uchar const asset[32],
                              at_uno_ciphertext_t * balance_out,
                              int * found_out );

int at_store_has_uno_balance_for( at_store_t * store,
                                  uchar const pubkey[32],
                                  uchar const asset[32],
                                  int * has_out );

int at_store_has_uno_balance_at_exact_topoheight( at_store_t * store,
                                                  uchar const pubkey[32],
                                                  uchar const asset[32],
                                                  ulong topoheight,
                                                  int * has_out );

int at_store_get_uno_balance_at_topo( at_store_t * store,
                                      uchar const pubkey[32],
                                      uchar const asset[32],
                                      ulong topoheight,
                                      at_versioned_uno_balance_t * vbal_out,
                                      int * found_out );

int at_store_get_uno_balance_at_max_topoheight( at_store_t * store,
                                                uchar const pubkey[32],
                                                uchar const asset[32],
                                                ulong maximum_topoheight,
                                                ulong * topo_out,
                                                at_versioned_uno_balance_t * vbal_out,
                                                int * found_out );

int at_store_get_last_topoheight_for_uno_balance( at_store_t * store,
                                                  uchar const pubkey[32],
                                                  uchar const asset[32],
                                                  ulong * topoheight_out );

int at_store_get_new_versioned_uno_balance( at_store_t * store,
                                            uchar const pubkey[32],
                                            uchar const asset[32],
                                            ulong topoheight,
                                            at_versioned_uno_balance_t * vbal_out,
                                            int * is_new_out );

int at_store_get_last_uno_balance( at_store_t * store,
                                   uchar const pubkey[32],
                                   uchar const asset[32],
                                   ulong * topo_out,
                                   at_versioned_uno_balance_t * vbal_out );

int at_store_get_uno_output_balance_at_max_topoheight( at_store_t * store,
                                                       uchar const pubkey[32],
                                                       uchar const asset[32],
                                                       ulong maximum_topoheight,
                                                       ulong * topo_out,
                                                       at_versioned_uno_balance_t * vbal_out,
                                                       int * found_out );

int at_store_get_uno_output_balance_in_range( at_store_t * store,
                                              uchar const pubkey[32],
                                              uchar const asset[32],
                                              ulong minimum_topoheight,
                                              ulong maximum_topoheight,
                                              ulong * topo_out,
                                              at_versioned_uno_balance_t * vbal_out,
                                              int * found_out );

int at_store_set_last_topoheight_for_uno_balance( at_store_t * store,
                                                  uchar const pubkey[32],
                                                  uchar const asset[32],
                                                  ulong topoheight );

int at_store_set_last_uno_balance_to( at_store_t * store,
                                      uchar const pubkey[32],
                                      uchar const asset[32],
                                      ulong topoheight,
                                      at_versioned_uno_balance_t const * vbal );

int at_store_set_uno_balance_at_topoheight( at_store_t * store,
                                            ulong topoheight,
                                            uchar const pubkey[32],
                                            uchar const asset[32],
                                            at_versioned_uno_balance_t const * vbal );

int at_store_get_uno_account_summary_for( at_store_t * store,
                                          uchar const pubkey[32],
                                          uchar const asset[32],
                                          ulong minimum_topoheight,
                                          ulong maximum_topoheight,
                                          at_uno_account_summary_t * summary_out,
                                          int * found_out );

int at_store_get_spendable_uno_balances_for( at_store_t * store,
                                             uchar const pubkey[32],
                                             uchar const asset[32],
                                             ulong minimum_topoheight,
                                             ulong maximum_topoheight,
                                             ulong maximum,
                                             at_uno_balance_entry_t * balances_out,
                                             ulong * count_out,
                                             ulong * next_topo_out,
                                             int * has_next_topo_out );

int at_store_delete_uno_balance_at_topoheight( at_store_t * store,
                                               uchar const pubkey[32],
                                               uchar const asset[32],
                                               ulong topoheight );

int at_store_list_all_uno_balance_keys( at_store_t * store,
                                        ulong skip,
                                        ulong limit,
                                        uchar (*pubkeys_out)[32],
                                        uchar (*assets_out)[32],
                                        ulong * out_count );

int at_store_import_uno_balance( at_store_t * store,
                                 uchar const pubkey[32],
                                 uchar const asset[32],
                                 ulong topoheight,
                                 at_versioned_uno_balance_t const * vbal );

int at_store_set_uno_balance( at_store_t * store,
                              uchar const pubkey[32],
                              uchar const asset[32],
                              at_uno_ciphertext_t const * balance,
                              ulong topoheight );

int at_store_add_uno_balance( at_store_t * store,
                              uchar const pubkey[32],
                              uchar const asset[32],
                              at_uno_ciphertext_t const * delta,
                              ulong topoheight );

int at_store_sub_uno_balance( at_store_t * store,
                              uchar const pubkey[32],
                              uchar const asset[32],
                              at_uno_ciphertext_t const * delta,
                              ulong topoheight );

/* ==========================================================================
   Merkle Provider (Unsupported)
   ==========================================================================
*/

int at_store_get_balances_merkle_hash_at_topoheight( at_store_t * store,
                                                     ulong topoheight,
                                                     uchar hash_out[32] );

int at_store_set_balances_merkle_hash_at_topoheight( at_store_t * store,
                                                     ulong topoheight,
                                                     uchar const hash[32] );

/* ==========================================================================
   Transaction Provider
   ==========================================================================
*/

int at_store_get_transaction_raw( at_store_t * store,
                                  uchar const hash[32],
                                  void ** raw_out,
                                  ulong * raw_sz_out );

int at_store_get_transaction_size( at_store_t * store,
                                   uchar const hash[32],
                                   ulong * size_out );

int at_store_count_transactions( at_store_t * store,
                                 ulong * count_out );

int at_store_list_unexecuted_transactions( at_store_t * store,
                                           ulong skip,
                                           ulong limit,
                                           uchar (*hashes_out)[32],
                                           ulong * out_count );

int at_store_has_transaction( at_store_t * store,
                              uchar const hash[32],
                              int * found_out );

int at_store_add_transaction( at_store_t * store,
                              uchar const hash[32],
                              void const * raw,
                              ulong raw_sz );

int at_store_delete_transaction( at_store_t * store,
                                 uchar const hash[32],
                                 void ** raw_out,
                                 ulong * raw_sz_out );

/* ==========================================================================
   Difficulty Provider
   ==========================================================================
*/

int at_store_get_height_for_block_hash( at_store_t * store,
                                        uchar const hash[32],
                                        ulong * height_out );

int at_store_get_version_for_block_hash( at_store_t * store,
                                         uchar const hash[32],
                                         uint * version_out );

int at_store_get_timestamp_for_block_hash( at_store_t * store,
                                           uchar const hash[32],
                                           ulong * timestamp_out );

int at_store_get_difficulty_for_block_hash( at_store_t * store,
                                            uchar const hash[32],
                                            at_difficulty_t * difficulty_out );

int at_store_get_cumulative_difficulty_for_block_hash( at_store_t * store,
                                                       uchar const hash[32],
                                                       at_cumulative_difficulty_t * cdiff_out );

int at_store_get_past_blocks_for_block_hash( at_store_t * store,
                                             uchar const hash[32],
                                             uchar (*tips_out)[32],
                                             ulong * tips_cnt_out );

int at_store_get_block_header_by_hash( at_store_t * store,
                                       uchar const hash[32],
                                       at_block_header_t * header_out );

int at_store_get_estimated_covariance_for_block_hash( at_store_t * store,
                                                      uchar const hash[32],
                                                      ulong * covariance_out );

/* ==========================================================================
   State Provider
   ==========================================================================
*/

int at_store_get_top_block_hash( at_store_t * store,
                                 uchar hash_out[32] );

int at_store_get_top_block_raw( at_store_t * store,
                                void ** raw_out,
                                ulong * raw_sz_out,
                                uchar hash_out[32] );

int at_store_get_top_block_header( at_store_t * store,
                                   at_block_header_t * header_out,
                                   uchar hash_out[32] );

/* ==========================================================================
   Tips Provider
   ==========================================================================
*/

int at_store_get_tips( at_store_t * store,
                       at_dag_tips_t * tips_out );

int at_store_set_tips( at_store_t * store,
                       at_dag_tips_t const * tips );

/* ==========================================================================
   Snapshot Provider (in-memory commit point)
   ==========================================================================
*/

int at_store_has_snapshot( at_store_t * store,
                           int * has_snapshot_out );

int at_store_start_snapshot( at_store_t * store );

int at_store_end_snapshot( at_store_t * store,
                           int apply );

int at_store_swap_snapshot( at_store_t * store,
                            void * other_snapshot,
                            void ** prev_snapshot_out );

/* Internal snapshot overlay hooks used by dispatch layer.
   These mirror TOS RocksStorage behavior where snapshot writes/read overlay
   intercept normal put/get/delete/exists paths while snapshot is active. */
int at_store_snapshot_overlay_put( at_store_t * store,
                                   at_cf_t cf,
                                   void const * key,
                                   ulong key_sz,
                                   void const * val,
                                   ulong val_sz,
                                   int * handled_out );

int at_store_snapshot_overlay_delete( at_store_t * store,
                                      at_cf_t cf,
                                      void const * key,
                                      ulong key_sz,
                                      int * handled_out );

int at_store_snapshot_overlay_get( at_store_t * store,
                                   at_cf_t cf,
                                   void const * key,
                                   ulong key_sz,
                                   at_store_snapshot_entry_state_t * state_out,
                                   at_store_bytes_view_t * value_out );

void at_store_snapshot_destroy_detached( at_store_t * store,
                                         void * snapshot );

/* ==========================================================================
   Network Provider
   ==========================================================================
*/

int at_store_get_network( at_store_t * store,
                          at_network_t * network_out,
                          int * found_out );

int at_store_set_network( at_store_t * store,
                          at_network_t network );

int at_store_has_network( at_store_t * store,
                          int * found_out );

int at_store_is_mainnet( at_store_t * store,
                         int * is_mainnet_out );

/* ==========================================================================
   Nonce Provider
   ==========================================================================
*/

int at_store_has_nonce( at_store_t * store,
                        uchar const pubkey[32],
                        int * found_out );

int at_store_has_nonce_at_exact_topoheight( at_store_t * store,
                                            uchar const pubkey[32],
                                            ulong topoheight,
                                            int * found_out );

int at_store_get_last_topoheight_for_nonce( at_store_t * store,
                                            uchar const pubkey[32],
                                            ulong * topo_out );

int at_store_get_nonce_at_exact_topoheight( at_store_t * store,
                                            uchar const pubkey[32],
                                            ulong topoheight,
                                            at_versioned_nonce_t * nonce_out );

int at_store_get_last_nonce( at_store_t * store,
                             uchar const pubkey[32],
                             ulong * topo_out,
                             at_versioned_nonce_t * nonce_out );

int at_store_get_nonce_at_maximum_topoheight( at_store_t * store,
                                              uchar const pubkey[32],
                                              ulong maximum_topoheight,
                                              ulong * topo_out,
                                              at_versioned_nonce_t * nonce_out,
                                              int * found_out );

int at_store_set_last_nonce_to( at_store_t * store,
                                uchar const pubkey[32],
                                ulong topoheight,
                                at_versioned_nonce_t const * nonce );

/* ==========================================================================
   Pruned Topoheight Provider
   ==========================================================================
*/

int at_store_get_pruned_topoheight( at_store_t * store,
                                    ulong * topo_out,
                                    int * found_out );

int at_store_set_pruned_topoheight( at_store_t * store,
                                    int has_value,
                                    ulong topoheight );

/* ==========================================================================
   Versioned Nonce Provider
   ==========================================================================
*/

int at_store_delete_versioned_nonces_at_topoheight( at_store_t * store,
                                                    ulong topoheight );

int at_store_delete_versioned_nonces_above_topoheight( at_store_t * store,
                                                       ulong topoheight );

int at_store_delete_versioned_nonces_below_topoheight( at_store_t * store,
                                                       ulong topoheight,
                                                       int keep_last );

/* ==========================================================================
   Versioned Asset/Balance Providers
   ==========================================================================
*/

int at_store_delete_versioned_balances_at_topoheight( at_store_t * store,
                                                      ulong topoheight );

int at_store_delete_versioned_balances_above_topoheight( at_store_t * store,
                                                         ulong topoheight );

int at_store_delete_versioned_balances_below_topoheight( at_store_t * store,
                                                         ulong topoheight,
                                                         int keep_last );

int at_store_delete_versioned_assets_at_topoheight( at_store_t * store,
                                                    ulong topoheight );

int at_store_delete_versioned_assets_above_topoheight( at_store_t * store,
                                                       ulong topoheight );

int at_store_delete_versioned_assets_below_topoheight( at_store_t * store,
                                                       ulong topoheight,
                                                       int keep_last );

int at_store_delete_versioned_assets_supply_at_topoheight( at_store_t * store,
                                                           ulong topoheight );

int at_store_delete_versioned_assets_supply_above_topoheight( at_store_t * store,
                                                              ulong topoheight );

int at_store_delete_versioned_assets_supply_below_topoheight( at_store_t * store,
                                                              ulong topoheight,
                                                              int keep_last );

AT_PROTOTYPES_END

#endif /* HEADER_at_store_providers_h */
