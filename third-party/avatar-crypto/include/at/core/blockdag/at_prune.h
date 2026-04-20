#ifndef HEADER_at_blockdag_at_prune_h
#define HEADER_at_blockdag_at_prune_h

/* at_prune.h - Chain pruning for TOS-compatible storage management

   Implements pruning of old block/transaction/versioned data to bound
   storage growth. The algorithm identifies "sync blocks" (stable,
   irreversible blocks) and deletes everything below them while
   maintaining a safety margin of AT_PRUNE_SAFETY_LIMIT (240) blocks.

   TOS Rust reference: core/storage/rocksdb/mod.rs
     - prune_until_topoheight_for_storage()
     - is_sync_block_at_height()
     - delete_block_at_topoheight()
     - delete_versioned_data_below_topoheight() */

#include "at/infra/at_util_base.h"
#include "at/core/blockdag/at_dag_config.h"
#include "at/core/blockdag/at_blockdag.h"
#include "at/core/storage/at_store.h"

AT_PROTOTYPES_BEGIN

/* ============================================================================
   Error Codes
   ============================================================================ */

#ifndef AT_PRUNE_OK
#define AT_PRUNE_OK                     (0)
#define AT_PRUNE_ERR_GENESIS            (-1)  /* Cannot prune genesis */
#define AT_PRUNE_ERR_ABOVE_CURRENT      (-2)  /* Target >= current topo */
#define AT_PRUNE_ERR_SAFETY_LIMIT       (-3)  /* Within safety limit of tip */
#define AT_PRUNE_ERR_BELOW_PRUNED       (-4)  /* Target < already pruned */
#define AT_PRUNE_ERR_NO_SYNC_BLOCK      (-5)  /* No sync block found */
#define AT_PRUNE_ERR_STORE              (-6)  /* Storage operation failed */
#endif
#define AT_PRUNE_ERR_INVAL              (-7)  /* Invalid argument (prune.h only) */

/* Maximum batch size before intermediate commit (bound memory usage) */
#define AT_PRUNE_BATCH_SIZE             (1000UL)

/* ============================================================================
   Pruned Topoheight Marker
   ============================================================================ */

/* Read the pruned topoheight from AT_CF_COMMON["PRUN"].
   Returns 0 if not set (no pruning has occurred). */
at_topoheight_t
at_prune_get_pruned_topoheight( at_store_t * store );

/* Write the pruned topoheight marker to a batch. */
int
at_prune_set_pruned_topoheight( struct at_store        * store,
                                struct at_store_batch  * batch,
                                at_topoheight_t          topo );

/* ============================================================================
   Sync Block Detection
   ============================================================================ */

/* Check if a block is a "sync block" suitable as a pruning boundary.
   A sync block is:
   - Genesis (height == 0), OR
   - An ordered block whose height + STABLE_LIMIT <= current_height AND
     either the only ordered block at its height, or has the highest
     cumulative difficulty among ordered blocks in the preceding
     STABLE_LIMIT heights.

   Returns 1 if sync block, 0 if not, <0 on error. */
int
at_prune_is_sync_block( at_dag_provider_t * dag,
                        struct at_store        * store,
                        uchar const            * hash,
                        ulong                    current_height );

/* Walk down from target_topo to find the nearest sync block.
   Returns AT_PRUNE_OK and writes the sync block's topoheight to *out_topo,
   or AT_PRUNE_ERR_NO_SYNC_BLOCK if none found. */
int
at_prune_locate_nearest_sync_block( at_dag_provider_t * dag,
                                    struct at_store        * store,
                                    at_topoheight_t          target_topo,
                                    ulong                    current_height,
                                    at_topoheight_t        * out_topo );

/* ============================================================================
   Block Deletion
   ============================================================================ */

/* Delete all data associated with the block at the given topoheight.
   Cleans: AT_CF_HASH_AT_TOPO, AT_CF_TOPO_BY_HASH, AT_CF_BLOCKS,
           AT_CF_BLOCKS_EXECUTION_ORDER, AT_CF_BLOCK_DIFFICULTY,
           AT_CF_TOPO_HEIGHT_METADATA, AT_CF_BLOCKS_AT_HEIGHT (remove hash),
           AT_CF_TRANSACTION_IN_BLOCKS, AT_CF_TRANSACTIONS (if orphaned),
           AT_CF_TRANSACTIONS_EXECUTED, AT_CF_TRANSACTIONS_OUTPUTS,
           AT_CF_ESCROW_HISTORY */
int
at_prune_delete_block_at_topoheight( at_dag_provider_t * dag,
                                     struct at_store        * store,
                                     struct at_store_batch  * batch,
                                     at_topoheight_t          topo );

/* ============================================================================
   Versioned Data Deletion
   ============================================================================ */

/* Delete versioned data entries below the given topoheight.
   Iterates through all versioned CFs and removes entries whose
   8-byte BE topoheight key prefix is below the threshold.
   If keep_last is true, keeps the most recent entry per key even
   if its topoheight is below the threshold. */
int
at_prune_delete_versioned_data( struct at_store       * store,
                                at_store_batch_t * batch,
                                at_topoheight_t         topo,
                                int                     keep_last );

/* ============================================================================
   Main Pruning Entry Points
   ============================================================================ */

/* Prune all chain data below target_topo.
   Validates safety constraints, locates the nearest sync block,
   deletes block data and versioned data, then updates the PRUN marker.
   Idempotent: resumes from the current PRUN marker on restart.

   Returns AT_PRUNE_OK on success, or an error code. */
int
at_prune_until_topoheight( at_dag_provider_t * dag,
                           struct at_store        * store,
                           at_topoheight_t          target_topo );

/* Auto-prune trigger: called after block execution.
   If current_topo is a multiple of keep_only and current_topo > keep_only,
   prunes to (current_topo - keep_only). */
int
at_prune_auto( at_dag_provider_t * dag,
               struct at_store        * store,
               at_topoheight_t          current_topo,
               ulong                    keep_only );

AT_PROTOTYPES_END

#endif /* HEADER_at_blockdag_at_prune_h */
