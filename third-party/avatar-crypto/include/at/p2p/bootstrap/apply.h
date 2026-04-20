#ifndef HEADER_at_waltz_p2p_bootstrap_apply_h
#define HEADER_at_waltz_p2p_bootstrap_apply_h

/* at_bootstrap_apply.h - Bootstrap Data Apply for Avatar (TOS Parity)

   This module applies bootstrap responses from TOS peers to local RocksDB
   storage, enabling fast-sync functionality.

   Usage:
     at_bootstrap_apply_ctx_t ctx;
     int rc = at_bootstrap_apply_init( &ctx, rocks );
     if( rc != AT_BOOTSTRAP_APPLY_OK ) return rc;

     // Apply chain info response
     rc = at_bootstrap_apply_chain_info( &ctx, &resp );

     // Apply assets
     rc = at_bootstrap_apply_assets( &ctx, &resp );

     // ... continue with other step types ...

     at_bootstrap_apply_fini( &ctx );

   Thread Safety:
     Single-threaded. Only one thread should call apply functions at a time.
*/

#include "at/core/storage/at_rocks.h"
#include "at/p2p/bootstrap/step.h"
#include "at/infra/spad/at_spad.h"

AT_PROTOTYPES_BEGIN

/* Spad memory size for bootstrap apply (8KB for temporary allocations) */
#define AT_BOOTSTRAP_APPLY_SPAD_MEM_MAX  (8192UL)

/* ============================================================================
   Error Codes
   ============================================================================ */

#define AT_BOOTSTRAP_APPLY_OK            (0)
#define AT_BOOTSTRAP_APPLY_ERR_INVAL    (-1)  /* Invalid argument */
#define AT_BOOTSTRAP_APPLY_ERR_IO       (-2)  /* Storage I/O error */
#define AT_BOOTSTRAP_APPLY_ERR_OVERFLOW (-3)  /* Buffer overflow */
#define AT_BOOTSTRAP_APPLY_ERR_PARSE    (-4)  /* Parse error */
#define AT_BOOTSTRAP_APPLY_ERR_STATE    (-5)  /* Invalid state */
#define AT_BOOTSTRAP_APPLY_ERR_MISMATCH (-6)  /* Data mismatch */

/* ============================================================================
   Apply Context Structure
   ============================================================================ */

/* Progress counters for tracking sync state */
typedef struct at_bootstrap_apply_progress {
  ulong assets_applied;           /* Total assets stored */
  ulong assets_supply_applied;    /* Total asset supply records stored */
  ulong keys_applied;             /* Total public keys stored */
  ulong key_balances_applied;     /* Total key balance entries stored */
  ulong spendable_balances_applied; /* Total spendable balance entries stored */
  ulong accounts_applied;         /* Total account entries stored */
  ulong contracts_applied;        /* Total contracts stored */
  ulong contract_modules_applied; /* Total contract modules stored */
  ulong contract_balances_applied; /* Total contract balance entries stored */
  ulong contract_stores_applied;  /* Total contract store entries stored */
  ulong contract_executions_applied; /* Total scheduled executions stored */
  ulong blocks_metadata_applied;  /* Total block metadata entries stored */
} at_bootstrap_apply_progress_t;

/* Bootstrap apply context */
typedef struct at_bootstrap_apply_ctx {
  at_rocks_t *      rocks;              /* RocksDB handle (not owned) */
  at_spad_t *       spad;               /* Scratch pad for temporary allocations */

  /* Target chain state */
  ulong             target_topoheight;  /* Sync target topoheight */
  ulong             stable_topoheight;  /* Stable topoheight from peer */
  uchar             top_hash[32];       /* Top block hash from peer */

  /* Common point tracking */
  int               has_common_point;   /* 1 if we found common point with peer */
  uchar             common_hash[32];    /* Common point block hash */
  ulong             common_topoheight;  /* Common point topoheight */

  /* Current request state (for pagination) */
  ulong             current_min_topo;   /* Current min topoheight for paginated requests */
  ulong             current_max_topo;   /* Current max topoheight for paginated requests */
  uchar             current_key[32];    /* Current key for key_balances pagination */
  uchar             current_asset[32];  /* Current asset for spendable_balances */
  uchar             current_contract[32]; /* Current contract for contract_* pagination */
  ulong             current_page;       /* Current page number (0 = first page) */
  int               has_more_pages;     /* 1 if more pages expected */

  /* Progress tracking */
  at_bootstrap_apply_progress_t progress;

  /* Batch write buffer for atomic operations */
  at_rocks_batch_t * batch;             /* Current batch (NULL when not in use) */
  ulong              batch_count;       /* Items in current batch */
  ulong              batch_max;         /* Max items before commit (default: 1000) */

  /* Error state */
  int               last_error;         /* Last error code */
  char              error_msg[256];     /* Last error message */
} at_bootstrap_apply_ctx_t;

/* ============================================================================
   Lifecycle Functions
   ============================================================================ */

/* Initialize bootstrap apply context.
   rocks: RocksDB handle (must remain valid for lifetime of context)
   Returns AT_BOOTSTRAP_APPLY_OK on success. */
int
at_bootstrap_apply_init( at_bootstrap_apply_ctx_t * ctx,
                         at_rocks_t *               rocks );

/* Finalize bootstrap apply context.
   Commits any pending batch and releases resources. */
void
at_bootstrap_apply_fini( at_bootstrap_apply_ctx_t * ctx );

/* Reset context for a new sync session.
   Clears progress and pagination state but keeps rocks handle. */
void
at_bootstrap_apply_reset( at_bootstrap_apply_ctx_t * ctx );

/* ============================================================================
   Chain Info Apply
   ============================================================================ */

/* Apply chain info response.
   Sets target topoheight, stable height, top hash, and common point.
   This should be called first before other apply functions. */
int
at_bootstrap_apply_chain_info( at_bootstrap_apply_ctx_t *                ctx,
                               at_bootstrap_step_resp_t const *          resp );

/* ============================================================================
   Asset Apply Functions
   ============================================================================ */

/* Apply assets response.
   Stores asset definitions in AT_CF_VERSIONED_ASSETS.
   Wire format: decimals(1) + name_len(1) + name(*) + ticker_len(1) + ticker(*) +
                max_supply(Option<u64>) + owner(Option<contract(32)+id(8)>) */
int
at_bootstrap_apply_assets( at_bootstrap_apply_ctx_t *       ctx,
                           at_bootstrap_step_resp_t const * resp );

/* Apply assets supply response.
   Stores asset supply tracking in AT_CF_VERSIONED_ASSETS_SUPPLY.
   Called after all assets are synced for supply tracking. */
int
at_bootstrap_apply_assets_supply( at_bootstrap_apply_ctx_t *       ctx,
                                  at_bootstrap_step_resp_t const * resp,
                                  uchar const (*                   asset_hashes)[32],
                                  ushort                           asset_count );

/* ============================================================================
   Key/Account Apply Functions
   ============================================================================ */

/* Apply keys response.
   Stores public keys discovered during sync.
   Creates account entries in AT_CF_ACCOUNT if not exists. */
int
at_bootstrap_apply_keys( at_bootstrap_apply_ctx_t *       ctx,
                         at_bootstrap_step_resp_t const * resp );

/* Apply key balances response.
   Stores balance pointers in AT_CF_BALANCES for a specific key.
   Must be called after at_bootstrap_apply_keys for the key. */
int
at_bootstrap_apply_key_balances( at_bootstrap_apply_ctx_t *       ctx,
                                 at_bootstrap_step_resp_t const * resp,
                                 uchar const                      key[32] );

/* Apply spendable balances response.
   Stores versioned balances in AT_CF_VERSIONED_BALANCES.
   Called for each key+asset pair to sync full balance history. */
int
at_bootstrap_apply_spendable_balances( at_bootstrap_apply_ctx_t *       ctx,
                                       at_bootstrap_step_resp_t const * resp,
                                       uchar const                      key[32],
                                       uchar const                      asset[32] );

/* Apply accounts response.
   Stores nonce and multisig state in AT_CF_VERSIONED_NONCES and
   AT_CF_VERSIONED_MULTISIG for a batch of keys. */
int
at_bootstrap_apply_accounts( at_bootstrap_apply_ctx_t *       ctx,
                             at_bootstrap_step_resp_t const * resp,
                             uchar const (*                   keys)[32],
                             ushort                           key_count );

/* ============================================================================
   Contract Apply Functions
   ============================================================================ */

/* Apply contracts list response.
   Stores contract addresses in AT_CF_CONTRACTS. */
int
at_bootstrap_apply_contracts( at_bootstrap_apply_ctx_t *       ctx,
                              at_bootstrap_step_resp_t const * resp );

/* Apply contract module response.
   Stores WASM module in AT_CF_VERSIONED_CONTRACTS.
   state_tag: 0=Clean, 1=Some(module), 2=None, 3=Deleted */
int
at_bootstrap_apply_contract_module( at_bootstrap_apply_ctx_t *       ctx,
                                    at_bootstrap_step_resp_t const * resp,
                                    uchar const                      contract[32] );

/* Apply contract balances response.
   Stores contract asset balances in AT_CF_CONTRACTS_BALANCES. */
int
at_bootstrap_apply_contract_balances( at_bootstrap_apply_ctx_t *       ctx,
                                      at_bootstrap_step_resp_t const * resp,
                                      uchar const                      contract[32],
                                      ulong                            topoheight );

/* Apply contract stores response.
   Stores contract KV data in AT_CF_CONTRACTS_DATA. */
int
at_bootstrap_apply_contract_stores( at_bootstrap_apply_ctx_t *       ctx,
                                    at_bootstrap_step_resp_t const * resp,
                                    uchar const                      contract[32],
                                    ulong                            topoheight );

/* Apply contracts executions response.
   Stores scheduled executions in AT_CF_DELAYED_EXECUTION. */
int
at_bootstrap_apply_contracts_executions( at_bootstrap_apply_ctx_t *       ctx,
                                         at_bootstrap_step_resp_t const * resp );

/* ============================================================================
   Blocks Metadata Apply
   ============================================================================ */

/* Apply blocks metadata response.
   Stores block metadata in AT_CF_BLOCKS, AT_CF_TOPO_BY_HASH,
   AT_CF_HASH_AT_TOPO, and AT_CF_BLOCK_DIFFICULTY. */
int
at_bootstrap_apply_blocks_metadata( at_bootstrap_apply_ctx_t *       ctx,
                                    at_bootstrap_step_resp_t const * resp,
                                    ulong                            start_topoheight );

/* ============================================================================
   Batch Management
   ============================================================================ */

/* Start a new batch for atomic writes.
   Called automatically by apply functions if no batch is active. */
int
at_bootstrap_apply_batch_begin( at_bootstrap_apply_ctx_t * ctx );

/* Commit current batch.
   Called automatically when batch_count reaches batch_max.
   Can also be called manually to force commit. */
int
at_bootstrap_apply_batch_commit( at_bootstrap_apply_ctx_t * ctx );

/* Abort current batch without committing.
   Discards all pending writes in the batch. */
void
at_bootstrap_apply_batch_abort( at_bootstrap_apply_ctx_t * ctx );

/* Set maximum batch size before auto-commit.
   Default is 1000 items. */
void
at_bootstrap_apply_set_batch_max( at_bootstrap_apply_ctx_t * ctx,
                                  ulong                      batch_max );

/* ============================================================================
   Progress and Status
   ============================================================================ */

/* Get current progress counters. */
at_bootstrap_apply_progress_t const *
at_bootstrap_apply_get_progress( at_bootstrap_apply_ctx_t const * ctx );

/* Get last error message. */
char const *
at_bootstrap_apply_get_error( at_bootstrap_apply_ctx_t const * ctx );

/* Check if context is ready for apply operations.
   Returns 1 if ready, 0 if not initialized or in error state. */
int
at_bootstrap_apply_is_ready( at_bootstrap_apply_ctx_t const * ctx );

/* Check if there are more pages to fetch for current step.
   Returns 1 if more pages expected, 0 if done. */
int
at_bootstrap_apply_has_more_pages( at_bootstrap_apply_ctx_t const * ctx );

/* Get next page number to request.
   Returns 0 if no pagination or done with pages. */
ulong
at_bootstrap_apply_get_next_page( at_bootstrap_apply_ctx_t const * ctx );

/* ============================================================================
   Utility Functions
   ============================================================================ */

/* Verify that all expected data was applied.
   Checks progress counters against expected totals.
   Returns AT_BOOTSTRAP_APPLY_OK if complete, error otherwise. */
int
at_bootstrap_apply_verify_complete( at_bootstrap_apply_ctx_t const * ctx,
                                    ulong                            expected_assets,
                                    ulong                            expected_keys,
                                    ulong                            expected_contracts,
                                    ulong                            expected_blocks );

/* Update common metadata after sync completion.
   Sets TIPS, TOPO, TOPH in AT_CF_COMMON. */
int
at_bootstrap_apply_finalize_metadata( at_bootstrap_apply_ctx_t * ctx );

AT_PROTOTYPES_END

#endif /* HEADER_at_waltz_p2p_bootstrap_apply_h */
