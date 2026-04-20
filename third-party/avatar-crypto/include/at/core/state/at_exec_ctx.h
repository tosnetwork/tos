#ifndef HEADER_at_tos_at_exec_ctx_h
#define HEADER_at_tos_at_exec_ctx_h

/* at_exec_ctx.h - Block Execution Context for Avatar (TOS-Compatible)

   This module implements the TOS Rust ChainState/ApplicableChainState equivalent
   for Avatar. It provides a two-phase execution model:

   1. Execute Phase: Transactions accumulate changes in memory buffers
   2. Commit Phase: All changes are atomically written to storage

   TOS Rust References:
   - daemon/src/core/state/chain_state/mod.rs (ChainState)
   - daemon/src/core/state/chain_state/apply.rs (apply_changes)

   Key Features:
   - In-memory buffering of sender account changes (via Echange)
   - In-memory buffering of receiver balance changes
   - DAG-aware versioned balance lookup (scenarios A/B/C/D)
   - Atomic commit with output balance merging
   - Clean rollback on failure

   Usage:
     at_exec_ctx_t ctx;
     at_exec_ctx_init(&ctx, store, dag, alloc, topoheight, ...);

     // Execute transactions - changes buffered in memory
     at_exec_ctx_execute_tx(&ctx, txn1, raw1, &receipt1);
     at_exec_ctx_execute_tx(&ctx, txn2, raw2, &receipt2);

     // Commit all changes atomically
     if( at_exec_ctx_commit(&ctx) != 0 ) {
       at_exec_ctx_rollback(&ctx);  // Discard all changes
     }

     at_exec_ctx_fini(&ctx);
*/

#include "at/infra/at_util_base.h"
#include "at/infra/alloc/at_alloc.h"
#include "at/core/storage/at_store.h"
#include "at/account/at_account.h"
#include "at/account/at_multisig.h"
#include "at/core/blockdag/at_dag_provider.h"
#include "at/core/state/at_echange.h"
#include "at/transaction/at_txn.h"
#include "at/core/state/at_executor.h"

AT_PROTOTYPES_BEGIN

/* Maximum sender accounts tracked per block */
#define AT_EXEC_CTX_MAX_SENDERS (1024UL)

/* Maximum receiver balance entries per block */
#define AT_EXEC_CTX_MAX_RECEIVERS (4096UL)

/* Maximum in-memory write trace kept in exec_ctx.
   Used by at_exec_ctx_batch_get/exists to observe pending writes before commit. */
#define AT_EXEC_CTX_BATCH_TRACE_MAX_BYTES (1UL << 20)

typedef struct at_exec_ctx_created_account {
  uchar               pubkey[32];
  at_account_t        account;
} at_exec_ctx_created_account_t;

typedef struct at_exec_ctx_multisig_update {
  uchar                     pubkey[32];
  at_versioned_multisig_t   config;
} at_exec_ctx_multisig_update_t;

/* ============================================================================
   Receiver Balance Entry
   ============================================================================ */

/* at_receiver_balance_t tracks a balance addition to a receiver account */
typedef struct at_receiver_balance {
  uchar pubkey[32];              /* Receiver public key */
  uchar asset[32];               /* Asset hash (zeros = native TOS) */
  ulong amount;                  /* Amount to add */
  ulong previous_topoheight;     /* Previous version's topoheight */
  int   has_previous_topoheight; /* Whether previous_topoheight is valid */
  int   is_new_account;          /* Whether this is a newly registered account */
} at_receiver_balance_t;

/* ============================================================================
   Execution Context
   ============================================================================ */

/* at_exec_ctx_t holds all state for block execution.
   This is the C equivalent of TOS Rust's ApplicableChainState. */
typedef struct at_exec_ctx {
  /* Storage references */
  at_store_t        * store;              /* Backend storage */
  at_dag_provider_t * dag;                /* DAG provider for topo lookups */
  at_alloc_t        * alloc;              /* Memory allocator */

  /* Block context */
  uchar               block_hash[32];     /* Current block hash */
  ulong               topoheight;         /* Current block topoheight */
  ulong               stable_topoheight;  /* Stable (finalized) topoheight */
  ulong               timestamp_ms;       /* Block timestamp in ms */
  uchar               miner[32];          /* Block miner public key */

  /* Sender account changes (Echange buffers) */
  at_account_echange_t * senders;         /* Array of sender echanges */
  ulong                  senders_cnt;     /* Number of active senders */
  ulong                  senders_cap;     /* Capacity of senders array */

  /* Receiver balance additions */
  at_receiver_balance_t * receivers;      /* Array of receiver balances */
  ulong                   receivers_cnt;  /* Number of active receivers */
  ulong                   receivers_cap;  /* Capacity of receivers array */

  /* Fee tracking */
  ulong               total_fees;         /* Total fees collected */
  ulong               burned_fees;        /* Total fees burned */
  ulong               gas_fee;            /* Gas fees from contracts */

  /* Unified execution batch for all execution-time writes.
     This batch remains open during block execution and is committed atomically
     together with buffered balance/nonce writes in at_exec_ctx_commit_impl(). */
  at_store_batch_t   * write_batch;
  uchar              * write_batch_trace_blob;
  ulong               write_batch_trace_len;
  ulong               write_batch_trace_cap;

  /* Batch-created account cache for block-local account IDs.
   * These entries avoid duplicate NEXT_ACCOUNT_ID reads while creating
   * multiple new accounts in the same execution batch.
   */
  at_exec_ctx_created_account_t * created_accounts;
  ulong               created_accounts_cnt;
  ulong               created_accounts_cap;
  ulong               created_next_account_id;
  int                 created_next_account_id_initialized;

  at_exec_ctx_multisig_update_t * multisig_updates;
  ulong               multisig_updates_cnt;
  ulong               multisig_updates_cap;

  /* State flags */
  int                 initialized;        /* Whether context is initialized */
  int                 committed;          /* Whether commit was called */

  /* Legacy executor reference (for gradual migration) */
  at_executor_t     * legacy_exec;        /* Optional legacy executor */
} at_exec_ctx_t;

/* ============================================================================
   Context Lifecycle
   ============================================================================ */

/* at_exec_ctx_footprint returns the memory footprint for an execution context.
   This is used for workspace allocation. */
ulong at_exec_ctx_footprint( void );

/* at_exec_ctx_align returns the alignment requirement for an execution context. */
ulong at_exec_ctx_align( void );

/* at_exec_ctx_new allocates a new execution context from an allocator.
   Returns pointer to context, or NULL on failure. */
at_exec_ctx_t *
at_exec_ctx_new( at_alloc_t * alloc );

/* at_exec_ctx_delete frees an execution context.
   Must call at_exec_ctx_fini first if initialized. */
void
at_exec_ctx_delete( at_exec_ctx_t * ctx );

/* at_exec_ctx_init initializes an execution context for a block.
   Returns 0 on success, -1 on failure. */
int
at_exec_ctx_init( at_exec_ctx_t     * ctx,
                  at_store_t        * store,
                  at_dag_provider_t * dag,
                  at_alloc_t        * alloc,
                  ulong               topoheight,
                  ulong               stable_topoheight,
                  ulong               timestamp_ms,
                  uchar const         miner[32],
                  uchar const         block_hash[32] );

/* at_exec_ctx_fini finalizes an execution context.
   If not committed, performs implicit rollback.
   Returns 0 on success. */
int
at_exec_ctx_fini( at_exec_ctx_t * ctx );

/* ============================================================================
   Sender Account Management
   ============================================================================ */

/* at_exec_ctx_get_sender finds or creates a sender account entry.
   Returns pointer to account echange, or NULL if full/error. */
at_account_echange_t *
at_exec_ctx_get_sender( at_exec_ctx_t * ctx,
                        uchar const     pubkey[32],
                        int             create );

/* at_exec_ctx_get_sender_balance gets the current balance for a sender.
   Handles DAG-aware versioned balance lookup (scenarios A/B/C/D).

   reference_topoheight: The topoheight referenced by the transaction
   reference_hash: The block hash referenced by the transaction (may be NULL)

   Returns: 0 on success, -1 on error */
int
at_exec_ctx_get_sender_balance( at_exec_ctx_t * ctx,
                                uchar const     pubkey[32],
                                uchar const     asset[32],
                                ulong           reference_topoheight,
                                uchar const     reference_hash[32],
                                ulong         * balance_out );

/* at_exec_ctx_sub_sender_balance subtracts from sender's balance.
   Updates the echange output tracking.

   reference_topoheight: The topoheight referenced by the transaction.
                         This is used for DAG-aware balance lookup (Scenarios B/C/D).

   Returns: 0 on success, AT_EXEC_ERR_INSUFFICIENT_BALANCE on underflow */
int
at_exec_ctx_sub_sender_balance( at_exec_ctx_t * ctx,
                                uchar const     pubkey[32],
                                uchar const     asset[32],
                                ulong           amount,
                                ulong           reference_topoheight );

/* at_exec_ctx_set_sender_nonce sets the sender's nonce.
   Returns: 0 on success */
int
at_exec_ctx_set_sender_nonce( at_exec_ctx_t * ctx,
                              uchar const     pubkey[32],
                              ulong           nonce );

/* at_exec_ctx_set_multisig registers multisig configuration updates for the current
   block commit. Updates are replayed into the current DB batch during commit to
   preserve atomicity and avoid direct store writes during execution.

   Returns 0 on success, -1 on failure. */
int
at_exec_ctx_set_multisig( at_exec_ctx_t * ctx,
                          uchar const     pubkey[32],
                          at_versioned_multisig_t const * config );

/* ============================================================================
   Receiver Balance Management
   ============================================================================ */

/* at_exec_ctx_add_receiver_balance adds balance to a receiver account.
   Buffers the change for atomic commit.
   Returns: 0 on success, -1 if buffer full */
int
at_exec_ctx_add_receiver_balance( at_exec_ctx_t * ctx,
                                  uchar const     pubkey[32],
                                  uchar const     asset[32],
                                  ulong           amount );

/* at_exec_ctx_get_receiver_balance gets the pending receiver balance.
   Returns the sum of all pending additions for this account/asset.
   Returns: 0 on success */
int
at_exec_ctx_get_receiver_balance( at_exec_ctx_t * ctx,
                                  uchar const     pubkey[32],
                                  uchar const     asset[32],
                                  ulong         * balance_out );

/* ============================================================================
   Transaction Execution
   ============================================================================ */

/* at_exec_ctx_execute_tx executes a single transaction.
   Changes are buffered in memory; call commit to persist.

   Returns: AT_EXEC_OK on success, error code on failure */
int
at_exec_ctx_execute_tx( at_exec_ctx_t       * ctx,
                        at_txn_t const      * txn,
                        uchar const         * raw,
                        at_tx_receipt_t     * receipt );

/* ============================================================================
   Commit and Rollback
   ============================================================================ */

/* at_exec_ctx_commit atomically commits all buffered changes to storage.

   This performs:
   1. Prepare all sender echanges (subtract output_sum)
   2. Merge sender/receiver balances where account has both
   3. Write all versioned balances to storage
   4. Write all versioned nonces to storage
   5. Update balance/nonce pointers

   Returns: 0 on success, -1 on failure (storage remains unchanged on failure) */
  int
at_exec_ctx_commit( at_exec_ctx_t * ctx );

/* at_exec_ctx_rollback discards all buffered changes.
   The storage remains unchanged.
   Returns: 0 on success */
int
at_exec_ctx_rollback( at_exec_ctx_t * ctx );

/* Get/create the unified execution batch for the current block.
   The batch remains owned by exec_ctx. */
at_store_batch_t *
at_exec_ctx_write_batch( at_exec_ctx_t * ctx );

/* Queue a KV write into the unified execution batch. */
int
at_exec_ctx_batch_put( at_exec_ctx_t * ctx,
                       at_cf_t          cf,
                       void const *     key,
                       ulong            key_sz,
                       void const *     val,
                       ulong            val_sz );

/* Queue a KV delete into the unified execution batch. */
int
at_exec_ctx_batch_delete( at_exec_ctx_t * ctx,
                          at_cf_t          cf,
                          void const *     key,
                          ulong            key_sz );

/* Read the latest pending value for (cf,key) from current block batch.
   Returns:
     AT_STORE_OK            if a pending PUT exists (value copied to val/val_sz)
     AT_STORE_ERR_NOT_FOUND if not present in batch or last op is DELETE
     AT_STORE_ERR_FULL      if val buffer is too small (val_sz updated) */
int
at_exec_ctx_batch_get( at_exec_ctx_t * ctx,
                       at_cf_t          cf,
                       void const *     key,
                       ulong            key_sz,
                       void *           val,
                       ulong *          val_sz );

/* Check pending existence for (cf,key) in current block batch.
   Returns 1 if pending PUT exists, 0 if absent/deleted, -1 on error. */
int
at_exec_ctx_batch_exists( at_exec_ctx_t * ctx,
                          at_cf_t          cf,
                          void const *     key,
                          ulong            key_sz );

/* ============================================================================
   Balance Search - DAG Aware (Scenarios A/B/C/D)
   ============================================================================ */

/* at_exec_ctx_search_balance searches for the correct balance to use.

   This implements TOS Rust's versioned balance search logic from
   state/mod.rs:86-277, handling these scenarios:

   Scenario A: TX references topo 1000, current topo 1001
               -> Use final balance (simple case)

   Scenario B: TX references topo 1000, current topo 1005, received funds at 1003
               -> Use topo 1000's final balance (ignore 1003 input)

   Scenario C: TX A references topo 1000, current topo 1005, TX B sent at 1001
               -> Use TX B's output balance

   Scenario D: TX references topo 1000, current topo 1005,
               TX B sent at 1003, TX C sent at 1004
               -> Use most recent output balance

   Parameters:
   - ctx: Execution context
   - pubkey: Account public key
   - asset: Asset hash (zeros = native)
   - reference_topoheight: Topoheight referenced by the transaction
   - reference_hash: Block hash referenced (may be NULL)
   - use_output_balance_out: Set to 1 if output balance should be used
   - new_version_out: Set to 1 if this is a new version at current topo
   - balance_out: The balance value to use
   - prev_topo_out: Previous version's topoheight

   Returns: 0 on success, -1 on error */
int
at_exec_ctx_search_balance( at_exec_ctx_t * ctx,
                            uchar const     pubkey[32],
                            uchar const     asset[32],
                            ulong           reference_topoheight,
                            uchar const     reference_hash[32],
                            int           * use_output_balance_out,
                            int           * new_version_out,
                            ulong         * balance_out,
                            ulong         * prev_topo_out );

/* at_exec_ctx_get_output_balance_in_range searches for output balance in a range.

   This is used for scenario C/D: finding the most recent output balance
   between reference_topoheight and current_topoheight.

   Returns: 0 on success (found), 1 if not found, -1 on error */
int
at_exec_ctx_get_output_balance_in_range( at_exec_ctx_t * ctx,
                                         uchar const     pubkey[32],
                                         uchar const     asset[32],
                                         ulong           start_topo,
                                         ulong           end_topo,
                                         ulong         * balance_out,
                                         ulong         * found_topo_out );

/* ============================================================================
   Fee Tracking
   ============================================================================ */

/* at_exec_ctx_add_fee adds to the total fees collected */
static inline void
at_exec_ctx_add_fee( at_exec_ctx_t * ctx, ulong fee ) {
  if( AT_UNLIKELY( !ctx ) ) return;
  if( ctx->total_fees > ULONG_MAX - fee ) {
    ctx->total_fees = ULONG_MAX;
  } else {
    ctx->total_fees += fee;
  }
}

/* at_exec_ctx_add_burned_fee adds to the burned fees */
static inline void
at_exec_ctx_add_burned_fee( at_exec_ctx_t * ctx, ulong fee ) {
  if( AT_UNLIKELY( !ctx ) ) return;
  if( ctx->burned_fees > ULONG_MAX - fee ) {
    ctx->burned_fees = ULONG_MAX;
  } else {
    ctx->burned_fees += fee;
  }
}

/* ============================================================================
   Buffered Account Operations
   These functions provide the same interface as at_account_* but buffer
   changes in the exec_ctx instead of writing directly to storage.
   ============================================================================ */

/* at_exec_ctx_account_exists checks if account exists (reads from storage).
   This is a read-only operation, so it's the same in both modes. */
int
at_exec_ctx_account_exists( at_exec_ctx_t * ctx,
                            uchar const     pubkey[32] );

/* at_exec_ctx_account_get_or_create ensures account exists.
   In buffered mode, marks new accounts for creation at commit time.
   Returns 0 on success. */
int
at_exec_ctx_account_get_or_create( at_exec_ctx_t * ctx,
                                   uchar const     pubkey[32] );

/* at_exec_ctx_get_balance gets the effective balance for an account.
   Considers both storage balance and pending changes in the buffer.
   Returns 0 on success. */
int
at_exec_ctx_get_balance( at_exec_ctx_t * ctx,
                         uchar const     pubkey[32],
                         ulong         * balance_out );

/* at_exec_ctx_get_balance_asset gets balance for a specific asset. */
int
at_exec_ctx_get_balance_asset( at_exec_ctx_t * ctx,
                               uchar const     pubkey[32],
                               uchar const     asset[32],
                               ulong         * balance_out );

/* at_exec_ctx_sub_balance subtracts from account balance (buffered).
   reference_topoheight: The topoheight referenced by the transaction (for DAG lookup).
   Returns 0 on success, AT_EXEC_ERR_INSUFFICIENT_BALANCE on underflow. */
int
at_exec_ctx_sub_balance( at_exec_ctx_t * ctx,
                         uchar const     pubkey[32],
                         ulong           amount,
                         ulong           reference_topoheight );

/* at_exec_ctx_sub_balance_asset subtracts from account's asset balance.
   reference_topoheight: The topoheight referenced by the transaction (for DAG lookup). */
int
at_exec_ctx_sub_balance_asset( at_exec_ctx_t * ctx,
                               uchar const     pubkey[32],
                               uchar const     asset[32],
                               ulong           amount,
                               ulong           reference_topoheight );

/* at_exec_ctx_add_balance adds to account balance (buffered). */
int
at_exec_ctx_add_balance( at_exec_ctx_t * ctx,
                         uchar const     pubkey[32],
                         ulong           amount );

/* at_exec_ctx_add_balance_asset adds to account's asset balance. */
int
at_exec_ctx_add_balance_asset( at_exec_ctx_t * ctx,
                               uchar const     pubkey[32],
                               uchar const     asset[32],
                               ulong           amount );

/* at_exec_ctx_get_nonce gets the current nonce for an account.
   Considers pending nonce changes in the buffer. */
int
at_exec_ctx_get_nonce( at_exec_ctx_t * ctx,
                       uchar const     pubkey[32],
                       ulong         * nonce_out );

/* at_exec_ctx_set_nonce sets the nonce for an account (buffered). */
int
at_exec_ctx_set_nonce( at_exec_ctx_t * ctx,
                       uchar const     pubkey[32],
                       ulong           nonce );

AT_PROTOTYPES_END

#endif /* HEADER_at_tos_at_exec_ctx_h */
