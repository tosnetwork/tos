#ifndef HEADER_at_tos_at_executor_h
#define HEADER_at_tos_at_executor_h

/* at_executor.h - Transaction execution engine for Avatar

   This module provides transaction and block execution functionality
   using two-phase execution with at_exec_ctx:

   Phase 1 (Execute): Transactions accumulate changes in memory buffers
   Phase 2 (Commit): All changes are atomically written to storage
   Phase 3 (Metadata): Topoheight metadata written after state commit

   This provides proper atomicity and matches TOS Rust architecture:
   1. ChainState.apply_changes() [= at_executor_commit]
   2. Storage.set_topoheight_metadata() [= at_executor_commit_metadata]

   TOS Rust References:
   - daemon/src/core/state/chain_state/apply.rs (apply_changes)
   - daemon/src/core/blockchain.rs (set_topoheight_metadata)
*/

#include "at/transaction/at_txn.h"
#include "at/block/at_block.h"
#include "at/core/storage/at_store.h"
#include "at/account/at_account.h"
#include "at/core/blockdag/at_dag_provider.h"
#include "at/vm/at_vm.h"
#include "at/vm/at_vm_exec_trace.h"

AT_PROTOTYPES_BEGIN

/* ============================================================================
   Execution Error Codes
   ============================================================================ */

#define AT_EXEC_OK                       (0)
#define AT_EXEC_ERR_INVALID_NONCE       (-1)
#define AT_EXEC_ERR_INSUFFICIENT_BALANCE (-2)
#define AT_EXEC_ERR_INSUFFICIENT_ENERGY  (-3)
#define AT_EXEC_ERR_CONTRACT_ERROR      (-4)
#define AT_EXEC_ERR_INVALID_TX          (-5)
#define AT_EXEC_ERR_FEE                 (-6)
#define AT_EXEC_ERR_COMMIT_FAILED       (-7)
#define AT_EXEC_ERR_ROLLBACK_FAILED     (-8)

/* Transaction receipt */
typedef struct {
  uchar  tx_hash[32];
  int    success;
  int    error_code;
  ulong  gas_used;
  ulong  fee_paid;
  uchar  logs[1024];
  ulong  logs_len;
} at_tx_receipt_t;

/* Block receipt (minimal stub) */
typedef struct {
  ulong tx_count;
  ulong success_count;
  ulong fail_count;
} at_block_receipt_t;

/* ============================================================================
   Transaction Receipt
   ============================================================================ */

/* Forward declaration for exec_ctx */
struct at_exec_ctx;

/* ============================================================================
   Executor Context
   ============================================================================ */

/* Executor context - manages transaction/block execution */
typedef struct at_executor {
  at_store_t        * store;          /* Backend storage */
  at_dag_provider_t * dag;            /* DAG provider for topo lookups */
  at_vm_t           * vm;             /* VM for contract execution */
  at_alloc_t        * alloc;          /* Memory allocator */

  /* Current execution context */
  uchar               block_hash[32]; /* Current block hash */
  ulong               topoheight;     /* Current block topoheight */
  ulong               stable_topoheight; /* Stable (finalized) topoheight */
  ulong               timestamp_ms;   /* Block timestamp in ms */
  uchar               miner[32];      /* Block miner public key */

  /* Fee tracking */
  ulong               total_fees;     /* Total fees collected */
  ulong               burned_fees;    /* Total fees burned */

  /* Energy tracking (for global GENR counter) */
  ulong               energy_added;   /* Energy added via freeze in this block */
  ulong               energy_removed; /* Energy removed via unfreeze in this block */

  /* Execution context (always present) */
  struct at_exec_ctx * exec_ctx;      /* Execution context */
} at_executor_t;

/* ============================================================================
   Executor Lifecycle
   ============================================================================ */

/* at_executor_init initializes an executor with buffered execution mode.
   All state changes are accumulated in exec_ctx and committed atomically.
   Returns 0 on success, -1 on failure. */
int
at_executor_init( at_executor_t     * exec,
                  at_store_t        * store,
                  at_dag_provider_t * dag,
                  at_alloc_t        * alloc );

/* at_executor_fini finalizes an executor and frees resources.
   If not committed, performs implicit rollback. */
void
at_executor_fini( at_executor_t * exec );

/* ============================================================================
   Block Context Setup
   ============================================================================ */

/* at_executor_begin_block prepares executor for a new block.
   In buffered mode, this initializes the exec_ctx.
   Returns 0 on success, -1 on failure. */
int
at_executor_begin_block( at_executor_t * exec,
                         ulong           topoheight,
                         ulong           stable_topoheight,
                         ulong           timestamp_ms,
                         uchar const     miner[32],
                         uchar const     block_hash[32] );

/* ============================================================================
   Transaction Execution
   ============================================================================ */

/* at_executor_execute_tx executes a single transaction.
   In legacy mode: Changes written immediately to storage
   In buffered mode: Changes buffered for atomic commit

   Returns AT_EXEC_OK on success, error code on failure. */
int
at_executor_execute_tx( at_executor_t       * exec,
                        at_txn_t const      * txn,
                        uchar const         * raw,
                        at_tx_receipt_t     * receipt );

/* Execute a contract bytecode blob in the VM with explicit kernel context.
   This is shared by regular contract tx execution and scheduled execution. */
int
at_executor_contract_vm_execute( at_executor_t * exec,
                                 uchar const    contract[32],
                                 uchar const *  bytecode,
                                 ulong          bytecode_sz,
                                 uchar const *  input_data,
                                 ulong          input_len,
                                 ulong          max_gas,
                                 uchar const    tx_sender[32],
                                 uchar const    tx_hash[32],
                                 uchar const    block_hash[32],
                                 ulong          block_height,
                                 ulong          block_timestamp_seconds,
                                 ulong *        used_gas_out,
                                 at_vm_exec_trace_t * exec_trace_out );

/* ============================================================================
   Block Execution
   ============================================================================ */

/* at_executor_execute_block executes all transactions in a block.
   This is a convenience function that:
   1. Calls begin_block
   2. Executes all transactions
   3. Processes scheduled executions
   4. Computes and distributes rewards
   5. Commits (in buffered mode)

   Returns AT_EXEC_OK on success, error code on failure. */
int
at_executor_execute_block( at_executor_t         * exec,
                           at_block_t const      * block,
                           at_block_receipt_t    * receipt );

/* ============================================================================
   Commit and Rollback
   ============================================================================ */

/* at_executor_apply_block_reward registers the miner account (if needed) and
   credits it with the block reward in buffered mode.  Must be called after
   at_executor_begin_block() and before at_executor_commit().

   block_reward  — pre-computed reward for this block (0 for pure side blocks)
   block_height  — block height (used for dev-fee schedule)

   TOS Rust equivalent: reward_miner() in blockchain.rs.
   Returns 0 on success, -1 on failure. */
int
at_executor_apply_block_reward( at_executor_t * exec,
                                ulong           block_reward,
                                ulong           block_height );

/* at_executor_commit commits all buffered changes to storage.
   Atomically writes all accumulated state changes.

   Returns 0 on success, AT_EXEC_ERR_COMMIT_FAILED on failure. */
int
at_executor_commit( at_executor_t * exec );

/* at_executor_commit_metadata commits topoheight metadata AFTER state commit.
   This must be called after at_executor_commit() succeeds.
   Matches TOS Rust: apply_changes() then set_topoheight_metadata().

   Writes:
   - Per-topoheight metadata (AT_CF_TOPO_HEIGHT_METADATA)
   - Global supply counters (GSUP/GBUR)
   - Global energy, height, timestamp (GENR/GBLK/GTIM)

   Returns 0 on success, -1 on failure. */
int
at_executor_commit_metadata( at_executor_t * exec,
                             ulong           block_reward,
                             ulong           emitted_supply,
                             ulong           burned_supply,
                             ulong           block_height,
                             ulong           timestamp_ms );

/* at_executor_rollback discards all buffered changes.
   Storage remains unchanged.

   Returns 0 on success. */
int
at_executor_rollback( at_executor_t * exec );

/* ============================================================================
   Auto-Prune Hook
   ============================================================================ */

/* at_executor_maybe_auto_prune triggers automatic pruning if configured.
   Should be called after a successful block execution + commit.
   keep_only: number of topoheights to keep (0 = no auto-prune).
   Returns 0 on success or no-op, negative on error. */
int
at_executor_maybe_auto_prune( at_executor_t * exec,
                               ulong           keep_only );

/* ============================================================================
   UNO (Privacy) Transactions
   ============================================================================ */

/* at_exec_uno executes a UNO privacy transaction.
   Defined in at_uno_exec.c */
int
at_exec_uno( at_executor_t     * exec,
             at_txn_t const    * txn,
             uchar const       * raw );

/* ============================================================================
   Execution Mode Query
   ============================================================================ */

/* at_executor_is_committed returns 1 if changes have been committed. */
int
at_executor_is_committed( at_executor_t const * exec );

/* ============================================================================
   Mode-Aware Account Operations

   These functions route balance/nonce operations based on execution mode:
   - In LEGACY mode: Direct write-through to storage
   - In BUFFERED mode: Buffer changes for atomic commit

   Domain modules (Escrow, KYC) should use these functions instead of
   calling at_account_* directly to ensure proper atomicity.
   ============================================================================ */

/* Check if account exists */
int
at_executor_account_exists( at_executor_t * exec, uchar const pubkey[32] );

/* Get or create account */
int
at_executor_account_get_or_create( at_executor_t * exec, uchar const pubkey[32],
                                   at_account_t * acc_out );

/* Get account balance (native asset) */
int
at_executor_get_balance( at_executor_t * exec, uchar const pubkey[32],
                         ulong * balance_out );

/* Get account balance for specific asset */
int
at_executor_get_balance_asset( at_executor_t * exec, uchar const pubkey[32],
                               uchar const asset[32], ulong * balance_out );

/* Subtract from account balance (native asset).
   reference_topoheight: The topoheight referenced by the transaction (for DAG lookup).
   Returns AT_STORE_OK on success, AT_EXEC_ERR_INSUFFICIENT_BALANCE on underflow. */
int
at_executor_sub_balance( at_executor_t * exec, uchar const pubkey[32],
                         ulong amount, ulong reference_topoheight );

/* Subtract from account balance for specific asset */
int
at_executor_sub_balance_asset( at_executor_t * exec, uchar const pubkey[32],
                               uchar const asset[32], ulong amount,
                               ulong reference_topoheight );

/* Add to account balance (native asset) */
int
at_executor_add_balance( at_executor_t * exec, uchar const pubkey[32],
                         ulong amount );

/* Add to account balance for specific asset */
int
at_executor_add_balance_asset( at_executor_t * exec, uchar const pubkey[32],
                               uchar const asset[32], ulong amount );

/* Get account nonce */
int
at_executor_get_nonce( at_executor_t * exec, uchar const pubkey[32],
                       ulong * nonce_out );

/* Set account nonce */
int
at_executor_set_nonce( at_executor_t * exec, uchar const pubkey[32],
                       ulong nonce );

AT_PROTOTYPES_END

#endif /* HEADER_at_tos_at_executor_h */
