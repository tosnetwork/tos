#ifndef HEADER_at_scheduled_exec_processor_h
#define HEADER_at_scheduled_exec_processor_h

/* at_scheduled_exec_processor.h - Scheduled execution processor for Avatar

   Processes scheduled contract executions at each topoheight, handling:
   - Priority-based execution ordering (by offer amount)
   - Block gas limits (100M CU per block)
   - Block execution limits (100 executions per block)
   - Deferral on transient failures
   - Expiration after max deferrals
   - Miner reward distribution (70% of offer)

   TOS Alignment: All logic matches TOS Rust scheduled_execution_processor.rs */

#include "at/contract/at_scheduled_exec.h"
#include "at/core/state/at_executor.h"
#include "at/core/storage/at_store.h"

AT_PROTOTYPES_BEGIN

/* ============================================================================
   Processor Configuration
   ============================================================================ */

typedef struct at_sched_exec_config {
  ulong max_executions_per_block;  /* Default: 100 */
  ulong max_gas_per_block;         /* Default: 100M CU */
  ulong min_gas_for_execution;     /* Default: 100000 CU */
} at_sched_exec_config_t;

/* Default configuration matching TOS Rust */
#define AT_SCHED_EXEC_CONFIG_DEFAULT { \
  .max_executions_per_block = AT_MAX_SCHEDULED_EXECUTIONS_PER_BLOCK, \
  .max_gas_per_block = AT_MAX_SCHEDULED_EXECUTION_GAS_PER_BLOCK, \
  .min_gas_for_execution = 100000UL \
}

/* ============================================================================
   Main Processor API
   ============================================================================ */

/* at_process_scheduled_executions - Process all scheduled executions at topoheight

   This is the main entry point called after transaction execution in a block.
   It processes scheduled executions in priority order (highest offer first)
   until either:
   - All executions are processed
   - MAX_EXECUTIONS_PER_BLOCK (100) is reached
   - MAX_GAS_PER_BLOCK (100M CU) is consumed

   Parameters:
     exec          - Executor context with store, topoheight, etc.
     block_hash    - Hash of current block
     block_height  - Height of current block
     block_timestamp - Timestamp of current block (ms)
     results       - Output: aggregate results of all processed executions

   Returns: AT_EXEC_OK on success, error code on failure */
int
at_process_scheduled_executions( at_executor_t *               exec,
                                 uchar const                   block_hash[32],
                                 ulong                         block_height,
                                 ulong                         block_timestamp,
                                 at_block_sched_exec_results_t * results );

/* at_process_scheduled_executions_config - Process with custom configuration */
int
at_process_scheduled_executions_config( at_executor_t *               exec,
                                        uchar const                   block_hash[32],
                                        ulong                         block_height,
                                        ulong                         block_timestamp,
                                        at_sched_exec_config_t const * config,
                                        at_block_sched_exec_results_t * results );

/* ============================================================================
   Storage Operations
   ============================================================================ */

/* Store a new scheduled execution record.
   Called by offer_call syscall after validation. */
int
at_scheduled_exec_store( at_store_t *              store,
                         at_scheduled_exec_full_t const * exec );

/* Load a scheduled execution by contract address and execution hash. */
int
at_scheduled_exec_load( at_store_t *        store,
                        uchar const         contract[32],
                        uchar const         hash[32],
                        at_scheduled_exec_full_t * out );

/* Delete a scheduled execution record.
   Called after execution completes or is cancelled. */
int
at_scheduled_exec_delete( at_store_t * store,
                          uchar const  contract[32],
                          uchar const  hash[32] );

/* Iterate scheduled executions at a topoheight in priority order. */
int
at_scheduled_exec_iter_by_topo( at_store_t *              store,
                                ulong                     topoheight,
                                at_scheduled_exec_iter_t * iter );

/* Get next execution from iterator. Returns 0 when done. */
int
at_scheduled_exec_iter_next( at_scheduled_exec_iter_t * iter,
                             at_scheduled_exec_full_t *      out );

/* Destroy iterator */
void
at_scheduled_exec_iter_destroy( at_scheduled_exec_iter_t * iter );

/* ============================================================================
   Rate Limiting
   ============================================================================ */

/* Check if contract has exceeded rate limit in current window.
   Returns: 0 if under limit, 1 if at/over limit, -1 on error */
int
at_scheduled_exec_rate_limit_check( at_store_t * store,
                                    uchar const  contract[32],
                                    ulong        current_topoheight );

/* Increment rate limit counter for contract.
   Called after successful scheduling. */
int
at_scheduled_exec_rate_limit_incr( at_store_t * store,
                                   uchar const  contract[32],
                                   ulong        current_topoheight );

/* ============================================================================
   Priority Queue Operations
   ============================================================================ */

/* Add execution to priority queue at target topoheight.
   Entries are sorted by offer amount (descending). */
int
at_scheduled_exec_priority_add( at_store_t *              store,
                                ulong                     target_topoheight,
                                ulong                     offer_amount,
                                uchar const               hash[32],
                                uchar const               contract[32] );

/* Remove execution from priority queue. */
int
at_scheduled_exec_priority_remove( at_store_t * store,
                                   ulong        target_topoheight,
                                   ulong        offer_amount,
                                   uchar const  hash[32] );

/* ============================================================================
   Helper Functions
   ============================================================================ */

/* Compute execution hash from parameters (Rust ScheduledExecution::compute_hash parity).
   hash = BLAKE3(contract || kind_tag(+topoheight for TopoHeight) ||
                registration_topoheight || chunk_id_u16 || scheduler_contract) */
void
at_scheduled_exec_compute_hash( uchar                   hash_out[32],
                                uchar const             contract[32],
                                at_scheduled_exec_kind_t kind,
                                ulong                   kind_topoheight,
                                ulong                   registration_topoheight,
                                ushort                  chunk_id,
                                uchar const             scheduler_contract[32] );

/* Check if target topoheight is valid (not in past, not too far in future). */
int
at_scheduled_exec_validate_target_topo( ulong current_topoheight,
                                        ulong target_topoheight );

/* Free results array memory. */
void
at_block_sched_exec_results_free( at_block_sched_exec_results_t * results,
                                  at_alloc_t * alloc );

AT_PROTOTYPES_END

#endif /* HEADER_at_scheduled_exec_processor_h */
