#ifndef HEADER_at_rocks_at_rocks_tx_h
#define HEADER_at_rocks_at_rocks_tx_h

/* at_rocks_tx.h - Transaction storage operations for at_rocks
 *
 * Provides transaction storage and retrieval with TOS-compatible
 * serialization format.
 *
 * Transaction Storage Layout:
 *   - AT_CF_TRANSACTIONS: hash -> raw transaction bytes
 *   - AT_CF_TRANSACTIONS_EXECUTED: hash -> execution info
 *   - AT_CF_TRANSACTION_IN_BLOCKS: hash -> block hashes containing TX
 *   - AT_CF_TRANSACTIONS_OUTPUTS: hash -> contract outputs
 */

#include "at_rocks.h"

AT_PROTOTYPES_BEGIN

/* ============================================================================
   Transaction Executor Info
   ============================================================================ */

typedef struct at_tx_executor {
  uchar block_hash[32];  /* Block where TX was executed */
  ulong topoheight;      /* Block topoheight */
  ulong timestamp;       /* Block timestamp (ms since epoch) */
} at_tx_executor_t;

/* ============================================================================
   Transaction Retrieval
   ============================================================================ */

/* at_rocks_tx_get retrieves raw transaction bytes by hash.
 * Allocates memory for raw_out which caller must free with at_rocks_free().
 * Returns AT_ROCKS_OK on success, AT_ROCKS_ERR_NOT_FOUND if not found. */
int
at_rocks_tx_get( at_rocks_t * db,
                 uchar const hash[32],
                 uchar ** raw_out,
                 ulong * raw_sz_out );

/* at_rocks_tx_get_executor retrieves execution info for a transaction.
 * Returns AT_ROCKS_OK on success, AT_ROCKS_ERR_NOT_FOUND if not executed. */
int
at_rocks_tx_get_executor( at_rocks_t * db,
                          uchar const hash[32],
                          at_tx_executor_t * out );

/* at_rocks_tx_get_blocks retrieves block hashes that contain this transaction.
 * blocks_out must have space for up to max_blocks * 32 bytes.
 * Returns actual count in count_out.
 * Returns AT_ROCKS_OK on success. */
int
at_rocks_tx_get_blocks( at_rocks_t * db,
                        uchar const hash[32],
                        uchar * blocks_out,
                        ulong * count_out );

/* at_rocks_tx_get_executed_block retrieves the block where TX was executed.
 * On success, executed_in_out is set to the block hash.
 * On failure or not executed, executed_in_out is zeroed.
 * Returns AT_ROCKS_OK on success. */
int
at_rocks_tx_get_executed_block( at_rocks_t * db,
                                uchar const hash[32],
                                uchar executed_in_out[32] );

/* at_rocks_count_transactions returns total transaction count.
 * Reads from AT_KEY_TXS_COUNT in AT_CF_COMMON. */
ulong
at_rocks_count_transactions( at_rocks_t * db );

/* at_rocks_is_tx_executed_in_block checks if TX was executed in a block.
 * Returns 1 if executed in that block, 0 otherwise. */
int
at_rocks_is_tx_executed_in_block( at_rocks_t * db,
                                  uchar const tx_hash[32],
                                  uchar const block_hash[32] );

/* ============================================================================
   Transaction Storage
   ============================================================================ */

/* at_rocks_tx_put stores a transaction by hash.
 * Does not overwrite if already exists.
 * Returns AT_ROCKS_OK on success. */
int
at_rocks_tx_put( at_rocks_t * db,
                 uchar const hash[32],
                 uchar const * raw,
                 ulong raw_sz );

/* at_rocks_tx_set_executor marks a transaction as executed in a block.
 * Returns AT_ROCKS_OK on success. */
int
at_rocks_tx_set_executor( at_rocks_t * db,
                          uchar const hash[32],
                          at_tx_executor_t const * executor );

/* at_rocks_tx_add_to_block associates a transaction with a block.
 * A transaction may appear in multiple blocks before execution.
 * Returns AT_ROCKS_OK on success. */
int
at_rocks_tx_add_to_block( at_rocks_t * db,
                          uchar const tx_hash[32],
                          uchar const block_hash[32] );

/* at_rocks_tx_increment_count increments the transaction counter.
 * Returns the new count. */
ulong
at_rocks_tx_increment_count( at_rocks_t * db );

AT_PROTOTYPES_END

#endif /* HEADER_at_rocks_at_rocks_tx_h */