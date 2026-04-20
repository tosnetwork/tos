#ifndef HEADER_at_rocks_at_rocks_contract_h
#define HEADER_at_rocks_at_rocks_contract_h

/* at_rocks_contract.h - Contract storage operations for at_rocks
 *
 * Provides contract metadata, data, balance, and event storage with
 * TOS-compatible serialization format and topoheight versioning.
 *
 * Contract Storage Layout:
 *   - AT_CF_CONTRACTS: contract_hash -> contract metadata (id + module pointer)
 *   - AT_CF_VERSIONED_CONTRACTS_DATA: topo[8]+contract_id[8]+data_id[8] -> Versioned<Option<ValueCell>>
 *   - AT_CF_CONTRACTS_DATA: contract_id[8]+data_id[8] -> topo pointer
 *   - AT_CF_CONTRACT_DATA_BY_ID: data_id[8] -> key(ValueCell)
 *   - AT_CF_CONTRACTS_BALANCES: contract_id[8]+asset_id[8] -> topo pointer
 *   - AT_CF_VERSIONED_CONTRACTS_BALANCES: topo[8]+contract_id[8]+asset_id[8] -> Versioned<u64>
 *   - AT_CF_CONTRACT_EVENTS: indexed contract events
 *   - AT_CF_DELAYED_EXECUTION: scheduled contract executions
 */

#include "at_rocks.h"

/* Forward declaration for at_value_cell_t used in data iteration */
struct at_value_cell;

AT_PROTOTYPES_BEGIN

/* ============================================================================
   Contract Output Types (from contract execution)
   ============================================================================ */

#define AT_CONTRACT_OUTPUT_TRANSFER     (0)
#define AT_CONTRACT_OUTPUT_CREATE_ASSET (1)
#define AT_CONTRACT_OUTPUT_REFUND_GAS   (2)

typedef struct at_contract_output {
  uchar type;  /* AT_CONTRACT_OUTPUT_* */
  union {
    struct {
      uchar asset[32];
      uchar destination[32];
      ulong amount;
    } transfer;
    struct {
      uchar asset[32];
      uchar decimals;
    } create_asset;
    struct {
      ulong amount;
    } refund_gas;
  };
} at_contract_output_t;

/* ============================================================================
   Contract Event Types
   ============================================================================ */

typedef struct at_contract_event {
  uchar contract[32];
  uchar tx_hash[32];
  uchar block_hash[32];
  ulong topoheight;
  uint  log_index;
  uchar topics[4 * 32];  /* Up to 4 topics, each 32 bytes */
  ulong topics_cnt;
  uchar data[1024];      /* Event data (max 1KB) */
  ulong data_sz;
} at_contract_event_t;

typedef struct at_contract_event_query {
  uchar contract[32];
  int   has_contract;
  uchar tx_hash[32];
  int   has_tx_hash;
  uchar topic0[32];
  int   has_topic0;
  ulong from_topo;
  ulong to_topo;
  ulong limit;
} at_contract_event_query_t;

/* ============================================================================
   Scheduled Execution Types
   ============================================================================ */

typedef struct at_scheduled_exec {
  uchar contract[32];
  uint  entry_id;
  ulong max_gas;
} at_scheduled_exec_t;

typedef struct at_registered_exec {
  uchar execution_hash[32];
  ulong execution_topoheight;
} at_registered_exec_t;

/* ============================================================================
   Contract Data Iterator
   ============================================================================ */

typedef struct at_contract_data_iter {
  void * _internal;
} at_contract_data_iter_t;

/* ============================================================================
   Contract Count and Listing
   ============================================================================ */

/* at_rocks_count_contracts returns total deployed contract count. */
ulong
at_rocks_count_contracts( at_rocks_t * db );

/* at_rocks_contract_iter lists contract addresses with pagination.
 * addrs_out must have space for max * 32 bytes.
 * Returns AT_ROCKS_OK on success. */
int
at_rocks_contract_iter( at_rocks_t * db,
                        ulong skip,
                        ulong max,
                        ulong min_topo,
                        ulong max_topo,
                        uchar * addrs_out,
                        ulong * count_out );

/* ============================================================================
   Contract Module (Bytecode)
   ============================================================================ */

/* at_rocks_contract_get_module retrieves TBPF bytecode for a contract.
 * Allocates memory for code_out which caller must free with at_rocks_free().
 * Returns AT_ROCKS_OK on success. */
int
at_rocks_contract_get_module( at_rocks_t * db,
                              uchar const addr[32],
                              uchar ** code_out,
                              ulong * code_sz_out );

/* ============================================================================
   Contract Data Storage
   ============================================================================ */

/* at_rocks_contract_get_data retrieves contract data by key.
 * Returns the latest version and its topoheight.
 * Allocates memory for val_out which caller must free.
 * Returns AT_ROCKS_OK on success. */
int
at_rocks_contract_get_data( at_rocks_t * db,
                            uchar const addr[32],
                            uchar const * key,
                            ulong key_sz,
                            uchar ** val_out,
                            ulong * val_sz_out,
                            ulong * topo_out );

/* at_rocks_contract_get_data_at_topo retrieves contract data at topoheight.
 * Allocates memory for val_out which caller must free.
 * Returns AT_ROCKS_OK on success. */
int
at_rocks_contract_get_data_at_topo( at_rocks_t * db,
                                    uchar const addr[32],
                                    uchar const * key,
                                    ulong key_sz,
                                    ulong topoheight,
                                    uchar ** val_out,
                                    ulong * val_sz_out );

/* at_rocks_contract_iter_data creates an iterator for contract data entries.
 * Returns AT_ROCKS_OK on success. */
int
at_rocks_contract_iter_data( at_rocks_t * db,
                             uchar const addr[32],
                             ulong skip,
                             ulong max,
                             ulong max_topo,
                             at_contract_data_iter_t * iter );

/* at_rocks_contract_data_iter_next advances iterator and returns entry.
 * key_out and val_out point to internal buffer valid until next call.
 * Returns AT_ROCKS_OK on success, AT_ROCKS_ERR_NOT_FOUND when exhausted. */
int
at_rocks_contract_data_iter_next( at_contract_data_iter_t * iter,
                                  uchar ** key_out,
                                  ulong * key_sz_out,
                                  uchar ** val_out,
                                  ulong * val_sz_out );

/* at_rocks_contract_data_iter_destroy cleans up iterator. */
void
at_rocks_contract_data_iter_destroy( at_contract_data_iter_t * iter );

/* ============================================================================
   Contract Balances
   ============================================================================ */

/* at_rocks_contract_get_balance retrieves contract balance for an asset.
 * Returns AT_ROCKS_OK on success. */
int
at_rocks_contract_get_balance( at_rocks_t * db,
                               uchar const addr[32],
                               uchar const asset[32],
                               ulong * balance_out,
                               ulong * topo_out );

/* at_rocks_contract_get_balance_at_topo retrieves historical balance.
 * Returns AT_ROCKS_OK on success. */
int
at_rocks_contract_get_balance_at_topo( at_rocks_t * db,
                                       uchar const addr[32],
                                       uchar const asset[32],
                                       ulong topoheight,
                                       ulong * balance_out );

/* at_rocks_contract_add_balance increases contract balance for an asset.
 * Returns AT_ROCKS_OK on success. */
int
at_rocks_contract_add_balance( at_rocks_t * db,
                               uchar const addr[32],
                               uchar const asset[32],
                               ulong amount,
                               ulong topoheight );

/* at_rocks_contract_sub_balance decreases contract balance for an asset.
 * Returns AT_ROCKS_OK on success, AT_ROCKS_ERR_INVALID if insufficient. */
int
at_rocks_contract_sub_balance( at_rocks_t * db,
                               uchar const addr[32],
                               uchar const asset[32],
                               ulong amount,
                               ulong topoheight );

/* at_rocks_contract_iter_assets lists assets held by a contract.
 * assets_out must have space for max * 32 bytes.
 * Returns AT_ROCKS_OK on success. */
int
at_rocks_contract_iter_assets( at_rocks_t * db,
                               uchar const addr[32],
                               ulong skip,
                               ulong max,
                               uchar * assets_out,
                               ulong * count_out );

/* ============================================================================
   Contract Outputs
   ============================================================================ */

/* at_rocks_contract_get_outputs retrieves outputs from a transaction.
 * outputs_out must have space for up to 64 entries.
 * Returns AT_ROCKS_OK on success. */
int
at_rocks_contract_get_outputs( at_rocks_t * db,
                               uchar const tx_hash[32],
                               at_contract_output_t * outputs_out,
                               ulong * count_out );

/* ============================================================================
   Contract Events
   ============================================================================ */

/* at_rocks_contract_get_events queries contract events.
 * events_out must have space for up to 100 entries.
 * Returns AT_ROCKS_OK on success. */
int
at_rocks_contract_get_events( at_rocks_t * db,
                              at_contract_event_query_t const * query,
                              at_contract_event_t * events_out,
                              ulong * count_out );

/* ============================================================================
   Scheduled Executions
   ============================================================================ */

/* at_rocks_contract_get_scheduled retrieves scheduled executions at topo.
 * execs_out must have space for up to max entries.
 * Returns AT_ROCKS_OK on success. */
int
at_rocks_contract_get_scheduled( at_rocks_t * db,
                                 ulong topoheight,
                                 ulong skip,
                                 ulong max,
                                 at_scheduled_exec_t * execs_out,
                                 ulong * count_out );

/* at_rocks_contract_get_registered retrieves registered executions at topo.
 * execs_out must have space for up to max entries.
 * Returns AT_ROCKS_OK on success. */
int
at_rocks_contract_get_registered( at_rocks_t * db,
                                  ulong topoheight,
                                  ulong skip,
                                  ulong max,
                                  at_registered_exec_t * execs_out,
                                  ulong * count_out );

AT_PROTOTYPES_END

#endif /* HEADER_at_rocks_at_rocks_contract_h */
