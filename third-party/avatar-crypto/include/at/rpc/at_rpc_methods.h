#ifndef HEADER_at_src_waltz_http_at_rpc_methods_h
#define HEADER_at_src_waltz_http_at_rpc_methods_h

/* at_rpc_methods.h - Helper functions for RPC method implementations

   This header provides common utilities for implementing TOS-compatible
   JSON-RPC methods:
   - Parameter parsing helpers
   - Response formatting helpers
   - Hex encoding/decoding utilities
   - TOS-specific error codes
*/

#include "at/infra/at_util_base.h"
#include "at/transaction/at_txn.h"
#include "at/transaction/at_txn_contract.h"
#include "at_jsonrpc.h"

AT_PROTOTYPES_BEGIN

/* ============================================================================
   TOS-Compatible RPC Error Codes
   See: tos/daemon/src/rpc/rpc.rs
   ============================================================================ */

#define AT_RPC_ERR_ACCOUNT_NOT_FOUND    (-32001)
#define AT_RPC_ERR_BLOCK_NOT_FOUND      (-32002)
#define AT_RPC_ERR_INVALID_ADDRESS      (-32003)
#define AT_RPC_ERR_INVALID_TOPOHEIGHT   (-32004)
#define AT_RPC_ERR_TOPOHEIGHT_TOO_HIGH  (-32005)
#define AT_RPC_ERR_PRUNED_DATA          (-32006)
#define AT_RPC_ERR_INVALID_HASH         (-32007)
#define AT_RPC_ERR_TX_NOT_FOUND         (-32008)
#define AT_RPC_ERR_TX_INVALID           (-32009)
#define AT_RPC_ERR_CONTRACT_NOT_FOUND   (-32010)
#define AT_RPC_ERR_ASSET_NOT_FOUND      (-32011)
#define AT_RPC_ERR_TX_REJECTED          (-32012)
#define AT_RPC_ERR_KEY_NOT_FOUND        (-32013)
#define AT_RPC_ERR_NOT_DEPLOY_TX        (-32014)
#define AT_RPC_ERR_FILTER_REQUIRED      (-32015)
#define AT_RPC_ERR_KYC_NOT_FOUND        (-32016)
#define AT_RPC_ERR_REFERRAL_NOT_FOUND   (-32017)
#define AT_RPC_ERR_ESCROW_NOT_FOUND     (-32018)
#define AT_RPC_ERR_ARBITER_NOT_FOUND    (-32019)
#define AT_RPC_ERR_MULTISIG_NOT_FOUND   (-32020)
#define AT_RPC_ERR_COMMITTEE_NOT_FOUND  (-32021)

/* Miner/Admin error codes */
#define AT_RPC_ERR_MINING_DISABLED      (-32024)
#define AT_RPC_ERR_ADMIN_DISABLED       (-32025)
#define AT_RPC_ERR_LOCALHOST_REQUIRED   (-32026)
#define AT_RPC_ERR_PRUNE_FAILED         (-32029)
#define AT_RPC_ERR_REWIND_FAILED        (-32030)

/* Shutdown-specific error codes (TOS Rust parity: -100 range) */
#define AT_RPC_ERR_SHUTDOWN_UNAUTHORIZED (-100)     /* Non-localhost connection */
#define AT_RPC_ERR_SHUTDOWN_RATE_LIMITED (-101)     /* Rate limit exceeded */
#define AT_RPC_ERR_SHUTDOWN_NO_CONFIRM   (-102)     /* Missing confirmation */
#define AT_RPC_ERR_SHUTDOWN_INVALID_TOKEN (-103)    /* Invalid or missing admin token */

/* TOS stable limit: blocks older than this depth are considered stable */
#define AT_RPC_STABLE_LIMIT             (24UL)

/* Pagination limits */
#define AT_RPC_MAX_ACCOUNTS_PER_REQUEST (100UL)
#define AT_RPC_MAX_BLOCKS_PER_REQUEST   (200UL)
#define AT_RPC_MAX_BLOCKS_WITH_TXS      (50UL)
#define AT_RPC_MAX_DAG_ORDER            (64UL)

/* Transaction size limits */
#define AT_RPC_MAX_TX_HEX_SIZE          (10UL * 1024UL * 1024UL)  /* 10 MB hex = ~5 MB binary */
#define AT_RPC_MAX_TXS_PER_REQUEST      (20UL)   /* TOS Rust parity: get_transactions (MAX_TXS = 20) */
#define AT_RPC_MAX_TXS_SUMMARY          (100UL)  /* TOS Rust parity: get_transactions_summary (MAX_TXS_SUMMARY = 100) */
#define AT_RPC_MAX_MEMPOOL_TXS          (100UL)
#define AT_RPC_MAX_MEMPOOL_SUMMARY      (100UL)

/* Contract limits */
#define AT_RPC_MAX_CONTRACTS            (100UL)
#define AT_RPC_MAX_CONTRACT_DATA        (20UL)
#define AT_RPC_MAX_CONTRACT_ASSETS      (1000UL)
#define AT_RPC_MAX_CONTRACT_EVENTS      (1000UL)
#define AT_RPC_DEFAULT_EVENTS_LIMIT     (100UL)
#define AT_RPC_MAX_SCHEDULED_EXEC       (100UL)

/* ============================================================================
   Parameter Parsing Helpers
   ============================================================================ */

/* Parse address parameter from JSON params.
   Supports both object { "address": "tos1..." } and array ["tos1..."] formats.
   Returns 1 on success, 0 on failure.
   On success, addr_out points to the address string (not null-terminated),
   and len_out contains the string length. */
int
at_rpc_parse_address_param( at_json_value_t * params,
                            char const     ** addr_out,
                            ulong           * len_out );

/* Parse hash parameter from JSON params by key.
   Expects hex-encoded 32-byte hash (64 characters).
   Returns 1 on success, 0 on failure.
   On success, hash_out contains the decoded 32-byte hash. */
int
at_rpc_parse_hash_param( at_json_value_t * params,
                         char const      * key,
                         uchar             hash_out[32] );

/* Parse topoheight parameter from JSON params.
   Returns 1 on success, 0 on failure. */
int
at_rpc_parse_topoheight_param( at_json_value_t * params,
                               ulong           * topo_out );

/* Parse boolean parameter from JSON params by key.
   Sets val_out to 1 if true, 0 if false or not found.
   Returns 1 if parameter was found, 0 if not found (val_out set to 0). */
int
at_rpc_parse_bool_param( at_json_value_t * params,
                         char const      * key,
                         int             * val_out );

/* Parse unsigned long parameter from JSON params by key.
   Returns 1 if parameter was found, 0 if not found (val_out set to default_val). */
int
at_rpc_parse_ulong_param( at_json_value_t * params,
                          char const      * key,
                          ulong           * val_out,
                          ulong             default_val );

/* Parse optional topoheight range parameters (start_topoheight, end_topoheight).
   Returns 1 on success, 0 on failure. */
int
at_rpc_parse_topo_range_params( at_json_value_t * params,
                                ulong           * start_out,
                                ulong           * end_out,
                                ulong             current_topo );

/* ============================================================================
   Response Formatting Helpers
   ============================================================================ */

/* Set error response fields.
   Returns the error code (for convenience in return statements). */
int
at_rpc_error( at_jsonrpc_response_t * resp,
              int                     code,
              char const            * msg );

/* Set success response fields.
   json should be a pre-formatted JSON string.
   Returns 0 (for convenience in return statements). */
int
at_rpc_success( at_jsonrpc_response_t * resp,
                char const            * json,
                ulong                   len );

/* Format a u64 as JSON number.
   Returns number of characters written, or negative on error. */
int
at_rpc_format_u64( char * buf, ulong buf_sz, ulong val );

/* Format a u128 as JSON string (decimal representation).
   u128 values are serialized as strings in TOS RPC.
   Returns number of characters written, or negative on error. */
int
at_rpc_format_u128_str( char * buf, ulong buf_sz, __uint128_t val );

/* Format optional u64: null or number.
   Returns number of characters written, or negative on error. */
int
at_rpc_format_optional_u64( char * buf, ulong buf_sz, int has_val, ulong val );

/* Format a hash as hex string (64 characters + quotes).
   Returns number of characters written, or negative on error. */
int
at_rpc_format_hash( char * buf, ulong buf_sz, uchar const hash[32] );

/* Format balance type as JSON string.
   type: 0=Input, 1=Output, 2=Both
   Returns number of characters written, or negative on error. */
int
at_rpc_format_balance_type( char * buf, ulong buf_sz, int type );

/* ============================================================================
   String Parameter Parsing Helpers
   ============================================================================ */

/* Parse string parameter from JSON params by key.
   Returns 1 on success, 0 on failure.
   On success, str_out points to the string (not null-terminated),
   and len_out contains the string length. */
int
at_rpc_parse_string_param( at_json_value_t * params,
                           char const      * key,
                           char const     ** str_out,
                           ulong           * len_out );

/* Parse an array of hashes from JSON params by key.
   Expects hex-encoded 32-byte hashes (64 characters each).
   Returns 1 on success, 0 on failure.
   On success, hashes_out contains decoded hashes, count_out is the number. */
int
at_rpc_parse_hash_array_param( at_json_value_t * params,
                               char const      * key,
                               uchar           * hashes_out,
                               ulong             max_hashes,
                               ulong           * count_out );

/* ============================================================================
   Transaction Formatting Helpers
   ============================================================================ */

/* Note: at_txn_t and at_value_cell_t are defined in included headers */

/* Format basic transaction info as JSON.
   Returns number of characters written, or negative on error. */
int
at_rpc_format_transaction( char               * buf,
                           ulong                buf_sz,
                           at_txn_t const     * txn,
                           uchar const        * raw,
                           uchar const          hash[32] );

/* Format full TransactionResponse as JSON (TOS-compatible).
   Includes blocks containing TX, mempool status, and execution info. */
int
at_rpc_format_transaction_response( char               * buf,
                                    ulong                buf_sz,
                                    at_txn_t const     * txn,
                                    uchar const        * raw,
                                    uchar const          hash[32],
                                    int                  in_mempool,
                                    ulong                first_seen,
                                    uchar const        * blocks,
                                    ulong                blocks_cnt,
                                    uchar const          executed_in[32] );

/* Format transaction summary as JSON. */
int
at_rpc_format_tx_summary( char        * buf,
                          ulong         buf_sz,
                          uchar const   hash[32],
                          uchar const   source[32],
                          ulong         fee,
                          ulong         size );

/* ============================================================================
   Contract Event Formatting Helpers
   ============================================================================ */

/* Format contract event as JSON. */
int
at_rpc_format_contract_event( char        * buf,
                              ulong         buf_sz,
                              uchar const   contract[32],
                              uchar const   tx_hash[32],
                              uchar const   block_hash[32],
                              ulong         topoheight,
                              uint          log_index,
                              uchar const * topics,
                              ulong         topics_cnt,
                              uchar const * data,
                              ulong         data_sz );

/* ============================================================================
   ValueCell JSON Formatting
   ============================================================================ */

/* Format ValueCell as JSON (TOS-compatible format).
   Returns number of characters written, or negative on error. */
int
at_rpc_format_value_cell( char                   * buf,
                          ulong                    buf_sz,
                          at_value_cell_t const  * cell,
                          uchar const            * raw );

/* ============================================================================
   Transaction Type Name Helpers
   ============================================================================ */

/* Get JSON-friendly transaction type name from type_id.
   Returns static string like "transfers", "burn", "invoke_contract", etc. */
char const *
at_rpc_tx_type_name( uchar type_id );

/* ============================================================================
   Hex Encoding/Decoding Utilities
   ============================================================================ */

/* Encode binary data to hexadecimal string.
   Writes 2*len hex characters + null terminator to out buffer.
   Returns number of characters written (2 * len), or 0 on buffer overflow.
   Requires out_max >= 2*len+1 for the hex string and null terminator. */
ulong
at_hex_encode( char        * out,
               ulong         out_max,
               uchar const * data,
               ulong         len );

/* Decode hexadecimal string to binary data.
   Returns 0 on success, -1 on invalid hex, -2 on buffer overflow. */
int
at_hex_decode( uchar      * out,
               ulong        out_max,
               char const * hex,
               ulong        hex_len );

/* Check if a character is a valid hex digit. */
static inline int
at_is_hex_digit( char c ) {
  return (c >= '0' && c <= '9') ||
         (c >= 'a' && c <= 'f') ||
         (c >= 'A' && c <= 'F');
}

/* Convert hex digit to value (0-15). Assumes valid hex digit. */
static inline int
at_hex_digit_val( char c ) {
  if( c >= '0' && c <= '9' ) return c - '0';
  if( c >= 'a' && c <= 'f' ) return c - 'a' + 10;
  return c - 'A' + 10;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_src_waltz_http_at_rpc_methods_h */
