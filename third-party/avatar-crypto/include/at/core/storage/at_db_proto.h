#ifndef HEADER_at_core_storage_at_db_proto_h
#define HEADER_at_core_storage_at_db_proto_h

#include "at/infra/at_util.h"

/* Query protocol shared by RPC query helpers and storage handlers.
   This stays transport-agnostic across in-process and external backends. */

/* Operation codes for DB queries */
typedef enum {
  AT_DB_OP_UNKNOWN = 0,

  /* ========== RPC Read Operations (10-99) ========== */
  /* Account operations */
  AT_DB_OP_GET_BALANCE = 10,
  AT_DB_OP_GET_ACCOUNT = 11,
  AT_DB_OP_GET_NONCE = 12,
  AT_DB_OP_HAS_BALANCE = 13,
  AT_DB_OP_HAS_NONCE = 14,
  AT_DB_OP_GET_ACCOUNT_REGISTRATION = 15,
  AT_DB_OP_GET_UNO_BALANCE = 16,
  AT_DB_OP_HAS_UNO_BALANCE = 17,
  AT_DB_OP_GET_BALANCE_AT_TOPO = 18,
  AT_DB_OP_GET_NONCE_AT_TOPO = 19,

  /* Block operations */
  AT_DB_OP_GET_BLOCK_AT_TOPOHEIGHT = 20,
  AT_DB_OP_GET_BLOCK_BY_HASH = 21,
  AT_DB_OP_GET_TOP_BLOCK = 22,
  AT_DB_OP_GET_BLOCK_HASH = 23,
  AT_DB_OP_GET_TOPO_METADATA = 24,
  AT_DB_OP_GET_BLOCKS_AT_HEIGHT = 25,
  AT_DB_OP_GET_HASH_AT_TOPO = 26,
  AT_DB_OP_GET_TOPO_BY_HASH = 27,

  /* Transaction operations */
  AT_DB_OP_GET_TX = 30,
  AT_DB_OP_IS_TX_EXECUTED = 31,
  AT_DB_OP_GET_TX_BLOCKS = 32,
  AT_DB_OP_GET_TX_EXECUTOR = 33,
  AT_DB_OP_GET_TX_EXECUTED_BLOCK = 34,

  /* Asset operations */
  AT_DB_OP_GET_ASSET_DECIMALS = 40,
  AT_DB_OP_HAS_ASSET = 41,
  AT_DB_OP_COUNT_ASSETS = 42,
  AT_DB_OP_GET_ASSET = 43,
  AT_DB_OP_COUNT_ACCOUNTS = 44,
  AT_DB_OP_IS_ACCOUNT_REGISTERED = 45,
  AT_DB_OP_GET_ASSETS = 46,
  AT_DB_OP_GET_ASSET_SUPPLY = 47,

  /* Batch/iterator operations */
  AT_DB_OP_GET_ACCOUNTS = 60,
  AT_DB_OP_GET_TRANSACTIONS = 61,
  AT_DB_OP_GET_BLOCKS_RANGE = 62,
  AT_DB_OP_GET_ACCOUNT_HISTORY = 63,
  AT_DB_OP_GET_BALANCE_AT_MAX_TOPO = 64,
  AT_DB_OP_GET_ACCOUNT_ASSETS = 65,
  AT_DB_OP_GET_CONTRACT_ASSETS = 66,
  AT_DB_OP_GET_VERSIONED_BALANCE = 67,
  AT_DB_OP_GET_VERSIONED_NONCE = 68,
  AT_DB_OP_GET_VERSIONED_BALANCE_AT_TOPO = 69,

  /* Metadata operations */
  AT_DB_OP_GET_TOP_TOPOHEIGHT = 70,
  AT_DB_OP_GET_SIZE_ON_DISK = 71,
  AT_DB_OP_COUNT_TRANSACTIONS = 72,
  AT_DB_OP_COUNT_CONTRACTS = 73,

  /* Contract operations */
  AT_DB_OP_GET_CONTRACTS = 80,
  AT_DB_OP_GET_CONTRACT_MODULE = 81,
  AT_DB_OP_GET_CONTRACT_OUTPUTS = 82,
  AT_DB_OP_GET_CONTRACT_DATA = 83,
  AT_DB_OP_GET_CONTRACT_DATA_AT_TOPO = 84,
  AT_DB_OP_GET_CONTRACT_DATA_ENTRIES = 85,
  AT_DB_OP_GET_CONTRACT_BALANCE = 86,
  AT_DB_OP_GET_CONTRACT_BALANCE_AT_TOPO = 87,
  AT_DB_OP_GET_CONTRACT_EVENTS = 88,
  AT_DB_OP_GET_SCHEDULED_EXECUTIONS = 89,
  AT_DB_OP_GET_REGISTERED_EXECUTIONS = 90,

  /* Multisig operations */
  AT_DB_OP_GET_MULTISIG = 91,
  AT_DB_OP_HAS_MULTISIG = 92,
  AT_DB_OP_GET_MULTISIG_AT_TOPO = 93,
  AT_DB_OP_HAS_MULTISIG_AT_TOPO = 94,
  AT_DB_OP_GET_UNO_BALANCE_AT_TOPO = 95,

  /* ========== Management Operations (200+) ========== */
  AT_DB_OP_FLUSH = 200,
  AT_DB_OP_COMPACT = 201,
  AT_DB_OP_CHECKPOINT = 202,
} at_db_op_t;

/* Tile identifiers for sender_tile field (kept for wire compatibility). */
#define AT_DB_SENDER_RPC   1UL

/* Status codes for DB operations */
#define AT_DB_OK                 0
#define AT_DB_ERR_NOT_FOUND     -1
#define AT_DB_ERR_IO            -2
#define AT_DB_ERR_TIMEOUT       -3
#define AT_DB_ERR_INVALID_OP    -4
#define AT_DB_ERR_CORRUPTED     -5
#define AT_DB_ERR_NO_MEMORY     -6

/* Query request message */
struct __attribute__((packed)) at_db_req {
  ulong op;
  ulong request_id;
  ulong sender_tile;
  ulong timestamp_ns;
  ulong ttl_us;
  ulong key_a[4];
  ulong key_b[4];
  ulong param1;
  ulong param2;
  ulong limit;
  ulong offset;
  ulong payload_gaddr;
  ulong payload_sz;
};
typedef struct at_db_req at_db_req_t;

/* Query response message */
struct __attribute__((packed)) at_db_resp {
  ulong request_id;
  int   status;
  ulong timestamp_ns;
  ulong value;
  ulong value2;
  ulong data_gaddr;
  ulong data_sz;
  ulong cursor;
  ulong remaining;
  ulong flags;
};
typedef struct at_db_resp at_db_resp_t;

/* Iterator flags */
#define AT_DB_FLAG_HAS_MORE      (1UL << 0)
#define AT_DB_FLAG_END_OF_STREAM (1UL << 1)

#endif /* HEADER_at_core_storage_at_db_proto_h */
