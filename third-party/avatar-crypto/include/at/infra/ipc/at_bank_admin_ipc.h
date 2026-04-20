#ifndef AT_INFRA_IPC_BANK_ADMIN_IPC_H
#define AT_INFRA_IPC_BANK_ADMIN_IPC_H

/* Admin IPC protocol for RPC ↔ Bank communication.

   This protocol enables admin operations (prune_chain, rewind_chain, etc.)
   to execute on the Bank tile while being invoked from the RPC tile.

   Architecture:
   - RPC sends admin requests via rpc_bank_admin mcache
   - Bank processes requests and sends responses via bank_rpc_admin mcache
   - Synchronous request-response pattern with correlation IDs

   This aligns with TOS Rust architecture where admin operations are
   methods on the blockchain object, not on the storage layer. */

#include "at/infra/at_util_base.h"

/* Admin operation codes */
typedef enum {
  AT_BANK_ADMIN_OP_UNKNOWN = 0,

  /* Chain management operations */
  AT_BANK_ADMIN_OP_PRUNE_CHAIN = 1,   /* Prune old blocks up to topoheight */
  AT_BANK_ADMIN_OP_REWIND_CHAIN = 2,  /* Rewind chain by N blocks */

  /* Future operations (reserved) */
  AT_BANK_ADMIN_OP_CLEAR_CACHES = 10,
  AT_BANK_ADMIN_OP_SHUTDOWN = 11,
} at_bank_admin_op_t;

/* Admin request message (128 bytes, cache-aligned)

   Sent from RPC tile to Bank tile via rpc_bank_admin mcache.
   Each request has a unique request_id for response correlation. */
struct __attribute__((packed)) at_bank_admin_req {
  /* Metadata */
  ulong op;              /* Operation code (at_bank_admin_op_t) */
  ulong request_id;      /* Correlation ID for response matching */
  ulong timestamp_ns;    /* Request timestamp (for timeout tracking) */
  ulong sender_tile;     /* Always 1 (RPC) for now */

  /* Parameters (operation-specific) */
  ulong param1;          /* topoheight (prune) or count (rewind) */
  ulong param2;          /* flags: until_stable_height (rewind) */

  /* Reserved for future use */
  ulong reserved[10];
};
typedef struct at_bank_admin_req at_bank_admin_req_t;

AT_STATIC_ASSERT( sizeof(at_bank_admin_req_t) == 128UL, "admin_req_size" );

/* Admin response message (96 bytes)

   Sent from Bank tile to RPC tile via bank_rpc_admin mcache.
   Contains operation result and optional workspace-allocated data. */
struct __attribute__((packed)) at_bank_admin_resp {
  /* Metadata */
  ulong request_id;      /* Correlation ID (must match request) */
  int   status;          /* 0=success, <0=error (AT_PRUNE_ERR_*, etc.) */
  uint  _pad;            /* Padding to align to 8 bytes */
  ulong timestamp_ns;    /* Response timestamp */

  /* Return values */
  ulong value;           /* Result: pruned_topoheight or rewind_topoheight */

  /* Large object support (e.g., rewind returns array of block hashes) */
  ulong data_gaddr;      /* Workspace pointer to array data */
  ulong data_sz;         /* Size of array in bytes */

  /* Reserved */
  ulong reserved[6];
};
typedef struct at_bank_admin_resp at_bank_admin_resp_t;

AT_STATIC_ASSERT( sizeof(at_bank_admin_resp_t) == 96UL, "admin_resp_size" );

/* Prune error codes (from at_prune.h, guarded to avoid redefinition) */
#ifndef AT_PRUNE_OK
#define AT_PRUNE_OK                 0
#define AT_PRUNE_ERR_GENESIS       -1   /* Cannot prune genesis block */
#define AT_PRUNE_ERR_ABOVE_CURRENT -2   /* Target >= current topoheight */
#define AT_PRUNE_ERR_SAFETY_LIMIT  -3   /* Within 240 blocks of tip */
#define AT_PRUNE_ERR_BELOW_PRUNED  -4   /* Target < already pruned */
#define AT_PRUNE_ERR_NO_SYNC_BLOCK -5   /* No sync block at target */
#define AT_PRUNE_ERR_STORE         -6   /* Storage layer error */
#endif

/* Rewind error codes */
#define AT_REWIND_OK                0
#define AT_REWIND_ERR_GENESIS      -1   /* Cannot rewind past genesis */
#define AT_REWIND_ERR_ABOVE_CURRENT -2  /* Count exceeds chain height */
#define AT_REWIND_ERR_ZERO_COUNT   -3   /* Count must be > 0 */
#define AT_REWIND_ERR_NO_MEMORY    -4   /* Workspace allocation failed */

/* Admin IPC timeout (5 seconds - admin ops can be slow) */
#define AT_BANK_ADMIN_TIMEOUT_NS  (5000000000UL)

#endif /* AT_INFRA_IPC_BANK_ADMIN_IPC_H */
