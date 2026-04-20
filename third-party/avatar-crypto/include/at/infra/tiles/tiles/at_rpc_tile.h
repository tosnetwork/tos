#ifndef HEADER_at_src_disco_tiles_at_rpc_tile_h
#define HEADER_at_src_disco_tiles_at_rpc_tile_h

/* at_rpc_tile.h provides the JSON-RPC server tile for Avatar.

   The RPC tile handles incoming HTTP requests, parses JSON-RPC messages,
   dispatches to method handlers, and sends responses.

   Supported protocols:
   - HTTP/1.1 POST /json_rpc - JSON-RPC 2.0 requests
   - WebSocket /json_rpc - JSON-RPC 2.0 over WebSocket (subscriptions)
   - HTTP GET / - Health check
*/

#include "at/infra/at_util_base.h"
#include "at/block/at_block.h"
#include "at/rpc/at_http.h"
#include "at/rpc/at_jsonrpc.h"
#include "at/core/storage/at_db_proto.h"

/* RPC tile configuration */
struct at_rpc_tile_config {
  uint   listen_addr;       /* IPv4 address to listen on (0 = any) */
  ushort listen_port;       /* Port to listen on (default 18089) */
  ulong  max_connections;   /* Max HTTP connections */
  ulong  max_ws_connections;/* Max WebSocket connections */
  ulong  max_request_len;   /* Max request body size */
  ulong  send_buffer_sz;    /* Outgoing buffer size */
};

typedef struct at_rpc_tile_config at_rpc_tile_config_t;

/* Default RPC configuration */
#define AT_RPC_DEFAULT_PORT          18089
#define AT_RPC_DEFAULT_MAX_CONNS     256
#define AT_RPC_DEFAULT_MAX_WS_CONNS  64
#define AT_RPC_DEFAULT_MAX_REQ_LEN   (512UL * 1024UL)  /* 512 KiB - supports 100+ tx hashes */
#define AT_RPC_DEFAULT_SEND_BUF_SZ   (4UL * 1024UL * 1024UL)  /* 4 MiB */

/* Mining connection state */
struct at_rpc_miner_state {
  int   active;                  /* 1 = slot occupied */
  ulong ws_conn_id;              /* WebSocket connection ID */
  uchar miner_pubkey[32];        /* Miner address (decoded from bech32) */
  char  worker_name[64];         /* Worker name */
  ulong jobs_sent;               /* Number of jobs sent to this miner */
  ulong blocks_accepted;         /* Number of blocks accepted */
  ulong blocks_rejected;         /* Number of blocks rejected */
  ulong first_seen_ms;           /* Timestamp when miner connected */
  ulong last_invalid_block_ms;   /* Timestamp of last rejected block (aligned with TOS Rust) */
  int   needs_initial_job;       /* Counter: >0 = needs initial job (decrements each poll) */
};

typedef struct at_rpc_miner_state at_rpc_miner_state_t;

/* RPC tile context */
struct at_rpc_tile_ctx {
  at_http_server_t * http;              /* HTTP server */
  at_jsonrpc_ctx_t   jsonrpc;           /* JSON-RPC context */

  at_rpc_tile_config_t config;          /* Configuration */

  /* References to other tiles/data (set during init) */
  void *             peer_pool;         /* at_peer_pool_t * - P2P peers */
  void *             dag_provider;      /* at_dag_provider_t * - BlockDAG storage */
  void *             mempool;           /* at_mempool_t * - pending transactions */
  void *             direct_bank_ctx;   /* at_bank_ctx_t * - single-process direct execution path */

  int                query_backend_initialized; /* 1 once fallback query backend is initialized */
  void *             wksp;              /* at_wksp_t * - workspace for gaddr/laddr translation (Firedancer funk pattern) */

  /* Monotonic request ID for direct admin correlation */
  ulong              admin_next_request_id;

  /* Miner/Admin gating */
  int              getwork_disable;      /* 1 = mining methods disabled */
  int              enable_admin_rpc;     /* 1 = admin methods enabled */
  char const *     admin_token;          /* Admin bearer token (NULL = none) */
  volatile int *   shutdown_flag;        /* Pointer to daemon shutdown flag */
  uint             current_client_ip4;   /* Client IP for current request */
  int              network;              /* at_network_t - network type (Mainnet/Testnet/Stagenet/Devnet) */
  int              is_mainnet;           /* 1 = mainnet, 0 = testnet (for address validation) */

  /* Mining state (for /getwork WebSocket miners) */
  at_rpc_miner_state_t * miners;        /* Array of miner states */
  ulong                  miners_max;    /* Max number of miners (= max_ws_connections) */

  /* Mining job cache (for /getwork) - aligned with TOS Rust implementation */
  void *                 mining_jobs;        /* LRU cache: Hash -> (BlockHeader, Difficulty) */
  uchar                  last_header_hash[32]; /* Last job header_work_hash (0 = none) */
  int                    has_last_header_hash; /* 1 = last_header_hash is valid */
  ulong                  last_notify_ms;     /* Timestamp of last job notification */
  int                    is_job_dirty;       /* 1 = job needs to be resent (rate limited) */
  ulong                  notify_rate_limit_ms; /* Min time between notifications (default 1000ms) */

  /* Scratch buffers */
  uchar *            jsonrpc_scratch;   /* JSON parsing scratch */
  ulong              jsonrpc_scratch_sz;
  char *             result_buf;        /* Method result buffer */
  ulong              result_buf_sz;
  char *             response_buf;      /* Final response formatting buffer */
  ulong              response_buf_sz;

  /* Statistics */
  ulong              requests_total;
  ulong              requests_success;
  ulong              requests_error;
  ulong              bytes_in;
  ulong              bytes_out;

  /* Local DAG provider join struct (for cross-process workspace access)
     MUST BE LAST FIELD to prevent overflow corruption!
     This is allocated as part of the RPC tile footprint and populated
     by at_dag_memory_provider_join() to enable safe cross-process DAG access
     Note: sizeof(at_dag_memory_provider_t) = 2840 bytes as of 2026-02-15 */
  uchar              dag_join_mem[4096]; /* Embedded storage for at_dag_memory_provider_t (2840 bytes + safety margin) */
};

typedef struct at_rpc_tile_ctx at_rpc_tile_ctx_t;

AT_PROTOTYPES_BEGIN

/* Initialize RPC tile configuration with defaults */
void
at_rpc_config_default( at_rpc_tile_config_t * config );

/* Calculate memory footprint for RPC tile */
AT_FN_CONST ulong
at_rpc_tile_footprint( at_rpc_tile_config_t const * config );

/* Initialize RPC tile context.
   shmem must point to at_rpc_tile_footprint() bytes of memory.
   Returns the context on success, NULL on failure. */
at_rpc_tile_ctx_t *
at_rpc_tile_new( void *                    shmem,
                 at_rpc_tile_config_t const *   config );

/* Set references to other tile data */
void
at_rpc_tile_set_peer_pool( at_rpc_tile_ctx_t * ctx, void * peer_pool );

void
at_rpc_tile_set_dag_provider( at_rpc_tile_ctx_t * ctx, void * dag_provider );

void
at_rpc_tile_set_mempool( at_rpc_tile_ctx_t * ctx, void * mempool );

/* Miner/Admin configuration */
void
at_rpc_tile_set_getwork_disable( at_rpc_tile_ctx_t * ctx, int disable );

void
at_rpc_tile_set_admin_config( at_rpc_tile_ctx_t * ctx, int enable, char const * token );

void
at_rpc_tile_set_shutdown_flag( at_rpc_tile_ctx_t * ctx, volatile int * flag );

void
at_rpc_tile_set_network( at_rpc_tile_ctx_t * ctx, int network /* at_network_t */ );

/* Query scalar data via RPC query backend.
 * Returns 0 on success, <0 on error. */
int
at_rpc_query_backend( at_rpc_tile_ctx_t * ctx,
                      ulong               operation,    /* AT_DB_OP_* */
                      ulong               param1,       /* Operation-specific param */
                      ulong               param2,       /* Operation-specific param */
                      ulong *             result_value, /* OUT: result value */
                      int *               result_status /* OUT: result status */ );

/* Query with binary keys (addresses/hashes).
 * Parameters:
 *   key_a: First binary key (32 bytes) - address or block hash
 *   key_b: Second binary key (32 bytes) - asset ID (for balance queries)
 *   param: Additional numeric parameter (topoheight, etc.)
 * Returns 0 on success, <0 on error. */
int
at_rpc_query_backend_binary( at_rpc_tile_ctx_t * ctx,
                              ulong               operation,
                              uchar const *       key_a,        /* 32-byte binary key (address/hash) */
                              uchar const *       key_b,        /* 32-byte binary key (asset) or NULL */
                              ulong               param,        /* numeric parameter */
                              ulong *             result_value,
                              int *               result_status );

/* Query large objects with full request fields (offset/limit/param2/payload).
   payload can be NULL when payload_sz is 0.
   Returns 0 on success, <0 on error. */
int
at_rpc_query_backend_large_object_req( at_rpc_tile_ctx_t * ctx,
                                       at_db_req_t const * req_template,
                                       void const *        payload,
                                       ulong               payload_sz,
                                       at_db_resp_t **     out_response,
                                       ulong *             out_resp_gaddr );

/* Submit mined block to Bank tile through unified block message path. */
int
at_rpc_submit_mined_block_to_bank( at_rpc_tile_ctx_t *       rpc,
                                   at_block_header_t const * header );

/* Start listening on configured address/port.
   Returns 0 on success, -1 on failure. */
int
at_rpc_tile_listen( at_rpc_tile_ctx_t * ctx );

/* Query Bank Tile for admin operations via IPC - declaration moved to at_rpc_admin.c */

/* Poll for incoming requests and process them.
   timeout_ms is the poll timeout in milliseconds (0 = non-blocking).
   Returns number of requests processed. */
int
at_rpc_tile_poll( at_rpc_tile_ctx_t * ctx, int timeout_ms );

/* Get current statistics */
void
at_rpc_tile_stats( at_rpc_tile_ctx_t const * ctx,
                   ulong * requests_total,
                   ulong * requests_success,
                   ulong * requests_error );

/* Cleanup RPC tile */
void
at_rpc_tile_delete( at_rpc_tile_ctx_t * ctx );

/* Notify all connected miners of new mining job.
   Call this when a new block template is available (e.g., after new block received).
   Uses rate limiting to avoid flooding miners.
   Returns 0 on success, -1 on error. */
int
at_rpc_tile_notify_new_mining_job( at_rpc_tile_ctx_t * ctx );

/* ========================================================================
 * Testing Interface
 * ======================================================================== */

/* Get the RPC method table for testing.
   Returns pointer to the internal method array and sets method_cnt. */
at_rpc_method_t const *
at_rpc_tile_get_methods( ulong * method_cnt );

/* Initialize RPC tile context for testing (no HTTP server).
   Uses caller-provided buffers instead of allocating from shmem.
   Returns 0 on success. */
int
at_rpc_tile_test_init( at_rpc_tile_ctx_t * ctx,
                       uchar *             scratch,
                       ulong               scratch_sz,
                       char *              result_buf,
                       ulong               result_buf_sz );

/* Process a JSON-RPC request directly (for testing).
   json_request is the raw JSON-RPC request string.
   response_buf receives the formatted response.
   Returns 0 on success. */
int
at_rpc_tile_test_request( at_rpc_tile_ctx_t * ctx,
                          char const *        json_request,
                          ulong               json_request_len,
                          char *              response_buf,
                          ulong               response_buf_sz,
                          ulong *             response_len_out );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_disco_tiles_at_rpc_tile_h */
