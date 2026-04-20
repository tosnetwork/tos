/* at_bank_tile.h - Avatar Bank Tile Header

   The bank tile executes transactions from pack microblocks,
   updates state via the executor, and emits finalized blocks
   to the store tile. */

#ifndef HEADER_at_disco_tiles_at_bank_tile_h
#define HEADER_at_disco_tiles_at_bank_tile_h

#include "at/infra/tiles/at_topo.h"
#include "at/core/state/at_executor.h"
#include "at/block/at_block.h"
#include "at/transaction/at_txn.h"
#include "at/core/storage/at_store.h"
#include "at/core/storage/at_rocks.h"
#include "at/core/blockdag/at_dag_provider.h"
#include "at/infra/alloc/at_alloc.h"
#include "at/infra/rng/at_rng.h"
#include "at/infra/ipc/at_bank_admin_ipc.h"

AT_PROTOTYPES_BEGIN

/* Input link kinds */
#define AT_BANK_IN_KIND_PACK    (0UL)  /* Microblocks from pack tile */
#define AT_BANK_IN_KIND_REPLAY  (1UL)  /* Replay from store tile */
#define AT_BANK_IN_KIND_GOSSIP  (2UL)  /* Blocks from gossip */
#define AT_BANK_IN_KIND_ADMIN   (3UL)  /* Admin operations from RPC */
#define AT_BANK_IN_KIND_RPC_MINE (4UL) /* RPC submit path (WS/HTTP mining) */

/* Output link kinds */
#define AT_BANK_OUT_KIND_STORE  (0UL)  /* To store tile */
#define AT_BANK_OUT_KIND_PACK   (1UL)  /* Feedback to pack tile */

/* External block execution mode */
#define AT_BANK_EXEC_BLOCK_MODE_REPLAY (0UL)
#define AT_BANK_EXEC_BLOCK_MODE_GOSSIP (1UL)

/* Block message from sync/gossip tile for execution.
   This message contains block metadata and raw block data.
   For REPLAY (sync): topoheight is pre-assigned by sync tile.
   For GOSSIP: topoheight is 0 (bank assigns it). */
typedef struct {
  uchar     block_hash[32];     /* Block hash (blake3 of header) */
  ulong     topoheight;         /* Pre-assigned topoheight (REPLAY) or 0 (GOSSIP) */
  ulong     height;             /* Block height from header */
  ulong     timestamp_ms;       /* Block timestamp from header */
  uchar     miner[32];          /* Miner public key */
  uchar     tips_cnt;           /* Number of parent blocks (1-3) */
  uchar     tips[AT_BLOCK_MAX_TIPS][32]; /* Parent block hashes */
  ulong     block_data_sz;      /* Size of raw block data following this header */
  /* Raw block data follows immediately after this struct */
} at_bank_block_msg_t;

/* Bank tile metrics */
typedef struct {
  ulong microblock_received_cnt;   /* Total microblocks received */
  ulong txn_executed_cnt;          /* Total transactions executed */
  ulong txn_success_cnt;           /* Successful transactions */
  ulong txn_failed_cnt;            /* Failed transactions */
  ulong block_produced_cnt;        /* Total blocks produced */
  ulong slot_completed_cnt;        /* Total slots completed */
  ulong state_commit_cnt;          /* State commits to RocksDB */
  ulong metadata_persist_fail_cnt; /* DB metadata persist failures */
  ulong fees_collected;            /* Total fees collected */
  ulong fees_burned;               /* Total fees burned */
} at_bank_metrics_t;

/* Slot state */
typedef enum {
  AT_BANK_SLOT_IDLE = 0,           /* Waiting for slot start */
  AT_BANK_SLOT_PROCESSING = 1,     /* Processing microblocks */
  AT_BANK_SLOT_FINALIZING = 2,     /* Finalizing block */
  AT_BANK_SLOT_COMPLETE = 3,       /* Slot complete */
} at_bank_slot_state_t;

/* Simulator modes (matches daemon config encoding) */
#define AT_BANK_SIM_NONE        (0U)
#define AT_BANK_SIM_BLOCKCHAIN  (1U)
#define AT_BANK_SIM_BLOCKDAG    (2U)
#define AT_BANK_SIM_STRESS      (3U)
#define AT_BANK_SIM_KEYS_CNT    (100UL)

/* Default configuration (must be before at_bank_block_t which uses these) */
#define AT_BANK_MAX_CU_PER_SLOT        (48000000UL)   /* 48M CU per slot */
#define AT_BANK_MAX_TXN_PER_SLOT       (1024UL)       /* Max txn per slot */
#define AT_BANK_SLOT_DURATION_NS       (400000000UL)  /* 400ms per slot */
#define AT_BANK_MAX_TXN_DATA_CAPACITY  (2097152UL)    /* 2MB txn data */

/* Block under construction */
typedef struct {
  uchar   block_hash[32];
  uchar   parent_hashes[AT_BLOCK_MAX_TIPS][32];
  uchar   parent_cnt;
  ulong   slot;
  ulong   height;
  ulong   timestamp_ms;
  uchar   miner[32];

  /* Transactions */
  ulong   txn_cnt;
  uchar * txn_data;                /* Concatenated raw transactions */
  ulong   txn_data_sz;
  ulong   txn_data_capacity;

  /* Transaction hashes (BLAKE3) for txs_root computation */
  uchar   txn_hashes[AT_BANK_MAX_TXN_PER_SLOT][32];

  /* Computed txs_root: BLAKE3( tx_hash[0] || tx_hash[1] || ... ) */
  uchar   txs_root[32];

  /* Execution state */
  ulong   total_cu;
  ulong   total_fees;
  ulong   burned_fees;
} at_bank_block_t;

/* Bank tile context */
typedef struct {
  /* Input link state */
  struct {
    at_wksp_t * mem;
    at_frag_meta_t * mcache;
    ulong *      fseq;
    ulong        link_id;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
    ulong       last_chunk;  /* Current chunk saved by during_frag */
  } in[ 32 ];
  ulong in_kind[ 32 ];
  ulong in_cnt;

  /* Output link state (to store tile) */
  at_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;
  ulong       out_mtu;

  /* Feedback output to pack tile (optional) */
  at_wksp_t * pack_out_mem;
  ulong       pack_out_chunk0;
  ulong       pack_out_wmark;
  ulong       pack_out_chunk;
  ulong       pack_out_mtu;

  /* Admin response output (to RPC tile) */
  at_frag_meta_t * admin_out_mcache; /* mcache ring buffer for publishing */
  ulong            admin_out_depth;  /* ring buffer depth */
  at_wksp_t * admin_out_mem;
  ulong       admin_out_chunk0;
  ulong       admin_out_wmark;
  ulong       admin_out_chunk;
  ulong       admin_out_mtu;

  /* Execution engine */
  at_executor_t     executor;
  at_store_t      * store;
  at_dag_provider_t * dag;
  at_alloc_t      * alloc;
  int               runtime_ready;

  at_wksp_t     * wksp;            /* Tile workspace */

  /* Current slot state */
  at_bank_slot_state_t slot_state;
  ulong                current_slot;
  ulong                slot_start_ns;
  ulong                slot_deadline_ns;
  ulong                last_tsorig;

  /* Block under construction */
  at_bank_block_t      block;

  /* Configuration */
  ulong  max_cu_per_slot;          /* Max compute units per slot */
  ulong  max_txn_per_slot;         /* Max transactions per slot */
  ulong  slot_duration_ns;         /* Slot duration in nanoseconds */
  uchar  identity[32];             /* Node identity (miner key) */
  uchar  network;                  /* Network type: 0=mainnet, 1=testnet, etc. */
  uchar  simulator_mode;           /* AT_BANK_SIM_* */
  ulong  simulator_next_tick_ns;   /* Next scheduled simulator tick */
  at_rng_t   simulator_rng_mem[1];
  at_rng_t * simulator_rng;
  uchar      simulator_privkeys[AT_BANK_SIM_KEYS_CNT][32];
  uchar      simulator_keys[AT_BANK_SIM_KEYS_CNT][32];

  /* Metrics */
  at_bank_metrics_t metrics;
} at_bank_ctx_t;

typedef int (*at_bank_publish_slot_fn_t)( at_bank_ctx_t * ctx, void * publish_ctx );
typedef int (*at_bank_admin_response_fn_t)( at_bank_ctx_t *                  ctx,
                                            at_bank_admin_resp_t const *     resp,
                                            void *                           response_ctx );

typedef struct {
  ulong        in_kind;   /* AT_BANK_IN_KIND_* */
  void const * wire_data; /* Input payload */
  ulong        wire_sz;   /* Input payload size */
  ulong        tsorig;    /* Source timestamp (0 allowed) */
} at_bank_input_t;

/* Tile run structure - defined in at_bank_tile.c */
extern at_topo_run_tile_t at_tile_bank;

/* Execute one external block message through DAG ingest + reorg/replay path.
   mode: AT_BANK_EXEC_BLOCK_MODE_*
   Returns 0 on success, >0 for skipped, <0 on hard failure. */
int
at_bank_execute_block_msg( at_bank_ctx_t *            ctx,
                           at_bank_block_msg_t const *msg,
                           uchar const *              block_data,
                           ulong                      mode );

/* Parse and execute one serialized at_bank_block_msg payload.
   `wire_data` points to:
     [at_bank_block_msg_t][raw block bytes ...]
   mode: AT_BANK_EXEC_BLOCK_MODE_*
   Returns 0 on success, >0 for skipped, <0 on hard failure. */
int
at_bank_execute_block_wire( at_bank_ctx_t * ctx,
                            void const *    wire_data,
                            ulong           wire_sz,
                            ulong           mode );

/* Dispatch helper for external block-like inputs.
   Supports AT_BANK_IN_KIND_REPLAY / AT_BANK_IN_KIND_GOSSIP / AT_BANK_IN_KIND_RPC_MINE.
   Returns:
     0 success, >0 skipped, <0 failure/unsupported kind. */
int
at_bank_execute_external_input( at_bank_ctx_t * ctx,
                                ulong           in_kind,
                                void const *    wire_data,
                                ulong           wire_sz );

/* Execute one pack microblock payload against current block-under-construction.
   Returns 0 on success, >0 if ignored (e.g. slot not processing), <0 on error. */
int
at_bank_execute_pack_microblock( at_bank_ctx_t * ctx,
                                 void const *    wire_data,
                                 ulong           wire_sz );

/* Finalize and rotate slot if trigger conditions are met.
   Trigger conditions match tile path:
     - now_ns >= slot_deadline_ns
     - block.total_cu >= max_cu_per_slot
     - block.txn_cnt >= max_txn_per_slot
   If `publish_fn` is non-NULL, it is invoked after successful block_finalize.
   Returns 0 when slot rotated, >0 when no-op, <0 on failure. */
int
at_bank_maybe_finalize_slot( at_bank_ctx_t *           ctx,
                             ulong                     now_ns,
                             at_bank_publish_slot_fn_t publish_fn,
                             void *                    publish_ctx );

/* Unified input dispatcher for bank execution path.
   Handles one input payload by kind (PACK / REPLAY / GOSSIP / RPC_MINE / ADMIN),
   then runs slot finalization check.
   Returns 0 on success, >0 for skipped/no-op, <0 on failure. */
int
at_bank_handle_input( at_bank_ctx_t *           ctx,
                      ulong                     in_kind,
                      void const *              wire_data,
                      ulong                     wire_sz,
                      ulong                     tsorig,
                      ulong                     now_ns,
                      at_bank_publish_slot_fn_t publish_fn,
                      void *                    publish_ctx );

/* Extended input dispatcher with pluggable admin response transport.
   `admin_response_fn` is used only for AT_BANK_IN_KIND_ADMIN.
   Returns 0 on success, >0 for skipped/no-op, <0 on failure. */
int
at_bank_handle_input_ex( at_bank_ctx_t *              ctx,
                         ulong                        in_kind,
                         void const *                 wire_data,
                         ulong                        wire_sz,
                         ulong                        tsorig,
                         ulong                        now_ns,
                         at_bank_publish_slot_fn_t    publish_fn,
                         void *                       publish_ctx,
                         at_bank_admin_response_fn_t  admin_response_fn,
                         void *                       admin_response_ctx );

/* Start slot-processing runtime state for bank execution.
   If `now_ns` is 0, implementation uses current monotonic time.
   Returns 0 on success, <0 on failure. */
int
at_bank_start_runtime( at_bank_ctx_t * ctx,
                       ulong           now_ns );

/* Periodic housekeeping tick for bank runtime (currently simulator scheduling).
   If `now_ns` is 0, implementation uses current monotonic time. */
void
at_bank_tick_housekeeping( at_bank_ctx_t * ctx,
                           ulong           now_ns );

/* Execute one parsed admin request. Business logic is transport-independent.
   If `response_fn` is non-NULL, it is called with generated response.
   Returns 0 on success, <0 on failure. */
int
at_bank_execute_admin_request( at_bank_ctx_t *              ctx,
                               at_bank_admin_req_t const *  req,
                               at_bank_admin_response_fn_t  response_fn,
                               void *                       response_ctx );

/* Execute one serialized admin request payload.
   `wire_data` points to at_bank_admin_req_t bytes.
   Returns 0 on success, <0 on failure. */
int
at_bank_execute_admin_request_wire( at_bank_ctx_t *             ctx,
                                    void const *                wire_data,
                                    ulong                       wire_sz,
                                    at_bank_admin_response_fn_t response_fn,
                                    void *                      response_ctx );

/* Map topology/input source name to AT_BANK_IN_KIND_*.
   Unknown names default to AT_BANK_IN_KIND_GOSSIP (current behavior). */
ulong
at_bank_input_kind_from_name( char const * link_name );

/* Serialize current block-under-construction into bank publish wire format:
   [block header][txn_cnt:ulong][raw txn bytes...]
   Returns 0 on success, <0 on error. */
int
at_bank_serialize_current_block( at_bank_ctx_t * ctx,
                                 void *          out_buf,
                                 ulong           out_cap,
                                 ulong *         out_sz );

/* Single-threaded runner helper for non-tile mode.
   Processes a batch of inputs, then runs finalize/housekeeping once.
   - If `now_ns` is 0, implementation uses current monotonic time.
   - `publish_fn` and `admin_response_fn` are optional.
   Returns 0 on success, <0 on failure. */
int
at_bank_run_once( at_bank_ctx_t *             ctx,
                  at_bank_input_t const *     inputs,
                  ulong                       input_cnt,
                  ulong                       now_ns,
                  at_bank_publish_slot_fn_t   publish_fn,
                  void *                      publish_ctx,
                  at_bank_admin_response_fn_t admin_response_fn,
                  void *                      admin_response_ctx );

/* Convenience wrapper: infer input kind from `source_name` and handle once.
   Returns 0 on success, >0 for skipped/no-op, <0 on failure. */
int
at_bank_handle_named_input( at_bank_ctx_t *              ctx,
                            char const *                 source_name,
                            void const *                 wire_data,
                            ulong                        wire_sz,
                            ulong                        tsorig,
                            ulong                        now_ns,
                            at_bank_publish_slot_fn_t    publish_fn,
                            void *                       publish_ctx,
                            at_bank_admin_response_fn_t  admin_response_fn,
                            void *                       admin_response_ctx );

AT_PROTOTYPES_END

#endif /* HEADER_at_disco_tiles_at_bank_tile_h */
