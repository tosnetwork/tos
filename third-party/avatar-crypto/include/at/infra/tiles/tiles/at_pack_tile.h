/* at_pack_tile.h - Avatar Pack Tile Header

   The pack tile receives verified transactions and packs them into
   microblocks for block production. It maintains a pool of pending
   transactions and selects the optimal set based on fees and compute
   budget. */

#ifndef HEADER_at_disco_tiles_at_pack_tile_h
#define HEADER_at_disco_tiles_at_pack_tile_h

#include "at/infra/tiles/at_topo.h"

AT_PROTOTYPES_BEGIN

/* Input link kinds */
#define AT_PACK_IN_KIND_DEDUP   (0UL)  /* From dedup tile */
#define AT_PACK_IN_KIND_GOSSIP  (1UL)  /* From gossip (vote transactions) */
#define AT_PACK_IN_KIND_BANK    (2UL)  /* From bank (pack feedback) */

/* Transaction pool entry */
typedef struct {
  ulong   sig_hash;       /* Hash of transaction signature for dedup */
  ulong   fee;            /* Transaction fee (for priority ordering) */
  ulong   compute_units;  /* Estimated compute units */
  ulong   expires_at;     /* Slot at which transaction expires */
  ulong   payload_sz;     /* Size of transaction payload */
  uchar * payload;        /* Pointer to transaction data in dcache */
} at_pack_txn_t;

/* Pack tile metrics */
typedef struct {
  ulong txn_received_cnt;       /* Total transactions received */
  ulong txn_packed_cnt;         /* Total transactions packed into blocks */
  ulong txn_expired_cnt;        /* Total transactions expired */
  ulong txn_dropped_cnt;        /* Total transactions dropped (pool full) */
  ulong microblock_cnt;         /* Total microblocks produced */
} at_pack_metrics_t;

/* Pack tile context - maintained in tile scratch space */
typedef struct {
  /* Input link state */
  struct {
    at_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
  } in[ 32 ];
  ulong in_kind[ 32 ];

  /* Output link state (to bank tile) */
  at_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;

  /* Transaction pool */
  at_pack_txn_t * pool;
  ulong           pool_cnt;
  ulong           pool_max;

  /* Current slot information */
  ulong           current_slot;
  int             is_leader;

  /* Microblock state */
  ulong           microblock_seq;
  ulong           microblock_txn_cnt;
  ulong           microblock_compute_units;

  /* Configuration */
  ulong           max_txn_per_microblock;
  ulong           max_compute_per_microblock;

  /* Metrics */
  at_pack_metrics_t metrics;
} at_pack_ctx_t;

/* Maximum transactions per microblock */
#define AT_PACK_MAX_TXN_PER_MICROBLOCK (64UL)

/* Maximum compute units per microblock */
#define AT_PACK_MAX_COMPUTE_PER_MICROBLOCK (12000000UL)

/* Default transaction pool size */
#define AT_PACK_DEFAULT_POOL_SZ (65536UL)

/* Tile run structure - defined in at_pack_tile.c */
extern at_topo_run_tile_t at_tile_pack;

AT_PROTOTYPES_END

#endif /* HEADER_at_disco_tiles_at_pack_tile_h */