#ifndef HEADER_at_disco_tiles_at_repair_tile_h
#define HEADER_at_disco_tiles_at_repair_tile_h

/* at_repair_tile.h - Avatar Block Repair Tile Header

   The repair tile handles recovery of missing blocks and transactions:
   - Detects gaps in the block chain
   - Requests missing data from peers using TOS ObjectRequest/ObjectResponse
   - Manages retry and timeout logic with inflight tracking
   - Computes block/TX hashes with SHA3-256

   TOS Protocol Constants:
   - PEER_TIMEOUT_REQUEST_OBJECT = 15 seconds
   - PEER_OBJECTS_CONCURRENCY    = 64 per peer
*/

#include "at/infra/tiles/at_topo.h"
#include "at/infra/spad/at_spad.h"
#include "at/p2p/at_peer.h"
#include "at/p2p/at_p2p_msg.h"
#include "at/crypto/at_sha3.h"
#include "at/core/blockdag/at_dag_provider.h"
#include "at/core/mempool/at_mempool.h"
#include "at/infra/at_util_base.h"

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* TOS Protocol Constants                                             */
/**********************************************************************/

#define AT_REPAIR_PEER_TIMEOUT_NS        (15000000000UL)  /* 15 seconds */
#define AT_REPAIR_OBJECTS_CONCURRENCY    (64UL)           /* Per peer */

/**********************************************************************/
/* Constants                                                          */
/**********************************************************************/

/* Maximum pending repair requests */
#define AT_REPAIR_MAX_PENDING  (1024UL)

/* Maximum inflight requests */
#define AT_REPAIR_INFLIGHT_MAX (256UL)

/* Request types */
#define AT_REPAIR_TYPE_TX      (1)  /* Transaction */
#define AT_REPAIR_TYPE_BLOCK   (2)  /* Block */
#define AT_REPAIR_TYPE_HEADER  (3)  /* Block header only */

/**********************************************************************/
/* Repair Request                                                     */
/**********************************************************************/

typedef struct {
  uchar hash[32];              /* Hash of missing item */
  uchar type;                  /* AT_REPAIR_TYPE_* */
  uchar _pad[7];

  ulong first_request;         /* When first requested */
  ulong last_request;          /* When last requested */
  uint  request_cnt;           /* Number of requests sent */
  uint  peer_idx;              /* Index of peer we last asked */

} at_repair_request_t;

/**********************************************************************/
/* Repair Metrics                                                     */
/**********************************************************************/

typedef struct {
  ulong requests_sent;         /* Total requests sent */
  ulong requests_fulfilled;    /* Requests that received data */
  ulong requests_timeout;      /* Requests that timed out */
  ulong items_repaired;        /* Items successfully repaired */
  ulong items_failed;          /* Items that couldn't be repaired */
  ulong avg_rtt_ns;            /* Average round-trip time */
} at_repair_metrics_t;

/**********************************************************************/
/* Inflight Request Tracking                                          */
/**********************************************************************/

typedef struct {
  uchar hash[32];              /* Hash of requested item */
  uchar obj_type;              /* AT_OBJ_TYPE_* */
  uchar _pad[3];
  uint  peer_idx;              /* Peer we sent request to */
  ulong sent_time;             /* When request was sent (for RTT) */
} at_repair_inflight_t;

/**********************************************************************/
/* Repair State                                                       */
/**********************************************************************/

typedef struct {
  /* Pending requests */
  at_repair_request_t pending[AT_REPAIR_MAX_PENDING];
  ulong               pending_cnt;

  /* Inflight requests (sent but not yet received) */
  at_repair_inflight_t inflight[AT_REPAIR_INFLIGHT_MAX];
  ulong                inflight_cnt;

  /* Configuration */
  ulong request_timeout_ns;    /* Timeout for single request */
  ulong max_retry_cnt;         /* Max retries before giving up */
  ulong retry_interval_ns;     /* Interval between retries */

  /* Round-robin peer selection */
  uint  next_peer_idx;

  /* RTT tracking */
  ulong total_rtt_ns;          /* Sum of RTTs for averaging */
  ulong rtt_sample_cnt;        /* Number of RTT samples */

} at_repair_state_t;

/**********************************************************************/
/* Repair Context                                                     */
/**********************************************************************/

/* Maximum block/TX data size for ObjectResponse */
#define AT_REPAIR_MAX_OBJECT_DATA_SZ  (65536UL)

/* Object response buffer: 1 byte type + max object data + margin */
#define AT_REPAIR_OBJECT_RESP_BUF_SZ  (AT_REPAIR_MAX_OBJECT_DATA_SZ + 256UL)

/* Spad memory size for repair tile (8KB for temporary allocations) */
#define AT_REPAIR_SPAD_MEM_MAX  (8192UL)

typedef struct {
  /* Input link state (increased from 16 to 32 to handle complex topologies) */
  struct {
    at_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
  } in[ 32 ];

  /* Output link state (to net for sending requests) */
  struct {
    at_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       chunk;
    ulong       mtu;
    ulong       idx;
    ulong       credits;
    ulong       max_credits;
  } net_out;

  /* Scratch pad for temporary allocations in hot paths */
  at_spad_t * spad;

  /* Peer pool reference (for peer lookup and sending) */
  at_peer_pool_t * peer_pool;

  /* BlockDAG provider for storage and validation */
  at_dag_provider_t * dag;

  /* Mempool for TX lookups (ObjectRequest responses) */
  at_mempool_t * mempool;

  /* Local network identity */
  uint   our_ip_addr;
  ushort our_port;

  /* SHA3-256 context for block/TX hashing */
  at_sha3_256_t sha3[1];

  /* Current time (updated each housekeeping) */
  ulong now;

  /* Repair state */
  at_repair_state_t repair;

  /* Pending object response (built on receive, sent in after_credit) */
  uint  pending_obj_resp_peer_idx;
  ulong pending_obj_resp_sz;
  int   pending_obj_resp_ready;
  uchar pending_obj_resp_buf[AT_REPAIR_OBJECT_RESP_BUF_SZ];

  /* Temporary buffer for object data (used during ObjectRequest handling) */
  uchar pending_obj_data_buf[AT_REPAIR_MAX_OBJECT_DATA_SZ];

  /* Metrics */
  at_repair_metrics_t metrics;

} at_repair_ctx_t;

/**********************************************************************/
/* Configuration Defaults                                             */
/**********************************************************************/

#define AT_REPAIR_REQUEST_TIMEOUT_NS  (10000000000UL)  /* 10 seconds */
#define AT_REPAIR_MAX_RETRY           (5UL)
#define AT_REPAIR_RETRY_INTERVAL_NS   (5000000000UL)   /* 5 seconds */

/**********************************************************************/
/* Repair API                                                         */
/**********************************************************************/

/* at_repair_state_init initializes repair state (without DAG). */
void
at_repair_state_init( at_repair_state_t * state );

/* at_repair_ctx_init initializes repair context with DAG provider and mempool. */
void
at_repair_ctx_init( at_repair_ctx_t * ctx, at_dag_provider_t * dag, at_mempool_t * mempool );

/* at_repair_request adds an item to the repair queue.
   Returns 0 on success, -1 if queue is full, -2 if already pending. */
int
at_repair_request( at_repair_state_t * state,
                   uchar const         hash[32],
                   uchar               type,
                   ulong               now );

/* at_repair_on_data marks an item as received.
   Returns 0 if item was pending, -1 if not found. */
int
at_repair_on_data( at_repair_state_t * state,
                   uchar const         hash[32],
                   uchar               type );

/* at_repair_get_pending_cnt returns number of pending requests. */
static inline ulong
at_repair_get_pending_cnt( at_repair_state_t const * state ) {
  return state->pending_cnt;
}

/* at_repair_is_pending checks if an item is pending repair.
   Returns 1 if pending, 0 if not. */
int
at_repair_is_pending( at_repair_state_t const * state,
                      uchar const               hash[32],
                      uchar                     type );

/**********************************************************************/
/* Inflight Tracking API                                              */
/**********************************************************************/

/* at_repair_inflight_add adds a request to inflight tracking.
   Returns pointer to new entry, or NULL if full. */
at_repair_inflight_t *
at_repair_inflight_add( at_repair_state_t * state,
                        uchar const         hash[32],
                        uchar               obj_type,
                        uint                peer_idx,
                        ulong               now );

/* at_repair_inflight_remove removes a request by hash and returns RTT.
   Returns RTT in nanoseconds, or 0 if not found. */
ulong
at_repair_inflight_remove( at_repair_state_t * state,
                           uchar const         hash[32],
                           ulong               now );

/* at_repair_inflight_expire removes timed-out requests.
   Returns number of expired requests. */
ulong
at_repair_inflight_expire( at_repair_state_t * state,
                           ulong               timeout_ns,
                           ulong               now );

/* at_repair_inflight_find finds an inflight request by hash.
   Returns pointer to entry, or NULL if not found. */
at_repair_inflight_t *
at_repair_inflight_find( at_repair_state_t * state,
                         uchar const         hash[32] );

/* at_repair_inflight_is_tracked returns 1 if hash is inflight. */
static inline int
at_repair_inflight_is_tracked( at_repair_state_t const * state,
                               uchar const               hash[32] ) {
  for( ulong i = 0; i < state->inflight_cnt; i++ ) {
    if( at_memcmp( state->inflight[i].hash, hash, 32 ) == 0 ) {
      return 1;
    }
  }
  return 0;
}

/**********************************************************************/
/* Hash Computation API                                               */
/**********************************************************************/

/* at_repair_compute_block_hash computes SHA3-256 hash of block data.
   Writes 32-byte hash to out_hash. */
void
at_repair_compute_block_hash( at_sha3_256_t * sha3,
                              void const *    block_data,
                              ulong           block_sz,
                              uchar           out_hash[32] );

/* at_repair_compute_tx_hash computes SHA3-256 hash of transaction.
   Writes 32-byte hash to out_hash. */
void
at_repair_compute_tx_hash( at_sha3_256_t * sha3,
                           void const *    tx_data,
                           ulong           tx_sz,
                           uchar           out_hash[32] );

/**********************************************************************/
/* Tile Export                                                        */
/**********************************************************************/

extern at_topo_run_tile_t at_tile_repair;

AT_PROTOTYPES_END

#endif /* HEADER_at_disco_tiles_at_repair_tile_h */