/* at_gossip_tile.h - Avatar Gossip Tile Header

   The gossip tile implements the peer-to-peer gossip protocol for
   validator discovery, cluster information propagation, and vote
   collection.

   TOS Propagation Rules:
   - Block propagation: peer within STABLE_LIMIT (24) blocks of block height
   - TX propagation: peer within STABLE_LIMIT of our topoheight
   - Common peer detection: skip sending to peers that likely already have the data
*/

#ifndef HEADER_at_disco_tiles_at_gossip_tile_h
#define HEADER_at_disco_tiles_at_gossip_tile_h

#include "at/infra/tiles/at_topo.h"
#include "at/infra/spad/at_spad.h"
#include "at/p2p/at_peer.h"
#include "at/p2p/at_p2p_cache.h"
#include "at/p2p/at_p2p_msg.h"
#include "at/p2p/at_bloom.h"
#include "at/p2p/at_p2p_security.h"
#include "at/core/blockdag/at_dag_provider.h"
#include "at/core/mempool/at_mempool.h"

AT_PROTOTYPES_BEGIN

/* Gossip message types (legacy, for compatibility) */
#define AT_GOSSIP_MSG_PULL_REQUEST   (0UL)
#define AT_GOSSIP_MSG_PULL_RESPONSE  (1UL)
#define AT_GOSSIP_MSG_PUSH           (2UL)
#define AT_GOSSIP_MSG_PRUNE          (3UL)
#define AT_GOSSIP_MSG_PING           (4UL)
#define AT_GOSSIP_MSG_PONG           (5UL)

/**********************************************************************/
/* TOS Protocol Constants                                             */
/**********************************************************************/

/* Stability limit for gossip propagation */
#define AT_GOSSIP_STABLE_LIMIT              (24UL)

/* Prune safety limit (24 * 10) */
#define AT_GOSSIP_PRUNE_SAFETY_LIMIT        (240UL)

/* Block propagation capacity (24 * 3) */
#define AT_GOSSIP_BLOCKS_PROPAGATION_CAP    (72UL)

/* Timing intervals (nanoseconds) */
#define AT_GOSSIP_PING_INTERVAL_NS          (30UL * 1000000000UL)   /* 30 seconds */
#define AT_GOSSIP_PEER_DISCOVERY_INTERVAL   (60UL * 1000000000UL)   /* 60 seconds */
#define AT_GOSSIP_HOUSEKEEPING_INTERVAL     (10UL * 1000000000UL)   /* 10 seconds */
#define AT_GOSSIP_CHAIN_SYNC_DELAY_NS       (5UL * 1000000000UL)    /* 5 seconds */
#define AT_GOSSIP_CHAIN_SYNC_TIMEOUT_NS     (15UL * 1000000000UL)   /* 15 seconds */

/* Chain sync constants */
#define AT_GOSSIP_CHAIN_SYNC_MAX_BLOCKS     (64UL)
#define AT_GOSSIP_CHAIN_SYNC_RESPONSE_MIN   (512UL)
#define AT_GOSSIP_CHAIN_SYNC_RESPONSE_MAX   (65535UL)
#define AT_GOSSIP_CHAIN_SYNC_TOP_BLOCKS     (10UL)

/* Maximum number of peers tracked */
#define AT_GOSSIP_MAX_PEERS (10000UL)

/* Sign queue size */
#define AT_GOSSIP_SIGN_QUEUE_MAX            (128UL)

/* In-flight sign requests */
#define AT_GOSSIP_SIGN_INFLIGHT_MAX         (64UL)

/* Peer entry in the gossip table */
typedef struct {
  uchar  pubkey[ 32 ];    /* Peer's public key */
  uint   ip_addr;         /* Peer's IP address */
  ushort gossip_port;     /* Peer's gossip port */
  ushort tpu_port;        /* Peer's TPU port */
  ulong  last_seen;       /* Timestamp of last contact */
  ulong  stake;           /* Peer's stake weight */
  int    is_active;       /* Whether peer is considered active */
} at_gossip_peer_t;

/* Gossip tile metrics */
typedef struct {
  ulong messages_received_cnt;   /* Total gossip messages received */
  ulong messages_sent_cnt;       /* Total gossip messages sent */
  ulong peers_active_cnt;        /* Currently active peers */
  ulong peers_discovered_cnt;    /* Total peers discovered */
  ulong pull_requests_cnt;       /* Pull requests sent */
  ulong push_messages_cnt;       /* Push messages sent */
  ulong blocks_propagated_cnt;   /* Blocks propagated */
  ulong txs_propagated_cnt;      /* TXs propagated */
  ulong duplicates_filtered_cnt; /* Duplicate messages filtered */
} at_gossip_metrics_t;

/**********************************************************************/
/* Sign Request Types                                                 */
/**********************************************************************/

typedef enum {
  AT_SIGN_REQ_PING        = 0,
  AT_SIGN_REQ_BLOCK_PROP  = 1,
  AT_SIGN_REQ_TX_PROP     = 2,
  AT_SIGN_REQ_OBJECT_REQ  = 3,
  AT_SIGN_REQ_CHAIN_REQ   = 4,
  AT_SIGN_REQ_NOTIFY_INV_REQ  = 5,
  AT_SIGN_REQ_NOTIFY_INV_RESP = 6,
} at_sign_req_type_t;

/* Pending sign request */
typedef struct {
  at_sign_req_type_t type;       /* Request type */
  uint               peer_idx;   /* Target peer index */
  uchar              data[1024]; /* Serialized message to sign */
  ulong              data_sz;    /* Size of data */
  ulong              pending_key;/* For tracking in-flight signs */
} at_sign_pending_t;

/* In-flight sign request tracker */
typedef struct {
  ulong              key;        /* Pending key for matching responses */
  at_sign_pending_t  req;        /* Original request */
} at_sign_req_t;

/**********************************************************************/
/* Link Output State                                                  */
/**********************************************************************/

typedef struct {
  at_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
  ulong       mtu;
  ulong       idx;               /* Output link index */
  ulong       credits;           /* Available credits */
  ulong       max_credits;       /* Maximum credits (depth) */
} at_gossip_out_link_t;

/* Spad memory size for gossip tile (16KB for temporary allocations) */
#define AT_GOSSIP_SPAD_MEM_MAX  (16384UL)

/* Gossip tile context - maintained in tile scratch space */
typedef struct {
  /* Input link state (increased from 16 to 32 to handle complex topologies) */
  struct {
    at_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
  } in[ 32 ];

  /* Scratch pad for temporary allocations in hot paths */
  at_spad_t * spad;

  /* Output link state (to sign tile for signatures) */
  at_gossip_out_link_t sign_out;

  /* Output link state (to net tile for sending) */
  at_gossip_out_link_t net_out;

  /* Output link state (to bank tile for block execution) */
  at_gossip_out_link_t bank_out;

  /* Optional output link state (to sync tile for legacy chain-response forwarding) */
  at_gossip_out_link_t sync_out;

  /* Sign input link index (for responses from sign tile) */
  ulong                sign_in_idx;

  /* Our identity */
  uchar       identity[ 32 ];    /* Our public key */
  uint        our_ip_addr;       /* Our IP address */
  ushort      our_gossip_port;   /* Our gossip port */

  /* Legacy peer table (for gossip compatibility) */
  at_gossip_peer_t * peers;
  ulong              peer_cnt;
  ulong              peer_max;

  /* TOS peer pool (for TOS P2P protocol) */
  at_peer_pool_t     peer_pool;

  /* Per-peer propagation state - pointer to allocated array */
  at_peer_propagation_t * peer_propagation;

  /* Global bloom filters for duplicate detection */
  at_bloom_t         global_tx_bloom;
  at_bloom_t         global_block_bloom;

  /* BlockDAG provider for chain state queries */
  at_dag_provider_t * dag;

  /* Mempool for transaction queries */
  at_mempool_t * mempool;

  /* Our chain state */
  ulong              our_height;        /* Block height */
  ulong              our_topoheight;    /* Topological height */
  uchar              our_top_hash[32];  /* Current top block hash */
  at_cumulative_diff_t our_cumulative_diff; /* PoW difficulty */

  /* Timing state */
  ulong              now;                    /* Current timestamp */
  ulong              last_ping_broadcast;    /* Last ping broadcast time */
  ulong              last_peer_discovery;    /* Last peer discovery time */
  ulong              last_housekeeping;      /* Last housekeeping time */

  /* Protocol state (legacy) */
  ulong       last_pull_time;    /* Last time we sent pull requests */
  ulong       last_push_time;    /* Last time we sent push messages */
  ulong       pull_interval_ns;  /* Interval between pull requests */
  ulong       push_interval_ns;  /* Interval between push messages */

  /* Sign queue */
  at_sign_pending_t  sign_queue[ AT_GOSSIP_SIGN_QUEUE_MAX ];
  uint               sign_queue_head;
  uint               sign_queue_tail;
  uint               sign_queue_cnt;
  ulong              next_pending_key;

  /* In-flight sign requests */
  at_sign_req_t      sign_inflight[ AT_GOSSIP_SIGN_INFLIGHT_MAX ];

  /* Security */
  at_ping_tracker_t  ping_tracker;
  at_rate_limiter_t  rate_limiter;

  /* Random state for peer selection */
  ulong       rng_state;

  /* Pending block to publish to bank (staged in handle_block_propagation,
     published in after_credit where stem is available) */
  int         pending_bank_block_ready;
  ulong       pending_bank_block_sz;
  uchar       pending_bank_block_hash[32];
  uchar       pending_bank_block_data[65536];  /* Max block size */

  /* Pending ChainResponse to publish to sync tile as AT_P2P_DISPATCH_SIG */
  int         pending_sync_chain_ready;
  uint        pending_sync_chain_peer_idx;
  ulong       pending_sync_chain_payload_sz;
  uchar       pending_sync_chain_payload[65536];

  /* Metrics */
  at_gossip_metrics_t metrics;
} at_gossip_ctx_t;

/* Default intervals */
#define AT_GOSSIP_PULL_INTERVAL_NS (1000000000UL)  /* 1 second */
#define AT_GOSSIP_PUSH_INTERVAL_NS (500000000UL)   /* 500ms */

/* Tile run structure - defined in at_gossip_tile.c */
extern at_topo_run_tile_t at_tile_gossip;

/**********************************************************************/
/* TOS Propagation Filters                                            */
/**********************************************************************/

/* at_should_propagate_block checks if a block should be propagated to peer.
   Based on TOS: ~/tos/daemon/src/p2p/mod.rs:3688-3693
   Returns 1 if should propagate, 0 otherwise. */
static inline int
at_should_propagate_block( ulong peer_height, ulong block_height ) {
  /* Case 1: Peer ahead or same - within STABLE_LIMIT */
  if( peer_height >= block_height ) {
    if( peer_height - block_height <= AT_GOSSIP_STABLE_LIMIT ) return 1;
  }
  /* Case 2: Peer behind - at most 1 block behind */
  if( block_height >= peer_height ) {
    if( block_height - peer_height <= 1 ) return 1;
  }
  return 0;
}

/* at_should_propagate_tx checks if a TX should be propagated to peer.
   Returns 1 if should propagate, 0 otherwise. */
static inline int
at_should_propagate_tx( ulong peer_topo, ulong our_topo ) {
  ulong diff;
  if( peer_topo >= our_topo ) {
    diff = peer_topo - our_topo;
  } else {
    diff = our_topo - peer_topo;
  }
  return diff < AT_GOSSIP_STABLE_LIMIT;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_disco_tiles_at_gossip_tile_h */
