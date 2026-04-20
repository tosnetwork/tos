#ifndef HEADER_at_disco_tiles_at_sync_tile_h
#define HEADER_at_disco_tiles_at_sync_tile_h

/* at_sync_tile.h - Avatar Chain Sync Tile Header

   The sync tile handles blockchain synchronization with peers:
   - Initial block download (IBD)
   - Catching up to tip
   - TOS ChainRequest/ChainResponse protocol

   TOS Chain Sync Protocol:
   - ChainRequest sends exponential sampling of block IDs (first 30 consecutive,
     then gaps double: 1,2,4,8,16...)
   - ChainResponse returns common point + block hashes from common point forward
   - Top blocks (alternative tips) included for BlockDAG

   Protocol Constants:
   - CHAIN_SYNC_DELAY         = 5 seconds between sync attempts
   - CHAIN_SYNC_TIMEOUT       = 15 seconds request timeout
   - CHAIN_REQUEST_MAX_BLOCKS = 64 block IDs in request
   - CHAIN_RESPONSE_MAX       = 65535 blocks in response
*/

#include "at/infra/tiles/at_topo.h"
#include "at/infra/spad/at_spad.h"
#include "at/infra/alloc/at_alloc.h"
#include "at/p2p/at_peer.h"
#include "at/p2p/at_p2p_msg.h"
#include "at/crypto/at_sha3.h"
#include "at/core/blockdag/at_dag_provider.h"
#include "at/core/storage/at_store.h"

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* TOS Protocol Constants                                             */
/**********************************************************************/

/* Note: AT_CHAIN_REQUEST_MAX_BLOCKS and AT_CHAIN_RESPONSE_MAX_BLOCKS
   are defined in at_p2p_msg.h */

#define AT_CHAIN_SYNC_DELAY_NS           (5000000000UL)   /* 5 seconds */
#define AT_CHAIN_SYNC_TIMEOUT_NS         (15000000000UL)  /* 15 seconds */
#define AT_CHAIN_SYNC_TOP_BLOCKS         (10UL)
#define AT_CHAIN_STABLE_LIMIT            (24UL)

/* Consecutive block sampling threshold (first 30, then exponential) */
#define AT_CHAIN_SYNC_CONSECUTIVE_LIMIT  (30UL)

/**********************************************************************/
/* Sync State Machine                                                 */
/**********************************************************************/

#define AT_SYNC_STATE_IDLE        (0)  /* Fully synced, monitoring tip */
#define AT_SYNC_STATE_FIND_PEERS  (1)  /* Looking for sync peers */
#define AT_SYNC_STATE_HEADERS     (2)  /* Downloading headers (chain request) */
#define AT_SYNC_STATE_BLOCKS      (3)  /* Downloading blocks */
#define AT_SYNC_STATE_CATCHUP     (4)  /* Catching up to tip */
#define AT_SYNC_STATE_BOOTSTRAP   (5)  /* Fast-sync via bootstrap protocol */

/**********************************************************************/
/* Bootstrap State Machine (Fast-Sync)                                */
/**********************************************************************/

#define AT_BOOTSTRAP_STATE_IDLE                   (0)
#define AT_BOOTSTRAP_STATE_CHAIN_INFO             (1)
#define AT_BOOTSTRAP_STATE_ASSETS                 (2)
#define AT_BOOTSTRAP_STATE_ASSETS_SUPPLY          (3)
#define AT_BOOTSTRAP_STATE_KEYS                   (4)
#define AT_BOOTSTRAP_STATE_KEY_BALANCES           (5)
#define AT_BOOTSTRAP_STATE_SPENDABLE_BALANCES     (6)
#define AT_BOOTSTRAP_STATE_ACCOUNTS               (7)
#define AT_BOOTSTRAP_STATE_CONTRACTS              (8)
#define AT_BOOTSTRAP_STATE_CONTRACT_MODULE        (9)
#define AT_BOOTSTRAP_STATE_CONTRACT_BALANCES      (10)
#define AT_BOOTSTRAP_STATE_CONTRACT_STORES        (11)
#define AT_BOOTSTRAP_STATE_CONTRACTS_EXECUTIONS   (12)
#define AT_BOOTSTRAP_STATE_BLOCKS_METADATA        (13)
#define AT_BOOTSTRAP_STATE_COMPLETE               (14)

/**********************************************************************/
/* Sync Metrics                                                       */
/**********************************************************************/

typedef struct {
  ulong headers_received;       /* Total headers received */
  ulong blocks_received;        /* Total blocks received */
  ulong blocks_validated;       /* Blocks that passed validation */
  ulong blocks_rejected;        /* Blocks that failed validation */
  ulong sync_started_cnt;       /* Number of sync attempts */
  ulong sync_completed_cnt;     /* Number of successful syncs */
} at_sync_metrics_t;

/**********************************************************************/
/* Chain Sync State (TOS Protocol)                                    */
/**********************************************************************/

typedef struct {
  /* Exponential sample block ID list for chain request */
  at_block_id_t  block_ids[AT_CHAIN_REQUEST_MAX_BLOCKS];
  uchar          block_id_cnt;

  /* Common point found in chain response */
  uchar          common_point_hash[32];
  ulong          common_point_height;  /* topoheight */
  int            has_common_point;

  /* Response blocks to download */
  uchar          response_hashes[512][32];  /* Block hashes from response */
  ushort         response_block_cnt;
  ushort         response_blocks_downloaded;

  /* Last block tracking for block_id_list.
     TOS assigns topoheight = common_point_topoheight + block_index + 1 */
  uchar          last_block_hash[32];      /* Hash of last block in response */
  ulong          last_block_topoheight;    /* TOS-assigned topoheight of last block */

  /* Timing */
  ulong          last_chain_request_time;
  ulong          last_chain_response_time;

} at_chain_sync_t;

/**********************************************************************/
/* Bootstrap Sync State (Fast-Sync Protocol)                          */
/**********************************************************************/

typedef struct {
  /* Current bootstrap step */
  int    state;                  /* AT_BOOTSTRAP_STATE_* */

  /* Target chain state (from chain info response) */
  ulong  target_topoheight;      /* Sync target topoheight */
  ulong  stable_topoheight;      /* Stable topoheight from peer */
  uchar  top_hash[32];           /* Top block hash from peer */

  /* Common point tracking */
  int    has_common_point;       /* 1 if we found common point with peer */
  uchar  common_hash[32];        /* Common point block hash */
  ulong  common_topoheight;      /* Common point topoheight */

  /* Pagination state for current step */
  ulong  current_page;           /* Current page number (0 = first) */
  int    has_more_pages;         /* 1 if more pages expected */
  ulong  min_topoheight;         /* Min topoheight for current step */
  ulong  max_topoheight;         /* Max topoheight for current step */

  /* Current iteration key (for key_balances, spendable_balances) */
  uchar  current_key[32];        /* Current public key being processed */
  ushort current_key_idx;        /* Index in keys array */

  /* Current contract (for contract_* steps) */
  uchar  current_contract[32];   /* Current contract being processed */
  ushort current_contract_idx;   /* Index in contracts array */

  /* Collected keys and contracts from discovery steps */
  uchar (*discovered_keys)[32];  /* Array of discovered public keys */
  ushort discovered_keys_cnt;    /* Number of discovered keys */
  ushort discovered_keys_cap;    /* Capacity of keys array */

  uchar (*discovered_contracts)[32]; /* Array of discovered contracts */
  ushort discovered_contracts_cnt;   /* Number of discovered contracts */
  ushort discovered_contracts_cap;   /* Capacity of contracts array */

  /* Progress counters */
  ulong  assets_synced;          /* Total assets synced */
  ulong  keys_synced;            /* Total keys synced */
  ulong  balances_synced;        /* Total balance entries synced */
  ulong  accounts_synced;        /* Total accounts synced */
  ulong  contracts_synced;       /* Total contracts synced */
  ulong  blocks_synced;          /* Total block metadata synced */

  /* Timing */
  ulong  step_started;           /* Timestamp when current step started */
  ulong  last_response;          /* Timestamp of last response */

} at_bootstrap_sync_t;

/**********************************************************************/
/* Sync State                                                         */
/**********************************************************************/

typedef struct {
  int    state;                 /* AT_SYNC_STATE_* */

  /* Current sync progress */
  ulong  local_height;          /* Our current block height */
  ulong  target_height;         /* Target height to sync to */
  uchar  local_tip[32];         /* Our current tip hash */
  uchar  target_tip[32];        /* Target tip hash */
  ulong  local_topoheight;      /* Our current topoheight */

  /* Sync peer */
  uint   sync_peer_idx;         /* Index of peer we're syncing from */
  uint   sync_peer_ip;          /* IP of peer we're syncing from */
  ushort sync_peer_port;        /* Port of sync peer */
  ulong  sync_started;          /* Timestamp when sync started */
  ulong  last_progress;         /* Timestamp of last progress */

  /* Header download state */
  ulong  headers_requested;     /* Number of headers requested */
  ulong  headers_received;      /* Number of headers received */

  /* Block download state */
  ulong  blocks_in_flight;      /* Blocks currently being downloaded */
  ulong  blocks_received;       /* Blocks received this sync */

  /* Timeout tracking */
  ulong  last_request_time;     /* Time of last request sent */
  uint   timeout_cnt;           /* Consecutive timeouts */

  /* Chain sync protocol state */
  at_chain_sync_t chain_sync;

  /* Bootstrap sync protocol state (fast-sync) */
  at_bootstrap_sync_t bootstrap;

} at_sync_state_t;

/**********************************************************************/
/* Sync Context                                                       */
/**********************************************************************/

#define AT_SYNC_CHAIN_RESPONSE_BUF_SZ (20000UL)

/* Spad memory size for sync tile (16KB for temporary allocations) */
#define AT_SYNC_SPAD_MEM_MAX  (16384UL)

typedef struct {
  /* Input link state (increased from 16 to 32 to handle complex topologies) */
  struct {
    at_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
    ulong       last_chunk;  /* Saved chunk from during_frag for after_frag */
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

  /* Output link state (to bank tile for block execution) */
  struct {
    at_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       chunk;
    ulong       mtu;
    ulong       idx;
  } bank_out;

  /* Scratch pad for temporary allocations in hot paths */
  at_spad_t * spad;

  /* Peer pool reference (for peer lookup and sending) */
  at_peer_pool_t * peer_pool;

  /* BlockDAG provider for chain state queries */
  at_dag_provider_t * dag;

  /* Storage backend (NULL if using memory provider) */
  at_store_t * store;
  at_alloc_t * alloc;

  /* Transaction execution (TBPF VM integration) */
  struct at_executor * executor;      /* For sync-time TX execution (always enabled) */

  /* Local network identity */
  uint   our_ip_addr;
  ushort our_port;
  uchar  network;       /* Network type: 0=mainnet, 1=testnet, 2=stagenet, 3=devnet */

  /* SHA3-256 context for block hashing */
  at_sha3_256_t sha3[1];

  /* Sync state */
  at_sync_state_t sync;

  /* Pending chain response (built on receive, sent in after_credit) */
  uint  pending_chain_resp_peer_idx;
  ulong pending_chain_resp_sz;
  int   pending_chain_resp_ready;
  uchar pending_chain_resp_buf[AT_SYNC_CHAIN_RESPONSE_BUF_SZ];

  /* Pending block to publish to bank (built on receive, sent in after_credit) */
  int   pending_bank_block_ready;
  ulong pending_bank_block_topoheight;
  ulong pending_bank_block_sz;
  uchar pending_bank_block_hash[32];
  uchar pending_bank_block_data[65536];  /* Max block size */

  /* Configuration */
  ulong chain_sync_delay_ns;    /* Delay between sync attempts */
  ulong request_timeout_ns;     /* Request timeout */
  ulong sync_timeout_ns;        /* Overall sync timeout */
  uint  max_headers_per_request;
  uint  max_blocks_in_flight;

  /* Current time (updated each housekeeping) */
  ulong now;

  /* Metrics */
  at_sync_metrics_t metrics;

} at_sync_ctx_t;

/**********************************************************************/
/* Configuration Defaults                                             */
/**********************************************************************/

#define AT_SYNC_REQUEST_TIMEOUT_NS    (15000000000UL)   /* 15 seconds (TOS) */
#define AT_SYNC_TIMEOUT_NS            (600000000000UL)  /* 10 minutes */
#define AT_SYNC_MAX_HEADERS_PER_REQ   (2000UL)
#define AT_SYNC_MAX_BLOCKS_IN_FLIGHT  (16UL)
#define AT_SYNC_DELAY_NS              (5000000000UL)    /* 5 seconds between syncs */

/**********************************************************************/
/* Sync API                                                           */
/**********************************************************************/

/* at_sync_state_init initializes sync state (without DAG). */
void
at_sync_state_init( at_sync_state_t * state );

/* at_sync_ctx_init initializes sync context with DAG provider.
   This updates local chain state from the DAG. */
void
at_sync_ctx_init( at_sync_ctx_t * ctx, at_dag_provider_t * dag );

/* at_sync_start_sync begins synchronization with a peer.
   Returns 0 on success, -1 if already syncing. */
int
at_sync_start_sync( at_sync_state_t * state,
                    uint              peer_idx,
                    uint              peer_ip,
                    ushort            peer_port,
                    ulong             peer_height,
                    uchar const       peer_tip[32],
                    ulong             now );

/* at_sync_is_syncing returns 1 if sync is in progress. */
static inline int
at_sync_is_syncing( at_sync_state_t const * state ) {
  return state->state != AT_SYNC_STATE_IDLE;
}

/* at_sync_is_synced returns 1 if fully synced. */
static inline int
at_sync_is_synced( at_sync_state_t const * state ) {
  return state->state == AT_SYNC_STATE_IDLE &&
         state->local_height >= state->target_height;
}

/* at_sync_get_progress returns sync progress as percentage (0-100). */
static inline uint
at_sync_get_progress( at_sync_state_t const * state ) {
  if( state->target_height == 0 ) return 100;
  if( state->local_height >= state->target_height ) return 100;
  return (uint)((state->local_height * 100) / state->target_height);
}

/**********************************************************************/
/* Chain Sync Protocol API                                            */
/**********************************************************************/

/* at_sync_build_block_id_list builds exponential sampling of block IDs.
   First 30 blocks: consecutive (gaps of 1)
   After 30: exponential gaps (2, 4, 8, 16, ...)
   Always includes genesis at end.
   Uses DAG provider to query block hashes at topoheights.
   Network parameter selects correct genesis: 0=mainnet, 1=testnet, 2=stagenet, 3=devnet.
   Returns number of block IDs written to out_blocks. */
uchar
at_sync_build_block_id_list( at_dag_provider_t * dag,
                             at_sync_state_t *   state,
                             at_block_id_t *     out_blocks,
                             uchar               max_blocks,
                             uchar               network );

/* at_sync_find_common_point finds the common point in peer's block ID list.
   Uses DAG provider to check which blocks we have.
   Returns 0 if common point found, -1 if not found.
   out_hash receives the common point hash.
   out_height receives the common point height. */
int
at_sync_find_common_point( at_dag_provider_t *   dag,
                           at_block_id_t const * peer_blocks,
                           uchar                 peer_block_cnt,
                           uchar                 out_hash[32],
                           ulong *               out_height );

/**********************************************************************/
/* Bootstrap Sync Protocol API                                        */
/**********************************************************************/

/* at_sync_bootstrap_init initializes bootstrap sync state.
   Must be called before starting bootstrap sync. */
void
at_sync_bootstrap_init( at_bootstrap_sync_t * bootstrap );

/* at_sync_bootstrap_start begins bootstrap synchronization with a peer.
   Returns 0 on success, -1 if already syncing. */
int
at_sync_bootstrap_start( at_sync_state_t * state,
                         uint              peer_idx,
                         ulong             target_topoheight,
                         ulong             now );

/* at_sync_bootstrap_advance advances to the next bootstrap step.
   Called when current step is complete.
   Returns next state, or AT_BOOTSTRAP_STATE_COMPLETE when done. */
int
at_sync_bootstrap_advance( at_bootstrap_sync_t * bootstrap );

/* at_sync_bootstrap_is_complete returns 1 if bootstrap sync is complete. */
static inline int
at_sync_bootstrap_is_complete( at_bootstrap_sync_t const * bootstrap ) {
  return bootstrap->state == AT_BOOTSTRAP_STATE_COMPLETE;
}

/* at_sync_bootstrap_get_progress returns bootstrap progress as percentage. */
static inline uint
at_sync_bootstrap_get_progress( at_bootstrap_sync_t const * bootstrap ) {
  if( bootstrap->state == AT_BOOTSTRAP_STATE_COMPLETE ) return 100;
  if( bootstrap->state == AT_BOOTSTRAP_STATE_IDLE ) return 0;
  /* Approximate: 14 steps total, return percentage based on current step */
  return (uint)((bootstrap->state * 100) / 14);
}

/**********************************************************************/
/* Tile Export                                                        */
/**********************************************************************/

extern at_topo_run_tile_t at_tile_sync;

AT_PROTOTYPES_END

#endif /* HEADER_at_disco_tiles_at_sync_tile_h */