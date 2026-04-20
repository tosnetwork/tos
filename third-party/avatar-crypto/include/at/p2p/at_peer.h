#ifndef HEADER_at_waltz_p2p_at_peer_h
#define HEADER_at_waltz_p2p_at_peer_h

/* at_peer.h - TOS P2P Peer Management

   Manages a pool of peer connections with:
   - Connection state tracking (extended for 2-phase handshake)
   - IPv4/IPv6 address support
   - Version and chain state info from handshake/ping
   - Reputation scoring
   - Automatic eviction of inactive/bad peers
   - Ban list management
*/

#include "at/p2p/at_p2p.h"
#include "at/p2p/at_p2p_msg.h"

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* Constants                                                          */
/**********************************************************************/

/* Maximum peers in pool - increased for production */
#define AT_PEER_MAX          (4096UL)

/* Maximum banned peers tracked - increased for production */
#define AT_PEER_BAN_MAX      (8192UL)
#define AT_PEER_DH_KEY_MAX   (4096UL)

/* Peer state - extended for 2-phase TOS handshake */
#define AT_PEER_STATE_FREE          (0)  /* Slot is empty */
#define AT_PEER_STATE_CONNECTING    (1)  /* TCP connect in progress */
#define AT_PEER_STATE_DH_EXCHANGE   (2)  /* X25519 DH key exchange */
#define AT_PEER_STATE_KEY_EXCHANGE  (3)  /* Symmetric key exchange */
#define AT_PEER_STATE_HANDSHAKE     (4)  /* TOS version negotiation */
#define AT_PEER_STATE_CONNECTED     (5)  /* Fully connected, ready for messages */
#define AT_PEER_STATE_DISCONNECTING (6)  /* Graceful disconnect */

/* Default timeouts (nanoseconds) */
#define AT_PEER_CONNECT_TIMEOUT_NS   (10000000000UL)  /* 10 seconds */
#define AT_PEER_HANDSHAKE_TIMEOUT_NS (5000000000UL)   /* 5 seconds */
#define AT_PEER_IDLE_TIMEOUT_NS      (120000000000UL) /* 2 minutes (TOS activity window) */
#define AT_PEER_PING_INTERVAL_NS     (30000000000UL)  /* 30 seconds */

/* Reputation scoring */
#define AT_PEER_SCORE_INITIAL        (100L)
#define AT_PEER_SCORE_MAX            (1000L)
#define AT_PEER_SCORE_MIN            (-100L)
#define AT_PEER_SCORE_BAN_THRESHOLD  (0L)

/* Score adjustments */
#define AT_PEER_SCORE_GOOD_BLOCK     (10L)
#define AT_PEER_SCORE_GOOD_TX        (1L)
#define AT_PEER_SCORE_BAD_MESSAGE    (-20L)
#define AT_PEER_SCORE_TIMEOUT        (-10L)
#define AT_PEER_SCORE_INVALID_DATA   (-50L)

/* Error codes */
#define AT_PEER_SUCCESS              (0)
#define AT_PEER_ERR_INVAL            (-1)
#define AT_PEER_ERR_FULL             (-2)
#define AT_PEER_ERR_NOT_FOUND        (-3)
#define AT_PEER_ERR_BANNED           (-4)
#define AT_PEER_ERR_STATE            (-5)

/**********************************************************************/
/* Peer Structure                                                     */
/**********************************************************************/

typedef struct {
  /* Network address (supports IPv4/IPv6) */
  at_peer_addr_t addr;           /* Peer address (IPv4 or IPv6 + port) */

  /* Identity */
  uchar  node_id[32];            /* Peer's node ID (public key, filled after handshake) */
  ulong  peer_id;                /* Peer's unique peer ID from handshake */
  uchar  dh_pubkey[32];          /* Peer's DH pubkey (for MITM detection) */

  /* State */
  int    state;                  /* AT_PEER_STATE_* */

  /* Version info from Handshake packet */
  uchar  version_len;            /* Length of version string */
  char   version[256];           /* Daemon version string */
  uchar  network;                /* at_network_t */
  uchar  node_tag_len;           /* 0=None, 1-16=Some (length IS the indicator) */
  char   node_tag[17];           /* User-defined node name (max 16) */

  /* Chain state from Ping packets */
  uchar  top_hash[32];           /* Peer's current top block hash */
  ulong  topoheight;             /* Topological height */
  ulong  height;                 /* Block height */
  at_cumulative_diff_t cumulative_diff;  /* Cumulative PoW difficulty */
  uchar  has_pruned;             /* 1 if peer reports pruned topoheight */
  ulong  pruned_topoheight;      /* Peer's pruned topoheight (if any) */

  /* Timestamps (nanoseconds since epoch or boot) */
  ulong  first_seen;             /* When connection was established */
  ulong  last_seen;              /* Last activity */
  ulong  last_ping_sent;         /* Last ping sent */
  ulong  last_ping_recv;         /* Last ping received */
  ulong  last_peer_list;         /* Last peerlist update (seconds) */
  ulong  last_inventory;         /* Last inventory response (seconds) */

  /* Metrics */
  ulong  ping_latency_ns;        /* Round-trip latency */
  ulong  bytes_in;               /* Total bytes received */
  ulong  bytes_out;              /* Total bytes sent */
  ulong  msgs_in;                /* Total messages received */
  ulong  msgs_out;               /* Total messages sent */

  /* Reputation */
  long   score;                  /* Reputation score */

  /* Encrypted session */
  at_p2p_session_t session;

  /* Peer sharing preference */
  uchar  can_be_shared;          /* 1 if peer can be shared with others */

  /* Inventory state */
  uchar  requested_inventory;    /* 1 if inventory was requested */
  uchar  ready_to_propagate_txs; /* 1 if inventory is synced */

} at_peer_t;

/**********************************************************************/
/* Ban Entry (supports both IPv4 and IPv6)                            */
/**********************************************************************/

typedef struct {
  at_peer_addr_t addr;           /* Banned address (IPv4 or IPv6) */
  ulong ban_until;               /* Ban expiration timestamp (0 = permanent) */
  long  last_score;              /* Score when banned */
} at_peer_ban_t;

typedef struct {
  uchar  addr_type;              /* AT_ADDR_TYPE_* */
  uchar  ip6[16];                /* IPv6 bytes if addr_type=IPV6 */
  uint   ip4_addr;               /* IPv4 in host order if addr_type=IPV4 */
  ushort local_port;             /* Peer local port from handshake */
  uchar  has_entry;
  uchar  has_key;
  uchar  out_success;
  uchar  fail_count;
  uchar  state;                  /* at_peerlist_state_t */
  ulong  temp_ban_until;         /* Seconds since epoch */
  uchar  key[32];                /* DH public key */
} at_peer_dh_key_t;

typedef enum {
  AT_PEERLIST_WHITELIST = 0,
  AT_PEERLIST_GRAYLIST  = 1,
  AT_PEERLIST_BLACKLIST = 2
} at_peerlist_state_t;

/**********************************************************************/
/* Peer Pool                                                          */
/**********************************************************************/

typedef struct {
  /* Peer slots */
  at_peer_t peers[AT_PEER_MAX];
  ulong     peer_cnt;            /* Number of active peers */
  ulong     connected_cnt;       /* Number of fully connected peers */

  /* Ban list */
  at_peer_ban_t bans[AT_PEER_BAN_MAX];
  ulong         ban_cnt;

  /* DH public key cache (per IPv4) */
  at_peer_dh_key_t dh_keys[AT_PEER_DH_KEY_MAX];
  ulong            dh_key_cnt;

  /* Configuration */
  ulong connect_timeout_ns;
  ulong handshake_timeout_ns;
  ulong idle_timeout_ns;
  ulong ping_interval_ns;
  ulong max_peers;

  /* Statistics */
  ulong total_connects;
  ulong total_disconnects;
  ulong total_bans;

  /* RNG state for random selection */
  ulong rng_state;

} at_peer_pool_t;

/**********************************************************************/
/* Pool Lifecycle                                                     */
/**********************************************************************/

/* at_peer_pool_init initializes a peer pool.
   Returns pool on success, NULL on failure. */
at_peer_pool_t *
at_peer_pool_init( at_peer_pool_t * pool );

/* at_peer_pool_fini cleans up a peer pool. */
void
at_peer_pool_fini( at_peer_pool_t * pool );

/**********************************************************************/
/* Peer Operations                                                    */
/**********************************************************************/

/* at_peer_pool_find finds a peer by address.
   Returns pointer to peer or NULL if not found. */
at_peer_t *
at_peer_pool_find( at_peer_pool_t *       pool,
                   at_peer_addr_t const * addr );

/* at_peer_pool_find_by_ip4 finds a peer by IPv4 address and port.
   Returns pointer to peer or NULL if not found. */
at_peer_t *
at_peer_pool_find_by_ip4( at_peer_pool_t * pool,
                          uint             ip4_addr,
                          ushort           port );

/* at_peer_pool_find_by_id finds a peer by node ID.
   Returns pointer to peer or NULL if not found. */
at_peer_t *
at_peer_pool_find_by_id( at_peer_pool_t * pool,
                         uchar const      node_id[32] );

/* at_peer_pool_find_by_peer_id finds a peer by peer_id.
   Returns pointer to peer or NULL if not found. */
at_peer_t *
at_peer_pool_find_by_peer_id( at_peer_pool_t * pool,
                              ulong            peer_id );

/* at_peer_pool_get_dh_key_ip4 fetches cached DH pubkey for IPv4.
   Returns 1 if found, 0 otherwise. */
int
at_peer_pool_get_dh_key_ip4( at_peer_pool_t * pool,
                             uint             ip4_addr,
                             uchar            out_key[32] );

/* at_peer_pool_set_dh_key_ip4 stores DH pubkey for IPv4 (updates if exists). */
void
at_peer_pool_set_dh_key_ip4( at_peer_pool_t * pool,
                             uint             ip4_addr,
                             uchar const      key[32] );

/* IPv6 variants */
int
at_peer_pool_get_dh_key_ip6( at_peer_pool_t * pool,
                             uchar const      ip6_addr[16],
                             uchar            out_key[32] );

void
at_peer_pool_set_dh_key_ip6( at_peer_pool_t * pool,
                             uchar const      ip6_addr[16],
                             uchar const      key[32] );

/* Peerlist entry helpers (fail count / temp ban / local port) */
at_peer_dh_key_t *
at_peer_pool_touch_peerlist_ip4( at_peer_pool_t * pool,
                                 uint             ip4_addr );

at_peer_dh_key_t *
at_peer_pool_touch_peerlist_ip6( at_peer_pool_t * pool,
                                 uchar const      ip6_addr[16] );

void
at_peer_pool_peerlist_fail_ip4( at_peer_pool_t * pool,
                                uint             ip4_addr,
                                uchar            fail_limit,
                                ulong            temp_ban_secs,
                                ulong            now_sec );

void
at_peer_pool_peerlist_fail_ip6( at_peer_pool_t * pool,
                                uchar const      ip6_addr[16],
                                uchar            fail_limit,
                                ulong            temp_ban_secs,
                                ulong            now_sec );

int
at_peer_pool_peerlist_is_temp_banned_ip4( at_peer_pool_t * pool,
                                          uint             ip4_addr,
                                          ulong            now_sec );

int
at_peer_pool_peerlist_is_temp_banned_ip6( at_peer_pool_t * pool,
                                          uchar const      ip6_addr[16],
                                          ulong            now_sec );

int
at_peer_pool_peerlist_is_blacklisted_ip4( at_peer_pool_t * pool,
                                          uint             ip4_addr );

int
at_peer_pool_peerlist_is_blacklisted_ip6( at_peer_pool_t * pool,
                                          uchar const      ip6_addr[16] );

/* at_peer_pool_add adds a new peer in CONNECTING state.
   Returns pointer to new peer or NULL on failure.
   opt_err receives error code if non-NULL. */
at_peer_t *
at_peer_pool_add( at_peer_pool_t *       pool,
                  at_peer_addr_t const * addr,
                  ulong                  now,
                  int *                  opt_err );

/* at_peer_pool_add_ip4 adds a new peer by IPv4 address.
   Convenience wrapper around at_peer_pool_add. */
at_peer_t *
at_peer_pool_add_ip4( at_peer_pool_t * pool,
                      uint             ip4_addr,
                      ushort           port,
                      ulong            now,
                      int *            opt_err );

/* at_peer_pool_remove removes a peer from the pool. */
void
at_peer_pool_remove( at_peer_pool_t * pool,
                     at_peer_t *      peer );

/**********************************************************************/
/* State Transitions                                                  */
/**********************************************************************/

/* at_peer_set_dh_exchange transitions peer to DH_EXCHANGE state. */
int
at_peer_set_dh_exchange( at_peer_t * peer, ulong now );

/* at_peer_set_key_exchange transitions peer to KEY_EXCHANGE state. */
int
at_peer_set_key_exchange( at_peer_t * peer, ulong now );

/* at_peer_set_handshake transitions peer to HANDSHAKE state. */
int
at_peer_set_handshake( at_peer_t * peer, ulong now );

/* at_peer_set_connected transitions peer to CONNECTED state.
   node_id is the peer's verified public key.
   Copies handshake info from hs (version, network, etc.). */
int
at_peer_set_connected( at_peer_t *            peer,
                       uchar const            node_id[32],
                       at_handshake_t const * hs,
                       ulong                  now );

/* at_peer_set_disconnecting transitions peer to DISCONNECTING state. */
int
at_peer_set_disconnecting( at_peer_t * peer, ulong now );

/**********************************************************************/
/* Chain State Updates                                                */
/**********************************************************************/

/* at_peer_update_chain_state updates peer's chain state from Ping packet. */
void
at_peer_update_chain_state( at_peer_t *       peer,
                            at_ping_t const * ping,
                            ulong             now );

/**********************************************************************/
/* Reputation                                                         */
/**********************************************************************/

/* at_peer_score_adjust adjusts peer's reputation score.
   Automatically bans if score drops below threshold.
   Returns new score. */
long
at_peer_score_adjust( at_peer_pool_t * pool,
                      at_peer_t *      peer,
                      long             delta );

/**********************************************************************/
/* Ban Management                                                     */
/**********************************************************************/

/* at_peer_pool_ban bans a peer's address for duration_ns nanoseconds.
   duration_ns of 0 means permanent ban. */
void
at_peer_pool_ban( at_peer_pool_t * pool,
                  at_peer_t *      peer,
                  ulong            duration_ns,
                  ulong            now );

/* at_peer_pool_ban_addr bans an address. */
void
at_peer_pool_ban_addr( at_peer_pool_t *       pool,
                       at_peer_addr_t const * addr,
                       ulong                  duration_ns,
                       ulong                  now );

/* at_peer_pool_ban_ip4 bans an IPv4 address. */
void
at_peer_pool_ban_ip4( at_peer_pool_t * pool,
                      uint             ip4_addr,
                      ulong            duration_ns,
                      ulong            now );

/* at_peer_pool_is_banned checks if an address is banned.
   Returns 1 if banned, 0 if not. */
int
at_peer_pool_is_banned( at_peer_pool_t *       pool,
                        at_peer_addr_t const * addr,
                        ulong                  now );

/* at_peer_pool_is_banned_ip4 checks if an IPv4 address is banned. */
int
at_peer_pool_is_banned_ip4( at_peer_pool_t * pool,
                            uint             ip4_addr,
                            ulong            now );

/* at_peer_pool_unban removes ban for an address. */
void
at_peer_pool_unban( at_peer_pool_t *       pool,
                    at_peer_addr_t const * addr );

/* at_peer_pool_unban_ip4 removes ban for an IPv4 address. */
void
at_peer_pool_unban_ip4( at_peer_pool_t * pool,
                        uint             ip4_addr );

/**********************************************************************/
/* Selection                                                          */
/**********************************************************************/

/* at_peer_pool_select_random selects a random connected peer.
   Returns pointer to peer or NULL if no connected peers. */
at_peer_t *
at_peer_pool_select_random( at_peer_pool_t * pool );

/* at_peer_pool_select_n_random selects up to n random connected peers.
   Writes peer pointers to out_peers array.
   Returns number of peers selected. */
ulong
at_peer_pool_select_n_random( at_peer_pool_t * pool,
                              at_peer_t **     out_peers,
                              ulong            n );

/* at_peer_pool_select_best selects the peer with highest score.
   Returns pointer to peer or NULL if no connected peers. */
at_peer_t *
at_peer_pool_select_best( at_peer_pool_t * pool );

/* at_peer_pool_select_by_difficulty selects peer with highest cumulative difficulty.
   Returns pointer to peer or NULL if no connected peers. */
at_peer_t *
at_peer_pool_select_by_difficulty( at_peer_pool_t * pool );

/**********************************************************************/
/* Housekeeping                                                       */
/**********************************************************************/

/* at_peer_pool_housekeeping performs periodic maintenance:
   - Disconnect timed-out peers
   - Expire old bans
   - Update connected_cnt
   Returns number of peers disconnected. */
ulong
at_peer_pool_housekeeping( at_peer_pool_t * pool,
                           ulong            now );

/**********************************************************************/
/* Queries                                                            */
/**********************************************************************/

/* at_peer_pool_connected_cnt returns count of connected peers. */
ulong
at_peer_pool_connected_cnt( at_peer_pool_t const * pool );

/* at_peer_pool_count_in_state returns count of peers in given state. */
ulong
at_peer_pool_count_in_state( at_peer_pool_t const * pool,
                             int                    state );

/* at_peer_addr_eq compares two peer addresses for equality.
   Returns 1 if equal, 0 if different. */
int
at_peer_addr_eq( at_peer_addr_t const * a,
                 at_peer_addr_t const * b );

/* at_peer_addr_from_ip4 initializes a peer_addr from IPv4 address. */
void
at_peer_addr_from_ip4( at_peer_addr_t * addr,
                       uint             ip4_addr,
                       ushort           port );

/**********************************************************************/
/* Iteration                                                          */
/**********************************************************************/

/* Iterate over all peers (use with care):
   for( ulong i = 0; i < AT_PEER_MAX; i++ ) {
     at_peer_t * peer = &pool->peers[i];
     if( peer->state == AT_PEER_STATE_FREE ) continue;
     // ... use peer ...
   }
*/

AT_PROTOTYPES_END

#endif /* HEADER_at_waltz_p2p_at_peer_h */