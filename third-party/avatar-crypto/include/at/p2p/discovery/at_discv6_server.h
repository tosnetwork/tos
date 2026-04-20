#ifndef HEADER_at_waltz_p2p_discovery_at_discv6_server_h
#define HEADER_at_waltz_p2p_discovery_at_discv6_server_h

/* at_discv6_server.h - Discovery Server Internal Structures

   Internal data structures for the discovery server.
   Not part of the public API - use at_discv6.h instead.
*/

#include "at/p2p/discovery/at_discv6.h"
#include "at/p2p/discovery/at_discv6_identity.h"
#include "at/p2p/discovery/at_discv6_messages.h"
#include "at/p2p/discovery/at_discv6_routing.h"

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* Pending Request Tracking                                            */
/**********************************************************************/

typedef struct {
  uchar          target_id[32];     /* Node ID we're waiting for */
  at_peer_addr_t target_addr;       /* Address we sent to */
  uchar          packet_hash[32];   /* Hash of sent packet (for PONG matching) */
  ulong          sent_at;           /* Timestamp when sent */
  ulong          seq;               /* Sequence number */
  int            active;            /* 1 if slot is in use */
} at_discv6_pending_t;

/**********************************************************************/
/* Endpoint Validation Cache                                           */
/**********************************************************************/

/* Key: first 20 bytes = truncated hash of address */
typedef struct {
  uchar  key[20];                   /* Truncated address hash */
  uchar  node_id[32];               /* Node ID validated at this endpoint */
  ulong  validated_at;              /* When endpoint was validated */
  int    active;
} at_discv6_validated_t;

/**********************************************************************/
/* Rate Limiter                                                        */
/**********************************************************************/

typedef struct {
  uchar  addr_key[20];              /* Truncated address hash */
  ulong  window_start;              /* Start of current window (seconds) */
  ulong  request_count;             /* Requests in current window */
  int    active;
} at_discv6_rate_entry_t;

#define AT_DISCV6_RATE_ENTRIES (1024UL)

/**********************************************************************/
/* Bootstrap Node                                                      */
/**********************************************************************/

typedef struct {
  at_peer_addr_t addr;
  uchar          node_id[32];
  ulong          last_ping;         /* Last ping sent */
  int            active;
} at_discv6_bootstrap_t;

/**********************************************************************/
/* Kademlia Lookup State                                               */
/**********************************************************************/

#define AT_DISCV6_LOOKUP_MAX_QUERIED (64UL)

typedef struct {
  uchar target[32];                             /* Target node ID */
  uchar queried[AT_DISCV6_LOOKUP_MAX_QUERIED][32];  /* Node IDs we've queried */
  ulong queried_cnt;
  ulong started_at;
  int   active;
} at_discv6_lookup_t;

#define AT_DISCV6_MAX_LOOKUPS (4UL)

/**********************************************************************/
/* Server Structure                                                    */
/**********************************************************************/

struct at_discv6_server {
  /* Identity */
  at_discv6_identity_t identity;

  /* Routing table */
  at_discv6_routing_table_t routing;

  /* UDP socket */
  int            socket_fd;
  at_peer_addr_t bind_addr;
  at_peer_addr_t external_addr;
  int            has_external_addr;

  /* Pending requests */
  at_discv6_pending_t pending_pings[AT_DISCV6_MAX_PENDING_PINGS];
  ulong               pending_ping_cnt;
  at_discv6_pending_t pending_findnodes[AT_DISCV6_MAX_PENDING_FINDNODES];
  ulong               pending_findnode_cnt;

  /* Endpoint validation cache */
  at_discv6_validated_t validated[AT_DISCV6_MAX_VALIDATED];
  ulong                 validated_cnt;

  /* Replay prevention - recent PONG hashes */
  uchar pong_hashes[AT_DISCV6_PONG_HASH_CACHE_SZ][32];
  ulong pong_hash_seen_at[AT_DISCV6_PONG_HASH_CACHE_SZ];
  ulong pong_hash_idx;

  /* Rate limiting */
  at_discv6_rate_entry_t rate_limits[AT_DISCV6_RATE_ENTRIES];

  /* Bootstrap nodes */
  at_discv6_bootstrap_t bootstrap[AT_DISCV6_MAX_BOOTSTRAP];
  ulong                 bootstrap_cnt;

  /* Active lookups */
  at_discv6_lookup_t lookups[AT_DISCV6_MAX_LOOKUPS];

  /* Configuration */
  int   bootnode_mode;              /* Discovery-only mode flag (kept for config parity) */
  ulong bucket_size;                /* Override for k (default 16) */

  /* Timing */
  ulong last_bootstrap_ping;        /* Last bootstrap ping attempt */
  ulong last_refresh_lookup;        /* Last periodic lookup refresh */
  ulong last_housekeeping;          /* Last housekeeping run */

  /* Statistics */
  at_discv6_stats_t stats;

  /* Monotonic sequence counter for PING messages */
  ulong seq_counter;

  /* RNG state */
  ulong rng_state;

  /* Receive buffer */
  uchar recv_buf[AT_DISCV6_MAX_PACKET_SZ];
};

/**********************************************************************/
/* Internal Functions                                                  */
/**********************************************************************/

/* Handle incoming packet (called from at_discv6_poll) */
int
at_discv6_handle_packet( at_discv6_server_t *     server,
                         uchar const *            buf,
                         ulong                    buf_sz,
                         at_peer_addr_t const *   from,
                         ulong                    now );

/* Send a packet to an address */
int
at_discv6_send( at_discv6_server_t *     server,
                uchar const *            buf,
                ulong                    buf_sz,
                at_peer_addr_t const *   to );

/* Send PING to an address */
int
at_discv6_send_ping( at_discv6_server_t *   server,
                     at_peer_addr_t const * to,
                     uchar const            expected_node_id[32],
                     ulong                  now );

/* Send PONG in response to a PING */
int
at_discv6_send_pong( at_discv6_server_t *         server,
                     at_peer_addr_t const *       to,
                     uchar const                  ping_hash[32],
                     ulong                        now );

/* Send FINDNODE to an address */
int
at_discv6_send_findnode( at_discv6_server_t *   server,
                         at_peer_addr_t const * to,
                         uchar const            target[32],
                         uchar const            sender_node_id[32],
                         ulong                  now );

/* Send NEIGHBORS in response to FINDNODE */
int
at_discv6_send_neighbors( at_discv6_server_t *          server,
                          at_peer_addr_t const *        to,
                          at_discv6_node_t const * const * nodes,
                          ulong                         node_cnt,
                          ulong                         now );

/**********************************************************************/
/* Validation Helpers                                                  */
/**********************************************************************/

/* Check if endpoint is validated (received valid PONG) */
int
at_discv6_is_validated( at_discv6_server_t const * server,
                        at_peer_addr_t const *     addr,
                        uchar const                node_id[32],
                        ulong                      now );

/* Mark endpoint as validated */
void
at_discv6_mark_validated( at_discv6_server_t *   server,
                          at_peer_addr_t const * addr,
                          uchar const            node_id[32],
                          ulong                  now );

/* Check rate limit for address */
int
at_discv6_check_rate_limit( at_discv6_server_t *   server,
                            at_peer_addr_t const * addr,
                            ulong                  now );

/* Check if PONG hash is a replay */
int
at_discv6_is_pong_replay( at_discv6_server_t const * server,
                          uchar const                hash[32],
                          ulong                      now );

/* Record PONG hash to prevent replay */
void
at_discv6_record_pong_hash( at_discv6_server_t * server,
                            uchar const          hash[32],
                            ulong                now );

/**********************************************************************/
/* Pending Request Helpers                                             */
/**********************************************************************/

/* Add pending PING */
int
at_discv6_add_pending_ping( at_discv6_server_t *   server,
                            at_peer_addr_t const * addr,
                            uchar const            node_id[32],
                            uchar const            packet_hash[32],
                            ulong                  now );

/* Find and remove pending PING by hash */
at_discv6_pending_t *
at_discv6_find_pending_ping( at_discv6_server_t * server,
                             uchar const          packet_hash[32] );

/* Add pending FINDNODE */
int
at_discv6_add_pending_findnode( at_discv6_server_t *   server,
                                at_peer_addr_t const * addr,
                                uchar const            sender_node_id[32],
                                ulong                  now );

/* Find pending FINDNODE by expected sender node ID */
at_discv6_pending_t *
at_discv6_find_pending_findnode( at_discv6_server_t *   server,
                                 uchar const            sender_node_id[32] );

/* Expire old pending requests */
void
at_discv6_expire_pending( at_discv6_server_t * server,
                          ulong                now );

/**********************************************************************/
/* Address Validation                                                  */
/**********************************************************************/

/* Check if address is valid for discovery (not private/loopback/multicast) */
int
at_discv6_addr_is_valid( at_peer_addr_t const * addr );

/* Compute address hash key (first 20 bytes of SHA3-256) */
void
at_discv6_addr_hash_key( uchar                  out[20],
                         at_peer_addr_t const * addr );

AT_PROTOTYPES_END

#endif /* HEADER_at_waltz_p2p_discovery_at_discv6_server_h */
