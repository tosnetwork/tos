#ifndef HEADER_at_waltz_p2p_discovery_at_discv6_h
#define HEADER_at_waltz_p2p_discovery_at_discv6_h

/* at_discv6.h - TOS Discv6 Peer Discovery Protocol

   Implements the discv6-based peer discovery protocol for Avatar C,
   compatible with TOS Rust PR #64. The discv6 protocol is a Kademlia-based
   UDP discovery mechanism that enables decentralized peer discovery.

   Protocol Overview:
   - Transport: UDP
   - Node ID: SHA3-256(compressed_schnorr_pubkey) - 32 bytes
   - Signatures: TOS Schnorr (Ristretto255 + SHA3-512)
   - Max Packet: 1280 bytes
   - Kademlia: k=16 bucket size, alpha=3 parallel lookups, 256 buckets
*/

#include "at/infra/at_util_base.h"
#include "at/p2p/at_p2p_msg.h"

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* Protocol Constants                                                  */
/**********************************************************************/

/* Message types */
#define AT_DISCV6_MSG_PING      (0x01)
#define AT_DISCV6_MSG_PONG      (0x02)
#define AT_DISCV6_MSG_FINDNODE  (0x03)
#define AT_DISCV6_MSG_NEIGHBORS (0x04)

/* Packet limits */
#define AT_DISCV6_MAX_PACKET_SZ   (1280UL)
#define AT_DISCV6_MAX_NEIGHBORS   (16UL)
#define AT_DISCV6_SIGNATURE_SZ    (64UL)
#define AT_DISCV6_NODE_ID_SZ      (32UL)
#define AT_DISCV6_PUBKEY_SZ       (32UL)

/* Kademlia parameters */
#define AT_DISCV6_K_BUCKET_SIZE   (16UL)   /* Max nodes per bucket */
#define AT_DISCV6_NUM_BUCKETS     (256UL)  /* One bucket per bit */
#define AT_DISCV6_ALPHA           (3UL)    /* Parallel lookups */

/* Timeouts (nanoseconds) */
#define AT_DISCV6_EXPIRATION_NS   (20000000000UL)  /* 20 seconds */
#define AT_DISCV6_RESPONSE_NS     (5000000000UL)   /* 5 seconds */
#define AT_DISCV6_REFRESH_NS      (300000000000UL) /* 5 minute bucket refresh */
#define AT_DISCV6_BOOTSTRAP_NS    (60000000000UL)  /* 60 seconds bootstrap interval */

/* Security limits */
#define AT_DISCV6_MAX_PENDING_PINGS     (256UL)
#define AT_DISCV6_MAX_PENDING_FINDNODES (256UL)
#define AT_DISCV6_MAX_VALIDATED         (1024UL)
#define AT_DISCV6_PONG_HASH_CACHE_SZ    (512UL)
#define AT_DISCV6_RATE_LIMIT_PER_MIN    (100UL)
#define AT_DISCV6_MAX_CONCURRENT        (64UL)

/* Bootstrap limits */
#define AT_DISCV6_MAX_BOOTSTRAP         (32UL)

/* Error codes */
#define AT_DISCV6_SUCCESS               (0)
#define AT_DISCV6_ERR_INVAL             (-1)
#define AT_DISCV6_ERR_EXPIRED           (-2)
#define AT_DISCV6_ERR_SIGNATURE         (-3)
#define AT_DISCV6_ERR_RATE_LIMIT        (-4)
#define AT_DISCV6_ERR_NOT_VALIDATED     (-5)
#define AT_DISCV6_ERR_DUPLICATE         (-6)
#define AT_DISCV6_ERR_SOCKET            (-7)
#define AT_DISCV6_ERR_FULL              (-8)
#define AT_DISCV6_ERR_NOT_FOUND         (-9)
#define AT_DISCV6_ERR_TRUNCATED         (-10)
#define AT_DISCV6_ERR_PRIVATE_ADDR      (-11)

/**********************************************************************/
/* Init Diagnostics                                                    */
/**********************************************************************/

/* Initialization failure stage for at_discv6_new(). */
#define AT_DISCV6_INIT_STAGE_NONE      (0)
#define AT_DISCV6_INIT_STAGE_ARGS      (1)
#define AT_DISCV6_INIT_STAGE_IDENTITY  (2)
#define AT_DISCV6_INIT_STAGE_ROUTING   (3)
#define AT_DISCV6_INIT_STAGE_SOCKET    (4)
#define AT_DISCV6_INIT_STAGE_FCNTL_GET (5)
#define AT_DISCV6_INIT_STAGE_FCNTL_SET (6)
#define AT_DISCV6_INIT_STAGE_BIND      (7)

typedef struct {
  int            stage;      /* AT_DISCV6_INIT_STAGE_* */
  int            sys_errno;  /* errno snapshot for syscall failures, else 0 */
  at_peer_addr_t bind_addr;  /* bind address requested during init */
} at_discv6_init_error_t;

/**********************************************************************/
/* Forward Declarations                                                */
/**********************************************************************/

typedef struct at_discv6_server at_discv6_server_t;

/**********************************************************************/
/* Server Lifecycle                                                    */
/**********************************************************************/

/* at_discv6_align returns the alignment requirement for a server. */
AT_FN_CONST ulong
at_discv6_align( void );

/* at_discv6_footprint returns the memory footprint for a server. */
AT_FN_CONST ulong
at_discv6_footprint( void );

/* at_discv6_new initializes a new discovery server in the given memory region.
   private_key: 32-byte Schnorr private key for this node
   bind_addr: UDP address to bind to
   bootnode_mode: 1 if this server should run as a bootnode (no active discovery)
   Returns the server handle or NULL on failure. */
at_discv6_server_t *
at_discv6_new( void *                   mem,
               uchar const              private_key[32],
               at_peer_addr_t const *   bind_addr,
               int                      bootnode_mode );

/* at_discv6_get_last_init_error copies the most recent init error metadata. */
void
at_discv6_get_last_init_error( at_discv6_init_error_t * out );

/* at_discv6_init_stage_to_cstr returns a textual name for init stage. */
char const *
at_discv6_init_stage_to_cstr( int stage );

/* at_discv6_delete shuts down and cleans up a discovery server. */
void
at_discv6_delete( at_discv6_server_t * server );

/**********************************************************************/
/* Bootstrap                                                           */
/**********************************************************************/

/* at_discv6_add_bootstrap adds a bootstrap node.
   url: tosnode:// URL or NULL if node_id/addr are provided directly
   node_id: 32-byte node ID (required if url is NULL)
   addr: peer address (required if url is NULL)
   Returns 0 on success, negative error code on failure. */
int
at_discv6_add_bootstrap( at_discv6_server_t *     server,
                         char const *             url,
                         uchar const              node_id[32],
                         at_peer_addr_t const *   addr );

/**********************************************************************/
/* Event Loop                                                          */
/**********************************************************************/

/* at_discv6_fd returns the UDP socket file descriptor for polling. */
int
at_discv6_fd( at_discv6_server_t const * server );

/* at_discv6_poll processes one iteration of the discovery event loop.
   now: current timestamp in nanoseconds
   Returns number of events processed, or negative error code. */
int
at_discv6_poll( at_discv6_server_t * server,
                ulong                now );

/* at_discv6_housekeeping performs periodic maintenance tasks.
   now: current timestamp in nanoseconds
   - Expires pending requests
   - Refreshes stale buckets
   - Reconnects to bootstrap nodes if needed */
void
at_discv6_housekeeping( at_discv6_server_t * server,
                        ulong                now );

/**********************************************************************/
/* Peer Discovery                                                      */
/**********************************************************************/

/* at_discv6_lookup initiates a Kademlia lookup for the given target.
   target: 32-byte node ID to find
   Returns 0 on success (lookup started), negative error code on failure. */
int
at_discv6_lookup( at_discv6_server_t * server,
                  uchar const          target[32] );

/* at_discv6_get_closest fills out_nodes with up to max_nodes closest
   known nodes to the given target.
   Returns number of nodes written. */
ulong
at_discv6_get_closest( at_discv6_server_t * server,
                       uchar const          target[32],
                       at_peer_addr_t *     out_addrs,
                       uchar *              out_pubkeys,  /* max_nodes * 32 bytes */
                       ulong                max_nodes );

/* at_discv6_node_count returns the total number of nodes in the routing table. */
ulong
at_discv6_node_count( at_discv6_server_t const * server );

/**********************************************************************/
/* Identity                                                            */
/**********************************************************************/

/* at_discv6_get_node_id returns a pointer to this server's node ID. */
uchar const *
at_discv6_get_node_id( at_discv6_server_t const * server );

/* at_discv6_get_public_key returns a pointer to this server's public key. */
uchar const *
at_discv6_get_public_key( at_discv6_server_t const * server );

/**********************************************************************/
/* Statistics                                                          */
/**********************************************************************/

typedef struct {
  ulong pings_sent;
  ulong pings_recv;
  ulong pongs_sent;
  ulong pongs_recv;
  ulong findnodes_sent;
  ulong findnodes_recv;
  ulong neighbors_sent;
  ulong neighbors_recv;
  ulong packets_dropped;
  ulong signature_failures;
  ulong rate_limited;
  ulong expired_messages;
  ulong nodes_discovered;
  ulong nodes_evicted;
} at_discv6_stats_t;

/* at_discv6_get_stats fills the stats structure with current statistics. */
void
at_discv6_get_stats( at_discv6_server_t const * server,
                     at_discv6_stats_t *        stats );

AT_PROTOTYPES_END

#endif /* HEADER_at_waltz_p2p_discovery_at_discv6_h */
