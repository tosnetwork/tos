#ifndef HEADER_at_waltz_p2p_discovery_at_discv6_messages_h
#define HEADER_at_waltz_p2p_discovery_at_discv6_messages_h

/* at_discv6_messages.h - Discovery Protocol Message Types

   TOS-parity packet format:
   - signed packet: signature(64) || message
   - message: msg_type(1) || payload

   Message payloads include source NodeInfo in all request/response types.
   PONG.ping_hash is SHA3-256 over the full encoded PING packet bytes. */

#include "at/infra/at_util_base.h"
#include "at/p2p/at_p2p_msg.h"

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* Message Constants                                                   */
/**********************************************************************/

#define AT_DISCV6_SIG_SZ        (64UL)
#define AT_DISCV6_HEADER_SZ     (AT_DISCV6_SIG_SZ + 1UL) /* signature + msg_type */

#define AT_DISCV6_NODEINFO_MIN_SZ (32UL + 1UL + 4UL + 2UL + 32UL)
#define AT_DISCV6_PING_MIN_SZ      (AT_DISCV6_HEADER_SZ + AT_DISCV6_NODEINFO_MIN_SZ + 8UL + 8UL)
#define AT_DISCV6_PONG_MIN_SZ      (AT_DISCV6_HEADER_SZ + 32UL + AT_DISCV6_NODEINFO_MIN_SZ + 8UL)
#define AT_DISCV6_FINDNODE_MIN_SZ  (AT_DISCV6_HEADER_SZ + AT_DISCV6_NODEINFO_MIN_SZ + 32UL + 8UL)
#define AT_DISCV6_NEIGHBORS_MIN_SZ (AT_DISCV6_HEADER_SZ + AT_DISCV6_NODEINFO_MIN_SZ + 1UL + 8UL)

#define AT_DISCV6_MAX_CLOCK_DRIFT_SEC (40UL)

/**********************************************************************/
/* Node Record (NodeInfo wire-compatible)                              */
/**********************************************************************/

typedef struct {
  uchar          node_id[32];       /* SHA3-256(public_key) */
  uchar          public_key[32];    /* Compressed Schnorr public key */
  at_peer_addr_t addr;              /* IP address and port */
  ulong          last_seen;         /* Local metadata only (not serialized) */
  int            is_validated;      /* Local metadata only (not serialized) */
} at_discv6_node_t;

/**********************************************************************/
/* PING Message                                                        */
/**********************************************************************/

typedef struct {
  at_discv6_node_t source;          /* Sender node info */
  ulong            expiration;      /* Unix timestamp (seconds) */
  ulong            seq;             /* Sequence number */
} at_discv6_ping_t;

/**********************************************************************/
/* PONG Message                                                        */
/**********************************************************************/

typedef struct {
  uchar            ping_hash[32];   /* SHA3-256(full PING packet bytes) */
  at_discv6_node_t source;          /* Sender node info */
  ulong            expiration;      /* Unix timestamp (seconds) */
} at_discv6_pong_t;

/**********************************************************************/
/* FINDNODE Message                                                    */
/**********************************************************************/

typedef struct {
  at_discv6_node_t source;          /* Sender node info */
  uchar            target[32];      /* Node ID to search for */
  ulong            expiration;      /* Unix timestamp (seconds) */
} at_discv6_findnode_t;

/**********************************************************************/
/* NEIGHBORS Message                                                   */
/**********************************************************************/

#define AT_DISCV6_NEIGHBORS_MAX (16UL)

typedef struct {
  at_discv6_node_t source;                              /* Sender node info */
  uchar            cnt;                                 /* Number of nodes */
  at_discv6_node_t nodes[AT_DISCV6_NEIGHBORS_MAX];     /* Node records */
  ulong            expiration;                          /* Unix timestamp */
} at_discv6_neighbors_t;

/**********************************************************************/
/* Packet Wrapper (parsed packet)                                      */
/**********************************************************************/

typedef struct {
  uchar   packet_hash[32];          /* SHA3-256(full packet bytes) */
  uchar   signature[64];            /* Schnorr signature */
  uchar   msg_type;                 /* Message type (AT_DISCV6_MSG_*) */
  ulong   expiration;               /* Message expiration timestamp */

  union {
    at_discv6_ping_t      ping;
    at_discv6_pong_t      pong;
    at_discv6_findnode_t  findnode;
    at_discv6_neighbors_t neighbors;
  };
} at_discv6_packet_t;

/**********************************************************************/
/* Serialization Functions                                             */
/**********************************************************************/

long
at_discv6_serialize_ping( at_discv6_ping_t const * ping,
                          uchar const              private_key[32],
                          uchar const              public_key[32],
                          uchar *                  buf,
                          ulong                    buf_sz );

long
at_discv6_serialize_pong( at_discv6_pong_t const * pong,
                          uchar const              private_key[32],
                          uchar const              public_key[32],
                          uchar *                  buf,
                          ulong                    buf_sz );

long
at_discv6_serialize_findnode( at_discv6_findnode_t const * findnode,
                              uchar const                  private_key[32],
                              uchar const                  public_key[32],
                              uchar *                      buf,
                              ulong                        buf_sz );

long
at_discv6_serialize_neighbors( at_discv6_neighbors_t const * neighbors,
                               uchar const                   private_key[32],
                               uchar const                   public_key[32],
                               uchar *                       buf,
                               ulong                         buf_sz );

/**********************************************************************/
/* Deserialization Functions                                           */
/**********************************************************************/

int
at_discv6_deserialize( at_discv6_packet_t * out,
                       uchar const *        buf,
                       ulong                buf_sz,
                       ulong                now );

/**********************************************************************/
/* Packet Hash Helper (legacy utility for tests)                       */
/**********************************************************************/

uchar *
at_discv6_compute_packet_hash( uchar       out[32],
                               uchar const signature[64],
                               uchar       msg_type,
                               uchar const pubkey[32],
                               uchar const * payload,
                               ulong       payload_sz,
                               ulong       expiration );

/**********************************************************************/
/* Address Serialization Helpers                                       */
/**********************************************************************/

long
at_discv6_serialize_addr( at_peer_addr_t const * addr,
                          uchar *                buf,
                          ulong                  buf_sz );

long
at_discv6_deserialize_addr( at_peer_addr_t * addr,
                            uchar const *    buf,
                            ulong            buf_sz );

AT_PROTOTYPES_END

#endif /* HEADER_at_waltz_p2p_discovery_at_discv6_messages_h */
