#ifndef HEADER_at_waltz_p2p_discovery_at_discv6_identity_h
#define HEADER_at_waltz_p2p_discovery_at_discv6_identity_h

/* at_discv6_identity.h - Node Identity and XOR Distance

   Node identity is computed as SHA3-256(compressed_schnorr_pubkey).
   XOR distance is used for Kademlia routing table organization.
*/

#include "at/infra/at_util_base.h"

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* Node Identity Structure                                             */
/**********************************************************************/

typedef struct {
  uchar private_key[32];    /* Schnorr private key */
  uchar public_key[32];     /* Compressed Schnorr public key */
  uchar node_id[32];        /* SHA3-256(public_key) */
} at_discv6_identity_t;

/**********************************************************************/
/* Identity Functions                                                  */
/**********************************************************************/

/* at_discv6_identity_init initializes an identity from a private key.
   TOS parity: input is treated as raw secret bytes and reduced mod-L to a
   canonical non-zero scalar before key derivation. Computes public key and
   node ID.
   Returns identity on success, NULL on failure. */
at_discv6_identity_t *
at_discv6_identity_init( at_discv6_identity_t * identity,
                         uchar const            private_key[32] );

/* at_discv6_identity_from_public creates a partial identity from public key.
   Only fills public_key and node_id (private_key is zeroed).
   Useful for representing remote nodes.
   Returns identity on success, NULL on failure. */
at_discv6_identity_t *
at_discv6_identity_from_public( at_discv6_identity_t * identity,
                                uchar const            public_key[32] );

/* at_discv6_compute_node_id computes SHA3-256(public_key).
   Writes 32 bytes to node_id.
   Returns node_id on success, NULL on failure. */
uchar *
at_discv6_compute_node_id( uchar       node_id[32],
                           uchar const public_key[32] );

/**********************************************************************/
/* XOR Distance Functions                                              */
/**********************************************************************/

/* at_discv6_xor_distance computes XOR distance between two node IDs.
   Writes 32 bytes to out.
   Returns out. */
uchar *
at_discv6_xor_distance( uchar       out[32],
                        uchar const a[32],
                        uchar const b[32] );

/* at_discv6_distance_cmp compares XOR distances.
   Returns negative if dist_a < dist_b, 0 if equal, positive if dist_a > dist_b. */
int
at_discv6_distance_cmp( uchar const dist_a[32],
                        uchar const dist_b[32] );

/* at_discv6_bucket_index returns the bucket index for a node ID relative
   to our own node ID. This is the number of leading zero bits in the
   XOR distance (clamped to [0, 255]).

   Bucket 0 = most distant (XOR has leading 1 bit)
   Bucket 255 = closest (XOR has 255 leading 0 bits, only last bit differs)

   Returns bucket index in [0, 255]. */
ulong
at_discv6_bucket_index( uchar const our_id[32],
                        uchar const their_id[32] );

/* at_discv6_leading_zeros returns the number of leading zero bits in a 256-bit value.
   Returns value in [0, 256]. */
ulong
at_discv6_leading_zeros( uchar const val[32] );

/**********************************************************************/
/* Comparison Functions                                                */
/**********************************************************************/

/* at_discv6_id_eq returns 1 if two node IDs are equal, 0 otherwise. */
static inline int
at_discv6_id_eq( uchar const a[32],
                 uchar const b[32] ) {
  return at_memeq( a, b, 32 );
}

/* at_discv6_closer_to returns 1 if node a is closer to target than node b.
   Used for sorting nodes by distance to a target. */
int
at_discv6_closer_to( uchar const target[32],
                     uchar const a[32],
                     uchar const b[32] );

AT_PROTOTYPES_END

#endif /* HEADER_at_waltz_p2p_discovery_at_discv6_identity_h */
