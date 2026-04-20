#ifndef HEADER_at_waltz_p2p_discovery_at_discv6_routing_h
#define HEADER_at_waltz_p2p_discovery_at_discv6_routing_h

/* at_discv6_routing.h - Kademlia Routing Table

   Implements a Kademlia-style routing table with 256 k-buckets.
   Each bucket holds up to k=16 nodes at a given XOR distance.

   Bucket Selection:
   - Bucket index = number of leading zero bits in XOR(local_id, remote_id)
   - Bucket 0: nodes with XOR distance starting with 1xxxxxxx (most distant)
   - Bucket 255: nodes with XOR distance starting with 255 zeros (closest)

   Node Lifecycle:
   - New nodes are added to appropriate bucket if space available
   - If bucket is full, check if oldest node is still alive
   - If oldest is dead, evict and add new node
   - If oldest is alive, keep it (Kademlia prefers older nodes)
*/

#include "at/p2p/discovery/at_discv6_messages.h"

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* Bucket Entry                                                        */
/**********************************************************************/

typedef struct {
  at_discv6_node_t node;            /* Node information */
  ulong            added_at;        /* Timestamp when added to bucket */
  uchar            fail_count;      /* Consecutive ping failures */
  uchar            _pad[7];
} at_discv6_bucket_entry_t;

/**********************************************************************/
/* K-Bucket                                                            */
/**********************************************************************/

#define AT_DISCV6_BUCKET_K (16UL)

typedef struct {
  at_discv6_bucket_entry_t entries[AT_DISCV6_BUCKET_K];
  ulong cnt;                        /* Number of nodes in bucket */
  ulong last_refresh;               /* Last time bucket was refreshed */
} at_discv6_bucket_t;

/**********************************************************************/
/* Routing Table                                                       */
/**********************************************************************/

#define AT_DISCV6_ROUTING_BUCKETS (256UL)

typedef struct {
  at_discv6_bucket_t buckets[AT_DISCV6_ROUTING_BUCKETS];
  uchar              local_id[32];  /* Our node ID for distance calculations */
  ulong              total_nodes;   /* Total nodes across all buckets */
} at_discv6_routing_table_t;

/**********************************************************************/
/* Table Lifecycle                                                     */
/**********************************************************************/

/* at_discv6_routing_init initializes a routing table.
   local_id: our node ID (32 bytes)
   Returns table on success, NULL on failure. */
at_discv6_routing_table_t *
at_discv6_routing_init( at_discv6_routing_table_t * table,
                        uchar const                 local_id[32] );

/**********************************************************************/
/* Node Operations                                                     */
/**********************************************************************/

/* at_discv6_routing_insert attempts to insert a node into the routing table.
   If the bucket is full, returns AT_DISCV6_ERR_FULL.
   Caller should then ping the oldest node in the bucket and evict if dead.
   Returns 0 on success, negative error code on failure. */
int
at_discv6_routing_insert( at_discv6_routing_table_t * table,
                          at_discv6_node_t const *    node,
                          ulong                       now );

/* at_discv6_routing_remove removes a node from the routing table.
   Returns 0 if removed, AT_DISCV6_ERR_NOT_FOUND if not present. */
int
at_discv6_routing_remove( at_discv6_routing_table_t * table,
                          uchar const                 node_id[32] );

/* at_discv6_routing_update updates a node's last_seen timestamp.
   Returns 0 if found and updated, AT_DISCV6_ERR_NOT_FOUND if not present. */
int
at_discv6_routing_update( at_discv6_routing_table_t * table,
                          uchar const                 node_id[32],
                          ulong                       now );

/* at_discv6_routing_find looks up a node by ID.
   Returns pointer to node or NULL if not found. */
at_discv6_node_t *
at_discv6_routing_find( at_discv6_routing_table_t * table,
                        uchar const                 node_id[32] );

/* at_discv6_routing_mark_failed increments fail count for a node.
   If fail_count exceeds threshold (3), removes the node.
   Returns 0 if updated, 1 if removed, negative error on failure. */
int
at_discv6_routing_mark_failed( at_discv6_routing_table_t * table,
                               uchar const                 node_id[32] );

/* at_discv6_routing_mark_alive resets fail count to 0.
   Returns 0 on success, negative error on failure. */
int
at_discv6_routing_mark_alive( at_discv6_routing_table_t * table,
                              uchar const                 node_id[32],
                              ulong                       now );

/**********************************************************************/
/* Lookup Operations                                                   */
/**********************************************************************/

/* at_discv6_routing_find_closest finds the closest nodes to a target.
   Writes up to max_nodes node pointers to out.
   Returns number of nodes found. */
ulong
at_discv6_routing_find_closest( at_discv6_routing_table_t * table,
                                uchar const                 target[32],
                                at_discv6_node_t const **   out,
                                ulong                       max_nodes );

/**********************************************************************/
/* Bucket Operations                                                   */
/**********************************************************************/

/* at_discv6_routing_bucket_for returns the bucket for a given node ID.
   Returns pointer to bucket or NULL if node ID equals local ID. */
at_discv6_bucket_t *
at_discv6_routing_bucket_for( at_discv6_routing_table_t * table,
                              uchar const                 node_id[32] );

/* at_discv6_routing_oldest_in_bucket returns the oldest node in a bucket.
   Returns pointer to oldest entry or NULL if bucket is empty. */
at_discv6_bucket_entry_t *
at_discv6_routing_oldest_in_bucket( at_discv6_bucket_t * bucket );

/* at_discv6_routing_evict_oldest removes the oldest node from a bucket.
   Returns 0 on success, AT_DISCV6_ERR_NOT_FOUND if bucket is empty. */
int
at_discv6_routing_evict_oldest( at_discv6_routing_table_t * table,
                                ulong                       bucket_idx );

/**********************************************************************/
/* Refresh Operations                                                  */
/**********************************************************************/

/* at_discv6_routing_needs_refresh returns 1 if any bucket needs refresh.
   stale_threshold: nanoseconds since last refresh to consider stale */
int
at_discv6_routing_needs_refresh( at_discv6_routing_table_t const * table,
                                 ulong                             now,
                                 ulong                             stale_threshold );

/* at_discv6_routing_next_refresh_target generates a random target ID
   that falls into the specified bucket index. Used to refresh stale buckets.
   Returns bucket index that needs refresh, or ULONG_MAX if none needed. */
ulong
at_discv6_routing_next_refresh_bucket( at_discv6_routing_table_t const * table,
                                       ulong                             now,
                                       ulong                             stale_threshold );

/* at_discv6_routing_random_target_for_bucket generates a random target
   that falls into the specified bucket.
   rng_state: pointer to PRNG state (will be modified)
   Returns out. */
uchar *
at_discv6_routing_random_target_for_bucket( at_discv6_routing_table_t const * table,
                                            ulong                             bucket_idx,
                                            ulong *                           rng_state,
                                            uchar                             out[32] );

/**********************************************************************/
/* Statistics                                                          */
/**********************************************************************/

/* at_discv6_routing_count returns total number of nodes in table. */
static inline ulong
at_discv6_routing_count( at_discv6_routing_table_t const * table ) {
  return table ? table->total_nodes : 0;
}

/* at_discv6_routing_bucket_count returns number of nodes in a bucket. */
static inline ulong
at_discv6_routing_bucket_count( at_discv6_routing_table_t const * table,
                                ulong                             bucket_idx ) {
  if( !table || bucket_idx >= AT_DISCV6_ROUTING_BUCKETS ) return 0;
  return table->buckets[bucket_idx].cnt;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_waltz_p2p_discovery_at_discv6_routing_h */
