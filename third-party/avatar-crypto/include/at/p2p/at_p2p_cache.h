#ifndef HEADER_at_waltz_p2p_at_p2p_cache_h
#define HEADER_at_waltz_p2p_at_p2p_cache_h

/* at_p2p_cache.h - P2P Propagation Cache

   LRU caches for tracking which transactions and blocks have been
   exchanged with peers, preventing redundant propagation.
*/

#include "at/infra/at_util_base.h"
#include "at/p2p/at_p2p_direction.h"

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* Constants                                                          */
/**********************************************************************/

/* Cache sizes */
#define AT_TX_CACHE_SIZE      (8192UL)  /* TX hash cache entries */
#define AT_BLOCK_CACHE_SIZE   (1024UL)  /* Block hash cache entries */

/* Entry directions (TOS: In/Out/Both) */
#define AT_CACHE_DIR_NONE     (AT_DIRECTION_NONE)
#define AT_CACHE_DIR_RECV     (AT_DIRECTION_IN)    /* We received this from peer (TOS: In) */
#define AT_CACHE_DIR_SENT     (AT_DIRECTION_OUT)   /* We sent this to peer (TOS: Out) */
#define AT_CACHE_DIR_BOTH     (AT_DIRECTION_BOTH)  /* Both directions (immutable) */

/* Default max age for cache entries (5 minutes) */
#define AT_CACHE_MAX_AGE      (300UL * 1000000000UL)

/**********************************************************************/
/* Cache Entry                                                        */
/**********************************************************************/

typedef struct {
  uchar  hash[32];               /* TX or Block hash */
  ulong  timestamp;              /* Last cache touch (for expiration/LRU) */
  at_timed_direction_t timed_direction;
} at_propagation_entry_t;

/**********************************************************************/
/* Propagation Cache (LRU)                                            */
/**********************************************************************/

typedef struct {
  at_propagation_entry_t * entries;  /* Entry array */
  ulong                    capacity; /* Max entries */
  ulong                    cnt;      /* Current count */
  ulong                    head;     /* Oldest entry index (for LRU) */
} at_propagation_cache_t;

/**********************************************************************/
/* Lifecycle                                                          */
/**********************************************************************/

/* at_propagation_cache_init initializes a cache with given capacity.
   entries must point to array of at least capacity entries.
   Returns cache on success, NULL on failure. */
at_propagation_cache_t *
at_propagation_cache_init( at_propagation_cache_t * cache,
                           at_propagation_entry_t * entries,
                           ulong                    capacity );

/* at_propagation_cache_clear resets the cache. */
void
at_propagation_cache_clear( at_propagation_cache_t * cache );

/**********************************************************************/
/* Operations                                                         */
/**********************************************************************/

/* at_propagation_cache_add adds or updates a hash in the cache.
   If hash already exists, updates direction and timestamp.
   Uses LRU eviction when full.
   Returns 0 on success, -1 on failure. */
int
at_propagation_cache_add( at_propagation_cache_t * cache,
                          uchar const              hash[32],
                          uchar                    direction,
                          ulong                    now );

/* at_propagation_cache_has checks if a hash is in the cache.
   Returns 1 if present, 0 if not. */
int
at_propagation_cache_has( at_propagation_cache_t const * cache,
                          uchar const                    hash[32] );

/* at_propagation_cache_get_direction returns the direction for a hash.
   Returns direction if found, -1 if not in cache. */
int
at_propagation_cache_get_direction( at_propagation_cache_t const * cache,
                                    uchar const                    hash[32] );

/* at_propagation_cache_get_timed_direction returns full direction metadata.
   Returns 0 on success, -1 if not in cache or invalid args. */
int
at_propagation_cache_get_timed_direction( at_propagation_cache_t const * cache,
                                          uchar const                    hash[32],
                                          at_timed_direction_t *         direction_out );

/* at_propagation_cache_needs_propagation checks if we need to propagate to this peer.
   This is a PER-PEER check: if we've exchanged this hash with the peer in ANY direction
   (received from them OR sent to them), they already have it.
   Returns 1 if hash is NOT in cache (needs propagation to this peer).
   Returns 0 if hash IS in cache (peer already has it, no propagation needed). */
int
at_propagation_cache_needs_propagation( at_propagation_cache_t const * cache,
                                        uchar const                    hash[32] );

/* at_propagation_cache_expire removes entries older than max_age. */
void
at_propagation_cache_expire( at_propagation_cache_t * cache,
                             ulong                    max_age,
                             ulong                    now );

/**********************************************************************/
/* Per-Peer Propagation State                                         */
/**********************************************************************/

/* Pre-allocated entry arrays for TX and block caches */
typedef struct {
  at_propagation_entry_t tx_entries[AT_TX_CACHE_SIZE];
  at_propagation_entry_t block_entries[AT_BLOCK_CACHE_SIZE];
  at_propagation_cache_t tx_cache;
  at_propagation_cache_t block_cache;
} at_peer_propagation_t;

/* at_peer_propagation_init initializes per-peer propagation state.
   Returns state on success, NULL on failure. */
at_peer_propagation_t *
at_peer_propagation_init( at_peer_propagation_t * state );

/* at_peer_propagation_clear resets both caches. */
void
at_peer_propagation_clear( at_peer_propagation_t * state );

/* at_peer_propagation_add_tx adds a TX hash. */
static inline int
at_peer_propagation_add_tx( at_peer_propagation_t * state,
                            uchar const             hash[32],
                            uchar                   direction,
                            ulong                   now ) {
  return at_propagation_cache_add( &state->tx_cache, hash, direction, now );
}

/* at_peer_propagation_add_block adds a block hash. */
static inline int
at_peer_propagation_add_block( at_peer_propagation_t * state,
                               uchar const             hash[32],
                               uchar                   direction,
                               ulong                   now ) {
  return at_propagation_cache_add( &state->block_cache, hash, direction, now );
}

/* at_peer_propagation_has_tx checks if TX hash is in cache. */
static inline int
at_peer_propagation_has_tx( at_peer_propagation_t const * state,
                            uchar const                   hash[32] ) {
  return at_propagation_cache_has( &state->tx_cache, hash );
}

/* at_peer_propagation_has_block checks if block hash is in cache. */
static inline int
at_peer_propagation_has_block( at_peer_propagation_t const * state,
                               uchar const                   hash[32] ) {
  return at_propagation_cache_has( &state->block_cache, hash );
}

/* at_peer_propagation_needs_tx checks if TX needs propagation. */
static inline int
at_peer_propagation_needs_tx( at_peer_propagation_t const * state,
                              uchar const                   hash[32] ) {
  return at_propagation_cache_needs_propagation( &state->tx_cache, hash );
}

/* at_peer_propagation_needs_block checks if block needs propagation. */
static inline int
at_peer_propagation_needs_block( at_peer_propagation_t const * state,
                                 uchar const                   hash[32] ) {
  return at_propagation_cache_needs_propagation( &state->block_cache, hash );
}

AT_PROTOTYPES_END

#endif /* HEADER_at_waltz_p2p_at_p2p_cache_h */
