#ifndef HEADER_at_blockdag_at_dag_provider_h
#define HEADER_at_blockdag_at_dag_provider_h

/* at_dag_provider.h - Abstract storage interface for BlockDAG

   This header defines the storage provider interface for BlockDAG
   operations. The interface abstracts away the underlying storage
   mechanism, allowing different implementations (memory, rocks).

   The production implementation uses RocksDB for TOS-compatible
   persistent storage. */

#include "at/infra/at_util_base.h"
#include "at/core/blockdag/at_dag_config.h"
#include "at_blockdag.h"
#include "at_difficulty.h"

/* Forward declarations for allocator */
#ifndef HEADER_at_alloc_at_alloc_h
struct at_alloc;
typedef struct at_alloc at_alloc_t;
#endif

/* Forward declaration for workspace handle */
#ifndef HEADER_at_wksp_at_wksp_h
struct at_wksp_private;
typedef struct at_wksp_private at_wksp_t;
#endif

/* Forward declarations for at_rocks / at_store types */
#ifndef HEADER_at_rocks_at_rocks_h
struct at_rocks;
typedef struct at_rocks at_rocks_t;
#endif
#ifndef HEADER_at_store_at_store_h
struct at_store;
typedef struct at_store at_store_t;
#endif

AT_PROTOTYPES_BEGIN

/* Provider type enum */

typedef enum {
  AT_DAG_PROVIDER_MEMORY = 0,  /* In-memory storage (for testing) */
  AT_DAG_PROVIDER_ROCKS  = 1   /* RocksDB-based persistent storage (TOS compatible) */
} at_dag_provider_type_t;

/* DAG provider metadata

   Singleton record containing global DAG state like next topoheight. */

typedef struct {
  at_topoheight_t next_topoheight;   /* Next topoheight to assign */
  at_topoheight_t stable_topoheight; /* Last stable (irreversible) topoheight */
  uchar           genesis_hash[AT_BLOCK_HASH_SZ]; /* Genesis block hash */
} at_dag_metadata_t;

/* Abstract provider structure

   Implementations should extend this with their specific fields. */

struct at_dag_provider {
  at_dag_provider_type_t type;

  /* Virtual function table */

  /* Node operations */
  int (*get_node)( at_dag_provider_t const * provider,
                   uchar const             * hash,
                   at_dag_node_t           * out_node );

  int (*set_node)( at_dag_provider_t * provider,
                   uchar const       * hash,
                   at_dag_node_t const * node );

  int (*del_node)( at_dag_provider_t * provider,
                   uchar const       * hash );

  /* Topoheight mapping */
  int (*get_hash_at_topoheight)( at_dag_provider_t const * provider,
                                 at_topoheight_t           topoheight,
                                 uchar                   * out_hash );

  int (*set_hash_at_topoheight)( at_dag_provider_t * provider,
                                 at_topoheight_t     topoheight,
                                 uchar const       * hash );

  int (*clear_topoheight)( at_dag_provider_t * provider,
                           at_topoheight_t     topoheight );

  /* Metadata */
  at_topoheight_t (*get_next_topoheight)( at_dag_provider_t const * provider );

  int (*set_next_topoheight)( at_dag_provider_t * provider,
                              at_topoheight_t     next_topo );

  at_topoheight_t (*get_stable_topoheight)( at_dag_provider_t const * provider );

  int (*set_stable_topoheight)( at_dag_provider_t * provider,
                                at_topoheight_t     stable_topo );

  /* Tips management */
  int (*get_tips)( at_dag_provider_t const * provider,
                   at_dag_tips_t           * out_tips );

  int (*set_tips)( at_dag_provider_t * provider,
                   at_dag_tips_t const * tips );

  /* Blocks-at-height index */
  int (*get_blocks_at_height)( at_dag_provider_t const * provider,
                               ulong                    height,
                               uchar                  * hashes_out,
                               ulong                    max_hashes,
                               ulong                  * count_out );
  int (*add_block_hash_at_height)( at_dag_provider_t * provider,
                                   uchar const       * hash,
                                   ulong              height );
  int (*remove_block_hash_at_height)( at_dag_provider_t * provider,
                                      uchar const       * hash,
                                      ulong              height );

  /* Raw block data storage (for ObjectRequest responses) */
  int (*get_block_data)( at_dag_provider_t const * provider,
                         uchar const             * hash,
                         void                    * out_data,
                         ulong                   * inout_sz );
  int (*set_block_data)( at_dag_provider_t * provider,
                         uchar const       * hash,
                         void const        * data,
                         ulong               sz );
  int (*get_tx_data)( at_dag_provider_t const * provider,
                      uchar const             * hash,
                      void                    * out_data,
                      ulong                   * inout_sz );
};

/* === Provider API Functions === */

static inline int
at_dag_provider_has_vtable( at_dag_provider_t const * provider ) {
  return (provider != NULL) && (provider->get_node != NULL) && (provider->set_node != NULL) &&
         (provider->del_node != NULL) && (provider->get_hash_at_topoheight != NULL) &&
         (provider->set_hash_at_topoheight != NULL) && (provider->clear_topoheight != NULL) &&
         (provider->get_next_topoheight != NULL) && (provider->set_next_topoheight != NULL) &&
         (provider->get_stable_topoheight != NULL) && (provider->set_stable_topoheight != NULL) &&
         (provider->get_tips != NULL) && (provider->set_tips != NULL) &&
         (provider->get_blocks_at_height != NULL) && (provider->add_block_hash_at_height != NULL) &&
         (provider->remove_block_hash_at_height != NULL) && (provider->get_block_data != NULL) &&
         (provider->set_block_data != NULL) && (provider->get_tx_data != NULL);
}

/* Node operations */

static inline int
at_dag_get_node( at_dag_provider_t const * provider,
                 uchar const             * hash,
                 at_dag_node_t           * out_node ) {
  if( !provider || !provider->get_node ) return AT_DAG_ERR_INVAL;
  return provider->get_node( provider, hash, out_node );
}

static inline int
at_dag_set_node( at_dag_provider_t * provider,
                 uchar const       * hash,
                 at_dag_node_t const * node ) {
  if( !provider || !provider->set_node ) return AT_DAG_ERR_INVAL;
  return provider->set_node( provider, hash, node );
}

static inline int
at_dag_del_node( at_dag_provider_t * provider,
                 uchar const       * hash ) {
  if( !provider || !provider->del_node ) return AT_DAG_ERR_INVAL;
  return provider->del_node( provider, hash );
}

/* Topoheight mapping */

static inline int
at_dag_get_hash_at_topoheight( at_dag_provider_t const * provider,
                               at_topoheight_t           topoheight,
                               uchar                   * out_hash ) {
  if( !provider || !provider->get_hash_at_topoheight ) return AT_DAG_ERR_INVAL;
  return provider->get_hash_at_topoheight( provider, topoheight, out_hash );
}

static inline int
at_dag_set_hash_at_topoheight( at_dag_provider_t * provider,
                               at_topoheight_t     topoheight,
                               uchar const       * hash ) {
  if( !provider || !provider->set_hash_at_topoheight ) return AT_DAG_ERR_INVAL;
  return provider->set_hash_at_topoheight( provider, topoheight, hash );
}

static inline int
at_dag_clear_topoheight( at_dag_provider_t * provider,
                         at_topoheight_t     topoheight ) {
  if( !provider || !provider->clear_topoheight ) return AT_DAG_ERR_INVAL;
  return provider->clear_topoheight( provider, topoheight );
}

/* Metadata */

static inline at_topoheight_t
at_dag_get_next_topoheight( at_dag_provider_t const * provider ) {
  if( !provider || !provider->get_next_topoheight ) return 0UL;
  return provider->get_next_topoheight( provider );
}

static inline int
at_dag_set_next_topoheight( at_dag_provider_t * provider,
                            at_topoheight_t     next_topo ) {
  if( !provider || !provider->set_next_topoheight ) return AT_DAG_ERR_INVAL;
  return provider->set_next_topoheight( provider, next_topo );
}

static inline at_topoheight_t
at_dag_get_stable_topoheight( at_dag_provider_t const * provider ) {
  if( !provider || !provider->get_stable_topoheight ) return 0UL;
  return provider->get_stable_topoheight( provider );
}

static inline int
at_dag_set_stable_topoheight( at_dag_provider_t * provider,
                              at_topoheight_t     stable_topo ) {
  if( !provider || !provider->set_stable_topoheight ) return AT_DAG_ERR_INVAL;
  return provider->set_stable_topoheight( provider, stable_topo );
}

/* Tips management */

static inline int
at_dag_get_tips( at_dag_provider_t const * provider,
                 at_dag_tips_t           * out_tips ) {
  if( !provider || !provider->get_tips ) return AT_DAG_ERR_INVAL;
  return provider->get_tips( provider, out_tips );
}

static inline int
at_dag_set_tips( at_dag_provider_t * provider,
                 at_dag_tips_t const * tips ) {
  if( !provider || !provider->set_tips ) return AT_DAG_ERR_INVAL;
  return provider->set_tips( provider, tips );
}

/* Blocks-at-height index */

static inline int
at_dag_get_blocks_at_height( at_dag_provider_t const * provider,
                             ulong                    height,
                             uchar                  * hashes_out,
                             ulong                    max_hashes,
                             ulong                  * count_out ) {
  if( !provider || !provider->get_blocks_at_height ) return AT_DAG_ERR_INVAL;
  return provider->get_blocks_at_height( provider, height, hashes_out, max_hashes, count_out );
}

static inline int
at_dag_add_block_hash_at_height( at_dag_provider_t * provider,
                                 uchar const       * hash,
                                 ulong              height ) {
  if( !provider || !provider->add_block_hash_at_height ) return AT_DAG_ERR_INVAL;
  return provider->add_block_hash_at_height( provider, hash, height );
}

static inline int
at_dag_remove_block_hash_at_height( at_dag_provider_t * provider,
                                    uchar const       * hash,
                                    ulong              height ) {
  if( !provider || !provider->remove_block_hash_at_height ) return AT_DAG_ERR_INVAL;
  return provider->remove_block_hash_at_height( provider, hash, height );
}

/* Raw block data storage */

static inline int
at_dag_get_block_data( at_dag_provider_t const * provider,
                       uchar const             * hash,
                       void                    * out_data,
                       ulong                   * inout_sz ) {
  if( !provider || !provider->get_block_data ) return AT_DAG_ERR_NOT_FOUND;
  return provider->get_block_data( provider, hash, out_data, inout_sz );
}

static inline int
at_dag_get_tx_data( at_dag_provider_t const * provider,
                    uchar const             * hash,
                    void                    * out_data,
                    ulong                   * inout_sz ) {
  if( !provider || !provider->get_tx_data ) return AT_DAG_ERR_NOT_FOUND;
  return provider->get_tx_data( provider, hash, out_data, inout_sz );
}

static inline int
at_dag_set_block_data( at_dag_provider_t * provider,
                       uchar const       * hash,
                       void const        * data,
                       ulong               sz ) {
  if( !provider || !provider->set_block_data ) return AT_DAG_ERR_INVAL;
  return provider->set_block_data( provider, hash, data, sz );
}

/* === Convenience Functions === */

/* Get block height */

static inline ulong
at_dag_get_height( at_dag_provider_t const * provider,
                   uchar const             * hash ) {
  at_dag_node_t node;
  if( at_dag_get_node( provider, hash, &node ) != AT_DAG_SUCCESS ) {
    return 0UL;
  }
  return node.height;
}

/* Get cumulative difficulty */

static inline at_cumulative_difficulty_t
at_dag_get_cumulative_difficulty( at_dag_provider_t const * provider,
                                  uchar const             * hash ) {
  at_dag_node_t node;
  if( at_dag_get_node( provider, hash, &node ) != AT_DAG_SUCCESS ) {
    return 0UL;
  }
  return node.cumulative_diff;
}

/* Get timestamp */

static inline ulong
at_dag_get_timestamp( at_dag_provider_t const * provider,
                      uchar const             * hash ) {
  at_dag_node_t node;
  if( at_dag_get_node( provider, hash, &node ) != AT_DAG_SUCCESS ) {
    return 0UL;
  }
  return node.timestamp_ms;
}

/* Get difficulty */

static inline at_difficulty_t
at_dag_get_difficulty( at_dag_provider_t const * provider,
                       uchar const             * hash ) {
  at_dag_node_t node;
  if( at_dag_get_node( provider, hash, &node ) != AT_DAG_SUCCESS ) {
    return 0UL;
  }
  return node.difficulty;
}

/* Get computed difficulty (Kalman output for next block) */

static inline at_difficulty_t
at_dag_get_computed_difficulty( at_dag_provider_t const * provider,
                                uchar const             * hash ) {
  at_dag_node_t node;
  if( at_dag_get_node( provider, hash, &node ) != AT_DAG_SUCCESS ) {
    return 0UL;
  }
  return node.computed_difficulty;
}

/* Get Kalman covariance */

static inline ulong
at_dag_get_covariance( at_dag_provider_t const * provider,
                       uchar const             * hash ) {
  at_dag_node_t node;
  if( at_dag_get_node( provider, hash, &node ) != AT_DAG_SUCCESS ) {
    return AT_KALMAN_INITIAL_P;
  }
  return node.estimated_covariance;
}

/* Check if block exists */

static inline int
at_dag_block_exists( at_dag_provider_t const * provider,
                     uchar const             * hash ) {
  at_dag_node_t node;
  return at_dag_get_node( provider, hash, &node ) == AT_DAG_SUCCESS;
}

/* === Memory-based Provider (for testing) === */

/* Memory provider structure */

/* Block data entry for memory provider */
typedef struct {
  uchar hash[AT_BLOCK_HASH_SZ];
  ulong   data_gaddr;
  ulong   sz;
} at_dag_block_data_entry_t;

/* Shared mutable counters for memory provider (workspace-backed). */
typedef struct {
  ulong nodes_cnt;
  ulong block_data_cnt;
} at_dag_memory_provider_state_t;

/* Maximum block data size for memory provider */
#define AT_DAG_MEMORY_MAX_BLOCK_DATA_SZ (65536UL)

typedef struct {
  at_dag_provider_t base;       /* Base provider (must be first) */

  /* Allocator for dynamic block data allocations */
  at_alloc_t      * alloc;

  /* Local workspace mapping for gaddr<->laddr conversion
   * (set by join path per process; NULL means conversions not possible) */
  at_wksp_t       * wksp;

  /* In-memory node storage (simple linear array for testing) */
  at_dag_node_t   * nodes;
  ulong             nodes_max;
  ulong             nodes_cnt;

  /* Topoheight -> hash mapping */
  uchar           (* topo_hashes)[AT_BLOCK_HASH_SZ];
  ulong             topo_max;

  /* Topoheight -> block height (survives node eviction, enables RPC block_type queries) */
  ulong           * topo_heights;    /* [topo_max]: block height at each topoheight (ULONG_MAX = unset) */

  /* Block data storage (for ObjectRequest responses) */
  at_dag_block_data_entry_t * block_data;
  ulong                       block_data_max;
  ulong                       block_data_cnt;

  /* Shared mutable counters */
  at_dag_memory_provider_state_t * state;

  /* Tips (shared across processes via workspace) */
  at_dag_tips_t   * tips;

  /* Metadata (shared across processes via workspace) */
  at_dag_metadata_t * metadata;

  /* Per-topoheight difficulty/cumulative_diff snapshots (survives node eviction).
     Populated by memory_set_hash_at_topoheight; used by RPC when node is evicted.
     Sentinel: (ulong)-1 = unset. */
  ulong * topo_difficulty;   /* [topo_max]: node.difficulty at each topoheight */
  ulong * topo_cumulative;   /* [topo_max]: node.cumulative_diff at each topoheight */
} at_dag_memory_provider_t;

/* Callback invoked just before a node is evicted from the memory DAG.
   Used by sync tile to persist difficulty/cumulative_diff to RocksDB
   before the node is removed from the in-memory array. */
typedef void (*at_dag_eviction_cb_t)( void * ctx, at_dag_node_t const * node );

/* Evict ordered DAG nodes at topoheight <= evict_up_to from memory (O(n) compaction).
   If cb is non-NULL, it is called for each node just before eviction.
   Memory-only: does not touch RocksDB. Returns number of nodes evicted. */
ulong
at_dag_memory_evict_below_topoheight( at_dag_provider_t    * provider,
                                       at_topoheight_t        evict_up_to,
                                       at_dag_eviction_cb_t   cb,
                                       void                 * cb_ctx );

/* Create memory-based provider

   Args:
     mem:       Memory for provider
     nodes_max: Maximum number of nodes to store
     topo_max:  Maximum topoheight

   Returns:
     Initialized provider, or NULL on error. */

at_dag_provider_t *
at_dag_memory_provider_new( void       * mem,
                            ulong        nodes_max,
                            ulong        topo_max,
                            at_alloc_t * alloc );

/* Join an existing memory-based provider

   This creates a local provider struct with pointers recalculated to
   point into the shared workspace, enabling cross-process access.

   Args:
     local_mem:     Local memory for join struct (sizeof(at_dag_memory_provider_t))
     workspace_mem: Shared workspace address (from at_topo_obj_laddr)
     wksp:         Workspace used to translate data_gaddr in this process
     nodes_max:     Maximum number of nodes (must match the original)
     topo_max:      Maximum topoheight (must match the original)
     alloc:         Local allocator for this process

   Returns:
     Joined provider, or NULL on error. */

at_dag_provider_t *
at_dag_memory_provider_join( void       * local_mem,
                             void       * workspace_mem,
                             at_wksp_t  * wksp,
                             ulong        nodes_max,
                             ulong        topo_max,
                             at_alloc_t * alloc );

/* Leave a memory-based provider

   Flushes any cached state and releases the provider.

   Args:
     provider: Provider to leave

   Returns:
     Original memory pointer. */

void *
at_dag_memory_provider_leave( at_dag_provider_t * provider );

/* Delete memory-based provider */

void *
at_dag_memory_provider_delete( at_dag_provider_t * provider );

/* Get memory provider alignment */

static inline ulong
at_dag_memory_provider_align( void ) {
  return 64UL;
}

/* Get memory provider footprint */

ulong
at_dag_memory_provider_footprint( ulong nodes_max,
                                  ulong topo_max );

/* === RocksDB-based Provider (TOS compatible) === */

/* RocksDB provider structure */

typedef struct {
  at_dag_provider_t base;       /* Base provider (must be first) */
  at_rocks_t      * rocks;      /* RocksDB instance */
  at_dag_metadata_t metadata;   /* Cached metadata */
  int               metadata_dirty; /* Metadata needs write */
} at_dag_rocks_provider_t;

/* Create RocksDB-based provider

   Args:
     mem:   Memory for provider (at least sizeof(at_dag_rocks_provider_t))
     rocks: RocksDB instance to use

   Returns:
     Initialized provider, or NULL on error. */

at_dag_provider_t *
at_dag_rocks_provider_new( void        * mem,
                           at_rocks_t  * rocks );

/* Join an existing RocksDB-based provider

   Args:
     mem:   Memory for provider
     rocks: RocksDB instance

   Returns:
     Joined provider, or NULL on error. */

at_dag_provider_t *
at_dag_rocks_provider_join( void       * mem,
                            at_rocks_t * rocks );

/* Leave a RocksDB-based provider

   Flushes any cached state and releases the provider.

   Args:
     provider: Provider to leave

   Returns:
     Original memory pointer. */

void *
at_dag_rocks_provider_leave( at_dag_provider_t * provider );

/* Get provider alignment requirement */

static inline ulong
at_dag_rocks_provider_align( void ) {
  return 64UL;
}

/* Get provider footprint */

static inline ulong
at_dag_rocks_provider_footprint( void ) {
  return sizeof(at_dag_rocks_provider_t);
}

AT_PROTOTYPES_END

#endif /* HEADER_at_blockdag_at_dag_provider_h */
