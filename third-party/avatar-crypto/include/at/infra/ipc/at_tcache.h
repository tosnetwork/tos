#ifndef HEADER_at_src_tango_tcache_at_tcache_h
#define HEADER_at_src_tango_tcache_at_tcache_h

/* A at_tcache_t is a cache of the most recently observed unique 64-bit
   tags.  It is useful for, among other things, deduplication of traffic
   based on a thumbprint / hash / signature. */

#include "at_tango_base.h"

/* AT_TCACHE_{ALIGN,FOOTPRINT} specify the alignment and footprint
   needed for a tcache with depth history and a tag key-only map with
   map_cnt slots. */

#define AT_TCACHE_ALIGN (128UL)
#define AT_TCACHE_FOOTPRINT( depth, map_cnt )                     \
  AT_LAYOUT_FINI( AT_LAYOUT_APPEND( AT_LAYOUT_INIT,               \
    AT_TCACHE_ALIGN, (4UL + (depth) + (map_cnt))*sizeof(ulong) ), \
    AT_TCACHE_ALIGN )

/* AT_TCACHE_TAG_NULL is a tag value that will never be inserted. */

#define AT_TCACHE_TAG_NULL (0UL)

/* AT_TCACHE_SPARSE_DEFAULT specifies how sparse a default map_cnt
   tcache map should be.  After startup, a tcache with a large depth
   with a default map size will have fixed fill ratio somewhere between
   ~2^-SPARSE_DEFAULT and ~2^-(SPARSE_DEFAULT-1). */

#define AT_TCACHE_SPARSE_DEFAULT (2)

/* at_tcache_t is an opaque handle of a tcache object. */

#define AT_TCACHE_MAGIC (0xf17eda2c377ca540UL) /* tcache ver 0 (binary compatible) */

struct __attribute((aligned(AT_TCACHE_ALIGN))) at_tcache_private {
  ulong magic;   /* ==AT_TCACHE_MAGIC */
  ulong depth;   /* The tcache will maintain a history of the most recent depth tags */
  ulong map_cnt;
  ulong oldest;  /* oldest is in [0,depth) */

  /* depth ulong (ring):
     After startup, ring[oldest] contains the oldest tag in the tcache.
     Ring is cyclic: entry before oldest (cyclic) is the newest tag. */

  /* map_cnt ulong (map):
     Sparse linear probed key-only map of tags currently in the tcache. */

  /* Padding to AT_TCACHE align */
};

typedef struct at_tcache_private at_tcache_t;

AT_PROTOTYPES_BEGIN

/* at_tcache_map_cnt_default returns the default map_cnt to use for the
   given depth.  Returns 0 if the depth is invalid. */

AT_FN_CONST static inline ulong
at_tcache_map_cnt_default( ulong depth ) {
  if( AT_UNLIKELY( !depth ) ) return 0UL;
  if( AT_UNLIKELY( depth==ULONG_MAX ) ) return 0UL;
  int lg_map_cnt = at_ulong_find_msb( depth + 1UL ) + AT_TCACHE_SPARSE_DEFAULT;
  if( AT_UNLIKELY( lg_map_cnt>63 ) ) return 0UL;
  return 1UL << lg_map_cnt;
}

/* at_tcache_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as a tcache. */

AT_FN_CONST static inline ulong at_tcache_align( void ) { return AT_TCACHE_ALIGN; }

AT_FN_CONST static inline ulong
at_tcache_footprint( ulong depth,
                     ulong map_cnt ) {
  if( !map_cnt ) map_cnt = at_tcache_map_cnt_default( depth );
  if( AT_UNLIKELY( (!depth) |
                   (!at_ulong_is_pow2( map_cnt )) |
                   (map_cnt<(depth+2UL)) ) ) return 0UL;
  return AT_TCACHE_FOOTPRINT( depth, map_cnt );
}

/* at_tcache_new formats an unused memory region for use as a tcache. */

void *
at_tcache_new( void * shmem,
               ulong  depth,
               ulong  map_cnt );

/* at_tcache_join joins the caller to the tcache. */

at_tcache_t *
at_tcache_join( void * shcache );

/* at_tcache_leave leaves a current local join. */

void *
at_tcache_leave( at_tcache_t * tcache );

/* at_tcache_delete unformats a memory region used as a tcache. */

void *
at_tcache_delete( void * shcache );

/* Accessor functions */

AT_FN_PURE static inline ulong at_tcache_depth  ( at_tcache_t const * tcache ) { return tcache->depth;   }
AT_FN_PURE static inline ulong at_tcache_map_cnt( at_tcache_t const * tcache ) { return tcache->map_cnt; }

AT_FN_PURE static inline ulong const *
at_tcache_oldest_laddr( at_tcache_t const * tcache ) {
  return &tcache->oldest;
}

static inline ulong *
at_tcache_oldest_laddr_nc( at_tcache_t * tcache ) {
  return &tcache->oldest;
}

AT_FN_PURE static inline ulong const *
at_tcache_ring_laddr( at_tcache_t const * tcache ) {
  return ((ulong const *)(tcache+1UL));
}

static inline ulong *
at_tcache_ring_laddr_nc( at_tcache_t * tcache ) {
  return ((ulong *)(tcache+1UL));
}

AT_FN_PURE static inline ulong const *
at_tcache_map_laddr( at_tcache_t const * tcache ) {
  return ((ulong const *)(tcache+1UL)) + tcache->depth;
}

static inline ulong *
at_tcache_map_laddr_nc( at_tcache_t * tcache ) {
  return ((ulong *)(tcache+1UL)) + tcache->depth;
}

/* AT_TCACHE_QUERY queries if tag is in the tcache map */

#define AT_TCACHE_QUERY( is_dup, map_idx, map, map_cnt, tag ) do {       \
    ulong _at_tcache_q_map_cnt = (map_cnt);                              \
    ulong _at_tcache_q_tag     = (tag);                                  \
    ulong _at_tcache_q_map_idx = _at_tcache_q_tag;                       \
    ulong const * _at_tcache_q_map = (map);                              \
    for(;;) {                                                            \
      _at_tcache_q_map_idx &= (_at_tcache_q_map_cnt-1UL);                \
      ulong _at_tcache_q_map_tag = _at_tcache_q_map[ _at_tcache_q_map_idx ]; \
      int _at_tcache_q_is_null = _at_tcache_q_map_tag==AT_TCACHE_TAG_NULL; \
      int _at_tcache_q_is_dup  = _at_tcache_q_map_tag==_at_tcache_q_tag; \
      if( _at_tcache_q_is_null | _at_tcache_q_is_dup ) {                 \
        (is_dup)  = _at_tcache_q_is_dup;                                 \
        (map_idx) = _at_tcache_q_map_idx;                                \
        break;                                                           \
      }                                                                  \
      _at_tcache_q_map_idx++;                                            \
    }                                                                    \
  } while(0)

/* AT_TCACHE_INSERT inserts tag into the tcache */

#define AT_TCACHE_INSERT( is_dup, oldest, ring, depth, map, map_cnt, tag ) do { \
    ulong _at_tcache_depth   = (depth);                                  \
    ulong _at_tcache_map_cnt = (map_cnt);                                \
    ulong _at_tcache_tag     = (tag);                                    \
    ulong * _at_tcache_ring  = (ring);                                   \
    ulong * _at_tcache_map   = (map);                                    \
    ulong _at_tcache_oldest  = (oldest);                                 \
    ulong _at_tcache_map_idx = 0UL;                                      \
    AT_TCACHE_QUERY( is_dup, _at_tcache_map_idx, _at_tcache_map, _at_tcache_map_cnt, _at_tcache_tag ); \
    if( AT_LIKELY( !(is_dup) ) ) {                                       \
      ulong _at_tcache_oldest_tag = _at_tcache_ring[ _at_tcache_oldest ];\
      _at_tcache_ring[ _at_tcache_oldest ] = _at_tcache_tag;             \
      (oldest) = at_ulong_if( (_at_tcache_oldest+1UL)<_at_tcache_depth,  \
                              _at_tcache_oldest+1UL, 0UL );              \
      _at_tcache_map[ _at_tcache_map_idx ] = _at_tcache_tag;             \
      if( AT_LIKELY( _at_tcache_oldest_tag ) ) {                         \
        ulong _at_tcache_remove_idx = _at_tcache_oldest_tag;             \
        for(;;) {                                                        \
          _at_tcache_remove_idx &= (_at_tcache_map_cnt-1UL);             \
          if( AT_LIKELY( _at_tcache_map[_at_tcache_remove_idx]==_at_tcache_oldest_tag ) ) { \
            _at_tcache_map[ _at_tcache_remove_idx ] = AT_TCACHE_TAG_NULL;\
            break;                                                       \
          }                                                              \
          _at_tcache_remove_idx++;                                       \
        }                                                                \
      }                                                                  \
    }                                                                    \
  } while(0)

AT_PROTOTYPES_END

#endif /* HEADER_at_src_tango_tcache_at_tcache_h */