#ifndef HEADER_at_src_waltz_neigh_at_neigh4_map_h
#define HEADER_at_src_waltz_neigh_at_neigh4_map_h

/* at_neigh4_map.h provides APIs for IPv4 neighbor discovery using ARP.

   The neighbor table is implemented as a hashmap using the at_map_slot
   template, providing O(1) average-case lookup, insert, and remove.

   Thread safety note: Individual entry access uses atomic load/store
   for the 16-byte entries when available (AT_HAS_INT128). The map
   structure itself is not thread-safe for concurrent modifications. */

#include "at/infra/at_util_base.h"
#include "at/infra/at_util.h"

/* at_neigh4_entry_t holds a neighbor table entry.

   Memory layout (16 bytes total):
   - ip4_addr:            4 bytes - IPv4 address (big endian)
   - mac_addr:            6 bytes - Ethernet MAC address
   - state:               1 byte  - Entry state
   - probe_suppress_until: 5 bytes - Probe suppression deadline (40-bit) */

union __attribute__((aligned(16))) at_neigh4_entry {
  struct {
    uint  ip4_addr;
    uchar mac_addr[6]; /* MAC address */
    uchar state;
    ulong probe_suppress_until : 40; /* Holds deadline>>24, so minimum delay
                                        is ~16.7M ticks (2**24) */
    #define AT_NEIGH4_PROBE_SUPPRESS_SHIFT ( sizeof(ulong)*8 - 40 )
    #define AT_NEIGH4_PROBE_SUPPRESS_MASK ( (1UL<<40) - 1 )

    #define AT_NEIGH4_PROBE_SUPPRESS_UNTIL_SET(entry, deadline) \
      ulong udead = ((ulong)(deadline))>>AT_NEIGH4_PROBE_SUPPRESS_SHIFT; \
      udead >>= AT_NEIGH4_PROBE_SUPPRESS_SHIFT; \
      (entry)->probe_suppress_until = udead & AT_NEIGH4_PROBE_SUPPRESS_MASK;
    #define AT_NEIGH4_PROBE_SUPPRESS_UNTIL_GET(entry) \
      (long)(((entry)->probe_suppress_until)<<AT_NEIGH4_PROBE_SUPPRESS_SHIFT)
  };
#if AT_HAS_INT128
  uint128 uf[1];
#endif
  /* Platform-specific fields omitted for portability */
};

typedef union at_neigh4_entry at_neigh4_entry_t;

/* Neighbor states */
#define AT_NEIGH4_STATE_INCOMPLETE (0)
#define AT_NEIGH4_STATE_ACTIVE     (1)

/* Map result codes - imported from at_map.h for convenience */
#define AT_MAP_SUCCESS     (0)
#define AT_MAP_ERR_KEY     (-1)
#define AT_MAP_ERR_AGAIN   (-2)

/* at_neigh4_entry_atomic_st atomically stores from src into dst.
   Assumes no other writers, and that src is non-volatile. */
static inline void
at_neigh4_entry_atomic_st( at_neigh4_entry_t       * dst,
                           at_neigh4_entry_t const * src ) {
#if AT_HAS_INT128
  AT_VOLATILE( dst->uf[0] ) = src->uf[0];
#else
  at_memcpy( dst->mac_addr, src->mac_addr, 6 );
  dst->probe_suppress_until     = src->probe_suppress_until;
  AT_VOLATILE( dst->ip4_addr )  = src->ip4_addr;
  AT_VOLATILE( dst->state )     = src->state;
#endif
}

/* at_neigh4_entry_atomic_ld atomically loads from src into dst.
   Assumes no other writers, and that dst is non-volatile. */
static inline void
at_neigh4_entry_atomic_ld( at_neigh4_entry_t       * dst,
                           at_neigh4_entry_t const * src ) {
#if AT_HAS_INT128
  dst->uf[0] = AT_VOLATILE_CONST( src->uf[0] );
#else
  at_memcpy( dst->mac_addr, src->mac_addr, 6 );
  dst->probe_suppress_until = src->probe_suppress_until;
  dst->ip4_addr             = AT_VOLATILE_CONST( src->ip4_addr );
  dst->state                = AT_VOLATILE_CONST( src->state );
#endif
}

/* Include template defines which set up MAP_* macros */
#include "at/p2p/net/neigh/at_neigh4_map_defines.h"

/* Generate the hashmap type and inline function declarations.
   The at_map_slot template with IMPL_STYLE=1 generates declarations only.

   This generates:
   - at_neigh4_hmap_t type
   - at_neigh4_hmap_align()
   - at_neigh4_hmap_footprint()
   - at_neigh4_hmap_new()
   - at_neigh4_hmap_join()
   - at_neigh4_hmap_leave()
   - at_neigh4_hmap_delete()
   - at_neigh4_hmap_query()
   - at_neigh4_hmap_update()
   - at_neigh4_hmap_insert()
   - at_neigh4_hmap_upsert()
   - at_neigh4_hmap_remove()
   - at_neigh4_hmap_verify()
   - etc. */

#define MAP_IMPL_STYLE 0  /* Header-only library */
#include "at/infra/tmpl/at_map_slot.c"

AT_PROTOTYPES_BEGIN

/* at_neigh4_hmap_query_entry looks up an entry by IP address and copies
   the entry data to the output buffer. Returns AT_MAP_SUCCESS on success,
   AT_MAP_ERR_KEY if not found. */
static inline int
at_neigh4_hmap_query_entry( at_neigh4_hmap_t * map,
                            uint               ip4_addr,
                            at_neigh4_entry_t * out ) {
  at_neigh4_entry_t const * entry = at_neigh4_hmap_query( map, &ip4_addr );
  if( !entry ) return AT_MAP_ERR_KEY;
  at_neigh4_entry_atomic_ld( out, entry );
  return AT_MAP_SUCCESS;
}

/* at_neigh4_hmap_est_slot_cnt computes the number of slots
   needed to store 'ele_max' entries. Uses a sparsity factor of 3
   and rounds up to a power of 2 (required by at_map_slot). */
static inline ulong
at_neigh4_hmap_est_slot_cnt( ulong ele_max ) {
  return at_ulong_pow2_up( 3UL * ele_max );
}

#if AT_HAS_HOSTED

/* at_neigh4_hmap_fprintf prints the neighbor table to the given FILE * pointer.
   Implemented in at_neigh4_hmap.c */
int
at_neigh4_hmap_fprintf( at_neigh4_hmap_t const * map,
                        void *                   file );

#endif /* AT_HAS_HOSTED */

AT_PROTOTYPES_END

#endif /* HEADER_at_src_waltz_neigh_at_neigh4_map_h */
