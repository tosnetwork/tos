/* at_xdp_tile.h - XDP high-performance network tile

   Provides AF_XDP socket network I/O for the tile system using eBPF/XDP.

   NOTE: This is Linux-specific and requires XDP support in the kernel.
   On other platforms, this compiles but does not function.

   TODO: Implement based on TOS requirements - full XDP tile */

#ifndef HEADER_at_disco_net_xdp_at_xdp_tile_h
#define HEADER_at_disco_net_xdp_at_xdp_tile_h

#include "at/infra/at_util_base.h"

/* XDP tile is Linux-only */
#ifdef __linux__
#define AT_HAS_XDP 1
#else
#define AT_HAS_XDP 0
#endif

#define AT_XDP_TILE_MAX_QUEUES (8UL)

AT_PROTOTYPES_BEGIN

/* at_xdp_tile_align returns required alignment for XDP tile memory */
AT_FN_CONST ulong
at_xdp_tile_align( void );

/* at_xdp_tile_footprint returns required memory size for XDP tile */
AT_FN_CONST ulong
at_xdp_tile_footprint( ulong queue_cnt );

/* at_xdp_tile_new formats memory for XDP tile
   Returns mem on success, NULL on failure */
void *
at_xdp_tile_new( void * mem,
                 ulong  queue_cnt );

/* at_xdp_tile_delete unformats XDP tile memory */
void *
at_xdp_tile_delete( void * mem );

AT_PROTOTYPES_END

#endif /* HEADER_at_disco_net_xdp_at_xdp_tile_h */