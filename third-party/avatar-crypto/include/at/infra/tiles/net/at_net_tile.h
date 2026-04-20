#ifndef HEADER_at_disco_net_at_net_tile_h
#define HEADER_at_disco_net_at_net_tile_h

/* at_net_tile.h contains APIs for providing XDP networking to an
   Avatar topology using the 'net' tile. */

#include "at/infra/tiles/at_disco_base.h"
#include "at/infra/tiles/net/at_net_common.h"
#include "at/infra/ipc/at_dcache.h"
#include "at/p2p/xdp/at_xdp1.h"

struct at_topo;
typedef struct at_topo at_topo_t;

/* Helpers for consumers of net tile RX packets */

struct at_net_rx_bounds {
  ulong base;       /* base address of wksp containing dcache */
  ulong pkt_lo;     /* lowest permitted pointer to packet payload */
  ulong pkt_wmark;  /* highest " */
};

typedef struct at_net_rx_bounds at_net_rx_bounds_t;

/* AT_NET_BOND_SLAVE_MAX is the hardcoded max number of slave devices
   per network bonding setup. */

#define AT_NET_BOND_SLAVE_MAX 16U

AT_PROTOTYPES_BEGIN

/* at_net_rx_bounds_init initializes a bounds checker for RX packets
   produced by the net tile.  dcache is a local join to a dcache that
   will carry packet payloads. */

AT_FN_UNUSED static void
at_net_rx_bounds_init( at_net_rx_bounds_t * bounds,
                       void *               dcache ) {
  bounds->base      = (ulong)at_wksp_containing( dcache );
  bounds->pkt_lo    = (ulong)dcache;
  bounds->pkt_wmark = bounds->pkt_lo + at_dcache_data_sz( dcache ) - AT_NET_MTU;
  if( AT_UNLIKELY( !bounds->base ) ) AT_LOG_ERR(( "Failed to find wksp containing dcache" ));
}

/* at_net_rx_translate_frag helps net tile consumers locate packet
   payloads.  bounds is a net_rx_bounds object for the net tile that the
   frag was received from.  chunk, ctl, sz are frag_meta parameters.

   Returns a pointer in the local address space to the first byte of an
   incoming packet.  Terminates the application if the given {chunk,ctl}
   params would produce an out of bounds buffer. */

AT_FN_UNUSED static void const *
at_net_rx_translate_frag( at_net_rx_bounds_t const * bounds,
                          ulong                      chunk,
                          ulong                      ctl,
                          ulong                      sz ) {
  ulong p = ((ulong)bounds->base + (chunk<<AT_CHUNK_LG_SZ) + ctl);
  if( AT_UNLIKELY( !( (p  >= bounds->pkt_lo   ) &
                      (p  <= bounds->pkt_wmark) &
                      (sz <= AT_NET_MTU       ) ) ) ) {
    AT_LOG_ERR(( "frag %p (chunk=%lu ctl=%lu sz=%lu) is not in bounds [%p:%p]",
                 (void *)p, chunk, ctl, sz,
                 (void *)bounds->pkt_lo, (void *)bounds->pkt_wmark ));
  }
  return (void const *)p;
}

AT_PROTOTYPES_END

/* Topology APIs */

AT_PROTOTYPES_BEGIN

/* at_topos_net_tiles appends the net and netlnk tiles to the
   topology.  These tiles provide fast XDP networking. */

struct at_config_net;
typedef struct at_config_net at_config_net_t;

void
at_topos_net_tiles( at_topo_t *             topo,
                    ulong                   net_tile_cnt,
                    at_config_net_t const * net_config,
                    ulong                   netlnk_max_routes,
                    ulong                   netlnk_max_peer_routes,
                    ulong                   netlnk_max_neighbors,
                    int                     xsk_core_dump,
                    ulong const             tile_to_cpu[ AT_TILE_MAX ] );

/* at_topos_net_rx_link is like at_topob_link, but for net->app tile
   packet RX links. */

void
at_topos_net_rx_link( at_topo_t *  topo,
                      char const * link_name,
                      ulong        net_kind_id,
                      ulong        depth );

/* at_topob_tile_in_net registers a net TX link with all net tiles. */

void
at_topos_tile_in_net( at_topo_t *  topo,
                      char const * fseq_wksp,
                      char const * link_name,
                      ulong        link_kind_id,
                      int          reliable,
                      int          polled );

/* This should be called *after* all app<->net tile links have been
   created.  Should be called once per net tile. */

void
at_topos_net_tile_finish( at_topo_t * topo,
                          ulong       net_kind_id );

/* at_topo_install_xdp installs XDP programs to all network devices used
   by the topology.  This creates a number of file descriptors which
   will be returned into the fds array.  On entry *fds_cnt is the array
   size of fds.  On exit, *fds_cnt is the number of fd array entries
   used.  Closing these fds will undo XDP program installation.
   bind_addr is an optional IPv4 address to used for filtering by dst
   IP.  If dry_run is set, does not actually install XDP config, but
   just returns file descriptors where installs would have occurred.

   On non-Linux platforms, this is a no-op that sets *fds_cnt to 0. */

void
at_topo_install_xdp( at_topo_t const * topo,
                     at_xdp_fds_t *    fds,
                     uint *            fds_cnt,
                     uint              bind_addr,
                     int               dry_run );

/* AT_TOPO_XDP_FDS_MAX is the max length of the at_xdp_fds_t array for
   an arbitrary supported topology.  (Number of bond slave devices plus
   loopback) */

#define AT_TOPO_XDP_FDS_MAX (AT_NET_BOND_SLAVE_MAX+1)

/* at_topo_install_xdp_simple is a convenience wrapper of the above. */

AT_FN_UNUSED static void
at_topo_install_xdp_simple( at_topo_t const * topo,
                            uint              bind_addr ) {
  at_xdp_fds_t fds[ AT_TOPO_XDP_FDS_MAX ];
  uint         fds_cnt = AT_TOPO_XDP_FDS_MAX;
  at_topo_install_xdp( topo, fds, &fds_cnt, bind_addr, 0 );
}

AT_PROTOTYPES_END

#endif /* HEADER_at_disco_net_at_net_tile_h */