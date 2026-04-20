#ifndef HEADER_at_core_infra_tiles_netlink_at_netlink_tile_h
#define HEADER_at_core_infra_tiles_netlink_at_netlink_tile_h

/* at_netlink_tile.h provides APIs for working with the netlink tile. */

#include "at/infra/tiles/at_topo.h"
#include "at/infra/ipc/at_mcache.h"

/* Hardcoded limits */
#define NETDEV_MAX      (256U)
#define BOND_MASTER_MAX (256U)

/* at_tile_netlnk provides the netlink tile. */

extern at_topo_run_tile_t at_tile_netlnk;

/* at_netlink_neigh4_solicit_link_t holds information required to send
   neighbor solicitation requests to the netlink tile. */

struct at_netlink_neigh4_solicit_link {
  at_frag_meta_t * mcache;
  ulong            depth;
  ulong            seq;
};

typedef struct at_netlink_neigh4_solicit_link at_netlink_neigh4_solicit_link_t;

AT_PROTOTYPES_BEGIN

void
at_netlink_topo_create( at_topo_tile_t * netlink_tile,
                        at_topo_t *      topo,
                        ulong            netlnk_max_routes,
                        ulong            netlnk_max_peer_routes,
                        ulong            netlnk_max_neighbors,
                        char const *     bind_interface );

void
at_netlink_topo_join( at_topo_t *      topo,
                      at_topo_tile_t * netlink_tile,
                      at_topo_tile_t * join_tile );

/* at_netlink_neigh4_solicit requests a neighbor solicitation (i.e. ARP
   request) for an IPv4 address.  Safe to call at a high rate.  The
   netlink tile will deduplicate requests.  ip4_addr is big endian. */

static inline void
at_netlink_neigh4_solicit( at_netlink_neigh4_solicit_link_t * link,
                           uint                               ip4_addr,
                           uint                               if_idx,
                           ulong                              tspub_comp ) {
  ulong seq = link->seq;
  ulong sig = (ulong)ip4_addr | ( (ulong)if_idx<<32 );
  at_mcache_publish( link->mcache, link->depth, seq, sig, 0UL, 0UL, 0UL, 0UL, tspub_comp );
  link->seq = at_seq_inc( seq, 1UL );
}

AT_PROTOTYPES_END

#endif /* HEADER_at_core_infra_tiles_netlink_at_netlink_tile_h */
