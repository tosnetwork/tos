#ifndef HEADER_at_disco_tiles_at_discv6_tile_h
#define HEADER_at_disco_tiles_at_discv6_tile_h

/* at_discv6_tile.h - Discovery Tile Header

   The discv6 tile runs the Kademlia-based peer discovery protocol.
   It operates independently via UDP and publishes discovered peers
   to the gossip tile via mcache.
*/

#include "at/infra/tiles/at_topo.h"
#include "at/p2p/discovery/at_discv6.h"

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* Tile Configuration                                                  */
/**********************************************************************/

/* Configuration passed from topology to tile */
typedef struct {
  int    disable;                   /* 1 to disable discovery */
  int    discovery_only;            /* 1 for bootnode mode (no P2P) */
  uint   bind_address;              /* host byte order IPv4 (0 = 0.0.0.0) */
  ushort port;                      /* UDP port (default 2126) */
  uchar  private_key[32];           /* Discovery private key */
  int    has_private_key;           /* 1 if private_key is set */
  ulong  bucket_size;               /* K-bucket size (default 16) */
} at_discv6_tile_config_t;

/**********************************************************************/
/* Tile Context                                                        */
/**********************************************************************/

/* Opaque tile context - defined in at_discv6_tile.c */
typedef struct at_discv6_tile_ctx at_discv6_tile_ctx_t;

/**********************************************************************/
/* Tile Metrics                                                        */
/**********************************************************************/

typedef struct {
  ulong pings_sent;
  ulong pings_recv;
  ulong pongs_sent;
  ulong pongs_recv;
  ulong findnodes_sent;
  ulong findnodes_recv;
  ulong neighbors_sent;
  ulong neighbors_recv;
  ulong nodes_discovered;
  ulong nodes_evicted;
  ulong packets_dropped;
  ulong poll_iterations;
} at_discv6_tile_metrics_t;

/**********************************************************************/
/* Tile Registration                                                   */
/**********************************************************************/

/* External tile definition for topology registration */
extern at_topo_run_tile_t at_tile_discv6;

AT_PROTOTYPES_END

#endif /* HEADER_at_disco_tiles_at_discv6_tile_h */
