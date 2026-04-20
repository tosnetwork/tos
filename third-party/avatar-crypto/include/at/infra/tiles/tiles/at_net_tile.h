/* at_net_tile.h - Avatar Net Tile Header

   The net tile coordinates network I/O across multiple networking
   tiles (sock, xdp) and provides a unified interface for sending
   and receiving network data. */

#ifndef HEADER_at_disco_tiles_at_net_tile_h
#define HEADER_at_disco_tiles_at_net_tile_h

#include "at/infra/tiles/at_topo.h"

AT_PROTOTYPES_BEGIN

/* Output link kinds */
#define AT_NET_OUT_KIND_QUIC    (0UL)  /* To QUIC tile */
#define AT_NET_OUT_KIND_GOSSIP  (1UL)  /* To gossip tile */
#define AT_NET_OUT_KIND_REPAIR  (2UL)  /* To repair tile */

/* Net tile metrics */
typedef struct {
  ulong packets_received_cnt;   /* Total packets received */
  ulong packets_sent_cnt;       /* Total packets sent */
  ulong bytes_received;         /* Total bytes received */
  ulong bytes_sent;             /* Total bytes sent */
  ulong drop_cnt;               /* Packets dropped */
} at_net_metrics_t;

/* Net tile context - maintained in tile scratch space */
typedef struct {
  /* Input link state (from sock/xdp tiles) */
  struct {
    at_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
  } in[ 32 ];

  /* Output links (to protocol tiles) */
  struct {
    at_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       chunk;
  } out[ 8 ];
  ulong out_kind[ 8 ];

  /* Network configuration */
  uint   src_ip_addr;     /* Our IP address */
  uchar  src_mac[ 6 ];    /* Our MAC address */

  /* Port routing table */
  ushort quic_port;       /* Port for QUIC traffic */
  ushort gossip_port;     /* Port for gossip traffic */
  ushort repair_port;     /* Port for repair traffic */

  /* Metrics */
  at_net_metrics_t metrics;
} at_net_ctx_t;

/* Tile run structure - defined in at_net_tile.c */
extern at_topo_run_tile_t at_tile_net;

AT_PROTOTYPES_END

#endif /* HEADER_at_disco_tiles_at_net_tile_h */