/* at_metric_tile.h - Avatar Metric Tile Header

   The metric tile collects metrics from all other tiles via shared
   memory and publishes them over HTTP for Prometheus scraping. */

#ifndef HEADER_at_disco_tiles_at_metric_tile_h
#define HEADER_at_disco_tiles_at_metric_tile_h

#include "at/infra/tiles/at_topo.h"

AT_PROTOTYPES_BEGIN

/* Metric tile context - maintained in tile scratch space */
typedef struct {
  /* HTTP server state */
  int             listen_fd;     /* Listening socket */
  int             conn_fd;       /* Current connection (-1 if none) */
  uint            bind_addr;     /* Bind address (network byte order) */
  ushort          bind_port;     /* Bind port (host byte order) */

  /* Buffer for HTTP response */
  uchar *         response_buf;
  ulong           response_buf_sz;

  /* Topology reference for reading metrics */
  at_topo_t *     topo;

  /* Metrics collection state */
  ulong           last_scrape_ns;
  ulong           scrape_cnt;
  ulong           error_cnt;
} at_metric_ctx_t;

/* Default HTTP port for metrics endpoint */
#define AT_METRIC_DEFAULT_PORT (9090U)

/* Maximum response buffer size */
#define AT_METRIC_RESPONSE_BUF_SZ (1UL << 20) /* 1 MiB */

/* Tile run structure - defined in at_metric_tile.c */
extern at_topo_run_tile_t at_tile_metric;

AT_PROTOTYPES_END

#endif /* HEADER_at_disco_tiles_at_metric_tile_h */