/* at_store_tile.h - Avatar Store Tile Header

   The store tile handles persistent storage of blocks, transactions,
   and validator state to disk. It receives data from various tiles
   and writes it to the configured storage backend. */

#ifndef HEADER_at_disco_tiles_at_store_tile_h
#define HEADER_at_disco_tiles_at_store_tile_h

#include "at/infra/tiles/at_topo.h"

#include <limits.h>

AT_PROTOTYPES_BEGIN

/* Input link kinds */
#define AT_STORE_IN_KIND_BANK    (0UL)  /* Confirmed blocks from bank */
#define AT_STORE_IN_KIND_REPLAY  (1UL)  /* Replay data for archival */

/* Store tile metrics */
typedef struct {
  ulong blocks_stored_cnt;      /* Total blocks written to disk */
  ulong bytes_written;          /* Total bytes written */
  ulong write_error_cnt;        /* Total write errors */
  ulong sync_cnt;               /* Total fsync operations */
} at_store_metrics_t;

/* Store tile context - maintained in tile scratch space */
typedef struct {
  /* Input link state (increased from 16 to 32 to handle complex topologies) */
  struct {
    at_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
  } in[ 32 ];
  ulong in_kind[ 32 ];

  /* Storage paths */
  char  ledger_path[ PATH_MAX ];   /* Path to ledger directory */
  char  accounts_path[ PATH_MAX ]; /* Path to accounts directory */

  /* File descriptors */
  int   ledger_fd;       /* Ledger file descriptor */
  int   accounts_fd;     /* Accounts snapshot fd */

  /* Current state */
  ulong current_slot;    /* Current slot being processed */
  ulong last_sync_slot;  /* Last slot that was fsync'd */
  ulong current_chunk;   /* Current chunk being processed (from during_frag) */

  /* Write buffer */
  uchar * write_buf;
  ulong   write_buf_sz;
  ulong   write_buf_used;

  /* Configuration */
  ulong   sync_interval_slots;  /* Slots between fsync operations */
  int     enable_compression;   /* Whether to compress data */

  /* Metrics */
  at_store_metrics_t metrics;
} at_store_ctx_t;

/* Default write buffer size */
#define AT_STORE_WRITE_BUF_SZ (4UL << 20) /* 4 MiB */

/* Default sync interval (slots) */
#define AT_STORE_DEFAULT_SYNC_INTERVAL (32UL)

/* Tile run structure - defined in at_store_tile.c */
extern at_topo_run_tile_t at_tile_store;

AT_PROTOTYPES_END

#endif /* HEADER_at_disco_tiles_at_store_tile_h */