#ifndef HEADER_at_disco_topo_h
#define HEADER_at_disco_topo_h

/* Avatar Topology Framework */

#include "at_disco_base.h"
#include "at_stem.h"
#include "at/p2p/at_p2p_msg.h"

#include "at/infra/at_util_base.h"
#include "at/infra/cstr/at_cstr.h"

#include <limits.h>   /* PATH_MAX */

/* Maximum number of workspaces that may be present in a topology. */
#define AT_TOPO_MAX_WKSPS         (256UL)
/* Maximum number of links that may be present in a topology. */
#define AT_TOPO_MAX_LINKS         (256UL)
/* Maximum number of tiles that may be present in a topology. */
#define AT_TOPO_MAX_TILES         (256UL)
/* Maximum number of objects that may be present in a topology. */
#define AT_TOPO_MAX_OBJS          (4096UL)
/* Maximum number of links that may go into any one tile in the
   topology. */
#define AT_TOPO_MAX_TILE_IN_LINKS  ( 128UL)
/* Maximum number of links that a tile may write to. */
#define AT_TOPO_MAX_TILE_OUT_LINKS ( 32UL)
/* Maximum number of objects that a tile can use. */
#define AT_TOPO_MAX_TILE_OBJS      ( 256UL)

/* Core dump levels */
#define AT_TOPO_CORE_DUMP_LEVEL_DISABLED (0)
#define AT_TOPO_CORE_DUMP_LEVEL_MINIMAL  (1)
#define AT_TOPO_CORE_DUMP_LEVEL_REGULAR  (2)
#define AT_TOPO_CORE_DUMP_LEVEL_FULL     (3)
#define AT_TOPO_CORE_DUMP_LEVEL_NEVER    (4)

/* Storage backend selection for daemon startup */
#define AT_DB_BACKEND_DEFAULT (0U)
#define AT_DB_BACKEND_ROCKS   (1U)
#define AT_DB_BACKEND_MEMORY  (2U)

/* A workspace is a memory management structure that sits on top of
   1 or more memory mapped gigantic or huge pages. */
typedef struct {
  ulong id;           /* The ID of this workspace.  Indexed from [0, wksp_cnt). */
  char  name[ 13UL ]; /* The name of this workspace, like "pack". */

  ulong numa_idx;     /* The index of the NUMA node. */

  ulong min_part_max; /* Artificially raise part_max */
  ulong min_loose_sz; /* Artificially raise loose footprint */

  /* Computed fields. */
  struct {
    ulong page_sz;  /* The size of the pages (AT_SHMEM_*_PAGE_SZ). */
    ulong page_cnt; /* The number of pages needed. */
    ulong part_max; /* The maximum number of partitions. */

    int core_dump_level; /* Core dump level for this workspace. */

    at_wksp_t * wksp;            /* The workspace memory in the local process. */
    ulong       known_footprint; /* Total size of all known data. */
    ulong       total_footprint; /* Total size including loose data. */
  };
} at_topo_wksp_t;

/* A link is an mcache in a workspace that has one producer and one or
   more consumers. */
typedef struct {
  ulong id;           /* The ID of this link.  Indexed from [0, link_cnt). */
  char  name[ 13UL ]; /* The name of this link, like "pack_bank". */
  ulong kind_id;      /* The ID of this link within its name. */

  ulong depth;    /* The depth of the mcache. */
  ulong mtu;      /* The MTU of data fragments (0 = no dcache). */
  ulong burst;    /* Max amount of MTU sized data that might be bursted. */

  ulong mcache_obj_id;
  ulong dcache_obj_id;

  /* Computed fields. */
  struct {
    at_frag_meta_t * mcache; /* The mcache of this link. */
    void *           dcache; /* The dcache of this link, if it has one. */
  };

  uint permit_no_consumers : 1;  /* Permit no consumers */
  uint permit_no_producers : 1;  /* Permit no producers */
} at_topo_link_t;

/* A tile is a unique process that represents one thread of execution. */
struct at_topo_tile {
  ulong id;                     /* The ID of this tile.  Indexed from [0, tile_cnt). */
  char  name[ 7UL ];            /* The name of this tile. */
  char  metrics_name[ 10UL ];   /* The name for metrics. */
  ulong kind_id;                /* The ID of this tile within its name. */
  int   is_tosrust;           /* Reserved for TOS Rust runtime compatibility. */
  int   allow_shutdown;         /* If the tile can shutdown gracefully. */

  /* Heartbeat monitoring (Reference-style fail-fast design)
     Uses metrics system - tiles write to metrics[8] via AT_MGAUGE_SET.
     heartbeat_ns kept for backward compat (local copy only, not shared). */
  _Atomic ulong heartbeat_ns;   /* Local copy (for backward compat) */

  ulong cpu_idx;                /* CPU index to pin (ULONG_MAX = floating). */

  ulong in_cnt;
  ulong in_link_id[ AT_TOPO_MAX_TILE_IN_LINKS ];
  int   in_link_reliable[ AT_TOPO_MAX_TILE_IN_LINKS ];
  int   in_link_poll[ AT_TOPO_MAX_TILE_IN_LINKS ];

  ulong out_cnt;
  ulong out_link_id[ AT_TOPO_MAX_TILE_OUT_LINKS ];

  ulong tile_obj_id;
  ulong metrics_obj_id;
  ulong keyswitch_obj_id;
  ulong in_link_fseq_obj_id[ AT_TOPO_MAX_TILE_IN_LINKS ];

  ulong uses_obj_cnt;
  ulong uses_obj_id[ AT_TOPO_MAX_TILE_OBJS ];
  int   uses_obj_mode[ AT_TOPO_MAX_TILE_OBJS ];

  /* Computed fields. */
  struct {
    ulong *    metrics;
    ulong *    in_link_fseq[ AT_TOPO_MAX_TILE_IN_LINKS ];
  };

  /* Avatar tile-specific configuration.
     Add tile configurations here as needed. */
  union {
    struct {
      /* Net tile config (used by XDP tile) */
      uint   bind_address;
      ushort listen_port;
      ushort shred_listen_port;
      ushort quic_transaction_listen_port;
      ushort legacy_transaction_listen_port;
      ushort gossip_listen_port;
      ushort repair_intake_listen_port;
      ushort repair_serve_listen_port;
      ushort send_src_port;
      ulong  umem_dcache_obj_id;
    } net;

    struct {
      /* XDP tile config */
      char   if_virt[16];
      char   if_phys[16];
      uint   if_queue;
      int    zero_copy;
      ulong  xdp_rx_queue_size;
      ulong  xdp_tx_queue_size;
      ulong  free_ring_depth;
      int    xsk_core_dump;
      double tx_flush_timeout_ns;
      ulong  fib4_local_obj_id;
      ulong  fib4_main_obj_id;
      ulong  neigh4_obj_id;
      ulong  netdev_dbl_buf_obj_id;
    } xdp;

    struct {
      /* Sock tile config */
      uint   bind_address;
      ushort listen_port;
      int    rcvbuf;
      int    sndbuf;
    } sock;

    struct {
      /* Netlink tile config */
      ulong netdev_dbl_buf_obj_id;
      ulong fib4_main_obj_id;
      ulong fib4_local_obj_id;
      ulong neigh4_obj_id;
      char  neigh_if[16];
    } netlink;

    struct {
      /* Verify tile config placeholder */
      ulong tcache_depth;
    } verify;

    struct {
      /* Dedup tile config placeholder */
      ulong tcache_depth;
    } dedup;

    struct {
      /* Pack tile config placeholder */
      ulong max_pending_transactions;
    } pack;

    struct {
      /* Bank tile config placeholder */
      char  state_path[ PATH_MAX ];
      ulong max_cu_per_slot;
      ulong max_txn_per_slot;
      uint  db_backend;     /* AT_DB_BACKEND_* */
      ulong dag_nodes_max;  /* For memory DAG backend */
      ulong dag_topo_max;   /* For memory DAG backend */
      uchar network;        /* Network type: 0=mainnet, 1=testnet, 2=stagenet, 3=devnet */
      uchar simulator;      /* 0=none, 1=blockchain, 2=blockdag, 3=stress */

      /* Cross-process object IDs (Firedancer Object ID Pattern) */
      ulong rocks_obj_id;   /* RocksDB store object in workspace */
      ulong dag_obj_id;     /* DAG provider object in workspace */
    } bank;

    struct {
      /* Mining tile config placeholder */
      char identity_key_path[ PATH_MAX ];
    } mining;

    struct {
      /* FFI tile config placeholder */
      ulong heap_size;
    } ffi;

    struct {
      /* Store tile config placeholder */
      char data_path[ PATH_MAX ];
    } store;

    struct {
      /* Gossip tile config placeholder */
      uint   ip_addr;
      ushort port;
    } gossip;

    struct {
      /* Discv6 tile config */
      int    disable;
      int    discovery_only;
      uint   bind_address; /* host byte order IPv4 (0 = 0.0.0.0) */
      ushort port;
      uchar  private_key[32];
      int    has_private_key;
      ulong  bucket_size;
      uint   bootstrap_cnt;
      char   bootstrap_urls[16][256];
    } discv6;

    struct {
      /* Sync tile config */
      ulong  max_pending;
      uint   ip_addr;
      ushort port;
      uchar  network;        /* Network type: 0=mainnet, 1=testnet, 2=stagenet, 3=devnet */
      ulong  dag_obj_id;     /* DAG provider object ID for block storage (legacy) */
      ulong  peer_pool_obj_id; /* Peer pool object ID for peer selection */
      /* RocksDB backend configuration */
      char   state_path[ PATH_MAX ]; /* RocksDB database path */
      uint   db_backend;     /* AT_DB_BACKEND_ROCKS or AT_DB_BACKEND_MEMORY */
      ulong  dag_nodes_max;  /* Max nodes for memory backend (default: 1M) */
      ulong  dag_topo_max;   /* Max topoheight for memory backend (default: 1M) */
    } sync;

    struct {
      /* Sign tile config */
      char identity_key_path[ PATH_MAX ];
      ulong authorized_voter_paths_cnt;
      char authorized_voter_paths[ 16 ][ PATH_MAX ];
    } sign;

    struct {
      /* Metric tile config */
      uint   bind_address;
      ushort bind_port;
    } metric;

    struct {
      /* Repair tile config */
      uint   ip_addr;
      ushort port;
    } repair;

    struct {
      /* Database backend config used by storage-facing tiles. */
      char  db_path[ PATH_MAX ];  /* RocksDB database path */
      uint  db_backend;           /* AT_DB_BACKEND_* (usually ROCKS) */
    } db;

    struct {
      /* P2P TCP transport tile config */
      uint   bind_address;
      ushort listen_port;
      uchar  network;
      uchar  network_id[16];
      uchar  version_len;
      char   version[17];
      uchar  node_tag_len;
      char   node_tag[17];
      uchar  can_be_shared;
      uchar  supports_fast_sync;
      uchar  on_dh_key_change;
      uint   max_peers;
      uint   max_outgoing;
      char   dh_key_db_path[ PATH_MAX ];
      ulong  temp_ban_duration_secs;
      uchar  fail_count_limit;
      uint   bootstrap_cnt;
      uint   priority_cnt;
      uint   exclusive_cnt;
      at_peer_addr_t priority_nodes[16];
      at_peer_addr_t exclusive_nodes[16];
      at_peer_addr_t bootstrap[16];
    } p2p;

    struct {
      /* RPC tile config (mirrors at_rpc_tile_config_t for footprint calculation) */
      uint   listen_addr;
      ushort listen_port;
      ulong  max_connections;
      ulong  max_ws_connections;
      ulong  max_request_len;
      ulong  send_buffer_sz;
    } rpc;
  };
};

typedef struct at_topo_tile at_topo_tile_t;

/* Topology object */
typedef struct {
  ulong id;
  char  name[ 13UL ];  /* object type */
  ulong wksp_id;

  char  label[ 13UL ]; /* object label */
  ulong label_idx;     /* index of object for this label (ULONG_MAX if not labelled) */

  ulong offset;
  ulong footprint;
} at_topo_obj_t;

/* Complete topology structure */
struct at_topo {
  char           app_name[ 256UL ];
  uchar          props[ 16384UL ];

  ulong          wksp_cnt;
  ulong          link_cnt;
  ulong          tile_cnt;
  ulong          obj_cnt;

  at_topo_wksp_t workspaces[ AT_TOPO_MAX_WKSPS ];
  at_topo_link_t links[ AT_TOPO_MAX_LINKS ];
  at_topo_tile_t tiles[ AT_TOPO_MAX_TILES ];
  at_topo_obj_t  objs[ AT_TOPO_MAX_OBJS ];

  ulong          blocklist_cores_cnt;
  ulong          blocklist_cores_cpu_idx[ AT_TILE_MAX ];

  ulong          max_page_size;
  ulong          gigantic_page_threshold;

  int            frozen;
  ulong          build_error_count;
};
typedef struct at_topo at_topo_t;

AT_FN_PURE static inline int
at_topo_is_frozen( at_topo_t const * topo ) {
  return (int)( topo && topo->frozen );
}

static inline void
at_topo_set_frozen( at_topo_t * topo ) {
  if( AT_UNLIKELY( !topo ) ) return;
  topo->frozen = 1;
}

AT_FN_PURE static inline int
at_topo_assert_not_frozen( at_topo_t const * topo ) {
  if( AT_LIKELY( !at_topo_is_frozen( topo ) ) ) return 0;
  AT_LOG_ERR(( "topology is frozen; topology mutations are forbidden" ));
  return -1;
}

/* Tile run structure - defines callbacks for a tile type */
struct sock_filter; /* forward declaration */

typedef struct {
  char const * name;

  int          keep_host_networking;
  int          allow_connect;
  int          allow_renameat;
  ulong        rlimit_file_cnt;
  ulong        rlimit_address_space;
  ulong        rlimit_data;
  int          for_tpool;

  ulong (*populate_allowed_seccomp)( at_topo_t const * topo, at_topo_tile_t const * tile, ulong out_cnt, struct sock_filter * out );
  ulong (*populate_allowed_fds    )( at_topo_t const * topo, at_topo_tile_t const * tile, ulong out_fds_sz, int * out_fds );
  ulong (*scratch_align           )( void );
  ulong (*scratch_footprint       )( at_topo_tile_t const * tile );
  ulong (*loose_footprint         )( at_topo_tile_t const * tile );
  void  (*privileged_init         )( at_topo_t * topo, at_topo_tile_t * tile );
  void  (*unprivileged_init       )( at_topo_t * topo, at_topo_tile_t * tile );
  void  (*run                     )( at_topo_t * topo, at_topo_tile_t * tile );
  ulong (*rlimit_file_cnt_fn      )( at_topo_t const * topo, at_topo_tile_t const * tile );
} at_topo_run_tile_t;

/* Object callbacks */
struct at_topo_obj_callbacks {
  char const * name;
  ulong (* footprint )( at_topo_t const * topo, at_topo_obj_t const * obj );
  ulong (* align     )( at_topo_t const * topo, at_topo_obj_t const * obj );
  ulong (* loose     )( at_topo_t const * topo, at_topo_obj_t const * obj );
  void  (* new       )( at_topo_t const * topo, at_topo_obj_t const * obj );
};

typedef struct at_topo_obj_callbacks at_topo_obj_callbacks_t;

AT_PROTOTYPES_BEGIN

/* Workspace alignment */
AT_FN_CONST static inline ulong
at_topo_workspace_align( void ) {
  return 4096UL;
}

/* Get local address for an object */
void *
at_topo_obj_laddr( at_topo_t const * topo,
                   ulong             obj_id );

/* Get workspace base for an object */
static inline void *
at_topo_obj_wksp_base( at_topo_t const * topo,
                       ulong             obj_id ) {
  if( obj_id >= AT_TOPO_MAX_OBJS ) return NULL;
  at_topo_obj_t const * obj = &topo->objs[ obj_id ];
  if( obj->id != obj_id ) return NULL;
  ulong const wksp_id = obj->wksp_id;
  if( wksp_id >= AT_TOPO_MAX_WKSPS ) return NULL;
  at_topo_wksp_t const * wksp = &topo->workspaces[ wksp_id ];
  if( wksp->id != wksp_id ) return NULL;
  return wksp->wksp;
}

static inline int
topo_cstr_eq( char const * a, char const * b ) {
  if( !a || !b ) return 0;
  ulong alen = at_cstr_nlen( a, (ulong)~0UL );
  ulong blen = at_cstr_nlen( b, (ulong)~0UL );
  if( alen!=blen ) return 0;
  return at_memcmp( a, b, alen )==0;
}

/* Count tiles with a given name */
AT_FN_PURE static inline ulong
at_topo_tile_name_cnt( at_topo_t const * topo,
                       char const *      name ) {
  ulong cnt = 0;
  for( ulong i=0; i<topo->tile_cnt; i++ ) {
    if( AT_UNLIKELY( topo_cstr_eq( topo->tiles[ i ].name, name ) ) ) cnt++;
  }
  return cnt;
}

/* Find workspace by name */
AT_FN_PURE static inline ulong
at_topo_find_wksp( at_topo_t const * topo,
                   char const *      name ) {
  for( ulong i=0; i<topo->wksp_cnt; i++ ) {
    if( AT_UNLIKELY( topo_cstr_eq( topo->workspaces[ i ].name, name ) ) ) return i;
  }
  return ULONG_MAX;
}

/* Find tile by name and kind_id */
AT_FN_PURE static inline ulong
at_topo_find_tile( at_topo_t const * topo,
                   char const *      name,
                   ulong             kind_id ) {
  for( ulong i=0; i<topo->tile_cnt; i++ ) {
    if( AT_UNLIKELY( topo_cstr_eq( topo->tiles[ i ].name, name ) ) && topo->tiles[ i ].kind_id == kind_id ) return i;
  }
  return ULONG_MAX;
}

/* Find link by name and kind_id */
AT_FN_PURE static inline ulong
at_topo_find_link( at_topo_t const * topo,
                   char const *      name,
                   ulong             kind_id ) {
  for( ulong i=0; i<topo->link_cnt; i++ ) {
    if( AT_UNLIKELY( topo_cstr_eq( topo->links[ i ].name, name ) ) && topo->links[ i ].kind_id == kind_id ) return i;
  }
  return ULONG_MAX;
}

/* Find tile's input link */
AT_FN_PURE static inline ulong
at_topo_find_tile_in_link( at_topo_t const *      topo,
                           at_topo_tile_t const * tile,
                           char const *           name,
                           ulong                  kind_id ) {
  for( ulong i=0; i<tile->in_cnt; i++ ) {
    if( AT_UNLIKELY( topo_cstr_eq( topo->links[ tile->in_link_id[ i ] ].name, name ) )
        && topo->links[ tile->in_link_id[ i ] ].kind_id == kind_id ) return i;
  }
  return ULONG_MAX;
}

/* Find tile's output link */
AT_FN_PURE static inline ulong
at_topo_find_tile_out_link( at_topo_t const *      topo,
                            at_topo_tile_t const * tile,
                            char const *           name,
                            ulong                  kind_id ) {
  for( ulong i=0; i<tile->out_cnt; i++ ) {
    if( AT_UNLIKELY( topo_cstr_eq( topo->links[ tile->out_link_id[ i ] ].name, name ) )
        && topo->links[ tile->out_link_id[ i ] ].kind_id == kind_id ) return i;
  }
  return ULONG_MAX;
}

/* Find link producer tile */
AT_FN_PURE static inline ulong
at_topo_find_link_producer( at_topo_t const *      topo,
                            at_topo_link_t const * link ) {
  for( ulong i=0; i<topo->tile_cnt; i++ ) {
    at_topo_tile_t const * tile = &topo->tiles[ i ];
    for( ulong j=0; j<tile->out_cnt; j++ ) {
      if( AT_UNLIKELY( tile->out_link_id[ j ] == link->id ) ) return i;
    }
  }
  return ULONG_MAX;
}

/* Count link consumers */
AT_FN_PURE static inline ulong
at_topo_link_consumer_cnt( at_topo_t const *      topo,
                           at_topo_link_t const * link ) {
  ulong cnt = 0;
  for( ulong i=0; i<topo->tile_cnt; i++ ) {
    at_topo_tile_t const * tile = &topo->tiles[ i ];
    for( ulong j=0; j<tile->in_cnt; j++ ) {
      if( AT_UNLIKELY( tile->in_link_id[ j ] == link->id ) ) cnt++;
    }
  }
  return cnt;
}

/* Count link reliable consumers */
AT_FN_PURE static inline ulong
at_topo_link_reliable_consumer_cnt( at_topo_t const *      topo,
                                    at_topo_link_t const * link ) {
  ulong cnt = 0;
  for( ulong i=0; i<topo->tile_cnt; i++ ) {
    at_topo_tile_t const * tile = &topo->tiles[ i ];
    for( ulong j=0; j<tile->in_cnt; j++ ) {
      if( AT_UNLIKELY( tile->in_link_id[ j ] == link->id && tile->in_link_reliable[ j ] ) ) cnt++;
    }
  }
  return cnt;
}

/* Count tile consumers */
AT_FN_PURE static inline ulong
at_topo_tile_consumer_cnt( at_topo_t const *      topo,
                           at_topo_tile_t const * tile ) {
  (void)topo;
  return tile->out_cnt;
}

/* Count tile reliable consumers */
AT_FN_PURE static inline ulong
at_topo_tile_reliable_consumer_cnt( at_topo_t const *      topo,
                                    at_topo_tile_t const * tile ) {
  ulong reliable_cons_cnt = 0UL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    at_topo_tile_t const * consumer_tile = &topo->tiles[ i ];
    for( ulong j=0UL; j<consumer_tile->in_cnt; j++ ) {
      for( ulong k=0UL; k<tile->out_cnt; k++ ) {
        if( AT_UNLIKELY( consumer_tile->in_link_id[ j ]==tile->out_link_id[ k ] && consumer_tile->in_link_reliable[ j ] ) ) {
          reliable_cons_cnt++;
        }
      }
    }
  }
  return reliable_cons_cnt;
}

/* Count tile producers */
AT_FN_PURE static inline ulong
at_topo_tile_producer_cnt( at_topo_t const *     topo,
                           at_topo_tile_t const * tile ) {
  (void)topo;
  ulong in_cnt = 0UL;
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    if( AT_UNLIKELY( !tile->in_link_poll[ i ] ) ) continue;
    in_cnt++;
  }
  return in_cnt;
}

/* Workspace management functions (implemented in at_topo.c) */
void at_topo_join_tile_workspaces( at_topo_t * topo, at_topo_tile_t * tile, int core_dump_level );
void at_topo_join_workspace( at_topo_t * topo, at_topo_wksp_t * wksp, int mode, int dump );
void at_topo_join_workspaces( at_topo_t * topo, int mode, int core_dump_level );
void at_topo_leave_workspace( at_topo_t * topo, at_topo_wksp_t * wksp );
void at_topo_leave_workspaces( at_topo_t * topo );
int  at_topo_create_workspace( at_topo_t * topo, at_topo_wksp_t * wksp, int update_existing );

/* Anonymous (heap-backed) workspace management for single-process mode */
int  at_topo_init_anon_workspaces ( at_topo_t * topo, at_topo_obj_callbacks_t ** callbacks, char * err, size_t err_sz );
void at_topo_leave_anon_workspaces( at_topo_t * topo );

/* Tile/workspace filling */
void at_topo_fill_tile( at_topo_t * topo, at_topo_tile_t * tile );
void at_topo_workspace_fill( at_topo_t * topo, at_topo_wksp_t * wksp );
void at_topo_wksp_new( at_topo_t const * topo, at_topo_wksp_t const * wksp, at_topo_obj_callbacks_t ** callbacks );
void at_topo_fill( at_topo_t * topo );

/* Stack joining */
void * at_topo_tile_stack_join( char const * app_name, char const * tile_name, ulong tile_kind_id );

/* Tile running */
void at_topo_run_single_process( at_topo_t * topo, int tosrust, uint uid, uint gid, at_topo_run_tile_t (* tile_run )( at_topo_tile_t const * tile ) );
void at_topo_run_tile( at_topo_t * topo, at_topo_tile_t * tile, int sandbox, int keep_controlling_terminal, int dumpable, uint uid, uint gid, int allow_fd, volatile int * wait, volatile int * debugger, at_topo_run_tile_t * tile_run );

/* Memory calculations */
AT_FN_PURE ulong at_topo_mlock_max_tile( at_topo_t const * topo );
AT_FN_PURE ulong at_topo_mlock( at_topo_t const * topo );
AT_FN_PURE ulong at_topo_gigantic_page_cnt( at_topo_t const * topo, ulong numa_idx );
AT_FN_PURE ulong at_topo_huge_page_cnt( at_topo_t const * topo, ulong numa_idx, int include_anonymous );

/* Debug printing */
void at_topo_print_log( int stdout, at_topo_t * topo );

/* Find tile by name and kind_id */
ulong at_topo_find_tile( at_topo_t const * topo,
                         char const *      tile_name,
                         ulong             kind_id );

AT_PROTOTYPES_END

#endif /* HEADER_at_disco_topo_h */
