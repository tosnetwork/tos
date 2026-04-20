#ifndef HEADER_at_disco_tiles_at_p2p_tile_h
#define HEADER_at_disco_tiles_at_p2p_tile_h

/* at_p2p_tile.h - Avatar TCP P2P transport tile

   Owns TCP connections, performs TOS key exchange + handshake,
   and dispatches decrypted packets to gossip/sync/repair tiles.
*/

#include "at/infra/tiles/at_topo.h"
#include "at/p2p/at_peer.h"
#include "at/p2p/at_p2p_msg.h"
#include "at/p2p/at_p2p_dispatch.h"
#include "at/core/blockdag/at_dag_provider.h"

AT_PROTOTYPES_BEGIN

#define AT_P2P_MAX_CONNS        (256UL)
#define AT_P2P_MAX_BOOTSTRAP    (16UL)

typedef struct {
  int   used;
  int   fd;
  uint  peer_idx;
  int   is_outgoing;
  int   sent_key;
  int   recv_key;
  int   handshake_sent;

  /* Read state */
  uchar len_buf[4];
  uint  len_have;
  uint  payload_len;
  uint  payload_have;
  uchar payload_buf[AT_P2P_FRAME_MAX_SZ];

  /* Write state */
  uchar write_buf[AT_P2P_FRAME_MAX_SZ + AT_P2P_FRAME_HDR_SZ];
  uint  write_len;
  uint  write_off;
} at_p2p_conn_t;

typedef struct {
  /* Config */
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
  at_peer_addr_t bootstrap[AT_P2P_MAX_BOOTSTRAP];

  /* Runtime */
  int   listen_fd;
  int   listen_fd6;
  ulong now;
  ulong last_connect_attempt;
  ulong last_dh_flush;
  int   dh_keys_loaded;
  int   dh_keys_dirty;

  at_peer_pool_t *    peer_pool;
  at_dag_provider_t * dag;

  at_p2p_conn_t conns[AT_P2P_MAX_CONNS];
  int           peer_to_conn[AT_PEER_MAX];

  /* Input links (from gossip/sync/repair) */
  struct {
    at_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
    ulong       last_chunk;  /* Saved chunk from during_frag for after_frag */
  } in[3];

  /* Output links (to gossip/sync/repair) */
  struct {
    at_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       chunk;
    ulong       mtu;
    ulong       idx;
    ulong       credits;
    ulong       max_credits;
  } out[3];

  /* Local peer id */
  ulong peer_id;

  /* Genesis hash for handshake (used when DAG is empty) */
  uchar genesis_hash[32];
  int   has_genesis_hash;

  /* Per-priority-node failure tracking for cooldown.
     Unlike temp_ban which doesn't apply to whitelisted nodes,
     this tracks consecutive failures to implement exponential backoff. */
  uchar  priority_fail_count[16];    /* Consecutive failures per priority node */
  ulong  priority_cooldown_until[16]; /* Nanosecond timestamp until next retry allowed */

  /* Handshake failure counter for peer_id regeneration */
  uint   handshake_fail_count;

} at_p2p_ctx_t;

extern at_topo_run_tile_t at_tile_p2p;

AT_PROTOTYPES_END

#endif /* HEADER_at_disco_tiles_at_p2p_tile_h */