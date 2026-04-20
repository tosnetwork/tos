/* at_sock_tile_private.h - UDP socket tile private definitions */

#ifndef HEADER_at_disco_net_sock_at_sock_tile_private_h
#define HEADER_at_disco_net_sock_at_sock_tile_private_h

#if AT_HAS_HOSTED

#include "at/infra/at_util_base.h"
#include <poll.h>
#include <sys/socket.h>

/* struct mmsghdr is Linux-specific. Provide a stub for other platforms. */
#ifndef __linux__
struct mmsghdr {
  struct msghdr msg_hdr;
  unsigned int  msg_len;
};
#endif

/* AT_SOCK_TILE_MAX_SOCKETS controls the max number of UDP ports that a
   sock tile can bind to. */

#define AT_SOCK_TILE_MAX_SOCKETS (8)

/* MAX_NET_INS controls the max number of TX links that a sock tile can
   serve. */

#define AT_SOCK_MAX_NET_INS (32UL)

/* MAX_NET_OUTS controls the max number of RX links that a sock tile can
   serve. */

#define AT_SOCK_MAX_NET_OUTS (5UL)

/* Local metrics.  Periodically copied to the metric_in shm region. */

struct at_sock_tile_metrics {
  ulong sys_recvmmsg_cnt;
  ulong sys_sendmmsg_cnt[8]; /* TODO: Implement based on TOS requirements - error enum count */
  ulong rx_pkt_cnt;
  ulong tx_pkt_cnt;
  ulong tx_drop_cnt;
  ulong rx_bytes_total;
  ulong tx_bytes_total;
};

typedef struct at_sock_tile_metrics at_sock_tile_metrics_t;

/* Tile private state */

struct at_sock_link_tx {
  void * base;
  ulong  chunk0;
  ulong  wmark;
};

typedef struct at_sock_link_tx at_sock_link_tx_t;

struct at_sock_link_rx {
  void * base;
  ulong  chunk0;
  ulong  wmark;
  ulong  chunk;
};

typedef struct at_sock_link_rx at_sock_link_rx_t;

struct at_sock_tile {
  /* RX SOCK_DGRAM sockets */
  struct pollfd pollfd[ AT_SOCK_TILE_MAX_SOCKETS ];
  uint          sock_cnt;
  uchar         proto_id[ AT_SOCK_TILE_MAX_SOCKETS ];

  /* TX SOCK_RAW socket */
  int  tx_sock;
  int  tx_fd;      /* TX socket file descriptor for seccomp */
  uint tx_idle_cnt;
  uint bind_address;
  uint rx_cnt;     /* Number of RX sockets for seccomp */

  /* RX/TX batches */
  ulong                batch_cnt;
  struct iovec *       batch_iov;
  void *               batch_cmsg;
  struct sockaddr_in * batch_sa;
  struct mmsghdr *     batch_msg;

  /* RX links */
  ushort            rx_sock_port[ AT_SOCK_TILE_MAX_SOCKETS ];
  uchar             link_rx_map [ AT_SOCK_TILE_MAX_SOCKETS ];
  at_sock_link_rx_t link_rx[ AT_SOCK_MAX_NET_OUTS ];

  /* TX links */
  at_sock_link_tx_t link_tx[ AT_SOCK_MAX_NET_INS ];

  /* TX scratch memory */
  uchar * tx_scratch0;
  uchar * tx_scratch1;
  uchar * tx_ptr;

  at_sock_tile_metrics_t metrics;
};

typedef struct at_sock_tile at_sock_tile_t;

#endif /* AT_HAS_HOSTED */

#endif /* HEADER_at_disco_net_sock_at_sock_tile_private_h */