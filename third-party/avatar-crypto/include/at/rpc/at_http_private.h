#ifndef HEADER_at_src_waltz_http_at_http_private_h
#define HEADER_at_src_waltz_http_at_http_private_h

#include "at_http.h"
#include "at/infra/spad/at_spad.h"

#define AT_HTTP_SERVER_MAGIC (0xAB41A00050A11D0UL) /* AVATAR HTTP V0 */

/* Spad memory size for HTTP server (8KB for temporary buffers) */
#define AT_HTTP_SERVER_SPAD_MEM_MAX  (8192UL)

#define AT_HTTP_SERVER_CONNECTION_STATE_READING        0
#define AT_HTTP_SERVER_CONNECTION_STATE_WRITING_HEADER 1
#define AT_HTTP_SERVER_CONNECTION_STATE_WRITING_BODY   2

#define AT_HTTP_SERVER_PONG_STATE_NONE    0
#define AT_HTTP_SERVER_PONG_STATE_WAITING 1
#define AT_HTTP_SERVER_PONG_STATE_WRITING 2

#define AT_HTTP_SERVER_SEND_FRAME_STATE_HEADER 0
#define AT_HTTP_SERVER_SEND_FRAME_STATE_DATA   1

struct at_http_server_connection {
  int          state;
  uint         client_ip4;       /* IPv4 address in host byte order */

  int          upgrade_websocket;
  ulong        request_bytes_len;
  char const * sec_websocket_key;

  char * request_bytes;
  ulong  request_bytes_read;

  at_http_server_response_t response;
  ulong response_bytes_written;

  /* Mining WebSocket upgrade info */
  int   is_mining_connection;    /* 1 = /getwork upgrade, 0 = normal */
  uchar miner_pubkey[32];        /* Miner address (decoded from bech32) */
  char  miner_worker[64];        /* Worker name */

  /* The treap fields */
  ushort left;
  ushort right;
  ushort parent;
  ushort prio;
  ushort prev;
  ushort next;

  /* The memory for the request is placed at the end of the struct here...
  char request[ ]; */
};

struct at_http_server_ws_frame {
  ulong off;
  ulong len;
};

typedef struct at_http_server_ws_frame at_http_server_ws_frame_t;

struct at_http_server_ws_connection {
  int   pong_state;
  ulong pong_data_len;
  uchar pong_data[ 125 ];
  ulong pong_bytes_written;

  int     recv_started_msg;
  int     recv_last_opcode;
  ulong   recv_bytes_parsed;
  ulong   recv_bytes_read;
  uchar * recv_bytes;

  int                         send_frame_state;
  ulong                       send_frame_bytes_written;
  ulong                       send_frame_cnt;
  ulong                       send_frame_idx;
  at_http_server_ws_frame_t * send_frames;

  /* Mining info (only for /getwork connections) */
  int   is_mining;           /* 1 = mining connection, 0 = JSON-RPC */
  uchar miner_pubkey[32];    /* Miner public key */
  char  miner_worker[64];    /* Worker name */

  /* The treap fields */
  ushort left;
  ushort right;
  ushort parent;
  ushort prio;
  ushort prev;
  ushort next;
};

struct at_http_server_hcache_private {
  int   err; /* If there has been an error while printing */
  ulong off; /* Offset into the staging buffer */
  ulong len; /* Length of the staging buffer */
};

struct __attribute__((aligned(AT_HTTP_SERVER_ALIGN))) at_http_server_private {

  int   socket_fd;

  uchar * oring;
  ulong   oring_sz;

  /* Scratch pad for temporary allocations */
  at_spad_t * spad;

  int   stage_err;
  ulong stage_off;
  ulong stage_len;

  ulong max_conns;
  ulong max_ws_conns;
  ulong max_request_len;
  ulong max_ws_recv_frame_len;
  ulong max_ws_send_frame_cnt;

  ulong evict_conn_id;
  ulong evict_ws_conn_id;

  void * callback_ctx;
  at_http_server_callbacks_t callbacks;

  struct at_http_server_connection *    conns;
  struct at_http_server_ws_connection * ws_conns;
  struct pollfd *                       pollfds;

  void * conn_treap;
  void * ws_conn_treap;

  struct {
    ulong connection_cnt;
    ulong ws_connection_cnt;

    ulong bytes_written;
    ulong bytes_read;

    ulong frames_written;
    ulong frames_read;
  } metrics;

  ulong magic;      /* ==AT_HTTP_SERVER_MAGIC */

  /* The memory for conns and pollfds is placed at the end of the struct
     here...

  struct at_http_server_connection    conns[ ];
  struct at_http_server_ws_connection ws_conns[ ];
  struct pollfd                       pollfds[ ]; */
};

/* Connection array accessors with correct variable-stride layout.
   Each connection slot is sizeof(at_http_server_connection) + max_request_len bytes.
   Each WS connection slot is sizeof(at_http_server_ws_connection) + max_ws_recv_frame_len
   + max_ws_send_frame_cnt * sizeof(at_http_server_ws_frame_t) bytes.
   Using http->conns[i] directly is WRONG because C uses sizeof() as the stride. */

static inline struct at_http_server_connection *
at_http_get_conn( struct at_http_server_private * http, ulong i ) {
  ulong stride = sizeof(struct at_http_server_connection) + http->max_request_len;
  return (struct at_http_server_connection *)((uchar *)http->conns + i * stride);
}

static inline struct at_http_server_ws_connection *
at_http_get_ws_conn( struct at_http_server_private * http, ulong i ) {
  ulong stride = sizeof(struct at_http_server_ws_connection) +
                 http->max_ws_recv_frame_len +
                 http->max_ws_send_frame_cnt * sizeof(at_http_server_ws_frame_t);
  return (struct at_http_server_ws_connection *)((uchar *)http->ws_conns + i * stride);
}

#endif /* HEADER_at_src_waltz_http_at_http_private_h */