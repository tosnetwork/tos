#ifndef HEADER_at_waltz_p2p_at_p2p_msg_h
#define HEADER_at_waltz_p2p_at_p2p_msg_h

/* at_p2p_msg.h - TOS P2P Message Protocol

   Defines the wire format for TOS peer-to-peer messages.
   Compatible with TOS Rust P2P protocol.

   TOS Wire Format:
   ┌─────────────────────────────────────────────────────────┐
   │  4 bytes: payload_length (u32 BE, UNENCRYPTED)          │
   ├─────────────────────────────────────────────────────────┤
   │  payload_length bytes: ENCRYPTED with ChaCha20-Poly1305 │
   │  ┌─────────────────────────────────────────────────────┐│
   │  │  1 byte: packet_type_id                             ││
   │  │  N bytes: packet-specific payload (TOS custom)      ││
   │  │  16 bytes: Poly1305 authentication tag              ││
   │  └─────────────────────────────────────────────────────┘│
   └─────────────────────────────────────────────────────────┘

   Key Points:
   - Length prefix is NOT encrypted (allows buffer allocation before decryption)
   - Packet type is INSIDE encrypted payload
   - All payloads use TOS custom serialization (LE integers, u8 string lengths)
   - Auth tag (16 bytes) is appended to ciphertext

   TOS Custom Serialization:
   - u8/i8: 1 byte
   - u16/i16: 2 bytes BE
   - u32/i32: 4 bytes BE
   - u64/i64: 8 bytes BE
   - String: u8 length prefix + UTF-8 bytes (max 255 bytes)
   - Option<u64>: 1 byte tag (0=None, 1=Some) + u64 if Some
   - Option<String>: 0x00=None, otherwise u8 length + UTF-8 (no separate tag!)
   - Hash: 32 bytes raw
   - bool: 1 byte (0 or 1)
   - VarUint: u8 length (0-32) + big-endian bytes (leading zeros stripped)
*/

#include "at/infra/at_util_base.h"
#include "at/p2p/at_p2p.h"

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* TOS Packet Type IDs                                                */
/**********************************************************************/

#define AT_PKT_KEY_EXCHANGE          (0)   /* Symmetric key exchange */
#define AT_PKT_HANDSHAKE             (1)   /* Version/network negotiation */
#define AT_PKT_TX_PROPAGATION        (2)   /* Transaction hash announcement */
#define AT_PKT_BLOCK_PROPAGATION     (3)   /* Block header announcement */
#define AT_PKT_CHAIN_REQUEST         (4)   /* Request chain segment */
#define AT_PKT_CHAIN_RESPONSE        (5)   /* Chain segment response */
#define AT_PKT_PING                  (6)   /* Heartbeat with chain state */
#define AT_PKT_OBJECT_REQUEST        (7)   /* Request TX/Block/Header by hash */
#define AT_PKT_OBJECT_RESPONSE       (8)   /* TX/Block/Header data or NotFound */
#define AT_PKT_NOTIFY_INV_REQUEST    (9)   /* Subscribe to state changes */
#define AT_PKT_NOTIFY_INV_RESPONSE   (10)  /* State change notification */
#define AT_PKT_BOOTSTRAP_REQUEST     (11)  /* Fast sync chain request */
#define AT_PKT_BOOTSTRAP_RESPONSE    (12)  /* Fast sync chain response */
#define AT_PKT_PEER_DISCONNECTED     (13)  /* Peer removal notification */

#define AT_PKT_TYPE_MAX              (14)  /* Total packet types */

/**********************************************************************/
/* Protocol Constants                                                 */
/**********************************************************************/

/* Maximum frame size (encrypted payload + length prefix) */
#define AT_P2P_FRAME_MAX_SZ          (1024UL * 1024UL)  /* 1 MB */

/* Frame header size (4-byte BE length, unencrypted) */
#define AT_P2P_FRAME_HDR_SZ          (4UL)

/* Tag size from ChaCha20-Poly1305 */
#define AT_P2P_FRAME_TAG_SZ          (16UL)

/* Maximum plaintext payload (excluding type byte and tag) */
#define AT_P2P_FRAME_MAX_PAYLOAD     (AT_P2P_FRAME_MAX_SZ - AT_P2P_FRAME_HDR_SZ - AT_P2P_FRAME_TAG_SZ - 1UL)

/* Ping constants */
#define AT_PING_MAX_PEERS            (16)  /* TOS P2P_PING_PEER_LIST_LIMIT */
#define AT_P2P_PING_PEER_LIST_DELAY  (300UL) /* seconds */

/* Chain sync constants */
#define AT_CHAIN_REQUEST_MAX_BLOCKS   (64)     /* TOS CHAIN_SYNC_REQUEST_MAX_BLOCKS */
#define AT_CHAIN_RESPONSE_MIN_BLOCKS  (512)    /* TOS CHAIN_SYNC_RESPONSE_MIN_BLOCKS */
#define AT_CHAIN_RESPONSE_MAX_BLOCKS  (65535)  /* TOS CHAIN_SYNC_RESPONSE_MAX_BLOCKS (u16::MAX) */

/* Stability limit for gossip */
#ifndef AT_STABLE_LIMIT
#define AT_STABLE_LIMIT              (24)  /* TOS STABLE_LIMIT */
#endif

/**********************************************************************/
/* Network Type                                                       */
/**********************************************************************/

#ifndef AT_NETWORK_TYPE_DEFINED
#define AT_NETWORK_TYPE_DEFINED
typedef enum {
  AT_NETWORK_MAINNET = 0,
  AT_NETWORK_TESTNET = 1,
  AT_NETWORK_STAGENET = 2,
  AT_NETWORK_DEVNET  = 3,
} at_network_t;
typedef at_network_t at_network_type_t;
#endif

/**********************************************************************/
/* Object Types                                                       */
/**********************************************************************/

/* Object request types (AT_PKT_OBJECT_REQUEST) - Rust IDs */
#define AT_OBJ_TYPE_BLOCK            (0)
#define AT_OBJ_TYPE_HEADER           (1)
#define AT_OBJ_TYPE_TX               (2)

/* Object response types (AT_PKT_OBJECT_RESPONSE) - Rust IDs */
#define AT_OBJ_RESP_BLOCK            (0)
#define AT_OBJ_RESP_HEADER           (1)
#define AT_OBJ_RESP_TX               (2)
#define AT_OBJ_RESP_NOT_FOUND        (3)

/**********************************************************************/
/* Notification Event Types                                           */
/**********************************************************************/

/* Rust notify inventory uses TX hashes pagination (no event enum) */
#define AT_NOTIFY_MAX_LEN            (16384)  /* TOS NOTIFY_MAX_LEN */

/**********************************************************************/
/* Error Codes                                                        */
/**********************************************************************/

#define AT_MSG_SUCCESS               (0)
#define AT_MSG_ERR_INVAL             (-1)   /* Invalid parameter */
#define AT_MSG_ERR_SIZE              (-2)   /* Buffer too small */
#define AT_MSG_ERR_TYPE              (-3)   /* Unknown message type */
#define AT_MSG_ERR_TRUNCATED         (-4)   /* Message truncated */
#define AT_MSG_ERR_OVERFLOW          (-5)   /* Payload too large */
#define AT_MSG_ERR_ENCODING          (-6)   /* Encoding error */

/**********************************************************************/
/* Peer Address (supports IPv4 and IPv6)                              */
/**********************************************************************/

/* TOS serializes SocketAddr with a type tag:
   - 0x00 + 4-byte IPv4 + 2-byte port (LE) = 7 bytes
   - 0x01 + 16-byte IPv6 + 2-byte port (LE) = 19 bytes */

#define AT_ADDR_TYPE_IPV4            (0)
#define AT_ADDR_TYPE_IPV6            (1)

typedef struct {
  uchar  addr_type;              /* AT_ADDR_TYPE_* */
  union {
    uchar ip4[4];                /* IPv4 address (if addr_type=0) */
    uchar ip6[16];               /* IPv6 address (if addr_type=1) */
  } addr;
  ushort port;                   /* Port (host byte order in memory) */
} at_peer_addr_t;

/* Size of serialized address */
#define AT_PEER_ADDR_IPV4_SZ         (7UL)   /* 1 + 4 + 2 */
#define AT_PEER_ADDR_IPV6_SZ         (19UL)  /* 1 + 16 + 2 */

/**********************************************************************/
/* Cumulative Difficulty (VarUint)                                    */
/**********************************************************************/

/* Variable-length big-endian integer for cumulative PoW difficulty.
   Wire format: 1 byte length (0-32) + length bytes (big-endian, leading zeros stripped)
   Example: 0x1234 serializes as: 0x02 0x12 0x34 (3 bytes total) */

#define AT_CUMULATIVE_DIFF_MAX_SZ    (33UL)  /* 1 byte len + 32 bytes max */

typedef struct {
  uchar  bytes[32];              /* Big-endian bytes (1-32 used) */
  uchar  len;                    /* Actual byte length (0-32) */
} at_cumulative_diff_t;

/**********************************************************************/
/* Handshake Packet (type 1)                                          */
/**********************************************************************/

/* TOS Handshake contains 15 fields for version/network negotiation.
   Note: Option<String> uses special encoding - 0x00=None, otherwise len+data */

typedef struct {
  /* Variable-length string: u8 length prefix + data (max 255 bytes) */
  uchar  version_len;            /* Length of version string */
  char   version[256];           /* Daemon version string */

  uchar  network;                /* at_network_t */

  /* Option<String>: if node_tag_len=0 then None, else Some(node_tag) */
  uchar  node_tag_len;           /* 0=None, 1-16=Some (length IS the indicator) */
  char   node_tag[17];           /* User-defined node name (max 16 enforced) */

  uchar  network_id[16];         /* Unique 16-byte network identifier */
  ulong  peer_id;                /* Unique peer identifier */
  ushort local_port;             /* Our P2P listening port */
  ulong  utc_time;               /* Current UTC timestamp (seconds) */
  ulong  topoheight;             /* Our current topo height */
  ulong  height;                 /* Our current block height */

  /* Option<u64>: pruned_topoheight */
  uchar  has_pruned;             /* 0=None, 1=Some (Option<u64> tag byte) */
  ulong  pruned_topoheight;      /* Lowest available height (if has_pruned=1) */

  uchar  top_hash[32];           /* Our current top block hash */
  uchar  genesis_hash[32];       /* Genesis block hash */

  at_cumulative_diff_t cumulative_diff;  /* Cumulative PoW difficulty */

  uchar  can_be_shared;          /* 1 if peer can be shared with others */
  uchar  supports_fast_sync;     /* 1 if bootstrap sync supported (default true) */
} at_handshake_t;

/**********************************************************************/
/* Ping Packet (type 6)                                               */
/**********************************************************************/

/* TOS Ping contains full chain state + peer list (max 16 peers) */

typedef struct {
  uchar  top_hash[32];           /* Current top block hash */
  ulong  topoheight;             /* Topological height */
  ulong  height;                 /* Block height */

  /* Option<u64>: pruned_topoheight */
  uchar  has_pruned;             /* 0=None, 1=Some */
  ulong  pruned_topoheight;      /* Lowest available height (if has_pruned=1) */

  at_cumulative_diff_t cumulative_diff;  /* Cumulative PoW difficulty */

  uchar  peer_cnt;               /* Number of peers in list (max 16) */
  /* Followed by: peer_cnt * at_peer_addr_t (serialized separately) */
} at_ping_t;

/**********************************************************************/
/* Chain Request Packet (type 4)                                      */
/**********************************************************************/

/* Block identifier (hash + topoheight) */
typedef struct {
  uchar  hash[32];               /* Block hash */
  ulong  topoheight;             /* Block topoheight */
} at_block_id_t;

typedef struct {
  uchar  block_cnt;              /* Number of known blocks (u8, max 64) */
  /* Followed by: block_cnt * at_block_id_t (40 bytes each) */
  ushort accepted_response_size; /* Max blocks to return (u16, 512-65535) */
} at_chain_request_t;

/**********************************************************************/
/* Chain Response Packet (type 5)                                     */
/**********************************************************************/

typedef struct {
  /* Option<BlockId>: common_point */
  uchar  has_common_point;       /* 0=None, 1=Some */
  uchar  common_point_hash[32];  /* Common point hash (if has_common_point=1) */
  ulong  common_point_topoheight;/* Common point topoheight (if has_common_point=1) */

  /* Lowest height (always present when has_common_point=1) */
  ulong  lowest_height;          /* Lowest available height */

  ushort block_cnt;              /* Number of block hashes (u16, max 65535) */
  /* Followed by: block_cnt * 32-byte hashes */

  uchar  top_block_cnt;          /* Number of top block hashes (u8) */
  /* Followed by: top_block_cnt * 32-byte hashes */
} at_chain_response_t;

/**********************************************************************/
/* Object Request Packet (type 7)                                     */
/**********************************************************************/

typedef struct {
  uchar  obj_type;               /* AT_OBJ_TYPE_* */
  uchar  hash[32];               /* Object hash */
} at_object_request_t;

/**********************************************************************/
/* Object Response Packet (type 8)                                    */
/**********************************************************************/

typedef struct {
  uchar  resp_type;              /* AT_OBJ_RESP_* */
  /* Followed by object data if not NOT_FOUND */
} at_object_response_t;

/**********************************************************************/
/* TX Propagation Packet (type 2)                                     */
/**********************************************************************/

/* Wrapped with Ping for state sync */
typedef struct {
  uchar  tx_hash[32];            /* Transaction hash */
  at_ping_t ping;                /* Chain state */
  /* Followed by: ping.peer_cnt * at_peer_addr_t */
} at_tx_propagation_t;

/**********************************************************************/
/* Block Propagation Packet (type 3)                                  */
/**********************************************************************/

/* Wrapped with Ping for state sync.
   Payload is serialized BlockHeader (Rust order) followed by Ping. */
typedef struct {
  uchar  _opaque;                /* Placeholder; see serializer for layout */
} at_block_propagation_t;

/**********************************************************************/
/* Notify Inventory Request (type 9)                                  */
/**********************************************************************/

typedef struct {
  /* Optional page (0=None, otherwise 1..255) */
  uchar  page;                   /* next page hint (0=None) */
} at_notify_inv_request_t;

/**********************************************************************/
/* Notify Inventory Response (type 10)                                */
/**********************************************************************/

typedef struct {
  /* Optional next page (0=None, otherwise 1..255) */
  uchar  next;                   /* next page hint (0=None) */
  ushort tx_cnt;                 /* number of tx hashes */
  /* Followed by: tx_cnt * 32-byte hashes */
} at_notify_inv_response_t;

/**********************************************************************/
/* Bootstrap Request (type 11)                                        */
/**********************************************************************/

typedef struct {
  ulong  step;                   /* Request step ID (for multi-round sync) */
  ulong  from_topoheight;        /* Starting topoheight */
  uchar  request_type;           /* 0=chain_info, 1=accounts, 2=assets, etc. */
} at_bootstrap_request_t;

/**********************************************************************/
/* Bootstrap Response (type 12)                                       */
/**********************************************************************/

typedef struct {
  ulong  step;                   /* Response step ID (matches request) */
  uchar  has_more;               /* 1 if more data available */
  uint   data_len;               /* Length of following data */
  /* Followed by: data_len bytes of serialized chain/account data */
} at_bootstrap_response_t;

/**********************************************************************/
/* Peer Disconnected (type 13)                                        */
/**********************************************************************/

typedef struct {
  ulong  peer_id;                /* Disconnected peer's ID */
} at_peer_disconnected_t;

/**********************************************************************/
/* Wire Format - Serialization Helpers                                */
/**********************************************************************/

/* Write unsigned integers (little-endian) */
int at_p2p_write_u8( uchar ** buf, ulong * remain, uchar val );
int at_p2p_write_u16( uchar ** buf, ulong * remain, ushort val );
int at_p2p_write_u32( uchar ** buf, ulong * remain, uint val );
int at_p2p_write_u64( uchar ** buf, ulong * remain, ulong val );

/* Write bool (1 byte) */
int at_p2p_write_bool( uchar ** buf, ulong * remain, int val );

/* Write raw bytes */
int at_p2p_write_bytes( uchar ** buf, ulong * remain, uchar const * data, ulong len );

/* Write hash (32 bytes) */
int at_p2p_write_hash( uchar ** buf, ulong * remain, uchar const hash[32] );

/* Write string with u8 length prefix (TOS format) */
int at_p2p_write_string( uchar ** buf, ulong * remain, char const * str, ulong len );

/* Write Option<u64>: 0x00=None, 0x01+u64=Some */
int at_p2p_write_option_u64( uchar ** buf, ulong * remain, int has_value, ulong val );

/* Write Option<String>: 0x00=None, otherwise len+data (no separate tag!) */
int at_p2p_write_option_string( uchar ** buf, ulong * remain, char const * str, ulong len );

/* Write VarUint (cumulative difficulty) */
int at_p2p_write_varuint( uchar ** buf, ulong * remain, at_cumulative_diff_t const * diff );

/* Write optional non-zero u8 (0=None, otherwise value) */
int at_p2p_write_optional_non_zero_u8( uchar ** buf, ulong * remain, uchar val );

/* Write socket address (IPv4 or IPv6) */
int at_p2p_write_sockaddr( uchar ** buf, ulong * remain, at_peer_addr_t const * addr );

/**********************************************************************/
/* Wire Format - Deserialization Helpers                              */
/**********************************************************************/

/* Read unsigned integers (little-endian) */
int at_p2p_read_u8( uchar const ** buf, ulong * remain, uchar * out );
int at_p2p_read_u16( uchar const ** buf, ulong * remain, ushort * out );
int at_p2p_read_u32( uchar const ** buf, ulong * remain, uint * out );
int at_p2p_read_u64( uchar const ** buf, ulong * remain, ulong * out );

/* Read bool (1 byte) */
int at_p2p_read_bool( uchar const ** buf, ulong * remain, int * out );

/* Read raw bytes */
int at_p2p_read_bytes( uchar const ** buf, ulong * remain, uchar * out, ulong len );

/* Read hash (32 bytes) */
int at_p2p_read_hash( uchar const ** buf, ulong * remain, uchar out[32] );

/* Read string with u8 length prefix (TOS format) */
int at_p2p_read_string( uchar const ** buf, ulong * remain, char * out, ulong max_len, ulong * out_len );

/* Read Option<u64> */
int at_p2p_read_option_u64( uchar const ** buf, ulong * remain, int * has_value, ulong * out );

/* Read Option<String> (0x00=None, otherwise len+data) */
int at_p2p_read_option_string( uchar const ** buf, ulong * remain, char * out, ulong max_len, ulong * out_len );

/* Read VarUint (cumulative difficulty) */
int at_p2p_read_varuint( uchar const ** buf, ulong * remain, at_cumulative_diff_t * out );

/* Read optional non-zero u8 (0=None, otherwise value) */
int at_p2p_read_optional_non_zero_u8( uchar const ** buf, ulong * remain, uchar * out );

/* Read socket address (IPv4 or IPv6) */
int at_p2p_read_sockaddr( uchar const ** buf, ulong * remain, at_peer_addr_t * out );

/**********************************************************************/
/* Frame Operations                                                   */
/**********************************************************************/

/* at_p2p_frame_send constructs an encrypted frame for transmission.
   - Prepends 4-byte BE length (unencrypted)
   - Encrypts (type byte + payload) with session, appends auth tag
   Returns total frame size on success (positive), error code on failure (negative). */
long
at_p2p_frame_send( at_p2p_session_t * session,
                   uchar              pkt_type,
                   void const *       payload,
                   ulong              payload_sz,
                   void *             out_frame,
                   ulong              out_frame_max );

/* at_p2p_frame_peek_length extracts the 4-byte BE length from a frame header.
   Does NOT decrypt. Use to allocate buffer before full receive.
   Returns payload length (encrypted payload size, NOT plaintext). */
ulong
at_p2p_frame_peek_length( void const * frame_hdr );

/* at_p2p_frame_recv decrypts a received frame.
   frame points to the 4-byte length header + encrypted payload.
   Outputs packet type and decrypted payload.
   Returns payload size on success (positive), error code on failure (negative). */
long
at_p2p_frame_recv( at_p2p_session_t * session,
                   void const *       frame,
                   ulong              frame_sz,
                   uchar *            out_pkt_type,
                   void *             out_payload,
                   ulong              out_payload_max );

/**********************************************************************/
/* Packet Serialization                                               */
/**********************************************************************/

/* Serialize handshake packet.
   Returns serialized size on success (positive), error code on failure (negative). */
long
at_p2p_serialize_handshake( at_handshake_t const * hs,
                            uchar *                buf,
                            ulong                  buf_sz );

/* Serialize ping packet with peer list.
   Returns serialized size on success (positive), error code on failure (negative). */
long
at_p2p_serialize_ping( at_ping_t const *       ping,
                       at_peer_addr_t const *  peers,
                       uchar                   peer_cnt,
                       uchar *                 buf,
                       ulong                   buf_sz );

/* Serialize object request.
   Returns serialized size on success (positive), error code on failure (negative). */
long
at_p2p_serialize_object_request( at_object_request_t const * req,
                                 uchar *                     buf,
                                 ulong                       buf_sz );

/* Serialize chain request with block IDs.
   Returns serialized size on success (positive), error code on failure (negative). */
long
at_p2p_serialize_chain_request( at_chain_request_t const * req,
                                at_block_id_t const *      blocks,
                                uchar                      block_cnt,
                                uchar *                    buf,
                                ulong                      buf_sz );

/* Serialize chain response with block hashes.
   Returns serialized size on success (positive), error code on failure (negative). */
long
at_p2p_serialize_chain_response( at_chain_response_t const * resp,
                                 uchar const (*             blocks)[32],
                                 ushort                     block_cnt,
                                 uchar const (*             top_blocks)[32],
                                 uchar                      top_block_cnt,
                                 uchar *                    buf,
                                 ulong                      buf_sz );

/* Serialize object response.
   resp_type uses AT_OBJ_RESP_*; for NOT_FOUND, obj must be at_object_request_t.
   Returns serialized size on success (positive), error code on failure (negative). */
long
at_p2p_serialize_object_response( uchar                     resp_type,
                                  void const *              obj,
                                  ulong                     obj_sz,
                                  uchar *                   buf,
                                  ulong                     buf_sz );

/* Serialize notify inventory request/response. */
long
at_p2p_serialize_notify_inv_request( at_notify_inv_request_t const * req,
                                     uchar *                         buf,
                                     ulong                           buf_sz );

long
at_p2p_serialize_notify_inv_response( at_notify_inv_response_t const * resp,
                                      uchar const (*                  txs)[32],
                                      ushort                          tx_cnt,
                                      uchar *                         buf,
                                      ulong                           buf_sz );

/**********************************************************************/
/* Packet Deserialization                                             */
/**********************************************************************/

/* Deserialize handshake packet.
   Returns 0 on success, error code on failure. */
int
at_p2p_deserialize_handshake( uchar const *    buf,
                              ulong            buf_sz,
                              at_handshake_t * out );

/* Deserialize ping packet with peer list.
   Returns 0 on success, error code on failure. */
int
at_p2p_deserialize_ping( uchar const *    buf,
                         ulong            buf_sz,
                         at_ping_t *      out_ping,
                         at_peer_addr_t * out_peers,
                         uchar            max_peers,
                         uchar *          out_peer_cnt );

/* Deserialize object request.
   Returns 0 on success, error code on failure. */
int
at_p2p_deserialize_object_request( uchar const *         buf,
                                   ulong                 buf_sz,
                                   at_object_request_t * out );

/* Deserialize chain request with block IDs.
   Returns 0 on success, error code on failure. */
int
at_p2p_deserialize_chain_request( uchar const *        buf,
                                  ulong                buf_sz,
                                  at_chain_request_t * out_req,
                                  at_block_id_t *      out_blocks,
                                  uchar                max_blocks,
                                  uchar *              out_block_cnt );

/* Deserialize chain response.
   Returns 0 on success, error code on failure. */
int
at_p2p_deserialize_chain_response( uchar const *         buf,
                                   ulong                 buf_sz,
                                   at_chain_response_t * out_resp,
                                   uchar (*              out_blocks)[32],
                                   ushort                max_blocks,
                                   ushort *              out_block_cnt,
                                   uchar (*              out_top_blocks)[32],
                                   uchar                 max_top_blocks,
                                   uchar *               out_top_block_cnt );

/* Deserialize object response. */
int
at_p2p_deserialize_object_response( uchar const * buf,
                                    ulong         buf_sz,
                                    uchar *       out_resp_type,
                                    uchar *       out_payload,
                                    ulong         out_payload_max,
                                    ulong *       out_payload_sz );

/* Deserialize notify inventory request/response. */
int
at_p2p_deserialize_notify_inv_request( uchar const *              buf,
                                       ulong                      buf_sz,
                                       at_notify_inv_request_t *  out_req );

int
at_p2p_deserialize_notify_inv_response( uchar const *               buf,
                                        ulong                       buf_sz,
                                        at_notify_inv_response_t *  out_resp,
                                        uchar (*                    out_txs)[32],
                                        ushort                      max_txs,
                                        ushort *                    out_tx_cnt );

/**********************************************************************/
/* Utility Functions                                                  */
/**********************************************************************/

/* Get packet type name for debugging */
char const *
at_p2p_pkt_type_name( uchar pkt_type );

/* Initialize cumulative_diff from u64 (low bits only) */
void
at_cumulative_diff_from_u64( at_cumulative_diff_t * diff, ulong val );

/* Compare two cumulative difficulties.
   Returns <0 if a<b, 0 if a==b, >0 if a>b */
int
at_cumulative_diff_cmp( at_cumulative_diff_t const * a,
                        at_cumulative_diff_t const * b );

AT_PROTOTYPES_END

#endif /* HEADER_at_waltz_p2p_at_p2p_msg_h */