#ifndef HEADER_at_waltz_p2p_discovery_at_discv6_url_h
#define HEADER_at_waltz_p2p_discovery_at_discv6_url_h

/* at_discv6_url.h - tosnode:// URL Parser

   Parses and generates tosnode:// URLs for peer discovery.

   URL Format: tosnode://<node_id_hex>@<ip>:<port>

   Example:
   tosnode://abc123def456...@192.168.1.100:2126
   tosnode://abc123def456...@[::1]:2126  (IPv6 in brackets)
*/

#include "at/infra/at_util_base.h"
#include "at/p2p/at_p2p_msg.h"

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* Constants                                                           */
/**********************************************************************/

#define AT_DISCV6_URL_SCHEME      "tosnode://"
#define AT_DISCV6_URL_SCHEME_LEN  (10UL)
#define AT_DISCV6_URL_MAX_LEN     (256UL)
#define AT_DISCV6_NODE_ID_HEX_LEN (64UL)  /* 32 bytes * 2 */

/**********************************************************************/
/* Parsed URL                                                          */
/**********************************************************************/

typedef struct {
  uchar          node_id[32];       /* Decoded node ID */
  at_peer_addr_t addr;              /* Parsed address */
} at_discv6_url_t;

/**********************************************************************/
/* Parsing Functions                                                   */
/**********************************************************************/

/* at_discv6_url_parse parses a tosnode:// URL.
   url: null-terminated URL string
   out: receives parsed components
   Returns 0 on success, negative error code on failure.

   Error codes:
   - AT_DISCV6_ERR_INVAL: malformed URL
   - AT_DISCV6_ERR_TRUNCATED: URL too long */
int
at_discv6_url_parse( char const *      url,
                     at_discv6_url_t * out );

/* at_discv6_url_parse_n parses a tosnode:// URL with explicit length.
   Does not require null termination.
   Returns 0 on success, negative error code on failure. */
int
at_discv6_url_parse_n( char const *      url,
                       ulong             url_len,
                       at_discv6_url_t * out );

/**********************************************************************/
/* Generation Functions                                                */
/**********************************************************************/

/* at_discv6_url_format generates a tosnode:// URL.
   node_id: 32-byte node ID
   addr: peer address
   buf: output buffer
   buf_sz: buffer size
   Returns number of bytes written (excluding null terminator),
   or negative error code if buffer too small. */
long
at_discv6_url_format( uchar const            node_id[32],
                      at_peer_addr_t const * addr,
                      char *                 buf,
                      ulong                  buf_sz );

/**********************************************************************/
/* Validation Functions                                                */
/**********************************************************************/

/* at_discv6_url_is_valid returns 1 if URL appears valid, 0 otherwise.
   Does not fully parse, just checks basic structure. */
int
at_discv6_url_is_valid( char const * url );

/**********************************************************************/
/* Hex Encoding Helpers                                                */
/**********************************************************************/

/* at_discv6_hex_encode encodes binary to lowercase hex.
   out must have space for len*2 bytes.
   Returns out. */
char *
at_discv6_hex_encode( char *        out,
                      uchar const * in,
                      ulong         len );

/* at_discv6_hex_decode decodes hex to binary.
   out must have space for len/2 bytes.
   Returns 0 on success, -1 on invalid hex. */
int
at_discv6_hex_decode( uchar *      out,
                      char const * in,
                      ulong        len );

AT_PROTOTYPES_END

#endif /* HEADER_at_waltz_p2p_discovery_at_discv6_url_h */
