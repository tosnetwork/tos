#ifndef HEADER_at_waltz_p2p_at_p2p_dispatch_h
#define HEADER_at_waltz_p2p_at_p2p_dispatch_h

/* at_p2p_dispatch.h - Internal P2P dispatch header for inter-tile messaging

   This header is used for passing decrypted P2P packets between tiles
   (TCP transport tile -> gossip/sync/repair and reverse for outbound).
*/

#include "at/infra/at_util_base.h"

AT_PROTOTYPES_BEGIN

/* Signature marker placed in mcache sig to identify dispatch payloads */
#define AT_P2P_DISPATCH_SIG (0x4154503250445350ULL) /* "ATP2PDSP" */

/* Fixed header prepended to dispatch payloads */
typedef struct __attribute__((packed)) {
  uint  peer_idx;     /* at_peer_pool index */
  uchar pkt_type;     /* AT_PKT_* */
  uchar _pad[3];
  uint  payload_sz;   /* bytes following header */
} at_p2p_dispatch_hdr_t;

#define AT_P2P_DISPATCH_HDR_SZ (sizeof(at_p2p_dispatch_hdr_t))

AT_PROTOTYPES_END

#endif /* HEADER_at_waltz_p2p_at_p2p_dispatch_h */