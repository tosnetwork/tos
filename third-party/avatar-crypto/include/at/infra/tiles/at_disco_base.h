#ifndef HEADER_at_disco_base_h
#define HEADER_at_disco_base_h

/* Avatar disco base - includes all dependencies needed by disco components */

#include "at/infra/at_util_base.h"
#include "at/infra/at_shmem.h"
#include "at/infra/at_wksp.h"
#include "at/infra/ipc/at_tango_base.h"
#include "at/infra/ipc/at_mcache.h"
#include "at/infra/ipc/at_dcache.h"
#include "at/infra/ipc/at_fseq.h"
#include "at/infra/tile/at_tile.h"

/* Public key type */
#ifndef AT_PUBKEY_T_DEFINED
#define AT_PUBKEY_T_DEFINED
struct at_pubkey {
  uchar key[32];
};
typedef struct at_pubkey at_pubkey_t;
#endif

/* IP4 port structure */
typedef struct {
  uint   addr; /* network byte order */
  ushort port; /* host byte order */
} at_ip4_port_t;

/**********************************************************************/
/* Network multiplexing signature (sig field encoding)                 */
/**********************************************************************/

/* Protocol identifiers for network packets */
#define DST_PROTO_OUTGOING  (0UL)  /* Outgoing packet to be sent */
#define DST_PROTO_TPU_UDP   (1UL)  /* TPU over UDP */
#define DST_PROTO_TPU_QUIC  (2UL)  /* TPU over QUIC */
#define DST_PROTO_SHRED     (3UL)  /* Shred/turbine protocol */
#define DST_PROTO_GOSSIP    (4UL)  /* Gossip protocol */
#define DST_PROTO_REPAIR    (5UL)  /* Repair protocol */
#define DST_PROTO_SEND      (6UL)  /* Send transaction */

/* at_disco_netmux_sig creates a signature for network multiplexing.

   hdr_sz is the total size of network headers (eth + ip + udp).
   For incoming packets, hash_ip_addr/hash_port are the source.
   For outgoing packets, they are the destination. */
AT_FN_CONST static inline ulong
at_disco_netmux_sig( uint   hash_ip_addr,
                     ushort hash_port,
                     uint   ip_addr,
                     ulong  proto,
                     ulong  hdr_sz ) {
  /* Compress header size: total = 42 + 4*i where 0 <= i <= 13 */
  ulong hdr_sz_i = ((hdr_sz - 42UL)>>2)&0xFUL;
  ulong hash     = 0xfffffUL & at_ulong_hash( (ulong)hash_ip_addr | ((ulong)hash_port<<32) );
  return (hash<<44) | ((hdr_sz_i&0xFUL)<<40UL) | ((proto&0xFFUL)<<32UL) | ((ulong)ip_addr);
}

AT_FN_CONST static inline ulong at_disco_netmux_sig_hash  ( ulong sig ) { return (sig>>44UL); }
AT_FN_CONST static inline ulong at_disco_netmux_sig_proto ( ulong sig ) { return (sig>>32UL) & 0xFFUL; }
AT_FN_CONST static inline uint  at_disco_netmux_sig_ip    ( ulong sig ) { return (uint)(sig & 0xFFFFFFFFUL); }
AT_FN_CONST static inline ulong at_disco_netmux_sig_hdr_sz( ulong sig ) { return 4UL*((sig>>40UL) & 0xFUL) + 42UL; }

#endif /* HEADER_at_disco_base_h */
