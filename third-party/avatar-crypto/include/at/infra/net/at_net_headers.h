#ifndef HEADER_at_src_util_net_at_net_headers_h
#define HEADER_at_src_util_net_at_net_headers_h

#include "at_udp.h"
#include "at_eth.h"

/* at_ip4_udp_hdrs is useful to construct Ethernet+IPv4+UDP network
   headers. Assumes that the IPv4 header has no options (IHL=5). */

union at_ip4_udp_hdrs {
  uchar uc[ 42 ];
  struct {
    at_eth_hdr_t eth[1];
    at_ip4_hdr_t ip4[1];
    at_udp_hdr_t udp[1];
  };
};

typedef union at_ip4_udp_hdrs at_ip4_udp_hdrs_t;

AT_PROTOTYPES_BEGIN

/* Helper method to populate a header template containing Ethernet,
   IPv4 (no options), and UDP headers.  Note that IPv4 and UDP header
   checksums are set to 0. */

static inline at_ip4_udp_hdrs_t *
at_ip4_udp_hdr_init( at_ip4_udp_hdrs_t * hdrs,
                     ulong               payload_sz,
                     uint                src_ip,
                     ushort              src_port ) {
  at_eth_hdr_t * eth = hdrs->eth;
  at_memset( eth->dst, 0, 6UL );
  at_memset( eth->src, 0, 6UL );
  eth->net_type  = at_ushort_bswap( AT_ETH_HDR_TYPE_IP );

  at_ip4_hdr_t * ip4 = hdrs->ip4;
  ip4->verihl       = AT_IP4_VERIHL( 4U, 5U );
  ip4->tos          = (uchar)0;
  ip4->net_tot_len  = at_ushort_bswap( (ushort)(payload_sz + sizeof(at_ip4_hdr_t)+sizeof(at_udp_hdr_t)) );
  ip4->net_frag_off = at_ushort_bswap( AT_IP4_HDR_FRAG_OFF_DF );
  ip4->ttl          = (uchar)64;
  ip4->protocol     = AT_IP4_HDR_PROTOCOL_UDP;
  ip4->check        = 0U;
  ip4->saddr        = src_ip;
  ip4->daddr        = 0;

  at_udp_hdr_t * udp = hdrs->udp;
  udp->net_sport = at_ushort_bswap( src_port );
  udp->net_dport = (ushort)0;
  udp->net_len   = at_ushort_bswap( (ushort)(payload_sz + sizeof(at_udp_hdr_t)) );
  udp->check     = (ushort)0;

  return hdrs;
}

AT_PROTOTYPES_END

union at_ip4_port {
  struct {
    uint   addr;  /* net order */
    ushort port;  /* net order */
  };
  ulong l : 48;
};

typedef union at_ip4_port at_ip4_port_t;

/* at_ip4_udp_hdr_strip deconstructs a network packet.  If any opt_* are
   set to NULL, then they are not populated. It copies pointers to
   Ethernet, IPv4 (no options), and UDP headers into opt_eth, opt_ip4,
   and opt_udp respectively. It copies a pointer to the start of the
   packet payload into opt_payload, and the packet payload size into
   opt_payload_sz.

   A few basic integrity checks are preformed on included size fields.
   Returns 1 on success and 0 on failure */

static inline int
at_ip4_udp_hdr_strip( uchar const *         data,
                      ulong                 data_sz,
                      uchar ** const        opt_payload,
                      ulong *               opt_payload_sz,
                      at_eth_hdr_t ** const opt_eth,
                      at_ip4_hdr_t ** const opt_ip4,
                      at_udp_hdr_t ** const opt_udp ) {
  at_eth_hdr_t const * eth = (at_eth_hdr_t const *)data;
  at_ip4_hdr_t const * ip4 = (at_ip4_hdr_t const *)( (ulong)eth + sizeof(at_eth_hdr_t) );
  at_udp_hdr_t const * udp = (at_udp_hdr_t const *)( (ulong)ip4 + AT_IP4_GET_LEN( *ip4 ) );

  /* data_sz is less than the observed combined header size */
  if( AT_UNLIKELY( (ulong)udp+sizeof(at_udp_hdr_t) > (ulong)eth+data_sz ) ) return 0;
  ulong udp_sz = at_ushort_bswap( udp->net_len );

  /* observed udp_hdr+payload sz is smaller than minimum udp header sz */
  if( AT_UNLIKELY( udp_sz<sizeof(at_udp_hdr_t) ) ) return 0;
  ulong payload_sz_ = udp_sz-sizeof(at_udp_hdr_t);
  uchar * payload_     = (uchar *)( (ulong)udp + sizeof(at_udp_hdr_t) );

  /* payload_sz is greater than the total packet size */
  if( AT_UNLIKELY( payload_+payload_sz_>data+data_sz ) ) return 0;

  at_ulong_store_if( !!opt_eth,        (ulong*)opt_eth,     (ulong)eth      );
  at_ulong_store_if( !!opt_ip4,        (ulong*)opt_ip4,     (ulong)ip4      );
  at_ulong_store_if( !!opt_udp,        (ulong*)opt_udp,     (ulong)udp      );
  at_ulong_store_if( !!opt_payload,    (ulong*)opt_payload, (ulong)payload_ );
  at_ulong_store_if( !!opt_payload_sz, opt_payload_sz,      payload_sz_     );

  return 1;
}

#endif /* HEADER_at_src_util_net_at_net_headers_h */