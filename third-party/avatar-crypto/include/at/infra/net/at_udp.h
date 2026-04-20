#ifndef HEADER_at_src_util_net_at_udp_h
#define HEADER_at_src_util_net_at_udp_h

#include "at_ip4.h" /* UDP is tightly tied to IP regardless of standard intent due to pseudo header layer violating BS */

/* FIXME: UDP CRASH COURSE HERE */

union at_udp_hdr {
  struct {
    ushort net_sport; /* src port, net order */
    ushort net_dport; /* dst port, net order */
    ushort net_len;   /* datagram length, from first byte of this header to last byte of the udp payload */
    ushort check;     /* UDP checksum ("invariant" order), from first byte of pseudo header prepended before this header to last
                         byte of udp payload with zero padding to even length inclusive.  In IP4, 0 indicates no checksum. */
  };
  uchar uc[8];
};

typedef union at_udp_hdr at_udp_hdr_t;

/* FIXME: CONSIDER A PRETTY PRINTER FOR A AT_UDP_HDR? */

AT_PROTOTYPES_BEGIN

/* at_ip4_udp_check is used for udp check field computation and
   validation.  If the dgram has no checksum (check==0), this returns
   the value to use for check.  If the dgram has a checksum (check!=0),
   this returns 0 if the message has a valid checksum or non-zero if
   not.  ip4_saddr and ip4_daddr are the ip4 source and destination
   addresses to use for the udp pseudo header.  udp is a non-NULL
   pointer to the first byte of a memory region containing the udp
   header and dgram is a non-NULL pointer to the first byte of a memory
   region containing a datagram of size:

     dgram_sz = at_ushort_bswap(udp->net_len) - sizeof(at_udp_hdr_t)

   bytes.  This assumes it is safe to read up to 3 bytes past the end of
   dgram (technically it will read the at_align_up(dgram_sz,4UL) bytes
   dgram).  The contents of the tail read region are irrelevant.

   This is neither a particularly fast calculation (reasonably fast
   O(dgram_sz)) nor a particularly robust and it can inhibit cut-through
   usage.  So in general it is best to avoid UDP checksums, usually by
   exploiting their optionality in IP4 (note that the Ethernet CRC is
   reasonably strong and still provides protection).

   As such, this is mostly here for the rare application that needs to
   manually compute / validate UDP checksums (e.g. overhead doesn't
   matter or when the hardware sending/receiving the packet doesn't do
   various checksum offload computations and UDP checksums are
   required). */

AT_FN_PURE static inline ushort
at_ip4_udp_check( uint                 ip4_saddr,
                  uint                 ip4_daddr,
                  at_udp_hdr_t const * udp,
                  void const *         dgram ) { /* Assumed safe to tail read up to 3 bytes past end of msg */
  ushort net_len = udp->net_len; /* In net order */
  uint   rem     = (uint)at_ushort_bswap( net_len ) - (uint)sizeof(at_udp_hdr_t);

  /* Sum the pseudo header and UDP header words */
  ulong ul = ((((ulong)AT_IP4_HDR_PROTOCOL_UDP)<<8) | (((ulong)net_len)<<16))
           + ((ulong)ip4_saddr)
           + ((ulong)ip4_daddr)
           + ((ulong)AT_LOAD( uint, udp->uc   ))
           + ((ulong)AT_LOAD( uint, udp->uc+4 ));

  /* Sum the dgram words (reads up to 4 past end of msg) */
  uchar const * u = dgram;
  for( ; rem>3U; rem-=4U, u+=4 ) ul += (ulong)AT_LOAD( uint, u );
  ul += (ulong)( AT_LOAD( uint, u ) & ((1U<<(8U*rem))-1U) );

  /* Reduce the sum to a 16-bit one's complement sum */
  ul  = ( ul>>32            ) +
        ((ul>>16) & 0xffffUL) +
        ( ul      & 0xffffUL);
  ul  = ( ul>>16            ) +
        ( ul      & 0xffffUL);
  ul += ( ul>>16            );

  /* And complement it */
  return (ushort)~ul;
}

/* at_udp_hdr_bswap reverses the endianness of all fields in the UDP
   header. */

static inline void
at_udp_hdr_bswap( at_udp_hdr_t * hdr ) {
  hdr->net_sport = (ushort)at_ushort_bswap( hdr->net_sport    );
  hdr->net_dport = (ushort)at_ushort_bswap( hdr->net_dport    );
  hdr->net_len   = (ushort)at_ushort_bswap( hdr->net_len      );
  hdr->check     = (ushort)at_ushort_bswap( hdr->check        );
}

AT_PROTOTYPES_END

#endif /* HEADER_at_src_util_net_at_udp_h */