#ifndef HEADER_at_src_util_net_at_ip4_h
#define HEADER_at_src_util_net_at_ip4_h

#include "../bits/at_bits.h"

/* FIXME: IP4 CRASH COURSE HERE */

#define AT_IP4_HDR_TOS_PREC_INTERNETCONTROL ((uchar)0xc0) /* This packet is should have Internet control type of service */

#define AT_IP4_HDR_FRAG_OFF_RF   ((ushort)0x8000) /* (in host byte order) Mask for the frag off reserved bit */
#define AT_IP4_HDR_FRAG_OFF_DF   ((ushort)0x4000) /* (in host byte order) Mask for the frag off don't frag bit */
#define AT_IP4_HDR_FRAG_OFF_MF   ((ushort)0x2000) /* (in host byte order) Mask for the frag off more frags bit */
#define AT_IP4_HDR_FRAG_OFF_MASK ((ushort)0x1fff) /* (in host byte order) Mask for the frag off offset bits */

#define AT_IP4_HDR_PROTOCOL_IP4  ((uchar) 0) /* The IP4 packet encapsulates an IP4  packet */
#define AT_IP4_HDR_PROTOCOL_ICMP ((uchar) 1) /* The IP4 packet encapsulates an ICMP packet */
#define AT_IP4_HDR_PROTOCOL_IGMP ((uchar) 2) /* The IP4 packet encapsulates an IGMP packet */
#define AT_IP4_HDR_PROTOCOL_TCP  ((uchar) 6) /* The IP4 packet encapsulates an TCP  packet */
#define AT_IP4_HDR_PROTOCOL_UDP  ((uchar)17) /* The IP4 packet encapsulates an UDP  packet */
#define AT_IP4_HDR_PROTOCOL_GRE  ((uchar)47) /* The IP4 packet encapsulates a GRE  packet */

#define AT_IP4_OPT_RA  ((uchar)148) /* This option is a router alert option */
#define AT_IP4_OPT_EOL ((uchar)0)   /* This is the end of the options list */

/* All of the below are in network byte order */
#define IP4_PRIVATE_RANGE1_START_NET AT_IP4_ADDR( 10,   0,   0,   0)
#define IP4_PRIVATE_RANGE1_END_NET   AT_IP4_ADDR( 10, 255, 255, 255)
#define IP4_PRIVATE_RANGE2_START_NET AT_IP4_ADDR(172,  16,   0,   0)
#define IP4_PRIVATE_RANGE2_END_NET   AT_IP4_ADDR(172,  31, 255, 255)
#define IP4_PRIVATE_RANGE3_START_NET AT_IP4_ADDR(192, 168,   0,   0)
#define IP4_PRIVATE_RANGE3_END_NET   AT_IP4_ADDR(192, 168, 255, 255)

#define IP4_LOOPBACK_START_NET       AT_IP4_ADDR(127,   0,   0,   0)
#define IP4_LOOPBACK_END_NET         AT_IP4_ADDR(127, 255, 255, 255)

union at_ip4_hdr {
  struct {
    uchar  verihl;       /* 4 msb: IP version (==4), assumes little endian */
                         /* 4 lsb: Header length in words (>=5) */
    uchar  tos;          /* Type of service */
    ushort net_tot_len;  /* Frag size in bytes, incl ip hdr, net order */
    ushort net_id;       /* Frag id, unique from sender for long enough, net order */
    ushort net_frag_off; /* Frag off (dbl words)+status (top 3 bits), net order */
    uchar  ttl;          /* Frag time to live */
    uchar  protocol;     /* Type of payload */
    ushort check;        /* Header checksum ("invariant" order) */
    union __attribute__((packed)) {
      uchar saddr_c[4];  /* Address of sender, technically net order but all APIs below work with this directly */
      uint  saddr;
    };
    union __attribute__((packed)) {
      uchar daddr_c[4];  /* Address of destination, technically net order but all APIs below work with this directly */
      uint  daddr;
    };
    /* Up to 40 bytes of options here */
  };
};

typedef union at_ip4_hdr at_ip4_hdr_t;

/* AT_IP4_GET_VERSION obtains the version from the supplied at_ip4_hdr */

#define AT_IP4_GET_VERSION(ip4) ((uchar)( ( (uint)(ip4).verihl >> 4u ) & 0x0fu ))

/* AT_IP4_SET_VERSION sets the version in the supplied at_ip4_hdr */

#define AT_IP4_SET_VERSION(ip4,value) (ip4).verihl = ((uchar)( \
      ( (uint)(ip4).verihl & 0x0fu ) | ( ( (uint)(value) & 0x0fu ) << 4u ) ))

/* AT_IP4_GET_IHL retrieves the IHL field from the supplied at_ip4_hdr */

#define AT_IP4_GET_IHL(ip4) ((uchar)( (uint)(ip4).verihl & 0x0fu ))

/* AT_IP4_GET_LEN retrieves and adjusts the IHL field from the supplied at_ip4_hdr */

#define AT_IP4_GET_LEN(ip4) ( AT_IP4_GET_IHL(ip4) * 4u )

/* AT_IP4_SET_IHL sets the IHL field in the supplied at_ip4_hdr */

#define AT_IP4_SET_IHL(ip4,value) (ip4).verihl = ((uchar)( \
      ( (uint)(ip4).verihl & 0xf0u ) | ( (uint)(value) & 0x0fu ) ))

/* AT_IP4_VERIHL combines the supplied IHL and VERSION into a single verihl fields */

#define AT_IP4_VERIHL(version,ihl) ((uchar)( ( ((uint)(version) & 0x0fu) << 4u ) | \
                                               ((uint)(ihl)     & 0x0fu) ))

/* AT_IP4_ADDR constructs an IP4 address from the 4-tuple x.y.z.w.
   Assumes x,y,z,w are all integers in [0,255]. */

#define AT_IP4_ADDR(x,y,z,w) (((uint)(x)) | (((uint)(y)) << 8) | (((uint)(z)) << 16) | (((uint)(w)) << 24))

/* AT_IP4_ADDR_FMT / AT_IP4_ADDR_FMT_ARGS are used to pretty print a
   ip4 address by a printf style formatter.  a must be safe against
   multiple evaluation.  Example usage:

     at_ip4_hdr_t * hdr = ...;
     AT_LOG_NOTICE(( "DST MAC: " AT_IP4_ADDR_FMT, AT_IP4_ADDR_FMT_ARGS( hdr->daddr ) */

#define AT_IP4_ADDR_FMT         "%u.%u.%u.%u"
#define AT_IP4_ADDR_FMT_ARGS(a) ((a) & 255U),(((a)>>8) & 255U),(((a)>>16) & 255U),((a)>>24)

/* FIXME: CONSIDER AN OVERALL HEADER PRETTY PRINTER? */

AT_PROTOTYPES_BEGIN

/* at_ip4_addr_is_{mcast,bcast} returns 1 if the ipaddr is {multicast
   (in [224-239].y.z.w),global broadcast (255.255.255.255)} and 0
   otherwise. at_ip4_hdr_net_frag_off_is_unfragmented returns 1 if the
   net_frag_off field of the ip4 header indicates the encapsulated
   packet is not fragmented (i.e. entirely containing the IP4 packet)
   and 0 otherwise (i.e. fragmented into multiple IP4 packets). */

AT_FN_CONST static inline int at_ip4_addr_is_mcast( uint addr ) { return (((uchar)addr)>>4)==(uchar)0xe; }
AT_FN_CONST static inline int at_ip4_addr_is_bcast( uint addr ) { return addr==~0U;                      }

AT_FN_CONST static inline int
at_ip4_hdr_net_frag_off_is_unfragmented( ushort net_frag_off ) { /* net order */
  return !(((uint)net_frag_off) & 0xff3fU); /* ff3f is at_ushort_bswap( NET_IP_HDR_FRAG_OFF_MASK | NET_IP_HDR_FRAG_OFF_MF ) */
}

/* at_ip4_hdr_check is used for hdr check field computation and
   validation.  hdr points to the first byte a memory region containing
   an ip4 header and any options that might follow it.  If the header
   has checksum (check==0), this returns the value to use for check.  If
   hdr has a checksum (check!=0), this returns 0 if hdr has a valid
   checksum (or non-zero if not).  This is mostly for use in cases where
   the overhead doesn't matter or when the hardware sending/receiving
   the packet doesn't do various checksum offload computations. */

AT_FN_PURE static inline ushort
at_ip4_hdr_check( void const * vp_hdr ) {
  uchar * cp = (uchar*)vp_hdr;

  uint n = ( (*cp) & 0x0fu );

  /* optimizes the first 5 by unrolling */
  if( n < 5 ) __builtin_unreachable();

  ulong        c = 0UL;
  for( uint i=0U; i<n; i++ ) {
    uint u;

    /* the compiler elides the copy in practice */
    at_memcpy( &u, cp + i*4, 4 );
    c += (ulong)u;
  }

  c  = ( c>>32            ) +
       ((c>>16) & 0xffffUL) +
       ( c      & 0xffffUL);
  c  = ( c>>16            ) +
       ( c      & 0xffffUL);
  c += ( c>>16            );

  return (ushort)~c;
}

/* at_ip4_hdr_check_fast is the same as the above but assumes that the
   header has no options (i.e. ihl==5) */

AT_FN_PURE static inline ushort
at_ip4_hdr_check_fast( void const * vp_hdr ) {
  uchar * cp = (uchar*)vp_hdr;

  uint n = ( (*cp) & 0x0fu );

  /* branches aren't taken don't use branch table entries */
  if( AT_UNLIKELY( n != 5 ) ) return at_ip4_hdr_check(vp_hdr);

  /* the compiler knows n here and completely unrolls the loop */
  ulong c = 0UL;
  for( uint i=0U; i<n; i++ ) {
    uint u;

    /* the compiler elides the copy in practice */
    at_memcpy( &u, cp + i*4, 4 );
    c += (ulong)u;
  }

  c  = ( c>>32            ) +
       ((c>>16) & 0xffffUL) +
       ( c      & 0xffffUL);
  c  = ( c>>16            ) +
       ( c      & 0xffffUL);
  c += ( c>>16            );

  return (ushort)~c;
}

/* at_cstr_to_ip4_addr parses an IPv4 address matching format
   %u.%u.%u.%u  On success stores address to out and returns 1. On fail
   returns 0.  The given address is returned in network byte order such
   that "1.0.0.0" => 0x00000001. */

int
at_cstr_to_ip4_addr( char const * s,
                     uint *       addr );

/* at_ip4_addr_is_public checks if the given IPv4 address is a public address.
   assumed to be in net byte order.  */

AT_FN_CONST static inline int
at_ip4_addr_is_public( uint addr ) {
  uint addr_host = at_uint_bswap( addr );
  return !((addr_host >= at_uint_bswap( IP4_PRIVATE_RANGE1_START_NET ) && addr_host <= at_uint_bswap( IP4_PRIVATE_RANGE1_END_NET )) ||
           (addr_host >= at_uint_bswap( IP4_PRIVATE_RANGE2_START_NET ) && addr_host <= at_uint_bswap( IP4_PRIVATE_RANGE2_END_NET )) ||
           (addr_host >= at_uint_bswap( IP4_PRIVATE_RANGE3_START_NET ) && addr_host <= at_uint_bswap( IP4_PRIVATE_RANGE3_END_NET )) ||
           (addr_host >= at_uint_bswap( IP4_LOOPBACK_START_NET )       && addr_host <= at_uint_bswap( IP4_LOOPBACK_END_NET )));
}

/* at_ip4_hdr_bswap reverses the endianness of all fields in the IPv4
   header. */

static inline void
at_ip4_hdr_bswap( at_ip4_hdr_t * hdr ) {
  hdr->net_tot_len  = (ushort)at_ushort_bswap( hdr->net_tot_len  );
  hdr->net_id       = (ushort)at_ushort_bswap( hdr->net_id       );
  hdr->net_frag_off = (ushort)at_ushort_bswap( hdr->net_frag_off );
  hdr->check        = (ushort)at_ushort_bswap( hdr->check        );
}

AT_PROTOTYPES_END

#endif /* HEADER_at_src_util_net_at_ip4_h */