#ifndef HEADER_at_src_util_net_at_ip6_h
#define HEADER_at_src_util_net_at_ip6_h

#include "../bits/at_bits.h"

static inline void
at_ip6_addr_ip4_mapped( uchar      ip6_addr[16],
                        uint const ip4_addr ) {
  at_memset( ip6_addr, 0, 10 );
  ip6_addr[ 10 ] = (uchar)0xff;
  ip6_addr[ 11 ] = (uchar)0xff;
  at_memcpy( ip6_addr+12, &ip4_addr, 4 );
}

static inline int
at_ip6_addr_is_ip4_mapped( uchar const ip6_addr[16] ) {
  return (
    (ip6_addr[  0 ]==0x00) & (ip6_addr[  1 ]==0x00) &
    (ip6_addr[  2 ]==0x00) & (ip6_addr[  3 ]==0x00) &
    (ip6_addr[  4 ]==0x00) & (ip6_addr[  5 ]==0x00) &
    (ip6_addr[  6 ]==0x00) & (ip6_addr[  7 ]==0x00) &
    (ip6_addr[  8 ]==0x00) & (ip6_addr[  9 ]==0x00) &
    (ip6_addr[ 10 ]==0xff) & (ip6_addr[ 11 ]==0xff)
  );
}

static inline uint
at_ip6_addr_to_ip4( uchar const ip6_addr[16] ) {
  uint ip4_addr;
  at_memcpy( &ip4_addr, ip6_addr+12, 4 );
  return ip4_addr;
}

#endif /* HEADER_at_src_util_net_at_ip6_h */