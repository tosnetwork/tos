#ifndef HEADER_at_src_util_net_at_gre_h
#define HEADER_at_src_util_net_at_gre_h

#include "../bits/at_bits.h"

#define AT_GRE_HDR_FLG_VER_BASIC ((ushort)0x0000)

union at_gre_hdr {
  struct {
    ushort flags_version; /* should be AT_GRE_HDR_FLG_VER_BASIC in net order */
    ushort protocol; /* should be AT_ETH_HDR_TYPE_IP in net order */
  };
  uchar uc[4];
};

typedef union at_gre_hdr at_gre_hdr_t;

#endif  /* HEADER_at_src_util_net_at_gre_h */