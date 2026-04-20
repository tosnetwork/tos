/* at_xdp1.h - XDP program generation and installation */

#ifndef HEADER_at_p2p_xdp_at_xdp1_h
#define HEADER_at_p2p_xdp_at_xdp1_h

#include "at/infra/at_util_base.h"

/* at_xdp_fds_t is defined on all platforms so that at_topo_install_xdp
   can have a consistent signature. */

struct at_xdp_fds {
  uint if_idx;
  int  xsk_map_fd;
  int  prog_link_fd;
};

typedef struct at_xdp_fds at_xdp_fds_t;

#if defined(__linux__)

AT_PROTOTYPES_BEGIN

/* at_xdp_gen_program generates an XDP program that steers incoming
   packets to AF_XDP sockets using XDP_REDIRECT.  Places the
   eBPF program bytecode at code_buf.  xsks_fd is the XSKMAP file
   descriptor.  If listen_ip_addr!=0, only redirects packets with a
   matching dst IP address.  ports is a list of UDP dst ports to
   redirect.  If allowed_gre==1, also forwards GRE-tunnelled packets. */

ulong
at_xdp_gen_program( ulong          code_buf[ 512 ],
                    int            xsks_fd,
                    uint           listen_ip4_addr,
                    ushort const * ports,
                    ulong          ports_cnt,
                    int            allowed_gre );

/* at_xdp_install installs a BPF program onto the given interface which
   only passes through UDP traffic on the provided ports to rings on an
   XSK map.  If listen_ip4_addr is not zero, specifies a net order IPv4
   address to filter the dest address for.  The XSK map is created and
   returned in the at_xdp_fds_t, along with a bpf link file descriptor.
   This link must not be closed or the XDP program will be uninstalled
   from the device.

   The XSK map returned in xsk_map_fd simply needs to have socket file
   descriptors inserted, one per each queue, with BPF_MAP_UPDATE_ELEM.

   This function will print a diagnostic error message and terminate the
   process if it fails, and will not return in failure cases. */

at_xdp_fds_t
at_xdp_install( uint           if_idx,
                uint           listen_ip4_addr,
                ulong          ports_cnt,
                ushort const * ports,
                char const *   xdp_mode );

AT_PROTOTYPES_END

#endif /* defined(__linux__) */

#endif /* HEADER_at_p2p_xdp_at_xdp1_h */
