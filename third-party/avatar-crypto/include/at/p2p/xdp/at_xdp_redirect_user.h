#ifndef HEADER_at_waltz_xdp_at_xdp_redirect_user_h
#define HEADER_at_waltz_xdp_at_xdp_redirect_user_h

/* at_xdp_redirect_user.h - XDP redirect program management */

#include "at_xsk.h"
#include "at/infra/at_util_base.h"

AT_PROTOTYPES_BEGIN

/* at_xsk_activate installs an XSK file descriptor into the XDP redirect
   program's XSKMAP for the network device with name at_xsk_ifname(xsk)
   at key at_xsk_ifqueue(xsk). If another XSK is already installed at
   this key, it will be silently replaced.  The given xsk must be a
   valid local join to at_xsk_t.  When packets arrive on the netdev RX
   queue that the XSK is bound to, and the XDP program takes action
   XDP_REDIRECT, causes these packets to be written to the XSK RX queue.
   Similarly, packets written to the XSK's TX ring get sent to the
   corresponding netdev TX queue.  Such writes may get lost on
   congestion.  Returns xsk on success.  On error, logs reason to
   warning log and returns NULL. */

at_xsk_t *
at_xsk_activate( at_xsk_t * xsk,
                 int        xsk_map_fd );

/* at_xsk_deactivate uninstalls an XSK file descriptor from the XDP
   redirect program's XSKMAP.  XSK will cease to receive traffic.
   Returns xsk on success or if no redirect program installation was
   found.  On error, logs reason to warning log and returns NULL. */

at_xsk_t *
at_xsk_deactivate( at_xsk_t * xsk,
                   int        xsk_map_fd );

AT_PROTOTYPES_END

#endif /* HEADER_at_waltz_xdp_at_xdp_redirect_user_h */