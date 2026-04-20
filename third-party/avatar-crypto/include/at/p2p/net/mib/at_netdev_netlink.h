#ifndef HEADER_at_src_waltz_mib_at_netdev_netlink_h
#define HEADER_at_src_waltz_mib_at_netdev_netlink_h

/* at_netdev_netlink.h provides APIs for importing network interfaces from
   Linux netlink. */

#if defined(__linux__)

#include "at_netdev_tbl.h"
#include "../ip/at_netlink1.h"

AT_PROTOTYPES_BEGIN

int
at_netdev_netlink_load_table( at_netdev_tbl_join_t * tbl,
                              at_netlink_t *         netlink );

AT_PROTOTYPES_END

#endif /* defined(__linux__) */

#endif /* HEADER_at_src_waltz_mib_at_netdev_netlink_h */
