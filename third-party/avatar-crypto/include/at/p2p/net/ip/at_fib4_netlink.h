#ifndef HEADER_at_src_waltz_ip_at_fib4_netlink_h
#define HEADER_at_src_waltz_ip_at_fib4_netlink_h

/* at_fib4_netlink.h provides APIs for importing routes from Linux netlink. */

#if defined(__linux__)

#include "at_fib4.h"
#include "at_netlink1.h"

/* AT_FIB_NETLINK_* gives error codes for netlink import operations. */

#define AT_FIB_NETLINK_SUCCESS   (0) /* success */
#define AT_FIB_NETLINK_ERR_OOPS  (1) /* unexpected internal error */
#define AT_FIB_NETLINK_ERR_IO    (2) /* netlink I/O error */
#define AT_FIB_NETLINK_ERR_INTR  (3) /* netlink read was interrupted */
#define AT_FIB_NETLINK_ERR_SPACE (4) /* fib is too small */

AT_PROTOTYPES_BEGIN

/* at_fib4_netlink_load_table mirrors a route table from netlink to fib.
   The route table is requested via RTM_GETROUTE,NLM_F_REQUEST|NLM_F_DUMP.
   table_id is in [0,2^31).  table_id is typically RT_TABLE_LOCAL or
   RT_TABLE_MAIN.  These are 255 and 254 respectively on Linux.  Assumes
   netlink has a usable rtnetlink socket.  fib is a writable join to a fib4
   object.  Logs to debug level for diagnostics and warning level in case
   of error.

   Returns AT_FIB4_NETLINK_SUCCESS on success and leaves netlink ready
   for the next request.  fib is not guaranteed to mirror the route
   table precisely even on success.  (May turn routes with unsupported
   type or attribute into blackhole routes.)

   On failure, leaves a route table that blackholes all packets.
   Return values AT_FIB4_NETLINK_ERR_{...} in case of error as follows:

     OOPS:  Internal error (bug) occurred.
     IO:    Unrecoverable send/recv error or failed to parse MULTIPART msg.
     INTR:  Concurrent write overran read of the routing table.  Try again.
     SPACE: Routing table is too small to mirror the requested table.

   On return, the netlink socket is ready for the next request (even in
   case of error) unless the error is AT_FIB_NETLINK_ERR_IO. */

int
at_fib4_netlink_load_table( at_fib4_t *    fib,
                            at_netlink_t * netlink,
                            uint           table_id );

AT_FN_CONST char const *
at_fib4_netlink_strerror( int err );

AT_PROTOTYPES_END

#endif /* defined(__linux__) */

#endif /* HEADER_at_src_waltz_ip_at_fib4_netlink_h */
