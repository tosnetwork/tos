#ifndef HEADER_at_src_waltz_ip_at_fib4_h
#define HEADER_at_src_waltz_ip_at_fib4_h

/* A fib4 stores IPv4 routes in a query-optimized data structure.

   fib4 does not scale well to large numbers of routes.  Every route
   lookup is O(n) where n is the number of routes in the FIB.

   fib4 only supports a minimal set of features required for end devices
   to operate.  Packet forwarding is not supported.

   fib4 supports multi-threaded operation in a x86-TSO like environment.
   (many reader threads, one writer thread) */

#include "at/infra/at_util_base.h"

#define AT_FIB4_ALIGN (128UL)

/* AT_FIB4_RTYPE_{...} enumerate route types.
   These match Linux RTN_UNICAST, etc. */

#define AT_FIB4_RTYPE_UNSPEC    (0) /* invalid */
#define AT_FIB4_RTYPE_UNICAST   (1) /* "normal" path */
#define AT_FIB4_RTYPE_LOCAL     (2) /* address on local host */
#define AT_FIB4_RTYPE_BROADCAST (3) /* reserved for future use */
#define AT_FIB4_RTYPE_MULTICAST (5) /* reserved for future use */
#define AT_FIB4_RTYPE_BLACKHOLE (6) /* drop packet */
#define AT_FIB4_RTYPE_THROW     (9) /* continue in next table */

/* at_fib4_t is a local handle to a fib4 object. */

struct at_fib4_priv;
typedef struct at_fib4_priv at_fib4_priv_t;

struct at_fib4 {
   at_fib4_priv_t * priv;
   uchar            hmap_join[64] __attribute__((aligned(8)));
};
typedef struct at_fib4 at_fib4_t;

/* at_fib4_hop_t holds a FIB lookup result */

struct __attribute__((aligned(16))) at_fib4_hop {
  uint  ip4_gw;   /* gateway address (big endian) */
  uint  if_idx;   /* output interface index */
  uint  ip4_src;  /* override source address (big endian). 0 implies unset */
  uchar rtype;    /* route type (e.g. AT_FIB4_RTYPE_UNICAST) */
  uchar scope;    /* used to select source address */
  uchar flags;    /* app-specific flags */
};

#define AT_FIB4_FLAG_RTA_UNSUPPORTED   ((uchar)0x01U) /* unsupported route attribute */
#define AT_FIB4_FLAG_RTA_PARSE_ERR     ((uchar)0x02U) /* failed to interpret route attribute */
#define AT_FIB4_FLAG_RTYPE_UNSUPPORTED ((uchar)0x03U) /* unsupported route type */

typedef struct at_fib4_hop at_fib4_hop_t;

AT_PROTOTYPES_BEGIN

/* Constructor APIs */

AT_FN_CONST ulong
at_fib4_align( void );

AT_FN_CONST ulong
at_fib4_footprint( ulong route_max,
                   ulong route_peer_max );

/* at_fib4_new formats a shared memory region mem with alignment and footprint
   suitable for a fib4. */

void *
at_fib4_new( void * mem,
             ulong  route_max,
             ulong  route_peer_max,
             ulong  route_peer_seed );

/* at_fib4_join joins the caller to a shared memory region shmem holding a fib4. */

at_fib4_t *
at_fib4_join( at_fib4_t * fib4,
              void *      shmem );

void *
at_fib4_leave( at_fib4_t * fib4 );

void *
at_fib4_delete( void * mem );

/* Write APIs */

/* at_fib4_clear removes all route table entries but the first. */

void
at_fib4_clear( at_fib4_t * fib );

/* at_fib4_insert attempts to add a new route entry to the FIB routing table.
   Returns 1 on success, 0 if the internal data structures are full. */

int
at_fib4_insert( at_fib4_t *     fib,
                uint            ip4_dst,
                int             prefix,
                uint            prio,
                at_fib4_hop_t * hop );

/* Read APIs */

/* at_fib4_lookup resolves the next hop for an arbitrary IPv4 address.
   If route was not found, retval.rtype is set to AT_FIB4_RTYPE_THROW.

   Thread safe: Multiple threads can use the read API concurrently. */

at_fib4_hop_t
at_fib4_lookup( at_fib4_t const * fib,
                uint              ip4_dst,
                ulong             flags );

/* at_fib4_hop_or is a helper to chain together multiple FIB lookups. */

AT_FN_PURE static inline at_fib4_hop_t const *
at_fib4_hop_or( at_fib4_hop_t const * left,
                at_fib4_hop_t const * right ) {
  return left->rtype!=AT_FIB4_RTYPE_THROW ? left : right;
}

/* at_fib4_max returns the max number of routes in the table. */

AT_FN_PURE ulong
at_fib4_max( at_fib4_t const * fib );

/* at_fib4_peer_max returns the max number of /32 routes (backed by a hashmap). */

AT_FN_PURE ulong
at_fib4_peer_max( at_fib4_t const * fib );

/* at_fib4_cnt returns the total number of routes stored in the fib4. */

AT_FN_PURE ulong
at_fib4_cnt( at_fib4_t const * fib );

#if AT_HAS_HOSTED

/* at_fib4_fprintf prints the routing table to the given FILE * pointer. */

int
at_fib4_fprintf( at_fib4_t const * fib,
                 void *            file );

#endif

AT_PROTOTYPES_END

#endif /* HEADER_at_src_waltz_ip_at_fib4_h */