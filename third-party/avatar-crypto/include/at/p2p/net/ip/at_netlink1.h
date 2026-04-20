#ifndef HEADER_at_src_waltz_ip_at_netlink1_h
#define HEADER_at_src_waltz_ip_at_netlink1_h

#if defined(__linux__)

#include "at/infra/at_util_base.h"

struct at_netlink {
  int   fd;   /* netlink socket */
  uint  seq;  /* netlink sequence number */
};

typedef struct at_netlink at_netlink_t;

/* FIXME this should be a 'buffered reader' style API not an iterator since
   iterators are infallible by definition in Reference style. */

struct at_netlink_iter {
  uchar * buf;
  ulong   buf_sz;
  uchar * msg0;
  uchar * msg1;
  int     err;
};

typedef struct at_netlink_iter at_netlink_iter_t;

struct nlmsghdr; /* forward declaration */

AT_PROTOTYPES_BEGIN

/* at_netlink_enobufs_cnt counts the number of ENOBUFS error occurrences. */

extern AT_TL ulong at_netlink_enobufs_cnt;

/* at_netlink_init creates a new netlink session.  Creates a new netlink
   socket with explicit ACKs.  seq0 is the initial sequence number. */

at_netlink_t *
at_netlink_init( at_netlink_t * netlink,
                 uint           seq0 );

/* at_netlink_fini closes the netlink socket. */

void *
at_netlink_fini( at_netlink_t * netlink );

/* at_netlink_read_socket wraps recvfrom(fd,buf,buf_sz,0,0,0) but
   automatically skips EINTR and ENOBUFS errors. */

long
at_netlink_read_socket( int     fd,
                        uchar * buf,
                        ulong   buf_sz );

/* at_netlink_iter_init prepares iteration over a sequence of incoming
   netlink multipart messages. */

at_netlink_iter_t *
at_netlink_iter_init( at_netlink_iter_t * iter,
                      at_netlink_t *      netlink,
                      uchar *             buf,
                      ulong               buf_sz );

/* at_netlink_iter_done returns 0 if there are more netlink messages to
   iterate over or 1 if not. */

int
at_netlink_iter_done( at_netlink_iter_t const * iter );

/* at_netlink_iter_next advances the iterator to the next netlink message
   (if any).  Assumes !at_netlink_iter_done(iter).  Invalidates pointers
   previously returned by at_netlink_iter_msg(iter). */

at_netlink_iter_t *
at_netlink_iter_next( at_netlink_iter_t * iter,
                      at_netlink_t *      netlink );

/* at_netlink_iter_msg returns a pointer to the current netlink message
   header.  Assumes !at_netlink_iter_done(iter). */

static inline struct nlmsghdr const *
at_netlink_iter_msg( at_netlink_iter_t const * iter ) {
  return at_type_pun_const( iter->msg0 );
}

static AT_FN_UNUSED ulong
at_netlink_iter_drain( at_netlink_iter_t * iter,
                       at_netlink_t *      netlink ) {
  ulong cnt;
  for( cnt=0UL; !at_netlink_iter_done( iter ); cnt++ ) {
    at_netlink_iter_next( iter, netlink );
  }
  return cnt;
}

/* Debug utils */

char const *
at_netlink_rtm_type_str( int rtm_type );

char const *
at_netlink_rtattr_str( int rta_type );

AT_PROTOTYPES_END

#endif /* defined(__linux__) */

#endif /* HEADER_at_src_waltz_ip_at_netlink1_h */
