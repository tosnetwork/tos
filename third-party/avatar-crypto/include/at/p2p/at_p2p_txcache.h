#ifndef HEADER_at_waltz_p2p_at_p2p_txcache_h
#define HEADER_at_waltz_p2p_at_p2p_txcache_h

/* at_p2p_txcache.h - Simple TX hash cache */

#include "at/infra/at_util_base.h"

AT_PROTOTYPES_BEGIN

typedef struct {
  ulong  head;
  ulong  cnt;
  ulong  cap;
  uchar *buf; /* cap * 32 */
} at_p2p_txcache_t;

void
at_p2p_txcache_init( at_p2p_txcache_t * cache,
                     void *            mem,
                     ulong             cap );

int
at_p2p_txcache_has( at_p2p_txcache_t const * cache,
                    uchar const             hash[32] );

void
at_p2p_txcache_add( at_p2p_txcache_t * cache,
                    uchar const        hash[32] );

ushort
at_p2p_txcache_copy_page( at_p2p_txcache_t const * cache,
                          ulong                    skip,
                          uchar                    out[][32],
                          ushort                   max_out );

AT_PROTOTYPES_END

#endif /* HEADER_at_waltz_p2p_at_p2p_txcache_h */
