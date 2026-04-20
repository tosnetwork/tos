#ifndef HEADER_at_waltz_p2p_at_p2p_txq_h
#define HEADER_at_waltz_p2p_at_p2p_txq_h

/* at_p2p_txq.h - Simple TX hash ring buffer */

#include "at/infra/at_util_base.h"

AT_PROTOTYPES_BEGIN

typedef struct {
  ulong head;
  ulong tail;
  ulong cap;
  uchar *buf; /* cap * 32 */
} at_p2p_txq_t;

int
at_p2p_txq_init( at_p2p_txq_t * q,
                 void *        mem,
                 ulong         cap );

int
at_p2p_txq_push( at_p2p_txq_t * q,
                 uchar const   hash[32] );

int
at_p2p_txq_push_blocking( at_p2p_txq_t * q,
                          uchar const   hash[32] );

int
at_p2p_txq_pop( at_p2p_txq_t * q,
                uchar         out[32] );

AT_PROTOTYPES_END

#endif /* HEADER_at_waltz_p2p_at_p2p_txq_h */
