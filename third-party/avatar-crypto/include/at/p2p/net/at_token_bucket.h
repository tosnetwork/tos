#ifndef HEADER_at_src_waltz_at_token_bucket_h
#define HEADER_at_src_waltz_at_token_bucket_h

#include "at/infra/at_util_base.h"
#include <math.h>

struct at_token_bucket {
  long  ts;
  float rate;
  float burst;
  float balance;
};

typedef struct at_token_bucket at_token_bucket_t;

AT_PROTOTYPES_BEGIN

static inline int
at_token_bucket_consume( at_token_bucket_t * bucket,
                         float               delta,
                         long                ts ) {
  /* Refill bucket */
  long  elapsed = ts - bucket->ts;
  float balance = bucket->balance + ((float)elapsed * bucket->rate);
  balance = fminf( balance, bucket->burst );

  /* Consume tokens */
  int ok = delta <= balance;
  balance -= (float)ok * delta;

  /* Store bucket */
  bucket->balance = balance;
  bucket->ts      = ts;
  return ok;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_src_waltz_at_token_bucket_h */
