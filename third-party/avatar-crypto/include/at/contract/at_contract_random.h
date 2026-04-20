#ifndef HEADER_at_contract_at_contract_random_h
#define HEADER_at_contract_at_contract_random_h

#include "at/contract/at_contract_base.h"

AT_PROTOTYPES_BEGIN

/* Deterministic random stream compatible with
   tos/common/src/contract/random.rs intent:
   seed = blake3(contract || block || transaction), then expand. */
typedef struct {
  uchar seed[32];
  ulong counter;
  ulong emitted;
} at_contract_deterministic_random_t;

void
at_contract_random_init( at_contract_deterministic_random_t * rng,
                         uchar const contract[32],
                         uchar const block[32],
                         uchar const transaction[32] );

int
at_contract_random_fill( at_contract_deterministic_random_t * rng,
                         uchar *                              out,
                         ulong                                out_sz );

AT_PROTOTYPES_END

#endif /* HEADER_at_contract_at_contract_random_h */
