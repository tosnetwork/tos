#ifndef HEADER_at_crypto_at_tos_hash_v3_h
#define HEADER_at_crypto_at_tos_hash_v3_h

/* at_tos_hash_v3.h - TOS Hash V3 (GPU/ASIC friendly) */

#include "at/infra/at_util_base.h"

AT_PROTOTYPES_BEGIN

#define AT_TOS_HASH_V3_HASH_SZ      (32UL)
#define AT_TOS_HASH_V3_MEM_WORDS    (8192UL)  /* 64KB scratchpad */
#define AT_TOS_HASH_V3_MIX_ROUNDS   (8UL)
#define AT_TOS_HASH_V3_MEM_PASSES   (4UL)

typedef struct {
  ulong words[AT_TOS_HASH_V3_MEM_WORDS];
} at_tos_hash_v3_scratch_t;

void
at_tos_hash_v3_scratch_init( at_tos_hash_v3_scratch_t * scratch );

int
at_tos_hash_v3_hash( uchar const *             input,
                     ulong                     input_sz,
                     uchar                     out_hash[AT_TOS_HASH_V3_HASH_SZ],
                     at_tos_hash_v3_scratch_t * scratch );

AT_PROTOTYPES_END

#endif /* HEADER_at_crypto_at_tos_hash_v3_h */
