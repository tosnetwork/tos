#ifndef HEADER_at_crypto_at_tos_hash_v2_h
#define HEADER_at_crypto_at_tos_hash_v2_h

/* at_tos_hash_v2.h - TOS Hash V2 */

#include "at/infra/at_util_base.h"

AT_PROTOTYPES_BEGIN

#define AT_TOS_HASH_V2_HASH_SZ   (32UL)
#define AT_TOS_HASH_V2_MEM_WORDS (429UL * 128UL)

typedef struct {
  ulong words[AT_TOS_HASH_V2_MEM_WORDS];
} at_tos_hash_v2_scratch_t;

void
at_tos_hash_v2_scratch_init( at_tos_hash_v2_scratch_t * scratch );

int
at_tos_hash_v2_hash( uchar const *              input,
                     ulong                      input_sz,
                     uchar                      out_hash[AT_TOS_HASH_V2_HASH_SZ],
                     at_tos_hash_v2_scratch_t * scratch );

AT_PROTOTYPES_END

#endif /* HEADER_at_crypto_at_tos_hash_v2_h */
