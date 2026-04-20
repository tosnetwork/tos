#ifndef HEADER_at_crypto_at_tos_hash_v1_h
#define HEADER_at_crypto_at_tos_hash_v1_h

/* at_tos_hash_v1.h - TOS Hash V1 */

#include "at/infra/at_util_base.h"

AT_PROTOTYPES_BEGIN

#define AT_TOS_HASH_V1_HASH_SZ    (32UL)
#define AT_TOS_HASH_V1_INPUT_SZ   (200UL)
#define AT_TOS_HASH_V1_MEM_WORDS  (32768UL)

typedef struct {
  ulong words[AT_TOS_HASH_V1_MEM_WORDS];
} at_tos_hash_v1_scratch_t;

void
at_tos_hash_v1_scratch_init( at_tos_hash_v1_scratch_t * scratch );

int
at_tos_hash_v1_hash( uchar const *              input,
                     ulong                      input_sz,
                     uchar                      out_hash[AT_TOS_HASH_V1_HASH_SZ],
                     at_tos_hash_v1_scratch_t * scratch );

AT_PROTOTYPES_END

#endif /* HEADER_at_crypto_at_tos_hash_v1_h */
