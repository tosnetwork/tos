#ifndef HEADER_at_src_ballet_ripemd160_at_ripemd160_h
#define HEADER_at_src_ballet_ripemd160_at_ripemd160_h

/* at_ripemd160 provides RIPEMD-160 hashing (EVM precompile 0x03).

   Output is 32 bytes: 12 zero bytes (left-padding) followed by the
   20-byte RIPEMD-160 digest. This matches the EVM convention. */

#include "at_crypto_base.h"

AT_PROTOTYPES_BEGIN

/* at_ripemd160_hash computes RIPEMD-160 of the input data and writes
   a 32-byte left-padded result (12 zero bytes + 20-byte digest) to out32.
   Returns out32. */

void *
at_ripemd160_hash( void const * data,
                   ulong        data_sz,
                   void *       out32 );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_ballet_ripemd160_at_ripemd160_h */
