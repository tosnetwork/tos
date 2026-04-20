#ifndef HEADER_at_src_ballet_secp256r1_at_secp256r1_h
#define HEADER_at_src_ballet_secp256r1_at_secp256r1_h

/* at_secp256r1 provides APIs for secp256r1 signature verification. */

#include "at_crypto_base.h"
#include "at_sha256.h"

#define AT_SECP256R1_SUCCESS 1
#define AT_SECP256R1_FAILURE 0

AT_PROTOTYPES_BEGIN

/* at_secp256r1_verify verifies a SECP256r1 signature. */
int
at_secp256r1_verify( uchar const   msg[], /* msg_sz */
                     ulong         msg_sz,
                     uchar const   sig[ 64 ],
                     uchar const   public_key[ 33 ],
                     at_sha256_t * sha );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_ballet_secp256r1_at_secp256r1_h */