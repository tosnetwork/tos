#ifndef HEADER_at_src_ballet_secp256k1_at_secp256k1_h
#define HEADER_at_src_ballet_secp256k1_at_secp256k1_h

/* at_secp256k1 provides APIs for secp256K1 signature computations. Currently this library wraps
   libsecp256k1. */

#include "at_crypto_base.h"

AT_PROTOTYPES_BEGIN

/* at_secp256k1_recover recovers a public key from a recoverable SECP256K1 signature.

   msg_hash is assumed to point to the first byte of a 32-byte memory region
   which holds the message to verify.

   sig is assumed to point to the first byte of a 64-byte memory region
   which holds the recoverable signature of the message.

   public_key is assumed to point to first byte of a 64-byte memory
   region that will hold public key recovered from the signature.

   recovery_id is the recovery id number used in the signing process.

   Does no input argument checking.  This function takes a write
   interest in public_key and a read interest in msg_hash, public_key and
   private_key for the duration the call.  Returns public_key on success and
   NULL on failure. */

void *
at_secp256k1_recover( void *       public_key,
                      void const * msg_hash,
                      void const * sig,
                      int          recovery_id );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_ballet_secp256k1_at_secp256k1_h */