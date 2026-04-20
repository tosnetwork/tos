#ifndef HEADER_at_src_ballet_hmac_at_hmac_h
#define HEADER_at_src_ballet_hmac_at_hmac_h

/* at_hmac provides APIs for HMAC,
   a mechanism for message authentication. */

#include "at_crypto_base.h"

typedef void *
(* at_hmac_fn_t)( void const * data,
                  ulong        data_sz,
                  void const * key,
                  ulong        key_sz,
                  void *       hash );

AT_PROTOTYPES_BEGIN

/* at_hmac_sha256 computes the HMAC-SHA256 digest given a key and a
   message.  key points to the first byte of the key byte array of size
   key_sz.  data points to the first byte of the message byte array of
   size data_sz.  Stores the digest into hash (a memory region of 32
   bytes) and returns hash. */

void *
at_hmac_sha256( void const * data,
                ulong        data_sz,
                void const * key,
                ulong        key_sz,
                void *       hash );

void *
at_hmac_sha384( void const * data,
                ulong        data_sz,
                void const * key,
                ulong        key_sz,
                void *       hash );

void *
at_hmac_sha512( void const * data,
                ulong        data_sz,
                void const * key,
                ulong        key_sz,
                void *       hash );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_ballet_hmac_at_hmac_h */