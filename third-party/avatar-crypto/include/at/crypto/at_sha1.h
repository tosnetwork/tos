#ifndef HEADER_at_src_crypto_sha1_at_sha1_h
#define HEADER_at_src_crypto_sha1_at_sha1_h

/* at_sha1 provides SHA1 hashing for WebSocket handshake.

   IMPORTANT: SHA1 is cryptographically broken and should NOT be used for
   security-critical operations. This implementation is ONLY for WebSocket
   protocol compliance (RFC 6455 mandates SHA1 for handshake).

   Usage:
     uchar hash[20];
     at_sha1_hash(data, data_len, hash);
*/

#include "at_crypto_base.h"

AT_PROTOTYPES_BEGIN

/* at_sha1_hash computes SHA1 hash of input data.

   data points to input bytes (arbitrary length, can be NULL if data_len==0).
   data_len is the number of bytes to hash.
   out points to output buffer (must be at least 20 bytes).

   This is a stateless one-shot hash function. */

void
at_sha1_hash( uchar const * data,
              ulong         data_len,
              uchar         out[ 20 ] );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_crypto_sha1_at_sha1_h */
