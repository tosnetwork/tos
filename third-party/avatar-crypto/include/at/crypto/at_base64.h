#ifndef HEADER_at_src_crypto_base64_at_base64_h
#define HEADER_at_src_crypto_base64_at_base64_h

/* at_base64 provides Base64 encoding for WebSocket handshake.

   This implements RFC 4648 standard Base64 encoding (NOT base64url variant).

   Usage:
     char encoded[256];
     ulong encoded_len = at_base64_encode(data, data_len, encoded, sizeof(encoded));
*/

#include "at_crypto_base.h"

AT_PROTOTYPES_BEGIN

/* at_base64_encode encodes input bytes to Base64 string.

   in points to input bytes to encode.
   in_len is the number of bytes to encode.
   out points to output buffer for Base64 string (no null terminator added).
   out_sz is the size of output buffer.

   Returns the number of Base64 characters written to out.
   Returns 0 if out_sz is too small.

   Required output size: ((in_len + 2) / 3) * 4 bytes
   Example: 20 bytes → 28 Base64 characters (for WebSocket accept key) */

ulong
at_base64_encode( uchar const * in,
                  ulong         in_len,
                  char *        out,
                  ulong         out_sz );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_crypto_base64_at_base64_h */
