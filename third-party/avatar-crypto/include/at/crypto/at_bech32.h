#ifndef HEADER_at_src_ballet_bech32_at_bech32_h
#define HEADER_at_src_ballet_bech32_at_bech32_h

/* at_bech32.h provides Bech32 encoding/decoding for TOS addresses.

   Bech32 is a checksummed base32 encoding format used for TOS addresses:
   - Mainnet prefix: "tos"
   - Testnet prefix: "tst"

   Address format: <hrp>1<data><checksum>
   Example: tos1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw

   Reference: BIP-173 (https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki)
*/

#include "at_crypto_base.h"

/* Bech32 constants */
#define AT_BECH32_CHARSET       "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
#define AT_BECH32_CHARSET_LEN   (32)
#define AT_BECH32_CHECKSUM_LEN  (6)
#define AT_BECH32_SEPARATOR     '1'

/* TOS address prefixes */
#define AT_BECH32_TOS_MAINNET   "tos"
#define AT_BECH32_TOS_TESTNET   "tst"

/* Error codes */
#define AT_BECH32_OK                    (0)
#define AT_BECH32_ERR_HRP_EMPTY         (-1)
#define AT_BECH32_ERR_HRP_INVALID_CHAR  (-2)
#define AT_BECH32_ERR_HRP_MIX_CASE      (-3)
#define AT_BECH32_ERR_DATA_INVALID      (-4)
#define AT_BECH32_ERR_SEPARATOR_MISSING (-5)
#define AT_BECH32_ERR_SEPARATOR_POS     (-6)
#define AT_BECH32_ERR_CHECKSUM_INVALID  (-7)
#define AT_BECH32_ERR_BUFFER_TOO_SMALL  (-8)
#define AT_BECH32_ERR_PADDING_INVALID   (-9)

AT_PROTOTYPES_BEGIN

/* at_bech32_encode encodes data into a Bech32 string.

   hrp: human-readable part (e.g., "tos" or "tst")
   data: raw bytes to encode (will be converted from 8-bit to 5-bit)
   data_sz: size of data in bytes
   out: buffer to receive the encoded string (null-terminated)
   out_sz: size of output buffer

   Returns the length of the encoded string (excluding null terminator),
   or a negative error code on failure.

   Required output buffer size: hrp_len + 1 + ceil(data_sz * 8 / 5) + 6 + 1 */

int
at_bech32_encode( char *       out,
                  ulong        out_sz,
                  char const * hrp,
                  uchar const * data,
                  ulong        data_sz );

/* at_bech32_decode decodes a Bech32 string into raw bytes.

   bech: null-terminated Bech32 string to decode
   hrp_out: buffer to receive the human-readable part (null-terminated)
   hrp_out_sz: size of hrp_out buffer
   data_out: buffer to receive the decoded data (converted from 5-bit to 8-bit)
   data_out_sz: pointer to size of data_out buffer; on return, set to actual data size

   Returns AT_BECH32_OK on success, or a negative error code on failure. */

int
at_bech32_decode( char const * bech,
                  char *       hrp_out,
                  ulong        hrp_out_sz,
                  uchar *      data_out,
                  ulong *      data_out_sz );

/* at_bech32_verify_checksum verifies the checksum of a Bech32 string.

   bech: null-terminated Bech32 string

   Returns 1 if checksum is valid, 0 if invalid. */

int
at_bech32_verify_checksum( char const * bech );

/* at_bech32_convert_bits converts data between different bit widths.

   out: output buffer
   out_sz: pointer to output buffer size; on return, set to actual output size
   to_bits: target bit width (e.g., 5)
   in: input data
   in_sz: input data size
   from_bits: source bit width (e.g., 8)
   pad: if non-zero, add padding bits to complete final group

   Returns AT_BECH32_OK on success, or a negative error code on failure.

   Common usage:
   - Encoding (8->5): at_bech32_convert_bits(out, &out_sz, 5, data, data_sz, 8, 1)
   - Decoding (5->8): at_bech32_convert_bits(out, &out_sz, 8, data, data_sz, 5, 0) */

int
at_bech32_convert_bits( uchar *       out,
                        ulong *       out_sz,
                        int           to_bits,
                        uchar const * in,
                        ulong         in_sz,
                        int           from_bits,
                        int           pad );

/* at_bech32_address_encode encodes a TOS address from a public key.

   This is a convenience function that:
   1. Prepends the address type byte
   2. Converts from 8-bit to 5-bit
   3. Adds the appropriate prefix and checksum

   mainnet: if non-zero, use "tos" prefix; otherwise use "tst"
   public_key: 32-byte compressed Ristretto public key
   out: buffer to receive the encoded address (null-terminated)
   out_sz: size of output buffer (minimum 64 bytes recommended)

   Returns the length of the encoded address, or negative error code. */

int
at_bech32_address_encode( char *       out,
                          ulong        out_sz,
                          int          mainnet,
                          uchar const  public_key[ 32 ] );

/* at_bech32_address_decode decodes a TOS address to a public key.

   address: null-terminated Bech32 address string
   mainnet: pointer to receive network flag (1=mainnet, 0=testnet)
   public_key: buffer to receive the 32-byte public key

   Returns AT_BECH32_OK on success, or negative error code. */

int
at_bech32_address_decode( char const * address,
                          int *        mainnet,
                          uchar        public_key[ 32 ] );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_ballet_bech32_at_bech32_h */