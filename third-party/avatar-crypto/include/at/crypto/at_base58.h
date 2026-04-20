#ifndef HEADER_at_src_ballet_base58_at_base58_h
#define HEADER_at_src_ballet_base58_at_base58_h

/* at_base58.h provides methods for converting between binary and
   base58. */

#include "at_crypto_base.h"

/* AT_BASE58_ENCODED_{32,64}_{LEN,SZ} give the maximum string length
   (LEN) and size (SZ, which includes the '\0') of the base58 cstrs that
   result from converting 32 or 64 bytes to base58. */

#define AT_BASE58_ENCODED_32_LEN (44UL)                         /* Computed as ceil(log_58(256^32 - 1)) */
#define AT_BASE58_ENCODED_64_LEN (88UL)                         /* Computed as ceil(log_58(256^64 - 1)) */
#define AT_BASE58_ENCODED_32_SZ  (AT_BASE58_ENCODED_32_LEN+1UL) /* Including the nul terminator */
#define AT_BASE58_ENCODED_64_SZ  (AT_BASE58_ENCODED_64_LEN+1UL) /* Including the nul terminator */

/* Maximum encoded length for N bytes: ceil(N * log(256) / log(58)) ≈ N * 1.37 + 1 */
#define AT_BASE58_ENCODED_MAX_LEN(n) (((n) * 138UL / 100UL) + 1UL)
#define AT_BASE58_ENCODED_MAX_SZ(n)  (AT_BASE58_ENCODED_MAX_LEN(n) + 1UL)

AT_PROTOTYPES_BEGIN

/* Macros for initializing a correctly sized out char
   array to encode into. */
#define AT_BASE58_ENCODE_32_BYTES( bytes, out )          \
   char out[ AT_BASE58_ENCODED_32_SZ ];                  \
   ulong out##_len;                                      \
   {                                                     \
     void const * b = (bytes);                           \
     if( AT_UNLIKELY( !b ) ) {                           \
       strcpy( out, "<NULL>" );                          \
       out##_len = 6UL;                                  \
     }                                                   \
     else at_base58_encode_32( bytes, &out##_len, out ); \
   }

#define AT_BASE58_ENCODE_64_BYTES( bytes, out )          \
   char out[ AT_BASE58_ENCODED_64_SZ ];                  \
   ulong out##_len;                                      \
   {                                                     \
     void const * b = (bytes);                           \
     if( AT_UNLIKELY( !b ) ) {                           \
       strcpy( out, "<NULL>" );                          \
       out##_len = 6UL;                                  \
     }                                                   \
     else at_base58_encode_64( bytes, &out##_len, out ); \
   }

/* at_base58_encode_{32, 64}: Interprets the supplied 32 or 64 bytes
   (respectively) as a large big-endian integer, and converts it to a
   nul-terminated base58 string of:

     32 to 44 characters, inclusive (not counting nul) for 32 B
     64 to 88 characters, inclusive (not counting nul) for 64 B

   Stores the output in the buffer pointed to by out.  If opt_len is
   non-NULL, *opt_len == at_strlen( out ) on return.  Returns out.  out is
   guaranteed to be nul terminated on return.

   Out must have enough space for AT_BASE58_ENCODED_{32,64}_SZ
   characters, including the nul terminator.

   The 32 byte conversion is suitable for printing account addresses,
   and the 64 byte conversion is suitable for printing transaction
   signatures.  This is high performance (~100ns for 32B and
   ~200ns for 64B without AVX, and roughly twice as fast with AVX), but
   base58 is an inherently slow format and should not be used in any
   performance critical places except where absolutely necessary. */

char * at_base58_encode_32( uchar const * bytes, ulong * opt_len, char * out );
char * at_base58_encode_64( uchar const * bytes, ulong * opt_len, char * out );

/* at_base58_decode_{32, 64}: Converts the base58 encoded number stored
   in the cstr `encoded` to a 32 or 64 byte number, which is written to
   out in big endian.  out must have room for 32 and 64 bytes respective
   on entry.  Returns out on success and NULL if the input string is
   invalid in some way: illegal base58 character or decodes to something
   other than 32 or 64 bytes (respectively).  The contents of out are
   undefined on failure (i.e. out may be clobbered).

   A similar note to the above applies: these are high performance
   (~120ns for 32 byte and ~300ns for 64 byte), but base58 is an
   inherently slow format and should not be used in any performance
   critical places except where absolutely necessary. */

uchar * at_base58_decode_32( char const * encoded, uchar * out );
uchar * at_base58_decode_64( char const * encoded, uchar * out );

/* at_base58_encode: General-purpose encoder for arbitrary length input.
   Converts bytes_sz bytes to base58.  The output buffer must have room
   for at least AT_BASE58_ENCODED_MAX_SZ(bytes_sz) characters including
   the nul terminator.  If opt_len is non-NULL, *opt_len == at_strlen(out)
   on return.  Returns out.

   This is slower than at_base58_encode_{32,64} for those specific sizes,
   so prefer those when applicable.  This uses the standard "divide by 58"
   algorithm with O(n^2) complexity. */

char * at_base58_encode( uchar const * bytes,
                         ulong         bytes_sz,
                         ulong       * opt_len,
                         char        * out );

/* at_base58_decode: General-purpose decoder for arbitrary length output.
   Converts a base58 string to binary.  out must have room for out_sz
   bytes.  Returns out on success, or NULL if the input is invalid or
   decodes to a different size than out_sz.

   This is slower than at_base58_decode_{32,64} for those specific sizes. */

uchar * at_base58_decode( char const * encoded,
                          uchar      * out,
                          ulong        out_sz );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_ballet_base58_at_base58_h */