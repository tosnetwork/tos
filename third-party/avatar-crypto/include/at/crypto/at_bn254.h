#ifndef HEADER_at_src_ballet_bn254_at_bn254_h
#define HEADER_at_src_ballet_bn254_at_bn254_h

/* at_bn254 implements utility functions for the bn254 (alt_bn128) curve. */

#include "at_crypto_base.h"
#include "at/infra/uint256/at_uint256.h"
#include "./at_bn254_scalar.h"

#define AT_BN254_PAIRING_BATCH_MAX 16UL
#define AT_BIG_ENDIAN_LIKELY AT_LIKELY

AT_PROTOTYPES_BEGIN

int
at_bn254_g1_add_syscall( uchar       out[64],
                         uchar const in[],
                         ulong       in_sz,
                         int         big_endian );

int
at_bn254_g1_scalar_mul_syscall( uchar       out[64],
                                uchar const in[],
                                ulong       in_sz,
                                int         big_endian );

int
at_bn254_g2_add_syscall( uchar       out[128],
                         uchar const in[],
                         ulong       in_sz,
                         int         big_endian );

int
at_bn254_g2_scalar_mul_syscall( uchar       out[128],
                                uchar const in[],
                                ulong       in_sz,
                                int         big_endian );

int
at_bn254_pairing_is_one_syscall( uchar       out[32],
                                 uchar const in[],
                                 ulong       in_sz,
                                 int         big_endian,
                                 int         check_len );

/* at_bn254_g1_compress compresses a point in G1.
   Input in is a 64-byte big endian buffer representing the point (x, y),
   with additional flags.
   Output out will contain x, serialized as 32-byte big endian buffer,
   with proper flags set.
   Returns out on success, NULL on failure.
   Note: this function does NOT check that (x, y) is in G1. */
uchar *
at_bn254_g1_compress( uchar       out[32],
                      uchar const in [64],
                      int         big_endian );

/* at_bn254_g1_decompress decompresses a point in G1.
   Input in is a 32-byte big endian buffer representing the x coord of a point,
   with additional flags.
   Output out will contain (x, y), serialized as 64-byte big endian buffer,
   with no flags set.
   Returns out on success, NULL on failure.
   (Success implies that (x, y) is in G1.) */
uchar *
at_bn254_g1_decompress( uchar       out[64],
                        uchar const in [32],
                        int         big_endian );

/* at_bn254_g2_compress compresses a point in G2.
   Same as at_bn254_g1_compress, but x, y are in Fp2, so twice as long.
   Input in is a 128-byte big endian buffer representing the point (x, y),
   with additional flags.
   Output out will contain x, serialized as 64-byte big endian buffer,
   with proper flags set.
   Returns out on success, NULL on failure.
   Note: this function does NOT check that (x, y) is in G2. */
uchar *
at_bn254_g2_compress( uchar       out[64],
                      uchar const in[128],
                      int         big_endian );

/* at_bn254_g2_decompress decompresses a point in G2.
   Same as at_bn254_g1_decompress, but x, y are in Fp2, so twice as long.
   Input in is a 64-byte big endian buffer representing the x coord of a point,
   with additional flags.
   Output out will contain (x, y), serialized as 128-byte big endian buffer,
   with no flags set.
   Returns out on success, NULL on failure.
   Note: this function does NOT check that (x, y) is in G2 (success does NOT
   imply that). */
uchar *
at_bn254_g2_decompress( uchar       out[128],
                        uchar const in  [64],
                        int         big_endian );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_ballet_bn254_at_bn254_h */