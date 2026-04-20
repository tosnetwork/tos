#ifndef HEADER_at_src_ballet_blake2b_at_blake2b_h
#define HEADER_at_src_ballet_blake2b_at_blake2b_h

/* at_blake2b provides the BLAKE2b-F compression function (EIP-152 / EVM precompile 0x09).

   This implements only the F compression function, not the full BLAKE2b hash.
   Input format (213 bytes per EIP-152):
     rounds [4 bytes BE] : number of compression rounds
     h      [64 bytes]   : state vector (8 x uint64 LE)
     m      [128 bytes]  : message block (16 x uint64 LE)
     t      [16 bytes]   : offset counters (2 x uint64 LE)
     f      [1 byte]     : final block flag (0 or 1)

   Output: 64 bytes (updated state vector h, as 8 x uint64 LE). */

#include "at_crypto_base.h"

AT_PROTOTYPES_BEGIN

/* at_blake2b_compress executes the BLAKE2b-F compression function.

   h_out  : output buffer, 64 bytes (8 x uint64 LE)
   rounds : number of compression rounds
   h      : input state vector, 64 bytes (8 x uint64 LE)
   m      : message block, 128 bytes (16 x uint64 LE)
   t0, t1 : 64-bit offset counters
   f      : final block flag (0 or 1) */

void
at_blake2b_compress( uchar *       h_out,
                     uint          rounds,
                     uchar const * h,
                     uchar const * m,
                     ulong         t0,
                     ulong         t1,
                     uchar         f );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_ballet_blake2b_at_blake2b_h */
