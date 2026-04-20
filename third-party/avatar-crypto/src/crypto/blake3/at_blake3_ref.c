#include "at_blake3_private.h"
#include "at/infra/at_util.h"

static inline void
g( uint * state,
   ulong  a,
   ulong  b,
   ulong  c,
   ulong  d,
   uint   x,
   uint   y ) {

  state[a] = state[a] + state[b] + x;
  state[d] = at_uint_rotate_right( state[d] ^ state[a], 16 );
  state[c] = state[c] + state[d];
  state[b] = at_uint_rotate_right( state[b] ^ state[c], 12 );
  state[a] = state[a] + state[b] + y;
  state[d] = at_uint_rotate_right( state[d] ^ state[a],  8 );
  state[c] = state[c] + state[d];
  state[b] = at_uint_rotate_right( state[b] ^ state[c],  7 );

}

static inline void
round_fn( uint         state[ static 16 ],
          uint const * msg,
          ulong        round ) {
  /* Select the message schedule based on the round */
  uchar const * schedule = AT_BLAKE3_MSG_SCHEDULE[round];

  /* Mix the columns */
  g( state,  0,  4,  8, 12, msg[ schedule[ 0] ], msg[ schedule[ 1] ] );
  g( state,  1,  5,  9, 13, msg[ schedule[ 2] ], msg[ schedule[ 3] ] );
  g( state,  2,  6, 10, 14, msg[ schedule[ 4] ], msg[ schedule[ 5] ] );
  g( state,  3,  7, 11, 15, msg[ schedule[ 6] ], msg[ schedule[ 7] ] );

  /* Mix the rows */
  g( state,  0,  5, 10, 15, msg[ schedule[ 8] ], msg[ schedule[ 9] ] );
  g( state,  1,  6, 11, 12, msg[ schedule[10] ], msg[ schedule[11] ] );
  g( state,  2,  7,  8, 13, msg[ schedule[12] ], msg[ schedule[13] ] );
  g( state,  3,  4,  9, 14, msg[ schedule[14] ], msg[ schedule[15] ] );
}

static inline void
compress_pre( uint        state[ static 16 ],
              uint const  cv   [ static  8 ],
              uchar const block[ AT_BLAKE3_BLOCK_SZ ],
              uint        block_len,
              ulong       counter,
              uint        flags ) {

  uint block_words[16];
  at_memcpy( block_words, block, 64 );

  uint ctr_lo = (uint)(counter&UINT_MAX);
  uint ctr_hi = (uint)(counter>>32);

  state[ 0] = cv[0];           state[ 1] = cv[1];
  state[ 2] = cv[2];           state[ 3] = cv[3];
  state[ 4] = cv[4];           state[ 5] = cv[5];
  state[ 6] = cv[6];           state[ 7] = cv[7];
  state[ 8] = AT_BLAKE3_IV[0]; state[ 9] = AT_BLAKE3_IV[1];
  state[10] = AT_BLAKE3_IV[2]; state[11] = AT_BLAKE3_IV[3];
  state[12] = ctr_lo;          state[13] = ctr_hi;
  state[14] = block_len;       state[15] = flags;

  round_fn( state, &block_words[0], 0 );
  round_fn( state, &block_words[0], 1 );
  round_fn( state, &block_words[0], 2 );
  round_fn( state, &block_words[0], 3 );
  round_fn( state, &block_words[0], 4 );
  round_fn( state, &block_words[0], 5 );
  round_fn( state, &block_words[0], 6 );
}

static inline void
compress_block( uint        cv[8],
                uchar const block[ AT_BLAKE3_BLOCK_SZ ],
                uint        block_len,
                ulong       counter,
                uint        flags,
                uint        cv_hi[8] ) {
  if( flags & AT_BLAKE3_FLAG_ROOT ) AT_BLAKE3_TRACE(( "at_blake3_ref_compress_block(counter=%lu,flags=%x)", counter, flags ));
  uint state[16];
  if( AT_UNLIKELY( cv_hi ) ) at_memcpy( cv_hi, cv, 32 );
  compress_pre( state, cv, block, block_len, counter, flags );
  cv[0] = state[0] ^ state[ 8];
  cv[1] = state[1] ^ state[ 9];
  cv[2] = state[2] ^ state[10];
  cv[3] = state[3] ^ state[11];
  cv[4] = state[4] ^ state[12];
  cv[5] = state[5] ^ state[13];
  cv[6] = state[6] ^ state[14];
  cv[7] = state[7] ^ state[15];
  if( AT_UNLIKELY( cv_hi ) ) {
    cv_hi[0] ^= state[ 8];
    cv_hi[1] ^= state[ 9];
    cv_hi[2] ^= state[10];
    cv_hi[3] ^= state[11];
    cv_hi[4] ^= state[12];
    cv_hi[5] ^= state[13];
    cv_hi[6] ^= state[14];
    cv_hi[7] ^= state[15];
  }
}

void
at_blake3_ref_compress1( uchar * restrict       out,
                         uchar const * restrict msg,
                         uint                   msg_sz,
                         ulong                  counter,
                         uint                   flags,
                         uchar * restrict       out_chain,
                         uchar const * restrict in_chain ) {
  AT_BLAKE3_TRACE(( "at_blake3_ref_compress1(out=%p,msg=%p,sz=%u,counter=%lu,flags=%02x)",
                    (void *)out, (void *)msg, msg_sz, counter, flags ));

  uint cv[8] = { AT_BLAKE3_IV[0], AT_BLAKE3_IV[1], AT_BLAKE3_IV[2], AT_BLAKE3_IV[3],
                 AT_BLAKE3_IV[4], AT_BLAKE3_IV[5], AT_BLAKE3_IV[6], AT_BLAKE3_IV[7] };
  uint * cv_hi = NULL;
  if( AT_UNLIKELY( in_chain ) ) {
    at_memcpy( cv, in_chain, AT_BLAKE3_OUTCHAIN_SZ );
    if( AT_UNLIKELY( in_chain ) ) cv_hi = (uint *)( out+32 );
  }

  uint block_flags = flags | at_uint_if( flags&AT_BLAKE3_FLAG_PARENT, 0, AT_BLAKE3_FLAG_CHUNK_START );
  if( AT_UNLIKELY( in_chain && !(flags&AT_BLAKE3_FLAG_CHUNK_START) ) ) {
    block_flags &= ~AT_BLAKE3_FLAG_CHUNK_START;
  }
  while( AT_LIKELY( msg_sz>AT_BLAKE3_BLOCK_SZ ) ) {
    compress_block( cv, msg, AT_BLAKE3_BLOCK_SZ, counter, block_flags&(~AT_BLAKE3_FLAG_ROOT), cv_hi );
    block_flags = flags;
    msg    += AT_BLAKE3_BLOCK_SZ;
    msg_sz -= (uint)AT_BLAKE3_BLOCK_SZ;
  }

  uchar block[ AT_BLAKE3_BLOCK_SZ ] = {0};
  at_memcpy( block, msg, msg_sz );

  block_flags = block_flags | at_uint_if( flags&AT_BLAKE3_FLAG_PARENT, 0, AT_BLAKE3_FLAG_CHUNK_END );
  if( AT_UNLIKELY( out_chain ) ) {
    /* If requested, capture the output chaining value before processing
       the last block.  This is useful for XOF mode, which repeats the
       hash operation of the last block with increasing counter values.
       We don't need to perform the final compression here (which
       computes the first 32 bytes of hash output) in the XOF case,
       since the fast/parallel XOF implementation that calls this
       function repeats compression for XOF slot 0 (first 64 bytes).

       FIXME better document and polish the transition from the compress
             part to the expand part. */
    at_memcpy( out,       block, AT_BLAKE3_BLOCK_SZ    ); /* FIXME DOCUMENT OVERLOADING OF OUT ARGUMENT */
    at_memcpy( out_chain, cv,    AT_BLAKE3_OUTCHAIN_SZ );
    AT_BLAKE3_TRACE(( "at_blake3_ref_compress1: done (XOF mode)" ));
    return;
  }
  compress_block( cv, block, msg_sz, counter, block_flags, cv_hi );
  at_memcpy( out, cv, 32 );

  AT_BLAKE3_TRACE(( "at_blake3_ref_compress1: done" ));
}