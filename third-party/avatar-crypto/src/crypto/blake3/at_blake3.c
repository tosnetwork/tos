#include "at_blake3.h"
#include "at/infra/at_util.h"
#include "at_blake3_private.h"
#include <assert.h>

/* Hash state machine *************************************************/

static AT_FN_UNUSED at_blake3_pos_t *
at_blake3_pos_init( at_blake3_pos_t * s,
                    uchar const *     data,
                    ulong             sz ) {
  *s = (at_blake3_pos_t) {
    .input    = data,
    .input_sz = sz,
    .magic    = AT_BLAKE3_MAGIC,
  };
  return s;
}

/* at_blake3_l0_complete returns 1 if all leaf nodes have been hashed,
   0 otherwise. */

AT_FN_PURE static inline int
at_blake3_l0_complete( at_blake3_pos_t const * s ) {
  return ( s->leaf_idx<<AT_BLAKE3_CHUNK_LG_SZ ) >= at_ulong_max( s->input_sz, 64 );
}

AT_FN_PURE static inline int
at_blake3_is_finished( at_blake3_pos_t const * s,
                       ulong                   tick ) {
  int l0_complete = at_blake3_l0_complete( s );
  int ln_complete = s->live_cnt == 1UL;
  int idle        = tick >= s->next_tick;
  return l0_complete & ln_complete & idle;
}

static at_blake3_op_t *
at_blake3_prepare_leaf( at_blake3_pos_t * restrict s,
                        at_blake3_buf_t * restrict buf,
                        at_blake3_op_t *  restrict op,
                        ulong                      tick ) {

  ulong         msg_off = s->leaf_idx << AT_BLAKE3_CHUNK_LG_SZ;
  ulong         msg_sz  = at_ulong_min( s->input_sz - msg_off, 1024UL );
  uchar const * msg     = s->input + msg_off;
  uchar       * out     = buf->slots[ s->layer ][ s->head.uc[ s->layer ] ];

  int flags = at_int_if( s->input_sz <= AT_BLAKE3_CHUNK_SZ, AT_BLAKE3_FLAG_ROOT, 0 );

  *op = (at_blake3_op_t) {
    .msg     = msg,
    .out     = out,
    .counter = s->leaf_idx,
    .sz      = (ushort)msg_sz,
    .flags   = (uchar)flags
  };

  s->head.uc[ 0 ] = (uchar)( s->head.uc[ 0 ]+1 );
  s->leaf_idx++;
  s->live_cnt++;
  s->next_tick = tick+1;

  return op;

}

static int
at_blake3_seek_branch( at_blake3_pos_t * restrict s,
                       at_blake3_buf_t * restrict buf,
                       ulong                      tick ) {

  if( s->live_cnt == 1UL )
    return 0;

  if( !at_blake3_l0_complete( s ) )
    return ( s->tail.uc[ s->layer - 1 ] + 1 ) <
           ( s->head.uc[ s->layer - 1 ]     );

# if AT_HAS_AVX

  wb_t diff = wb_sub( s->head.wb, s->tail.wb );

  uint mergeable_layers = (uint)_mm256_movemask_epi8( wb_gt( diff, wb_bcast( 1 ) ) );
  int  merge_layer = at_uint_find_lsb_w_default( mergeable_layers, -1 );
  if( merge_layer>=0 ) {
    if( ((uint)merge_layer >= s->layer) & (tick < s->next_tick) )
      return 0;  /* still waiting for previous merge */
    s->layer = (uint)merge_layer+1U;
    return 1;
  }

  uint single_layers = (uint)_mm256_movemask_epi8( wb_eq( diff, wb_bcast( 1 ) ) );
  uint single_lo = (uint)at_uint_find_lsb( single_layers );
  uint single_hi = (uint)at_uint_find_lsb( single_layers & ( ~at_uint_mask_lsb( (int)(single_lo+1U) ) ) );

  wb_t node = wb_ld( buf->slots[ single_lo ][ s->tail.uc[ single_lo ] ] );
              wb_st( buf->slots[ single_hi ][ s->head.uc[ single_hi ] ], node );

# else /* AT_HAS_AVX */

  uchar diff[ 32 ];
  for( ulong j=0UL; j<32UL; j++ ) diff[j] = (uchar)( s->head.uc[j] - s->tail.uc[j] );

  int merge_layer = -1;
  for( uint j=0U; j<32U; j++ ) {
    if( diff[j]>1 ) {
      merge_layer = (int)j;
      break;
    }
  }
  if( merge_layer>=0 ) {
    if( ((uint)merge_layer >= s->layer) & (tick < s->next_tick) )
      return 0;  /* still waiting for previous merge */
    s->layer = (uint)(merge_layer+1);
    return 1;
  }

  uint j=0U;
  uint single_lo = 0UL;
  uint single_hi = 0UL;
  for( ; j<32U; j++ ) {
    if( diff[j] ) {
      single_lo = j;
      break;
    }
  }
  j++;
  for( ; j<32U; j++ ) {
    if( diff[j] ) {
      single_hi = j;
      break;
    }
  }

  at_memcpy( buf->slots[ single_hi ][ s->head.uc[ single_hi ] ],
          buf->slots[ single_lo ][ s->tail.uc[ single_lo ] ],
          32UL );

# endif /* AT_HAS_AVX */

  AT_BLAKE3_TRACE(( "at_blake3_seek_branch: moving up %u/%u to %u/%u",
                    single_lo, s->tail.uc[ single_lo ],
                    single_hi, s->head.uc[ single_hi ] ));

  if( ((uint)single_hi >= s->layer) & (tick < s->next_tick) )
    return 0;  /* still waiting for previous merge */

  s->head.uc[ single_lo ] = (uchar)( s->head.uc[ single_lo ]-1 );
  s->head.uc[ single_hi ] = (uchar)( s->head.uc[ single_hi ]+1 );

  s->layer = (uint)single_hi+1U;
  return 1;
}

static at_blake3_op_t *
at_blake3_prepare_branch( at_blake3_pos_t * restrict s,
                          at_blake3_buf_t * restrict buf,
                          at_blake3_op_t *  restrict op,
                          ulong                      tick ) {

  if( !at_blake3_seek_branch( s, buf, tick ) )
    return NULL;

  assert( s->layer < AT_BLAKE3_ROW_CNT );

  uchar const * msg = buf->slots[ s->layer-1U ][ s->tail.uc[ s->layer-1U ] ];
  uchar       * out = buf->slots[ s->layer    ][ s->head.uc[ s->layer    ] ];

  s->head.uc[ s->layer   ] = (uchar)( s->head.uc[ s->layer   ]+1 );
  s->tail.uc[ s->layer-1 ] = (uchar)( s->tail.uc[ s->layer-1 ]+2 );
  s->live_cnt--;
  s->next_tick = tick+1;

  uint flags = AT_BLAKE3_FLAG_PARENT |
               at_uint_if( s->live_cnt==1UL, AT_BLAKE3_FLAG_ROOT, 0u );

  *op = (at_blake3_op_t) {
    .msg     = msg,
    .out     = out,
    .counter = 0UL,
    .sz      = 64U,
    .flags   = (uchar)flags
  };
  return op;

}

static void
at_blake3_advance( at_blake3_pos_t * restrict s ) {

# if AT_HAS_AVX

  wb_t mask = wb_eq( s->tail.wb, s->head.wb );
  s->tail.wb = wb_andnot( mask, s->tail.wb );
  s->head.wb = wb_andnot( mask, s->head.wb );

# else /* AT_HAS_AVX */

  for( ulong j=0UL; j<32UL; j++ ) {
    if( s->tail.uc[j] == s->head.uc[j] ) {
      s->tail.uc[j] = 0;
      s->head.uc[j] = 0;
    }
  }

# endif /* AT_HAS_AVX */

  if( s->head.uc[ s->layer ]==AT_BLAKE3_COL_CNT ) {
    s->layer++;
  }
  else if( ( s->layer > 0UL ) &&
           ( s->tail.uc[ s->layer-1 ] < s->head.uc[ s->layer-1 ] ) ) {
    /* pass */
  }
  else if( at_blake3_l0_complete( s ) ) {
    s->layer++;
  }
  else if( s->layer > 0UL ) {
    s->layer = 0UL;
  }

}

static at_blake3_op_t *
at_blake3_prepare( at_blake3_pos_t * restrict s,
                   at_blake3_buf_t * restrict buf,
                   at_blake3_op_t *  restrict op,
                   ulong                      tick ) {

  assert( s->layer < AT_BLAKE3_ROW_CNT );

  if( at_blake3_is_finished( s, tick ) )
    return NULL;

  if( tick >= s->next_tick )
    at_blake3_advance( s );

  if( s->layer != 0 )
    return at_blake3_prepare_branch( s, buf, op, tick );

  if( ( s->head.uc[0] >= AT_BLAKE3_COL_CNT ) |
      ( at_blake3_l0_complete( s )         ) ) {
    return NULL;
  }

  return at_blake3_prepare_leaf( s, buf, op, tick );

}

#if AT_BLAKE3_PARA_MAX>1

/* at_blake3_prepare_fast does streamlined hashing of full chunks or
   full branches. */

static at_blake3_op_t *
at_blake3_prepare_fast( at_blake3_pos_t * restrict s,
                        at_blake3_buf_t * restrict buf,
                        at_blake3_op_t *  restrict op,
                        ulong                      n,
                        ulong                      min ) {

  if( s->layer && s->head.uc[ s->layer-1 ]==AT_BLAKE3_COL_CNT ) {
    op->msg     = buf->rows[ s->layer-1 ];
    op->out     = buf->rows[ s->layer ] + (s->head.uc[ s->layer ]<<AT_BLAKE3_OUTCHAIN_LG_SZ);
    op->counter = 0UL;
    op->flags   = AT_BLAKE3_FLAG_PARENT;

    /* Assume that branch layer is fully hashed (up to col cnt) */
    s->head.uc[ s->layer-1 ] =  0;
    s->head.uc[ s->layer   ] = (uchar)( (ulong)s->head.uc[ s->layer ]+n );
    s->live_cnt -= n;
    s->layer = at_uint_if( s->head.uc[ s->layer ]==AT_BLAKE3_COL_CNT,
                           s->layer+1U, 0U );

    return op;
  }

  ulong pos   = s->leaf_idx << AT_BLAKE3_CHUNK_LG_SZ;
  ulong avail = at_ulong_align_dn( s->input_sz - pos, AT_BLAKE3_CHUNK_SZ ) >> AT_BLAKE3_CHUNK_LG_SZ;
  n = at_ulong_min( n, avail );

  /* This constants controls the threshold when to use the (slow)
     scheduler instead of fast single-message hashing.  Carefully tuned
     for best overall performance. */
  if( n<min ) return NULL;

  op->msg     = s->input + (s->leaf_idx<<AT_BLAKE3_CHUNK_LG_SZ);
  op->out     = buf->rows[0] + (s->head.uc[0]<<AT_BLAKE3_OUTCHAIN_LG_SZ);
  op->counter = s->leaf_idx;
  op->flags   = 0;

  s->head.uc[0] = (uchar)( (ulong)s->head.uc[0]+n );
  s->leaf_idx   += n;
  s->live_cnt   += n;
  s->layer      =  at_uint_if( s->head.uc[0]==AT_BLAKE3_COL_CNT, 1U, 0U );

  return op;
}

static void
at_blake3_batch_hash( at_blake3_op_t const * ops,
                      ulong                  op_cnt ) {
  uchar const * batch_data   [ AT_BLAKE3_PARA_MAX ] __attribute__((aligned(64)));
  uint          batch_data_sz[ AT_BLAKE3_PARA_MAX ] = {0};
  uchar *       batch_hash   [ AT_BLAKE3_PARA_MAX ] __attribute__((aligned(64)));
  ulong         batch_ctr    [ AT_BLAKE3_PARA_MAX ];
  uint          batch_flags  [ AT_BLAKE3_PARA_MAX ];
  for( ulong j=0UL; j<op_cnt; j++ ) {
    batch_data   [ j ] = ops[ j ].msg;
    batch_hash   [ j ] = ops[ j ].out;
    batch_data_sz[ j ] = ops[ j ].sz;
    batch_ctr    [ j ] = ops[ j ].counter;
    batch_flags  [ j ] = ops[ j ].flags;
  }
#if AT_HAS_AVX512
  at_blake3_avx512_compress16( op_cnt, batch_data, batch_data_sz, batch_ctr, batch_flags, at_type_pun( batch_hash ), NULL, 32U, NULL );
#elif AT_HAS_AVX
  at_blake3_avx_compress8    ( op_cnt, batch_data, batch_data_sz, batch_ctr, batch_flags, at_type_pun( batch_hash ), NULL, 32U, NULL );
#else
  #error "FIXME missing para support"
#endif
}

#endif

/* Simple API *********************************************************/

ulong
at_blake3_align( void ) {
  return AT_BLAKE3_ALIGN;
}

ulong
at_blake3_footprint( void ) {
  return AT_BLAKE3_FOOTPRINT;
}

void *
at_blake3_new( void * shmem ) {
  at_blake3_t * sha = (at_blake3_t *)shmem;

  if( AT_UNLIKELY( !shmem ) ) {
    AT_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( AT_UNLIKELY( !at_ulong_is_aligned( (ulong)shmem, at_blake3_align() ) ) ) {
    AT_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong footprint = at_blake3_footprint();

  at_memset( sha, 0, footprint );

  AT_COMPILER_MFENCE();
  AT_VOLATILE( sha->pos.magic ) = AT_BLAKE3_MAGIC;
  AT_COMPILER_MFENCE();

  return (void *)sha;
}

at_blake3_t *
at_blake3_join( void * shsha ) {

  if( AT_UNLIKELY( !shsha ) ) {
    AT_LOG_WARNING(( "NULL shsha" ));
    return NULL;
  }

  if( AT_UNLIKELY( !at_ulong_is_aligned( (ulong)shsha, at_blake3_align() ) ) ) {
    AT_LOG_WARNING(( "misaligned shsha" ));
    return NULL;
  }

  at_blake3_t * sha = (at_blake3_t *)shsha;

  if( AT_UNLIKELY( sha->pos.magic!=AT_BLAKE3_MAGIC ) ) {
    AT_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return sha;
}

void *
at_blake3_leave( at_blake3_t * sha ) {

  if( AT_UNLIKELY( !sha ) ) {
    AT_LOG_WARNING(( "NULL sha" ));
    return NULL;
  }

  return (void *)sha;
}

void *
at_blake3_delete( void * shsha ) {

  if( AT_UNLIKELY( !shsha ) ) {
    AT_LOG_WARNING(( "NULL shsha" ));
    return NULL;
  }

  if( AT_UNLIKELY( !at_ulong_is_aligned( (ulong)shsha, at_blake3_align() ) ) ) {
    AT_LOG_WARNING(( "misaligned shsha" ));
    return NULL;
  }

  at_blake3_t * sha = (at_blake3_t *)shsha;

  if( AT_UNLIKELY( sha->pos.magic!=AT_BLAKE3_MAGIC ) ) {
    AT_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  AT_COMPILER_MFENCE();
  AT_VOLATILE( sha->pos.magic ) = 0UL;
  AT_COMPILER_MFENCE();

  return (void *)sha;
}


at_blake3_t *
at_blake3_init( at_blake3_t * sha ) {
  AT_BLAKE3_TRACE(( "at_blake3_init(sha=%p)", (void *)sha ));
  at_blake3_pos_init( &sha->pos, NULL, 0UL );
  sha->block_sz = 0UL;
  return sha;
}

#if AT_BLAKE3_PARA_MAX>1

static void
at_blake3_append_blocks( at_blake3_pos_t * s,
                         at_blake3_buf_t * tbl,
                         uchar const *     data,
                         ulong             buf_cnt ) {
  s->input = data - (s->leaf_idx << AT_BLAKE3_CHUNK_LG_SZ); /* TODO HACKY!! */
  for( ulong i=0UL; i<buf_cnt; i++ ) {
    at_blake3_op_t op[1];
    do {
      if( !at_blake3_prepare_fast( s, tbl, op, AT_BLAKE3_PARA_MAX, AT_BLAKE3_PARA_MAX ) )
        return;
#if AT_HAS_AVX512
      at_blake3_avx512_compress16_fast( op->msg, op->out, op->counter, op->flags );
#elif AT_HAS_AVX
      at_blake3_avx_compress8_fast( op->msg, op->out, op->counter, op->flags );
#else
      #error "missing para support"
#endif
    } while( op->flags & AT_BLAKE3_FLAG_PARENT );
  }
}

#else

static void
at_blake3_append_blocks( at_blake3_pos_t * s,
                         at_blake3_buf_t * tbl,
                         uchar const *     data,
                         ulong             buf_cnt ) {
  (void)buf_cnt;
  s->input = data - (s->leaf_idx << AT_BLAKE3_CHUNK_LG_SZ); /* TODO HACKY!! */
  at_blake3_op_t op[1];
  while( buf_cnt ) {
    if( !at_blake3_prepare( s, tbl, op, s->next_tick ) ) {
      AT_BLAKE3_TRACE(( "at_blake3_append_blocks: no more ops to prepare" ));
      break;
    }
    if( op->flags & AT_BLAKE3_FLAG_PARENT ) {
      AT_BLAKE3_TRACE(( "at_blake3_append_blocks: compressing output chaining values (layer %u)", s->layer ));
      at_blake3_ref_compress1( op->out, op->msg, 64UL, op->counter, op->flags, NULL, NULL );
    } else {
      AT_BLAKE3_TRACE(( "at_blake3_append_blocks: compressing %lu leaf chunks", AT_BLAKE3_COL_CNT ));
      at_blake3_ref_compress1( op->out, op->msg, AT_BLAKE3_CHUNK_SZ, op->counter, op->flags, NULL, NULL );
      buf_cnt--;
    }
    s->next_tick++;
  }
}

#endif

at_blake3_t *
at_blake3_append( at_blake3_t * sha,
                  void const *  _data,
                  ulong         sz ) {

  /* If no data to append, we are done */

  if( AT_UNLIKELY( !sz ) ) return sha;
  AT_BLAKE3_TRACE(( "at_blake3_append(sha=%p,data=%p,sz=%lu)", (void *)sha, _data, sz ));

  /* Unpack inputs */

  at_blake3_pos_t * s        = &sha->pos;
  at_blake3_buf_t * tbl      = &sha->buf;
  uchar *           buf      = sha->block;
  ulong             buf_used = sha->block_sz;

  uchar const * data = (uchar const *)_data;

  /* Update input_sz */

  s->input_sz += sz;

  /* Edge case: For the first completed 1024 bytes of input, don't
     immediately hash, since it is not clear whether this chunk has
     the root flag set. */
  if( AT_UNLIKELY( AT_BLAKE3_PARA_MAX==1 && s->input_sz==1024UL ) ) {
    at_memcpy( buf + buf_used, data, sz );
    sha->block_sz = AT_BLAKE3_CHUNK_SZ;
    return sha;
  }

  /* Handle buffered bytes from previous appends */

  if( AT_UNLIKELY( buf_used ) ) { /* optimized for well aligned use of append */

    /* If the append isn't large enough to complete the current block,
       buffer these bytes too and return */

    ulong buf_rem = AT_BLAKE3_PRIVATE_BUF_MAX - buf_used; /* In (0,AT_BLAKE3_PRIVATE_BUF_MAX) */
    if( AT_UNLIKELY( sz < buf_rem ) ) { /* optimize for large append */
      at_memcpy( buf + buf_used, data, sz );
      sha->block_sz = buf_used + sz;
      return sha;
    }

    /* Otherwise, buffer enough leading bytes of data to complete the
       block, update the hash and then continue processing any remaining
       bytes of data. */

    at_memcpy( buf + buf_used, data, buf_rem );
    data += buf_rem;
    sz   -= buf_rem;

    at_blake3_append_blocks( s, tbl, buf, 1UL );
    sha->block_sz = 0UL;
  }

  /* Append the bulk of the data */

  ulong buf_cnt = sz >> AT_BLAKE3_PRIVATE_LG_BUF_MAX;
  if( AT_LIKELY( buf_cnt ) ) at_blake3_append_blocks( s, tbl, data, buf_cnt ); /* optimized for large append */

  /* Buffer any leftover bytes */

  buf_used = sz & (AT_BLAKE3_PRIVATE_BUF_MAX-1UL); /* In [0,AT_BLAKE3_PRIVATE_BUF_MAX) */
  if( AT_UNLIKELY( buf_used ) ) { /* optimized for well aligned use of append */
    at_memcpy( buf, data + (buf_cnt << AT_BLAKE3_PRIVATE_LG_BUF_MAX), buf_used );
    sha->block_sz = buf_used; /* In (0,AT_BLAKE3_PRIVATE_BUF_MAX) */
  }

  AT_BLAKE3_TRACE(( "at_blake3_append: done" ));
  return sha;
}

static void const *
at_blake3_single_hash( at_blake3_pos_t * s,
                       at_blake3_buf_t * tbl ) {
#if AT_BLAKE3_PARA_MAX>1
  ulong tick = 0UL;
  while( !at_blake3_is_finished( s, tick ) ) {
    at_blake3_op_t ops[ AT_BLAKE3_PARA_MAX ] = {0};
    ulong          op_cnt = 0UL;
    while( op_cnt<AT_BLAKE3_PARA_MAX ) {
      at_blake3_op_t * op = &ops[ op_cnt ];
      if( !at_blake3_prepare( s, tbl, op, tick ) )
        break;
      op_cnt++;
    }

    at_blake3_batch_hash( ops, op_cnt );
    tick++;
  }
#else
  while( !at_blake3_is_finished( s, s->next_tick ) ) {
    at_blake3_op_t op[1] = {0};
    if( !at_blake3_prepare( s, tbl, op, s->next_tick ) )
      break;
    s->next_tick++;
    AT_BLAKE3_TRACE(( "at_blake3_single_hash: compressing %hu bytes at layer %u, counter %lu, flags 0x%x",
                      op->sz, s->layer, op->counter, op->flags ));
#   if AT_HAS_SSE
    at_blake3_sse_compress1( op->out, op->msg, op->sz, op->counter, op->flags, NULL, NULL );
#   else
    at_blake3_ref_compress1( op->out, op->msg, op->sz, op->counter, op->flags, NULL, NULL );
#   endif
  }
#endif
  return tbl->slots[ s->layer ][0];
}

void *
at_blake3_fini( at_blake3_t * sha,
                void *        hash ) {

  /* Unpack inputs */

  at_blake3_pos_t * s        = &sha->pos;
  at_blake3_buf_t * tbl      = &sha->buf;
  uchar *           buf      = sha->block;
  ulong             buf_used = sha->block_sz;
  AT_BLAKE3_TRACE(( "at_blake3_fini(sha=%p,sz=%lu)", (void *)sha, s->input_sz ));

  /* TODO HACKY!! */
  s->input    = buf - ( s->leaf_idx << AT_BLAKE3_CHUNK_LG_SZ );
  s->input_sz = ( s->leaf_idx << AT_BLAKE3_CHUNK_LG_SZ ) + buf_used;

  void const * hash_ = at_blake3_single_hash( s, tbl );
  at_memcpy( hash, hash_, 32UL );
  return hash;
}

/* at_blake3_fini_xof_compress performs BLAKE3 compression (input
   hashing) for all blocks in the hash tree except for the root block.
   Root compression inputs are returned via the function's out pointers:
   On return, root_msg[0..64] contains the padded message input for the
   root block, root_cv_pre[0..64] contains the output chaining value of
   the previous block (or the BLAKE3 IV if root block is the only block
   in the hash operation, i.e. <=64 byte hash input).
   Other values (counter, flags, size) are re-derived by the XOF
   implementation using the blake3 state object. */

void
at_blake3_fini_xof_compress( at_blake3_t * sha,
                             uchar *       root_msg,
                             uchar *       root_cv_pre ) {
  at_blake3_pos_t * s        = &sha->pos;
  at_blake3_buf_t * tbl      = &sha->buf;
  uchar *           buf      = sha->block;
  ulong             buf_used = sha->block_sz;

  /* TODO HACKY!! */
  s->input    = buf - ( s->leaf_idx << AT_BLAKE3_CHUNK_LG_SZ );
  s->input_sz = ( s->leaf_idx << AT_BLAKE3_CHUNK_LG_SZ ) + buf_used;

  /* The root block is contained in a leaf.  Process all but the last
     blocks of the chunk.  (The last block is the "root" block) */
  if( s->input_sz<=AT_BLAKE3_CHUNK_SZ ) {
    at_blake3_op_t op[1];
    if( !at_blake3_prepare_leaf( s, tbl, op, s->next_tick ) )
      AT_LOG_ERR(( "at_blake3_fini_xof_compress invariant violation: failed to prepare compression of <=1024 byte message (duplicate call to fini?)" ));
#if AT_HAS_SSE
    at_blake3_sse_compress1( root_msg, op->msg, op->sz, op->counter, op->flags, root_cv_pre, NULL );
#else
    at_blake3_ref_compress1( root_msg, op->msg, op->sz, op->counter, op->flags, root_cv_pre, NULL );
#endif
    return;
  }

  /* The root block is a branch node.  Continue working until there are
     only two blocks remaining. */
  ulong tick = sha->pos.next_tick+1;
  for(;;) {
    int l0_complete = at_blake3_l0_complete( s );
    int ln_complete = s->live_cnt == 2UL;
    if( l0_complete & ln_complete ) break;

#if AT_BLAKE3_PARA_MAX>1
    at_blake3_op_t ops[ AT_BLAKE3_PARA_MAX ] = {0};
    ulong          op_cnt = 0UL;
    while( op_cnt<AT_BLAKE3_PARA_MAX ) {
      at_blake3_op_t * op = &ops[ op_cnt ];
      if( !at_blake3_prepare( s, tbl, op, tick ) )
        break;
      op_cnt++;
    }
    if( AT_UNLIKELY( !op_cnt ) ) {
      AT_LOG_ERR(( "at_blake3_fini_xof_compress invariant violation: failed to prepare branch compression with live_cnt=%lu (duplicate call to fini?)", s->live_cnt ));
    }

    at_blake3_batch_hash( ops, op_cnt );
#else
    at_blake3_op_t op[1] = {0};
    if( !at_blake3_prepare( s, tbl, op, tick ) )
      break;
#   if AT_HAS_SSE
    at_blake3_sse_compress1( op->out, op->msg, op->sz, op->counter, op->flags, NULL, NULL );
#   else
    at_blake3_ref_compress1( op->out, op->msg, op->sz, op->counter, op->flags, NULL, NULL );
#   endif
#endif
    tick++;
  }
}

void *
at_blake3_fini_2048( at_blake3_t * sha,
                     void *        hash ) {
  AT_BLAKE3_TRACE(( "at_blake3_fini_2048(sha=%p,hash=%p)", (void *)sha, hash ));

  /* Compress input until the last remaining piece of work is the BLAKE3
     root block.  This root block is put through the compression
     function repeatedly to "expand" the hash output (XOF hashing).
     at_blake3 does this SIMD-parallel for better performance. */
  uchar root_msg   [ 64 ] __attribute__((aligned(64)));
  uchar root_cv_pre[ 32 ] __attribute__((aligned(32)));
  at_blake3_fini_xof_compress( sha, root_msg, root_cv_pre );

  /* Restore root block details */
  uint          last_block_sz    = 64u;
  uint          last_block_flags = AT_BLAKE3_FLAG_ROOT | AT_BLAKE3_FLAG_PARENT;
  ulong         ctr0             = 0UL;
  if( sha->pos.input_sz<=AT_BLAKE3_CHUNK_SZ ) {
    last_block_sz    = (uint)sha->pos.input_sz & 63u;
    if( at_ulong_is_aligned( sha->pos.input_sz, 64 ) ) last_block_sz = 64;
    if( AT_UNLIKELY( sha->pos.input_sz==0UL        ) ) last_block_sz = 0u;
    last_block_flags = AT_BLAKE3_FLAG_ROOT | AT_BLAKE3_FLAG_CHUNK_END;
    if( sha->pos.input_sz<=AT_BLAKE3_BLOCK_SZ ) last_block_flags |= AT_BLAKE3_FLAG_CHUNK_START;
    ctr0             = sha->pos.leaf_idx-1UL;
  } else {
    at_blake3_op_t op[1];
    if( AT_UNLIKELY( !at_blake3_prepare( &sha->pos, &sha->buf, op, sha->pos.next_tick+1UL ) ) ) {
      AT_LOG_ERR(( "at_blake3_fini_2048 invariant violation: failed to prepare branch root compression (duplicate call to fini?)" ));
    }
    at_memcpy( root_msg,    op->msg,      64UL );
    at_memcpy( root_cv_pre, AT_BLAKE3_IV, 32UL );
  }
  AT_BLAKE3_TRACE(( "at_blake3_fini_2048: sz=%lu ctr0=%lu flags=%x",
                    sha->pos.input_sz, ctr0, last_block_flags ));

  /* Expand LtHash
     For now, this uses the generic AVX2/AVX512 compress backend.
     Could write a more optimized version in the future saving some of
     the matrix transpose work. */
  for( ulong i=0UL; i<32UL; i+=AT_BLAKE3_PARA_MAX ) {
#if AT_HAS_AVX512
    ulong  batch_data [ 16 ] __attribute__((aligned(64)));
    /*                     */ for( ulong j=0; j<16; j++ ) batch_data [ j ] = (ulong)root_msg;
    uint   batch_sz   [ 16 ]; for( ulong j=0; j<16; j++ ) batch_sz   [ j ] = last_block_sz;
    ulong  batch_ctr  [ 16 ]; for( ulong j=0; j<16; j++ ) batch_ctr  [ j ] = ctr0+i+j;
    uint   batch_flags[ 16 ]; for( ulong j=0; j<16; j++ ) batch_flags[ j ] = last_block_flags;
    void * batch_hash [ 16 ]; for( ulong j=0; j<16; j++ ) batch_hash [ j ] = (uchar *)hash + (i+j)*64;
    void * batch_cv   [ 16 ]; for( ulong j=0; j<16; j++ ) batch_cv   [ j ] = root_cv_pre;
    at_blake3_avx512_compress16( 16UL, batch_data, batch_sz, batch_ctr, batch_flags, batch_hash, NULL, 64U, batch_cv );
#elif AT_HAS_AVX
    ulong  batch_data [ 8 ]; for( ulong j=0; j<8; j++ ) batch_data [ j ] = (ulong)root_msg;
    uint   batch_sz   [ 8 ]; for( ulong j=0; j<8; j++ ) batch_sz   [ j ] = last_block_sz;
    ulong  batch_ctr  [ 8 ]; for( ulong j=0; j<8; j++ ) batch_ctr  [ j ] = ctr0+i+j;
    uint   batch_flags[ 8 ]; for( ulong j=0; j<8; j++ ) batch_flags[ j ] = last_block_flags;
    void * batch_hash [ 8 ]; for( ulong j=0; j<8; j++ ) batch_hash [ j ] = (uchar *)hash + (i+j)*64;
    void * batch_cv   [ 8 ]; for( ulong j=0; j<8; j++ ) batch_cv   [ j ] = root_cv_pre;
    at_blake3_avx_compress8( 8UL, batch_data, batch_sz, batch_ctr, batch_flags, batch_hash, NULL, 64U, batch_cv );
#elif AT_HAS_SSE
    at_blake3_sse_compress1( (uchar *)hash+i*64, root_msg, last_block_sz, ctr0+i, last_block_flags, NULL, root_cv_pre );
#else
    at_blake3_ref_compress1( (uchar *)hash+i*64, root_msg, last_block_sz, ctr0+i, last_block_flags, NULL, root_cv_pre );
#endif
  }

  AT_BLAKE3_TRACE(( "at_blake3_fini_2048: done" ));
  return hash;
}

void *
at_blake3_hash( void const * data,
                ulong        sz,
                void *       hash ) {

  at_blake3_buf_t tbl[1];
  at_blake3_pos_t s[1];
  at_blake3_pos_init( s, data, sz );

#if AT_BLAKE3_PARA_MAX>1
  for(;;) {
    at_blake3_op_t op[1];
    if( !at_blake3_prepare_fast( s, tbl, op, AT_BLAKE3_PARA_MAX, 4 ) )
      break;
#if AT_HAS_AVX512
    at_blake3_avx512_compress16_fast( op->msg, op->out, op->counter, op->flags );
#elif AT_HAS_AVX
    at_blake3_avx_compress8_fast( op->msg, op->out, op->counter, op->flags );
#else
    #error "missing para support"
#endif
  }
#endif

  void const * hash_ = at_blake3_single_hash( s, tbl );
  at_memcpy( hash, hash_, 32UL );
  return hash;
}

#if AT_HAS_AVX

void
at_blake3_lthash_batch8(
    void const * batch_data[8],  /* align=32 ele_align=1 */
    uint const   batch_sz  [8],  /* align=32 */
    void *       out_lthash      /* align=32 */
) {
  if( AT_UNLIKELY( !at_ulong_is_aligned( (ulong)batch_data, 32 ) ) ) {
    AT_LOG_ERR(( "misaligned batch_data: %p", (void *)batch_data ));
  }
  if( AT_UNLIKELY( !at_ulong_is_aligned( (ulong)batch_sz, 32 ) ) ) {
    AT_LOG_ERR(( "misaligned batch_sz: %p", (void *)batch_sz ));
  }
  if( AT_UNLIKELY( !at_ulong_is_aligned( (ulong)out_lthash, 32 ) ) ) {
    AT_LOG_ERR(( "misaligned out_lthash: %p", (void *)out_lthash ));
  }

  ulong batch_ctr  [ 8 ] = {0};
  uint  batch_flags[ 8 ]; for( uint i=0; i<8; i++ ) batch_flags[ i ] = AT_BLAKE3_FLAG_ROOT;
  at_blake3_avx_compress8( 8UL, batch_data, batch_sz, batch_ctr, batch_flags, NULL, out_lthash, 32U, NULL );
}

#endif

#if AT_HAS_AVX512

void
at_blake3_lthash_batch16(
    void const * batch_data[16],  /* align=32 ele_align=1 */
    uint const   batch_sz  [16],  /* align=32 */
    void *       out_lthash      /* align=32 */
) {
  if( AT_UNLIKELY( !at_ulong_is_aligned( (ulong)batch_data, 64 ) ) ) {
    AT_LOG_ERR(( "misaligned batch_data: %p", (void *)batch_data ));
  }
  if( AT_UNLIKELY( !at_ulong_is_aligned( (ulong)batch_sz, 64 ) ) ) {
    AT_LOG_ERR(( "misaligned batch_sz: %p", (void *)batch_sz ));
  }
  if( AT_UNLIKELY( !at_ulong_is_aligned( (ulong)out_lthash, 64 ) ) ) {
    AT_LOG_ERR(( "misaligned out_lthash: %p", (void *)out_lthash ));
  }

  ulong batch_ctr  [ 16 ] = {0};
  uint  batch_flags[ 16 ]; for( uint i=0; i<16; i++ ) batch_flags[ i ] = AT_BLAKE3_FLAG_ROOT;
  at_blake3_avx512_compress16( 16UL, batch_data, batch_sz, batch_ctr, batch_flags, NULL, out_lthash, 32U, NULL );
}

#endif