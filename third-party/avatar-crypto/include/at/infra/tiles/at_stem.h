#ifndef HEADER_at_disco_stem_h
#define HEADER_at_disco_stem_h

#include "at_disco_base.h"

#define AT_STEM_SCRATCH_ALIGN (128UL)

struct at_stem_context {
   at_frag_meta_t ** mcaches;
   ulong *           seqs;
   ulong *           depths;

   ulong *           cr_avail;
   ulong *           min_cr_avail;
   ulong             cr_decrement_amount;
};

typedef struct at_stem_context at_stem_context_t;

struct __attribute__((aligned(64))) at_stem_tile_in {
  at_frag_meta_t const * mcache;   /* local join to this in's mcache */
  uint                   depth;    /* == at_mcache_depth( mcache ), depth of this in's cache (const) */
  uint                   idx;      /* index of this in in the list of providers, [0, in_cnt) */
  ulong                  seq;      /* sequence number of next frag expected from the upstream producer,
                                      updated when frag from this in is published */
  at_frag_meta_t const * mline;    /* == mcache + at_mcache_line_idx( seq, depth ), location to poll next */
  ulong *                fseq;     /* local join to the fseq used to return flow control credits to the in */
  uint                   accum[6]; /* local diagnostic accumulators.  These are drained during in housekeeping. */
                                   /* Assumes AT_FSEQ_DIAG_{PUB_CNT,PUB_SZ,FILT_CNT,FILT_SZ,OVRNP_CNT,OVRNP_FRAG_CNT} are 0:5 */
};

typedef struct at_stem_tile_in at_stem_tile_in_t;

static inline void
at_stem_publish( at_stem_context_t * stem,
                 ulong               out_idx,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub ) {
  ulong * seqp = &stem->seqs[ out_idx ];
  ulong   seq  = *seqp;
  at_mcache_publish( stem->mcaches[ out_idx ], stem->depths[ out_idx ], seq, sig, chunk, sz, ctl, tsorig, tspub );
  stem->cr_avail[ out_idx ] -= stem->cr_decrement_amount;
  *stem->min_cr_avail        = at_ulong_min( stem->cr_avail[ out_idx ], *stem->min_cr_avail );
  *seqp = at_seq_inc( seq, 1UL );
}

static inline ulong
at_stem_advance( at_stem_context_t * stem,
                 ulong               out_idx ) {
  ulong * seqp = &stem->seqs[ out_idx ];
  ulong   seq  = *seqp;
  stem->cr_avail[ out_idx ] -= stem->cr_decrement_amount;
  *stem->min_cr_avail        = at_ulong_min( stem->cr_avail[ out_idx ], *stem->min_cr_avail );
  *seqp = at_seq_inc( seq, 1UL );
  return seq;
}

#endif /* HEADER_at_disco_stem_h */