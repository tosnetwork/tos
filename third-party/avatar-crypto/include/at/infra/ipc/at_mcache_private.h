#ifndef HEADER_at_src_tango_at_mcache_private_h
#define HEADER_at_src_tango_at_mcache_private_h

#include "at_mcache.h"

/* AT_MCACHE_MAGIC is used to signal the layout of shared memory region
   of a mcache. */

#define AT_MCACHE_MAGIC (0xF17EDA2C373CA540UL) /* F17E=FIRE,DA2C/37=DANCER,3C/A54=MCASH,0=V0 / FIRE DANCER MCASH V0 */

/* at_mcache_private_hdr specifies the detailed layout of the shared
   memory region.  */

struct __attribute__((aligned(AT_MCACHE_ALIGN))) at_mcache_private_hdr {

  /* This point is AT_MCACHE_ALIGN aligned  */

  ulong magic;   /* == AT_MCACHE_MAGIC */
  ulong depth;   /* == 2^lg_depth >= AT_MCACHE_LG_BLOCK */
  ulong app_sz;  /* Size of the application region in bytes */
  ulong seq0;    /* Initial sequence number passed on creation */
  ulong app_off; /* Location of the application region relative to the first byte of the header */

  /* Padding to AT_MCACHE_ALIGN here (lots of room for additional static data here) */

  ulong __attribute__((aligned(AT_MCACHE_ALIGN))) seq[ AT_MCACHE_SEQ_CNT ];

  /* Padding to AT_MCACHE_ALIGN here (probably zero), this is implicitly AT_FRAG_META_ALIGNED */

  /* depth at_frag_meta_t here */

  /* Padding to AT_MCACHE_ALIGN (probably zero) */

  /* app_off points here */
  /* app_sz byte reserved here */

  /* Padding to AT_MCACHE_ALIGN here */
};

typedef struct at_mcache_private_hdr at_mcache_private_hdr_t;

AT_PROTOTYPES_BEGIN

AT_FN_CONST static inline at_frag_meta_t const *
at_mcache_private_cache_const( at_mcache_private_hdr_t const * mcache ) {
  return (at_frag_meta_t const *)(mcache+1UL);
}

AT_FN_CONST static inline at_frag_meta_t *
at_mcache_private_mcache( at_mcache_private_hdr_t * mcache ) {
  return (at_frag_meta_t *)(mcache+1UL);
}

AT_FN_CONST static inline at_mcache_private_hdr_t const *
at_mcache_private_hdr_const( at_frag_meta_t const * mcache ) {
  return (at_mcache_private_hdr_t const *)(((ulong)mcache) - sizeof(at_mcache_private_hdr_t));
}

AT_FN_CONST static inline at_mcache_private_hdr_t *
at_mcache_private_hdr( at_frag_meta_t * mcache ) {
  return (at_mcache_private_hdr_t *)(((ulong)mcache) - sizeof(at_mcache_private_hdr_t));
}

AT_PROTOTYPES_END

#endif /* HEADER_at_src_tango_at_mcache_private_h */