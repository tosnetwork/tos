#ifndef HEADER_at_src_tango_at_dcache_private_h
#define HEADER_at_src_tango_at_dcache_private_h

#include "at_dcache.h"

/* AT_DCACHE_MAGIC is used to signal the layout of shared memory region
   of a dcache. */

#define AT_DCACHE_MAGIC (0xF17EDA2C37DCA540UL) /* F17E=FIRE,DA2C/37=DANCER,DC/A54=DCASH,0=V0 / FIRE DANCER MCASH V0 */

/* at_dcache_private_hdr specifies the detailed layout of the shared
   memory region. */

struct __attribute__((aligned(AT_DCACHE_ALIGN))) at_dcache_private_hdr {

  /* This point is AT_DCACHE_ALIGN aligned */

  ulong magic;   /* == AT_DCACHE_MAGIC */
  ulong data_sz; /* Size of the data region in bytes */
  ulong app_sz;  /* Size of the application region in bytes */
  ulong app_off; /* Location of the application region relative to first byte of the header */

  /* Padding to AT_DCACHE_SLOT_ALIGN here */

  uchar __attribute__((aligned(AT_DCACHE_SLOT_ALIGN))) guard[ AT_DCACHE_GUARD_FOOTPRINT ];

  /* Padding to AT_DCACHE_ALIGN here (probably zero) */

  /* data_sz bytes here */

  /* Padding to AT_DCACHE_ALIGN here */

  /* app_off points here */
  /* app_sz byte reserved here */

  /* Padding to AT_DCACHE_ALIGN here */
};

typedef struct at_dcache_private_hdr at_dcache_private_hdr_t;

AT_PROTOTYPES_BEGIN

AT_FN_CONST static inline uchar const *
at_dcache_private_cache_const( at_dcache_private_hdr_t const * dcache ) {
  return (uchar const *)(dcache+1UL);
}

AT_FN_CONST static inline uchar *
at_dcache_private_dcache( at_dcache_private_hdr_t * dcache ) {
  return (uchar *)(dcache+1UL);
}

AT_FN_CONST static inline at_dcache_private_hdr_t const *
at_dcache_private_hdr_const( uchar const * dcache ) {
  return (at_dcache_private_hdr_t const *)(((ulong)dcache) - sizeof(at_dcache_private_hdr_t));
}

AT_FN_CONST static inline at_dcache_private_hdr_t *
at_dcache_private_hdr( uchar * dcache ) {
  return (at_dcache_private_hdr_t *)(((ulong)dcache) - sizeof(at_dcache_private_hdr_t));
}

AT_PROTOTYPES_END

#endif /* HEADER_at_src_tango_at_dcache_private_h */