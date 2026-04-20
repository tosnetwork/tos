#ifndef HEADER_at_src_util_tmpl_at_map_h
#define HEADER_at_src_util_tmpl_at_map_h

#include "../at_util_base.h"

/* Common map error codes (FIXME: probably should get around to making
   unified error codes, error strings and/or flags across util at least
   so we don't have to do this in the generator itself) */

#define AT_MAP_SUCCESS     (0)
#define AT_MAP_ERR_INVAL   (-1)
#define AT_MAP_ERR_AGAIN   (-2)
#define AT_MAP_ERR_CORRUPT (-3)
#define AT_MAP_ERR_EMPTY   (-4)
#define AT_MAP_ERR_FULL    (-5)
#define AT_MAP_ERR_KEY     (-6)

/* Common map flags (note that different maps support different subsets
   of these flags) */

#define AT_MAP_FLAG_BLOCKING      (1<<0)
#define AT_MAP_FLAG_ADAPTIVE      (1<<1)
#define AT_MAP_FLAG_USE_HINT      (1<<2)
#define AT_MAP_FLAG_PREFETCH_NONE (0<<3)
#define AT_MAP_FLAG_PREFETCH_META (1<<3)
#define AT_MAP_FLAG_PREFETCH_DATA (2<<3)
#define AT_MAP_FLAG_PREFETCH      (3<<3)
#define AT_MAP_FLAG_RDONLY        (1<<5)

struct at_map_chain_iter { /* FIXME: why is this here? */
  ulong chain_rem;
  ulong ele_idx;
};

AT_PROTOTYPES_BEGIN

AT_FN_CONST char const *
at_map_strerror( int err );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_util_tmpl_at_map_h */