#ifndef HEADER_at_features_at_features_h
#define HEADER_at_features_at_features_h

/* TOS/Avatar feature flags
   This provides compile-time and runtime feature flag management
   for protocol upgrades and feature gates. */

#include "at/infra/at_util_base.h"

/* Feature flags structure - tracks which features are enabled */
struct at_features {
  /* VM-related features */
  uchar enable_tbpf_v1;           /* Enable TBPF v1 instructions */
  uchar enable_tbpf_v2;           /* Enable TBPF v2 instructions */
  uchar enable_tbpf_v3;           /* Enable TBPF v3 instructions */
  uchar static_syscalls;          /* Use static syscall registration */
  uchar direct_mapping;           /* Enable direct memory mapping */
  uchar disable_fees;             /* Disable transaction fees (testing) */
  uchar bpf_account_data_direct_mapping; /* Direct mapping for account data */

  /* CPI-related features */
  uchar loosen_cpi_size_restriction; /* Allow larger CPI data */
  uchar increase_cpi_account_info_limit; /* SIMD-0339 */

  /* Reserved for future use */
  uchar _reserved[23];
};
typedef struct at_features at_features_t;

AT_PROTOTYPES_BEGIN

/* Initialize features with default values (all disabled) */
static inline void
at_features_init( at_features_t * features ) {
  at_memset( features, 0, sizeof(at_features_t) );
}

/* Enable all features (for testing) */
static inline void
at_features_enable_all( at_features_t * features ) {
  features->enable_tbpf_v1 = 1;
  features->enable_tbpf_v2 = 1;
  features->enable_tbpf_v3 = 1;
  features->static_syscalls = 1;
  features->direct_mapping = 1;
}

/* Check if a specific TBPF version is enabled */
static inline int
at_features_tbpf_version_enabled( at_features_t const * features, uint version ) {
  if( !features ) return 1; /* Default: all versions enabled if no features struct */
  switch( version ) {
    case 0: return 1; /* V0 always enabled */
    case 1: return features->enable_tbpf_v1;
    case 2: return features->enable_tbpf_v2;
    case 3: return features->enable_tbpf_v3;
    default: return 0;
  }
}

AT_PROTOTYPES_END

#endif /* HEADER_at_features_at_features_h */