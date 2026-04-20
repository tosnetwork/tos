#ifndef HEADER_at_src_ballet_aes_at_aes_gcm_ref_h
#define HEADER_at_src_ballet_aes_at_aes_gcm_ref_h

#include "at_aes_base.h"

union at_gcm128 {
  struct {
    ulong hi;
    ulong lo;
  };
# if AT_HAS_INT128
  uint128 u128;
# endif
};

typedef union at_gcm128 at_gcm128_t;

struct __attribute__((aligned(64UL))) at_aes_gcm_ref_state {
  /* Offset of Yi, EKi, EK0, len, Xi, H, and Htable is hardcoded in
     asm modules -- Do not change offsets */

  /* Following 6 names follow names in GCM specification */
  union {
    ulong u[ 2];
    uint  d[ 4];
    uchar c[16];
    ulong t[ 2];
  } Yi, EKi, EK0, len, Xi, H;
  at_gcm128_t Htable[16];

  uint    mres, ares;
  uchar   Xn[48];

  at_aes_key_ref_t key;
};
typedef struct at_aes_gcm_ref_state at_aes_gcm_ref_t;

void
at_gcm_init_4bit( at_gcm128_t Htable[16],
                  ulong const H[2] );

void
at_gcm_gmult_4bit( ulong         Xi[2],
                   at_gcm128_t const Htable[16] );

void
at_gcm_ghash_4bit( ulong             Xi[2],
                   at_gcm128_t const Htable[16],
                   uchar const *     in,
                   ulong             len );

AT_PROTOTYPES_BEGIN

void
at_aes_128_gcm_init_ref( at_aes_gcm_ref_t * gcm,
                         uchar const        key[ 16 ],
                         uchar const        iv [ 12 ] );

void
at_aes_256_gcm_init_ref( at_aes_gcm_ref_t * gcm,
                         uchar const        key[ 32 ],
                         uchar const        iv [ 12 ] );

void
at_aes_gcm_encrypt_ref( at_aes_gcm_ref_t * aes_gcm,
                        uchar *            c,
                        uchar const *      p,
                        ulong              sz,
                        uchar const *      aad,
                        ulong              aad_sz,
                        uchar              tag[ 16 ] );

int
at_aes_gcm_decrypt_ref( at_aes_gcm_ref_t * aes_gcm,
                        uchar const *      c,
                        uchar *            p,
                        ulong              sz,
                        uchar const *      aad,
                        ulong              aad_sz,
                        uchar const        tag[ 16 ] );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_ballet_aes_at_aes_gcm_ref_h */