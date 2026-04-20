#ifndef HEADER_at_src_ballet_aes_at_aes_base_h
#define HEADER_at_src_ballet_aes_at_aes_base_h

#include "at_crypto_base.h"
#include "at/infra/sanitize/at_msan.h"

#define AT_AES_128_KEY_SZ (16UL)

/* Reference backend internals ****************************************/

struct at_aes_key_ref {
  uint rd_key[ 60 ];
  int  rounds;
};

typedef struct at_aes_key_ref at_aes_key_ref_t;

AT_PROTOTYPES_BEGIN

int
at_aes_ref_set_encrypt_key( uchar const *      user_key,
                            ulong              bits,
                            at_aes_key_ref_t * key );

int
at_aes_ref_set_decrypt_key( uchar const *      user_key,
                            ulong              bits,
                            at_aes_key_ref_t * key );

void
at_aes_ref_encrypt_core( uchar const *            in,
                         uchar *                  out,
                         at_aes_key_ref_t const * key );

void
at_aes_ref_decrypt_core( uchar const *        in,
                         uchar *              out,
                         at_aes_key_ref_t const * key );

AT_PROTOTYPES_END

/* AES-NI backend internals *******************************************/

#if AT_HAS_AESNI

AT_PROTOTYPES_BEGIN

__attribute__((sysv_abi)) void
at_aesni_set_encrypt_key( uchar const *      user_key,
                          ulong              bits,
                          at_aes_key_ref_t * key );

__attribute__((sysv_abi)) void
at_aesni_set_decrypt_key( uchar const *      user_key,
                          ulong              bits,
                          at_aes_key_ref_t * key );

__attribute__((sysv_abi)) void
at_aesni_encrypt( uchar const *            in,
                  uchar *                  out,
                  at_aes_key_ref_t const * key );

__attribute__((sysv_abi)) void
at_aesni_decrypt( uchar const *            in,
                  uchar *                  out,
                  at_aes_key_ref_t const * key );

AT_PROTOTYPES_END

#endif /* AT_HAS_AESNI */

/* Backend selection **************************************************/

#if AT_HAS_AESNI
#define AT_AES_IMPL 1 /* AESNI */
#else
#define AT_AES_IMPL 0 /* Portable */
#endif

#if AT_AES_IMPL == 0

  typedef at_aes_key_ref_t               at_aes_key_t;
  #define at_aes_private_encrypt         at_aes_ref_encrypt_core
  #define at_aes_private_decrypt         at_aes_ref_decrypt_core
  #define at_aes_private_set_encrypt_key at_aes_ref_set_encrypt_key
  #define at_aes_private_set_decrypt_key at_aes_ref_set_decrypt_key

#elif AT_AES_IMPL == 1

  typedef at_aes_key_ref_t               at_aes_key_t;
  #define at_aes_private_encrypt         at_aesni_encrypt
  #define at_aes_private_decrypt         at_aesni_decrypt
  #define at_aes_private_set_encrypt_key at_aesni_set_encrypt_key
  #define at_aes_private_set_decrypt_key at_aesni_set_decrypt_key

#endif

static inline void
at_aes_set_encrypt_key( uchar const *  user_key,
                        ulong          bits,
                        at_aes_key_t * key ) {
  at_msan_check   ( user_key, bits/8               );
  at_msan_unpoison( key,      sizeof(at_aes_key_t) );
  at_aes_private_set_encrypt_key( user_key, bits, key );
}

static inline void
at_aes_set_decrypt_key( uchar const *  user_key,
                        ulong          bits,
                        at_aes_key_t * key ) {
  at_msan_check   ( user_key, bits/8               );
  at_msan_unpoison( key,      sizeof(at_aes_key_t) );
  at_aes_private_set_decrypt_key( user_key, bits, key );
}

static inline void
at_aes_encrypt( uchar const *        in,
                uchar *              out,
                at_aes_key_t const * key ) {
  at_msan_check   ( key, sizeof(at_aes_key_t) );
  at_msan_check   ( in,  16UL );
  at_msan_unpoison( out, 16UL );
  at_aes_private_encrypt( in, out, key );
}

static inline void
at_aes_decrypt( uchar const *        in,
                uchar *              out,
                at_aes_key_t const * key ) {
  at_msan_check   ( key, sizeof(at_aes_key_t) );
  at_msan_check   ( in,  16UL );
  at_msan_unpoison( out, 16UL );
  at_aes_private_decrypt( in, out, key );
}

#endif /* HEADER_at_src_ballet_aes_at_aes_base_h */