#ifndef HEADER_at_src_ballet_chacha_at_chacha_h
#define HEADER_at_src_ballet_chacha_at_chacha_h

/* at_chacha.h - ChaCha20 Stream Cipher (RFC 8439)

   ChaCha20 is a stream cipher designed by Daniel J. Bernstein.
   This implementation follows RFC 8439 for use with Poly1305 AEAD.
*/

#include "at_crypto_base.h"

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* Constants                                                          */
/**********************************************************************/

/* AT_CHACHA_BLOCK_SZ is the output size of the ChaCha20 block function. */
#define AT_CHACHA_BLOCK_SZ (64UL)

/* AT_CHACHA_KEY_SZ is the size of the ChaCha20 encryption key */
#define AT_CHACHA_KEY_SZ (32UL)

/* AT_CHACHA_NONCE_SZ is the size of the ChaCha20 nonce (96 bits) */
#define AT_CHACHA_NONCE_SZ (12UL)

/**********************************************************************/
/* Block Function                                                     */
/**********************************************************************/

/* at_chacha20_block is the ChaCha20 block function.

   - block points to the output block (64 byte size, 64 byte align)
   - key points to the encryption key (32 byte size, 32 byte align)
   - idx_nonce points to the block index and block nonce
     (first 4 bytes: 32-bit block counter, next 12 bytes: nonce)
     (16 byte size, 16 byte align)

   Returns block. */

void *
at_chacha8_block( void *       block,
                  void const * key,
                  void const * idx_nonce );

void *
at_chacha20_block( void *       block,
                   void const * key,
                   void const * idx_nonce );

/**********************************************************************/
/* Stream Cipher                                                      */
/**********************************************************************/

/* at_chacha20_ctx_t holds the state for ChaCha20 stream encryption.
   Must be 64-byte aligned for block function.
   IMPORTANT: block MUST be first to ensure 64-byte alignment for AVX. */

typedef struct __attribute__((aligned(64))) {
  uchar block[64];         /* Current keystream block - MUST be first for alignment */
  uchar key[32];           /* Encryption key */
  uchar nonce[12];         /* Nonce */
  uint  counter;           /* Block counter */
  uint  block_offset;      /* Offset within current block */
} at_chacha20_ctx_t;

/* at_chacha20_init initializes a ChaCha20 context.
   key is 32 bytes, nonce is 12 bytes.
   counter is the initial block counter (usually 0 or 1). */
void
at_chacha20_init( at_chacha20_ctx_t * ctx,
                  uchar const         key[32],
                  uchar const         nonce[12],
                  uint                counter );

/* at_chacha20_crypt encrypts or decrypts data in place.
   ChaCha20 is symmetric - same operation for encrypt and decrypt.
   Returns out. */
void *
at_chacha20_crypt( at_chacha20_ctx_t * ctx,
                   void *              out,
                   void const *        in,
                   ulong               len );

/* at_chacha20_keystream generates keystream bytes.
   Useful for generating Poly1305 key. */
void
at_chacha20_keystream( at_chacha20_ctx_t * ctx,
                       void *              out,
                       ulong               len );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_ballet_chacha_at_chacha_h */