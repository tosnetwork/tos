#ifndef HEADER_at_ballet_at_chacha20_poly1305_h
#define HEADER_at_ballet_at_chacha20_poly1305_h

/* at_chacha20_poly1305.h - ChaCha20-Poly1305 AEAD (RFC 8439)

   ChaCha20-Poly1305 is an authenticated encryption with associated data
   (AEAD) algorithm that combines ChaCha20 stream cipher with Poly1305 MAC.

   This implementation is compatible with TOS Rust P2P encryption which uses
   the chacha20poly1305 crate (RustCrypto).

   Key:   32 bytes
   Nonce: 12 bytes (unique per message with same key)
   Tag:   16 bytes (appended to ciphertext)
*/

#include "at/crypto/at_chacha.h"
#include "at/crypto/at_poly1305.h"

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* Constants                                                          */
/**********************************************************************/

#define AT_CHACHA20_POLY1305_KEY_SZ   (32UL)
#define AT_CHACHA20_POLY1305_NONCE_SZ (12UL)
#define AT_CHACHA20_POLY1305_TAG_SZ   (16UL)

/* Error codes */
#define AT_CHACHA20_POLY1305_SUCCESS   (0)
#define AT_CHACHA20_POLY1305_ERR_INVAL (-1)
#define AT_CHACHA20_POLY1305_ERR_AUTH  (-2)  /* Authentication failed */

/**********************************************************************/
/* One-Shot API (recommended)                                         */
/**********************************************************************/

/* at_chacha20_poly1305_encrypt encrypts plaintext and produces ciphertext
   with authentication tag.

   Parameters:
     ciphertext  - Output buffer (must be plaintext_len + 16 bytes)
     key         - 32-byte encryption key
     nonce       - 12-byte nonce (must be unique for each message)
     aad         - Additional authenticated data (can be NULL if aad_len is 0)
     aad_len     - Length of AAD
     plaintext   - Input plaintext
     plaintext_len - Length of plaintext

   Returns ciphertext.
   Output format: [ciphertext (plaintext_len bytes)][tag (16 bytes)]
*/
uchar *
at_chacha20_poly1305_encrypt( uchar *       ciphertext,
                              uchar const   key[32],
                              uchar const   nonce[12],
                              uchar const * aad,
                              ulong         aad_len,
                              uchar const * plaintext,
                              ulong         plaintext_len );

/* at_chacha20_poly1305_decrypt decrypts ciphertext and verifies tag.

   Parameters:
     plaintext    - Output buffer (must be ciphertext_len - 16 bytes)
     key          - 32-byte encryption key
     nonce        - 12-byte nonce
     aad          - Additional authenticated data (can be NULL if aad_len is 0)
     aad_len      - Length of AAD
     ciphertext   - Input ciphertext with tag
     ciphertext_len - Length of ciphertext including 16-byte tag

   Returns:
     AT_CHACHA20_POLY1305_SUCCESS on success (plaintext is valid)
     AT_CHACHA20_POLY1305_ERR_AUTH if authentication fails (plaintext is zeroed)
     AT_CHACHA20_POLY1305_ERR_INVAL if parameters are invalid
*/
int
at_chacha20_poly1305_decrypt( uchar *       plaintext,
                              uchar const   key[32],
                              uchar const   nonce[12],
                              uchar const * aad,
                              ulong         aad_len,
                              uchar const * ciphertext,
                              ulong         ciphertext_len );

/**********************************************************************/
/* In-Place API (for TOS P2P compatibility)                           */
/**********************************************************************/

/* at_chacha20_poly1305_encrypt_in_place encrypts plaintext in place.
   Buffer must have 16 extra bytes for the tag.

   Parameters:
     buf      - Buffer containing plaintext, receives ciphertext + tag
     buf_len  - Length of plaintext (tag will be written at buf + buf_len)
     key      - 32-byte encryption key
     nonce    - 12-byte nonce
     aad      - Additional authenticated data (can be NULL)
     aad_len  - Length of AAD

   Returns 0 on success.
*/
int
at_chacha20_poly1305_encrypt_in_place( uchar *       buf,
                                       ulong         buf_len,
                                       uchar const   key[32],
                                       uchar const   nonce[12],
                                       uchar const * aad,
                                       ulong         aad_len );

/* at_chacha20_poly1305_decrypt_in_place decrypts ciphertext in place.

   Parameters:
     buf      - Buffer containing ciphertext + tag, receives plaintext
     buf_len  - Length of ciphertext including 16-byte tag
     key      - 32-byte encryption key
     nonce    - 12-byte nonce
     aad      - Additional authenticated data (can be NULL)
     aad_len  - Length of AAD

   Returns:
     AT_CHACHA20_POLY1305_SUCCESS on success
     AT_CHACHA20_POLY1305_ERR_AUTH if authentication fails (buffer is zeroed)
*/
int
at_chacha20_poly1305_decrypt_in_place( uchar *       buf,
                                       ulong         buf_len,
                                       uchar const   key[32],
                                       uchar const   nonce[12],
                                       uchar const * aad,
                                       ulong         aad_len );

AT_PROTOTYPES_END

#endif /* HEADER_at_ballet_at_chacha20_poly1305_h */