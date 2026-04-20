#ifndef HEADER_at_ballet_at_poly1305_h
#define HEADER_at_ballet_at_poly1305_h

/* at_poly1305.h - Poly1305 Message Authentication Code (RFC 8439)

   Poly1305 is a one-time authenticator designed by Daniel J. Bernstein.
   It takes a 32-byte one-time key and a message and produces a 16-byte tag.

   IMPORTANT: The key must never be reused for different messages.
   When used with ChaCha20, a unique key is derived for each message
   using the ChaCha20 keystream.
*/

#include "at_crypto_base.h"

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* Constants                                                          */
/**********************************************************************/

#define AT_POLY1305_KEY_SZ  (32UL)
#define AT_POLY1305_TAG_SZ  (16UL)

/**********************************************************************/
/* Context                                                            */
/**********************************************************************/

/* Poly1305 state for incremental computation.
   Uses 130-bit arithmetic internally. */

typedef struct {
  /* Accumulator (5 x 26-bit limbs for 130-bit number) */
  uint h[5];

  /* r key (clamped, 5 x 26-bit limbs) */
  uint r[5];

  /* s key (added at end) */
  uint s[4];

  /* Partial block buffer */
  uchar buf[16];
  ulong buf_len;

} at_poly1305_ctx_t;

/**********************************************************************/
/* One-Shot API                                                       */
/**********************************************************************/

/* at_poly1305 computes the Poly1305 tag for a message.
   key is 32 bytes (r || s), msg is the message, tag receives 16 bytes.
   Returns tag. */
uchar *
at_poly1305( uchar         tag[16],
             uchar const   key[32],
             uchar const * msg,
             ulong         msg_len );

/**********************************************************************/
/* Incremental API                                                    */
/**********************************************************************/

/* at_poly1305_init initializes a Poly1305 context with a key.
   key is 32 bytes (r || s). */
void
at_poly1305_init( at_poly1305_ctx_t * ctx,
                  uchar const         key[32] );

/* at_poly1305_update adds message bytes to the computation. */
void
at_poly1305_update( at_poly1305_ctx_t * ctx,
                    uchar const *       msg,
                    ulong               msg_len );

/* at_poly1305_final finalizes and outputs the 16-byte tag.
   The context should not be used after this call. */
void
at_poly1305_final( at_poly1305_ctx_t * ctx,
                   uchar               tag[16] );

/**********************************************************************/
/* Verification                                                       */
/**********************************************************************/

/* at_poly1305_verify computes tag and compares in constant time.
   Returns 1 if tags match, 0 otherwise. */
int
at_poly1305_verify( uchar const   expected[16],
                    uchar const   key[32],
                    uchar const * msg,
                    ulong         msg_len );

AT_PROTOTYPES_END

#endif /* HEADER_at_ballet_at_poly1305_h */