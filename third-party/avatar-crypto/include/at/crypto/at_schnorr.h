#ifndef HEADER_at_src_ballet_schnorr_at_schnorr_h
#define HEADER_at_src_ballet_schnorr_at_schnorr_h

/* at_schnorr.h provides the TOS-compatible Schnorr signature API.

   This implements TOS's custom Schnorr-variant signature scheme:
   - Curve: Ristretto255
   - Hash: SHA3-512
   - Signature format: (s, e) - two 32-byte scalars

   Algorithm:
   - Public key: PK = priv^(-1) * H, where H is the Pedersen blinding generator
   - Sign: e = SHA3-512(PK || message || r), s = priv^(-1) * e + k, where r = k * H
   - Verify: r = s*H - e*PK, check if e == SHA3-512(PK || message || r)

   Note: This is NOT standard Ed25519 or standard Schnorr. It's a TOS-specific
   variant that uses inverted private keys and the Pedersen blinding generator. */

#include "at_ristretto255.h"
#include "at_curve25519_scalar.h"

/* Size constants */
#define AT_SCHNORR_SIGNATURE_SZ (64UL)  /* Two 32-byte scalars: s || e */
#define AT_SCHNORR_PUBLIC_KEY_SZ (32UL) /* Compressed Ristretto point */
#define AT_SCHNORR_PRIVATE_KEY_SZ (32UL) /* Scalar */

/* The H generator point (Pedersen blinding generator from bulletproofs)
   This is PedersenGens::default().B_blinding in compressed form.
   Hex: 8c9240b456a9e6dc65c377a1048d745f94a08cdb7f44cbcd7b46f34048871134 */
static const uchar at_schnorr_h_generator[ 32 ] = {
  0x8c, 0x92, 0x40, 0xb4, 0x56, 0xa9, 0xe6, 0xdc,
  0x65, 0xc3, 0x77, 0xa1, 0x04, 0x8d, 0x74, 0x5f,
  0x94, 0xa0, 0x8c, 0xdb, 0x7f, 0x44, 0xcb, 0xcd,
  0x7b, 0x46, 0xf3, 0x40, 0x48, 0x87, 0x11, 0x34
};

/* at_schnorr_signature_t holds a TOS Schnorr signature.
   Format: first 32 bytes = s, next 32 bytes = e */
typedef struct {
  uchar s[ 32 ]; /* First scalar */
  uchar e[ 32 ]; /* Second scalar (hash result) */
} at_schnorr_signature_t;

AT_PROTOTYPES_BEGIN

/* at_schnorr_public_key_from_private computes the public key from a private key.

   public_key = private_key^(-1) * H

   private_key must be a valid non-zero scalar (32 bytes).
   public_key receives the compressed Ristretto point (32 bytes).

   Returns public_key on success, NULL if private_key is invalid. */

uchar *
at_schnorr_public_key_from_private( uchar       public_key [ 32 ],
                                    uchar const private_key[ 32 ] );

/* at_schnorr_sign creates a TOS Schnorr signature.

   Computes:
     k = random nonce
     r = k * H
     e = SHA3-512(public_key || message || r) mod L
     s = private_key^(-1) * e + k
     signature = (s, e)

   private_key: 32-byte scalar (must be valid non-zero scalar)
   public_key: 32-byte compressed Ristretto point (must match private_key)
   message: arbitrary length message to sign
   message_sz: length of message in bytes
   signature: receives the 64-byte signature (s || e)

   Returns signature on success, NULL on failure. */

at_schnorr_signature_t *
at_schnorr_sign( at_schnorr_signature_t * signature,
                 uchar const              private_key[ 32 ],
                 uchar const              public_key [ 32 ],
                 void const *             message,
                 ulong                    message_sz );

/* at_schnorr_sign_deterministic creates a TOS Schnorr signature with a
   deterministic nonce k.

   This function is primarily for testing. In production, use at_schnorr_sign
   which generates a random nonce.

   k: 32-byte scalar to use as nonce (for testing purposes)

   Returns signature on success, NULL on failure. */

at_schnorr_signature_t *
at_schnorr_sign_deterministic( at_schnorr_signature_t * signature,
                               uchar const              private_key[ 32 ],
                               uchar const              public_key [ 32 ],
                               void const *             message,
                               ulong                    message_sz,
                               uchar const              k[ 32 ] );

/* at_schnorr_verify verifies a TOS Schnorr signature.

   Computes:
     r = s*H - e*PK
     e' = SHA3-512(public_key || message || r) mod L
     return e == e'

   signature: 64-byte signature (s || e)
   public_key: 32-byte compressed Ristretto point
   message: arbitrary length message
   message_sz: length of message in bytes

   Returns 1 if signature is valid, 0 if invalid. */

int
at_schnorr_verify( at_schnorr_signature_t const * signature,
                   uchar const                    public_key[ 32 ],
                   void const *                   message,
                   ulong                          message_sz );

/* at_schnorr_verify_batch verifies multiple TOS Schnorr signatures.

   This function provides a convenient API for verifying multiple signatures.
   Due to the TOS Schnorr variant's structure (where R must be computed from
   (s, e) to verify e' == e), true batch verification with combined MSM is
   not applicable. The function verifies each signature sequentially but
   shares the H generator point decompression across all verifications.

   Note: The Straus MSM algorithm (at_ed25519_multi_scalar_mul_straus) is
   available for use cases where true batching applies, such as range proof
   verification or other protocols with batch-friendly equations.

   sigs:     Array of n signatures
   pks:      Array of n compressed public keys (32 bytes each)
   msgs:     Array of n message pointers
   msg_lens: Array of n message lengths
   n:        Number of signatures to verify

   Returns 1 if ALL signatures are valid, 0 if any signature is invalid.
   For n=0, returns 1 (vacuously true).
   For n=1, behaves identically to at_schnorr_verify. */

int
at_schnorr_verify_batch( at_schnorr_signature_t const * sigs,
                         uchar const                  * pks,      /* n * 32 bytes */
                         void const * const           * msgs,
                         ulong const                  * msg_lens,
                         ulong                          n );

/* at_schnorr_signature_to_bytes serializes a signature to a 64-byte array. */

static inline uchar *
at_schnorr_signature_to_bytes( uchar                          out[ 64 ],
                               at_schnorr_signature_t const * sig ) {
  at_memcpy( out,      sig->s, 32 );
  at_memcpy( out + 32, sig->e, 32 );
  return out;
}

/* at_schnorr_signature_from_bytes deserializes a 64-byte array to a signature.
   Returns sig on success, NULL if the scalars are invalid. */

static inline at_schnorr_signature_t *
at_schnorr_signature_from_bytes( at_schnorr_signature_t * sig,
                                 uchar const              in[ 64 ] ) {
  /* Validate that both s and e are valid scalars */
  if( !at_curve25519_scalar_validate( in ) ) return NULL;
  if( !at_curve25519_scalar_validate( in + 32 ) ) return NULL;

  at_memcpy( sig->s, in,      32 );
  at_memcpy( sig->e, in + 32, 32 );
  return sig;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_src_ballet_schnorr_at_schnorr_h */