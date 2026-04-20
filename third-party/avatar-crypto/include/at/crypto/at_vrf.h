#ifndef HEADER_at_ballet_at_vrf_h
#define HEADER_at_ballet_at_vrf_h

/* at_vrf provides VRF (Verifiable Random Function) support using
   schnorrkel-compatible DLEQ proofs over Ristretto255.

   This implements the schnorrkel 0.11.x VRF algorithm with:
   - MiniSecretKey expansion with Ed25519 mode (divide by cofactor 8)
   - Merlin transcript for Fiat-Shamir heuristic
   - DLEQ proof construction with specific schnorrkel labels

   The domain separator "TOS-VRF-v1" is used for TOS compatibility.

   A VRF allows generating provably random values that can be verified
   by anyone with the public key. Key properties:
   - Deterministic: same input + key always produces same output
   - Unpredictable: output appears random without the secret key
   - Verifiable: anyone can verify the output was correctly generated */

#include "at_ristretto255.h"
#include "at_sha512.h"

/* VRF error codes */
#define AT_VRF_SUCCESS       ( 0) /* Operation was successful */
#define AT_VRF_ERR_PUBKEY    (-1) /* Invalid public key */
#define AT_VRF_ERR_PROOF     (-2) /* Invalid proof */
#define AT_VRF_ERR_OUTPUT    (-3) /* Invalid output */
#define AT_VRF_ERR_VERIFY    (-4) /* Verification failed */

/* VRF key sizes in bytes */
#define AT_VRF_PUBLIC_KEY_SZ  (32UL)
#define AT_VRF_SECRET_KEY_SZ  (32UL)
#define AT_VRF_OUTPUT_SZ      (32UL)
#define AT_VRF_PROOF_SZ       (64UL)

/* Maximum input length for VRF operations */
#define AT_VRF_MAX_INPUT_LEN  (256UL)

/* TOS VRF domain separator */
#define AT_VRF_TOS_CONTEXT    "TOS-VRF-v1"
#define AT_VRF_TOS_CONTEXT_SZ (10UL)

/* VRF public key (compressed Ristretto255 point) */
typedef uchar at_vrf_public_key_t[ AT_VRF_PUBLIC_KEY_SZ ];

/* VRF secret key (32-byte mini secret key) */
typedef uchar at_vrf_secret_key_t[ AT_VRF_SECRET_KEY_SZ ];

/* VRF output (compressed Ristretto255 point - the "pre-output") */
typedef uchar at_vrf_output_t[ AT_VRF_OUTPUT_SZ ];

/* VRF proof (64 bytes: c scalar + s scalar for DLEQ proof) */
typedef uchar at_vrf_proof_t[ AT_VRF_PROOF_SZ ];

/* Expanded keypair for signing operations.
   schnorrkel stores: scalar (32 bytes) + nonce_seed (32 bytes) + public_key (32 bytes) */
typedef struct at_vrf_keypair {
  uchar secret[ 32 ];  /* Secret scalar (after cofactor division) */
  uchar nonce[ 32 ];   /* Nonce seed for deterministic signing */
  uchar public_key[ AT_VRF_PUBLIC_KEY_SZ ];
} at_vrf_keypair_t;

AT_PROTOTYPES_BEGIN

/* at_vrf_keypair_from_seed expands a 32-byte seed (mini secret key)
   into a full VRF keypair using Ed25519-style expansion.

   keypair will be filled with the expanded keypair.
   seed is the 32-byte mini secret key.

   Returns keypair on success. */

at_vrf_keypair_t *
at_vrf_keypair_from_seed( at_vrf_keypair_t * keypair,
                          uchar const        seed[ 32 ] );

/* at_vrf_public_key extracts the public key from a keypair.

   public_key will be filled with the compressed public key.
   keypair is the expanded keypair.

   Returns public_key. */

uchar *
at_vrf_public_key( uchar                      public_key[ 32 ],
                   at_vrf_keypair_t const *   keypair );

/* at_vrf_sign generates a VRF output and proof for the given input.

   output will be filled with the 32-byte VRF output (pre-output).
   proof will be filled with the 64-byte DLEQ proof.
   input is the message to sign.
   input_sz is the length of the input (max AT_VRF_MAX_INPUT_LEN).
   keypair is the VRF keypair.

   Returns 0 on success, error code on failure. */

int
at_vrf_sign( uchar                    output[ 32 ],
             uchar                    proof[ 64 ],
             uchar const *            input,
             ulong                    input_sz,
             at_vrf_keypair_t const * keypair );

/* at_vrf_verify verifies a VRF proof.

   input is the message that was signed.
   input_sz is the length of the input.
   output is the claimed VRF output.
   proof is the VRF proof.
   public_key is the signer's public key.

   Returns AT_VRF_SUCCESS (0) if valid, or an error code. */

int
at_vrf_verify( uchar const * input,
               ulong         input_sz,
               uchar const   output[ 32 ],
               uchar const   proof[ 64 ],
               uchar const   public_key[ 32 ] );

/* at_vrf_strerror converts a VRF error code to a human-readable string.

   Returns a pointer to a static string. */

AT_FN_CONST char const *
at_vrf_strerror( int err );

AT_PROTOTYPES_END

#endif /* HEADER_at_ballet_at_vrf_h */