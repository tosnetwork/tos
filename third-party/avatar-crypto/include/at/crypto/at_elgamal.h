#ifndef HEADER_at_crypto_at_elgamal_h
#define HEADER_at_crypto_at_elgamal_h

/* ElGamal and Pedersen helpers for UNO privacy primitives.

   This header provides:
   - Low-level compressed ciphertext arithmetic
   - Compressed wrapper types (commitment/handle/ciphertext/public key)
   - Pedersen opening + commitment construction
   - ElGamal keypair generation/encryption/decryption-to-point
   - Schnorr-variant signing wrappers for ElGamal keypairs
*/

#include "at_ristretto255.h"
#include "at_curve25519_scalar.h"
#include "at_schnorr.h"
#include "at_bech32.h"

AT_PROTOTYPES_BEGIN

#define AT_ELGAMAL_COMPRESSED_POINT_SZ (32UL)
#define AT_ELGAMAL_SCALAR_SZ           (32UL)
#define AT_ELGAMAL_CIPHERTEXT_SZ       (64UL)

typedef struct {
  at_ristretto255_point_t commitment;
  at_ristretto255_point_t handle;
} at_elgamal_ct_t;

typedef struct {
  uchar bytes[ AT_ELGAMAL_COMPRESSED_POINT_SZ ];
} at_elgamal_compressed_commitment_t;

typedef struct {
  uchar bytes[ AT_ELGAMAL_COMPRESSED_POINT_SZ ];
} at_elgamal_compressed_handle_t;

typedef struct {
  uchar bytes[ AT_ELGAMAL_CIPHERTEXT_SZ ];
} at_elgamal_compressed_ciphertext_t;

typedef struct {
  uchar bytes[ AT_ELGAMAL_COMPRESSED_POINT_SZ ];
} at_elgamal_public_key_t;

typedef struct {
  uchar bytes[ AT_ELGAMAL_SCALAR_SZ ];
} at_elgamal_private_key_t;

typedef struct {
  uchar bytes[ AT_ELGAMAL_SCALAR_SZ ];
} at_pedersen_opening_t;

typedef struct {
  at_elgamal_public_key_t  public_key;
  at_elgamal_private_key_t private_key;
} at_elgamal_keypair_t;

/* Decompress 64-byte ciphertext (commitment||handle) into points. */
int
at_elgamal_ct_decompress( at_elgamal_ct_t * out,
                          uchar const      in[64] );

/* Build ciphertext from compressed commitment and handle points. */
int
at_elgamal_ct_new( at_elgamal_ct_t * out,
                   uchar const       commitment[32],
                   uchar const       handle[32] );

/* Compress ciphertext points into 64-byte (commitment||handle). */
void
at_elgamal_ct_compress( uchar out[64],
                        at_elgamal_ct_t const * in );

/* Homomorphic add/sub on ciphertexts (point-wise). */
void
at_elgamal_ct_add( at_elgamal_ct_t *       out,
                   at_elgamal_ct_t const * a,
                   at_elgamal_ct_t const * b );

void
at_elgamal_ct_sub( at_elgamal_ct_t *       out,
                   at_elgamal_ct_t const * a,
                   at_elgamal_ct_t const * b );

/* Set ciphertext to identity (zero value). */
void
at_elgamal_ct_set_zero( at_elgamal_ct_t * out );

/* Add/sub plaintext amount on commitment component only. */
int
at_elgamal_ct_add_amount( at_elgamal_ct_t *       out,
                          at_elgamal_ct_t const * in,
                          ulong                    amount );

int
at_elgamal_ct_sub_amount( at_elgamal_ct_t *       out,
                          at_elgamal_ct_t const * in,
                          ulong                    amount );

/* Add/sub scalar*G on commitment component only. */
int
at_elgamal_ct_add_scalar( at_elgamal_ct_t *       out,
                          at_elgamal_ct_t const * in,
                          uchar const              scalar[32] );

int
at_elgamal_ct_sub_scalar( at_elgamal_ct_t *       out,
                          at_elgamal_ct_t const * in,
                          uchar const              scalar[32] );

/* Multiply both commitment and handle by scalar (32-byte canonical scalar). */
int
at_elgamal_ct_mul_scalar( at_elgamal_ct_t *       out,
                          at_elgamal_ct_t const * in,
                          uchar const              scalar[32] );

/* Compressed add/sub helpers. Returns 0 on success, -1 on invalid input. */
int
at_elgamal_ct_add_compressed( uchar out[64],
                              uchar const a[64],
                              uchar const b[64] );

int
at_elgamal_ct_sub_compressed( uchar out[64],
                              uchar const a[64],
                              uchar const b[64] );

/* Generate a random non-zero Pedersen opening scalar. */
int
at_pedersen_opening_generate( at_pedersen_opening_t * out );

/* Build Pedersen commitment C = amount*G + opening*H (compressed). */
int
at_pedersen_commitment_new_with_opening( at_elgamal_compressed_commitment_t * out,
                                          ulong                                 amount,
                                          at_pedersen_opening_t const *         opening );

/* Build Pedersen commitment with generated opening. opening_out may be NULL. */
int
at_pedersen_commitment_new( at_elgamal_compressed_commitment_t * out,
                            at_pedersen_opening_t *              opening_out,
                            ulong                                 amount );

/* Compute public key from private key: PK = priv^{-1} * H. */
int
at_elgamal_public_key_from_private( at_elgamal_public_key_t *  out,
                                    at_elgamal_private_key_t const * priv );

/* Generate random keypair. */
int
at_elgamal_keypair_generate( at_elgamal_keypair_t * out );

/* Build decrypt handle D = opening * PK (compressed). */
int
at_elgamal_decrypt_handle( at_elgamal_compressed_handle_t * out,
                           at_elgamal_public_key_t const *  public_key,
                           at_pedersen_opening_t const *    opening );

/* Encrypt amount with a caller-provided opening. */
int
at_elgamal_encrypt_with_opening( at_elgamal_compressed_ciphertext_t * out,
                                 at_elgamal_public_key_t const *       public_key,
                                 ulong                                  amount,
                                 at_pedersen_opening_t const *          opening );

/* Encrypt amount with generated opening. opening_out may be NULL. */
int
at_elgamal_encrypt( at_elgamal_compressed_ciphertext_t * out,
                    at_pedersen_opening_t *              opening_out,
                    at_elgamal_public_key_t const *      public_key,
                    ulong                                 amount );

/* Decrypt ciphertext to Ristretto point M = C - priv*D (compressed point bytes). */
int
at_elgamal_private_key_decrypt_to_point( uchar                                  out_point[32],
                                         at_elgamal_private_key_t const *       private_key,
                                         at_elgamal_compressed_ciphertext_t const * ciphertext );

/* Sign/verify wrappers using TOS Schnorr-variant on the same key material. */
int
at_elgamal_keypair_sign( at_schnorr_signature_t *        signature,
                         at_elgamal_keypair_t const *     keypair,
                         void const *                     message,
                         ulong                            message_sz );

int
at_elgamal_signature_verify( at_schnorr_signature_t const * signature,
                             at_elgamal_public_key_t const * public_key,
                             void const *                    message,
                             ulong                           message_sz );

/* Convert a (compressed) ElGamal public key to TOS bech32 address string.
   This covers Rust PublicKey::to_address and CompressedPublicKey::to_address
   for normal address type. */
int
at_elgamal_public_key_to_address( char *                            out,
                                  ulong                             out_sz,
                                  int                               mainnet,
                                  at_elgamal_public_key_t const *   public_key );

AT_PROTOTYPES_END

#endif /* HEADER_at_crypto_at_elgamal_h */
