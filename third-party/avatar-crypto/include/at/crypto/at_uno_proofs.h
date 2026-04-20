#ifndef HEADER_at_crypto_at_uno_proofs_h
#define HEADER_at_crypto_at_uno_proofs_h

/* at_uno_proofs.h - UNO Zero-Knowledge Proof Structures

   This module implements the cryptographic proof structures used in
   TOS UNO (privacy) transactions:

   1. ShieldCommitmentProof (96 bytes)
      - Proves that a Pedersen commitment C = amount*G + r*H contains
        the claimed amount, and that the handle D = r*P uses the same
        randomness r.

   2. CiphertextValidityProof (128 or 160 bytes)
      - Proves that a ciphertext (commitment, handle) is correctly formed
      - T0 version: 128 bytes (Y_0, Y_1, z_r, z_x)
      - T1 version: 160 bytes (Y_0, Y_1, Y_2, z_r, z_x)

   Reference: TOS Rust implementation in common/src/crypto/proofs/
*/

#include "at_merlin.h"
#include "at_ristretto255.h"

AT_PROTOTYPES_BEGIN

typedef struct at_uno_batch_collector at_uno_batch_collector_t;

/**********************************************************************/
/* ShieldCommitmentProof (96 bytes)                                    */
/**********************************************************************/

/* ShieldCommitmentProof proves knowledge of (amount, r) such that:
   - C = amount*G + r*H  (Pedersen commitment)
   - D = r*P             (decryption handle)

   This is a Schnorr-like sigma protocol made non-interactive via
   Fiat-Shamir using a Merlin transcript.

   Wire format (96 bytes):
   - Y_H [32 bytes]: k*H commitment
   - Y_P [32 bytes]: k*P commitment
   - z   [32 bytes]: response scalar

   Verification:
   1. Compute challenge c = Hash(transcript || C || D || Y_H || Y_P)
   2. Check: z*H == Y_H + c*(C - amount*G)
   3. Check: z*P == Y_P + c*D
*/

typedef struct {
  uchar Y_H[32];   /* k*H commitment */
  uchar Y_P[32];   /* k*P commitment */
  uchar z[32];     /* Response scalar */
} at_shield_proof_t;

/* Parse ShieldCommitmentProof from wire format.
   Returns 0 on success, -1 on error. */
int
at_shield_proof_parse( uchar const          data[96],
                        at_shield_proof_t * out );

/* Verify ShieldCommitmentProof.
   Returns 0 if valid, -1 if invalid. */
int
at_shield_proof_verify( at_shield_proof_t const *   proof,
                         uchar const                commitment[32],
                         uchar const                receiver_handle[32],
                         uchar const                receiver_pubkey[32],
                         ulong                      amount,
                         at_merlin_transcript_t *   transcript );

/**********************************************************************/
/* CiphertextValidityProof (128 or 160 bytes)                          */
/**********************************************************************/

/* CiphertextValidityProof proves that a ciphertext is correctly formed:
   - C = amount*G + r*H  (Pedersen commitment)
   - D_sender = r*P_sender
   - D_receiver = r*P_receiver (if applicable)

   T0 version (128 bytes):
   - Y_0  [32 bytes]: First commitment point
   - Y_1  [32 bytes]: Second commitment point
   - z_r  [32 bytes]: Response for randomness
   - z_x  [32 bytes]: Response for amount

   T1 version (160 bytes):
   - Y_0  [32 bytes]: First commitment point
   - Y_1  [32 bytes]: Second commitment point
   - Y_2  [32 bytes]: Sender authentication point
   - z_r  [32 bytes]: Response for randomness
   - z_x  [32 bytes]: Response for amount
*/

typedef struct {
  uchar Y_0[32];   /* First commitment point */
  uchar Y_1[32];   /* Second commitment point */
  int   has_Y_2;   /* 1 if T1 version with Y_2 */
  uchar Y_2[32];   /* Sender authentication point (T1 only) */
  uchar z_r[32];   /* Response scalar (randomness) */
  uchar z_x[32];   /* Response scalar (amount) */
} at_ct_validity_proof_t;

/* Parse CiphertextValidityProof from wire format.
   tx_version_t1: 1 for T1 format (160 bytes), 0 for T0 (128 bytes).
   bytes_read: set to number of bytes consumed.
   Returns 0 on success, -1 on error. */
int
at_ct_validity_proof_parse( uchar const              * data,
                             ulong                    data_sz,
                             int                      tx_version_t1,
                             at_ct_validity_proof_t * out,
                             ulong *                  bytes_read );

/* Verify CiphertextValidityProof.
   TOS Rust mapping:
   - Y_1 is verified against receiver (destination): z_r*P_receiver == Y_1 + c*D_receiver
   - Y_2 (T1 only) is verified against sender (source): z_r*P_sender == Y_2 + c*D_sender

   receiver_handle and receiver_pubkey are ALWAYS required (for Y_1).
   sender_handle and sender_pubkey are required for T1 (for Y_2).
   Returns 0 if valid, -1 if invalid. */
int
at_ct_validity_proof_verify( at_ct_validity_proof_t const * proof,
                              uchar const                    commitment[32],
                              uchar const                    sender_handle[32],
                              uchar const                    receiver_handle[32],
                              uchar const                    sender_pubkey[32],
                              uchar const                    receiver_pubkey[32],
                              int                            tx_version_t1,
                              at_merlin_transcript_t *       transcript );

/**********************************************************************/
/* CommitmentEqProof / BalanceProof                                    */
/**********************************************************************/

typedef struct {
  uchar Y_0[32];
  uchar Y_1[32];
  uchar Y_2[32];
  uchar z_s[32];
  uchar z_x[32];
  uchar z_r[32];
} at_commitment_eq_proof_t;

#define AT_COMMITMENT_EQ_PROOF_SZ (192UL)

int
at_commitment_eq_proof_parse( uchar const *            data,
                              ulong                    data_sz,
                              at_commitment_eq_proof_t * out );

/* source_ciphertext = commitment(32) || handle(32), destination_commitment=32 */
int
at_commitment_eq_proof_verify( at_commitment_eq_proof_t const * proof,
                               uchar const                      source_pubkey[32],
                               uchar const                      source_ciphertext[64],
                               uchar const                      destination_commitment[32],
                               at_merlin_transcript_t *         transcript );

int
at_commitment_eq_proof_pre_verify( at_commitment_eq_proof_t const * proof,
                                   uchar const                      source_pubkey[32],
                                   uchar const                      source_ciphertext[64],
                                   uchar const                      destination_commitment[32],
                                   at_merlin_transcript_t *         transcript,
                                   at_uno_batch_collector_t *       collector );

typedef struct {
  ulong amount;
  at_commitment_eq_proof_t commitment_eq_proof;
} at_balance_proof_t;

#define AT_BALANCE_PROOF_SZ (8UL + AT_COMMITMENT_EQ_PROOF_SZ)

int
at_balance_proof_parse( uchar const *         data,
                        ulong                 data_sz,
                        at_balance_proof_t *  out );

/* source_ciphertext = commitment(32) || handle(32) */
int
at_balance_proof_verify( at_balance_proof_t const * proof,
                         uchar const               public_key[32],
                         uchar const               source_ciphertext[64] );

int
at_balance_proof_pre_verify( at_balance_proof_t const * proof,
                             uchar const                public_key[32],
                             uchar const                source_ciphertext[64],
                             at_merlin_transcript_t *   transcript,
                             at_uno_batch_collector_t * collector );

/**********************************************************************/
/* Transcript Domain Separators                                        */
/**********************************************************************/

/* These must match TOS Rust exactly for proof compatibility.
   See: common/src/crypto/transcript.rs

   TOS Rust uses:
   - append_message(b"dom-sep", b"shield-commitment-proof")
   - append_message(b"dom-sep", b"validity-proof")
*/

#define AT_PROOF_DOMAIN_SEP_LABEL "dom-sep"
#define AT_SHIELD_PROOF_DOMAIN    "shield-commitment-proof"
#define AT_CT_VALIDITY_DOMAIN     "validity-proof"
#define AT_EQ_PROOF_DOMAIN        "equality-proof"
#define AT_NEW_COMMITMENT_EQ_PROOF_DOMAIN "new-commitment-proof"
#define AT_BALANCE_PROOF_DOMAIN   "balance-proof"
#define AT_OWNERSHIP_PROOF_DOMAIN "ownership-proof"

/* Transcript labels - must match TOS Rust exactly */
#define AT_PROOF_LABEL_Y_H        "Y_H"
#define AT_PROOF_LABEL_Y_P        "Y_P"
#define AT_PROOF_LABEL_Y_0        "Y_0"
#define AT_PROOF_LABEL_Y_1        "Y_1"
#define AT_PROOF_LABEL_Y_2        "Y_2"
#define AT_PROOF_LABEL_Z_S        "z_s"
#define AT_PROOF_LABEL_Z_X        "z_x"
#define AT_PROOF_LABEL_Z_R        "z_r"
#define AT_PROOF_LABEL_CHALLENGE  "c"
#define AT_PROOF_LABEL_FINALIZE   "w"

/**********************************************************************/
/* Generator Points                                                    */
/**********************************************************************/

/* Standard Ristretto255 basepoint G (matches dalek/curve25519-dalek) */
extern uchar const AT_RISTRETTO_BASEPOINT_COMPRESSED[32];

/* Pedersen commitment generator H (matches TOS Rust bulletproofs) */
extern uchar const AT_PEDERSEN_H_COMPRESSED[32];

/**********************************************************************/
/* Batch-preverify Compatibility Layer                                 */
/**********************************************************************/

/* C path verifies equations individually. This collector is provided to keep
   API parity with Rust pre_verify/batch flows used by higher layers. */
struct at_uno_batch_collector {
  uint reserved;
};

typedef struct at_uno_batch_collector at_uno_batch_collector_t;

static inline void
at_uno_batch_collector_init( at_uno_batch_collector_t * c ) {
  if( c ) c->reserved = 0u;
}

/* Returns 0 to indicate "collected equations verify".
   In C implementation equations are checked eagerly in pre_verify wrappers. */
static inline int
at_uno_batch_collector_verify( at_uno_batch_collector_t const * c ) {
  (void)c;
  return 0;
}

/* Pre-verify wrappers (currently eager single-proof verification). */
int
at_shield_proof_pre_verify( at_shield_proof_t const *   proof,
                            uchar const                commitment[32],
                            uchar const                receiver_handle[32],
                            uchar const                receiver_pubkey[32],
                            ulong                      amount,
                            at_merlin_transcript_t *   transcript,
                            at_uno_batch_collector_t * collector );

int
at_ct_validity_proof_pre_verify( at_ct_validity_proof_t const * proof,
                                 uchar const                    commitment[32],
                                 uchar const                    sender_handle[32],
                                 uchar const                    receiver_handle[32],
                                 uchar const                    sender_pubkey[32],
                                 uchar const                    receiver_pubkey[32],
                                 int                            tx_version_t1,
                                 at_merlin_transcript_t *       transcript,
                                 at_uno_batch_collector_t *     collector );

AT_PROTOTYPES_END

#endif /* HEADER_at_crypto_at_uno_proofs_h */
