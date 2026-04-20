#ifndef HEADER_at_tos_at_txn_uno_h
#define HEADER_at_tos_at_txn_uno_h

/* at_txn_uno.h - TOS UNO (Privacy) Payload Structures

   Transaction Type Discriminators (5-7):
   - 5: UnoTransfers    - Private transfers within UNO
   - 6: Shield          - TOS -> UNO (enter privacy pool)
   - 7: Unshield        - UNO -> TOS (exit privacy pool)

   UNO uses Bulletproofs range proofs and Pedersen commitments for
   confidential transactions. Twisted ElGamal encryption is used for
   encrypted balances.

   Transaction Version:
   - T1 is the ONLY supported version (TOS Rust removed T0 support)
   - T0 (128-byte ct_proof without Y_2) is DEPRECATED and not accepted
   - T1 (160-byte ct_proof with Y_2) includes sender authentication

   Wire Format (Big-Endian, TOS Rust Compatible, T1 only):

   Shield (Type 6):
     [asset:32][destination:32][amount:8][extra_data?][commitment:32]
     [receiver_handle:32][proof:96]

   Unshield (Type 7):
     [asset:32][destination:32][amount:8][extra_data?][commitment:32]
     [sender_handle:32][ct_proof:160]

   UnoTransfer (Type 5):
     [asset:32][destination:32][extra_data?][commitment:32]
     [sender_handle:32][receiver_handle:32][ct_proof:160]

   Note: Source commitments and range proofs are parsed as part of the
   main transaction structure (at_txn_t), not in the payload.
*/

#include "at/transaction/at_txn.h"

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* UNO Constants                                                       */
/**********************************************************************/

/* Size constants */
#define AT_UNO_ASSET_SZ           (32UL)
#define AT_UNO_PUBKEY_SZ          (32UL)
#define AT_UNO_COMMITMENT_SZ      (32UL)
#define AT_UNO_HANDLE_SZ          (32UL)
#define AT_UNO_NULLIFIER_SZ       (32UL)
#define AT_UNO_MAX_TRANSFERS      (64UL)

/* Proof sizes */
#define AT_SHIELD_PROOF_SZ        (96UL)   /* Y_H + Y_P + z */
#define AT_CT_PROOF_T0_SZ         (128UL)  /* DEPRECATED: Y_0 + Y_1 + z_r + z_x (no Y_2) */
#define AT_CT_PROOF_T1_SZ         (160UL)  /* Y_0 + Y_1 + Y_2 + z_r + z_x (current) */
#define AT_CT_PROOF_SZ            AT_CT_PROOF_T1_SZ  /* Default: T1 only */

/* Asset identifiers (32 bytes each) */
static uchar const AT_UNO_ASSET_HASH[32] = {
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1
};

static uchar const AT_TOS_ASSET_HASH[32] = {
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

/**********************************************************************/
/* UNO Ciphertext (Twisted ElGamal)                                    */
/**********************************************************************/

/* ElGamal ciphertext for encrypted balance:
   - commitment: C = amount*G + r*H (Pedersen commitment)
   - handle: D = r*P (decryption handle, where P is recipient pubkey) */
typedef struct {
  uchar commitment[AT_UNO_COMMITMENT_SZ];
  uchar handle[AT_UNO_HANDLE_SZ];
} at_uno_ciphertext_t;

/**********************************************************************/
/* Shield Payload (Type 6)                                             */
/**********************************************************************/

/* Wire format:
   [asset:32][destination:32][amount:8][extra_data?][commitment:32]
   [receiver_handle:32][proof:96]

   extra_data is Option<Vec<u8>>:
   - 0x00 = None
   - 0x01 + [len:2] + [data:len] = Some(data) */

typedef struct {
  uchar  asset[AT_UNO_ASSET_SZ];
  uchar  destination[AT_UNO_PUBKEY_SZ];
  ulong  amount;
  uint   extra_data_off;     /* Offset in raw buffer (0 if None) */
  ushort extra_data_len;     /* Length of extra data (0 if None) */
  uchar  commitment[AT_UNO_COMMITMENT_SZ];
  uchar  receiver_handle[AT_UNO_HANDLE_SZ];
  uint   proof_off;          /* Offset to ShieldCommitmentProof (96 bytes) */
} at_shield_payload_t;

/* Minimum size: 32 + 32 + 8 + 1(None) + 32 + 32 + 96 = 233 bytes */
#define AT_SHIELD_PAYLOAD_MIN_SZ  (233UL)

/* Parse Shield payload from wire format.
   Returns 0 on success, -1 on error. */
static inline int
at_shield_parse( uchar const *        data,
                 ulong                data_sz,
                 uint                 base_off,
                 at_shield_payload_t * out ) {
  if( AT_UNLIKELY( data_sz < AT_SHIELD_PAYLOAD_MIN_SZ ) ) {
    return -1;
  }

  ulong off = 0;

  /* asset */
  at_memcpy( out->asset, data + off, AT_UNO_ASSET_SZ );
  off += AT_UNO_ASSET_SZ;

  /* destination */
  at_memcpy( out->destination, data + off, AT_UNO_PUBKEY_SZ );
  off += AT_UNO_PUBKEY_SZ;

  /* amount (u64 BE) */
  out->amount = at_be64_to_native( data + off );
  off += 8;

  /* Validate amount is non-zero */
  if( AT_UNLIKELY( out->amount == 0 ) ) {
    return -1;
  }

  /* extra_data (Option<Vec<u8>>) */
  if( data[off] == 0x00 ) {
    out->extra_data_off = 0;
    out->extra_data_len = 0;
    off += 1;
  } else if( data[off] == 0x01 ) {
    off += 1;
    if( AT_UNLIKELY( off + 2 > data_sz ) ) return -1;
    ushort len = at_be16_to_native( data + off );
    off += 2;
    if( AT_UNLIKELY( off + len > data_sz ) ) return -1;
    out->extra_data_off = base_off + (uint)off;
    out->extra_data_len = len;
    off += len;
  } else {
    return -1;
  }

  /* commitment */
  if( AT_UNLIKELY( off + AT_UNO_COMMITMENT_SZ > data_sz ) ) return -1;
  at_memcpy( out->commitment, data + off, AT_UNO_COMMITMENT_SZ );
  off += AT_UNO_COMMITMENT_SZ;

  /* receiver_handle */
  if( AT_UNLIKELY( off + AT_UNO_HANDLE_SZ > data_sz ) ) return -1;
  at_memcpy( out->receiver_handle, data + off, AT_UNO_HANDLE_SZ );
  off += AT_UNO_HANDLE_SZ;

  /* proof (ShieldCommitmentProof, 96 bytes) */
  if( AT_UNLIKELY( off + AT_SHIELD_PROOF_SZ > data_sz ) ) return -1;
  out->proof_off = base_off + (uint)off;

  return 0;
}

/**********************************************************************/
/* Unshield Payload (Type 7)                                           */
/**********************************************************************/

/* Wire format:
   [asset:32][destination:32][amount:8][extra_data?][commitment:32]
   [sender_handle:32][ct_proof:128-160]

   ct_proof is CiphertextValidityProof:
   - T0 version: 128 bytes
   - T1 version: 160 bytes */

typedef struct {
  uchar  asset[AT_UNO_ASSET_SZ];
  uchar  destination[AT_UNO_PUBKEY_SZ];
  ulong  amount;
  uint   extra_data_off;     /* Offset in raw buffer (0 if None) */
  ushort extra_data_len;     /* Length of extra data (0 if None) */
  uchar  commitment[AT_UNO_COMMITMENT_SZ];
  uchar  sender_handle[AT_UNO_HANDLE_SZ];
  uint   ct_proof_off;       /* Offset to CiphertextValidityProof */
  uint   ct_proof_sz;        /* Size of proof (128 or 160) */
} at_unshield_payload_t;

/* Minimum size: 32 + 32 + 8 + 1(None) + 32 + 32 + 128 = 265 bytes */
#define AT_UNSHIELD_PAYLOAD_MIN_SZ  (265UL)

/* Parse Unshield payload from wire format.
   tx_version_t1: set to 1 if transaction uses T1 format (160-byte proofs).
   Returns 0 on success, -1 on error. */
static inline int
at_unshield_parse( uchar const *          data,
                   ulong                  data_sz,
                   uint                   base_off,
                   int                    tx_version_t1,
                   at_unshield_payload_t * out ) {
  ulong expected_proof_sz = tx_version_t1 ? AT_CT_PROOF_T1_SZ : AT_CT_PROOF_T0_SZ;
  ulong min_sz = 32 + 32 + 8 + 1 + 32 + 32 + expected_proof_sz;

  if( AT_UNLIKELY( data_sz < min_sz ) ) {
    return -1;
  }

  ulong off = 0;

  /* asset */
  at_memcpy( out->asset, data + off, AT_UNO_ASSET_SZ );
  off += AT_UNO_ASSET_SZ;

  /* destination */
  at_memcpy( out->destination, data + off, AT_UNO_PUBKEY_SZ );
  off += AT_UNO_PUBKEY_SZ;

  /* amount (u64 BE) */
  out->amount = at_be64_to_native( data + off );
  off += 8;

  /* Validate amount is non-zero */
  if( AT_UNLIKELY( out->amount == 0 ) ) {
    return -1;
  }

  /* extra_data (Option<Vec<u8>>) */
  if( data[off] == 0x00 ) {
    out->extra_data_off = 0;
    out->extra_data_len = 0;
    off += 1;
  } else if( data[off] == 0x01 ) {
    off += 1;
    if( AT_UNLIKELY( off + 2 > data_sz ) ) return -1;
    ushort len = at_be16_to_native( data + off );
    off += 2;
    if( AT_UNLIKELY( off + len > data_sz ) ) return -1;
    out->extra_data_off = base_off + (uint)off;
    out->extra_data_len = len;
    off += len;
  } else {
    return -1;
  }

  /* commitment */
  if( AT_UNLIKELY( off + AT_UNO_COMMITMENT_SZ > data_sz ) ) return -1;
  at_memcpy( out->commitment, data + off, AT_UNO_COMMITMENT_SZ );
  off += AT_UNO_COMMITMENT_SZ;

  /* sender_handle */
  if( AT_UNLIKELY( off + AT_UNO_HANDLE_SZ > data_sz ) ) return -1;
  at_memcpy( out->sender_handle, data + off, AT_UNO_HANDLE_SZ );
  off += AT_UNO_HANDLE_SZ;

  /* ct_proof (CiphertextValidityProof) */
  if( AT_UNLIKELY( off + expected_proof_sz > data_sz ) ) return -1;
  out->ct_proof_off = base_off + (uint)off;
  out->ct_proof_sz = (uint)expected_proof_sz;

  return 0;
}

/**********************************************************************/
/* UnoTransfer Payload (Type 5)                                        */
/**********************************************************************/

/* Wire format:
   [asset:32][destination:32][extra_data?][commitment:32]
   [sender_handle:32][receiver_handle:32][ct_proof:128-160]

   Note: UnoTransfer has NO amount field - the amount is fully hidden
   in the commitment. */

typedef struct {
  uchar  asset[AT_UNO_ASSET_SZ];
  uchar  destination[AT_UNO_PUBKEY_SZ];
  uint   extra_data_off;     /* Offset in raw buffer (0 if None) */
  ushort extra_data_len;     /* Length of extra data (0 if None) */
  uchar  commitment[AT_UNO_COMMITMENT_SZ];
  uchar  sender_handle[AT_UNO_HANDLE_SZ];
  uchar  receiver_handle[AT_UNO_HANDLE_SZ];
  uint   ct_proof_off;       /* Offset to CiphertextValidityProof */
  uint   ct_proof_sz;        /* Size of proof (128 or 160) */
} at_uno_transfer_payload_t;

/* Minimum size: 32 + 32 + 1(None) + 32 + 32 + 32 + 128 = 289 bytes */
#define AT_UNO_TRANSFER_PAYLOAD_MIN_SZ  (289UL)

/* Parse UnoTransfer payload from wire format.
   tx_version_t1: set to 1 if transaction uses T1 format (160-byte proofs).
   Returns 0 on success, -1 on error. */
static inline int
at_uno_transfer_parse( uchar const *              data,
                       ulong                      data_sz,
                       uint                       base_off,
                       int                        tx_version_t1,
                       at_uno_transfer_payload_t * out ) {
  ulong expected_proof_sz = tx_version_t1 ? AT_CT_PROOF_T1_SZ : AT_CT_PROOF_T0_SZ;
  ulong min_sz = 32 + 32 + 1 + 32 + 32 + 32 + expected_proof_sz;

  if( AT_UNLIKELY( data_sz < min_sz ) ) {
    return -1;
  }

  ulong off = 0;

  /* asset */
  at_memcpy( out->asset, data + off, AT_UNO_ASSET_SZ );
  off += AT_UNO_ASSET_SZ;

  /* destination */
  at_memcpy( out->destination, data + off, AT_UNO_PUBKEY_SZ );
  off += AT_UNO_PUBKEY_SZ;

  /* extra_data (Option<Vec<u8>>) */
  if( data[off] == 0x00 ) {
    out->extra_data_off = 0;
    out->extra_data_len = 0;
    off += 1;
  } else if( data[off] == 0x01 ) {
    off += 1;
    if( AT_UNLIKELY( off + 2 > data_sz ) ) return -1;
    ushort len = at_be16_to_native( data + off );
    off += 2;
    if( AT_UNLIKELY( off + len > data_sz ) ) return -1;
    out->extra_data_off = base_off + (uint)off;
    out->extra_data_len = len;
    off += len;
  } else {
    return -1;
  }

  /* commitment */
  if( AT_UNLIKELY( off + AT_UNO_COMMITMENT_SZ > data_sz ) ) return -1;
  at_memcpy( out->commitment, data + off, AT_UNO_COMMITMENT_SZ );
  off += AT_UNO_COMMITMENT_SZ;

  /* sender_handle */
  if( AT_UNLIKELY( off + AT_UNO_HANDLE_SZ > data_sz ) ) return -1;
  at_memcpy( out->sender_handle, data + off, AT_UNO_HANDLE_SZ );
  off += AT_UNO_HANDLE_SZ;

  /* receiver_handle */
  if( AT_UNLIKELY( off + AT_UNO_HANDLE_SZ > data_sz ) ) return -1;
  at_memcpy( out->receiver_handle, data + off, AT_UNO_HANDLE_SZ );
  off += AT_UNO_HANDLE_SZ;

  /* ct_proof (CiphertextValidityProof) */
  if( AT_UNLIKELY( off + expected_proof_sz > data_sz ) ) return -1;
  out->ct_proof_off = base_off + (uint)off;
  out->ct_proof_sz = (uint)expected_proof_sz;

  return 0;
}

/**********************************************************************/
/* UNO Payload Encoding Helpers (TOS-compatible wire format)           */
/**********************************************************************/

static inline ulong
at_shield_payload_wire_size( ushort extra_data_len ) {
  ulong sz = 32UL + 32UL + 8UL + 1UL + 32UL + 32UL + AT_SHIELD_PROOF_SZ;
  if( extra_data_len ) sz += 2UL + (ulong)extra_data_len;
  return sz;
}

static inline ulong
at_unshield_payload_wire_size( ushort extra_data_len,
                               int    tx_version_t1 ) {
  ulong proof_sz = tx_version_t1 ? AT_CT_PROOF_T1_SZ : AT_CT_PROOF_T0_SZ;
  ulong sz = 32UL + 32UL + 8UL + 1UL + 32UL + 32UL + proof_sz;
  if( extra_data_len ) sz += 2UL + (ulong)extra_data_len;
  return sz;
}

static inline ulong
at_uno_transfer_payload_wire_size( ushort extra_data_len,
                                   int    tx_version_t1 ) {
  ulong proof_sz = tx_version_t1 ? AT_CT_PROOF_T1_SZ : AT_CT_PROOF_T0_SZ;
  ulong sz = 32UL + 32UL + 1UL + 32UL + 32UL + 32UL + proof_sz;
  if( extra_data_len ) sz += 2UL + (ulong)extra_data_len;
  return sz;
}

static inline ulong
at_shield_write( uchar *      out,
                 ulong        out_cap,
                 uchar const  asset[32],
                 uchar const  destination[32],
                 ulong        amount,
                 uchar const * extra_data,
                 ushort       extra_data_len,
                 uchar const  commitment[32],
                 uchar const  receiver_handle[32],
                 uchar const  proof[96] ) {
  ulong need = at_shield_payload_wire_size( extra_data_len );
  if( AT_UNLIKELY( !out || out_cap < need || amount==0 ) ) return 0;

  ulong off = 0;
  at_memcpy( out+off, asset, 32 ); off += 32;
  at_memcpy( out+off, destination, 32 ); off += 32;
  at_native_to_be64( amount, out+off ); off += 8;
  if( extra_data_len==0 ) {
    out[off++] = 0x00;
  } else {
    out[off++] = 0x01;
    at_native_to_be16( extra_data_len, out+off ); off += 2;
    at_memcpy( out+off, extra_data, extra_data_len ); off += extra_data_len;
  }
  at_memcpy( out+off, commitment, 32 ); off += 32;
  at_memcpy( out+off, receiver_handle, 32 ); off += 32;
  at_memcpy( out+off, proof, 96 ); off += 96;
  return off;
}

static inline ulong
at_unshield_write( uchar *      out,
                   ulong        out_cap,
                   uchar const  asset[32],
                   uchar const  destination[32],
                   ulong        amount,
                   uchar const * extra_data,
                   ushort       extra_data_len,
                   uchar const  commitment[32],
                   uchar const  sender_handle[32],
                   uchar const * ct_proof,
                   int          tx_version_t1 ) {
  ulong proof_sz = tx_version_t1 ? AT_CT_PROOF_T1_SZ : AT_CT_PROOF_T0_SZ;
  ulong need = at_unshield_payload_wire_size( extra_data_len, tx_version_t1 );
  if( AT_UNLIKELY( !out || !ct_proof || out_cap < need || amount==0 ) ) return 0;

  ulong off = 0;
  at_memcpy( out+off, asset, 32 ); off += 32;
  at_memcpy( out+off, destination, 32 ); off += 32;
  at_native_to_be64( amount, out+off ); off += 8;
  if( extra_data_len==0 ) {
    out[off++] = 0x00;
  } else {
    out[off++] = 0x01;
    at_native_to_be16( extra_data_len, out+off ); off += 2;
    at_memcpy( out+off, extra_data, extra_data_len ); off += extra_data_len;
  }
  at_memcpy( out+off, commitment, 32 ); off += 32;
  at_memcpy( out+off, sender_handle, 32 ); off += 32;
  at_memcpy( out+off, ct_proof, proof_sz ); off += proof_sz;
  return off;
}

static inline ulong
at_uno_transfer_write( uchar *      out,
                       ulong        out_cap,
                       uchar const  asset[32],
                       uchar const  destination[32],
                       uchar const * extra_data,
                       ushort       extra_data_len,
                       uchar const  commitment[32],
                       uchar const  sender_handle[32],
                       uchar const  receiver_handle[32],
                       uchar const * ct_proof,
                       int          tx_version_t1 ) {
  ulong proof_sz = tx_version_t1 ? AT_CT_PROOF_T1_SZ : AT_CT_PROOF_T0_SZ;
  ulong need = at_uno_transfer_payload_wire_size( extra_data_len, tx_version_t1 );
  if( AT_UNLIKELY( !out || !ct_proof || out_cap < need ) ) return 0;

  ulong off = 0;
  at_memcpy( out+off, asset, 32 ); off += 32;
  at_memcpy( out+off, destination, 32 ); off += 32;
  if( extra_data_len==0 ) {
    out[off++] = 0x00;
  } else {
    out[off++] = 0x01;
    at_native_to_be16( extra_data_len, out+off ); off += 2;
    at_memcpy( out+off, extra_data, extra_data_len ); off += extra_data_len;
  }
  at_memcpy( out+off, commitment, 32 ); off += 32;
  at_memcpy( out+off, sender_handle, 32 ); off += 32;
  at_memcpy( out+off, receiver_handle, 32 ); off += 32;
  at_memcpy( out+off, ct_proof, proof_sz ); off += proof_sz;
  return off;
}

static inline int
at_shield_get_extra_data( at_shield_payload_t const * payload,
                          uchar const *               raw,
                          uchar const **              out_ptr,
                          ushort *                    out_len ) {
  if( !payload || !raw || !out_ptr || !out_len ) return -1;
  if( payload->extra_data_len==0 ) {
    *out_ptr = NULL;
    *out_len = 0;
    return 0;
  }
  *out_ptr = raw + payload->extra_data_off;
  *out_len = payload->extra_data_len;
  return 0;
}

static inline int
at_unshield_get_extra_data( at_unshield_payload_t const * payload,
                            uchar const *                 raw,
                            uchar const **                out_ptr,
                            ushort *                      out_len ) {
  if( !payload || !raw || !out_ptr || !out_len ) return -1;
  if( payload->extra_data_len==0 ) {
    *out_ptr = NULL;
    *out_len = 0;
    return 0;
  }
  *out_ptr = raw + payload->extra_data_off;
  *out_len = payload->extra_data_len;
  return 0;
}

static inline int
at_uno_transfer_get_extra_data( at_uno_transfer_payload_t const * payload,
                                uchar const *                     raw,
                                uchar const **                    out_ptr,
                                ushort *                          out_len ) {
  if( !payload || !raw || !out_ptr || !out_len ) return -1;
  if( payload->extra_data_len==0 ) {
    *out_ptr = NULL;
    *out_len = 0;
    return 0;
  }
  *out_ptr = raw + payload->extra_data_off;
  *out_len = payload->extra_data_len;
  return 0;
}

typedef enum {
  AT_UNO_ROLE_SENDER   = 0,
  AT_UNO_ROLE_RECEIVER = 1,
} at_uno_transfer_role_t;

static inline int
at_uno_transfer_get_ciphertext( at_uno_transfer_payload_t const * payload,
                                at_uno_transfer_role_t           role,
                                at_uno_ciphertext_t *            out_ct ) {
  if( !payload || !out_ct ) return -1;
  at_memcpy( out_ct->commitment, payload->commitment, 32 );
  if( role == AT_UNO_ROLE_SENDER ) {
    at_memcpy( out_ct->handle, payload->sender_handle, 32 );
  } else if( role == AT_UNO_ROLE_RECEIVER ) {
    at_memcpy( out_ct->handle, payload->receiver_handle, 32 );
  } else {
    return -1;
  }
  return 0;
}

/**********************************************************************/
/* SourceCommitment (UNO proof binding per asset)                      */
/**********************************************************************/

#define AT_SOURCE_COMMITMENT_EQ_PROOF_SZ (192UL)
#define AT_SOURCE_COMMITMENT_WIRE_SZ     (256UL)

typedef struct {
  uchar commitment[32];
  uchar proof[AT_SOURCE_COMMITMENT_EQ_PROOF_SZ];
  uchar asset[32];
} at_source_commitment_t;

static inline int
at_source_commitment_parse( uchar const *         data,
                            ulong                 data_sz,
                            at_source_commitment_t * out ) {
  if( AT_UNLIKELY( !data || !out || data_sz < AT_SOURCE_COMMITMENT_WIRE_SZ ) ) return -1;
  at_memcpy( out->commitment, data, 32 );
  at_memcpy( out->proof, data + 32, AT_SOURCE_COMMITMENT_EQ_PROOF_SZ );
  at_memcpy( out->asset, data + 32 + AT_SOURCE_COMMITMENT_EQ_PROOF_SZ, 32 );
  return 0;
}

static inline int
at_source_commitment_write( uchar *                     out,
                            ulong                       out_cap,
                            at_source_commitment_t const * sc ) {
  if( AT_UNLIKELY( !out || !sc || out_cap < AT_SOURCE_COMMITMENT_WIRE_SZ ) ) return -1;
  at_memcpy( out, sc->commitment, 32 );
  at_memcpy( out + 32, sc->proof, AT_SOURCE_COMMITMENT_EQ_PROOF_SZ );
  at_memcpy( out + 32 + AT_SOURCE_COMMITMENT_EQ_PROOF_SZ, sc->asset, 32 );
  return 0;
}

/**********************************************************************/
/* Source Commitment Iterator                                          */
/**********************************************************************/

/* Iterator for source commitments in at_txn_t */
typedef struct {
  uchar const * data;
  uchar         count;
  uchar         idx;
} at_source_commits_iter_t;

/* Initialize source commitments iterator */
static inline void
at_source_commits_iter_init( at_source_commits_iter_t * iter,
                             at_txn_t const *           txn,
                             uchar const *              raw ) {
  iter->data = raw + txn->source_commitments_off;
  iter->count = txn->source_commitments_cnt;
  iter->idx = 0;
}

/* Get next source commitment.
   Returns pointer to 32-byte commitment, or NULL if done. */
static inline uchar const *
at_source_commits_iter_next( at_source_commits_iter_t * iter ) {
  if( iter->idx >= iter->count ) {
    return NULL;
  }
  uchar const * commit = iter->data + ((ulong)iter->idx * AT_UNO_COMMITMENT_SZ);
  iter->idx++;
  return commit;
}

/**********************************************************************/
/* Ciphertext Helpers                                                  */
/**********************************************************************/

/* Build a ciphertext from commitment and handle */
static inline void
at_uno_ciphertext_from_parts( at_uno_ciphertext_t * ct,
                               uchar const          commitment[32],
                               uchar const          handle[32] ) {
  at_memcpy( ct->commitment, commitment, 32 );
  at_memcpy( ct->handle, handle, 32 );
}

/* Check if asset is native TOS (all zeros) */
static inline int
at_uno_asset_is_native( uchar const asset[32] ) {
  for( int i = 0; i < 32; i++ ) {
    if( asset[i] != 0 ) return 0;
  }
  return 1;
}

/* Check if asset is UNO asset (0x...01) */
static inline int
at_uno_asset_is_uno( uchar const asset[32] ) {
  for( int i = 0; i < 31; i++ ) {
    if( asset[i] != 0 ) return 0;
  }
  return asset[31] == 1;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_tos_at_txn_uno_h */
