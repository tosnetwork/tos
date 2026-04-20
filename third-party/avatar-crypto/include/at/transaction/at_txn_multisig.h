#ifndef HEADER_at_tos_at_txn_multisig_h
#define HEADER_at_tos_at_txn_multisig_h

/* at_txn_multisig.h - TOS MultiSig Transaction Payload

   Transaction Type Discriminator: 2 (AT_TXN_TYPE_MULTISIG)

   IMPORTANT: TOS MultiSig is an ACCOUNT CONFIGURATION model, not a transaction
   wrapper. A MultiSig transaction (Type 0x02) is used to configure an account's
   multi-signature settings. Once configured:
   - ANY transaction from that account requires threshold signatures
   - Signatures are provided in the transaction's `multisig` field
   - Each signature is a SignatureWithIndex: [participant_id:1][signature:64]

   Wire Format (Big-Endian):

   MultiSigPayload (Type 0x02) - Configure Account MultiSig:
     Disable multisig (threshold=0):
       [threshold:1] = 1 byte total

     Enable multisig (threshold>0):
       [threshold:1][participants_count:1][participants:32*count]
       Min: 2 bytes (threshold + count with 0 participants - invalid)
       Max: 2 + 255*32 = 8162 bytes

   SignatureWithIndex (in transaction multisig field):
     [participant_id:1][signature:64] = 65 bytes per signature

   Key Rules:
   - threshold=0 disables multisig for the account
   - threshold>0 requires exactly threshold signatures for ANY transaction
   - participant_id is 0-based index into the participants list
   - Signature count in tx MUST EQUAL threshold (not >= threshold)
*/

#include "at/transaction/at_txn.h"

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* MultiSig Constants                                                  */
/**********************************************************************/

#define AT_MULTISIG_MAX_PARTICIPANTS  (255UL)
#define AT_MULTISIG_CONFIG_MIN_SZ     (1UL)   /* Just threshold byte for disable */
#define AT_MULTISIG_CONFIG_MAX_SZ     (2UL + 255UL * 32UL)  /* 8162 bytes max */
#define AT_MULTISIG_SIG_ENTRY_SZ      (65UL)  /* participant_id(1) + signature(64) */

/**********************************************************************/
/* MultiSig Config Payload (Type 0x02)                                 */
/**********************************************************************/

/* Parsed MultiSig configuration payload.
   This represents an account's multisig settings. */
typedef struct {
  uchar threshold;          /* 0=disabled, 1-255=required signatures */
  uchar participants_cnt;   /* Number of authorized participants (0 if disabled) */
  uint  participants_off;   /* Offset to participant pubkeys in raw buffer */
} at_multisig_config_t;

/* Parse MultiSig configuration payload.
   data: pointer to payload data (after type discriminator)
   data_sz: size of payload data
   base_off: offset in raw buffer where data starts (for storing offsets)
   out: parsed configuration output

   Returns 0 on success, -1 on failure.

   Valid configurations:
   - threshold=0, participants_cnt=0: disable multisig
   - 1 <= threshold <= participants_cnt <= 255: enable multisig */
static inline int
at_multisig_config_parse( uchar const *         data,
                          ulong                 data_sz,
                          uint                  base_off,
                          at_multisig_config_t * out ) {
  if( AT_UNLIKELY( !data || !out || data_sz < AT_MULTISIG_CONFIG_MIN_SZ ) ) {
    return -1;
  }

  out->threshold = data[0];
  out->participants_cnt = 0;
  out->participants_off = 0;

  /* threshold=0 means disable multisig - valid with just 1 byte */
  if( out->threshold == 0 ) {
    return 0;
  }

  /* threshold>0 requires participants */
  if( AT_UNLIKELY( data_sz < 2 ) ) {
    return -1;
  }

  out->participants_cnt = data[1];

  /* Validate threshold is achievable */
  if( AT_UNLIKELY( out->threshold > out->participants_cnt ) ) {
    return -1;
  }

  /* participants_cnt must be non-zero when enabling */
  if( AT_UNLIKELY( out->participants_cnt == 0 ) ) {
    return -1;
  }

  /* Calculate expected size and validate */
  ulong expected_sz = 2UL + ((ulong)out->participants_cnt * 32UL);
  if( AT_UNLIKELY( data_sz < expected_sz ) ) {
    return -1;
  }

  out->participants_off = base_off + 2;

  return 0;
}

/* Get participant public key by index.
   cfg: parsed configuration
   raw: raw transaction buffer
   idx: participant index (0-based)

   Returns pointer to 32-byte public key, or NULL if index invalid. */
static inline uchar const *
at_multisig_config_get_participant( at_multisig_config_t const * cfg,
                                    uchar const *                raw,
                                    uchar                        idx ) {
  if( AT_UNLIKELY( !cfg || !raw || idx >= cfg->participants_cnt ) ) {
    return NULL;
  }
  return raw + cfg->participants_off + ((ulong)idx * 32UL);
}

/**********************************************************************/
/* MultiSig Signature Entry (in transaction multisig field)            */
/**********************************************************************/

/* Parsed signature with participant index.
   This is one entry from the transaction's multisig field. */
typedef struct {
  uchar id;               /* Participant index (0-based) */
  uchar signature[64];    /* Schnorr signature */
} at_multisig_sig_entry_t;

/* Parse a multisig signature entry from transaction's multisig field.
   raw: raw transaction buffer
   multisig_off: offset to multisig signatures in raw (from at_txn_t)
   multisig_cnt: total number of signatures (from at_txn_t)
   idx: which signature to parse (0-based)
   out: output signature entry

   Returns 0 on success, -1 on failure. */
static inline int
at_multisig_sig_parse( uchar const *            raw,
                       uint                     multisig_off,
                       uchar                    multisig_cnt,
                       uchar                    idx,
                       at_multisig_sig_entry_t * out ) {
  if( AT_UNLIKELY( !raw || !out || idx >= multisig_cnt ) ) {
    return -1;
  }

  ulong entry_off = (ulong)multisig_off + ((ulong)idx * AT_MULTISIG_SIG_ENTRY_SZ);
  uchar const * entry = raw + entry_off;

  out->id = entry[0];
  at_memcpy( out->signature, entry + 1, 64 );

  return 0;
}

/**********************************************************************/
/* Backward Compatibility - Legacy Types (DEPRECATED)                  */
/**********************************************************************/

/* NOTE: The old at_multisig_payload_t assumed MultiSig wrapped an inner
   transaction. This is INCORRECT for TOS. Keeping for reference but
   marked deprecated. Use at_multisig_config_t instead. */

#if 0  /* DEPRECATED - DO NOT USE */
typedef struct {
  uchar threshold;        /* Required number of signatures */
  uchar signers_count;    /* Total number of signers */
  uint  signers_off;      /* Offset to signer pubkeys in raw */
  uint  inner_txn_off;    /* DEPRECATED: No inner transaction in TOS */
  uint  inner_txn_len;    /* DEPRECATED: No inner transaction in TOS */
} at_multisig_payload_t;
#endif

AT_PROTOTYPES_END

#endif /* HEADER_at_tos_at_txn_multisig_h */
