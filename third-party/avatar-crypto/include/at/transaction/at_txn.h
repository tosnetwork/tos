#ifndef HEADER_at_tos_at_txn_h
#define HEADER_at_tos_at_txn_h

/* at_txn.h - TOS Transaction Structure

   This header defines the TOS transaction format for the Avatar validator.

   TOS Wire Format (Verified):
   - Big-endian byte order for all integers
   - 8 transaction types (discriminators 0-7)
   - Signature at END of transaction
   - Signing bytes INCLUDE reference field

   Wire Layout:
   [version:1][chain_id:1][source:32][data:*][fee:8][fee_type:1][nonce:8]
   [source_commitments_cnt?:1][source_commitments?:*][range_proof_sz?:4][range_proof?:*]
   [ref_hash:32][ref_topoheight:8][multisig_cnt:1][multisig?:*][signature:64]

   TOS Cryptography:
   - Schnorr-variant signatures on Ristretto255
   - SHA3-512 for signature hashing
   - BLAKE3-256 for transaction hashing
*/

#include "at/transaction/at_txn_types.h"
#include "at/crypto/at_schnorr.h"
#include "at/crypto/at_sha3.h"
#include "at/crypto/at_blake3.h"
#include "at/infra/at_util_base.h"

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* Transaction Constants                                               */
/**********************************************************************/

#define AT_TXN_SIGNATURE_SZ       (64UL)    /* Schnorr signature size */
#define AT_TXN_PUBKEY_SZ          (32UL)    /* Compressed Ristretto255 */
#define AT_TXN_HASH_SZ            (32UL)    /* Transaction hash (BLAKE3-256) */
#define AT_TXN_SOURCE_SZ          (32UL)    /* Source address (compressed pubkey) */
#define AT_TXN_ASSET_SZ           (32UL)    /* Asset identifier */
#define AT_TXN_REF_HASH_SZ        (32UL)    /* Reference block hash */

#define AT_TXN_MAX_PAYLOAD_SZ     (65536UL) /* 64 KB max payload */
#define AT_TXN_MAX_TRANSFERS      (500UL)   /* Max recipients per transfer tx */
#define AT_TXN_MAX_SIGNERS        (255UL)   /* Max multisig signers */
#define AT_TXN_MAX_DELEGATEES     (500UL)   /* Max delegated recipients */
#define AT_TXN_MAX_SRC_COMMITS    (255UL)   /* Max source commitments (UNO) */

/* Version */
#define AT_TXN_VERSION_CURRENT    (0UL)     /* Current transaction version */

/**********************************************************************/
/* Big-Endian Byte Order Utilities                                     */
/**********************************************************************/

/* TOS wire format uses big-endian byte order for all integers */

static inline ushort
at_be16_to_native( uchar const * p ) {
  return (ushort)( ((ushort)p[0] << 8) | (ushort)p[1] );
}

static inline uint
at_be32_to_native( uchar const * p ) {
  return (uint)( ((uint)p[0] << 24) | ((uint)p[1] << 16) |
                 ((uint)p[2] << 8)  |  (uint)p[3] );
}

static inline ulong
at_be64_to_native( uchar const * p ) {
  return (ulong)( ((ulong)p[0] << 56) | ((ulong)p[1] << 48) |
                  ((ulong)p[2] << 40) | ((ulong)p[3] << 32) |
                  ((ulong)p[4] << 24) | ((ulong)p[5] << 16) |
                  ((ulong)p[6] << 8)  |  (ulong)p[7] );
}

static inline void
at_native_to_be16( ushort v, uchar * p ) {
  p[0] = (uchar)(v >> 8);
  p[1] = (uchar)(v);
}

static inline void
at_native_to_be32( uint v, uchar * p ) {
  p[0] = (uchar)(v >> 24);
  p[1] = (uchar)(v >> 16);
  p[2] = (uchar)(v >> 8);
  p[3] = (uchar)(v);
}

static inline void
at_native_to_be64( ulong v, uchar * p ) {
  p[0] = (uchar)(v >> 56);
  p[1] = (uchar)(v >> 48);
  p[2] = (uchar)(v >> 40);
  p[3] = (uchar)(v >> 32);
  p[4] = (uchar)(v >> 24);
  p[5] = (uchar)(v >> 16);
  p[6] = (uchar)(v >> 8);
  p[7] = (uchar)(v);
}

/**********************************************************************/
/* Transaction Structure (Zero-Copy)                                   */
/**********************************************************************/

/* TOS transaction view structure
   Uses offsets for zero-copy parsing - all data references point into
   the original raw buffer.

   Wire format (big-endian):
   [version:1][chain_id:1][source:32][data_sz:4][data:*][fee:8][fee_type:1][nonce:8]
   [source_commits_cnt?:1][source_commits?:*][range_proof_sz?:4][range_proof?:*]
   [ref_hash:32][ref_topoheight:8][multisig_cnt:1][multisig?:*][signature:64]

   Note: Signing bytes include everything from version through ref_topoheight
         (excluding multisig signatures and the final signature).
*/
typedef struct __attribute__((aligned(64))) {
  /* === Parsed Fixed Fields === */
  uchar  version;                           /* Transaction version */
  uchar  chain_id;                          /* Chain identifier */
  uchar  type_id;                           /* Transaction type discriminator */
  uchar  fee_type;                          /* Fee payment type (AT_FEE_TYPE_*) */
  uchar  source[AT_TXN_SOURCE_SZ];          /* Source address (32 bytes) */
  ulong  fee;                               /* Transaction fee */
  ulong  nonce;                             /* Replay protection nonce */

  /* === Reference Block === */
  uchar  ref_hash[AT_TXN_REF_HASH_SZ];      /* Reference block hash (32 bytes) */
  ulong  ref_topoheight;                    /* Reference topoheight */

  /* === Payload Offsets (zero-copy) === */
  uint   payload_off;                       /* Offset to type-specific data */
  uint   payload_sz;                        /* Size of type-specific data */

  /* === Signature Offsets === */
  uint   signature_off;                     /* Offset to signature (64 bytes) */
  uint   multisig_off;                      /* Offset to multisig signatures */
  uchar  multisig_cnt;                      /* Number of multisig signatures */

  /* === UNO Privacy Fields (optional) === */
  uint   source_commitments_off;            /* Offset to source commitments */
  uchar  source_commitments_cnt;            /* Number of source commitments */
  uint   range_proof_off;                   /* Offset to range proof */
  uint   range_proof_sz;                    /* Size of range proof */

  /* === Computed Fields === */
  uchar  hash[AT_TXN_HASH_SZ];              /* Transaction hash (BLAKE3-256) */
  uint   raw_sz;                            /* Total raw transaction size */

  /* Padding to 64-byte alignment */
  uchar  _pad[4];
} at_txn_t;

/* Minimum transaction size: version(1) + chain_id(1) + source(32) + data_sz(4) +
   type_id(1) + fee(8) + fee_type(1) + nonce(8) + ref_hash(32) + ref_topoheight(8) +
   multisig_cnt(1) + signature(64) = 161 bytes minimum (empty payload) */
#define AT_TXN_MIN_SZ (161UL)

/**********************************************************************/
/* Parse Error Codes                                                   */
/**********************************************************************/

#define AT_TXN_PARSE_OK                 (0)
#define AT_TXN_PARSE_ERR_TOO_SMALL     (-1)   /* Buffer too small */
#define AT_TXN_PARSE_ERR_TRUNCATED     (-2)   /* Payload truncated */
#define AT_TXN_PARSE_ERR_INVALID_TYPE  (-3)   /* Invalid transaction type */
#define AT_TXN_PARSE_ERR_INVALID_VER   (-4)   /* Invalid version */
#define AT_TXN_PARSE_ERR_OVERFLOW      (-5)   /* Size overflow */
#define AT_TXN_PARSE_ERR_PAYLOAD       (-6)   /* Invalid payload structure */

/**********************************************************************/
/* Verification Result Codes                                           */
/**********************************************************************/

#define AT_TXN_VERIFY_SUCCESS          (0)
#define AT_TXN_VERIFY_PARSE_ERR       (-1)
#define AT_TXN_VERIFY_SIG_ERR         (-2)
#define AT_TXN_VERIFY_DEDUP           (-3)
#define AT_TXN_VERIFY_INVALID         (-4)
#define AT_TXN_VERIFY_NONCE_ERR       (-5)
#define AT_TXN_VERIFY_FEE_ERR         (-6)
#define AT_TXN_VERIFY_BALANCE_ERR     (-7)

/* Business validation error codes */
#define AT_TXN_VERIFY_INVALID_STATE   (-8)   /* State machine violation */
#define AT_TXN_VERIFY_UNAUTHORIZED    (-9)   /* Permission denied */
#define AT_TXN_VERIFY_TIMEOUT         (-10)  /* Time constraint failed */
#define AT_TXN_VERIFY_THRESHOLD       (-11)  /* Approval threshold not met */
#define AT_TXN_VERIFY_DUPLICATE       (-12)  /* Duplicate operation */
#define AT_TXN_VERIFY_SELF_OP         (-13)  /* Self-operation not allowed */
#define AT_TXN_VERIFY_EXPIRED         (-14)  /* Approval/window expired */
#define AT_TXN_VERIFY_CONFIG          (-15)  /* Invalid configuration */

/**********************************************************************/
/* Transaction Parsing (Declaration)                                   */
/**********************************************************************/

/* Parse a transaction from raw bytes (big-endian wire format).
   Returns AT_TXN_PARSE_OK (0) on success, negative error code on failure.

   The txn structure will contain offsets into the raw data (zero-copy).
   Caller must ensure raw data outlives the txn structure.

   Implementation in at_txn_parse.c */
int at_txn_parse( uchar const * raw, ulong raw_sz, at_txn_t * out );

/* Get pointer to payload data */
static inline uchar const *
at_txn_payload( at_txn_t const * txn, uchar const * raw ) {
  return raw + txn->payload_off;
}

/* Get pointer to signature */
static inline uchar const *
at_txn_signature( at_txn_t const * txn, uchar const * raw ) {
  return raw + txn->signature_off;
}

/* Get pointer to multisig signatures (if any) */
static inline uchar const *
at_txn_multisig( at_txn_t const * txn, uchar const * raw ) {
  if( txn->multisig_cnt == 0 ) return NULL;
  return raw + txn->multisig_off;
}

/**********************************************************************/
/* Transaction Hashing                                                 */
/**********************************************************************/

/* Compute transaction hash (BLAKE3-256 of full raw transaction).
   TOS uses BLAKE3 for transaction hashing (aligned with TOS Rust).
   The hash is stored in txn->hash if txn is non-const, otherwise
   the hash is returned in the provided buffer. */
static inline void
at_txn_hash_compute( uchar          hash[AT_TXN_HASH_SZ],
                     uchar const *  raw,
                     ulong          raw_sz ) {
  at_blake3_hash( raw, raw_sz, hash );
}

/* Get transaction hash as 64-bit value for tcache lookup.
   Takes first 8 bytes of full hash. */
static inline ulong
at_txn_hash64( at_txn_t const * txn ) {
  /* Use first 8 bytes of hash in native byte order */
  return *(ulong const *)txn->hash;
}

/**********************************************************************/
/* Signing Bytes Computation                                           */
/**********************************************************************/

/* Compute the bytes that are signed for this transaction.

   IMPORTANT: Signing bytes include:
   - version (1 byte)
   - chain_id (1 byte)
   - source (32 bytes)
   - data_sz (4 bytes, big-endian)
   - data (payload_sz bytes)
   - fee (8 bytes, big-endian)
   - fee_type (1 byte)
   - nonce (8 bytes, big-endian)
   - [source_commits_cnt + source_commits] (if UNO)
   - [range_proof_sz + range_proof] (if UNO)
   - ref_hash (32 bytes)
   - ref_topoheight (8 bytes, big-endian)

   Signing bytes do NOT include:
   - multisig_cnt and multisig signatures
   - the final signature

   Returns the number of bytes written to out, or 0 on error.
   If out is NULL, returns the required buffer size.

   Implementation in at_txn_verify.c */
ulong at_txn_signing_bytes( at_txn_t const * txn,
                            uchar const *    raw,
                            uchar *          out,
                            ulong            out_cap );

/**********************************************************************/
/* Transaction Verification (Declaration)                              */
/**********************************************************************/

/* Verify transaction signature.
   Returns AT_TXN_VERIFY_SUCCESS (0) if valid.

   Implementation in at_txn_verify.c */
int at_txn_verify_signature( at_txn_t const * txn,
                             uchar const *    raw );

/* Validate transaction (stateless checks).
   Checks: valid type, valid fee type, valid chain ID, payload structure.

   Implementation in at_txn_verify.c */
int at_txn_validate_stateless( at_txn_t const * txn,
                               uchar const *    raw );

/* Full transaction verification: parse + signature + validate.
   This is the main entry point for transaction verification.
   Returns AT_TXN_VERIFY_SUCCESS (0) if transaction is valid.

   Implementation in at_txn_verify.c */
int at_txn_verify( at_txn_t *    txn,
                   uchar const * raw,
                   ulong         raw_sz );

/**********************************************************************/
/* Transaction Serialization (Declaration)                             */
/**********************************************************************/

/* Serialize a transaction to wire format.
   Returns the number of bytes written, or 0 on error.
   If out is NULL, returns the required buffer size.

   Implementation in at_txn_serialize.c */
ulong at_txn_serialize( at_txn_t const * txn,
                        uchar const *    raw,
                        uchar *          out,
                        ulong            out_cap );

/**********************************************************************/
/* Transaction Builder (for creating new transactions)                 */
/**********************************************************************/

/* Transaction builder structure for constructing transactions */
typedef struct {
  uchar   version;
  uchar   chain_id;
  uchar   source[AT_TXN_SOURCE_SZ];
  uchar   type_id;
  uchar * payload;
  uint    payload_sz;
  ulong   fee;
  uchar   fee_type;
  ulong   nonce;
  uchar   ref_hash[AT_TXN_REF_HASH_SZ];
  ulong   ref_topoheight;

  /* UNO fields (optional) */
  uchar * source_commitments;
  uchar   source_commitments_cnt;
  uchar * range_proof;
  uint    range_proof_sz;

  /* Multisig (optional) */
  uchar * multisig_sigs;
  uchar   multisig_cnt;
} at_txn_builder_t;

/* Initialize a transaction builder with defaults */
static inline void
at_txn_builder_init( at_txn_builder_t * b ) {
  b->version = AT_TXN_VERSION_CURRENT;
  b->chain_id = AT_CHAIN_MAINNET;
  at_memset( b->source, 0, AT_TXN_SOURCE_SZ );
  b->type_id = AT_TXN_TYPE_BURN;
  b->payload = NULL;
  b->payload_sz = 0;
  b->fee = 0;
  b->fee_type = AT_FEE_TYPE_TOS;
  b->nonce = 0;
  at_memset( b->ref_hash, 0, AT_TXN_REF_HASH_SZ );
  b->ref_topoheight = 0;
  b->source_commitments = NULL;
  b->source_commitments_cnt = 0;
  b->range_proof = NULL;
  b->range_proof_sz = 0;
  b->multisig_sigs = NULL;
  b->multisig_cnt = 0;
}

/* Build and sign a transaction.
   Writes the serialized transaction to out buffer.
   Returns number of bytes written, or 0 on error.
   If out is NULL, returns the required buffer size.

   Implementation in at_txn_serialize.c */
ulong at_txn_build( at_txn_builder_t const * builder,
                    uchar const *            private_key,
                    uchar *                  out,
                    ulong                    out_cap );

AT_PROTOTYPES_END

#endif /* HEADER_at_tos_at_txn_h */
