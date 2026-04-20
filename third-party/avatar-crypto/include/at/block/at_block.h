#ifndef HEADER_at_tos_at_block_h
#define HEADER_at_tos_at_block_h

/* at_block.h - Block and BlockHeader structures for TOS BlockDAG

   This header defines the block data structures used in the TOS
   BlockDAG consensus. Each block can reference up to 3 parent blocks
   (tips), enabling parallel block production and higher throughput. */

#include "at/infra/at_util_base.h"
#include "at/core/blockdag/at_dag_config.h"

AT_PROTOTYPES_BEGIN

/* VRF data for randomness (schnorrkel 0.11 compatible)
   Wire format (192 bytes when present):
   - public_key: 32 bytes
   - output: 32 bytes
   - proof: 64 bytes
   - binding_signature: 64 bytes */

typedef struct {
  uchar public_key[32];        /* VRF public key */
  uchar output[32];            /* VRF output (randomness) */
  uchar proof[64];             /* VRF proof */
  uchar binding_signature[64]; /* Binding signature */
} at_vrf_data_t;

/* Domain separators (TOS-aligned) used by VRF helper hashing. */
extern uchar const AT_VRF_INPUT_DOMAIN[];
extern ulong const AT_VRF_INPUT_DOMAIN_SZ;
extern uchar const AT_VRF_BINDING_DOMAIN[];
extern ulong const AT_VRF_BINDING_DOMAIN_SZ;

/* Compute VRF input hash:
   BLAKE3("TOS-VRF-INPUT-v1" || block_hash || miner_pubkey). */
uchar *
at_vrf_compute_input( uchar             out_hash[32],
                      uchar const       block_hash[32],
                      uchar const       miner_pubkey[32] );

/* Compute VRF binding message hash:
   BLAKE3("TOS-VRF-BINDING-v1" || chain_id_le_u64 || vrf_public_key || block_hash). */
uchar *
at_vrf_compute_binding_message( uchar             out_hash[32],
                                ulong             chain_id,
                                uchar const       vrf_public_key[32],
                                uchar const       block_hash[32] );

/* Constructor-style helper for at_vrf_data_t. */
at_vrf_data_t *
at_vrf_data_new( at_vrf_data_t * out,
                 uchar const     public_key[32],
                 uchar const     output[32],
                 uchar const     proof[64],
                 uchar const     binding_signature[64] );

/* Block header (~320 bytes)

   The block header contains all metadata needed for consensus:
   - Version for protocol upgrades
   - Tips (parent block hashes) for DAG structure
   - Timestamp for ordering and difficulty adjustment
   - Height derived from parents
   - Mining nonces for PoW
   - Miner identity and transaction root
   - VRF for randomness beacon */

typedef struct __attribute__((aligned(8))) {
  uint   version;                              /* Block version */
  uchar  tips[AT_BLOCK_MAX_TIPS][AT_BLOCK_HASH_SZ];  /* Parent block hashes */
  uchar  tips_cnt;                             /* Number of tips (1-3) */
  uchar  has_vrf;                              /* VRF presence flag (0 or 1) */
  uchar  _pad0[2];

  ulong  timestamp_ms;                         /* Unix timestamp in milliseconds */
  ulong  height;                               /* Block height */
  ulong  nonce;                                /* PoW nonce */
  uchar  extra_nonce[32];                      /* Extra nonce for mining spread */

  uchar  miner[AT_PUBKEY_COMPRESSED_SZ];       /* Miner's compressed public key */
  uchar  txs_root[AT_BLOCK_HASH_SZ];           /* Merkle root of transactions */

  at_vrf_data_t vrf;                           /* VRF for randomness (if has_vrf=1) */
} at_block_header_t;

/* Verify VRF payload for a block header.
   Rules:
   - height==0 (genesis): VRF is not required
   - height>0: VRF must be present, proof must verify, and binding signature
     over BLAKE3("TOS-VRF-BINDING-v1"||chain_id||vrf_pk||block_hash) must
     validate against header->miner.
   Returns 0 on success, -1 on failure. */
int
at_block_verify_vrf_data( at_block_header_t const * header,
                          ulong                     chain_id );

/* Verify header size at compile time (VRF is now 192 bytes) */
AT_STATIC_ASSERT( sizeof(at_block_header_t) <= 416UL, at_block_header_size_check );

/* Block structure

   A block consists of its header and variable-length transaction data.
   The txs_cnt field indicates how many transactions follow. */

typedef struct {
  at_block_header_t header;
  ulong             txs_cnt;
  /* Transaction data follows (variable length) */
} at_block_t;

/* Block hash type (32 bytes, same as AT_BLOCK_HASH_SZ) */

typedef struct __attribute__((aligned(8))) {
  uchar hash[AT_BLOCK_HASH_SZ];
} at_block_hash_t;

/* Compare two block hashes
   Returns: <0 if a<b, 0 if a==b, >0 if a>b */

static inline int
at_block_hash_cmp( uchar const * a,
                   uchar const * b ) {
  return at_memcmp( a, b, AT_BLOCK_HASH_SZ );
}

/* Check if block hash is zero (null) */

static inline int
at_block_hash_is_null( uchar const * hash ) {
  for( ulong i = 0UL; i < AT_BLOCK_HASH_SZ; i++ ) {
    if( hash[i] != 0 ) return 0;
  }
  return 1;
}

/* Copy block hash */

static inline void
at_block_hash_copy( uchar       * dst,
                    uchar const * src ) {
  at_memcpy( dst, src, AT_BLOCK_HASH_SZ );
}

/* Clear block hash to zero */

static inline void
at_block_hash_clear( uchar * hash ) {
  at_memset( hash, 0, AT_BLOCK_HASH_SZ );
}

/* Get tip count from header (with validation) */

static inline ulong
at_block_header_tips_cnt( at_block_header_t const * header ) {
  ulong cnt = (ulong)header->tips_cnt;
  if( AT_UNLIKELY( cnt > AT_BLOCK_MAX_TIPS ) ) {
    return AT_BLOCK_MAX_TIPS;  /* Clamp to max */
  }
  return cnt;
}

/* Check if header has valid tip count */

static inline int
at_block_header_tips_valid( at_block_header_t const * header ) {
  return header->tips_cnt >= 1U && header->tips_cnt <= AT_BLOCK_MAX_TIPS;
}

/* Compute block hash using TOS Rust algorithm (BLAKE3)

   Algorithm (matches TOS Rust block/header.rs):
   1. tips_hash = BLAKE3( tip[0] || tip[1] || ... )
   2. txs_hash = BLAKE3( tx[0] || tx[1] || ... ) [already in header->txs_root]
   3. work = version(1) + height(8 BE) + tips_hash(32) + txs_hash(32) = 73 bytes
   4. work_hash = BLAKE3(work)
   5. serialized = work_hash(32) + timestamp(8 BE) + nonce(8 BE) + extra_nonce(32) + miner(32) = 112 bytes
   6. block_hash = BLAKE3(serialized)

   Caller provides output buffer of at least AT_BLOCK_HASH_SZ (32) bytes.
   Returns out_hash on success. */

uchar *
at_block_hash_compute_tos( uchar                     out_hash[32],
                           at_block_header_t const * header );

/* Miner work size: work_hash(32) + timestamp(8) + nonce(8) + extra_nonce(32) + miner(32) = 112 bytes */
#define AT_BLOCK_MINER_WORK_SIZE (112UL)

/* Compute 112-byte MinerWork from a block header.
   out must be at least AT_BLOCK_MINER_WORK_SIZE bytes.
   Returns out on success, NULL on error. */

uchar *
at_block_compute_miner_work( uchar                     out[112],
                              at_block_header_t const * header );

/* Serialize block header to wire format
   Returns number of bytes written, or 0 on error. */

ulong
at_block_header_serialize( uchar                   * out,
                           ulong                     out_max,
                           at_block_header_t const * header );

/* Deserialize block header from wire format
   Returns number of bytes consumed, or 0 on error. */

ulong
at_block_header_deserialize( at_block_header_t * header,
                             uchar const       * data,
                             ulong               data_sz );

AT_PROTOTYPES_END

#endif /* HEADER_at_tos_at_block_h */
