#ifndef HEADER_at_config_at_genesis_h
#define HEADER_at_config_at_genesis_h

/* at_genesis.h - Genesis block definitions for TOS networks

   Provides hardcoded genesis block data and hashes for each network.
   Genesis blocks are the first block in the blockchain and establish
   the initial state of the network.

   Wire format (93 bytes for genesis, big-endian):
     version(1) + height(8) + timestamp(8) + nonce(8) + extra_nonce(32) +
     tips_cnt(1) + txs_cnt(2) + miner_pubkey(32) + vrf_flag(1)

   Block hash is computed via the multi-step BLAKE3 algorithm
   (see at_block_hash_compute_tos in at_block.c). */

#include "at/infra/at_util_base.h"

AT_PROTOTYPES_BEGIN

/* Network types - use shared definition if available */
#ifndef AT_NETWORK_TYPE_DEFINED
#define AT_NETWORK_TYPE_DEFINED
typedef enum {
  AT_NETWORK_MAINNET  = 0,
  AT_NETWORK_TESTNET  = 1,
  AT_NETWORK_STAGENET = 2,
  AT_NETWORK_DEVNET   = 3,
} at_network_t;
typedef at_network_t at_network_type_t;
#endif

/* Genesis block timestamp (milliseconds since Unix epoch) */
#define AT_GENESIS_TIMESTAMP_MAINNET  (1772323200000UL)  /* 2026-03-01 00:00:00 UTC */
#define AT_GENESIS_TIMESTAMP_TESTNET  (1735689600000UL)  /* 2025-01-01 00:00:00 UTC */

/* Genesis block difficulty (= MAINNET_MINIMUM_HASHRATE = 100 KH/s) */
#define AT_GENESIS_BLOCK_DIFFICULTY   (100000UL)

/* Genesis block wire format size (no tips, no txs, no VRF) */
#define AT_GENESIS_BLOCK_WIRE_SZ      (93UL)

/* Developer public key (32 bytes, compressed Ristretto255)
   Derived from address: tos1qsl6sj2u0gp37tr6drrq964rd4d8gnaxnezgytmt0cfltnp2wsgqqak28je */
static uchar const AT_DEV_PUBLIC_KEY[32] = {
  0x04, 0x3f, 0xa8, 0x49, 0x5c, 0x7a, 0x03, 0x1f,
  0x2c, 0x7a, 0x68, 0xc6, 0x02, 0xea, 0xa3, 0x6d,
  0x5a, 0x74, 0x4f, 0xa6, 0x9e, 0x44, 0x82, 0x2f,
  0x6b, 0x7e, 0x13, 0xf5, 0xcc, 0x2a, 0x74, 0x10
};

/* Mainnet genesis block (93 bytes, P2P wire format, big-endian)
   version=0, height=0, timestamp=1772323200000, nonce=0, extra_nonce=zeros,
   tips_cnt=0, txs_cnt=0, miner=DEV_PUBLIC_KEY, vrf_flag=0 */
static uchar const AT_GENESIS_BLOCK_MAINNET[93] = {
  0x00,                                                 /* version */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     /* height */
  0x00, 0x00, 0x01, 0x9c, 0xa6, 0xb1, 0xdc, 0x00,     /* timestamp */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     /* nonce */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     /* extra_nonce[0..7] */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     /* extra_nonce[8..15] */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     /* extra_nonce[16..23] */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     /* extra_nonce[24..31] */
  0x00,                                                 /* tips_cnt */
  0x00, 0x00,                                           /* txs_cnt */
  0x04, 0x3f, 0xa8, 0x49, 0x5c, 0x7a, 0x03, 0x1f,     /* miner[0..7] */
  0x2c, 0x7a, 0x68, 0xc6, 0x02, 0xea, 0xa3, 0x6d,     /* miner[8..15] */
  0x5a, 0x74, 0x4f, 0xa6, 0x9e, 0x44, 0x82, 0x2f,     /* miner[16..23] */
  0x6b, 0x7e, 0x13, 0xf5, 0xcc, 0x2a, 0x74, 0x10,     /* miner[24..31] */
  0x00                                                  /* vrf_flag */
};

/* Testnet genesis block (93 bytes, P2P wire format, big-endian)
   version=0, height=0, timestamp=1735689600000, nonce=0, extra_nonce=zeros,
   tips_cnt=0, txs_cnt=0, miner=DEV_PUBLIC_KEY, vrf_flag=0 */
static uchar const AT_GENESIS_BLOCK_TESTNET[93] = {
  0x00,                                                 /* version */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     /* height */
  0x00, 0x00, 0x01, 0x94, 0x1f, 0x29, 0x7c, 0x00,     /* timestamp */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     /* nonce */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     /* extra_nonce[0..7] */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     /* extra_nonce[8..15] */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     /* extra_nonce[16..23] */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     /* extra_nonce[24..31] */
  0x00,                                                 /* tips_cnt */
  0x00, 0x00,                                           /* txs_cnt */
  0x04, 0x3f, 0xa8, 0x49, 0x5c, 0x7a, 0x03, 0x1f,     /* miner[0..7] */
  0x2c, 0x7a, 0x68, 0xc6, 0x02, 0xea, 0xa3, 0x6d,     /* miner[8..15] */
  0x5a, 0x74, 0x4f, 0xa6, 0x9e, 0x44, 0x82, 0x2f,     /* miner[16..23] */
  0x6b, 0x7e, 0x13, 0xf5, 0xcc, 0x2a, 0x74, 0x10,     /* miner[24..31] */
  0x00                                                  /* vrf_flag */
};

/* Genesis block hash for mainnet (BLAKE3, multi-step)
   Hash: ddd10764610850e05191baec336720b609722db75ac4490daeb73af8472a9ea3 */
static uchar const AT_GENESIS_HASH_MAINNET[32] = {
  0xdd, 0xd1, 0x07, 0x64, 0x61, 0x08, 0x50, 0xe0,
  0x51, 0x91, 0xba, 0xec, 0x33, 0x67, 0x20, 0xb6,
  0x09, 0x72, 0x2d, 0xb7, 0x5a, 0xc4, 0x49, 0x0d,
  0xae, 0xb7, 0x3a, 0xf8, 0x47, 0x2a, 0x9e, 0xa3
};

/* Genesis block hash for testnet (BLAKE3, multi-step)
   Hash: 5fe9de143238941639be15f3c7ec08c1cab5d99cdbd183f9879047841f0a5e0a */
static uchar const AT_GENESIS_HASH_TESTNET[32] = {
  0x5f, 0xe9, 0xde, 0x14, 0x32, 0x38, 0x94, 0x16,
  0x39, 0xbe, 0x15, 0xf3, 0xc7, 0xec, 0x08, 0xc1,
  0xca, 0xb5, 0xd9, 0x9c, 0xdb, 0xd1, 0x83, 0xf9,
  0x87, 0x90, 0x47, 0x84, 0x1f, 0x0a, 0x5e, 0x0a
};

/* Network ID (16 bytes: "terminossonimret") — same for all networks */
static uchar const AT_NETWORK_ID[16] = {
  't', 'e', 'r', 'm', 'i', 'n', 'o', 's',
  's', 'o', 'n', 'i', 'm', 'r', 'e', 't'
};

/* Dev addresses per network (same public key, different bech32 HRP) */
#define AT_DEV_ADDRESS_MAINNET  "tos1qsl6sj2u0gp37tr6drrq964rd4d8gnaxnezgytmt0cfltnp2wsgqqak28je"
#define AT_DEV_ADDRESS_TESTNET  "tst1qsl6sj2u0gp37tr6drrq964rd4d8gnaxnezgytmt0cfltnp2wsgqqxxrx64"

/* Mainnet seed nodes */
#define AT_SEED_NODES_MAINNET_CNT  (7)
static char const * const AT_SEED_NODES_MAINNET[7] = {
  "51.210.117.23:2125",
  "198.71.55.87:2125",
  "162.19.249.100:2125",
  "139.99.89.27:2125",
  "51.68.142.141:2125",
  "51.195.220.137:2125",
  "66.70.179.137:2125",
};

/* Testnet seed nodes */
#define AT_SEED_NODES_TESTNET_CNT  (1)
static char const * const AT_SEED_NODES_TESTNET[1] = {
  "157.7.65.157:2125",
};

/* Get genesis hash for a network
   Returns: 0 on success, -1 if network has no predefined genesis */
int at_genesis_get_hash( at_network_t network, uchar out_hash[32] );

/* Get network ID for a network
   Returns: 0 on success, -1 on error */
int at_genesis_get_network_id( at_network_t network, uchar out_id[16] );

/* Map network enum to canonical chain_id used by TX replay protection and
   VRF binding.
   Returns: Mainnet=0, Testnet=1, Stagenet=2, Devnet=3. */
static inline ulong
at_network_chain_id( at_network_t network ) {
  switch( network ) {
    case AT_NETWORK_MAINNET:  return 0UL;
    case AT_NETWORK_TESTNET:  return 1UL;
    case AT_NETWORK_STAGENET: return 2UL;
    case AT_NETWORK_DEVNET:   return 3UL;
    default:                  return 0UL;
  }
}

/* Check if a hash matches the expected genesis hash for a network
   Returns: 1 if matches, 0 if doesn't match */
int at_genesis_hash_matches( at_network_t network, uchar const hash[32] );

/* Parse network type from string
   Returns: Network type, or AT_NETWORK_DEVNET on unknown */
at_network_t at_genesis_parse_network( char const * name );

/* Get network name as string */
char const * at_genesis_network_name( at_network_t network );

/* Get hardcoded genesis block wire data for a network.
   Returns: 0 on success with out/out_sz set, -1 if no hardcoded block (devnet) */
int at_genesis_get_block( at_network_t network, uchar const ** out, ulong * out_sz );

/* Validate a genesis block's wire data.
   Checks: miner key matches DEV_PUBLIC_KEY, wire bytes match hardcoded block.
   block_data must be in P2P wire format.
   Returns: 0 on success, -1 on validation failure */
int at_genesis_validate_block( at_network_t network,
                               uchar const * block_data,
                               ulong         block_sz );

/* Get seed nodes for a network.
   Returns: 0 on success with *out and *out_cnt set */
int at_genesis_get_seed_nodes( at_network_t network,
                               char const * const ** out,
                               ulong * out_cnt );

/* Get dev address string for a network */
char const * at_genesis_get_dev_address( at_network_t network );

AT_PROTOTYPES_END

#endif /* HEADER_at_config_at_genesis_h */
