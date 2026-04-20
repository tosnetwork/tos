#ifndef HEADER_at_block_at_txs_root_h
#define HEADER_at_block_at_txs_root_h

/* at_txs_root.h - Transaction Root (txs_root) Computation

   Computes the txs_root for a block, 100% aligned with TOS Rust.

   TOS Rust Algorithm (from ~/tos/common/src/block/header.rs):
     pub fn get_txs_hash(&self) -> Hash {
       let mut bytes = Vec::with_capacity(self.txs_hashes.len() * HASH_SIZE);
       for tx in &self.txs_hashes {
         bytes.extend(tx.as_bytes())  // 32 bytes each
       }
       hash(&bytes)  // BLAKE3
     }

   Algorithm: txs_root = BLAKE3( tx_hash[0] || tx_hash[1] || ... || tx_hash[n-1] )
   Empty block: BLAKE3(empty) = af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9... */

#include "at/infra/at_util_base.h"

AT_PROTOTYPES_BEGIN

/* Compute txs_root from pre-computed transaction hashes.
   Algorithm: txs_root = BLAKE3( tx_hash[0] || tx_hash[1] || ... )
   Empty block (txs_cnt == 0): returns BLAKE3 of empty byte array.

   Parameters:
     out_root   - Output buffer for 32-byte txs_root
     tx_hashes  - Array of 32-byte transaction hashes
     txs_cnt    - Number of transactions

   Returns: out_root on success, NULL on error. */
uchar *
at_txs_root_compute( uchar       out_root[32],
                     uchar const (*tx_hashes)[32],
                     ulong       txs_cnt );

/* Compute txs_root from raw transaction data.
   Parses each tx, computes BLAKE3 hash, then computes txs_root.

   Parameters:
     out_root       - Output buffer for 32-byte txs_root
     txn_data       - Raw transaction data (concatenated)
     txn_data_sz    - Total size of transaction data
     txn_cnt        - Number of transactions
     out_tx_hashes  - Optional output buffer for individual tx hashes
                      (must be at least txn_cnt * 32 bytes if provided)

   Returns: out_root on success, NULL on error. */
uchar *
at_txs_root_compute_from_raw( uchar         out_root[32],
                              uchar const * txn_data,
                              ulong         txn_data_sz,
                              ulong         txn_cnt,
                              uchar       (*out_tx_hashes)[32] );

AT_PROTOTYPES_END

#endif /* HEADER_at_block_at_txs_root_h */
