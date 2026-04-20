#ifndef HEADER_at_contract_opaque_at_contract_opaque_block_h
#define HEADER_at_contract_opaque_at_contract_opaque_block_h

#include "at/block/at_block.h"
#include "at/contract/opaque/at_contract_opaque_transaction.h"

AT_PROTOTYPES_BEGIN

typedef struct {
  at_block_t const * block;
} at_contract_opaque_block_t;

int
at_contract_opaque_block_current( at_contract_chain_state_t const * state,
                                  at_contract_opaque_block_t *      out );

int
at_contract_opaque_block_nonce( at_contract_opaque_block_t const * block,
                                ulong *                            nonce_out );

int
at_contract_opaque_block_timestamp( at_contract_opaque_block_t const * block,
                                    ulong *                            timestamp_out );

int
at_contract_opaque_block_miner( at_contract_opaque_block_t const * block,
                                int                                mainnet,
                                at_contract_opaque_address_t *     miner_out );

int
at_contract_opaque_block_hash( at_contract_chain_state_t const * state,
                               at_contract_opaque_hash_t *       hash_out );

int
at_contract_opaque_block_version( at_contract_opaque_block_t const * block,
                                  uint *                             version_out );

int
at_contract_opaque_block_tips( at_contract_opaque_block_t const * block,
                               uchar const (**                   tips_out)[32],
                               ulong *                            tips_cnt_out );

int
at_contract_opaque_block_transactions_hashes( at_contract_opaque_block_t const * block,
                                              at_contract_opaque_hash_t *        hashes_out,
                                              ulong                               max_hashes,
                                              ulong *                             count_out );

int
at_contract_opaque_block_transactions_count( at_contract_opaque_block_t const * block,
                                             ulong *                             count_out );

int
at_contract_opaque_block_height( at_contract_opaque_block_t const * block,
                                 ulong *                            height_out );

int
at_contract_opaque_block_extra_nonce( at_contract_opaque_block_t const * block,
                                      uchar                               out[32] );

AT_PROTOTYPES_END

#endif /* HEADER_at_contract_opaque_at_contract_opaque_block_h */
