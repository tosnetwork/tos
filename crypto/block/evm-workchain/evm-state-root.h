/*
    EVM Workchain — Ethereum-compatible trie root computation.

    Provides proper Merkle Patricia Trie root hashes for transactionsRoot
    and receiptsRoot using the vendored Silkworm trie library
    (silkworm::trie::root_hash from vector_root.hpp).

    The transactionsRoot is the MPT root of RLP-encoded transactions keyed
    by their RLP-encoded index within the block (Yellow Paper Section 4.3.2).
    The receiptsRoot follows the same structure over RLP-encoded receipts.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include <vector>

#include <evmc/evmc.hpp>

#include "evm-state.h"

namespace evm_workchain {

/// Compute the Ethereum transactionsRoot (MPT root of RLP-encoded transactions)
/// for the given block's transaction list.
///
/// @param tx_hashes  Ordered list of transaction hashes in the block.
/// @param state      EVM state containing stored transactions (caller must hold lock).
/// @return           The 32-byte Merkle Patricia Trie root hash.
evmc::bytes32 compute_transactions_root(const std::vector<evmc::bytes32>& tx_hashes,
                                         const EvmState& state);

/// Compute the Ethereum receiptsRoot (MPT root of RLP-encoded receipts)
/// for the given block's transaction list.
///
/// @param tx_hashes  Ordered list of transaction hashes in the block.
/// @param state      EVM state containing stored receipts (caller must hold lock).
/// @return           The 32-byte Merkle Patricia Trie root hash.
evmc::bytes32 compute_receipts_root(const std::vector<evmc::bytes32>& tx_hashes,
                                     const EvmState& state);

}  // namespace evm_workchain
