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

#include "evm/core/state.h"

namespace evm_workchain {

/// Compute the Ethereum transactionsRoot (MPT root of RLP-encoded transactions)
/// for the given block's transaction list.
///
/// @param tx_hashes  Ordered list of transaction hashes in the block.
/// @param state      EVM state containing stored transactions (caller must hold lock).
/// @return           The 32-byte Merkle Patricia Trie root hash.
///
/// NOTE: when a tx_hash is not present in `state` this function inserts a
/// default-empty StoredTransaction at that index — callers on the consensus
/// compute path must use `compute_transactions_root_from_records()` instead,
/// which derives the root directly from the side-effect buffer (audit #5).
evmc::bytes32 compute_transactions_root(const std::vector<evmc::bytes32>& tx_hashes,
                                         const EvmState& state);

/// Compute the Ethereum receiptsRoot (MPT root of RLP-encoded receipts)
/// for the given block's transaction list.
///
/// @param tx_hashes  Ordered list of transaction hashes in the block.
/// @param state      EVM state containing stored receipts (caller must hold lock).
/// @return           The 32-byte Merkle Patricia Trie root hash.
///
/// NOTE: see compute_transactions_root above — same fallback semantics; use
/// `compute_receipts_root_from_records()` on the consensus compute path.
evmc::bytes32 compute_receipts_root(const std::vector<evmc::bytes32>& tx_hashes,
                                     const EvmState& state);

/// Audit #5 (2026-04-26) — state-less variants used by the consensus
/// compute phase. Compute the MPT root directly over the supplied records,
/// without consulting EvmState. The state-based overloads above silently
/// substitute default-empty records when get_transaction/get_receipt miss,
/// which produced wrong roots whenever compute ran before post-accept
/// publication (i.e. the entire single-tx-per-block flow).
evmc::bytes32 compute_transactions_root_from_records(
    const std::vector<StoredTransaction>& txns);

evmc::bytes32 compute_receipts_root_from_records(
    const std::vector<StoredReceipt>& receipts);

}  // namespace evm_workchain
