/*
    EVM Workchain — native (no-MPT) block-content commitments.

    Replaces the MPT-based transactionsRoot / receiptsRoot path with
    deterministic, domain-separated commitments over canonical record
    encodings. All commitments are:

      - byte-exact reproducible (no map/set iteration order, no RNG);
      - bounded by O(sum of record sizes) — callers already hold the full
        ordered record list in memory;
      - independent of any trie library and of any persistent KV store.

    State commitment uses the TOS cell representation hash directly: the
    cell DAG already provides a collision-resistant Merkle commitment over
    the entire EVM account/storage/code subtree.

    List commitments use keccak256 with a static domain tag and a
    length-prefixed record stream:

        commitment = keccak256(
            domain_tag_bytes
            || u32_be(count)
            || (u32_be(len_i) || record_i  for i in 0..count)
        )

    Source: TOS-specific adapter (not copied from third-party silkworm).
*/
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include <evmc/evmc.hpp>
#include <silkworm/core/types/log.hpp>

#include "evm/core/state.h"
#include "vm/cells.h"

namespace evm_workchain {

/// Native EVM state commitment.
///
/// On a non-null state-root cell, returns the cell's representation hash
/// (the TOS cell DAG already encodes a Merkle commitment over the EVM
/// account / storage / code subtree).
///
/// On a null state-root cell, returns the all-zero bytes32 (the canonical
/// "no EVM state present" commitment).
evmc::bytes32 compute_native_evm_state_commitment(
    const td::Ref<vm::Cell>& state_root);

/// Native commitment over an ordered transaction list.
///
/// Encoding per record: the original signed transaction RLP (`raw_rlp`).
/// This matches the canonical encoding the trie-based path used so old
/// records re-hash identically when loaded via the legacy importer.
///
/// Empty list returns keccak256(domain_tag || u32_be(0)).
evmc::bytes32 compute_native_tx_list_commitment(
    const std::vector<StoredTransaction>& txs);

/// Native commitment over an ordered receipt list.
///
/// Encoding per record: silkworm RLP-encoded
/// `[status, cumulativeGasUsed, logsBloom, logs]` receipt list (the
/// post-Byzantium canonical receipt encoding). The bloom is recomputed
/// from `receipt.logs` to match the trie-based path's behaviour.
///
/// Empty list returns keccak256(domain_tag || u32_be(0)).
evmc::bytes32 compute_native_receipt_list_commitment(
    const std::vector<StoredReceipt>& receipts);

/// Native commitment over an ordered log list.
///
/// Encoding per record: silkworm RLP-encoded `Log` (`[address, topics,
/// data]`). Used by callers that want a per-block log digest without
/// materialising any receipt-tree structure.
///
/// Empty list returns keccak256(domain_tag || u32_be(0)).
evmc::bytes32 compute_native_log_list_commitment(
    const std::vector<silkworm::Log>& logs);

}  // namespace evm_workchain
