/*
    EVM Workchain — Ethereum-compatible trie root computation.

    Uses silkworm::trie::root_hash() (vector_root.hpp) to compute proper
    Merkle Patricia Trie roots for transactionsRoot and receiptsRoot.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm/core/state-root.h"

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/rlp/encode.hpp>
#include <silkworm/core/trie/vector_root.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/bloom.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/core/types/log.hpp>
#include <silkworm/core/types/receipt.hpp>

namespace evm_workchain {

using silkworm::Bytes;
using silkworm::ByteView;

// ---------------------------------------------------------------------------
// Transaction RLP encoding
// ---------------------------------------------------------------------------

// Encode the original signed transaction RLP for trie root computation.
// No legacy fallback: TOS has not launched, so newly produced block records
// must carry `raw_rlp`; callers use try_* APIs to fail closed before this
// encoder is invoked.
static void encode_stored_transaction(Bytes& to, const StoredTransaction& tx) {
    to.insert(to.end(), tx.raw_rlp.begin(), tx.raw_rlp.end());
}

// Encode a StoredReceipt as RLP for trie root computation.
// Format: receipt RLP list [status, cumulativeGasUsed, logsBloom, logs].
static void encode_stored_receipt(Bytes& to, const StoredReceipt& receipt) {
    silkworm::Receipt sw_receipt;
    sw_receipt.type = receipt.type;
    sw_receipt.success = receipt.success;
    sw_receipt.cumulative_gas_used = receipt.cumulative_gas_used;
    sw_receipt.bloom = silkworm::logs_bloom(receipt.logs);
    sw_receipt.logs = receipt.logs;
    silkworm::rlp::encode(to, sw_receipt);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

std::optional<evmc::bytes32> try_compute_transactions_root(
    const std::vector<evmc::bytes32>& tx_hashes,
    const EvmState& state) {
    if (tx_hashes.empty()) {
        // Empty trie root = keccak256(RLP("")) = kEmptyRoot
        // silkworm::trie::HashBuilder::root_hash() returns this for empty input.
        silkworm::trie::HashBuilder hb;
        return hb.root_hash();
    }

    // Gather stored transactions in block order
    std::vector<StoredTransaction> txns;
    txns.reserve(tx_hashes.size());
    for (const auto& h : tx_hashes) {
        const auto* tx = state.get_transaction(h);
        if (!tx || tx->raw_rlp.empty()) {
            return std::nullopt;
        }
        txns.push_back(*tx);
    }

    return silkworm::trie::root_hash(txns, encode_stored_transaction);
}

evmc::bytes32 compute_transactions_root(const std::vector<evmc::bytes32>& tx_hashes,
                                         const EvmState& state) {
    auto root = try_compute_transactions_root(tx_hashes, state);
    return root.value_or(evmc::bytes32{});
}

evmc::bytes32 compute_receipts_root(const std::vector<evmc::bytes32>& tx_hashes,
                                     const EvmState& state) {
    if (tx_hashes.empty()) {
        silkworm::trie::HashBuilder hb;
        return hb.root_hash();
    }

    // Gather stored receipts in block order
    std::vector<StoredReceipt> receipts;
    receipts.reserve(tx_hashes.size());
    for (const auto& h : tx_hashes) {
        const auto* r = state.get_receipt(h);
        if (r) {
            receipts.push_back(*r);
        } else {
            receipts.emplace_back();
        }
    }

    return silkworm::trie::root_hash(receipts, encode_stored_receipt);
}

// ---------------------------------------------------------------------------
// Audit #5 (2026-04-26): state-less variants. The consensus compute path
// constructs StoredTransaction / StoredReceipt records inline (in fx) and
// must derive the block roots from those records directly — at compute time
// the records are not yet stored in EvmState (publication is deferred to
// post-accept), so the state-lookup variants would silently substitute
// default-empty records and produce wrong transactionsRoot/receiptsRoot.
// ---------------------------------------------------------------------------

evmc::bytes32 compute_transactions_root_from_records(
    const std::vector<StoredTransaction>& txns) {
    auto root = try_compute_transactions_root_from_records(txns);
    return root.value_or(evmc::bytes32{});
}

std::optional<evmc::bytes32> try_compute_transactions_root_from_records(
    const std::vector<StoredTransaction>& txns) {
    if (txns.empty()) {
        silkworm::trie::HashBuilder hb;
        return hb.root_hash();
    }
    for (const auto& tx : txns) {
        if (tx.raw_rlp.empty()) {
            return std::nullopt;
        }
    }
    return silkworm::trie::root_hash(txns, encode_stored_transaction);
}

evmc::bytes32 compute_receipts_root_from_records(
    const std::vector<StoredReceipt>& receipts) {
    if (receipts.empty()) {
        silkworm::trie::HashBuilder hb;
        return hb.root_hash();
    }
    return silkworm::trie::root_hash(receipts, encode_stored_receipt);
}

}  // namespace evm_workchain
