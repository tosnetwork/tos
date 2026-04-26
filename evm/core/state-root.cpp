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

// Compute the RLP payload length for a StoredTransaction encoded as a
// legacy Ethereum transaction: [nonce, gasPrice, gasLimit, to, value, data, v, r, s].
// We encode v=0, r=0, s=0 since StoredTransaction does not carry signature fields.
static size_t stored_tx_payload_length(const StoredTransaction& tx) {
    size_t len = 0;
    len += silkworm::rlp::length(tx.nonce);
    len += silkworm::rlp::length(tx.gas_price);
    len += silkworm::rlp::length(tx.gas_limit);
    // "to": RLP-encode as 20-byte address or as empty string (for contract creation)
    if (tx.to) {
        len += silkworm::rlp::length(*tx.to);
    } else {
        len += silkworm::rlp::length(ByteView{});
    }
    len += silkworm::rlp::length(tx.value);
    len += silkworm::rlp::length(ByteView{tx.data});
    // v, r, s — we store 0 for all (no signature preserved in StoredTransaction)
    len += silkworm::rlp::length(uint64_t{0});  // v
    len += silkworm::rlp::length(intx::uint256{0});  // r
    len += silkworm::rlp::length(intx::uint256{0});  // s
    return len;
}

// Encode a StoredTransaction as RLP for trie root computation.
// Format: legacy tx RLP list [nonce, gasPrice, gasLimit, to, value, data, v, r, s].
static void encode_stored_transaction(Bytes& to, const StoredTransaction& tx) {
    if (!tx.raw_rlp.empty()) {
        to.insert(to.end(), tx.raw_rlp.begin(), tx.raw_rlp.end());
        return;
    }

    const size_t payload = stored_tx_payload_length(tx);
    silkworm::rlp::encode_header(to, {.list = true, .payload_length = payload});

    silkworm::rlp::encode(to, tx.nonce);
    silkworm::rlp::encode(to, tx.gas_price);
    silkworm::rlp::encode(to, tx.gas_limit);
    if (tx.to) {
        silkworm::rlp::encode(to, *tx.to);
    } else {
        silkworm::rlp::encode(to, ByteView{});
    }
    silkworm::rlp::encode(to, tx.value);
    silkworm::rlp::encode(to, ByteView{tx.data});
    silkworm::rlp::encode(to, uint64_t{0});        // v
    silkworm::rlp::encode(to, intx::uint256{0});   // r
    silkworm::rlp::encode(to, intx::uint256{0});   // s
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

evmc::bytes32 compute_transactions_root(const std::vector<evmc::bytes32>& tx_hashes,
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
        if (tx) {
            txns.push_back(*tx);
        } else {
            // Fallback: insert a default/empty transaction so indices stay aligned
            txns.emplace_back();
        }
    }

    return silkworm::trie::root_hash(txns, encode_stored_transaction);
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
    if (txns.empty()) {
        silkworm::trie::HashBuilder hb;
        return hb.root_hash();
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
