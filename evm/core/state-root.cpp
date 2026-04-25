/*
    EVM Workchain — Ethereum-compatible trie root computation.

    Uses silkworm::trie::root_hash() (vector_root.hpp) to compute proper
    Merkle Patricia Trie roots for transactionsRoot and receiptsRoot.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm/core/state-root.h"

#include <cstring>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/rlp/encode.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/core/trie/vector_root.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/core/types/log.hpp>

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

// ---------------------------------------------------------------------------
// Receipt RLP encoding
// ---------------------------------------------------------------------------

// Compute the RLP payload length for a StoredReceipt encoded as an
// Ethereum receipt: [status, cumulativeGasUsed, logsBloom, logs].
static size_t stored_receipt_payload_length(const StoredReceipt& receipt) {
    size_t len = 0;
    // status: boolean (1 = success, 0 = failure), RLP-encoded as integer
    len += silkworm::rlp::length(receipt.success);
    len += silkworm::rlp::length(receipt.cumulative_gas_used);

    // logsBloom: 256 bytes (always fixed length as a byte string)
    // We compute the bloom from receipt logs inline.
    len += silkworm::rlp::length(ByteView{nullptr, 256});

    // logs: RLP list of Log entries
    // Each Log is [address, topics, data] — silkworm already provides rlp::length(Log)
    size_t logs_payload = 0;
    for (const auto& log : receipt.logs) {
        logs_payload += silkworm::rlp::length(log);
    }
    len += silkworm::rlp::length_of_length(logs_payload) + logs_payload;

    return len;
}

// Compute the 256-byte Ethereum bloom filter for a set of logs.
// Reference: Silkworm ~/s/silkworm/core/types/bloom.cpp
static void compute_receipt_bloom(const std::vector<silkworm::Log>& logs, uint8_t bloom[256]) {
    std::memset(bloom, 0, 256);
    for (const auto& log : logs) {
        auto ah = ethash::keccak256(log.address.bytes, 20);
        for (int i = 0; i < 6; i += 2) {
            uint16_t bit = (static_cast<uint16_t>(ah.bytes[i]) << 8 | ah.bytes[i + 1]) & 0x7FF;
            bloom[bit / 8] |= (1 << (bit % 8));
        }
        for (const auto& topic : log.topics) {
            auto th = ethash::keccak256(topic.bytes, 32);
            for (int i = 0; i < 6; i += 2) {
                uint16_t bit = (static_cast<uint16_t>(th.bytes[i]) << 8 | th.bytes[i + 1]) & 0x7FF;
                bloom[bit / 8] |= (1 << (bit % 8));
            }
        }
    }
}

// Encode a StoredReceipt as RLP for trie root computation.
// Format: receipt RLP list [status, cumulativeGasUsed, logsBloom, logs].
static void encode_stored_receipt(Bytes& to, const StoredReceipt& receipt) {
    const size_t payload = stored_receipt_payload_length(receipt);
    silkworm::rlp::encode_header(to, {.list = true, .payload_length = payload});

    silkworm::rlp::encode(to, receipt.success);
    silkworm::rlp::encode(to, receipt.cumulative_gas_used);

    // Logs bloom: compute and encode as 256-byte string
    uint8_t bloom[256];
    compute_receipt_bloom(receipt.logs, bloom);
    silkworm::rlp::encode(to, ByteView{bloom, 256});

    // Logs list: encode header then each log
    size_t logs_payload = 0;
    for (const auto& log : receipt.logs) {
        logs_payload += silkworm::rlp::length(log);
    }
    silkworm::rlp::encode_header(to, {.list = true, .payload_length = logs_payload});
    for (const auto& log : receipt.logs) {
        silkworm::rlp::encode(to, log);
    }
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
