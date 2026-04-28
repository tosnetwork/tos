/*
    EVM Workchain — native (no-MPT) block-content commitments.

    Implementation notes:

      - All list commitments are keccak256 of a flat byte stream:
            domain_tag || u32_be(count) || (u32_be(len_i) || record_i)*
        with a static, version-tagged domain prefix per list type.
      - u32_be is a fixed-width 4-byte big-endian count / length. The
        record-count and each per-record length are bounded by the
        EvmState capacity caps (kMaxCachedReceipts / kMaxCachedTransactions
        ~ 10 000) and by silkworm RLP encoding sizes — both well under
        2^32, so the u32 width is sufficient.
      - The buffer is materialised into a contiguous silkworm::Bytes
        before hashing. We do not stream into keccak because ethash
        exposes only a one-shot API; the buffer size is bounded by the
        callers' already-resident record vector and is not new memory
        pressure.
      - State commitment short-circuits to the cell representation hash:
        the TOS cell DAG already commits to the full EVM account /
        storage / code subtree.

    Source: TOS-specific adapter (not copied from third-party silkworm).
*/
#include "evm/core/native-commitment.h"

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <ethash/keccak.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/rlp/encode.hpp>
#include <silkworm/core/types/bloom.hpp>
#include <silkworm/core/types/log.hpp>
#include <silkworm/core/types/receipt.hpp>

namespace evm_workchain {

namespace {

using silkworm::Bytes;

// Domain-separation tags. Raw byte literals, no NUL terminator. The "-vN"
// suffix is part of the tag — bumping it produces a disjoint commitment
// space and is the supported way to evolve the encoding.
constexpr unsigned char kTxListDomain[]      = "TOS-EVM-TX-LIST-v1";
constexpr unsigned char kReceiptListDomain[] = "TOS-EVM-RCPT-LIST-v1";
constexpr unsigned char kLogListDomain[]     = "TOS-EVM-LOG-LIST-v1";

// sizeof(string-literal) includes the trailing NUL; subtract 1 to get the
// raw byte length the spec calls for.
constexpr size_t kTxListDomainLen      = sizeof(kTxListDomain) - 1;
constexpr size_t kReceiptListDomainLen = sizeof(kReceiptListDomain) - 1;
constexpr size_t kLogListDomainLen     = sizeof(kLogListDomain) - 1;

inline void append_bytes(Bytes& to, const unsigned char* data, size_t len) {
    to.insert(to.end(), data, data + len);
}

inline void append_u32_be(Bytes& to, uint32_t value) {
    unsigned char buf[4];
    buf[0] = static_cast<unsigned char>((value >> 24) & 0xFF);
    buf[1] = static_cast<unsigned char>((value >> 16) & 0xFF);
    buf[2] = static_cast<unsigned char>((value >> 8) & 0xFF);
    buf[3] = static_cast<unsigned char>(value & 0xFF);
    to.insert(to.end(), buf, buf + 4);
}

inline evmc::bytes32 keccak_of(const Bytes& buf) {
    auto h = ethash::keccak256(buf.data(), buf.size());
    evmc::bytes32 out{};
    std::memcpy(out.bytes, h.bytes, 32);
    return out;
}

// Encode a transaction record canonically. Mirrors the encoder used by the
// legacy trie-based path in state-root.cpp: the original signed RLP is the
// canonical byte form. Empty raw_rlp would produce a zero-length record;
// callers (post-accept publication) must already have populated raw_rlp
// before commitment time.
inline void encode_tx_record(Bytes& to, const StoredTransaction& tx) {
    to.insert(to.end(), tx.raw_rlp.begin(), tx.raw_rlp.end());
}

// Encode a receipt record canonically. Mirrors encode_stored_receipt in the
// legacy state-root.cpp: silkworm RLP of [status, cumulativeGasUsed,
// logsBloom, logs] with the bloom recomputed from logs.
inline void encode_receipt_record(Bytes& to, const StoredReceipt& receipt) {
    silkworm::Receipt sw_receipt;
    sw_receipt.type = receipt.type;
    sw_receipt.success = receipt.success;
    sw_receipt.cumulative_gas_used = receipt.cumulative_gas_used;
    sw_receipt.bloom = silkworm::logs_bloom(receipt.logs);
    sw_receipt.logs = receipt.logs;
    silkworm::rlp::encode(to, sw_receipt);
}

inline void encode_log_record(Bytes& to, const silkworm::Log& log) {
    silkworm::rlp::encode(to, log);
}

// Generic length-prefixed list commitment.
//
//   keccak256(domain || u32_be(count) || (u32_be(len_i) || record_i)*)
//
// The per-record encoder appends the canonical bytes for a single record
// to a temporary buffer; we then write u32_be(len) followed by the buffer
// into the running stream. This keeps the encoder free of length-prefix
// bookkeeping and lets each record type reuse silkworm's RLP encoders
// directly.
template <typename Record, typename Encoder>
evmc::bytes32 commit_list(const unsigned char* domain,
                          size_t domain_len,
                          const std::vector<Record>& records,
                          Encoder&& encode_one) {
    Bytes stream;
    append_bytes(stream, domain, domain_len);
    append_u32_be(stream, static_cast<uint32_t>(records.size()));

    Bytes record_buf;
    for (const auto& record : records) {
        record_buf.clear();
        encode_one(record_buf, record);
        append_u32_be(stream, static_cast<uint32_t>(record_buf.size()));
        stream.insert(stream.end(), record_buf.begin(), record_buf.end());
    }
    return keccak_of(stream);
}

}  // namespace

evmc::bytes32 compute_native_evm_state_commitment(
    const td::Ref<vm::Cell>& state_root) {
    evmc::bytes32 out{};
    if (state_root.not_null()) {
        // Cell::get_hash() returns a Cell::Hash (Bits256-shaped); .as_array()
        // exposes the 32 raw bytes of the canonical representation hash.
        // This matches the existing pattern in init.cpp / cell-state.cpp.
        auto h = state_root->get_hash().as_array();
        std::memcpy(out.bytes, h.data(), 32);
    }
    return out;
}

evmc::bytes32 compute_native_tx_list_commitment(
    const std::vector<StoredTransaction>& txs) {
    return commit_list(kTxListDomain, kTxListDomainLen, txs,
                       encode_tx_record);
}

evmc::bytes32 compute_native_receipt_list_commitment(
    const std::vector<StoredReceipt>& receipts) {
    return commit_list(kReceiptListDomain, kReceiptListDomainLen, receipts,
                       encode_receipt_record);
}

evmc::bytes32 compute_native_log_list_commitment(
    const std::vector<silkworm::Log>& logs) {
    return commit_list(kLogListDomain, kLogListDomainLen, logs,
                       encode_log_record);
}

}  // namespace evm_workchain
