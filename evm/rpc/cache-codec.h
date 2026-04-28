/*
    EVM Workchain — RPC cache cell codec.

    Encodes/decodes the receipts / transactions / blocks / logs that today live
    in `g_evm_state` RAM containers (see `evm-state.h`) into TOS cells.  The
    persisted form is described in `doc/evm-workchain-rpc-cache-persistence.md`
    (Option C: side-channel cell tree referenced from `cp.new_data` but NOT
    contributing to consensus state_hash).

    Canonical-identity binding (native-state plan)
    -----------------------------------------------
    Every cached record (per-receipt, per-transaction, per-block-by-{number,
    hash}, per-block-logs) MUST carry an `EvmCacheRecordStamp` that binds the
    record to the canonical (workchain_id, block_seqno, block_hash,
    native_state_commitment) tuple, plus a schema_version for offline
    invalidation.  The cache is allowed to lag or be wiped; it is NEVER the
    canonical truth.  An RPC reader treats any record whose stamp does not
    match the current canonical (block_hash, native_state_commitment) pair
    for the requested block_number as a cache-miss, falling back to the
    canonical reconstruction path.

    Records produced by older binaries that pre-date the stamp field are
    rejected on read and surfaced as cache-miss (with a logged warning).
    Bumping `kEvmCacheCodecSchemaVersion` invalidates the entire RocksDB
    cache directory and forces a rebuild from canonical state.

    TLB schema (PersistedReceipt sketch — full schema in the design doc):

      cache_record_stamp#5354414d   // "STAM"
        workchain_id:uint8
        schema_version:uint8
        block_seqno:uint32
        block_hash:bits256
        native_state_commitment:bits256
        logs_commitment:bits256        // receipt-only summary slot
        receipts_commitment:bits256    // receipt-only summary slot
        = CacheRecordStamp;

      persisted_receipt#52505432
        stamp:^CacheRecordStamp        // canonical-identity binding
        type:uint8
        success:Bool
        gas_used:uint64
        cumulative_gas_used:uint64
        block_number:uint64
        tx_index:uint32
        from:bits160
        to_kind:(##2) to:to_kind?bits160
        contract_kind:(##2) contract_address:contract_kind?bits160
        return_data:(Maybe ^Cell)
        logs:^PersistedLogList
        = PersistedReceipt;

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include "evm/core/state.h"

#include "vm/cells.h"

#include <cstdint>

namespace evm_workchain {

// 32-bit cell magics. Match the TLB schema in the design doc.
constexpr unsigned long long kPersistedReceiptMagic = 0x52505432ull;
constexpr int kPersistedReceiptMagicBits = 32;

constexpr unsigned long long kPersistedLogMagic = 0x4c4f4720ull;  // "LOG "
constexpr int kPersistedLogMagicBits = 32;

constexpr unsigned long long kPersistedTransactionMagic = 0x54584e5full;  // "TXN_"
constexpr int kPersistedTransactionMagicBits = 32;

constexpr unsigned long long kPersistedBlockMagic = 0x424c4b5full;  // "BLK_"
constexpr int kPersistedBlockMagicBits = 32;

constexpr unsigned long long kPersistedIndexedLogMagic = 0x494c4f47ull;  // "ILOG"
constexpr int kPersistedIndexedLogMagicBits = 32;

constexpr unsigned long long kCacheRecordStampMagic = 0x5354414dull;  // "STAM"
constexpr int kCacheRecordStampMagicBits = 32;

// Schema version for the entire cache directory. Bumping this constant
// invalidates every record on disk and forces hydration to rebuild from
// canonical state. Records whose stamp.schema_version does not match are
// rejected on read (logged-warning, surfaced as cache-miss). The hardening
// script does NOT verify this constant — it is a purely-internal invariant.
constexpr uint8_t kEvmCacheCodecSchemaVersion = 1;

// Canonical workchain id for the EVM workchain. Cached records produced by
// any other workchain are rejected on read.
constexpr uint8_t kEvmCacheWorkchainId = 1;

/// Canonical-identity binding stamped on every cached record.  The cache is
/// not authoritative; readers gate hits on the stamp matching the current
/// canonical chain at the requested block.
struct EvmCacheRecordStamp {
    uint8_t workchain_id{kEvmCacheWorkchainId};
    uint8_t schema_version{kEvmCacheCodecSchemaVersion};
    uint32_t block_seqno{0};
    evmc::bytes32 block_hash{};
    evmc::bytes32 native_state_commitment{};

    // Receipt-only summary slots so canonical-state hydration can
    // recompute logs/receipts without reaching back to the full RAM
    // containers. Producers (post-accept.cpp) populate these via
    // compute_native_log_list_commitment / compute_native_receipt_list_commitment.
    // Non-receipt records leave them zeroed; the decoder still emits them.
    evmc::bytes32 logs_commitment{};
    evmc::bytes32 receipts_commitment{};
};

/// Encode the stamp tuple as its own cell (called via store_ref by every
/// per-record encoder). Output is deterministic: identical input → identical
/// cell hash on every binary.
td::Ref<vm::Cell> encode_stamp(const EvmCacheRecordStamp& stamp);

/// Decode a stamp cell. Returns false on schema-magic mismatch or missing
/// fields. Caller compares the recovered stamp against the canonical chain
/// via `stamp_is_fresh` before consuming the wrapped record.
bool decode_stamp(td::Ref<vm::Cell> cell, EvmCacheRecordStamp& out);

/// Encode a StoredReceipt with its canonical-identity stamp.  The encoding
/// is deterministic — identical input produces identical cell hashes on
/// every binary.  Producer (post-accept.cpp) is responsible for filling
/// `stamp.logs_commitment` / `stamp.receipts_commitment`; failing to
/// populate them leaves the stamp valid but the receipt-only summary slots
/// zeroed, which the canonical-state path treats as "summary unavailable,
/// rebuild from receipts".
td::Ref<vm::Cell> encode_persisted_receipt(const StoredReceipt& receipt,
                                            const EvmCacheRecordStamp& stamp);

/// Decode a stamped receipt cell. Returns false on schema mismatch, missing
/// stamp, or layout corruption. On success `stamp_out` is populated with
/// the cached canonical-identity tuple — caller MUST gate consumption on
/// `stamp_is_fresh`.
bool decode_persisted_receipt(td::Ref<vm::Cell> cell, StoredReceipt& out,
                              EvmCacheRecordStamp& stamp_out);

/// Encode a StoredTransaction with its canonical-identity stamp.
td::Ref<vm::Cell> encode_persisted_transaction(const StoredTransaction& txn,
                                                const EvmCacheRecordStamp& stamp);
bool decode_persisted_transaction(td::Ref<vm::Cell> cell, StoredTransaction& out,
                                   EvmCacheRecordStamp& stamp_out);

/// Encode a StoredBlock. The stamp's workchain_id + schema_version are
/// the only explicit fields the encoder needs from the caller; the
/// canonical (block_seqno, block_hash, native_state_commitment) tuple is
/// derived from the StoredBlock fields (`number`, `hash`, `state_root`)
/// the encoder already sees.  Receipt-only summary slots in the stamp
/// are left zero for block records.
td::Ref<vm::Cell> encode_persisted_block(const StoredBlock& block,
                                          uint8_t workchain_id = kEvmCacheWorkchainId,
                                          uint8_t schema_version = kEvmCacheCodecSchemaVersion);
bool decode_persisted_block(td::Ref<vm::Cell> cell, StoredBlock& out,
                             EvmCacheRecordStamp& stamp_out);

/// Encode the per-block IndexedLog vector with its canonical-identity stamp.
///
/// Each IndexedLog adds (block_number, tx_hash, log_index, tx_index) to the
/// silkworm::Log fields already covered by the existing PersistedLog cell.
/// We store them as a chunked chain: each chunk holds up to 3 ref slots for
/// IndexedLog cells + 1 continuation ref. The head cell carries the total
/// count (32 bits — well beyond any plausible per-block log count) and a
/// ref to the stamp.
td::Ref<vm::Cell> encode_persisted_logs_for_block(const std::vector<IndexedLog>& logs,
                                                   const EvmCacheRecordStamp& stamp);
bool decode_persisted_logs_for_block(td::Ref<vm::Cell> cell,
                                      std::vector<IndexedLog>& out,
                                      EvmCacheRecordStamp& stamp_out);

}  // namespace evm_workchain
