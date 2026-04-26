/*
    EVM Workchain — RPC cache cell codec (Phase F scaffold).

    Encodes/decodes the receipts / transactions / blocks / logs that today live
    in `g_evm_state` RAM containers (see `evm-state.h`) into TOS cells.  The
    persisted form is described in `doc/evm-workchain-rpc-cache-persistence.md`
    (Option C: side-channel cell tree referenced from `cp.new_data` but NOT
    contributing to consensus state_hash).

    This file is a *scaffold* for that design.  It defines:
      - encode_persisted_receipt(StoredReceipt) -> Cell
      - decode_persisted_receipt(Cell, StoredReceipt&) -> bool

    The live receipt-store path (evm-compute-phase.cpp / evm-state.cpp /
    evm-rpc.cpp) is intentionally NOT yet wired.  See the design doc above
    for the full Phase F plan; this file is the proof-of-concept that the
    chosen TLB schema round-trips losslessly under existing CellBuilder /
    CellSlice.

    TLB schema (PersistedReceipt only — full schema in the design doc):

      persisted_receipt#52505432     // "RPT2"
        type:uint8                   // EIP-2718 transaction type
        success:Bool
        gas_used:uint64
        cumulative_gas_used:uint64
        block_number:uint64
        tx_index:uint32
        from:bits160
        to_kind:(## 2)               // 0 = none, 1 = address
        to:to_kind?bits160
        contract_kind:(## 2)
        contract_address:contract_kind?bits160
        return_data:(Maybe ^Cell)    // chunked, reuses encode_evm_bytecode
        logs:^PersistedLogList
        = PersistedReceipt;

      persisted_log#4c4f4720         // "LOG "
        address:bits160
        topic_count:(## 4)
        topics:(Maybe ^TopicArray)   // outer ref so we don't blow the cell
                                     // when topic_count == 4 (4×256 = 1024 b)
        data:(Maybe ^Cell)
        = PersistedLog;

      // Topics live in a parent cell whose refs each point at one 32-byte
      // leaf cell. The per-topic-ref form (rather than inline) is forced
      // by the per-cell 1023-bit limit: 4 × 256 = 1024 bits would not fit
      // a single cell.
      topic_array#_ {n:#} entries:(n * ^TopicLeaf) { n <= 4 } = TopicArray;
      topic_leaf#_ topic:bits256 = TopicLeaf;

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include "evm/core/state.h"

#include "vm/cells.h"

namespace evm_workchain {

// 32-bit cell magic ("RPT2"). Matches the TLB schema in the design doc.
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

/// Encode a StoredReceipt into a single cell tree (returns the root).
///
/// The encoding is deterministic — identical input produces identical cell
/// hashes on every binary, so two validators that both call this on the same
/// receipt produce byte-equal cells.  Determinism is required even though
/// receipts are non-consensus, because operators that compare receipts
/// across validators (indexers, bridges) expect byte equality.
td::Ref<vm::Cell> encode_persisted_receipt(const StoredReceipt& receipt);

/// Decode a cell tree produced by `encode_persisted_receipt` back into a
/// StoredReceipt.  Returns true on success; on failure `out` is left in an
/// unspecified (but not corrupting) state.
bool decode_persisted_receipt(td::Ref<vm::Cell> cell, StoredReceipt& out);

/// Encode/decode a StoredTransaction (eth_getTransactionByHash payload).
td::Ref<vm::Cell> encode_persisted_transaction(const StoredTransaction& txn);
bool decode_persisted_transaction(td::Ref<vm::Cell> cell, StoredTransaction& out);

/// Encode/decode a StoredBlock (eth_getBlockByNumber / *_byHash payload).
td::Ref<vm::Cell> encode_persisted_block(const StoredBlock& block);
bool decode_persisted_block(td::Ref<vm::Cell> cell, StoredBlock& out);

/// Encode/decode the per-block IndexedLog vector (eth_getLogs payload).
///
/// Each IndexedLog adds (block_number, tx_hash, log_index, tx_index) to the
/// silkworm::Log fields already covered by the existing PersistedLog cell.
/// We store them as a chunked chain: each chunk holds up to 3 ref slots for
/// IndexedLog cells + 1 continuation ref. The head cell carries the total
/// count (32 bits — well beyond any plausible per-block log count).
td::Ref<vm::Cell> encode_persisted_logs_for_block(const std::vector<IndexedLog>& logs);
bool decode_persisted_logs_for_block(td::Ref<vm::Cell> cell, std::vector<IndexedLog>& out);

}  // namespace evm_workchain
