/*
    EVM Workchain — cell codec for EVM account data.

    Encodes/decodes EVM accounts and storage values into TOS cells, following
    the cell-native design:

      evm_account_data#45564d
        nonce:uint64
        balance:uint256
        code_hash:bits256
        storage:(Maybe ^Cell)
        code:(Maybe ^EvmBytecodeChunk)
        = EvmAccountData;

      evm_storage_entry#_ value:bits256 = EvmStorageEntry;

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include <silkworm/core/types/account.hpp>
#include <evmc/evmc.hpp>

#include "vm/cells.h"

namespace evm_workchain {

constexpr unsigned long long kEvmAccountMagic = 0x45564Dull;  // "EVM"
constexpr int kEvmMagicBits = 24;
constexpr unsigned kCpNewDataSchemaVersion = 4;

/// Encode a silkworm::Account plus its storage root and (optional) bytecode
/// chain into an EvmAccountData cell. Either ref may be null.
td::Ref<vm::Cell> encode_evm_account_data(const silkworm::Account& acct,
                                          const td::Ref<vm::Cell>& storage_root,
                                          const td::Ref<vm::Cell>& code_root = {});

/// Decode an EvmAccountData cell back into a silkworm::Account plus its
/// storage and code root cells. Either output ref may be null. Returns true
/// on success. Requires the current canonical schema, including code:Maybe^Cell.
bool decode_evm_account_data(td::Ref<vm::Cell> cell,
                             silkworm::Account& acct,
                             td::Ref<vm::Cell>& storage_root,
                             td::Ref<vm::Cell>& code_root);

inline bool decode_evm_account_data(td::Ref<vm::Cell> cell,
                                    silkworm::Account& acct,
                                    td::Ref<vm::Cell>& storage_root) {
    td::Ref<vm::Cell> code_root;
    return decode_evm_account_data(std::move(cell), acct, storage_root, code_root);
}

/// Encode a 32-byte storage value into a cell (256 data bits, 0 refs).
td::Ref<vm::Cell> encode_storage_value(const evmc::bytes32& value);

/// Decode a storage value cell back into bytes32. Returns false on malformed
/// cells and requires canonical 256-bit, 0-ref shape.
bool decode_storage_value(td::Ref<vm::Cell> cell, evmc::bytes32& out);

/// Decode a storage value cell back into bytes32. Returns zero on failure.
evmc::bytes32 decode_storage_value(td::Ref<vm::Cell> cell);

/// Build a 256-bit key from a 20-byte EVM address (left-padded with zeros).
/// Stores the result into out (must point to 32 bytes / 256 bits of writable space).
void address_to_key(const evmc::address& addr, unsigned char out[32]);

/// Convert a bytes32 directly to a 256-bit key (identity copy into out).
void bytes32_to_key(const evmc::bytes32& v, unsigned char out[32]);

/// Decode a `cp.new_data`-shaped cell (the cell that compute-phase writes
/// into `Transaction::new_data` for wc=1 accounts). Layout:
///
///   v4: magic:24 + schema_version:uint8(4)
///       + has_state_root:1 + [state_root:^Cell]
///       + eth_state_root:bits256 + Maybe ^EvmRpcCacheRoot
///       + Maybe ^EvmBlockHashHistoryRoot
///       + Maybe ^ReservedBlockAccumulatorRoot (must be absent)
///
/// On success returns true and populates the output refs/value. `state_root`
/// may be null if `has_state_root` was zero (valid per the encoder, used at
/// genesis when the executor account exists with no inner state). The decoder
/// requires canonical v4 shape, rejects trailing bits/refs, and can verify
/// that `eth_state_root` is the full trie root recomputed from `state_root`.
///
/// Used by both the snapshot compute path (to seed a per-call CellEvmState
/// from the block-declared pre-state) and the global-state hydration path
/// (`populate_state_from_shard_accounts`).
bool decode_cp_new_data(const td::Ref<vm::Cell>& cell,
                        td::Ref<vm::Cell>& state_root_out,
                        evmc::bytes32& eth_state_root_out,
                        td::Ref<vm::Cell>& rpc_cache_root_out,
                        bool verify_eth_state_root = true,
                        td::Ref<vm::Cell>* block_hashes_root_out = nullptr,
                        td::Ref<vm::Cell>* block_accumulator_root_out = nullptr);

// ---------------------------------------------------------------------------
// EVM bytecode cell encoding (Phase D.2)
// ---------------------------------------------------------------------------
//
// Schema:
//   evm_bytecode_chunk$_ {n:#}
//     bytes:(n * Bit) { n <= 1016 }
//     next:(Maybe ^Cell)
//     = EvmBytecodeChunk;
//
// Linear chain: each cell stores up to 127 bytes (1016 bits) inline + a
// Maybe-tagged ref to the next chunk. A 24 KB EIP-170 max contract uses
// ~190 cells; typical 5–15 KB contracts use 40–120 cells.

/// Maximum bytes stored inline per chunk cell.
constexpr unsigned kEvmBytecodeChunkBytes = 127;

/// Encode arbitrary EVM bytecode into a chain of cells. Returns null cell
/// when `code` is empty. Deterministic — identical input bytes produce
/// identical cell hashes on every binary.
td::Ref<vm::Cell> encode_evm_bytecode(td::Slice code);

/// Walk a bytecode chain and return concatenated bytes. Returns empty on:
///   - null root cell
///   - cell shaped like `kEvmCodeMarker` (callers should never invoke this
///     for accounts whose code_hash == silkworm::kEmptyHash; if they do,
///     this function refuses to misinterpret the marker as 1-byte bytecode)
///   - any malformed chunk (logs nothing; just returns empty)
std::string decode_evm_bytecode(td::Ref<vm::Cell> root);

}  // namespace evm_workchain
