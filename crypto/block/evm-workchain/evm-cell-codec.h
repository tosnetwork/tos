/*
    EVM Workchain — cell codec for EVM account data.

    Encodes/decodes EVM accounts and storage values into TOS cells, following
    the cell-native design:

      evm_account_data#45564d
        nonce:uint64
        balance:uint256
        code_hash:bits256
        storage:(HashmapE 256 ^EvmStorageEntry)
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

/// Encode a silkworm::Account plus its storage root cell into an EvmAccountData cell.
/// storage_root may be null (no storage).
td::Ref<vm::Cell> encode_evm_account_data(const silkworm::Account& acct,
                                          const td::Ref<vm::Cell>& storage_root);

/// Decode an EvmAccountData cell back into a silkworm::Account and its storage root cell.
/// Returns true on success. storage_root may be set to null if account has no storage.
bool decode_evm_account_data(td::Ref<vm::Cell> cell,
                             silkworm::Account& acct,
                             td::Ref<vm::Cell>& storage_root);

/// Encode a 32-byte storage value into a cell (256 data bits, 0 refs).
td::Ref<vm::Cell> encode_storage_value(const evmc::bytes32& value);

/// Decode a storage value cell back into bytes32. Returns zero on failure.
evmc::bytes32 decode_storage_value(td::Ref<vm::Cell> cell);

/// Build a 256-bit key from a 20-byte EVM address (left-padded with zeros).
/// Stores the result into out (must point to 32 bytes / 256 bits of writable space).
void address_to_key(const evmc::address& addr, unsigned char out[32]);

/// Convert a bytes32 directly to a 256-bit key (identity copy into out).
void bytes32_to_key(const evmc::bytes32& v, unsigned char out[32]);

}  // namespace evm_workchain
