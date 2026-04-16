/*
    EVM Workchain — cell codec implementation.
    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm-cell-codec.h"

#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"

#include <cstring>

namespace evm_workchain {

td::Ref<vm::Cell> encode_evm_account_data(const silkworm::Account& acct,
                                          const td::Ref<vm::Cell>& storage_root) {
    vm::CellBuilder cb;
    // magic#45564d (24 bits)
    cb.store_long(static_cast<long long>(kEvmAccountMagic), kEvmMagicBits);
    // nonce (64 bits, big-endian)
    cb.store_long(static_cast<long long>(acct.nonce), 64);
    // balance (256 bits, big-endian uint256)
    auto bal_be = intx::be::store<evmc::uint256be>(acct.balance);
    cb.store_bytes(bal_be.bytes, 32);
    // code_hash (256 bits)
    cb.store_bytes(acct.code_hash.bytes, 32);
    // storage: HashmapE 256 ^EvmStorageEntry
    // = Maybe ^Cell  → 1 bit + ^Cell (if present)
    if (storage_root.not_null()) {
        cb.store_long(1, 1);
        cb.store_ref(storage_root);
    } else {
        cb.store_long(0, 1);
    }
    return cb.finalize();
}

bool decode_evm_account_data(td::Ref<vm::Cell> cell,
                             silkworm::Account& acct,
                             td::Ref<vm::Cell>& storage_root) {
    if (cell.is_null()) return false;
    auto cs = vm::load_cell_slice(cell);
    // magic
    long long magic = 0;
    if (!cs.fetch_long_bool(kEvmMagicBits, magic) ||
        static_cast<unsigned long long>(magic) != kEvmAccountMagic) {
        return false;
    }
    // nonce
    long long nonce = 0;
    if (!cs.fetch_long_bool(64, nonce)) return false;
    acct.nonce = static_cast<uint64_t>(nonce);
    // balance
    evmc::uint256be bal_be{};
    if (!cs.fetch_bytes(bal_be.bytes, 32)) return false;
    acct.balance = intx::be::load<intx::uint256>(bal_be);
    // code_hash
    if (!cs.fetch_bytes(acct.code_hash.bytes, 32)) return false;
    // storage Maybe ^Cell
    long long has_storage = 0;
    if (!cs.fetch_long_bool(1, has_storage)) return false;
    if (has_storage) {
        if (!cs.fetch_ref_to(storage_root)) return false;
    } else {
        storage_root = td::Ref<vm::Cell>{};
    }
    // incarnation is not part of cell schema (always 0 in our model)
    acct.incarnation = 0;
    return true;
}

td::Ref<vm::Cell> encode_storage_value(const evmc::bytes32& value) {
    vm::CellBuilder cb;
    cb.store_bytes(value.bytes, 32);
    return cb.finalize();
}

evmc::bytes32 decode_storage_value(td::Ref<vm::Cell> cell) {
    evmc::bytes32 v{};
    if (cell.is_null()) return v;
    auto cs = vm::load_cell_slice(cell);
    if (cs.size() >= 256) {
        cs.fetch_bytes(v.bytes, 32);
    }
    return v;
}

void address_to_key(const evmc::address& addr, unsigned char out[32]) {
    std::memset(out, 0, 12);                     // left-pad
    std::memcpy(out + 12, addr.bytes, 20);       // 20-byte EVM address
}

void bytes32_to_key(const evmc::bytes32& v, unsigned char out[32]) {
    std::memcpy(out, v.bytes, 32);
}

}  // namespace evm_workchain
