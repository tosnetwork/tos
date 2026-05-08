/*
    JVM Workchain — per-account contract state envelope.

    Each JVM contract is a real wc=3 account at a deterministic 256-bit
    address with its own class bytes, per-account method manifest, and
    isolated storage.  This codec defines the canonical
    `JvmContractAccountState` cell (magic JVAC) carried in `account.data`
    plus a `StateInit{code, data}` builder used by `action_create_account`.
*/
#pragma once

#include <array>
#include <cstdint>

#include "jvm/core/config-param.h"
#include "jvm/core/deploy-abi.h"
#include "vm/cells.h"

namespace jvm_workchain {

constexpr std::uint32_t kJvmContractAccountStateMagic = 0x4a564143;  // "JVAC"
constexpr unsigned kJvmContractAccountStateMagicBits = 32;
constexpr std::uint8_t kJvmContractAccountStateSchemaVersion = 2;

// One contract == one wc=3 account.  Stored in `account.data`; the matching
// `account.code` cell is the activation marker (single byte 0x4a, see
// `jvm_activation_code_cell()` in dispatch-engine.cpp).
struct JvmContractAccountState {
    std::uint8_t schema_version{kJvmContractAccountStateSchemaVersion};
    std::array<std::uint8_t, kJvmStdlibHashBytes> stdlib_hash{};
    JvmClassHash class_hash{};
    // class_bytes is held as a Cell ref so the Cell DB physically deduplicates
    // contracts that share identical bytecode (verified: CellStorage keys by
    // hash with refcount accounting; see crypto/vm/db/CellStorage.cpp:267).
    td::Ref<vm::Cell> class_bytes;
    td::Ref<vm::Cell> storage_root;
    td::Ref<vm::Cell> manifest_root;  // per-account method-id → method spec
};

// Layout:
//   jvm_contract_account#4a564143
//     schema_version:uint8 (=2)
//     stdlib_hash:bits256
//     class_hash:bits256
//     class_bytes:^Cell
//     storage_root:(Maybe ^Cell)
//     manifest_root:(Maybe ^Cell)
//     = JvmContractAccountState;
td::Ref<vm::Cell> encode_jvm_contract_account_state(
    const JvmContractAccountState& state);

// Decode the canonical v2 per-account envelope.  Rejects null/special cells,
// wrong magic/schema, zero class_hash, non-canonical Maybe refs, and trailing
// bits/refs.  Does not validate the storage trie or the method manifest in
// depth; callers re-validate those once they have a config + workchain
// context.
bool decode_jvm_contract_account_state(td::Ref<vm::Cell> cell,
                                       JvmContractAccountState& out);

// Build the canonical TLB `StateInit{code, data}` cell that materializes a
// new wc=3 account whose initial state is `state`.  `code` is the JVM
// activation marker (0x4a) and `data` is the encoded
// `JvmContractAccountState` cell.  Returns `td::Ref{}` if the state fails to
// encode.
td::Ref<vm::Cell> encode_jvm_state_init_cell(
    const JvmContractAccountState& state);

}  // namespace jvm_workchain
