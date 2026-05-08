/*
    JVM Workchain — cell codec for the executor-state and per-account
    envelopes.

    v1 (`JvmExecutorState`, magic JVMS) routes every wc=3 contract through a
    SingletonExecutor account holding a shared storage trie and a global class
    manifest. v2 (`JvmContractAccountState`, magic JVAC) makes each contract a
    real wc=3 account with its own class bytes, per-account method manifest,
    and isolated storage. Both codecs coexist while the engine migrates;
    Phase D removes the v1 path.
*/
#pragma once

#include <array>
#include <cstdint>

#include "jvm/core/config-param.h"
#include "jvm/core/deploy-abi.h"
#include "vm/cells.h"

namespace jvm_workchain {

constexpr std::uint32_t kJvmExecutorStateMagic = 0x4a564d53;  // "JVMS"
constexpr unsigned kJvmExecutorStateMagicBits = 32;
constexpr std::uint8_t kJvmExecutorStateSchemaVersion = 1;

struct JvmExecutorState {
    std::uint8_t schema_version{kJvmExecutorStateSchemaVersion};
    std::array<std::uint8_t, kJvmStdlibHashBytes> stdlib_hash{};
    td::Ref<vm::Cell> storage_root;
    td::Ref<vm::Cell> class_state_root;
};

// Layout:
//   jvm_executor_state#4a564d53
//     schema_version:uint8 (=1)
//     stdlib_hash:bits256
//     storage_root:(Maybe ^Cell)
//     class_state_root:(Maybe ^Cell)
//     = JvmExecutorState;
td::Ref<vm::Cell> encode_jvm_executor_state(const JvmExecutorState& state);

// Decode the canonical v1 executor-state envelope.  Rejects null/special cells,
// wrong magic/schema, non-canonical Maybe refs, and trailing bits/refs.
bool decode_jvm_executor_state(td::Ref<vm::Cell> cell, JvmExecutorState& out);

// -------------------------------------------------------------------------
// JVM v2: per-account contract state envelope
// -------------------------------------------------------------------------

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
