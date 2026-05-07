/*
    JVM Workchain — cell codec for the v1 executor state envelope.

    This is the Phase 4 entry point, not a general Java object-graph
    serializer.  The v1 contract model persists explicit Storage/Mapping roots;
    ordinary Java heap objects remain transaction-local.
*/
#pragma once

#include <array>
#include <cstdint>

#include "jvm/core/config-param.h"
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

}  // namespace jvm_workchain
