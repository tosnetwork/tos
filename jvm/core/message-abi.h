/*
    JVM Workchain — inbound message ABI codec.

    The v1 compute path accepts a single contract-call descriptor. Deployment
    and richer argument decoding build on this cell envelope instead of letting
    raw inbound bodies reach the Avata runtime unchecked.
*/
#pragma once

#include <array>
#include <cstdint>

#include "td/utils/Status.h"
#include "vm/cells.h"

namespace jvm_workchain {

constexpr std::uint32_t kJvmCallDescriptorMagic = 0x4a564d49;  // "JVMI"
constexpr std::uint8_t kJvmCallDescriptorSchemaVersion = 1;
constexpr unsigned kJvmContractIdBytes = 32;

using JvmContractId = std::array<std::uint8_t, kJvmContractIdBytes>;

struct JvmCallDescriptor {
    std::uint8_t schema_version{kJvmCallDescriptorSchemaVersion};
    JvmContractId contract_id{};
    std::uint32_t method_id{0};
    td::Ref<vm::Cell> args;
};

// Layout:
//   jvm_call#4a564d49
//     schema_version:uint8 (=1)
//     contract_id:bits256
//     method_id:uint32
//     args:^Cell
//     = JvmCallDescriptor;
td::Ref<vm::Cell> encode_jvm_call_descriptor(
    const JvmCallDescriptor& descriptor);

td::Result<JvmCallDescriptor> parse_jvm_call_descriptor(
    td::Ref<vm::CellSlice> body);

td::Result<JvmCallDescriptor> parse_jvm_call_descriptor(vm::CellSlice body);

}  // namespace jvm_workchain
