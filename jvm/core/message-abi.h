/*
    JVM Workchain — inbound message ABI codec.

    The v1 compute path accepts a single contract-call descriptor. Deployment
    and richer argument decoding build on this cell envelope instead of letting
    raw inbound bodies reach the Avata runtime unchecked.
*/
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "td/utils/Status.h"
#include "vm/cells.h"

namespace jvm_workchain {

constexpr std::uint32_t kJvmCallDescriptorMagic = 0x4a564d49;  // "JVMI"
constexpr std::uint8_t kJvmCallDescriptorSchemaVersion = 1;
constexpr unsigned kJvmContractIdBytes = 32;
constexpr const char* kJvmStaticVoidMethodSpec = "()V";
constexpr std::uint32_t kJvmArgsMagic = 0x4a564d41;  // "JVMA"
constexpr std::uint8_t kJvmArgsSchemaVersion = 1;
constexpr std::size_t kJvmArgsMaxCount = 64;

using JvmContractId = std::array<std::uint8_t, kJvmContractIdBytes>;

struct JvmCallDescriptor {
    std::uint8_t schema_version{kJvmCallDescriptorSchemaVersion};
    JvmContractId contract_id{};
    std::uint32_t method_id{0};
    td::Ref<vm::Cell> args;
};

enum class JvmArgType : std::uint8_t {
    Bool = 1,
    Int32 = 2,
    Int64 = 3,
    Bytes = 4,
    Address = 5,
    Uint256 = 6,
    Bytes32 = 7,
    Bytes4 = 8,
};

struct JvmTypedArg {
    JvmArgType type{JvmArgType::Bytes};
    std::vector<std::uint8_t> bytes;
};

struct JvmArgs {
    std::uint8_t schema_version{kJvmArgsSchemaVersion};
    std::vector<JvmTypedArg> values;
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

// -------------------------------------------------------------------------
// JVM v2: per-account call descriptor.
//
// Drops `contract_id` because under the v2 account-native topology each JVM
// contract is its own wc=3 account: the inbound message destination already
// names the contract.  Magic and schema_version are bumped so v1 and v2 cells
// can be distinguished even if a node receives a stale v1 body.
// -------------------------------------------------------------------------

constexpr std::uint32_t kJvmCallDescriptorV2Magic = 0x4a564932;  // "JVI2"
constexpr std::uint8_t kJvmCallDescriptorV2SchemaVersion = 2;

struct JvmCallDescriptorV2 {
    std::uint8_t schema_version{kJvmCallDescriptorV2SchemaVersion};
    std::uint32_t method_id{0};
    td::Ref<vm::Cell> args;
};

// Layout:
//   jvm_call_v2#4a564932
//     schema_version:uint8 (=2)
//     method_id:uint32
//     args:^Cell
//     = JvmCallDescriptorV2;
td::Ref<vm::Cell> encode_jvm_call_descriptor_v2(
    const JvmCallDescriptorV2& descriptor);

td::Result<JvmCallDescriptorV2> parse_jvm_call_descriptor_v2(
    td::Ref<vm::CellSlice> body);

td::Result<JvmCallDescriptorV2> parse_jvm_call_descriptor_v2(
    vm::CellSlice body);

td::Ref<vm::Cell> encode_jvm_args(const JvmArgs& args);

td::Result<JvmArgs> parse_jvm_args(td::Ref<vm::Cell> root);

td::Result<std::vector<JvmArgType>> parse_jvm_method_argument_types(
    const std::string& method_spec);

td::Status validate_jvm_typed_call_args(const std::string& method_spec,
                                        td::Ref<vm::Cell> args);

// Legacy static-void calls without parameters use the canonical empty args
// cell. Parameterized static-void calls use validate_jvm_typed_call_args().
td::Status validate_jvm_static_void_call_args(
    const std::string& method_spec,
    td::Ref<vm::Cell> args);

}  // namespace jvm_workchain
