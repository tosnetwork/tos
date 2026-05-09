/*
    JVM Workchain — inbound message ABI codec.

    The compute path accepts a single contract-call descriptor.  Each
    inbound wc=3 message names the destination contract directly via its
    account address; the descriptor body therefore carries only the
    method id and a typed args cell.
*/
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "td/utils/Status.h"
#include "vm/cells.h"

namespace jvm_workchain {

constexpr std::uint32_t kJvmCallDescriptorMagic = 0x4a564932;  // "JVI2"
constexpr std::uint8_t kJvmCallDescriptorSchemaVersion = 2;
constexpr unsigned kJvmContractIdBytes = 32;
constexpr const char* kJvmStaticVoidMethodSpec = "()V";
constexpr std::uint32_t kJvmArgsMagic = 0x4a564d41;  // "JVMA"
constexpr std::uint8_t kJvmArgsSchemaVersion = 1;
constexpr std::size_t kJvmArgsMaxCount = 64;

// Generic 32-byte deployer / salt / address-like value.
using JvmContractId = std::array<std::uint8_t, kJvmContractIdBytes>;

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

struct JvmCallDescriptor {
    std::uint8_t schema_version{kJvmCallDescriptorSchemaVersion};
    std::uint32_t method_id{0};
    td::Ref<vm::Cell> args;
};

// Layout:
//   jvm_call#4a564932
//     schema_version:uint8 (=2)
//     method_id:uint32
//     args:^Cell
//     = JvmCallDescriptor;
td::Ref<vm::Cell> encode_jvm_call_descriptor(
    const JvmCallDescriptor& descriptor);

td::Result<JvmCallDescriptor> parse_jvm_call_descriptor(
    td::Ref<vm::CellSlice> body);

td::Result<JvmCallDescriptor> parse_jvm_call_descriptor(vm::CellSlice body);

td::Ref<vm::Cell> encode_jvm_args(const JvmArgs& args);

td::Result<JvmArgs> parse_jvm_args(td::Ref<vm::Cell> root);

/// Round 64 MEDIUM fix: peek the args header + per-node type tags
/// WITHOUT decoding the value-ref byte payloads.  Walks the linked
/// node chain summing types only — O(N) cells touched but no
/// memcpy of the typed `Bytes` payload chains, which can each be
/// up to `kJvmStorageValueMaxBytes` (1 MiB).  Used by the resolver
/// to fail fast on count or type mismatch before paying the full
/// decode cost.
td::Result<std::vector<JvmArgType>> peek_jvm_args_types(
    td::Ref<vm::Cell> root);

td::Result<std::vector<JvmArgType>> parse_jvm_method_argument_types(
    const std::string& method_spec);

td::Status validate_jvm_typed_call_args(const std::string& method_spec,
                                        td::Ref<vm::Cell> args);

/// Round 61 MEDIUM fix: validate already-parsed args against the
/// method spec WITHOUT re-parsing the cell.  Pre-fix
/// `validate_jvm_typed_call_args` itself called `parse_jvm_args` and
/// the resolver in `decode_linked_invocation_args` then called it
/// again, doubling the byte-decode work for typed `Bytes` arguments
/// before any Avata gas charge.  Callers that already hold a
/// `JvmArgs` should prefer this overload.
td::Status validate_jvm_typed_args_against_spec(
    const std::string& method_spec, const JvmArgs& parsed_args);

// Legacy static-void calls without parameters use the canonical empty args
// cell. Parameterized static-void calls use validate_jvm_typed_call_args().
td::Status validate_jvm_static_void_call_args(
    const std::string& method_spec,
    td::Ref<vm::Cell> args);

}  // namespace jvm_workchain
