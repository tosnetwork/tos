/*
    JVM Workchain — JSON-RPC namespace.

    Provides jvm_* JSON-RPC endpoints for the JVM workchain.  These are
    non-consensus surfaces and must not affect compute.

    Implemented endpoints:
      jvm_deployContract  — validate class bytes and build an external message
                            targeting the executor account; returns contract_id
      jvm_callContract    — read-only local call against installed state
      jvm_getContractState — return decoded storage of a deployed contract
      jvm_getReceipts     — return event logs for a given block range

    Admission note: jvm_deployContract pre-validates class bytes against the
    Java 8 verifier profile and ConfigParam 85 class-store limits as a
    developer convenience.  Consensus re-validates on execution and never
    trusts the result of the RPC admission check.

    Integration note: full node RPC integration waits on the
    WorkchainRuntimeServices::register_rpc hook.  Until that hook lands, the
    codec and admission logic here can be tested standalone and wired by the
    caller (validator-engine, test harnesses) through handle_jvm_rpc().

    Source: TOS-specific integration point (Phase 7).
*/
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "jvm/core/config-param.h"
#include "jvm/core/deploy-abi.h"
#include "jvm/core/message-abi.h"
#include "jvm/core/storage-cell-host.h"
#include "vm/cells.h"

namespace jvm_workchain {

// ---------------------------------------------------------------------------
// RPC result
// ---------------------------------------------------------------------------

/// Result of a jvm_* RPC call.
struct JvmRpcResult {
    std::string json;   ///< JSON-RPC response body
    bool is_error{false};
};

// ---------------------------------------------------------------------------
// jvm_deployContract
// ---------------------------------------------------------------------------

/// Parsed request for jvm_deployContract.
struct JvmDeployContractRequest {
    std::vector<uint8_t> class_bytes;     ///< raw Java 8 class file
    std::string class_name;              ///< internal class name ("pkg/Foo")
    std::array<uint8_t, 32> deployer{};  ///< deployer address (32 bytes)
    std::array<uint8_t, 32> salt{};      ///< deployment salt (32 bytes)
    td::Ref<vm::Cell> init_args;         ///< JVMA typed init args cell (may be null)
};

/// Parse a jvm_deployContract JSON params array.
/// Returns nullopt if params are malformed.
std::optional<JvmDeployContractRequest> parse_jvm_deploy_contract_request(
    const std::string& params_json);

/// Validate class_bytes against the Java 8 profile and ConfigParam 85 limits,
/// derive contract_id, and encode an external message cell targeting the
/// singleton executor account.  Returns an error result if validation fails.
///
/// This is an admission convenience; consensus re-validates on execution.
JvmRpcResult handle_jvm_deploy_contract(
    const JvmDeployContractRequest& req,
    const JvmConfig& config,
    const std::string& id = "null");

// ---------------------------------------------------------------------------
// jvm_callContract
// ---------------------------------------------------------------------------

/// Parsed request for jvm_callContract (read-only local call).
struct JvmCallContractRequest {
    std::array<uint8_t, 32> contract_id{};  ///< deployed contract instance
    uint32_t method_id{0};                  ///< ABI method id
    td::Ref<vm::Cell> args;                 ///< JVMA typed args cell (may be null)
    td::Ref<vm::Cell> current_state;        ///< JvmExecutorState cell to call against
    uint64_t gas_limit{0};                  ///< gas limit for the local call
};

/// Parse a jvm_callContract JSON params array.
std::optional<JvmCallContractRequest> parse_jvm_call_contract_request(
    const std::string& params_json);

/// Encode the call as a JvmCallDescriptor cell suitable for submission or
/// local execution.  The caller is responsible for wiring actual execution.
JvmRpcResult handle_jvm_call_contract(const JvmCallContractRequest& req,
                                      const std::string& id = "null");

// ---------------------------------------------------------------------------
// jvm_getContractState
// ---------------------------------------------------------------------------

/// Parsed request for jvm_getContractState.
struct JvmGetContractStateRequest {
    std::array<uint8_t, 32> contract_id{};
    td::Ref<vm::Cell> executor_state;  ///< JvmExecutorState cell from block state
};

/// Parse a jvm_getContractState JSON params array.
std::optional<JvmGetContractStateRequest> parse_jvm_get_contract_state_request(
    const std::string& params_json);

/// Return the decoded storage slots of the named contract as a JSON object.
JvmRpcResult handle_jvm_get_contract_state(const JvmGetContractStateRequest& req,
                                           const std::string& id = "null");

// ---------------------------------------------------------------------------
// jvm_getReceipts
// ---------------------------------------------------------------------------

/// Parsed request for jvm_getReceipts.
struct JvmGetReceiptsRequest {
    std::array<uint8_t, 32> contract_id{};
    uint64_t from_block{0};
    uint64_t to_block{0};
};

/// Parse a jvm_getReceipts JSON params array.
std::optional<JvmGetReceiptsRequest> parse_jvm_get_receipts_request(
    const std::string& params_json);

/// Return event receipts in the given block range.  In v1 this scans staged
/// event logs committed in block side effects.
JvmRpcResult handle_jvm_get_receipts(const JvmGetReceiptsRequest& req,
                                     const std::string& id = "null");

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

/// Dispatch a jvm_* JSON-RPC call.
///
/// Returns std::nullopt if the method is not a jvm_* method handled here.
/// Callers should fall through to next handlers in that case.
///
/// @param method      e.g. "jvm_deployContract"
/// @param params      raw JSON params array
/// @param id          request id to echo back
/// @param config      resolved ConfigParam 85 for the current block
std::optional<JvmRpcResult> handle_jvm_rpc(
    const std::string& method,
    const std::string& params,
    const std::string& id,
    const JvmConfig& config);

/// Returns true if method is handled by the JVM RPC facade.
bool is_jvm_rpc_method(const std::string& method) noexcept;

}  // namespace jvm_workchain
