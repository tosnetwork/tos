/*
    JVM Workchain — JSON-RPC namespace.

    Provides jvm_* JSON-RPC endpoints for the JVM workchain.  These are
    non-consensus surfaces and must not affect compute.

    Implemented endpoints (account-native topology):
      jvm_deployContract    — validate class bytes and build a deploy
                              descriptor cell + per-contract wc=3
                              `contractAddress` derived from the descriptor
      jvm_callContract      — encode a JVI2 call descriptor and optionally
                              simulate it locally against an account state
      jvm_getContractState  — return decoded storage of a single per-contract
                              wc=3 account
      jvm_getReceipts       — return event logs for a given block range

    Admission note: jvm_deployContract pre-validates class bytes against the
    Java 8 verifier profile and ConfigParam 85 class-store limits as a
    developer convenience.  Consensus re-validates on execution and never
    trusts the result of the RPC admission check.

    Integration note: validator-engine wires these handlers into the full-node
    JSON-RPC dispatcher via JsonRpcServer::handle_jvm_rpc_method().  Tests may
    still call handle_jvm_rpc() directly with an injected ConfigParam 85 and
    optional runtime.
*/
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "jvm/core/cell-codec.h"
#include "jvm/core/class-manifest.h"
#include "jvm/core/config-param.h"
#include "jvm/core/deploy-abi.h"
#include "jvm/core/dispatch-engine.h"
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
    /// Per-account method manifest the deployer commits to at deploy
    /// time.  Bound into the v2 address derivation so an attacker who
    /// knows the rest of the deploy tuple cannot squat the address with
    /// a different ABI dispatch table.  May be empty for contracts that
    /// expose no callable methods.
    std::vector<JvmMethodManifestEntry> manifest_entries;
};

/// Parse a jvm_deployContract JSON params array.
/// Returns nullopt if params are malformed.
std::optional<JvmDeployContractRequest> parse_jvm_deploy_contract_request(
    const std::string& params_json);

/// Validate class_bytes against the Java 8 profile and ConfigParam 85 limits,
/// derive the deterministic per-contract wc=3 address, and return the deploy
/// descriptor BOC.  The deployer wraps the descriptor in StateInit and emits
/// `action_create_account` to materialize a new account at that address.
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
    std::array<uint8_t, 32> contract_address{};  ///< destination wc=3 account
    uint32_t method_id{0};                       ///< ABI method id
    td::Ref<vm::Cell> args;       ///< JVMA typed args cell; from argsBoc or empty
    td::Ref<vm::Cell> current_state;  ///< per-account JvmContractAccountState cell
    uint64_t gas_limit{0};                  ///< gas limit for the local call
    /// Optional hint: the destination account's balance in tomis.  When
    /// the hint is present, RPC simulation applies the consensus
    /// affordability cap (`balance / config.gas_price`) so
    /// balance-derived `sk_no_gas` rejections show up locally — even
    /// when the live balance is zero (round 43 fix: zero balance must
    /// be distinguishable from "no hint", because consensus rejects
    /// pre-runtime when `effective_gas_limit == 0`).  The
    /// validator-engine live path always injects the live balance;
    /// callers passing `accountStateBoc` directly may also include this
    /// hint.  Absence (default) means balance-blind simulation.
    std::optional<uint64_t> account_balance;
};

/// Parse a jvm_callContract JSON params array.
std::optional<JvmCallContractRequest> parse_jvm_call_contract_request(
    const std::string& params_json);

/// Encode the call as a JvmCallDescriptor cell and return it as
/// callDescriptorBoc.  When runtime is non-null and req.current_state is
/// set, also runs a local simulation and appends a localResult object to
/// the response containing gasUsed, success, vmLog, and newStateBoc.
JvmRpcResult handle_jvm_call_contract(const JvmCallContractRequest& req,
                                      const std::string& id = "null",
                                      const JvmConfig* config = nullptr,
                                      const JvmComputeRuntime* runtime = nullptr);

// ---------------------------------------------------------------------------
// jvm_getContractState
// ---------------------------------------------------------------------------

/// Parsed request for jvm_getContractState.
struct JvmGetContractStateRequest {
    std::array<uint8_t, 32> contract_address{};
    td::Ref<vm::Cell> account_state;  ///< per-account JvmContractAccountState cell
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
    std::array<uint8_t, 32> contract_address{};
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
/// @param runtime     optional runtime; when non-null, jvm_callContract with
///                    executorStateBoc will also perform a local simulation
std::optional<JvmRpcResult> handle_jvm_rpc(
    const std::string& method,
    const std::string& params,
    const std::string& id,
    const JvmConfig& config,
    const JvmComputeRuntime* runtime = nullptr);

/// Returns true if method is handled by the JVM RPC facade.
bool is_jvm_rpc_method(const std::string& method) noexcept;

}  // namespace jvm_workchain
