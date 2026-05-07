/*
    JVM Workchain — JSON-RPC namespace implementation.

    Phase 7 scaffold.  Implements request parsing, admission validation, and
    response encoding for the four jvm_* endpoints.  Full node wiring waits on
    WorkchainRuntimeServices::register_rpc; callers invoke handle_jvm_rpc()
    directly for now.

    Design constraints:
    - These functions are non-consensus.  They must not call run_compute or
      modify block state.
    - jvm_deployContract admission is a convenience; consensus re-validates.
    - No threading, no shared state.  Every function is pure given its inputs.

    Source: TOS-specific integration point.
*/
#include "jvm/core/rpc.h"

#include "jvm/core/cell-codec.h"
#include "jvm/core/class-manifest.h"
#include "jvm/core/deploy-abi.h"
#include "jvm/core/message-abi.h"
#include "jvm/core/storage-cell-host.h"
#include "td/utils/JsonBuilder.h"
#include "td/utils/logging.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cellslice.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>

namespace jvm_workchain {

namespace {

// -------------------------------------------------------------------------
// JSON response helpers
// -------------------------------------------------------------------------

std::string json_rpc_ok(const std::string& id, const std::string& result_json) {
    return std::string{"{\"jsonrpc\":\"2.0\",\"id\":"} + id
         + ",\"result\":" + result_json + "}";
}

std::string json_rpc_err(const std::string& id, int code, const std::string& msg) {
    std::string s = std::string{"{\"jsonrpc\":\"2.0\",\"id\":"} + id
        + ",\"error\":{\"code\":" + std::to_string(code)
        + ",\"message\":\"" + msg + "\"}}";
    return s;
}

// Minimal hex encoding.
std::string hex_encode(const uint8_t* data, size_t len) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(2 + len * 2);
    out += "0x";
    for (size_t i = 0; i < len; ++i) {
        out += kHex[(data[i] >> 4) & 0xF];
        out += kHex[data[i] & 0xF];
    }
    return out;
}

std::string hex_encode(const std::array<uint8_t, 32>& arr) {
    return hex_encode(arr.data(), arr.size());
}

// Decode a 0x-prefixed hex string into a 32-byte array.
// Returns false if the input is malformed or wrong length.
bool hex_decode_32(const std::string& s, std::array<uint8_t, 32>& out) {
    if (s.size() < 2 || s[0] != '0' || s[1] != 'x') {
        return false;
    }
    if (s.size() != 66) {  // 0x + 64 hex chars
        return false;
    }
    for (int i = 0; i < 32; ++i) {
        auto c0 = s[2 + i * 2];
        auto c1 = s[3 + i * 2];
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int n0 = nibble(c0), n1 = nibble(c1);
        if (n0 < 0 || n1 < 0) return false;
        out[i] = static_cast<uint8_t>((n0 << 4) | n1);
    }
    return true;
}

// Decode a 0x-prefixed hex string into a byte vector.
bool hex_decode_bytes(const std::string& s, std::vector<uint8_t>& out) {
    if (s.size() < 2 || s[0] != '0' || s[1] != 'x') {
        return false;
    }
    if ((s.size() % 2) != 0) {
        return false;
    }
    out.clear();
    for (size_t i = 2; i < s.size(); i += 2) {
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int n0 = nibble(s[i]), n1 = nibble(s[i + 1]);
        if (n0 < 0 || n1 < 0) return false;
        out.push_back(static_cast<uint8_t>((n0 << 4) | n1));
    }
    return true;
}

// Decode a 0x-prefixed hex BOC string into a cell.
// Returns an empty Ref on error (returns success for empty BOC as empty cell).
td::Ref<vm::Cell> hex_boc_decode_cell(const std::string& s) {
    std::vector<uint8_t> bytes;
    if (!hex_decode_bytes(s, bytes)) return {};
    if (bytes.empty()) return {};
    auto result = vm::std_boc_deserialize(
        td::Slice(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
    if (result.is_error()) return {};
    return result.move_as_ok();
}

// Very minimal JSON field extractor.  Not a general JSON parser —
// only extracts top-level fields by key from a flat object.
// Handles optional whitespace around ':' and value.
std::string json_get_string(const std::string& json, const std::string& key) {
    auto needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return {};
    // Skip past the key and optional whitespace to find ':'
    auto idx = pos + needle.size();
    while (idx < json.size() && (json[idx] == ' ' || json[idx] == '\t'
                                 || json[idx] == '\n' || json[idx] == '\r')) {
        ++idx;
    }
    if (idx >= json.size() || json[idx] != ':') return {};
    ++idx;
    while (idx < json.size() && (json[idx] == ' ' || json[idx] == '\t'
                                 || json[idx] == '\n' || json[idx] == '\r')) {
        ++idx;
    }
    if (idx >= json.size() || json[idx] != '"') return {};
    ++idx;  // skip opening quote
    auto end = json.find('"', idx);
    if (end == std::string::npos) return {};
    return json.substr(idx, end - idx);
}

std::string json_get_number_str(const std::string& json, const std::string& key) {
    auto needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return {};
    auto idx = pos + needle.size();
    while (idx < json.size() && (json[idx] == ' ' || json[idx] == '\t'
                                 || json[idx] == '\n' || json[idx] == '\r')) {
        ++idx;
    }
    if (idx >= json.size() || json[idx] != ':') return {};
    ++idx;
    while (idx < json.size() && (json[idx] == ' ' || json[idx] == '\t'
                                 || json[idx] == '\n' || json[idx] == '\r')) {
        ++idx;
    }
    auto end = idx;
    while (end < json.size() && (std::isdigit(json[end]) || json[end] == '-')) {
        ++end;
    }
    return json.substr(idx, end - idx);
}

// -------------------------------------------------------------------------
// Minimal class-name validation (copy of manifest admission rule).
// A valid Java internal class name uses '/' as package separator and may
// only contain ASCII letters, digits, '_', '$', and '/'.
// -------------------------------------------------------------------------
bool is_valid_class_name(const std::string& name) {
    if (name.empty() || name.front() == '/' || name.back() == '/') return false;
    for (char c : name) {
        if (!std::isalnum(static_cast<unsigned char>(c))
            && c != '/' && c != '_' && c != '$') {
            return false;
        }
    }
    return true;
}

}  // namespace

// -------------------------------------------------------------------------
// jvm_deployContract
// -------------------------------------------------------------------------

std::optional<JvmDeployContractRequest> parse_jvm_deploy_contract_request(
    const std::string& params_json) {
    JvmDeployContractRequest req;

    auto class_bytes_hex = json_get_string(params_json, "classBytes");
    if (class_bytes_hex.empty()) return std::nullopt;
    if (!hex_decode_bytes(class_bytes_hex, req.class_bytes)) return std::nullopt;

    req.class_name = json_get_string(params_json, "className");
    if (req.class_name.empty()) return std::nullopt;

    auto deployer_hex = json_get_string(params_json, "deployer");
    if (deployer_hex.empty() || !hex_decode_32(deployer_hex, req.deployer)) {
        return std::nullopt;
    }

    auto salt_hex = json_get_string(params_json, "salt");
    if (!salt_hex.empty()) {
        if (!hex_decode_32(salt_hex, req.salt)) return std::nullopt;
    }

    // init_args is optional; absent = canonical empty args cell.
    req.init_args = vm::CellBuilder().finalize();
    return req;
}

JvmRpcResult handle_jvm_deploy_contract(
    const JvmDeployContractRequest& req,
    const JvmConfig& config,
    const std::string& id) {
    // Build a descriptor for validation.
    JvmDeployDescriptor descriptor;
    descriptor.deployer = req.deployer;
    descriptor.salt = req.salt;
    descriptor.class_name = req.class_name;
    descriptor.class_bytes = JvmStorageValue(req.class_bytes.begin(),
                                              req.class_bytes.end());
    descriptor.class_hash = compute_jvm_class_hash(descriptor.class_bytes);
    descriptor.init_args = req.init_args;

    // Admission: class name shape.
    if (!is_valid_class_name(req.class_name)) {
        return JvmRpcResult{
            json_rpc_err(id, -32602, "invalid class name"),
            true};
    }

    // Admission: class size limits from ConfigParam 85.
    if (config.max_class_bytes > 0
        && req.class_bytes.size() > config.max_class_bytes) {
        return JvmRpcResult{
            json_rpc_err(id, -32602, "class bytes exceed max_class_bytes"),
            true};
    }

    // Admission: encode to verify the descriptor is well-formed.
    auto encoded = encode_jvm_deploy_descriptor(descriptor);
    if (encoded.is_null()) {
        return JvmRpcResult{
            json_rpc_err(id, -32602, "deploy descriptor encoding failed"),
            true};
    }

    // Derive contract_id.
    auto contract_id_result = derive_jvm_contract_id(descriptor);
    if (contract_id_result.is_error()) {
        return JvmRpcResult{
            json_rpc_err(id, -32602, "contract_id derivation failed"),
            true};
    }
    const auto& contract_id = contract_id_result.ok();
    std::string result = "{\"contractId\":\""
                       + hex_encode(contract_id) + "\"}";
    return JvmRpcResult{json_rpc_ok(id, result), false};
}

// -------------------------------------------------------------------------
// jvm_callContract
// -------------------------------------------------------------------------

std::optional<JvmCallContractRequest> parse_jvm_call_contract_request(
    const std::string& params_json) {
    JvmCallContractRequest req;

    auto contract_id_hex = json_get_string(params_json, "contractId");
    if (contract_id_hex.empty()
        || !hex_decode_32(contract_id_hex, req.contract_id)) {
        return std::nullopt;
    }

    auto method_id_str = json_get_number_str(params_json, "methodId");
    if (method_id_str.empty()) return std::nullopt;
    try {
        req.method_id = static_cast<uint32_t>(std::stoul(method_id_str));
    } catch (...) {
        return std::nullopt;
    }

    auto gas_str = json_get_number_str(params_json, "gasLimit");
    if (!gas_str.empty()) {
        try {
            req.gas_limit = std::stoull(gas_str);
        } catch (...) {
            return std::nullopt;
        }
    }

    // args is optional; absent = canonical empty args cell.
    req.args = vm::CellBuilder().finalize();

    // Optional: caller-supplied executor state as a hex-encoded BOC.
    auto state_boc_hex = json_get_string(params_json, "executorStateBoc");
    if (!state_boc_hex.empty()) {
        req.current_state = hex_boc_decode_cell(state_boc_hex);
        if (req.current_state.is_null()) {
            return std::nullopt;  // malformed BOC
        }
    }
    return req;
}

JvmRpcResult handle_jvm_call_contract(const JvmCallContractRequest& req,
                                      const std::string& id) {
    // Build the call descriptor cell.
    JvmCallDescriptor descriptor;
    descriptor.contract_id = req.contract_id;
    descriptor.method_id = req.method_id;
    descriptor.args = req.args;

    auto encoded = encode_jvm_call_descriptor(descriptor);
    if (encoded.is_null()) {
        return JvmRpcResult{
            json_rpc_err(id, -32602, "call descriptor encoding failed"),
            true};
    }

    // Serialize the descriptor cell to BOC so the caller can submit it
    // as an external message body or pass it to the local runner.
    // Local execution is not wired in v1 (requires an installed runtime and
    // a block-state snapshot); the encoded descriptor is the return value.
    auto boc = vm::std_boc_serialize(encoded, 0);
    if (boc.is_error()) {
        return JvmRpcResult{
            json_rpc_err(id, -32602, "call descriptor boc serialization failed"),
            true};
    }
    const auto& boc_bytes = boc.ok();
    std::string result = "{\"callDescriptorBoc\":\""
                       + hex_encode(reinterpret_cast<const uint8_t*>(
                                        boc_bytes.data()),
                                    boc_bytes.size())
                       + "\",\"contractId\":\""
                       + hex_encode(req.contract_id) + "\"}";
    return JvmRpcResult{json_rpc_ok(id, result), false};
}

// -------------------------------------------------------------------------
// jvm_getContractState
// -------------------------------------------------------------------------

std::optional<JvmGetContractStateRequest> parse_jvm_get_contract_state_request(
    const std::string& params_json) {
    JvmGetContractStateRequest req;
    auto contract_id_hex = json_get_string(params_json, "contractId");
    if (contract_id_hex.empty()
        || !hex_decode_32(contract_id_hex, req.contract_id)) {
        return std::nullopt;
    }
    // Optional: caller-supplied executor state as a hex-encoded BOC.
    // When present, the handler can resolve className/classHash without a live
    // block-state connection.  Absent means the caller must inject executor_state
    // directly (e.g. from the node's block-state lookup via the register_rpc hook).
    auto state_boc_hex = json_get_string(params_json, "executorStateBoc");
    if (!state_boc_hex.empty()) {
        req.executor_state = hex_boc_decode_cell(state_boc_hex);
        if (req.executor_state.is_null()) {
            return std::nullopt;  // malformed BOC
        }
    }
    return req;
}

JvmRpcResult handle_jvm_get_contract_state(
    const JvmGetContractStateRequest& req,
    const std::string& id) {
    if (req.executor_state.is_null()) {
        return JvmRpcResult{
            json_rpc_err(id, -32602, "executor state cell is required"),
            true};
    }

    JvmExecutorState state;
    if (!decode_jvm_executor_state(req.executor_state, state)) {
        return JvmRpcResult{
            json_rpc_err(id, -32602, "malformed executor state cell"),
            true};
    }

    // Storage root hash — v1 storage is a flat shared namespace; the hash
    // covers all contracts.  Full per-contract slot enumeration requires an
    // explicit index not present in v1.
    std::string storage_hash = "null";
    if (state.storage_root.not_null()) {
        auto h = state.storage_root->get_hash();
        storage_hash = "\"" + hex_encode(h.as_slice().ubegin(), 32) + "\"";
    }

    // Look up the contract's class name and class hash from the manifest.
    std::string class_name_json = "null";
    std::string class_hash_json = "null";
    if (state.class_state_root.not_null()) {
        auto manifest_result =
            parse_jvm_avata_class_manifest(state.class_state_root);
        if (manifest_result.is_ok()) {
            for (const auto& entry : manifest_result.ok()) {
                if (entry.contract_id == req.contract_id) {
                    class_name_json = "\"" + entry.class_name + "\"";
                    // Find the class definition to get the class hash.
                    auto def = find_jvm_avata_class_definition(
                        state.class_state_root, entry.class_name);
                    if (def.is_ok()) {
                        class_hash_json =
                            "\"" + hex_encode(def.ok().class_hash) + "\"";
                    }
                    break;
                }
            }
        }
    }

    std::string result = "{\"contractId\":\""
                       + hex_encode(req.contract_id)
                       + "\",\"className\":" + class_name_json
                       + ",\"classHash\":" + class_hash_json
                       + ",\"storageRootHash\":" + storage_hash + "}";
    return JvmRpcResult{json_rpc_ok(id, result), false};
}

// -------------------------------------------------------------------------
// jvm_getReceipts
// -------------------------------------------------------------------------

std::optional<JvmGetReceiptsRequest> parse_jvm_get_receipts_request(
    const std::string& params_json) {
    JvmGetReceiptsRequest req;
    auto contract_id_hex = json_get_string(params_json, "contractId");
    if (contract_id_hex.empty()
        || !hex_decode_32(contract_id_hex, req.contract_id)) {
        return std::nullopt;
    }

    auto from_str = json_get_number_str(params_json, "fromBlock");
    if (!from_str.empty()) {
        try { req.from_block = std::stoull(from_str); } catch (...) {}
    }
    auto to_str = json_get_number_str(params_json, "toBlock");
    if (!to_str.empty()) {
        try { req.to_block = std::stoull(to_str); } catch (...) {}
    }
    return req;
}

JvmRpcResult handle_jvm_get_receipts(const JvmGetReceiptsRequest& req,
                                     const std::string& id) {
    // v1: event logs are committed into block side effects via the event-host
    // path.  Full receipt retrieval requires a block-state index; return an
    // empty list for now so the endpoint is functional.
    std::string result = "{\"contractId\":\""
                       + hex_encode(req.contract_id)
                       + "\",\"receipts\":[]}";
    return JvmRpcResult{json_rpc_ok(id, result), false};
}

// -------------------------------------------------------------------------
// Dispatcher
// -------------------------------------------------------------------------

bool is_jvm_rpc_method(const std::string& method) noexcept {
    return method == "jvm_deployContract"
        || method == "jvm_callContract"
        || method == "jvm_getContractState"
        || method == "jvm_getReceipts";
}

std::optional<JvmRpcResult> handle_jvm_rpc(
    const std::string& method,
    const std::string& params,
    const std::string& id,
    const JvmConfig& config) {
    if (method == "jvm_deployContract") {
        auto req = parse_jvm_deploy_contract_request(params);
        if (!req) {
            return JvmRpcResult{
                json_rpc_err(id, -32602, "invalid jvm_deployContract params"),
                true};
        }
        return handle_jvm_deploy_contract(*req, config, id);
    }

    if (method == "jvm_callContract") {
        auto req = parse_jvm_call_contract_request(params);
        if (!req) {
            return JvmRpcResult{
                json_rpc_err(id, -32602, "invalid jvm_callContract params"),
                true};
        }
        return handle_jvm_call_contract(*req, id);
    }

    if (method == "jvm_getContractState") {
        auto req = parse_jvm_get_contract_state_request(params);
        if (!req) {
            return JvmRpcResult{
                json_rpc_err(id, -32602, "invalid jvm_getContractState params"),
                true};
        }
        return handle_jvm_get_contract_state(*req, id);
    }

    if (method == "jvm_getReceipts") {
        auto req = parse_jvm_get_receipts_request(params);
        if (!req) {
            return JvmRpcResult{
                json_rpc_err(id, -32602, "invalid jvm_getReceipts params"),
                true};
        }
        return handle_jvm_get_receipts(*req, id);
    }

    return std::nullopt;
}

}  // namespace jvm_workchain
