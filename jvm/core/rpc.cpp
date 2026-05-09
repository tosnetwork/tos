/*
    JVM Workchain — JSON-RPC namespace implementation.

    Implements request parsing, admission validation, local simulation, and
    response encoding for the four jvm_* endpoints.  Full-node routing lives in
    validator-engine/json-rpc-server-jvm.cpp; tests can still invoke
    handle_jvm_rpc() directly with an injected ConfigParam 85.

    Design constraints:
    - These functions are non-consensus.  Optional local simulation uses an
      injected runtime and returns newStateBoc to the caller; it must not
      modify block state.
    - jvm_deployContract admission is a convenience; consensus re-validates.
    - No threading, no shared state.  Every function is pure given its inputs.

    Source: TOS-specific integration point.
*/
#include "jvm/core/rpc.h"

#include "block/workchain-execution-dispatch.h"
#include "jvm/core/avata-execution.h"
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
#include <limits>
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

// Conservatively escape a UTF-8 string for emission as a JSON string
// literal.  The cell-codec admits manifest strings that may contain `"`,
// `\`, and control bytes; emitting them raw allows attacker-controlled
// account state to inject fields into our RPC response JSON.
std::string json_escape_string(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    static constexpr char kHex[] = "0123456789abcdef";
                    out += "\\u00";
                    out += kHex[(c >> 4) & 0xF];
                    out += kHex[c & 0xF];
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
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
    // Reject numbers whose JSON token does not end on a valid delimiter:
    // anything other than whitespace, `,`, `}`, `]`, or end-of-string
    // means the original token contained `.`, `e`, `E`, or a stray
    // character.  Returning an empty string forces the caller to treat
    // the number as malformed (rather than silently truncating "1.5"
    // to "1" or "1e2" to "1").
    if (end < json.size()) {
        char c = json[end];
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r' &&
            c != ',' && c != '}' && c != ']') {
            return {};
        }
    }
    return json.substr(idx, end - idx);
}

// Strict unsigned-integer parser: accepts only 1..max_digits ASCII
// digits (no sign, decimal point, exponent), rejects values outside
// [0, max_value].  Replaces std::stoul/std::stoull which silently:
//   * accept "-1" as ULONG_MAX (the cast then wraps to UINT32_MAX),
//   * stop mid-token on "1.5" / "1e2" (returns 1),
//   * succeed on "4294967296" then wrap during the uint32 cast.
// Overflow during accumulation is detected on every step rather than
// post-loop so that with max_value == UINT64_MAX the wrap is caught
// before it loses the original magnitude (e.g. 20-digit input
// "99999999999999999999" wraps to 7766279631452241919 in a 64-bit
// accumulator and the post-loop `v > max_value` check could never
// fire).
bool parse_strict_uint(const std::string& s, std::uint64_t max_value,
                       std::size_t max_digits, std::uint64_t& out) {
    if (s.empty() || s.size() > max_digits) {
        return false;
    }
    std::uint64_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') {
            return false;
        }
        const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
        // v * 10 must not exceed max_value, AND v * 10 + digit must
        // also not.  Equivalent to: v > (max_value - digit) / 10.
        // We split the check so it's clear.
        if (v > max_value / 10) {
            return false;
        }
        v *= 10;
        if (v > max_value - digit) {
            return false;
        }
        v += digit;
    }
    out = v;
    return true;
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

    // manifestEntries is optional; absent = empty manifest.  When
    // present, it must be a JSON array of objects with shape
    //   {"methodId":<u32>, "className":"...", "methodName":"...",
    //    "methodSpec":"..."}
    // The address derivation binds manifest_root.hash, so this MUST be
    // populated faithfully — clients that omit it deploy an
    // empty-manifest contract; clients that supply it commit to the
    // exact ABI dispatch table at deploy time.
    if (params_json.find("\"manifestEntries\"") != std::string::npos) {
        std::string mutable_copy = params_json;
        auto decoded = td::json_decode(td::MutableSlice(mutable_copy));
        if (decoded.is_error() ||
            decoded.ok().type() != td::JsonValue::Type::Object) {
            return std::nullopt;
        }
        const auto& root = decoded.ok().get_object();
        const td::JsonValue* entries_field = nullptr;
        // Find the manifestEntries field via the public field_values_
        // (no explicit getter; we just scan).
        for (const auto& kv : root.field_values_) {
            if (kv.first == td::Slice("manifestEntries")) {
                entries_field = &kv.second;
                break;
            }
        }
        if (entries_field != nullptr) {
            if (entries_field->type() != td::JsonValue::Type::Array) {
                return std::nullopt;
            }
            const auto& arr = entries_field->get_array();
            req.manifest_entries.reserve(arr.size());
            for (const auto& elem : arr) {
                if (elem.type() != td::JsonValue::Type::Object) {
                    return std::nullopt;
                }
                const auto& obj = elem.get_object();
                JvmMethodManifestEntry entry;
                bool found_method_id = false;
                for (const auto& kv : obj.field_values_) {
                    if (kv.first == td::Slice("methodId")) {
                        if (kv.second.type() != td::JsonValue::Type::Number) {
                            return std::nullopt;
                        }
                        std::uint64_t v = 0;
                        if (!parse_strict_uint(
                                kv.second.get_number().str(),
                                std::numeric_limits<std::uint32_t>::max(),
                                10, v)) {
                            return std::nullopt;
                        }
                        entry.method_id = static_cast<std::uint32_t>(v);
                        found_method_id = true;
                    } else if (kv.first == td::Slice("className")) {
                        if (kv.second.type() != td::JsonValue::Type::String) {
                            return std::nullopt;
                        }
                        entry.class_name = kv.second.get_string().str();
                    } else if (kv.first == td::Slice("methodName")) {
                        if (kv.second.type() != td::JsonValue::Type::String) {
                            return std::nullopt;
                        }
                        entry.method_name = kv.second.get_string().str();
                    } else if (kv.first == td::Slice("methodSpec")) {
                        if (kv.second.type() != td::JsonValue::Type::String) {
                            return std::nullopt;
                        }
                        entry.method_spec = kv.second.get_string().str();
                    }
                }
                if (!found_method_id || entry.class_name.empty() ||
                    entry.method_name.empty() || entry.method_spec.empty()) {
                    return std::nullopt;
                }
                req.manifest_entries.push_back(std::move(entry));
            }
        }
    }
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

    // Serialize the deploy descriptor to BOC for the caller to submit.
    auto boc = vm::std_boc_serialize(encoded, 0);
    if (boc.is_error()) {
        return JvmRpcResult{
            json_rpc_err(id, -32602, "deploy descriptor boc serialization failed"),
            true};
    }
    const auto& boc_bytes = boc.ok();
    std::string descriptor_boc_hex = hex_encode(
        reinterpret_cast<const uint8_t*>(boc_bytes.data()), boc_bytes.size());

    // Build the manifest_root the deployer commits to.  Empty manifest
    // is represented by a manifest_root with zero entries (which encodes
    // to a non-null cell — its hash is bound into the address).
    auto manifest_root = encode_jvm_method_manifest(req.manifest_entries);
    if (manifest_root.is_null()) {
        return JvmRpcResult{
            json_rpc_err(id, -32602, "manifest encoding failed"),
            true};
    }

    // Derive the deterministic per-contract wc=3 account address.  The
    // deployer wraps `descriptor` in StateInit and emits an
    // `action_create_account` to materialize a new account at this address.
    // The address derivation now also binds `manifest_root.hash` so the
    // deployer's chosen ABI dispatch table is committed to at deploy time
    // (round-3 fix against ABI-swap squat at first activation).
    auto contract_address_result =
        derive_jvm_contract_address(descriptor, manifest_root);
    if (contract_address_result.is_error()) {
        return JvmRpcResult{
            json_rpc_err(id, -32602, "contract_address derivation failed"),
            true};
    }
    const auto& contract_address = contract_address_result.ok();

    std::string result = "{\"contractAddress\":\""
                       + hex_encode(contract_address)
                       + "\",\"deployDescriptorBoc\":\"" + descriptor_boc_hex
                       + "\"}";
    return JvmRpcResult{json_rpc_ok(id, result), false};
}

// -------------------------------------------------------------------------
// jvm_callContract
// -------------------------------------------------------------------------

std::optional<JvmCallContractRequest> parse_jvm_call_contract_request(
    const std::string& params_json) {
    JvmCallContractRequest req;

    // Accept either "contractAddress" (v2 canonical name) or legacy
    // "contractId" so older clients still work.
    auto contract_address_hex =
        json_get_string(params_json, "contractAddress");
    if (contract_address_hex.empty()) {
        contract_address_hex = json_get_string(params_json, "contractId");
    }
    if (contract_address_hex.empty()
        || !hex_decode_32(contract_address_hex, req.contract_address)) {
        return std::nullopt;
    }

    auto method_id_str = json_get_number_str(params_json, "methodId");
    if (method_id_str.empty()) return std::nullopt;
    {
        std::uint64_t v = 0;
        if (!parse_strict_uint(method_id_str,
                                std::numeric_limits<std::uint32_t>::max(),
                                10, v)) {
            return std::nullopt;
        }
        req.method_id = static_cast<std::uint32_t>(v);
    }

    // gasLimit is optional, but if the key is present it must parse.
    if (params_json.find("\"gasLimit\"") != std::string::npos) {
        auto gas_str = json_get_number_str(params_json, "gasLimit");
        std::uint64_t v = 0;
        if (gas_str.empty() ||
            !parse_strict_uint(gas_str,
                                std::numeric_limits<std::uint64_t>::max(),
                                20 /* uint64 max has 20 digits */, v)) {
            return std::nullopt;
        }
        req.gas_limit = v;
    }

    // accountBalance is optional (round-42 hint).  When present it must
    // parse as an unsigned 64-bit integer in tomis.  Round 43 MEDIUM
    // fix: track presence explicitly via `std::optional` so a live
    // zero-balance account (`accountBalance:0`) triggers the
    // affordability cap (which evaluates to 0 → reject pre-runtime),
    // matching consensus.  Pre-fix, `0` was indistinguishable from
    // "absent" and the cap was skipped.
    if (params_json.find("\"accountBalance\"") != std::string::npos) {
        auto balance_str = json_get_number_str(params_json, "accountBalance");
        std::uint64_t v = 0;
        if (balance_str.empty() ||
            !parse_strict_uint(balance_str,
                                std::numeric_limits<std::uint64_t>::max(),
                                20, v)) {
            return std::nullopt;
        }
        req.account_balance = v;
    }

    // args is optional; absent = canonical empty args cell.
    req.args = vm::CellBuilder().finalize();
    auto args_boc_hex = json_get_string(params_json, "argsBoc");
    if (!args_boc_hex.empty()) {
        req.args = hex_boc_decode_cell(args_boc_hex);
        if (req.args.is_null()) return std::nullopt;  // malformed BOC
    }

    // Optional: caller-supplied per-account state as a hex-encoded BOC.
    // Accept either the v2 `accountStateBoc` or the legacy
    // `executorStateBoc` parameter name.
    auto state_boc_hex = json_get_string(params_json, "accountStateBoc");
    if (state_boc_hex.empty()) {
        state_boc_hex = json_get_string(params_json, "executorStateBoc");
    }
    if (!state_boc_hex.empty()) {
        req.current_state = hex_boc_decode_cell(state_boc_hex);
        if (req.current_state.is_null()) {
            return std::nullopt;  // malformed BOC
        }
    }
    return req;
}

JvmRpcResult handle_jvm_call_contract(const JvmCallContractRequest& req,
                                      const std::string& id,
                                      const JvmConfig* config,
                                      const JvmComputeRuntime* runtime) {
    // Build the call descriptor cell.  Under the account-native topology the
    // destination address already names the contract, so the descriptor body
    // carries only `method_id` and the typed args cell.
    JvmCallDescriptor descriptor;
    descriptor.method_id = req.method_id;
    descriptor.args = req.args;

    auto encoded = encode_jvm_call_descriptor(descriptor);
    if (encoded.is_null()) {
        return JvmRpcResult{
            json_rpc_err(id, -32602, "call descriptor encoding failed"),
            true};
    }

    // Serialize the descriptor cell to BOC for the caller.
    auto boc = vm::std_boc_serialize(encoded, 0);
    if (boc.is_error()) {
        return JvmRpcResult{
            json_rpc_err(id, -32602, "call descriptor boc serialization failed"),
            true};
    }
    const auto& boc_bytes = boc.ok();
    std::string descriptor_boc_hex = hex_encode(
        reinterpret_cast<const uint8_t*>(boc_bytes.data()), boc_bytes.size());

    // Optional local simulation: runs when a runtime and per-account state are
    // both supplied.  Result is appended as a localResult JSON object.
    std::string local_result_json = "null";
    if (runtime != nullptr && config != nullptr && req.current_state.not_null()) {
        JvmContractAccountState previous_state;
        if (!decode_jvm_contract_account_state(req.current_state, previous_state)) {
            return JvmRpcResult{
                json_rpc_err(id, -32602,
                             "accountStateBoc: malformed contract account state"),
                true};
        }

        block::WorkchainComputeInput input;
        input.gas_limit = (req.gas_limit > 0) ? req.gas_limit
                                               : config->max_gas_per_tx;
        std::memcpy(input.account_addr.data(), req.contract_address.data(),
                    req.contract_address.size());
        input.current_data = req.current_state;
        input.inbound_body = vm::load_cell_slice_ref(encoded);

        block::WorkchainComputeContext context;
        context.workchain_id = 3;

        // Mirror the consensus stdlib_hash gate in dispatch-engine.cpp: if
        // the per-account `stdlib_hash` does not match ConfigParam 85,
        // consensus will reject this state, so RPC simulation must too —
        // otherwise a full-node returns a successful simulation for state
        // that on-chain execution would skip with `sk_bad_state`.
        if (previous_state.stdlib_hash != config->stdlib_hash) {
            local_result_json =
                "{\"success\":false,\"outOfGas\":false,"
                "\"outOfMemory\":false,\"gasUsed\":0,"
                "\"vmLog\":\"accountStateBoc stdlib_hash does not match "
                "ConfigParam 85\",\"newStateBoc\":null}";
            std::string result = "{\"callDescriptorBoc\":\"" + descriptor_boc_hex
                               + "\",\"contractAddress\":\""
                               + hex_encode(req.contract_address)
                               + "\",\"localResult\":" + local_result_json + "}";
            return JvmRpcResult{json_rpc_ok(id, result), false};
        }
        // Round 18 MEDIUM fix: mirror the consensus rt.jar hash gate
        // (round-17 fix in dispatch-engine.cpp).  Without this, a
        // full node could return a successful localResult for a
        // state+config pair that on-chain consensus would skip
        // because the validator's loaded rt.jar disagrees with
        // ConfigParam 85's stdlib_hash.
        std::array<std::uint8_t, 32> cfg_stdlib_hash_array{};
        std::memcpy(cfg_stdlib_hash_array.data(),
                    config->stdlib_hash.data(),
                    cfg_stdlib_hash_array.size());
        if (runtime->rt_jar_hash() != cfg_stdlib_hash_array) {
            local_result_json =
                "{\"success\":false,\"outOfGas\":false,"
                "\"outOfMemory\":false,\"gasUsed\":0,"
                "\"vmLog\":\"validator rt.jar does not match ConfigParam "
                "85 stdlib_hash; consensus would reject this call\","
                "\"newStateBoc\":null}";
            std::string result = "{\"callDescriptorBoc\":\"" + descriptor_boc_hex
                               + "\",\"contractAddress\":\""
                               + hex_encode(req.contract_address)
                               + "\",\"localResult\":" + local_result_json + "}";
            return JvmRpcResult{json_rpc_ok(id, result), false};
        }
        // Mirror the consensus address-binding gate too: if the supplied
        // accountStateBoc does not actually correspond to the requested
        // contractAddress, consensus would reject with sk_bad_state.
        // Without this, RPC simulation would happily run any state under
        // any address — which lets an attacker confuse clients into
        // believing a contract exists at a victim's deterministic address.
        const auto bound_manifest_hash = compute_jvm_manifest_root_hash(
            previous_state.manifest_root);
        const auto bound_addr = derive_jvm_contract_address_from_state(
            previous_state.deployer, previous_state.address_commit,
            previous_state.class_hash, bound_manifest_hash);
        if (std::memcmp(req.contract_address.data(), bound_addr.data(),
                        bound_addr.size()) != 0) {
            local_result_json =
                "{\"success\":false,\"outOfGas\":false,"
                "\"outOfMemory\":false,\"gasUsed\":0,"
                "\"vmLog\":\"accountStateBoc does not bind to "
                "contractAddress\",\"newStateBoc\":null}";
            std::string result = "{\"callDescriptorBoc\":\"" + descriptor_boc_hex
                               + "\",\"contractAddress\":\""
                               + hex_encode(req.contract_address)
                               + "\",\"localResult\":" + local_result_json + "}";
            return JvmRpcResult{json_rpc_ok(id, result), false};
        }
        // Mirror the consensus max_class_bytes gate (round-9 fix in
        // dispatch-engine.cpp): RPC simulation must reject states
        // whose decoded class_bytes exceed the ConfigParam 85 cap so
        // a full-node cannot be pushed into oversized class
        // decode/load work that on-chain execution would skip with
        // `sk_bad_state`.
        if (config->max_class_bytes > 0 &&
            previous_state.decoded_class_bytes_size >
                config->max_class_bytes) {
            local_result_json =
                "{\"success\":false,\"outOfGas\":false,"
                "\"outOfMemory\":false,\"gasUsed\":0,"
                "\"vmLog\":\"accountStateBoc class_bytes exceeds "
                "ConfigParam 85 max_class_bytes\","
                "\"newStateBoc\":null}";
            std::string result = "{\"callDescriptorBoc\":\"" + descriptor_boc_hex
                               + "\",\"contractAddress\":\""
                               + hex_encode(req.contract_address)
                               + "\",\"localResult\":" + local_result_json + "}";
            return JvmRpcResult{json_rpc_ok(id, result), false};
        }
        // Round-37 fix (kept), Round-42 fix (re-ordered + balance cap):
        // Apply consensus's gas-cap order before the admission floor
        // check so RPC matches dispatch-engine.cpp exactly:
        //   1. cap to `max_gas_per_tx`
        //   2. cap to `balance / gas_price` (when balance hint provided)
        //   3. reject if zero
        //   4. reject if below `kJvmAdmissionGasFloor`
        // Pre-Round-42, RPC checked the floor against the un-capped
        // `input.gas_limit`, so a config with `max_gas_per_tx < 1024`
        // would let RPC simulate a successful call where consensus
        // rejects pre-runtime — and the live RPC path threw away the
        // account balance entirely, so balance-derived rejections
        // never showed up in localResult.
        if (config->max_gas_per_tx > 0
            && input.gas_limit > config->max_gas_per_tx) {
            input.gas_limit = config->max_gas_per_tx;
        }
        // Round-42 fix: mirror the engine's round-31 affordability cap
        // when the live RPC path injects the account's balance.  The
        // validator-engine fetches the on-chain account balance and
        // populates `req.account_balance` so RPC simulation matches the
        // consensus path's `balance/gas_price` cap.  When the balance
        // hint is absent (caller-supplied state without balance), the
        // cap reduces to `min(input.gas_limit, max_gas_per_tx)` and the
        // simulation is balance-blind — clients that need affordability
        // semantics must pass `accountBalance`.
        //
        // Round 43 MEDIUM fix: the predicate now uses `has_value()`
        // rather than `> 0`, so a live zero-balance account triggers
        // the cap (affordable=0 → reject pre-runtime) instead of being
        // treated as "no hint" and skipping the cap.
        if (config->gas_price > 0 && req.account_balance.has_value()) {
            std::uint64_t affordable =
                *req.account_balance / config->gas_price;
            if (affordable < input.gas_limit) {
                input.gas_limit = affordable;
            }
        }
        if (input.gas_limit == 0) {
            local_result_json =
                "{\"success\":false,\"outOfGas\":true,"
                "\"outOfMemory\":false,\"gasUsed\":0,"
                "\"vmLog\":\"effective gasLimit is zero after balance / "
                "max_gas_per_tx caps (consensus would reject)\","
                "\"newStateBoc\":null}";
            std::string result = "{\"callDescriptorBoc\":\"" + descriptor_boc_hex
                               + "\",\"contractAddress\":\""
                               + hex_encode(req.contract_address)
                               + "\",\"localResult\":" + local_result_json + "}";
            return JvmRpcResult{json_rpc_ok(id, result), false};
        }
        // Round-36 fix: mirror the engine's round-35 admission gas
        // floor.  Public full-node RPC otherwise accepts any
        // `gasLimit` and runs the resolver / class-loading work
        // before AVATA gas accounting starts, exactly the surface
        // round 35 closed on-chain.  Reject simulation when the
        // (capped) gas budget is below the floor.
        if (input.gas_limit < kJvmAdmissionGasFloor) {
            local_result_json =
                "{\"success\":false,\"outOfGas\":true,"
                "\"outOfMemory\":false,\"gasUsed\":0,"
                "\"vmLog\":\"effective gasLimit is below the JVM "
                "admission floor (consensus would reject)\","
                "\"newStateBoc\":null}";
            std::string result = "{\"callDescriptorBoc\":\"" + descriptor_boc_hex
                               + "\",\"contractAddress\":\""
                               + hex_encode(req.contract_address)
                               + "\",\"localResult\":" + local_result_json + "}";
            return JvmRpcResult{json_rpc_ok(id, result), false};
        }

        auto invocation_result = runtime->run_contract(
            input, context, *config, previous_state);
        if (invocation_result.is_error()) {
            // Round 45 LOW fix: runtime invocation errors are billed
            // by consensus through `skipped_output_billed(sk_bad_state,
            // ..., kJvmAdmissionGasFloor)` (dispatch-engine.cpp round 37);
            // pre-fix RPC reported `gasUsed:0` for the same condition,
            // so localResult under-reported the on-chain charge.
            local_result_json = "{\"success\":false,\"outOfGas\":false,"
                                "\"outOfMemory\":false,\"gasUsed\":"
                                + std::to_string(kJvmAdmissionGasFloor)
                                + ",\"vmLog\":\"runtime error: "
                                + invocation_result.error().message().str()
                                + "\",\"newStateBoc\":null}";
        } else {
            auto inv = invocation_result.move_as_ok();
            // Round 41 MEDIUM fix: mirror the consensus round-39 storage
            // walk gas billing AND round-40 affordable-cap reject in the
            // RPC local-simulation.  Pre-fix, a storage-mutating call
            // whose runtime gas equals `input.gas_limit` would simulate
            // `success=true` with `newStateBoc != null`, while consensus
            // adds walk gas, sees the total exceed `effective_gas_limit`,
            // and rejects with sk_no_gas.  Public full-nodes therefore
            // told clients a transaction would succeed when on-chain
            // execution would burn the cap and discard state.
            //
            // RPC has no `account_balance` to derive an affordability
            // cap, so the "effective gas limit" here is `input.gas_limit`
            // (already capped to `max_gas_per_tx` above by the round-37
            // mirror).  The walk + cap logic is otherwise identical to
            // dispatch-engine.cpp (kJvmStorageWalkGasPerCell shared via
            // avata-execution.h).
            bool walk_cap_exceeded = false;
            // Round 44 MEDIUM fix: also track the `max_storage_cells`
            // exceedance result.  Round 43 made build_output skip its
            // defensive walk when dispatch already walked, but RPC was
            // discarding the stat_result — so a contract that committed
            // a storage_root above `max_storage_cells` simulated
            // success here while consensus rejected with sk_bad_state
            // via the dispatch's stat-error branch.
            bool walk_max_cells_exceeded = false;
            // Round 43 LOW: track whether the RPC walk happened so
            // build_jvm_workchain_output can skip its redundant walk.
            bool storage_walk_performed = false;
            if (config->max_storage_cells > 0
                && inv.success
                && inv.storage_root.not_null()) {
                const bool storage_changed =
                    previous_state.storage_root.is_null()
                    || inv.storage_root->get_hash()
                           != previous_state.storage_root->get_hash();
                if (storage_changed) {
                    storage_walk_performed = true;
                    vm::CellStorageStat stat(static_cast<unsigned long long>(
                        config->max_storage_cells));
                    auto stat_result =
                        stat.add_used_storage(inv.storage_root, true);
                    const std::uint64_t walk_gas =
                        stat.cells * kJvmStorageWalkGasPerCell;
                    if (inv.gas_used >
                        std::numeric_limits<std::uint64_t>::max() - walk_gas) {
                        inv.gas_used =
                            std::numeric_limits<std::uint64_t>::max();
                    } else {
                        inv.gas_used += walk_gas;
                    }
                    if (inv.gas_used > input.gas_limit) {
                        walk_cap_exceeded = true;
                    } else if (stat_result.is_error()) {
                        // Mirrors dispatch's sk_bad_state branch.  The
                        // cap-check fires first because consensus also
                        // bills the affordable cap on overflow before
                        // reporting max_storage_cells.
                        walk_max_cells_exceeded = true;
                    }
                }
            }

            if (walk_cap_exceeded) {
                local_result_json = std::string("{\"success\":false,")
                    + "\"outOfGas\":true,\"outOfMemory\":false,"
                    + "\"gasUsed\":" + std::to_string(input.gas_limit) +
                    ",\"vmLog\":\"JVM storage walk gas exceeded affordable "
                    "cap\",\"newStateBoc\":null}";
            } else if (walk_max_cells_exceeded) {
                // Bill `max(post-walk gas, kJvmAdmissionGasFloor)` to
                // mirror consensus's `skipped_output_billed(sk_bad_state)`.
                const std::uint64_t billed = std::max<std::uint64_t>(
                    inv.gas_used, kJvmAdmissionGasFloor);
                local_result_json = std::string("{\"success\":false,")
                    + "\"outOfGas\":false,\"outOfMemory\":false,"
                    + "\"gasUsed\":" + std::to_string(billed) +
                    ",\"vmLog\":\"JVM committed storage_root exceeds "
                    "ConfigParam 85 max_storage_cells\","
                    "\"newStateBoc\":null}";
            } else {
                auto output = build_jvm_workchain_output(
                    *config, previous_state, input.gas_limit, inv,
                    /*storage_walk_already_billed=*/storage_walk_performed);

                std::string new_state_hex = "null";
                if (output.is_ok() && output.ok().new_data.not_null()) {
                    auto new_boc = vm::std_boc_serialize(output.ok().new_data, 0);
                    if (new_boc.is_ok()) {
                        new_state_hex = "\"" + hex_encode(
                            reinterpret_cast<const uint8_t*>(new_boc.ok().data()),
                            new_boc.ok().size()) + "\"";
                    }
                }
                const std::string vm_log = output.is_ok()
                    ? output.ok().vm_log
                    : inv.out_of_gas ? "JVM execution exhausted gas"
                    : inv.out_of_memory ? "JVM execution exhausted memory"
                    : "JVM execution failed";

                // Round 14 MEDIUM fix: report `success=false` when
                // `build_jvm_workchain_output` rejected the result (e.g.,
                // max_storage_cells exceeded).  Pre-fix the RPC reflected
                // `inv.success` directly, so a runtime-successful call
                // whose committed storage exceeded the cap returned
                // `success=true` with `newStateBoc=null` — RPC simulation
                // diverged from on-chain consensus exactly on the cap that
                // round 12 added.
                const bool output_ok = output.is_ok();
                const bool effective_success = inv.success && output_ok;
                // Round 43 LOW fix: report the consensus-charged gas
                // (which `build_jvm_workchain_output` floors to
                // `kJvmAdmissionGasFloor` on success) rather than the
                // raw runtime-reported gas.  Pre-fix RPC under-reported
                // for accounts that consumed less than 1024 gas — the
                // localResult said `gasUsed=100` while consensus billed
                // 1024.
                //
                // Round 44 LOW fix: also apply the floor on the error
                // path.  When build_output rejects (e.g. malformed
                // post-runtime state), consensus bills
                // `max(inv.gas_used, kJvmAdmissionGasFloor)` via
                // `skipped_output_billed`; pre-fix RPC reported the
                // raw `inv.gas_used` here too.
                const std::uint64_t reported_gas_used =
                    output_ok ? output.ok().gas_used
                              : std::max<std::uint64_t>(
                                    inv.gas_used, kJvmAdmissionGasFloor);
                local_result_json = std::string("{\"success\":") +
                    (effective_success ? "true" : "false") +
                    ",\"outOfGas\":" + (inv.out_of_gas ? "true" : "false") +
                    ",\"outOfMemory\":" + (inv.out_of_memory ? "true" : "false") +
                    ",\"gasUsed\":" + std::to_string(reported_gas_used) +
                    ",\"vmLog\":\"" + vm_log + "\"" +
                    ",\"newStateBoc\":" + new_state_hex + "}";
            }
        }
    }

    std::string result = "{\"callDescriptorBoc\":\"" + descriptor_boc_hex
                       + "\",\"contractAddress\":\""
                       + hex_encode(req.contract_address)
                       + "\",\"localResult\":" + local_result_json + "}";
    return JvmRpcResult{json_rpc_ok(id, result), false};
}

// -------------------------------------------------------------------------
// jvm_getContractState
// -------------------------------------------------------------------------

std::optional<JvmGetContractStateRequest> parse_jvm_get_contract_state_request(
    const std::string& params_json) {
    JvmGetContractStateRequest req;
    auto contract_address_hex =
        json_get_string(params_json, "contractAddress");
    if (contract_address_hex.empty()) {
        contract_address_hex = json_get_string(params_json, "contractId");
    }
    if (contract_address_hex.empty()
        || !hex_decode_32(contract_address_hex, req.contract_address)) {
        return std::nullopt;
    }
    auto state_boc_hex = json_get_string(params_json, "accountStateBoc");
    if (state_boc_hex.empty()) {
        state_boc_hex = json_get_string(params_json, "executorStateBoc");
    }
    if (!state_boc_hex.empty()) {
        req.account_state = hex_boc_decode_cell(state_boc_hex);
        if (req.account_state.is_null()) {
            return std::nullopt;  // malformed BOC
        }
    }
    return req;
}

JvmRpcResult handle_jvm_get_contract_state(
    const JvmGetContractStateRequest& req,
    const std::string& id) {
    if (req.account_state.is_null()) {
        return JvmRpcResult{
            json_rpc_err(id, -32602, "account state cell is required"),
            true};
    }

    JvmContractAccountState state;
    if (!decode_jvm_contract_account_state(req.account_state, state)) {
        return JvmRpcResult{
            json_rpc_err(id, -32602, "malformed contract account state cell"),
            true};
    }

    std::string storage_hash = "null";
    if (state.storage_root.not_null()) {
        auto h = state.storage_root->get_hash();
        storage_hash = "\"" + hex_encode(h.as_slice().ubegin(), 32) + "\"";
    }

    // class_hash is pinned in the per-account state; the manifest's first
    // entry (if any) supplies the class name for human readability.
    std::string class_name_json = "null";
    std::string class_hash_json =
        "\"" + hex_encode(state.class_hash) + "\"";
    if (state.manifest_root.not_null()) {
        auto manifest_result = parse_jvm_method_manifest(state.manifest_root);
        if (manifest_result.is_ok() && !manifest_result.ok().empty()) {
            class_name_json =
                "\"" + json_escape_string(manifest_result.ok().front().class_name)
                + "\"";
        }
    }

    // Enumerate storage slots (up to the default limit) for this single
    // contract account; the storage dict is per-account and isolated.
    std::string slots_json = "null";
    bool slots_truncated = false;
    if (state.storage_root.not_null()) {
        JvmStorageCellHost storage(state.storage_root);
        std::string slots_buf = "[";
        std::size_t slot_count = 0;
        static constexpr std::size_t kSlotLimit =
            JvmStorageCellHost::kEnumerateDefaultLimit;
        auto enum_status = storage.enumerate_slots(
            [&](const JvmStorageSlot& slot, const JvmStorageValue& value) {
                if (slot_count > 0) slots_buf += ",";
                slots_buf += "{\"key\":\"" + hex_encode(slot.data(), slot.size())
                           + "\",\"value\":\""
                           + hex_encode(value.data(), value.size()) + "\"}";
                ++slot_count;
                return true;
            },
            kSlotLimit + 1);  // fetch one extra to detect truncation
        if (enum_status.is_ok()) {
            if (slot_count > kSlotLimit) {
                auto last_comma = slots_buf.rfind(',');
                if (last_comma != std::string::npos) {
                    slots_buf.erase(last_comma);
                }
                slots_truncated = true;
                --slot_count;
            }
            slots_buf += "]";
            slots_json = slots_buf;
        }
    }

    std::string result = "{\"contractAddress\":\""
                       + hex_encode(req.contract_address)
                       + "\",\"className\":" + class_name_json
                       + ",\"classHash\":" + class_hash_json
                       + ",\"storageRootHash\":" + storage_hash
                       + ",\"storageSlots\":" + slots_json
                       + ",\"storageTruncated\":"
                       + (slots_truncated ? "true" : "false") + "}";
    return JvmRpcResult{json_rpc_ok(id, result), false};
}

// -------------------------------------------------------------------------
// jvm_getReceipts
// -------------------------------------------------------------------------

std::optional<JvmGetReceiptsRequest> parse_jvm_get_receipts_request(
    const std::string& params_json) {
    JvmGetReceiptsRequest req;
    auto contract_address_hex =
        json_get_string(params_json, "contractAddress");
    if (contract_address_hex.empty()) {
        contract_address_hex = json_get_string(params_json, "contractId");
    }
    if (contract_address_hex.empty()
        || !hex_decode_32(contract_address_hex, req.contract_address)) {
        return std::nullopt;
    }

    if (params_json.find("\"fromBlock\"") != std::string::npos) {
        auto from_str = json_get_number_str(params_json, "fromBlock");
        std::uint64_t v = 0;
        if (from_str.empty() ||
            !parse_strict_uint(from_str,
                                std::numeric_limits<std::uint64_t>::max(),
                                20, v)) {
            return std::nullopt;
        }
        req.from_block = v;
    }
    if (params_json.find("\"toBlock\"") != std::string::npos) {
        auto to_str = json_get_number_str(params_json, "toBlock");
        std::uint64_t v = 0;
        if (to_str.empty() ||
            !parse_strict_uint(to_str,
                                std::numeric_limits<std::uint64_t>::max(),
                                20, v)) {
            return std::nullopt;
        }
        req.to_block = v;
    }
    return req;
}

JvmRpcResult handle_jvm_get_receipts(const JvmGetReceiptsRequest& req,
                                     const std::string& id) {
    // Pure core fallback: full-node routing in validator-engine handles live
    // receipt retrieval by scanning the wc=3 account history at the supplied
    // address and decoding committed JVME event messages.  Unit tests that
    // call this core facade directly have no block-state/liteserver
    // connection, so they receive a well-formed empty result.
    std::string result = "{\"contractAddress\":\""
                       + hex_encode(req.contract_address)
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
    const JvmConfig& config,
    const JvmComputeRuntime* runtime) {
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
        return handle_jvm_call_contract(*req, id, &config, runtime);
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
