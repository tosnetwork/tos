/*
    EVM Workchain — Ethereum JSON-RPC facade implementation.

    First-slice implementation:
      - eth_chainId, eth_blockNumber, eth_gasPrice, net_version: static responses
      - eth_getBalance, eth_getTransactionCount, eth_getCode: read from global EVM state
      - eth_sendRawTransaction: decode RLP → execute → return tx hash
      - eth_call, eth_estimateGas: read-only execution (simplified)
      - eth_getTransactionReceipt: stub (receipts not persisted yet)

    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm-rpc.h"

#include "evm-workchain.h"
#include "evm-init.h"
#include "evm-state.h"
#include "evm-block-context.h"
#include "evm-executor.h"
#include "evm-transaction.h"
#include "evm-tracer.h"
#include "evm-subscriptions.h"

#include <silkworm/core/common/util.hpp>
#include <ethash/keccak.hpp>
#include <silkworm/core/types/address.hpp>
#include <intx/intx.hpp>

#include <cstdio>
#include <cstring>
#include <sstream>

namespace evm_workchain {

// ---------------------------------------------------------------------------
// Hex encoding helpers (Ethereum canonical format: 0x-prefixed, no leading zeros)
// ---------------------------------------------------------------------------

static std::string to_hex_quantity(uint64_t val) {
    char buf[32];
    if (val == 0) return "\"0x0\"";
    snprintf(buf, sizeof(buf), "\"0x%lx\"", (unsigned long)val);
    return buf;
}

static std::string to_hex_quantity(const intx::uint256& val) {
    if (val == 0) return "\"0x0\"";
    std::string hex = intx::hex(val);
    // Remove leading zeros
    size_t start = hex.find_first_not_of('0');
    if (start == std::string::npos) return "\"0x0\"";
    return "\"0x" + hex.substr(start) + "\"";
}

static std::string to_hex_data(const uint8_t* data, size_t len) {
    std::string out = "\"0x";
    for (size_t i = 0; i < len; ++i) {
        char buf[4];
        snprintf(buf, sizeof(buf), "%02x", data[i]);
        out += buf;
    }
    out += "\"";
    return out;
}

static std::string to_hex_addr(const evmc::address& addr) {
    return to_hex_data(addr.bytes, 20);
}

static std::string make_result(const std::string& id, const std::string& result_value) {
    return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":" + result_value + "}";
}

static std::string make_error(const std::string& id, int code, const std::string& msg) {
    return "{\"jsonrpc\":\"2.0\",\"id\":" + id +
           ",\"error\":{\"code\":" + std::to_string(code) +
           ",\"message\":\"" + msg + "\"}}";
}

// ---------------------------------------------------------------------------
// Param parsing (minimal: extract hex address from first param)
// ---------------------------------------------------------------------------

static bool parse_hex_byte(char c, uint8_t& out) {
    if (c >= '0' && c <= '9') { out = static_cast<uint8_t>(c - '0'); return true; }
    if (c >= 'a' && c <= 'f') { out = static_cast<uint8_t>(c - 'a' + 10); return true; }
    if (c >= 'A' && c <= 'F') { out = static_cast<uint8_t>(c - 'A' + 10); return true; }
    return false;
}

static bool parse_hex_address(const std::string& params, evmc::address& out) {
    // Find the first 0x in the params string
    auto pos = params.find("0x");
    if (pos == std::string::npos || pos + 42 > params.size()) return false;
    pos += 2;  // skip "0x"
    for (int i = 0; i < 20; ++i) {
        uint8_t hi, lo;
        if (!parse_hex_byte(params[pos + i*2], hi) || !parse_hex_byte(params[pos + i*2 + 1], lo))
            return false;
        out.bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

static bool parse_hex_bytes(const std::string& hex, silkworm::Bytes& out) {
    auto pos = hex.find("0x");
    if (pos == std::string::npos) return false;
    pos += 2;
    size_t len = 0;
    // Find end of hex string (until quote or end)
    while (pos + len < hex.size() && hex[pos + len] != '"' && hex[pos + len] != ',' && hex[pos + len] != '}') ++len;
    if (len % 2 != 0) return false;
    out.resize(len / 2);
    for (size_t i = 0; i < len / 2; ++i) {
        uint8_t hi, lo;
        if (!parse_hex_byte(hex[pos + i*2], hi) || !parse_hex_byte(hex[pos + i*2 + 1], lo))
            return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

// Forward declarations
static std::vector<std::vector<evmc::bytes32>> parse_topics_array(const std::string& params);

// Look up the real block hash for a given block number, return hex or zeros if not found.
static std::string lookup_block_hash_hex(uint64_t block_num) {
    auto hash = global_evm_state().get_block_hash(block_num);
    bool is_zero = true;
    for (auto b : hash.bytes) { if (b != 0) { is_zero = false; break; } }
    if (is_zero) return "\"0x" + std::string(64, '0') + "\"";
    return to_hex_data(hash.bytes, 32);
}

// Compute Ethereum logs bloom (2048-bit / 256-byte) into caller-provided buffer.
// For each log: hash(address) and hash(each topic) contribute 3 bits each to the bloom.
// Reference: ~/s/silkworm/core/types/bloom.cpp
static void compute_logs_bloom(const std::vector<silkworm::Log>& logs, uint8_t bloom[256]) {
    std::memset(bloom, 0, 256);
    for (const auto& log : logs) {
        auto ah = ethash::keccak256(log.address.bytes, 20);
        for (int i = 0; i < 6; i += 2) {
            uint16_t bit = (static_cast<uint16_t>(ah.bytes[i]) << 8 | ah.bytes[i + 1]) & 0x7FF;
            bloom[bit / 8] |= (1 << (bit % 8));
        }
        for (const auto& topic : log.topics) {
            auto th = ethash::keccak256(topic.bytes, 32);
            for (int i = 0; i < 6; i += 2) {
                uint16_t bit = (static_cast<uint16_t>(th.bytes[i]) << 8 | th.bytes[i + 1]) & 0x7FF;
                bloom[bit / 8] |= (1 << (bit % 8));
            }
        }
    }
}

static std::string compute_logs_bloom_hex(const std::vector<silkworm::Log>& logs) {
    uint8_t bloom[256];
    compute_logs_bloom(logs, bloom);
    return to_hex_data(bloom, 256);
}

// ---------------------------------------------------------------------------
// Method handlers
// ---------------------------------------------------------------------------

static RpcResult handle_chain_id(const std::string& id) {
    return {make_result(id, to_hex_quantity(kEvmChainId)), false};
}

static RpcResult handle_net_version(const std::string& id) {
    return {make_result(id, "\"" + std::to_string(kEvmChainId) + "\""), false};
}

static RpcResult handle_block_number(const std::string& id) {
    return {make_result(id, to_hex_quantity(global_evm_state().block_number())), false};
}

static RpcResult handle_gas_price(const std::string& id) {
    // Return current base fee + suggested priority fee (1 gwei)
    const auto latest_bn = global_evm_state().block_number();
    auto latest = global_evm_state().get_block_copy(latest_bn);
    intx::uint256 base_fee{kInitialBaseFee};
    if (global_evm_state().has_block(latest_bn)) {
        base_fee = calc_base_fee(latest.base_fee_per_gas,
                                  latest.gas_used, latest.gas_limit);
    }
    intx::uint256 suggested = base_fee + intx::uint256{1'000'000'000};  // base + 1 gwei priority
    return {make_result(id, to_hex_quantity(suggested)), false};
}

static RpcResult handle_get_balance(const std::string& params, const std::string& id) {
    evmc::address addr{};
    if (!parse_hex_address(params, addr)) {
        return {make_error(id, -32602, "invalid address parameter"), true};
    }
    auto balance = global_evm_state().get_balance(addr);
    return {make_result(id, to_hex_quantity(balance)), false};
}

static RpcResult handle_get_transaction_count(const std::string& params, const std::string& id) {
    evmc::address addr{};
    if (!parse_hex_address(params, addr)) {
        return {make_error(id, -32602, "invalid address parameter"), true};
    }
    auto nonce = global_evm_state().get_nonce(addr);
    return {make_result(id, to_hex_quantity(nonce)), false};
}

static RpcResult handle_get_code(const std::string& params, const std::string& id) {
    evmc::address addr{};
    if (!parse_hex_address(params, addr)) {
        return {make_error(id, -32602, "invalid address parameter"), true};
    }
    auto acct = global_evm_state().read_account(addr);
    if (!acct) {
        return {make_result(id, "\"0x\""), false};
    }
    auto code = global_evm_state().read_code_copy(addr, acct->code_hash);
    if (code.empty()) {
        return {make_result(id, "\"0x\""), false};
    }
    return {make_result(id, to_hex_data(code.data(), code.size())), false};
}

// Synchronous execution path — used by test-evm-executor only.
// In the real node, eth_sendRawTransaction is intercepted by
// JsonRpcServer::handle_eth_sendRawTransaction() which submits
// to the ExtMessagePool asynchronously.
static RpcResult handle_send_raw_transaction(const std::string& params, const std::string& id) {
    silkworm::Bytes raw_tx;
    if (!parse_hex_bytes(params, raw_tx)) {
        return {make_error(id, -32602, "invalid hex transaction data"), true};
    }

    auto decode_result = decode_evm_transaction(raw_tx);
    if (auto* err = std::get_if<TxDecodeError>(&decode_result)) {
        return {make_error(id, -32000, err->reason), true};
    }
    auto& decoded = std::get<DecodedTransaction>(decode_result);

    auto& evm_state = global_evm_state();
    std::optional<StoredBlock> parent_block;
    uint64_t bn = evm_state.allocate_next_block_number(parent_block);

    // Compute EIP-1559 base fee from parent block
    intx::uint256 base_fee{kInitialBaseFee};
    if (parent_block) {
        base_fee = calc_base_fee(parent_block->base_fee_per_gas,
                                  parent_block->gas_used,
                                  parent_block->gas_limit);
    }

    uint8_t rand_seed[32] = {};
    auto block = make_evm_block(
        bn,
        static_cast<uint64_t>(std::time(nullptr)),
        rand_seed);
    // Set the computed base fee on the block header
    block.header.base_fee_per_gas = base_fee;
    const auto& config = evm_chain_config();

    auto exec_result = execute_evm_transaction(decoded.txn, block, evm_state, config);

    auto tx_hash = decoded.txn.hash();

    // Store receipt
    StoredReceipt receipt;
    receipt.success = exec_result.success;
    receipt.gas_used = exec_result.gas_used;
    receipt.cumulative_gas_used = exec_result.gas_used;  // first (only) tx in sync-path block
    receipt.block_number = bn;
    receipt.tx_index = 0;
    receipt.from = decoded.sender;
    receipt.to = decoded.txn.to;
    receipt.contract_address = exec_result.contract_address;
    receipt.logs = exec_result.logs;
    receipt.return_data = exec_result.return_data;
    evm_state.store_receipt(tx_hash, std::move(receipt));

    // Store transaction for eth_getTransactionByHash
    StoredTransaction stored_tx;
    stored_tx.from = decoded.sender;
    stored_tx.to = decoded.txn.to;
    stored_tx.value = decoded.txn.value;
    stored_tx.data = decoded.txn.data;
    stored_tx.nonce = decoded.txn.nonce;
    stored_tx.gas_limit = decoded.txn.gas_limit;
    stored_tx.gas_price = decoded.txn.max_fee_per_gas;
    stored_tx.block_number = bn;
    stored_tx.tx_index = 0;
    evm_state.store_transaction(tx_hash, std::move(stored_tx));

    // Store logs for eth_getLogs
    if (!exec_result.logs.empty()) {
        evm_state.store_logs(bn, tx_hash, exec_result.logs);
    }

    // Build and store the block
    StoredBlock stored_block;
    stored_block.number = bn;
    stored_block.timestamp = static_cast<uint64_t>(std::time(nullptr));
    stored_block.gas_used = exec_result.gas_used;
    stored_block.base_fee_per_gas = base_fee;
    stored_block.transaction_hashes.push_back(tx_hash);

    // Block hash = keccak256(block_number || parent_hash || timestamp)
    stored_block.parent_hash = parent_block ? parent_block->hash : evmc::bytes32{};

    // Compute block hash deterministically
    // Block hash = keccak256(block_number || parent_hash || timestamp)
    uint8_t hash_input[32 + 32 + 8];
    auto bn_be = intx::be::store<evmc::uint256be>(intx::uint256{bn});
    std::memcpy(hash_input, bn_be.bytes, 32);
    std::memcpy(hash_input + 32, stored_block.parent_hash.bytes, 32);
    uint64_t ts_be = __builtin_bswap64(stored_block.timestamp);
    std::memcpy(hash_input + 64, &ts_be, 8);
    auto h = ethash::keccak256(hash_input, sizeof(hash_input));
    std::memcpy(stored_block.hash.bytes, h.bytes, 32);

    // Compute block-level logs bloom from all transaction logs
    compute_logs_bloom(exec_result.logs, stored_block.logs_bloom);

    // Compute transactionsRoot = keccak256(concatenated tx hashes)
    if (!stored_block.transaction_hashes.empty()) {
        size_t total = stored_block.transaction_hashes.size() * 32;
        std::vector<uint8_t> buf(total);
        for (size_t ti = 0; ti < stored_block.transaction_hashes.size(); ++ti) {
            std::memcpy(buf.data() + ti * 32,
                        stored_block.transaction_hashes[ti].bytes, 32);
        }
        auto tr = ethash::keccak256(buf.data(), buf.size());
        std::memcpy(stored_block.transactions_root.bytes, tr.bytes, 32);
    }

    // Compute receiptsRoot (simplified: no MPT available, use keccak256 of receipt data)
    {
        std::vector<uint8_t> buf;
        buf.push_back(exec_result.success ? 1 : 0);
        uint64_t gu_be = __builtin_bswap64(exec_result.gas_used);
        buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&gu_be),
                   reinterpret_cast<uint8_t*>(&gu_be) + 8);
        buf.insert(buf.end(), stored_block.logs_bloom,
                   stored_block.logs_bloom + 256);
        auto rr = ethash::keccak256(buf.data(), buf.size());
        std::memcpy(stored_block.receipts_root.bytes, rr.bytes, 32);
    }

    evm_state.store_block(stored_block);

    // Notify subscribers
    auto& sub_mgr = global_subscription_manager();
    sub_mgr.notify_new_head(stored_block);
    sub_mgr.notify_new_pending_transaction(tx_hash);
    if (!exec_result.logs.empty()) {
        sub_mgr.notify_logs(bn, tx_hash, exec_result.logs, stored_block.hash);
    }

    return {make_result(id, to_hex_data(tx_hash.bytes, 32)), false};
}

static RpcResult handle_get_transaction_receipt(const std::string& params, const std::string& id) {
    // Parse tx hash from params
    silkworm::Bytes hash_bytes;
    if (!parse_hex_bytes(params, hash_bytes) || hash_bytes.size() != 32) {
        return {make_error(id, -32602, "invalid transaction hash"), true};
    }

    evmc::bytes32 tx_hash;
    std::memcpy(tx_hash.bytes, hash_bytes.data(), 32);

    auto receipt = global_evm_state().get_receipt_copy(tx_hash);
    if (!receipt) {
        return {make_result(id, "null"), false};
    }

    // Build receipt JSON
    std::string r = "{";
    r += "\"transactionHash\":" + to_hex_data(tx_hash.bytes, 32) + ",";
    r += "\"blockNumber\":" + to_hex_quantity(receipt->block_number) + ",";
    r += "\"from\":" + to_hex_addr(receipt->from) + ",";
    if (receipt->to) {
        r += "\"to\":" + to_hex_addr(*receipt->to) + ",";
    } else {
        r += "\"to\":null,";
    }
    if (receipt->contract_address) {
        r += "\"contractAddress\":" + to_hex_addr(*receipt->contract_address) + ",";
    } else {
        r += "\"contractAddress\":null,";
    }
    r += "\"gasUsed\":" + to_hex_quantity(receipt->gas_used) + ",";
    r += "\"cumulativeGasUsed\":" + to_hex_quantity(receipt->cumulative_gas_used) + ",";
    // effectiveGasPrice: look up from stored transaction (required by EIP-1559 wallets)
    {
        auto stored_tx = global_evm_state().get_transaction_copy(tx_hash);
        r += "\"effectiveGasPrice\":" + to_hex_quantity(stored_tx ? stored_tx->gas_price : intx::uint256{0}) + ",";
    }
    r += "\"status\":" + to_hex_quantity(receipt->success ? uint64_t{1} : uint64_t{0}) + ",";
    r += "\"logs\":[";
    for (size_t i = 0; i < receipt->logs.size(); ++i) {
        if (i > 0) r += ",";
        const auto& log = receipt->logs[i];
        r += "{\"address\":" + to_hex_addr(log.address) + ",";
        r += "\"topics\":[";
        for (size_t j = 0; j < log.topics.size(); ++j) {
            if (j > 0) r += ",";
            r += to_hex_data(log.topics[j].bytes, 32);
        }
        r += "],";
        r += "\"data\":" + to_hex_data(log.data.data(), log.data.size()) + ",";
        r += "\"logIndex\":" + to_hex_quantity(static_cast<uint64_t>(i)) + ",";
        r += "\"blockNumber\":" + to_hex_quantity(receipt->block_number) + ",";
        r += "\"transactionHash\":" + to_hex_data(tx_hash.bytes, 32) + ",";
        r += "\"blockHash\":" + lookup_block_hash_hex(receipt->block_number) + ",";
        r += "\"transactionIndex\":" + to_hex_quantity(static_cast<uint64_t>(receipt->tx_index)) + ",";
        r += "\"removed\":false";
        r += "}";
    }
    r += "],";
    r += "\"logsBloom\":" + compute_logs_bloom_hex(receipt->logs) + ",";
    r += "\"type\":\"0x0\",";
    r += "\"transactionIndex\":" + to_hex_quantity(static_cast<uint64_t>(receipt->tx_index)) + ",";
    r += "\"blockHash\":" + lookup_block_hash_hex(receipt->block_number);
    r += "}";

    return {make_result(id, r), false};
}

// Extract the string value after a JSON key, e.g. for "to":"0xabc..." returns "0xabc..."
// Returns empty string if key not found or value is null.
static std::string extract_json_string_value(const std::string& json, const std::string& key) {
    auto key_pos = json.find("\"" + key + "\"");
    if (key_pos == std::string::npos) return "";
    auto colon = json.find(':', key_pos + key.size() + 2);
    if (colon == std::string::npos) return "";
    // Skip whitespace
    size_t start = colon + 1;
    while (start < json.size() && (json[start] == ' ' || json[start] == '\t')) ++start;
    if (start >= json.size()) return "";
    // Check for null
    if (json.substr(start, 4) == "null") return "";
    // Find quoted string
    if (json[start] != '"') return "";
    size_t end = json.find('"', start + 1);
    if (end == std::string::npos) return "";
    return json.substr(start + 1, end - start - 1);
}

static uint64_t parse_hex_uint64(const std::string& hex_str) {
    if (hex_str.empty()) return 0;
    size_t start = 0;
    if (hex_str.size() >= 2 && hex_str[0] == '0' && (hex_str[1] == 'x' || hex_str[1] == 'X'))
        start = 2;
    return std::strtoull(hex_str.c_str() + start, nullptr, 16);
}

static intx::uint256 parse_hex_uint256(const std::string& hex_str) {
    if (hex_str.empty()) return 0;
    std::string hex = hex_str;
    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
        hex = hex.substr(2);
    if (hex.empty()) return 0;
    // Pad to 64 chars for intx parsing
    while (hex.size() < 64) hex = "0" + hex;
    return intx::from_string<intx::uint256>("0x" + hex);
}

// Parse "address" param: accepts single string or array of strings.
// Ethereum spec: "address": "0x..." OR "address": ["0x...", "0x..."]
static std::vector<evmc::address> parse_address_param(const std::string& params) {
    std::vector<evmc::address> result;
    auto key_pos = params.find("\"address\"");
    if (key_pos == std::string::npos) return result;
    auto colon = params.find(':', key_pos + 9);
    if (colon == std::string::npos) return result;
    size_t start = colon + 1;
    while (start < params.size() && (params[start] == ' ' || params[start] == '\t')) ++start;
    if (start >= params.size()) return result;

    if (params[start] == '"') {
        // Single address string
        evmc::address addr{};
        if (parse_hex_address(params.substr(start), addr)) {
            result.push_back(addr);
        }
    } else if (params[start] == '[') {
        // Array of addresses — scan for each 0x within the array
        size_t bracket_end = params.find(']', start);
        if (bracket_end == std::string::npos) return result;
        size_t pos = start + 1;
        while (pos < bracket_end) {
            auto hex_start = params.find("0x", pos);
            if (hex_start == std::string::npos || hex_start >= bracket_end) break;
            evmc::address addr{};
            if (parse_hex_address(params.substr(hex_start), addr)) {
                result.push_back(addr);
            }
            pos = hex_start + 42;  // skip past 0x + 40 hex chars
        }
    }
    return result;
}

// Parse a call object from JSON-RPC params:
//   [{"from":"0x...", "to":"0x...", "data":"0x...", "value":"0x...", "gas":"0x..."}, "latest"]
// All fields are optional per Ethereum spec.
static silkworm::Transaction parse_call_object(const std::string& params) {
    silkworm::Transaction txn;
    txn.type = silkworm::TransactionType::kLegacy;
    txn.chain_id = kEvmChainId;
    txn.gas_limit = 10'000'000;  // default high gas limit for eth_call
    txn.max_fee_per_gas = 0;
    txn.max_priority_fee_per_gas = 0;

    // Parse "from" (optional — zero address if missing)
    std::string from_hex = extract_json_string_value(params, "from");
    evmc::address from_addr{};
    if (!from_hex.empty()) {
        parse_hex_address(from_hex, from_addr);
    }
    txn.set_sender(from_addr);

    // Parse "to" (optional — nullopt means CREATE)
    std::string to_hex = extract_json_string_value(params, "to");
    if (!to_hex.empty()) {
        evmc::address to_addr{};
        if (parse_hex_address(to_hex, to_addr)) {
            txn.to = to_addr;
        }
    }

    // Parse "data" or "input" (optional)
    std::string data_hex = extract_json_string_value(params, "data");
    if (data_hex.empty()) {
        data_hex = extract_json_string_value(params, "input");
    }
    if (!data_hex.empty()) {
        parse_hex_bytes(data_hex, txn.data);
    }

    // Parse "value" (optional — 0 if missing)
    std::string value_hex = extract_json_string_value(params, "value");
    if (!value_hex.empty()) {
        txn.value = parse_hex_uint256(value_hex);
    }

    // Parse "gas" or "gasLimit" (optional)
    std::string gas_hex = extract_json_string_value(params, "gas");
    if (gas_hex.empty()) {
        gas_hex = extract_json_string_value(params, "gasLimit");
    }
    if (!gas_hex.empty()) {
        txn.gas_limit = parse_hex_uint64(gas_hex);
    }

    // Parse "gasPrice" / "maxFeePerGas" (optional)
    std::string gp_hex = extract_json_string_value(params, "gasPrice");
    if (gp_hex.empty()) gp_hex = extract_json_string_value(params, "maxFeePerGas");
    if (!gp_hex.empty()) {
        txn.max_fee_per_gas = parse_hex_uint256(gp_hex);
    }

    return txn;
}

static RpcResult handle_call(const std::string& params, const std::string& id) {
    auto txn = parse_call_object(params);

    // For eth_call, gas price should be 0 (no balance needed for simulation).
    txn.max_fee_per_gas = 0;
    txn.max_priority_fee_per_gas = 0;

    uint8_t rand_seed[32] = {};
    auto block = make_evm_block(
        global_evm_state().block_number(),
        static_cast<uint64_t>(std::time(nullptr)),
        rand_seed);
    const auto& config = evm_chain_config();

    auto result = call_evm_transaction(txn, block, global_evm_state(), config);

    if (!result.success) {
        // Return revert data in the error response (EIP-3668 compatible)
        std::string revert_hex = to_hex_data(result.return_data.data(), result.return_data.size());
        std::string err_body = "{\"jsonrpc\":\"2.0\",\"id\":" + id +
            ",\"error\":{\"code\":3,\"message\":\"execution reverted\"" +
            ",\"data\":" + revert_hex + "}}";
        return {err_body, true};
    }

    return {make_result(id, to_hex_data(result.return_data.data(), result.return_data.size())), false};
}

static RpcResult handle_estimate_gas(const std::string& params, const std::string& id) {
    auto txn = parse_call_object(params);

    // For estimation, gas price = 0 so no balance requirement.
    txn.max_fee_per_gas = 0;
    txn.max_priority_fee_per_gas = 0;
    // Use a generous gas limit if not specified.
    if (txn.gas_limit == 10'000'000) {
        txn.gas_limit = 30'000'000;
    }

    uint8_t rand_seed[32] = {};
    auto block = make_evm_block(
        global_evm_state().block_number(),
        static_cast<uint64_t>(std::time(nullptr)),
        rand_seed);
    const auto& config = evm_chain_config();

    auto result = call_evm_transaction(txn, block, global_evm_state(), config);

    if (!result.success) {
        std::string revert_hex = to_hex_data(result.return_data.data(), result.return_data.size());
        std::string err_body = "{\"jsonrpc\":\"2.0\",\"id\":" + id +
            ",\"error\":{\"code\":3,\"message\":\"execution reverted\"" +
            ",\"data\":" + revert_hex + "}}";
        return {err_body, true};
    }

    // Add 10% buffer for safety
    uint64_t estimated = result.gas_used + result.gas_used / 10;
    if (estimated < 21000) estimated = 21000;

    return {make_result(id, to_hex_quantity(estimated)), false};
}

// --- Additional methods for wallet/dApp compatibility ---

static RpcResult handle_accounts(const std::string& id) {
    // No server-side accounts — wallets manage their own keys.
    return {make_result(id, "[]"), false};
}

static RpcResult handle_client_version(const std::string& id) {
    return {make_result(id, "\"evm-workchain/0.1.0\""), false};
}

static std::string format_block_json(const StoredBlock& blk, bool full_transactions = false) {
    std::string r = "{";
    r += "\"number\":" + to_hex_quantity(blk.number) + ",";
    r += "\"hash\":" + to_hex_data(blk.hash.bytes, 32) + ",";
    r += "\"parentHash\":" + to_hex_data(blk.parent_hash.bytes, 32) + ",";
    r += "\"timestamp\":" + to_hex_quantity(blk.timestamp) + ",";
    r += "\"gasLimit\":" + to_hex_quantity(blk.gas_limit) + ",";
    r += "\"gasUsed\":" + to_hex_quantity(blk.gas_used) + ",";
    r += "\"miner\":" + to_hex_addr(blk.miner) + ",";
    r += "\"baseFeePerGas\":" + to_hex_quantity(blk.base_fee_per_gas) + ",";
    r += "\"nonce\":\"0x0000000000000000\",";
    r += "\"difficulty\":\"0x0\",";
    r += "\"totalDifficulty\":\"0x0\",";
    r += "\"extraData\":\"0x\",";
    r += "\"size\":\"0x0\",";
    r += "\"mixHash\":\"0x" + std::string(64, '0') + "\",";
    r += "\"stateRoot\":\"0x" + std::string(64, '0') + "\",";
    r += "\"transactionsRoot\":" + to_hex_data(blk.transactions_root.bytes, 32) + ",";
    r += "\"receiptsRoot\":" + to_hex_data(blk.receipts_root.bytes, 32) + ",";
    r += "\"logsBloom\":" + to_hex_data(blk.logs_bloom, 256) + ",";
    r += "\"sha3Uncles\":\"0x" + std::string(64, '0') + "\",";
    r += "\"uncles\":[],";
    r += "\"transactions\":[";
    for (size_t i = 0; i < blk.transaction_hashes.size(); ++i) {
        if (i > 0) r += ",";
        const auto& th = blk.transaction_hashes[i];
        if (full_transactions) {
            auto tx = global_evm_state().get_transaction_copy(th);
            if (tx) {
                r += "{\"hash\":" + to_hex_data(th.bytes, 32) + ",";
                r += "\"from\":" + to_hex_addr(tx->from) + ",";
                r += tx->to ? "\"to\":" + to_hex_addr(*tx->to) + "," : "\"to\":null,";
                r += "\"value\":" + to_hex_quantity(tx->value) + ",";
                r += "\"input\":" + to_hex_data(tx->data.data(), tx->data.size()) + ",";
                r += "\"nonce\":" + to_hex_quantity(tx->nonce) + ",";
                r += "\"gas\":" + to_hex_quantity(tx->gas_limit) + ",";
                r += "\"gasPrice\":" + to_hex_quantity(tx->gas_price) + ",";
                r += "\"blockNumber\":" + to_hex_quantity(blk.number) + ",";
                r += "\"blockHash\":" + to_hex_data(blk.hash.bytes, 32) + ",";
                r += "\"transactionIndex\":" + to_hex_quantity(static_cast<uint64_t>(i)) + ",";
                r += "\"type\":\"0x0\",\"v\":\"0x0\",\"r\":\"0x0\",\"s\":\"0x0\"}";
            } else {
                r += to_hex_data(th.bytes, 32);
            }
        } else {
            r += to_hex_data(th.bytes, 32);
        }
    }
    r += "]}";
    return r;
}

static std::string format_empty_block_json(uint64_t bn) {
    StoredBlock blk;
    blk.number = bn;
    blk.timestamp = static_cast<uint64_t>(std::time(nullptr));
    return format_block_json(blk);
}

static RpcResult handle_get_block_by_number(const std::string& params, const std::string& id) {
    uint64_t bn = global_evm_state().block_number();
    bool full_transactions = false;

    // Parse block number from params
    std::string bn_str = extract_json_string_value(params, "");
    if (bn_str.empty()) {
        // Try array format: ["0x1", false]
        auto pos = params.find("0x");
        if (pos != std::string::npos) {
            auto end = params.find_first_of("\",]}", pos);
            bn_str = params.substr(pos, end - pos);
        }
    }
    if (!bn_str.empty() && bn_str != "latest" && bn_str != "pending" &&
        bn_str != "safe" && bn_str != "finalized") {
        if (bn_str == "earliest") bn = 0;
        else bn = parse_hex_uint64(bn_str);
    }
    // Parse fullTransactions boolean (second param)
    if (params.find("true") != std::string::npos) {
        full_transactions = true;
    }

    auto blk = global_evm_state().get_block_copy(bn);
    if (global_evm_state().has_block(bn)) {
        return {make_result(id, format_block_json(blk, full_transactions)), false};
    }
    return {make_result(id, format_empty_block_json(bn)), false};
}

static RpcResult handle_get_logs(const std::string& params, const std::string& id) {
    // Parse filter: {"fromBlock":"0x1","toBlock":"latest","address":"0x...","topics":[...]}
    uint64_t from_block = 0;
    uint64_t to_block = global_evm_state().block_number();
    std::vector<evmc::address> addresses;
    std::vector<std::vector<evmc::bytes32>> topics;

    // Parse fromBlock
    std::string fb_hex = extract_json_string_value(params, "fromBlock");
    if (!fb_hex.empty() && fb_hex != "latest" && fb_hex != "pending" && fb_hex != "earliest") {
        from_block = parse_hex_uint64(fb_hex);
    }
    // Parse toBlock
    std::string tb_hex = extract_json_string_value(params, "toBlock");
    if (!tb_hex.empty() && tb_hex != "latest" && tb_hex != "pending") {
        if (tb_hex == "earliest") to_block = 0;
        else to_block = parse_hex_uint64(tb_hex);
    }
    // Parse address (single string or array of strings)
    addresses = parse_address_param(params);

    // Parse topics
    topics = parse_topics_array(params);

    // Query logs
    auto logs = global_evm_state().get_logs(from_block, to_block, addresses, topics);

    // Build JSON array
    std::string arr = "[";
    for (size_t i = 0; i < logs.size(); ++i) {
        if (i > 0) arr += ",";
        const auto& il = logs[i];
        arr += "{\"address\":" + to_hex_addr(il.log.address) + ",";
        arr += "\"topics\":[";
        for (size_t j = 0; j < il.log.topics.size(); ++j) {
            if (j > 0) arr += ",";
            arr += to_hex_data(il.log.topics[j].bytes, 32);
        }
        arr += "],";
        arr += "\"data\":" + to_hex_data(il.log.data.data(), il.log.data.size()) + ",";
        arr += "\"blockNumber\":" + to_hex_quantity(il.block_number) + ",";
        arr += "\"transactionHash\":" + to_hex_data(il.tx_hash.bytes, 32) + ",";
        arr += "\"logIndex\":" + to_hex_quantity(static_cast<uint64_t>(il.log_index)) + ",";
        arr += "\"blockHash\":" + lookup_block_hash_hex(il.block_number) + ",";
        arr += "\"transactionIndex\":" + to_hex_quantity(static_cast<uint64_t>(il.tx_index)) + ",";
        arr += "\"removed\":false}";
    }
    arr += "]";
    return {make_result(id, arr), false};
}

static RpcResult handle_get_transaction_by_hash(const std::string& params, const std::string& id) {
    silkworm::Bytes hash_bytes;
    if (!parse_hex_bytes(params, hash_bytes) || hash_bytes.size() != 32) {
        return {make_error(id, -32602, "invalid transaction hash"), true};
    }
    evmc::bytes32 tx_hash;
    std::memcpy(tx_hash.bytes, hash_bytes.data(), 32);

    auto tx = global_evm_state().get_transaction_copy(tx_hash);
    if (!tx) {
        return {make_result(id, "null"), false};
    }

    std::string r = "{";
    r += "\"hash\":" + to_hex_data(tx_hash.bytes, 32) + ",";
    r += "\"from\":" + to_hex_addr(tx->from) + ",";
    if (tx->to) {
        r += "\"to\":" + to_hex_addr(*tx->to) + ",";
    } else {
        r += "\"to\":null,";
    }
    r += "\"value\":" + to_hex_quantity(tx->value) + ",";
    r += "\"input\":" + to_hex_data(tx->data.data(), tx->data.size()) + ",";
    r += "\"nonce\":" + to_hex_quantity(tx->nonce) + ",";
    r += "\"gas\":" + to_hex_quantity(tx->gas_limit) + ",";
    r += "\"gasPrice\":" + to_hex_quantity(tx->gas_price) + ",";
    r += "\"blockNumber\":" + to_hex_quantity(tx->block_number) + ",";
    r += "\"blockHash\":" + lookup_block_hash_hex(tx->block_number) + ",";
    r += "\"transactionIndex\":" + to_hex_quantity(static_cast<uint64_t>(tx->tx_index)) + ",";
    r += "\"type\":\"0x0\",";
    r += "\"v\":\"0x0\",\"r\":\"0x0\",\"s\":\"0x0\"";
    r += "}";

    return {make_result(id, r), false};
}

// --- Ethereum opcode names (subset for trace output) ---
static const char* opcode_name(uint8_t op) {
    static const char* names[256] = {};
    static bool init = false;
    if (!init) {
        for (int i = 0; i < 256; i++) names[i] = "UNKNOWN";
        names[0x00]="STOP"; names[0x01]="ADD"; names[0x02]="MUL"; names[0x03]="SUB";
        names[0x04]="DIV"; names[0x05]="SDIV"; names[0x06]="MOD"; names[0x07]="SMOD";
        names[0x08]="ADDMOD"; names[0x09]="MULMOD"; names[0x0a]="EXP"; names[0x0b]="SIGNEXTEND";
        names[0x10]="LT"; names[0x11]="GT"; names[0x12]="SLT"; names[0x13]="SGT";
        names[0x14]="EQ"; names[0x15]="ISZERO"; names[0x16]="AND"; names[0x17]="OR";
        names[0x18]="XOR"; names[0x19]="NOT"; names[0x1a]="BYTE"; names[0x1b]="SHL";
        names[0x1c]="SHR"; names[0x1d]="SAR";
        names[0x20]="KECCAK256";
        names[0x30]="ADDRESS"; names[0x31]="BALANCE"; names[0x32]="ORIGIN";
        names[0x33]="CALLER"; names[0x34]="CALLVALUE"; names[0x35]="CALLDATALOAD";
        names[0x36]="CALLDATASIZE"; names[0x37]="CALLDATACOPY"; names[0x38]="CODESIZE";
        names[0x39]="CODECOPY"; names[0x3a]="GASPRICE"; names[0x3b]="EXTCODESIZE";
        names[0x3d]="RETURNDATASIZE"; names[0x3e]="RETURNDATACOPY";
        names[0x40]="BLOCKHASH"; names[0x41]="COINBASE"; names[0x42]="TIMESTAMP";
        names[0x43]="NUMBER"; names[0x44]="DIFFICULTY"; names[0x45]="GASLIMIT";
        names[0x46]="CHAINID"; names[0x47]="SELFBALANCE"; names[0x48]="BASEFEE";
        names[0x50]="POP"; names[0x51]="MLOAD"; names[0x52]="MSTORE"; names[0x53]="MSTORE8";
        names[0x54]="SLOAD"; names[0x55]="SSTORE"; names[0x56]="JUMP"; names[0x57]="JUMPI";
        names[0x58]="PC"; names[0x59]="MSIZE"; names[0x5a]="GAS"; names[0x5b]="JUMPDEST";
        names[0x5f]="PUSH0";
        for (int i = 0; i < 32; i++) { static char buf[33][8]; snprintf(buf[i], 8, "PUSH%d", i+1); names[0x60+i] = buf[i]; }
        for (int i = 0; i < 16; i++) { static char buf[16][8]; snprintf(buf[i], 8, "DUP%d", i+1); names[0x80+i] = buf[i]; }
        for (int i = 0; i < 16; i++) { static char buf[16][8]; snprintf(buf[i], 8, "SWAP%d", i+1); names[0x90+i] = buf[i]; }
        for (int i = 0; i < 5; i++) { static char buf[5][8]; snprintf(buf[i], 8, "LOG%d", i); names[0xa0+i] = buf[i]; }
        names[0xf0]="CREATE"; names[0xf1]="CALL"; names[0xf2]="CALLCODE";
        names[0xf3]="RETURN"; names[0xf4]="DELEGATECALL"; names[0xf5]="CREATE2";
        names[0xfa]="STATICCALL"; names[0xfd]="REVERT"; names[0xfe]="INVALID"; names[0xff]="SELFDESTRUCT";
        init = true;
    }
    return names[op];
}

static RpcResult handle_debug_trace_transaction(const std::string& params, const std::string& id) {
    // Parse tx hash
    silkworm::Bytes hash_bytes;
    if (!parse_hex_bytes(params, hash_bytes) || hash_bytes.size() != 32) {
        return {make_error(id, -32602, "invalid transaction hash"), true};
    }
    evmc::bytes32 tx_hash;
    std::memcpy(tx_hash.bytes, hash_bytes.data(), 32);

    // Look up the stored transaction to re-execute with tracing
    auto stored_tx = global_evm_state().get_transaction_copy(tx_hash);
    if (!stored_tx) {
        return {make_error(id, -32000, "transaction not found"), true};
    }

    // Reconstruct the transaction
    silkworm::Transaction txn;
    txn.type = silkworm::TransactionType::kLegacy;
    txn.chain_id = kEvmChainId;
    txn.nonce = stored_tx->nonce;
    txn.max_fee_per_gas = stored_tx->gas_price;
    txn.max_priority_fee_per_gas = stored_tx->gas_price;
    txn.gas_limit = stored_tx->gas_limit;
    txn.to = stored_tx->to;
    txn.value = stored_tx->value;
    txn.data = stored_tx->data;
    txn.set_sender(stored_tx->from);

    uint8_t rs[32] = {};
    auto block = make_evm_block(stored_tx->block_number, 0, rs);
    auto trace = trace_evm_transaction(txn, block, global_evm_state(), evm_chain_config());

    // Build the structLogs JSON
    std::string logs = "[";
    for (size_t i = 0; i < trace.steps.size(); ++i) {
        if (i > 0) logs += ",";
        const auto& s = trace.steps[i];
        logs += "{\"pc\":" + std::to_string(s.pc);
        logs += ",\"op\":\"" + std::string(opcode_name(s.op)) + "\"";
        logs += ",\"gas\":" + std::to_string(s.gas);
        logs += ",\"gasCost\":" + std::to_string(s.gas_cost);
        logs += ",\"depth\":" + std::to_string(s.depth);
        logs += ",\"stack\":[";
        for (size_t j = 0; j < s.stack.size(); ++j) {
            if (j > 0) logs += ",";
            logs += "\"" + intx::hex(s.stack[j]) + "\"";
        }
        logs += "]}";
    }
    logs += "]";

    std::string result = "{\"gas\":" + std::to_string(trace.gas_used) +
        ",\"failed\":" + (trace.success ? "false" : "true") +
        ",\"returnValue\":" + to_hex_data(trace.return_data.data(), trace.return_data.size()) +
        ",\"structLogs\":" + logs + "}";

    return {make_result(id, result), false};
}

static RpcResult handle_eth_subscribe(const std::string& params, const std::string& id) {
    // Parse subscription type: ["newHeads"], ["logs", {filter}], ["newPendingTransactions"]
    std::string type_str;
    auto pos = params.find("\"newHeads\"");
    if (pos != std::string::npos) type_str = "newHeads";
    if (type_str.empty()) {
        pos = params.find("\"logs\"");
        if (pos != std::string::npos) type_str = "logs";
    }
    if (type_str.empty()) {
        pos = params.find("\"newPendingTransactions\"");
        if (pos != std::string::npos) type_str = "newPendingTransactions";
    }
    if (type_str.empty()) {
        return {make_error(id, -32602, "invalid subscription type"), true};
    }

    SubscriptionType type;
    LogSubscriptionFilter filter;
    if (type_str == "newHeads") {
        type = SubscriptionType::NewHeads;
    } else if (type_str == "logs") {
        type = SubscriptionType::Logs;
        // Parse optional address filter (single or array)
        filter.addresses = parse_address_param(params);
        // Parse optional topics filter
        filter.topics = parse_topics_array(params);
    } else {
        type = SubscriptionType::NewPendingTransactions;
    }

    uint64_t sub_id = global_subscription_manager().subscribe(type, filter);
    return {make_result(id, to_hex_quantity(sub_id)), false};
}

static RpcResult handle_eth_unsubscribe(const std::string& params, const std::string& id) {
    // Parse subscription ID
    uint64_t sub_id = 0;
    auto pos = params.find("0x");
    if (pos != std::string::npos) {
        sub_id = std::strtoull(params.c_str() + pos + 2, nullptr, 16);
    }
    bool ok = global_subscription_manager().unsubscribe(sub_id);
    return {make_result(id, ok ? "true" : "false"), false};
}

static RpcResult handle_eth_get_subscription(const std::string& params, const std::string& id) {
    // Custom method: poll subscription events (for HTTP clients without WebSocket)
    uint64_t sub_id = 0;
    auto pos = params.find("0x");
    if (pos != std::string::npos) {
        sub_id = std::strtoull(params.c_str() + pos + 2, nullptr, 16);
    }
    auto events = global_subscription_manager().poll(sub_id);
    std::string arr = "[";
    for (size_t i = 0; i < events.size(); ++i) {
        if (i > 0) arr += ",";
        arr += events[i].json;
    }
    arr += "]";
    return {make_result(id, arr), false};
}

static RpcResult handle_get_block_receipts(const std::string& params, const std::string& id) {
    // Parse block number
    uint64_t bn = global_evm_state().block_number();
    auto pos = params.find("0x");
    if (pos != std::string::npos) {
        auto end = params.find_first_of("\",]}", pos);
        std::string bn_str = params.substr(pos, end - pos);
        if (bn_str != "latest" && bn_str != "pending") {
            bn = parse_hex_uint64(bn_str);
        }
    }

    // Get the block to find its transaction hashes
    auto blk = global_evm_state().get_block_copy(bn);
    if (!global_evm_state().has_block(bn)) {
        return {make_result(id, "[]"), false};
    }

    // Build receipts array
    std::string arr = "[";
    for (size_t i = 0; i < blk.transaction_hashes.size(); ++i) {
        if (i > 0) arr += ",";
        const auto& tx_hash = blk.transaction_hashes[i];
        auto receipt = global_evm_state().get_receipt_copy(tx_hash);
        if (!receipt) continue;

        arr += "{";
        arr += "\"transactionHash\":" + to_hex_data(tx_hash.bytes, 32) + ",";
        arr += "\"blockNumber\":" + to_hex_quantity(receipt->block_number) + ",";
        arr += "\"from\":" + to_hex_addr(receipt->from) + ",";
        arr += receipt->to ? "\"to\":" + to_hex_addr(*receipt->to) + "," : "\"to\":null,";
        arr += receipt->contract_address ? "\"contractAddress\":" + to_hex_addr(*receipt->contract_address) + "," : "\"contractAddress\":null,";
        arr += "\"gasUsed\":" + to_hex_quantity(receipt->gas_used) + ",";
        arr += "\"cumulativeGasUsed\":" + to_hex_quantity(receipt->cumulative_gas_used) + ",";
        arr += "\"status\":" + to_hex_quantity(receipt->success ? uint64_t{1} : uint64_t{0}) + ",";
        arr += "\"logsBloom\":" + compute_logs_bloom_hex(receipt->logs) + ",";
        arr += "\"logs\":[";
        for (size_t li = 0; li < receipt->logs.size(); ++li) {
            if (li > 0) arr += ",";
            const auto& log = receipt->logs[li];
            arr += "{\"address\":" + to_hex_addr(log.address) + ",";
            arr += "\"topics\":[";
            for (size_t j = 0; j < log.topics.size(); ++j) {
                if (j > 0) arr += ",";
                arr += to_hex_data(log.topics[j].bytes, 32);
            }
            arr += "],";
            arr += "\"data\":" + to_hex_data(log.data.data(), log.data.size()) + ",";
            arr += "\"logIndex\":" + to_hex_quantity(static_cast<uint64_t>(li)) + ",";
            arr += "\"blockNumber\":" + to_hex_quantity(receipt->block_number) + ",";
            arr += "\"transactionHash\":" + to_hex_data(tx_hash.bytes, 32) + ",";
            arr += "\"blockHash\":" + to_hex_data(blk.hash.bytes, 32) + ",";
            arr += "\"transactionIndex\":" + to_hex_quantity(static_cast<uint64_t>(i)) + ",";
            arr += "\"removed\":false}";
        }
        arr += "],";
        arr += "\"transactionIndex\":" + to_hex_quantity(static_cast<uint64_t>(i)) + ",";
        arr += "\"blockHash\":" + to_hex_data(blk.hash.bytes, 32) + ",";
        arr += "\"type\":\"0x0\"";
        arr += "}";
    }
    arr += "]";
    return {make_result(id, arr), false};
}

static RpcResult handle_mining(const std::string& id) {
    return {make_result(id, "false"), false};
}

static RpcResult handle_syncing(const std::string& id) {
    return {make_result(id, "false"), false};
}

// --- MetaMask-required methods ---

static RpcResult handle_get_storage_at(const std::string& params, const std::string& id) {
    // params: [address, slot, block]
    evmc::address addr{};
    if (!parse_hex_address(params, addr)) {
        return {make_error(id, -32602, "invalid address parameter"), true};
    }

    // Parse storage slot (second hex param after the address)
    evmc::bytes32 slot{};
    auto second_0x = params.find("0x", params.find("0x") + 1);
    if (second_0x != std::string::npos) {
        silkworm::Bytes slot_bytes;
        if (parse_hex_bytes(params.substr(second_0x - 1), slot_bytes) && slot_bytes.size() <= 32) {
            // Left-pad to 32 bytes
            size_t offset = 32 - slot_bytes.size();
            std::memcpy(slot.bytes + offset, slot_bytes.data(), slot_bytes.size());
        }
    }

    auto acct = global_evm_state().read_account(addr);
    if (!acct) {
        return {make_result(id, "\"0x" + std::string(64, '0') + "\""), false};
    }
    auto value = global_evm_state().read_storage_copy(addr, acct->incarnation, slot);
    return {make_result(id, to_hex_data(value.bytes, 32)), false};
}

static RpcResult handle_fee_history(const std::string& params, const std::string& id) {
    // Parse block count from params: [blockCount, newestBlock, rewardPercentiles]
    uint64_t block_count = 1;
    auto pos = params.find("0x");
    if (pos != std::string::npos) {
        block_count = std::max(uint64_t{1}, parse_hex_uint64(params.substr(pos)));
    }
    if (block_count > 1024) block_count = 1024;

    uint64_t newest = global_evm_state().block_number();
    uint64_t oldest = newest >= block_count ? newest - block_count + 1 : 0;

    std::string base_fees = "[";
    std::string gas_ratios = "[";
    std::string rewards = "[";

    for (uint64_t i = oldest; i <= newest; ++i) {
        if (i > oldest) { gas_ratios += ","; rewards += ","; }
        if (i > oldest) base_fees += ",";

        auto blk = global_evm_state().get_block_copy(i);
        if (global_evm_state().has_block(i)) {
            base_fees += to_hex_quantity(blk.base_fee_per_gas);
            double ratio = blk.gas_limit > 0
                ? static_cast<double>(blk.gas_used) / blk.gas_limit : 0.0;
            char ratio_buf[32];
            snprintf(ratio_buf, sizeof(ratio_buf), "%.6f", ratio);
            gas_ratios += ratio_buf;
        } else {
            base_fees += to_hex_quantity(intx::uint256{kInitialBaseFee});
            gas_ratios += "0";
        }
        rewards += "[\"0x0\"]";
    }
    // One extra base fee for the next block
    auto last_blk = global_evm_state().get_block_copy(newest);
    intx::uint256 next_base_fee{kInitialBaseFee};
    if (global_evm_state().has_block(newest)) {
        next_base_fee = calc_base_fee(last_blk.base_fee_per_gas,
                                       last_blk.gas_used, last_blk.gas_limit);
    }
    base_fees += "," + to_hex_quantity(next_base_fee);
    base_fees += "]";
    gas_ratios += "]";
    rewards += "]";

    std::string r = "{";
    r += "\"oldestBlock\":" + to_hex_quantity(oldest) + ",";
    r += "\"baseFeePerGas\":" + base_fees + ",";
    r += "\"gasUsedRatio\":" + gas_ratios + ",";
    r += "\"reward\":" + rewards;
    r += "}";
    return {make_result(id, r), false};
}

static RpcResult handle_max_priority_fee(const std::string& id) {
    // Return 1 gwei as the suggested priority fee
    return {make_result(id, to_hex_quantity(uint64_t{1'000'000'000})), false};
}

static RpcResult handle_get_block_by_hash(const std::string& params, const std::string& id) {
    silkworm::Bytes hash_bytes;
    if (!parse_hex_bytes(params, hash_bytes) || hash_bytes.size() != 32) {
        return {make_result(id, "null"), false};
    }
    evmc::bytes32 block_hash;
    std::memcpy(block_hash.bytes, hash_bytes.data(), 32);

    bool full_transactions = (params.find("true") != std::string::npos);

    auto blk = global_evm_state().get_block_by_hash_copy(block_hash);
    if (blk.number != 0 || blk.hash != evmc::bytes32{}) {
        return {make_result(id, format_block_json(blk, full_transactions)), false};
    }
    return {make_result(id, "null"), false};
}

// --- Filter storage (bounded, with expiry) ---
// Pattern: ~/s/silkworm/rpc/core/filter_storage.hpp
// - max_filters: reject new filters when full
// - max_age: expire idle filters
// - mutex: thread-safe

// --- Filter storage (bounded, with expiry, stores criteria, returns real changes) ---
// Pattern: ~/s/silkworm/rpc/core/filter_storage.hpp

enum class FilterType { Logs, Blocks, PendingTx };

struct FilterEntry {
    FilterType type{FilterType::Logs};
    uint64_t last_polled_block{0};
    uint64_t created_at{0};
    uint64_t last_access{0};
    // Log filter criteria (only for FilterType::Logs)
    std::vector<evmc::address> addresses;
    std::vector<std::vector<evmc::bytes32>> topics;
};

static constexpr size_t kMaxFilters = 1024;
static constexpr uint64_t kMaxFilterAgeSec = 900;  // 15 minutes

static std::mutex g_filter_mutex;
static uint64_t g_next_filter_id = 1;
static std::unordered_map<uint64_t, FilterEntry> g_filters;

void reset_evm_rpc_filter_state_for_test() {
    std::lock_guard<std::mutex> lock(g_filter_mutex);
    g_next_filter_id = 1;
    g_filters.clear();
}

static void cleanup_expired_filters() {
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    for (auto it = g_filters.begin(); it != g_filters.end(); ) {
        if (now - it->second.last_access > kMaxFilterAgeSec) {
            it = g_filters.erase(it);
        } else {
            ++it;
        }
    }
}

static uint64_t create_filter(FilterType type,
                               const std::vector<evmc::address>& addresses = {},
                               const std::vector<std::vector<evmc::bytes32>>& topics = {}) {
    std::lock_guard<std::mutex> lock(g_filter_mutex);
    cleanup_expired_filters();
    if (g_filters.size() >= kMaxFilters) return 0;
    uint64_t fid = g_next_filter_id++;
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    FilterEntry entry;
    entry.type = type;
    entry.last_polled_block = global_evm_state().block_number();
    entry.created_at = now;
    entry.last_access = now;
    entry.addresses = addresses;
    entry.topics = topics;
    g_filters[fid] = std::move(entry);
    return fid;
}

// Parse topics array from JSON: [["0xddf2..."], null, ["0x00...","0x01..."]]
static std::vector<std::vector<evmc::bytes32>> parse_topics_array(const std::string& params) {
    std::vector<std::vector<evmc::bytes32>> result;
    auto pos = params.find("\"topics\"");
    if (pos == std::string::npos) return result;
    auto arr_start = params.find('[', pos + 8);
    if (arr_start == std::string::npos) return result;
    // Simple parser: find each "0x..." within the topics array
    size_t depth = 0;
    size_t i = arr_start;
    std::vector<evmc::bytes32> current_set;
    bool in_sub_array = false;
    while (i < params.size()) {
        if (params[i] == '[') {
            depth++;
            if (depth == 2) { in_sub_array = true; current_set.clear(); }
        } else if (params[i] == ']') {
            if (depth == 2 && in_sub_array) {
                result.push_back(current_set);
                in_sub_array = false;
            }
            depth--;
            if (depth == 0) break;
        } else if (params[i] == 'n' && params.substr(i, 4) == "null" && depth == 1) {
            result.push_back({});  // null = match any
            i += 3;
        } else if (params[i] == '0' && i + 1 < params.size() && params[i+1] == 'x' &&
                   (in_sub_array || depth == 1)) {
            // Parse a 32-byte topic hash
            evmc::bytes32 topic{};
            silkworm::Bytes tb;
            if (parse_hex_bytes(params.substr(i - 1), tb) && tb.size() == 32) {
                std::memcpy(topic.bytes, tb.data(), 32);
                if (in_sub_array) {
                    current_set.push_back(topic);
                } else {
                    // Bare string at outer array level (most common eth_getLogs format)
                    result.push_back({topic});
                }
            }
            i += 65;  // skip past "0x" + 64 hex chars
            continue;
        }
        i++;
    }
    return result;
}

static RpcResult handle_new_filter(const std::string& params, const std::string& id) {
    // Parse filter criteria: {"fromBlock":"0x1","toBlock":"latest","address":"0x...","topics":[...]}
    auto addresses = parse_address_param(params);
    auto topics = parse_topics_array(params);

    uint64_t fid = create_filter(FilterType::Logs, addresses, topics);
    if (fid == 0) return {make_error(id, -32000, "too many filters"), true};
    return {make_result(id, to_hex_quantity(fid)), false};
}

static RpcResult handle_new_block_filter(const std::string& id) {
    uint64_t fid = create_filter(FilterType::Blocks);
    if (fid == 0) return {make_error(id, -32000, "too many filters"), true};
    return {make_result(id, to_hex_quantity(fid)), false};
}

static std::string format_log_json(const IndexedLog& il) {
    std::string r = "{\"address\":" + to_hex_addr(il.log.address) + ",";
    r += "\"topics\":[";
    for (size_t j = 0; j < il.log.topics.size(); ++j) {
        if (j > 0) r += ",";
        r += to_hex_data(il.log.topics[j].bytes, 32);
    }
    r += "],";
    r += "\"data\":" + to_hex_data(il.log.data.data(), il.log.data.size()) + ",";
    r += "\"blockNumber\":" + to_hex_quantity(il.block_number) + ",";
    r += "\"transactionHash\":" + to_hex_data(il.tx_hash.bytes, 32) + ",";
    r += "\"logIndex\":" + to_hex_quantity(static_cast<uint64_t>(il.log_index)) + ",";
    r += "\"blockHash\":" + lookup_block_hash_hex(il.block_number) + ",";
    r += "\"transactionIndex\":" + to_hex_quantity(static_cast<uint64_t>(il.tx_index)) + ",\"removed\":false}";
    return r;
}

static RpcResult handle_get_filter_changes(const std::string& params, const std::string& id) {
    uint64_t fid = parse_hex_uint64(extract_json_string_value(params, ""));
    if (fid == 0) {
        auto pos = params.find("0x");
        if (pos != std::string::npos)
            fid = std::strtoull(params.c_str() + pos + 2, nullptr, 16);
    }

    std::lock_guard<std::mutex> lock(g_filter_mutex);
    auto it = g_filters.find(fid);
    if (it == g_filters.end()) {
        return {make_error(id, -32000, "filter not found"), true};
    }
    auto& f = it->second;
    f.last_access = static_cast<uint64_t>(std::time(nullptr));

    uint64_t current_block = global_evm_state().block_number();
    uint64_t from_block = f.last_polled_block + 1;
    f.last_polled_block = current_block;

    if (from_block > current_block) {
        return {make_result(id, "[]"), false};
    }

    std::string arr = "[";
    if (f.type == FilterType::Logs) {
        auto logs = global_evm_state().get_logs(from_block, current_block,
                                                 f.addresses, f.topics);
        for (size_t i = 0; i < logs.size(); ++i) {
            if (i > 0) arr += ",";
            arr += format_log_json(logs[i]);
        }
    } else if (f.type == FilterType::Blocks) {
        // Return block hashes for new blocks
        for (uint64_t bn = from_block; bn <= current_block; ++bn) {
            auto hash = global_evm_state().get_block_hash(bn);
            bool is_zero = true;
            for (auto b : hash.bytes) { if (b != 0) { is_zero = false; break; } }
            if (!is_zero) {
                if (arr.size() > 1) arr += ",";
                arr += to_hex_data(hash.bytes, 32);
            }
        }
    } else if (f.type == FilterType::PendingTx) {
        // Pending tx filter: return empty (we execute immediately, no mempool)
    }
    arr += "]";
    return {make_result(id, arr), false};
}

static RpcResult handle_uninstall_filter(const std::string& params, const std::string& id) {
    uint64_t fid = 0;
    auto pos = params.find("0x");
    if (pos != std::string::npos)
        fid = std::strtoull(params.c_str() + pos + 2, nullptr, 16);
    std::lock_guard<std::mutex> lock(g_filter_mutex);
    bool removed = g_filters.erase(fid) > 0;
    return {make_result(id, removed ? "true" : "false"), false};
}

static RpcResult handle_new_pending_transaction_filter(const std::string& id) {
    uint64_t fid = create_filter(FilterType::PendingTx);
    if (fid == 0) return {make_error(id, -32000, "too many filters"), true};
    return {make_result(id, to_hex_quantity(fid)), false};
}

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

bool is_eth_rpc_method(const std::string& method) noexcept {
    return method == "eth_chainId" ||
           method == "eth_blockNumber" ||
           method == "eth_gasPrice" ||
           method == "eth_getBalance" ||
           method == "eth_getTransactionCount" ||
           method == "eth_getCode" ||
           method == "eth_getStorageAt" ||
           method == "eth_sendRawTransaction" ||
           method == "eth_getTransactionReceipt" ||
           method == "eth_getTransactionByHash" ||
           method == "eth_call" ||
           method == "eth_estimateGas" ||
           method == "eth_feeHistory" ||
           method == "eth_maxPriorityFeePerGas" ||
           method == "eth_accounts" ||
           method == "eth_getBlockByNumber" ||
           method == "eth_getBlockByHash" ||
           method == "eth_getLogs" ||
           method == "eth_newFilter" ||
           method == "eth_newBlockFilter" ||
           method == "eth_newPendingTransactionFilter" ||
           method == "eth_getFilterChanges" ||
           method == "eth_uninstallFilter" ||
           method == "eth_mining" ||
           method == "eth_syncing" ||
           method == "net_version" ||
           method == "net_listening" ||
           method == "net_peerCount" ||
           method == "web3_clientVersion" ||
           method == "debug_traceTransaction" ||
           method == "eth_getBlockReceipts" ||
           method == "eth_subscribe" ||
           method == "eth_unsubscribe" ||
           method == "eth_getSubscription";
}

std::optional<RpcResult> handle_eth_rpc(
    const std::string& method,
    const std::string& params,
    const std::string& id) {

    if (method == "eth_chainId")              return handle_chain_id(id);
    if (method == "net_version")              return handle_net_version(id);
    if (method == "net_listening")            return RpcResult{make_result(id, "true"), false};
    if (method == "net_peerCount")            return RpcResult{make_result(id, "\"0x0\""), false};
    if (method == "web3_clientVersion")       return handle_client_version(id);
    if (method == "eth_blockNumber")          return handle_block_number(id);
    if (method == "eth_gasPrice")             return handle_gas_price(id);
    if (method == "eth_maxPriorityFeePerGas") return handle_max_priority_fee(id);
    if (method == "eth_feeHistory")           return handle_fee_history(params, id);
    if (method == "eth_accounts")             return handle_accounts(id);
    if (method == "eth_mining")               return handle_mining(id);
    if (method == "eth_syncing")              return handle_syncing(id);
    if (method == "eth_getBalance")           return handle_get_balance(params, id);
    if (method == "eth_getTransactionCount")  return handle_get_transaction_count(params, id);
    if (method == "eth_getCode")              return handle_get_code(params, id);
    if (method == "eth_getStorageAt")         return handle_get_storage_at(params, id);
    if (method == "eth_getBlockByNumber")     return handle_get_block_by_number(params, id);
    if (method == "eth_getBlockByHash")       return handle_get_block_by_hash(params, id);
    if (method == "eth_getTransactionByHash") return handle_get_transaction_by_hash(params, id);
    if (method == "eth_getLogs")              return handle_get_logs(params, id);
    if (method == "eth_newFilter")            return handle_new_filter(params, id);
    if (method == "eth_newBlockFilter")       return handle_new_block_filter(id);
    if (method == "eth_newPendingTransactionFilter") return handle_new_pending_transaction_filter(id);
    if (method == "eth_getFilterChanges")     return handle_get_filter_changes(params, id);
    if (method == "eth_uninstallFilter")      return handle_uninstall_filter(params, id);
    if (method == "debug_traceTransaction")  return handle_debug_trace_transaction(params, id);
    if (method == "eth_getBlockReceipts")    return handle_get_block_receipts(params, id);
    if (method == "eth_subscribe")           return handle_eth_subscribe(params, id);
    if (method == "eth_unsubscribe")         return handle_eth_unsubscribe(params, id);
    if (method == "eth_getSubscription")     return handle_eth_get_subscription(params, id);
    if (method == "eth_sendRawTransaction")   return handle_send_raw_transaction(params, id);
    if (method == "eth_getTransactionReceipt") return handle_get_transaction_receipt(params, id);
    if (method == "eth_call")                 return handle_call(params, id);
    if (method == "eth_estimateGas")          return handle_estimate_gas(params, id);

    return std::nullopt;
}

}  // namespace evm_workchain
