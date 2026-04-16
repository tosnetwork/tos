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

#include <silkworm/core/common/util.hpp>
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
    // Simple fixed gas price: 1 gwei
    return {make_result(id, to_hex_quantity(uint64_t{1'000'000'000})), false};
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
    auto acct = global_evm_state().state().read_account(addr);
    if (!acct) {
        return {make_result(id, "\"0x\""), false};
    }
    auto code = global_evm_state().state().read_code(addr, acct->code_hash);
    if (code.empty()) {
        return {make_result(id, "\"0x\""), false};
    }
    return {make_result(id, to_hex_data(code.data(), code.size())), false};
}

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
    evm_state.increment_block_number();

    uint8_t rand_seed[32] = {};
    auto block = make_evm_block(
        evm_state.block_number(),
        static_cast<uint64_t>(std::time(nullptr)),
        rand_seed);
    const auto& config = evm_chain_config();

    auto exec_result = execute_evm_transaction(decoded.txn, block, evm_state, config);

    auto tx_hash = decoded.txn.hash();
    uint64_t bn = evm_state.block_number();

    // Store receipt
    StoredReceipt receipt;
    receipt.success = exec_result.success;
    receipt.gas_used = exec_result.gas_used;
    receipt.block_number = bn;
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

    // Store block hash for BLOCKHASH opcode
    // Use keccak of (block_number || timestamp) as a simple block hash
    evmc::bytes32 block_hash{};
    auto bn_bytes = intx::be::store<evmc::uint256be>(intx::uint256{bn});
    std::memcpy(block_hash.bytes, bn_bytes.bytes, 32);  // simplified: hash = padded block number
    evm_state.store_block_hash(bn, block_hash);

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

    const auto* receipt = global_evm_state().get_receipt(tx_hash);
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
    r += "\"cumulativeGasUsed\":" + to_hex_quantity(receipt->gas_used) + ",";
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
        r += "\"transactionHash\":" + to_hex_data(tx_hash.bytes, 32);
        r += "}";
    }
    r += "],";
    r += "\"logsBloom\":\"0x" + std::string(512, '0') + "\",";
    r += "\"type\":\"0x0\",";
    r += "\"transactionIndex\":\"0x0\",";
    r += "\"blockHash\":\"0x" + std::string(64, '0') + "\"";
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

    if (!result.success && !result.error_message.empty()) {
        return {make_error(id, 3, result.error_message), true};
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

static RpcResult handle_get_block_by_number(const std::string& /*params*/, const std::string& id) {
    auto bn = global_evm_state().block_number();
    // Minimal block object — enough for wallets to not error.
    std::string block_json = "{";
    block_json += "\"number\":" + to_hex_quantity(bn) + ",";
    block_json += "\"hash\":\"0x" + std::string(64, '0') + "\",";
    block_json += "\"parentHash\":\"0x" + std::string(64, '0') + "\",";
    block_json += "\"timestamp\":" + to_hex_quantity(static_cast<uint64_t>(std::time(nullptr))) + ",";
    block_json += "\"gasLimit\":" + to_hex_quantity(uint64_t{30000000}) + ",";
    block_json += "\"gasUsed\":" + to_hex_quantity(uint64_t{0}) + ",";
    block_json += "\"miner\":\"0x" + std::string(40, '0') + "\",";
    block_json += "\"baseFeePerGas\":" + to_hex_quantity(uint64_t{0}) + ",";
    block_json += "\"transactions\":[]";
    block_json += "}";
    return {make_result(id, block_json), false};
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
    // Parse address (single or array)
    std::string addr_hex = extract_json_string_value(params, "address");
    if (!addr_hex.empty()) {
        evmc::address addr{};
        if (parse_hex_address(addr_hex, addr)) {
            addresses.push_back(addr);
        }
    }

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
        arr += "\"blockHash\":\"0x" + std::string(64, '0') + "\",";
        arr += "\"transactionIndex\":\"0x0\",";
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

    const auto* tx = global_evm_state().get_transaction(tx_hash);
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
    r += "\"blockHash\":\"0x" + std::string(64, '0') + "\",";
    r += "\"transactionIndex\":" + to_hex_quantity(static_cast<uint64_t>(tx->tx_index)) + ",";
    r += "\"type\":\"0x0\",";
    r += "\"v\":\"0x0\",\"r\":\"0x0\",\"s\":\"0x0\"";
    r += "}";

    return {make_result(id, r), false};
}

static RpcResult handle_mining(const std::string& id) {
    return {make_result(id, "false"), false};
}

static RpcResult handle_syncing(const std::string& id) {
    return {make_result(id, "false"), false};
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
           method == "eth_sendRawTransaction" ||
           method == "eth_getTransactionReceipt" ||
           method == "eth_call" ||
           method == "eth_estimateGas" ||
           method == "eth_accounts" ||
           method == "eth_getBlockByNumber" ||
           method == "eth_getTransactionByHash" ||
           method == "eth_getLogs" ||
           method == "eth_mining" ||
           method == "eth_syncing" ||
           method == "net_version" ||
           method == "web3_clientVersion";
}

std::optional<RpcResult> handle_eth_rpc(
    const std::string& method,
    const std::string& params,
    const std::string& id) {

    if (method == "eth_chainId")              return handle_chain_id(id);
    if (method == "net_version")              return handle_net_version(id);
    if (method == "web3_clientVersion")       return handle_client_version(id);
    if (method == "eth_blockNumber")          return handle_block_number(id);
    if (method == "eth_gasPrice")             return handle_gas_price(id);
    if (method == "eth_accounts")             return handle_accounts(id);
    if (method == "eth_mining")               return handle_mining(id);
    if (method == "eth_syncing")              return handle_syncing(id);
    if (method == "eth_getBalance")           return handle_get_balance(params, id);
    if (method == "eth_getTransactionCount")  return handle_get_transaction_count(params, id);
    if (method == "eth_getCode")              return handle_get_code(params, id);
    if (method == "eth_getBlockByNumber")     return handle_get_block_by_number(params, id);
    if (method == "eth_getTransactionByHash") return handle_get_transaction_by_hash(params, id);
    if (method == "eth_getLogs")              return handle_get_logs(params, id);
    if (method == "eth_sendRawTransaction")   return handle_send_raw_transaction(params, id);
    if (method == "eth_getTransactionReceipt") return handle_get_transaction_receipt(params, id);
    if (method == "eth_call")                 return handle_call(params, id);
    if (method == "eth_estimateGas")          return handle_estimate_gas(params, id);

    return std::nullopt;
}

}  // namespace evm_workchain
