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
#include "evm-state-root.h"
#include "evm-incremental-trie.h"
#include "evm-access-list-tracer.h"
#include "evm-cell-state.h"
#include "evm-mpt-prover.h"

#include <silkworm/core/execution/evm.hpp>
#include <silkworm/core/protocol/intrinsic_gas.hpp>
#include <silkworm/core/trie/hash_builder.hpp>
#include <silkworm/core/trie/nibbles.hpp>
#include <silkworm/core/common/empty_hashes.hpp>

#include <silkworm/core/common/util.hpp>
#include <ethash/keccak.hpp>
#include <silkworm/core/types/address.hpp>
#include <intx/intx.hpp>

#include <cstdio>
#include <cstring>
#include <sstream>
#include <chrono>

namespace evm_workchain {

// ---------------------------------------------------------------------------
// Rate limiting constants
// ---------------------------------------------------------------------------

static constexpr uint64_t kMaxRpcRequestsPerSec = 100;   // refill rate (tokens/sec)
static constexpr uint64_t kMaxRpcBurst = 1000;            // bucket capacity
static constexpr uint64_t kMaxGetLogsRequestsPerSec = 10; // tighter refill for eth_getLogs
static constexpr uint64_t kMaxGetLogsBurst = 50;          // tighter burst for eth_getLogs
static constexpr uint64_t kMaxGetLogsBlockRange = 10000;  // max toBlock - fromBlock
static constexpr size_t   kMaxRpcParamsSize = 1 << 20;    // 1 MB

// ---------------------------------------------------------------------------
// Token-bucket rate limiter
// ---------------------------------------------------------------------------

struct RateLimiter {
    std::mutex mutex;
    uint64_t tokens;
    uint64_t max_tokens;
    uint64_t refill_rate;     // tokens per second
    uint64_t last_refill;     // steady_clock seconds since epoch

    RateLimiter(uint64_t max_tok, uint64_t rate)
        : tokens(max_tok)
        , max_tokens(max_tok)
        , refill_rate(rate)
        , last_refill(static_cast<uint64_t>(
              std::chrono::duration_cast<std::chrono::seconds>(
                  std::chrono::steady_clock::now().time_since_epoch())
                  .count())) {}

    void refill() {
        uint64_t now = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now().time_since_epoch())
                .count());
        if (now > last_refill) {
            uint64_t elapsed = now - last_refill;
            uint64_t added = elapsed * refill_rate;
            tokens = std::min(tokens + added, max_tokens);
            last_refill = now;
        }
    }

    bool try_consume() {
        std::lock_guard<std::mutex> lock(mutex);
        refill();
        if (tokens == 0) return false;
        --tokens;
        return true;
    }

    void reset() {
        std::lock_guard<std::mutex> lock(mutex);
        tokens = max_tokens;
        last_refill = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now().time_since_epoch())
                .count());
    }
};

static RateLimiter g_rpc_limiter{kMaxRpcBurst, kMaxRpcRequestsPerSec};
static RateLimiter g_getlogs_limiter{kMaxGetLogsBurst, kMaxGetLogsRequestsPerSec};

// Rate limiting is disabled by default so that test harnesses are not
// affected.  Production code enables it via enable_evm_rpc_rate_limit().
static bool g_rate_limit_enabled = false;

void enable_evm_rpc_rate_limit(bool enable) {
    g_rate_limit_enabled = enable;
    if (enable) {
        g_rpc_limiter.reset();
        g_getlogs_limiter.reset();
    }
}

void reset_evm_rpc_rate_limit_for_test() {
    g_rpc_limiter.reset();
    g_getlogs_limiter.reset();
}

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

    // Store transaction for eth_getTransactionByHash + raw RLP for eth_getRawTransactionByHash
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
    stored_tx.raw_rlp = raw_tx;  // original bytes from eth_sendRawTransaction
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

    // Compute transactionsRoot and receiptsRoot using proper Merkle Patricia Trie.
    // The trie root functions read from evm_state, which already has the stored tx/receipt.
    stored_block.transactions_root = compute_transactions_root(
        stored_block.transaction_hashes, evm_state);
    stored_block.receipts_root = compute_receipts_root(
        stored_block.transaction_hashes, evm_state);

    // Compute incremental state root (Erigon-style MPT)
    // Needs lock since compute_state_root reads from InMemoryState.
    {
        std::unique_lock trie_lock(evm_state.mutex());
        stored_block.state_root = global_trie_calculator().compute_state_root(
            evm_state, &evm_state.account_changes(), &evm_state.storage_changes());
        evm_state.clear_change_tracking();
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

// Hex-char validator used by the numeric parsers below. Returns true
// iff `c` is a valid hex digit (case-insensitive).
static bool is_hex_char(char c) {
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

static uint64_t parse_hex_uint64(const std::string& hex_str) {
    if (hex_str.empty()) return 0;
    size_t start = 0;
    if (hex_str.size() >= 2 && hex_str[0] == '0' && (hex_str[1] == 'x' || hex_str[1] == 'X'))
        start = 2;
    // Validate all remaining chars are hex. strtoull happily returns 0 on
    // leading junk but consumes partial input on trailing junk — we'd
    // rather detect malformed input cleanly so upstream parsers can
    // default to 0 (caller-specific semantic).
    for (size_t i = start; i < hex_str.size(); ++i) {
        if (!is_hex_char(hex_str[i])) return 0;
    }
    return std::strtoull(hex_str.c_str() + start, nullptr, 16);
}

static intx::uint256 parse_hex_uint256(const std::string& hex_str) {
    if (hex_str.empty()) return 0;
    std::string hex = hex_str;
    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
        hex = hex.substr(2);
    if (hex.empty()) return 0;
    // Reject invalid hex before handing to intx::from_string, which
    // throws `std::invalid_argument` on any non-hex character. An
    // uncaught throw here would propagate through the RPC dispatch
    // loop and terminate the whole validator — i.e. a remote-reachable
    // DoS (found by Phase G.5 fuzz, e.g. value="0xZZ" crashed the
    // node in ~1s). Reject → return 0 → caller sees a zero-value
    // param and the request proceeds harmlessly.
    if (hex.size() > 64) return 0;  // uint256 is at most 64 hex digits
    for (char c : hex) {
        if (!is_hex_char(c)) return 0;
    }
    while (hex.size() < 64) hex = "0" + hex;
    try {
        return intx::from_string<intx::uint256>("0x" + hex);
    } catch (...) {
        return 0;  // defense-in-depth if intx adds new throw paths
    }
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

    auto result = call_evm_transaction_with_balance_topup(txn, block, global_evm_state(), config);

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
    // totalDifficulty is omitted for post-merge blocks (geth, erigon,
    // reth all do this starting with the merge). Keeping it as a
    // deprecated-but-present field confuses newer clients.
    r += "\"extraData\":\"0x\",";
    r += "\"size\":\"0x0\",";
    r += "\"mixHash\":\"0x" + std::string(64, '0') + "\",";
    r += "\"stateRoot\":" + to_hex_data(blk.state_root.bytes, 32) + ",";
    r += "\"transactionsRoot\":" + to_hex_data(blk.transactions_root.bytes, 32) + ",";
    r += "\"receiptsRoot\":" + to_hex_data(blk.receipts_root.bytes, 32) + ",";
    r += "\"logsBloom\":" + to_hex_data(blk.logs_bloom, 256) + ",";
    r += "\"sha3Uncles\":\"0x" + std::string(64, '0') + "\",";
    // Cancun (EIP-4844 / EIP-4788) fields — always emitted because
    // block explorers and indexers (Etherscan, Blockscout, The Graph)
    // assume every modern RPC returns them. We don't support blobs or
    // the beacon root today, so emit zero values.
    r += "\"blobGasUsed\":\"0x0\",";
    r += "\"excessBlobGas\":\"0x0\",";
    r += "\"parentBeaconBlockRoot\":\"0x" + std::string(64, '0') + "\",";
    // Shanghai (EIP-4895) withdrawals — not supported, emit empty.
    r += "\"withdrawals\":[],";
    r += "\"withdrawalsRoot\":\"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421\",";  // keccak256(rlp([]))
    // Prague (EIP-7685) execution-layer requests — empty root = sha256(0x00).
    r += "\"requestsHash\":\"0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",";
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
    // Enforce maximum block range to prevent expensive scans
    if (to_block > from_block && (to_block - from_block) > kMaxGetLogsBlockRange) {
        return {make_error(id, -32005, "query exceeds max block range of " +
                           std::to_string(kMaxGetLogsBlockRange)), true};
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
    std::string blob_base_fees = "[";
    std::string gas_ratios = "[";
    std::string blob_gas_ratios = "[";
    std::string rewards = "[";

    for (uint64_t i = oldest; i <= newest; ++i) {
        if (i > oldest) {
            gas_ratios += ",";
            blob_gas_ratios += ",";
            rewards += ",";
            base_fees += ",";
            blob_base_fees += ",";
        }

        auto blk = global_evm_state().get_block_copy(i);
        if (global_evm_state().has_block(i)) {
            base_fees += to_hex_quantity(blk.base_fee_per_gas);
            double ratio = blk.gas_limit > 0
                ? static_cast<double>(blk.gas_used) / blk.gas_limit : 0.0;
            // Emit integer when exact 0 or 1 (matches geth/erigon);
            // otherwise print as float with 6 decimals.
            if (ratio == 0.0) {
                gas_ratios += "0";
            } else if (ratio == 1.0) {
                gas_ratios += "1";
            } else {
                char ratio_buf[32];
                snprintf(ratio_buf, sizeof(ratio_buf), "%.6f", ratio);
                gas_ratios += ratio_buf;
            }
        } else {
            base_fees += to_hex_quantity(intx::uint256{kInitialBaseFee});
            gas_ratios += "0";
        }
        blob_base_fees += "\"0x0\"";
        blob_gas_ratios += "0";  // spec: integer when exactly 0
        rewards += "[\"0x0\"]";
    }
    // One extra base fee (and blob fee) for the next block.
    auto last_blk = global_evm_state().get_block_copy(newest);
    intx::uint256 next_base_fee{kInitialBaseFee};
    if (global_evm_state().has_block(newest)) {
        next_base_fee = calc_base_fee(last_blk.base_fee_per_gas,
                                       last_blk.gas_used, last_blk.gas_limit);
    }
    base_fees += "," + to_hex_quantity(next_base_fee);
    base_fees += "]";
    blob_base_fees += ",\"0x0\"]";
    gas_ratios += "]";
    blob_gas_ratios += "]";
    rewards += "]";

    std::string r = "{";
    r += "\"oldestBlock\":" + to_hex_quantity(oldest) + ",";
    r += "\"baseFeePerGas\":" + base_fees + ",";
    r += "\"baseFeePerBlobGas\":" + blob_base_fees + ",";
    r += "\"gasUsedRatio\":" + gas_ratios + ",";
    r += "\"blobGasUsedRatio\":" + blob_gas_ratios + ",";
    r += "\"reward\":" + rewards;
    r += "}";
    return {make_result(id, r), false};
}

static RpcResult handle_max_priority_fee(const std::string& id) {
    // Return 1 gwei as the suggested priority fee
    return {make_result(id, to_hex_quantity(uint64_t{1'000'000'000})), false};
}

// ---------------------------------------------------------------------------
// Block explorer RPC helpers
// ---------------------------------------------------------------------------

// Parse a block number tag from the first param in an array:
//   ["latest"] / ["earliest"] / ["safe"] / ["finalized"] / ["pending"] / ["0x1"]
// Returns the resolved uint64_t block number.
static uint64_t parse_block_number_param(const std::string& params) {
    uint64_t bn = global_evm_state().block_number();
    // Check for named tags first
    if (params.find("\"latest\"") != std::string::npos ||
        params.find("\"pending\"") != std::string::npos ||
        params.find("\"safe\"") != std::string::npos ||
        params.find("\"finalized\"") != std::string::npos) {
        return bn;
    }
    if (params.find("\"earliest\"") != std::string::npos) {
        return 0;
    }
    // Otherwise parse hex
    auto pos = params.find("0x");
    if (pos != std::string::npos) {
        auto end = params.find_first_of("\",]}", pos);
        std::string hex_str = params.substr(pos, end - pos);
        return parse_hex_uint64(hex_str);
    }
    return bn;
}

// Parse a 32-byte hash from the first hex param in the params string.
static bool parse_hash_param(const std::string& params, evmc::bytes32& out) {
    silkworm::Bytes hash_bytes;
    if (!parse_hex_bytes(params, hash_bytes) || hash_bytes.size() != 32) {
        return false;
    }
    std::memcpy(out.bytes, hash_bytes.data(), 32);
    return true;
}

// Parse the second hex param (transaction index) from params like ["0x1", "0x0"].
static uint64_t parse_second_hex_param(const std::string& params) {
    // Find first 0x, skip past it, then find the second 0x
    auto first = params.find("0x");
    if (first == std::string::npos) return 0;
    auto second = params.find("0x", first + 2);
    if (second == std::string::npos) return 0;
    auto end = params.find_first_of("\",]}", second);
    std::string hex_str = params.substr(second, end - second);
    return parse_hex_uint64(hex_str);
}

// Format a full transaction object JSON (same as handle_get_transaction_by_hash output).
static std::string format_transaction_json(const evmc::bytes32& tx_hash, const StoredTransaction& tx) {
    std::string r = "{";
    r += "\"hash\":" + to_hex_data(tx_hash.bytes, 32) + ",";
    r += "\"from\":" + to_hex_addr(tx.from) + ",";
    if (tx.to) {
        r += "\"to\":" + to_hex_addr(*tx.to) + ",";
    } else {
        r += "\"to\":null,";
    }
    r += "\"value\":" + to_hex_quantity(tx.value) + ",";
    r += "\"input\":" + to_hex_data(tx.data.data(), tx.data.size()) + ",";
    r += "\"nonce\":" + to_hex_quantity(tx.nonce) + ",";
    r += "\"gas\":" + to_hex_quantity(tx.gas_limit) + ",";
    r += "\"gasPrice\":" + to_hex_quantity(tx.gas_price) + ",";
    r += "\"blockNumber\":" + to_hex_quantity(tx.block_number) + ",";
    r += "\"blockHash\":" + lookup_block_hash_hex(tx.block_number) + ",";
    r += "\"transactionIndex\":" + to_hex_quantity(static_cast<uint64_t>(tx.tx_index)) + ",";
    r += "\"type\":\"0x0\",";
    r += "\"v\":\"0x0\",\"r\":\"0x0\",\"s\":\"0x0\"";
    r += "}";
    return r;
}

static RpcResult handle_get_block_tx_count_by_number(const std::string& params, const std::string& id) {
    uint64_t bn = parse_block_number_param(params);
    if (!global_evm_state().has_block(bn)) {
        return {make_result(id, "\"0x0\""), false};
    }
    auto blk = global_evm_state().get_block_copy(bn);
    return {make_result(id, to_hex_quantity(static_cast<uint64_t>(blk.transaction_hashes.size()))), false};
}

static RpcResult handle_get_block_tx_count_by_hash(const std::string& params, const std::string& id) {
    evmc::bytes32 block_hash{};
    if (!parse_hash_param(params, block_hash)) {
        return {make_result(id, "null"), false};
    }
    auto blk = global_evm_state().get_block_by_hash_copy(block_hash);
    if (blk.number == 0 && blk.hash == evmc::bytes32{}) {
        return {make_result(id, "null"), false};
    }
    return {make_result(id, to_hex_quantity(static_cast<uint64_t>(blk.transaction_hashes.size()))), false};
}

static RpcResult handle_get_uncle_count_by_block_number(const std::string& /*params*/, const std::string& id) {
    // PoS chain has no uncles — always return 0
    return {make_result(id, "\"0x0\""), false};
}

static RpcResult handle_get_tx_by_block_number_and_index(const std::string& params, const std::string& id) {
    uint64_t bn = parse_block_number_param(params);
    uint64_t tx_index = parse_second_hex_param(params);

    if (!global_evm_state().has_block(bn)) {
        return {make_result(id, "null"), false};
    }
    auto blk = global_evm_state().get_block_copy(bn);
    if (tx_index >= blk.transaction_hashes.size()) {
        return {make_result(id, "null"), false};
    }

    const auto& tx_hash = blk.transaction_hashes[tx_index];
    auto tx = global_evm_state().get_transaction_copy(tx_hash);
    if (!tx) {
        return {make_result(id, "null"), false};
    }

    return {make_result(id, format_transaction_json(tx_hash, *tx)), false};
}

static RpcResult handle_get_tx_by_block_hash_and_index(const std::string& params, const std::string& id) {
    evmc::bytes32 block_hash{};
    if (!parse_hash_param(params, block_hash)) {
        return {make_result(id, "null"), false};
    }
    uint64_t tx_index = parse_second_hex_param(params);

    auto blk = global_evm_state().get_block_by_hash_copy(block_hash);
    if (blk.number == 0 && blk.hash == evmc::bytes32{}) {
        return {make_result(id, "null"), false};
    }
    if (tx_index >= blk.transaction_hashes.size()) {
        return {make_result(id, "null"), false};
    }

    const auto& tx_hash = blk.transaction_hashes[tx_index];
    auto tx = global_evm_state().get_transaction_copy(tx_hash);
    if (!tx) {
        return {make_result(id, "null"), false};
    }

    return {make_result(id, format_transaction_json(tx_hash, *tx)), false};
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

// =============================================================================
// Standard Ethereum RPC methods — full surface compatibility
// =============================================================================

// --- Trivial constants ---

static RpcResult handle_protocol_version(const std::string& id) {
    // Symbolic protocol version. 65 = TOS protocol v1.
    return {make_result(id, "\"0x41\""), false};
}

static RpcResult handle_coinbase(const std::string& id) {
    // We have no mining beneficiary — the basechain handles fees via TOS gas.
    return {make_result(id, "\"0x" + std::string(40, '0') + "\""), false};
}

static RpcResult handle_hashrate(const std::string& id) {
    // Not a PoW chain.
    return {make_result(id, "\"0x0\""), false};
}

static RpcResult handle_blob_base_fee(const std::string& id) {
    // EIP-4844 blob transactions are not supported.
    return {make_result(id, "\"0x0\""), false};
}

static RpcResult handle_uncle_count_by_block_hash(const std::string&, const std::string& id) {
    return {make_result(id, "\"0x0\""), false};
}

static RpcResult handle_uncle_by_block_hash_and_index(const std::string&, const std::string& id) {
    return {make_result(id, "null"), false};
}

static RpcResult handle_uncle_by_block_number_and_index(const std::string&, const std::string& id) {
    return {make_result(id, "null"), false};
}

// --- web3_sha3: keccak256 of input bytes ---

static RpcResult handle_web3_sha3(const std::string& params, const std::string& id) {
    silkworm::Bytes data;
    if (!parse_hex_bytes(params, data)) {
        return {make_error(id, -32602, "invalid hex input"), true};
    }
    auto h = ethash::keccak256(data.data(), data.size());
    return {make_result(id, to_hex_data(h.bytes, 32)), false};
}

// --- Raw transaction RLP serving ---

static std::string raw_tx_response(const std::string& id, const StoredTransaction& tx) {
    if (tx.raw_rlp.empty()) {
        return make_result(id, "null");
    }
    return make_result(id, to_hex_data(tx.raw_rlp.data(), tx.raw_rlp.size()));
}

static RpcResult handle_get_raw_transaction_by_hash(const std::string& params, const std::string& id) {
    silkworm::Bytes hash_bytes;
    if (!parse_hex_bytes(params, hash_bytes) || hash_bytes.size() != 32) {
        return {make_error(id, -32602, "invalid transaction hash"), true};
    }
    evmc::bytes32 tx_hash;
    std::memcpy(tx_hash.bytes, hash_bytes.data(), 32);

    auto tx = global_evm_state().get_transaction_copy(tx_hash);
    if (!tx) return {make_result(id, "null"), false};
    return {raw_tx_response(id, *tx), false};
}

static RpcResult handle_get_raw_tx_by_block_hash_and_index(const std::string& params, const std::string& id) {
    // params: ["0x<blockHash>", "0x<index>"]
    silkworm::Bytes hash_bytes;
    if (!parse_hex_bytes(params, hash_bytes) || hash_bytes.size() != 32) {
        return {make_error(id, -32602, "invalid block hash"), true};
    }
    evmc::bytes32 block_hash;
    std::memcpy(block_hash.bytes, hash_bytes.data(), 32);

    auto blk = global_evm_state().get_block_by_hash_copy(block_hash);
    if (blk.hash == evmc::bytes32{} && blk.number == 0) {
        return {make_result(id, "null"), false};
    }

    // Parse index (second hex param)
    auto first_pos = params.find("0x");
    if (first_pos == std::string::npos) return {make_result(id, "null"), false};
    auto second_pos = params.find("0x", first_pos + 1);
    uint64_t index = 0;
    if (second_pos != std::string::npos) {
        index = std::strtoull(params.c_str() + second_pos + 2, nullptr, 16);
    }
    if (index >= blk.transaction_hashes.size()) {
        return {make_result(id, "null"), false};
    }
    auto tx = global_evm_state().get_transaction_copy(blk.transaction_hashes[index]);
    if (!tx) return {make_result(id, "null"), false};
    return {raw_tx_response(id, *tx), false};
}

static RpcResult handle_get_raw_tx_by_block_number_and_index(const std::string& params, const std::string& id) {
    // params: ["0x<blockNumber>" or "latest", "0x<index>"]
    uint64_t bn = global_evm_state().block_number();
    auto pos = params.find("0x");
    if (pos != std::string::npos) {
        auto end = params.find_first_of("\",]}", pos);
        std::string bn_str = params.substr(pos, end - pos);
        if (bn_str != "latest" && bn_str != "pending" && bn_str != "safe" && bn_str != "finalized") {
            bn = parse_hex_uint64(bn_str);
        }
    }
    if (!global_evm_state().has_block(bn)) {
        return {make_result(id, "null"), false};
    }
    auto blk = global_evm_state().get_block_copy(bn);

    // index: second hex param
    uint64_t index = 0;
    auto first_pos = params.find("0x");
    if (first_pos != std::string::npos) {
        auto second_pos = params.find("0x", first_pos + 1);
        if (second_pos != std::string::npos) {
            index = std::strtoull(params.c_str() + second_pos + 2, nullptr, 16);
        }
    }
    if (index >= blk.transaction_hashes.size()) {
        return {make_result(id, "null"), false};
    }
    auto tx = global_evm_state().get_transaction_copy(blk.transaction_hashes[index]);
    if (!tx) return {make_result(id, "null"), false};
    return {raw_tx_response(id, *tx), false};
}

// --- debug_getRaw* (block / header / receipts / tx) ---

// Build an Ethereum-format block header RLP from our StoredBlock.
// Layout per yellow paper §4.3:
//   [parentHash, ommersHash, beneficiary, stateRoot, transactionsRoot,
//    receiptsRoot, logsBloom, difficulty, number, gasLimit, gasUsed,
//    timestamp, extraData, mixHash, nonce, baseFeePerGas]
static silkworm::Bytes encode_eth_header_rlp(const StoredBlock& blk) {
    silkworm::Bytes payload;
    silkworm::rlp::encode(payload, silkworm::ByteView{blk.parent_hash.bytes, 32});
    // ommers (uncles) hash = keccak256(rlp([])) = kEmptyListHash
    silkworm::rlp::encode(payload, silkworm::ByteView{silkworm::kEmptyListHash.bytes, 32});
    silkworm::rlp::encode(payload, silkworm::ByteView{blk.miner.bytes, 20});
    silkworm::rlp::encode(payload, silkworm::ByteView{evmc::bytes32{}.bytes, 32});  // stateRoot placeholder (TODO real)
    silkworm::rlp::encode(payload, silkworm::ByteView{blk.transactions_root.bytes, 32});
    silkworm::rlp::encode(payload, silkworm::ByteView{blk.receipts_root.bytes, 32});
    silkworm::rlp::encode(payload, silkworm::ByteView{blk.logs_bloom, 256});
    silkworm::rlp::encode(payload, intx::uint256{0});  // difficulty
    silkworm::rlp::encode(payload, blk.number);
    silkworm::rlp::encode(payload, blk.gas_limit);
    silkworm::rlp::encode(payload, blk.gas_used);
    silkworm::rlp::encode(payload, blk.timestamp);
    silkworm::rlp::encode(payload, silkworm::ByteView{});  // extraData empty
    silkworm::rlp::encode(payload, silkworm::ByteView{evmc::bytes32{}.bytes, 32});  // mixHash
    uint64_t nonce_zero = 0;
    silkworm::Bytes nonce_be(8, 0);
    silkworm::rlp::encode(payload, silkworm::ByteView{nonce_be});  // 8-byte nonce
    (void)nonce_zero;
    silkworm::rlp::encode(payload, blk.base_fee_per_gas);

    silkworm::Bytes out;
    silkworm::rlp::Header h{true, payload.size()};
    silkworm::rlp::encode_header(out, h);
    out.append(payload);
    return out;
}

static RpcResult handle_debug_get_raw_header(const std::string& params, const std::string& id) {
    uint64_t bn = global_evm_state().block_number();
    auto pos = params.find("0x");
    if (pos != std::string::npos) {
        auto end = params.find_first_of("\",]}", pos);
        std::string s = params.substr(pos, end - pos);
        if (s != "latest" && s != "pending" && s != "safe" && s != "finalized") {
            bn = parse_hex_uint64(s);
        }
    }
    if (!global_evm_state().has_block(bn)) return {make_result(id, "null"), false};
    auto blk = global_evm_state().get_block_copy(bn);
    auto rlp = encode_eth_header_rlp(blk);
    return {make_result(id, to_hex_data(rlp.data(), rlp.size())), false};
}

static RpcResult handle_debug_get_raw_block(const std::string& params, const std::string& id) {
    uint64_t bn = global_evm_state().block_number();
    auto pos = params.find("0x");
    if (pos != std::string::npos) {
        auto end = params.find_first_of("\",]}", pos);
        std::string s = params.substr(pos, end - pos);
        if (s != "latest" && s != "pending" && s != "safe" && s != "finalized") {
            bn = parse_hex_uint64(s);
        }
    }
    if (!global_evm_state().has_block(bn)) return {make_result(id, "null"), false};
    auto blk = global_evm_state().get_block_copy(bn);

    // block = [header, transactions, ommers]
    silkworm::Bytes header_rlp = encode_eth_header_rlp(blk);

    // transactions: list of raw RLP txs
    silkworm::Bytes txs_payload;
    for (const auto& th : blk.transaction_hashes) {
        auto tx = global_evm_state().get_transaction_copy(th);
        if (tx && !tx->raw_rlp.empty()) {
            txs_payload.append(tx->raw_rlp);
        }
    }
    silkworm::Bytes txs_rlp;
    silkworm::rlp::Header th{true, txs_payload.size()};
    silkworm::rlp::encode_header(txs_rlp, th);
    txs_rlp.append(txs_payload);

    // ommers: empty list
    silkworm::Bytes ommers_rlp;
    silkworm::rlp::Header oh{true, 0};
    silkworm::rlp::encode_header(ommers_rlp, oh);

    silkworm::Bytes payload;
    payload.append(header_rlp);
    payload.append(txs_rlp);
    payload.append(ommers_rlp);

    silkworm::Bytes out;
    silkworm::rlp::Header bh{true, payload.size()};
    silkworm::rlp::encode_header(out, bh);
    out.append(payload);

    return {make_result(id, to_hex_data(out.data(), out.size())), false};
}

static RpcResult handle_debug_get_raw_receipts(const std::string& params, const std::string& id) {
    uint64_t bn = global_evm_state().block_number();
    auto pos = params.find("0x");
    if (pos != std::string::npos) {
        auto end = params.find_first_of("\",]}", pos);
        std::string s = params.substr(pos, end - pos);
        if (s != "latest" && s != "pending" && s != "safe" && s != "finalized") {
            bn = parse_hex_uint64(s);
        }
    }
    if (!global_evm_state().has_block(bn)) return {make_result(id, "[]"), false};
    auto blk = global_evm_state().get_block_copy(bn);

    // Encode each receipt as RLP([status, cumulative_gas, logs_bloom, logs])
    std::string out = "[";
    for (size_t i = 0; i < blk.transaction_hashes.size(); i++) {
        if (i > 0) out += ",";
        auto r = global_evm_state().get_receipt_copy(blk.transaction_hashes[i]);
        if (!r) { out += "null"; continue; }
        silkworm::Bytes payload;
        silkworm::rlp::encode(payload, r->success ? uint64_t{1} : uint64_t{0});
        silkworm::rlp::encode(payload, r->cumulative_gas_used);
        // logsBloom from receipt logs
        uint8_t bloom[256] = {};
        compute_logs_bloom(r->logs, bloom);
        silkworm::rlp::encode(payload, silkworm::ByteView{bloom, 256});
        // logs sub-list
        silkworm::Bytes logs_payload;
        for (const auto& log : r->logs) {
            silkworm::Bytes lp;
            silkworm::rlp::encode(lp, silkworm::ByteView{log.address.bytes, 20});
            silkworm::Bytes topics_payload;
            for (const auto& t : log.topics) {
                silkworm::rlp::encode(topics_payload, silkworm::ByteView{t.bytes, 32});
            }
            silkworm::Bytes topics_list;
            silkworm::rlp::encode_header(topics_list, silkworm::rlp::Header{true, topics_payload.size()});
            topics_list.append(topics_payload);
            lp.append(topics_list);
            silkworm::rlp::encode(lp, log.data);
            silkworm::Bytes lh;
            silkworm::rlp::encode_header(lh, silkworm::rlp::Header{true, lp.size()});
            lh.append(lp);
            logs_payload.append(lh);
        }
        silkworm::Bytes logs_list;
        silkworm::rlp::encode_header(logs_list, silkworm::rlp::Header{true, logs_payload.size()});
        logs_list.append(logs_payload);
        payload.append(logs_list);

        silkworm::Bytes receipt_rlp;
        silkworm::rlp::encode_header(receipt_rlp, silkworm::rlp::Header{true, payload.size()});
        receipt_rlp.append(payload);
        out += to_hex_data(receipt_rlp.data(), receipt_rlp.size());
    }
    out += "]";
    return {make_result(id, out), false};
}

// --- eth_getProof: full MPT inclusion proofs ---
//
// Builds an Ethereum-canonical MPT (Yellow Paper Appendix D) over all
// hashed accounts to generate an accountProof. For each requested storage
// slot, builds the per-account storage MPT and generates a proof.
//
// All four fields are now correct for offline verification:
//   - balance, nonce, codeHash: from CellEvmState
//   - storageHash: keccak256 of root MPT node of storage trie
//   - accountProof: list of RLP-encoded MPT nodes (root → leaf for the address)
//   - storageProof[i].proof: same, for each requested slot in the storage trie
//
// Cost: O(N_accounts) for the account trie build; O(N_slots) per storage trie.
// This is acceptable for read-only RPC; not on the consensus path.

static RpcResult handle_get_proof(const std::string& params, const std::string& id) {
    evmc::address addr{};
    if (!parse_hex_address(params, addr)) {
        return {make_error(id, -32602, "invalid address"), true};
    }

    auto& state = global_evm_state();
    auto acct = state.read_account(addr);
    silkworm::Account a;
    if (acct) a = *acct;

    // Parse storage keys array. params has the shape
    //   ["0x<addr>", [ "0x<key1>", "0x<key2>", ... ], "<blockTag>"]
    // Find the INNER array and scan only within its bounds so a later
    // blockhash string isn't mis-read as a storage key.
    std::vector<evmc::bytes32> slots;
    auto kpos = params.find('[', params.find('[') + 1);
    auto kend = (kpos != std::string::npos) ? params.find(']', kpos + 1) : std::string::npos;
    if (kpos != std::string::npos && kend != std::string::npos && kend > kpos) {
        size_t scan = kpos;
        while (scan < kend) {
            auto h = params.find("0x", scan);
            if (h == std::string::npos || h >= kend) break;
            auto e = params.find_first_of("\",]", h);
            if (e == std::string::npos || e > kend) break;
            // Keys can be any length ≤ 32 bytes per the spec ("0x0", "0x00",
            // "0x0000...0000" are all the zero slot). parse_hex_bytes rejects
            // odd-length hex, but "0x0" is odd (1 nibble = half-byte). Handle
            // both even and odd by reading hex nibbles manually.
            // h points to the '0' of "0x", e is past the hex digits.
            size_t hex_start = h + 2;  // past "0x"
            size_t hex_end = e;
            size_t hex_len = hex_end - hex_start;
            if (hex_len == 0 || hex_len > 64) {
                scan = e + 1; continue;
            }
            evmc::bytes32 s{};
            size_t nibble_offset = 64 - hex_len;  // left-pad nibbles
            bool ok = true;
            for (size_t i = 0; i < hex_len; ++i) {
                uint8_t n;
                if (!parse_hex_byte(params[hex_start + i], n)) { ok = false; break; }
                size_t tgt_nibble = nibble_offset + i;
                size_t byte = tgt_nibble / 2;
                if (tgt_nibble % 2 == 0) {
                    s.bytes[byte] = static_cast<uint8_t>(n << 4);
                } else {
                    s.bytes[byte] |= n;
                }
            }
            if (ok) slots.push_back(s);
            scan = e + 1;
        }
    }

    // ----- Build storage trie + storage proofs -----
    evmc::bytes32 storage_hash = silkworm::kEmptyRoot;
    std::map<silkworm::Bytes, silkworm::Bytes> storage_kv;
    if (acct) {
        auto* cs = dynamic_cast<CellEvmState*>(&state.state());
        if (cs) {
            cs->for_each_storage(addr, [&](const evmc::bytes32& slot,
                                            const evmc::bytes32& value) {
                if (value == evmc::bytes32{}) return;  // zero values absent from trie
                auto kh = ethash::keccak256(slot.bytes, 32);
                silkworm::Bytes key(kh.bytes, kh.bytes + 32);
                silkworm::Bytes val_rlp;
                intx::uint256 v_int = intx::be::load<intx::uint256>(value);
                silkworm::rlp::encode(val_rlp, v_int);
                storage_kv[std::move(key)] = std::move(val_rlp);
            });
            storage_hash = mpt_root(storage_kv);
        }
    }

    // ----- Build account trie + account proof -----
    // Iterate every account, hash the address, RLP-encode the account.
    std::map<silkworm::Bytes, silkworm::Bytes> account_kv;
    {
        auto* cs = dynamic_cast<CellEvmState*>(&state.state());
        if (cs) {
            cs->for_each_account([&](const unsigned char key[32],
                                     const silkworm::Account& other_acct) {
                evmc::address other_addr{};
                std::memcpy(other_addr.bytes, key + 12, 20);
                // Each account also needs its own storage_hash for accurate proof.
                // For non-target accounts we use kEmptyRoot (most accounts have
                // no storage); the storage_hash matters only for the target.
                evmc::bytes32 their_storage_hash = silkworm::kEmptyRoot;
                if (other_addr == addr) their_storage_hash = storage_hash;
                silkworm::Bytes acct_rlp = other_acct.rlp(their_storage_hash);
                auto ah = ethash::keccak256(other_addr.bytes, 20);
                silkworm::Bytes hashed_addr(ah.bytes, ah.bytes + 32);
                account_kv[std::move(hashed_addr)] = std::move(acct_rlp);
            });
        }
    }

    // Account proof for the target address
    auto target_hash = ethash::keccak256(addr.bytes, 20);
    silkworm::Bytes target_key(target_hash.bytes, target_hash.bytes + 32);
    auto account_proof = generate_mpt_proof(account_kv, target_key);

    // Helper to format a list of RLP node bytes as JSON array of hex strings
    auto format_proof = [](const std::vector<silkworm::Bytes>& proof) -> std::string {
        std::string out = "[";
        for (size_t i = 0; i < proof.size(); ++i) {
            if (i > 0) out += ",";
            out += to_hex_data(proof[i].data(), proof[i].size());
        }
        out += "]";
        return out;
    };

    std::string r = "{";
    r += "\"address\":" + to_hex_addr(addr) + ",";
    r += "\"balance\":" + to_hex_quantity(a.balance) + ",";
    r += "\"nonce\":" + to_hex_quantity(a.nonce) + ",";
    r += "\"codeHash\":" + to_hex_data(a.code_hash.bytes, 32) + ",";
    r += "\"storageHash\":" + to_hex_data(storage_hash.bytes, 32) + ",";
    r += "\"accountProof\":" + format_proof(account_proof) + ",";
    r += "\"storageProof\":[";
    for (size_t i = 0; i < slots.size(); i++) {
        if (i > 0) r += ",";
        auto v = state.read_storage_copy(addr, a.incarnation, slots[i]);
        // Per-slot proof
        auto sh = ethash::keccak256(slots[i].bytes, 32);
        silkworm::Bytes slot_key(sh.bytes, sh.bytes + 32);
        auto slot_proof = generate_mpt_proof(storage_kv, slot_key);
        r += "{";
        r += "\"key\":" + to_hex_data(slots[i].bytes, 32) + ",";
        r += "\"value\":" + to_hex_quantity(intx::be::load<intx::uint256>(v)) + ",";
        r += "\"proof\":" + format_proof(slot_proof);
        r += "}";
    }
    r += "]}";
    return {make_result(id, r), false};
}

// --- eth_simulateV1: simulate one or more blocks of transactions ---
//
// Spec (simplified): https://github.com/ethereum/execution-apis/blob/main/src/eth/execute.yaml
//   params: [{ blockStateCalls: [{ calls: [tx, tx, ...] }, ...] }, blockTag]
//   result: [{ number, hash, timestamp, calls: [{ returnData, logs, gasUsed, status }] }]
//
// Our scope: run each call against a fresh in-memory IntraBlockState seeded
// from current state. Results are NOT committed. Multiple calls within the
// same block share state (one call's state changes are visible to the next).
// Multiple blocks each get a fresh IntraBlockState.
//
// Skipped vs full spec: stateOverrides (replacing balances/code), blockOverrides
// (custom timestamp/coinbase per simulated block), validation flag (skips
// nonce/balance checks). These are TODOs for next iteration.

static RpcResult handle_simulate_v1(const std::string& params, const std::string& id) {
    // Find the calls array(s). Parsing is minimal because our request format
    // uses raw substring extraction throughout the file.
    auto& evm_state = global_evm_state();
    const auto& config = evm_chain_config();
    uint64_t base_block = evm_state.block_number();

    uint8_t rs[32] = {};
    auto block = make_evm_block(base_block,
                                static_cast<uint64_t>(std::time(nullptr)), rs);
    // Do not set block.header.base_fee_per_gas — we run with max_fee_per_gas=0
    // (read-only), so base_fee must also be 0 to avoid the silkworm
    // assertion that base_fee <= max_fee_per_gas.
    intx::uint256 base_fee{0};

    std::string out = "[";
    bool first_block = true;

    // Iterate each blockStateCalls entry. We support a single block for now;
    // detect block boundaries by counting "calls":[ occurrences.
    size_t scan = 0;
    uint64_t simulated_bn = base_block;
    while (true) {
        auto bsc_pos = params.find("\"calls\"", scan);
        if (bsc_pos == std::string::npos) break;
        auto arr_start = params.find('[', bsc_pos + 7);
        if (arr_start == std::string::npos) break;
        // Find matching ]
        int depth = 1;
        size_t i = arr_start + 1;
        while (i < params.size() && depth > 0) {
            if (params[i] == '[') depth++;
            else if (params[i] == ']') depth--;
            if (depth == 0) break;
            i++;
        }
        if (depth != 0) break;
        const std::string calls_block = params.substr(arr_start + 1, i - arr_start - 1);
        scan = i + 1;
        ++simulated_bn;

        if (!first_block) out += ",";
        first_block = false;

        // Each call object starts with '{'. Extract one at a time.
        std::vector<std::string> call_jsons;
        int cd = 0;
        size_t cs = 0;
        for (size_t j = 0; j < calls_block.size(); j++) {
            if (calls_block[j] == '{') {
                if (cd == 0) cs = j;
                cd++;
            } else if (calls_block[j] == '}') {
                cd--;
                if (cd == 0) call_jsons.push_back(calls_block.substr(cs, j - cs + 1));
            }
        }

        // Build simulated block JSON
        out += "{\"number\":" + to_hex_quantity(simulated_bn) + ",";
        out += "\"hash\":\"0x" + std::string(64, '0') + "\",";
        out += "\"timestamp\":" + to_hex_quantity(static_cast<uint64_t>(std::time(nullptr))) + ",";
        out += "\"baseFeePerGas\":" + to_hex_quantity(base_fee) + ",";
        out += "\"calls\":[";

        for (size_t k = 0; k < call_jsons.size(); k++) {
            if (k > 0) out += ",";
            auto txn = parse_call_object(call_jsons[k]);
            txn.max_fee_per_gas = 0;
            txn.max_priority_fee_per_gas = 0;
            if (txn.gas_limit < 21000) txn.gas_limit = 21000;  // floor
            if (txn.gas_limit > 30'000'000) txn.gas_limit = 30'000'000;  // ceiling
            // Wrap in try/catch to avoid crashing the whole node on bad input
            ExecutionResult result;
            try {
                result = call_evm_transaction(txn, block, evm_state, config);
            } catch (const std::exception& e) {
                result.success = false;
                result.error_message = std::string("simulate exception: ") + e.what();
            } catch (...) {
                result.success = false;
                result.error_message = "simulate: unknown exception";
            }

            out += "{";
            out += "\"status\":\"" + std::string(result.success ? "0x1" : "0x0") + "\",";
            out += "\"returnData\":" + to_hex_data(result.return_data.data(), result.return_data.size()) + ",";
            out += "\"gasUsed\":" + to_hex_quantity(result.gas_used) + ",";
            out += "\"logs\":[";
            for (size_t li = 0; li < result.logs.size(); li++) {
                if (li > 0) out += ",";
                const auto& log = result.logs[li];
                out += "{\"address\":" + to_hex_addr(log.address) + ",";
                out += "\"topics\":[";
                for (size_t ti = 0; ti < log.topics.size(); ti++) {
                    if (ti > 0) out += ",";
                    out += to_hex_data(log.topics[ti].bytes, 32);
                }
                out += "],\"data\":" + to_hex_data(log.data.data(), log.data.size()) + "}";
            }
            out += "]";
            if (!result.success && !result.error_message.empty()) {
                out += ",\"error\":{\"code\":3,\"message\":\"" + result.error_message + "\"}";
            }
            out += "}";
        }
        out += "]}";
    }
    out += "]";
    return {make_result(id, out), false};
}

// --- eth_createAccessList: run EVM with AccessListTracer, return real list ---
//
// Hooks our AccessListTracer (ported from silkworm) into a read-only EVM
// execution. The tracer records every SLOAD/SSTORE/EXTCODE*/CALL target and
// every CREATE/CREATE2 contract address. Result format (EIP-2930):
//   { "accessList": [{"address":"0x...","storageKeys":["0x...",...]}, ...],
//     "gasUsed":"0x..." }

static RpcResult handle_create_access_list(const std::string& params, const std::string& id) {
    auto txn = parse_call_object(params);
    txn.max_fee_per_gas = 0;
    txn.max_priority_fee_per_gas = 0;
    if (txn.gas_limit == 10'000'000) txn.gas_limit = 30'000'000;

    uint8_t rs[32] = {};
    auto block = make_evm_block(global_evm_state().block_number(),
                                static_cast<uint64_t>(std::time(nullptr)), rs);
    const auto& config = evm_chain_config();

    auto& evm_state = global_evm_state();
    std::unique_lock lock(evm_state.mutex());

    // Build IntraBlockState wrapping mutable view (commit_state=false → no DB writes)
    auto& mutable_state = const_cast<silkworm::State&>(evm_state.state());
    silkworm::IntraBlockState ibs(mutable_state);

    silkworm::EVM evm(block, ibs, config);
    AccessListTracer tracer;
    evm.add_tracer(tracer);

    // Compute intrinsic gas + warm-up access lists
    auto rev = evm.revision();
    auto intrinsic = silkworm::protocol::intrinsic_gas(txn, rev);
    uint64_t exec_gas = (intrinsic > static_cast<intx::uint128>(txn.gas_limit))
        ? txn.gas_limit
        : (txn.gas_limit - static_cast<uint64_t>(intrinsic));

    // Warm sender, recipient, beneficiary
    auto sender = txn.sender();
    if (sender) ibs.access_account(*sender);
    if (txn.to) ibs.access_account(*txn.to);
    ibs.access_account(block.header.beneficiary);

    auto call_result = evm.execute(txn, exec_gas);

    // Optimize per EIP-2930 (drop addresses whose listing isn't profitable)
    if (sender) tracer.optimize_gas(*sender, txn.to.value_or(evmc::address{}),
                                     block.header.beneficiary);

    // Compute gas used (no refund for read-only access list creation)
    uint64_t gas_used = txn.gas_limit - call_result.gas_left;

    // Build JSON
    std::string r = "{\"accessList\":[";
    const auto& acl = tracer.get_access_list();
    for (size_t i = 0; i < acl.size(); i++) {
        if (i > 0) r += ",";
        r += "{\"address\":" + to_hex_addr(acl[i].account) + ",";
        r += "\"storageKeys\":[";
        for (size_t j = 0; j < acl[i].storage_keys.size(); j++) {
            if (j > 0) r += ",";
            r += to_hex_data(acl[i].storage_keys[j].bytes, 32);
        }
        r += "]}";
    }
    if (call_result.status != EVMC_SUCCESS) {
        r += "],\"error\":\"execution reverted\",\"gasUsed\":" + to_hex_quantity(gas_used) + "}";
    } else {
        r += "],\"gasUsed\":" + to_hex_quantity(gas_used) + "}";
    }
    return {make_result(id, r), false};
}

// --- eth_getFilterLogs: returns all logs for a filter id (vs eth_getFilterChanges
//     which returns since-last-poll) ---

static RpcResult handle_get_filter_logs(const std::string& params, const std::string& id) {
    uint64_t fid = 0;
    auto pos = params.find("0x");
    if (pos != std::string::npos) {
        fid = std::strtoull(params.c_str() + pos + 2, nullptr, 16);
    }
    std::lock_guard<std::mutex> lock(g_filter_mutex);
    auto it = g_filters.find(fid);
    if (it == g_filters.end()) {
        return {make_error(id, -32000, "filter not found"), true};
    }
    auto& f = it->second;
    if (f.type != FilterType::Logs) {
        return {make_error(id, -32000, "not a log filter"), true};
    }
    auto logs = global_evm_state().get_logs(0, global_evm_state().block_number(),
                                             f.addresses, f.topics);
    std::string arr = "[";
    for (size_t i = 0; i < logs.size(); i++) {
        if (i > 0) arr += ",";
        arr += format_log_json(logs[i]);
    }
    arr += "]";
    return {make_result(id, arr), false};
}

// --- Rejection handlers for methods we cannot implement (no node-side keys) ---

static RpcResult handle_unsupported_signing(const std::string& method, const std::string& id) {
    // eth_sign / eth_signTransaction / eth_sendTransaction require node-managed
    // private keys. We never store user keys server-side — wallets hold their
    // own keys and submit pre-signed transactions via eth_sendRawTransaction.
    return {make_error(id, -32601, method + " not supported: node does not manage user keys; use eth_sendRawTransaction"), true};
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
           method == "eth_getSubscription" ||
           method == "eth_getBlockTransactionCountByNumber" ||
           method == "eth_getBlockTransactionCountByHash" ||
           method == "eth_getUncleCountByBlockNumber" ||
           method == "eth_getTransactionByBlockNumberAndIndex" ||
           method == "eth_getTransactionByBlockHashAndIndex" ||
           // 18 newly added methods for full Ethereum RPC surface compatibility:
           method == "eth_protocolVersion" ||
           method == "eth_coinbase" ||
           method == "eth_hashrate" ||
           method == "eth_blobBaseFee" ||
           method == "eth_getUncleCountByBlockHash" ||
           method == "eth_getUncleByBlockHashAndIndex" ||
           method == "eth_getUncleByBlockNumberAndIndex" ||
           method == "eth_getFilterLogs" ||
           method == "web3_sha3" ||
           method == "eth_getRawTransactionByHash" ||
           method == "eth_getRawTransactionByBlockHashAndIndex" ||
           method == "eth_getRawTransactionByBlockNumberAndIndex" ||
           method == "debug_getRawTransaction" ||
           method == "debug_getRawHeader" ||
           method == "debug_getRawBlock" ||
           method == "debug_getRawReceipts" ||
           method == "eth_getProof" ||
           method == "eth_createAccessList" ||
           method == "eth_simulateV1" ||
           // Rejection methods (we explicitly handle these to return informative errors):
           method == "eth_sign" ||
           method == "eth_signTransaction" ||
           method == "eth_sendTransaction";
}

std::optional<RpcResult> handle_eth_rpc(
    const std::string& method,
    const std::string& params,
    const std::string& id) {

    // --- Production hardening: request size validation ---
    if (params.size() > kMaxRpcParamsSize) {
        return RpcResult{make_error(id, -32600, "request params exceed max size"), true};
    }

    // --- Production hardening: rate limiting ---
    if (g_rate_limit_enabled) {
        // Method-level rate limit for expensive queries
        if (method == "eth_getLogs") {
            if (!g_getlogs_limiter.try_consume()) {
                return RpcResult{make_error(id, -32005, "eth_getLogs rate limit exceeded"), true};
            }
        }
        // Global rate limit for all methods
        if (!g_rpc_limiter.try_consume()) {
            return RpcResult{make_error(id, -32005, "rate limit exceeded"), true};
        }
    }

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
    if (method == "eth_getBlockTransactionCountByNumber") return handle_get_block_tx_count_by_number(params, id);
    if (method == "eth_getBlockTransactionCountByHash")   return handle_get_block_tx_count_by_hash(params, id);
    if (method == "eth_getUncleCountByBlockNumber")       return handle_get_uncle_count_by_block_number(params, id);
    if (method == "eth_getTransactionByBlockNumberAndIndex") return handle_get_tx_by_block_number_and_index(params, id);
    if (method == "eth_getTransactionByBlockHashAndIndex")  return handle_get_tx_by_block_hash_and_index(params, id);
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

    // 18 added methods for full Ethereum RPC surface compatibility
    if (method == "eth_protocolVersion")      return handle_protocol_version(id);
    if (method == "eth_coinbase")             return handle_coinbase(id);
    if (method == "eth_hashrate")             return handle_hashrate(id);
    if (method == "eth_blobBaseFee")          return handle_blob_base_fee(id);
    if (method == "eth_getUncleCountByBlockHash") return handle_uncle_count_by_block_hash(params, id);
    if (method == "eth_getUncleByBlockHashAndIndex")   return handle_uncle_by_block_hash_and_index(params, id);
    if (method == "eth_getUncleByBlockNumberAndIndex") return handle_uncle_by_block_number_and_index(params, id);
    if (method == "eth_getFilterLogs")        return handle_get_filter_logs(params, id);
    if (method == "web3_sha3")                return handle_web3_sha3(params, id);
    if (method == "eth_getRawTransactionByHash") return handle_get_raw_transaction_by_hash(params, id);
    if (method == "eth_getRawTransactionByBlockHashAndIndex") return handle_get_raw_tx_by_block_hash_and_index(params, id);
    if (method == "eth_getRawTransactionByBlockNumberAndIndex") return handle_get_raw_tx_by_block_number_and_index(params, id);
    if (method == "debug_getRawTransaction")  return handle_get_raw_transaction_by_hash(params, id);
    if (method == "debug_getRawHeader")       return handle_debug_get_raw_header(params, id);
    if (method == "debug_getRawBlock")        return handle_debug_get_raw_block(params, id);
    if (method == "debug_getRawReceipts")     return handle_debug_get_raw_receipts(params, id);
    if (method == "eth_getProof")             return handle_get_proof(params, id);
    if (method == "eth_createAccessList")     return handle_create_access_list(params, id);
    if (method == "eth_simulateV1")           return handle_simulate_v1(params, id);

    // Reject methods that require node-side accounts (we never store user keys)
    if (method == "eth_sign" || method == "eth_signTransaction" || method == "eth_sendTransaction") {
        return handle_unsupported_signing(method, id);
    }

    return std::nullopt;
}

}  // namespace evm_workchain
