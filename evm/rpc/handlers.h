/*
    EVM Workchain — Ethereum JSON-RPC facade.

    Provides wallet-facing eth_* methods that make the EVM workchain look
    like a standard Ethereum node to MetaMask, ethers.js, viem, etc.

    Methods implemented (MVP wallet-facing set per feasibility doc §0):
      eth_chainId              — network identifier
      eth_blockNumber          — latest block height
      eth_getBalance           — account balance
      eth_getTransactionCount  — account nonce
      eth_getCode              — contract bytecode
      eth_gasPrice             — current gas price
      eth_sendRawTransaction   — submit signed tx
      eth_getTransactionReceipt — execution result
      eth_call                 — read-only execution
      eth_estimateGas          — gas estimation
      net_version              — network id (same as chainId for compatibility)

    All methods accept and return standard Ethereum JSON-RPC format.
    Addresses are 0x-prefixed 20-byte hex, quantities are 0x-prefixed hex.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <functional>

namespace evm_workchain {

/// Result of an RPC call: JSON string to return to the caller.
struct RpcResult {
    std::string json;
    bool is_error{false};
};

/// Handle an eth_* JSON-RPC request.
///
/// @param method    The method name (e.g. "eth_chainId").
/// @param params    The raw JSON params array as a string.
/// @param id        The request id (number or string) to echo back.
/// @return          RpcResult with the JSON-RPC response, or std::nullopt
///                  if this method is not handled by the EVM RPC facade.
std::optional<RpcResult> handle_eth_rpc(
    const std::string& method,
    const std::string& params,
    const std::string& id);

/// Returns true if the given method name is an eth_* method handled by this facade.
bool is_eth_rpc_method(const std::string& method) noexcept;

/// Test helper: reset in-memory filter state to a clean slate.
void reset_evm_rpc_filter_state_for_test();

/// Enable or disable RPC rate limiting.
/// Rate limiting is disabled by default (for test harnesses).
/// Production code should call enable_evm_rpc_rate_limit(true) at startup.
void enable_evm_rpc_rate_limit(bool enable);

/// Enable public eth_getProof backed by the persistent execution trie witness.
/// Enabled by default; production profiles may still turn it off by policy.
void enable_public_evm_getproof(bool enable);

/// Enable the admin/conformance read-only EVM RPC profile. When OFF
/// (the default), per-request read-only gas (eth_call /
/// eth_estimateGas / eth_createAccessList / eth_simulateV1) is capped
/// at the public 10M-gas limit. When ON, the cap is raised to 30M to
/// match Ethereum L1 block gas — required for the execution-apis
/// conformance suite and for local tooling that simulates whole-block
/// sized calls. Must only be enabled on local-only / admin RPC
/// endpoints.
void enable_admin_evm_rpc_profile(bool enable);

/// Try to consume one token from the global EVM RPC bucket. Used by the
/// `eth_sendRawTransaction` fast path in `json-rpc-server-send.cpp`, which
/// dispatches BEFORE `handle_eth_rpc` and therefore needs to hit the bucket
/// itself. Returns true when rate-limiting is disabled (test mode) or when
/// a token is available; false when the bucket is empty.
/// Shared with the raw transaction fast path before expensive decoding.
bool try_consume_evm_rpc_token();

/// Maximum size in bytes of a raw eth_sendRawTransaction hex blob (after
/// the optional `0x` prefix). Mirrors `kMaxRpcParamsSize` so the fast path
/// rejects oversized blobs BEFORE the expensive hex/RLP decode.
size_t max_eth_send_raw_tx_hex_size();

/// Test helper: reset rate limiter token buckets to full capacity.
void reset_evm_rpc_rate_limit_for_test();

/// Test helpers for the H-02 inflight-permit gates. Each setter pins
/// the named atomic counter to `value`; the regression tests use them
/// to simulate "another request already running" without spawning
/// real threads. NOT for production use.
void set_readonly_evm_inflight_for_test(uint32_t value);
void set_estimate_gas_inflight_for_test(uint32_t value);
void set_access_list_inflight_for_test(uint32_t value);

}  // namespace evm_workchain
