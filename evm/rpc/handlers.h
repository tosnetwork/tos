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
#include <string_view>
#include <functional>

namespace evm_workchain {

/// Result of an RPC call: JSON string to return to the caller.
struct RpcResult {
    std::string json;
    bool is_error{false};
};

/// Handle an eth_* JSON-RPC request.
///
/// @param method     The method name (e.g. "eth_chainId").
/// @param params     The raw JSON params array as a string.
/// @param id         The request id (number or string) to echo back.
/// @param source_ip  Source IP string of the caller, used for the
///                   in-process per-IP rate-limit gate. Pass an empty
///                   view to bypass per-IP gating (test harnesses,
///                   internal callers). The contents of the view are
///                   not retained beyond the call.
/// @return           RpcResult with the JSON-RPC response, or std::nullopt
///                   if this method is not handled by the EVM RPC facade.
std::optional<RpcResult> handle_eth_rpc(
    const std::string& method,
    const std::string& params,
    const std::string& id,
    std::string_view source_ip);

/// Backwards-compatible overload: pass an empty source-IP. Prefer the
/// 4-argument form on every public dispatch path so the per-IP gate
/// has visibility into untrusted clients. This 3-argument form is
/// retained for in-process callers (test harnesses, EVM internal
/// reflection paths) that have no IP to attribute the call to.
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

/// JSON-RPC node profile selector. The active profile drives every
/// security-sensitive surface of the EVM RPC handlers in lockstep:
///   - which read-only EVM RPC methods (eth_call / eth_estimateGas /
///     eth_createAccessList) are enabled at all;
///   - the per-request read-only gas cap;
///   - whether debug_* RPC methods are exposed even when
///     `TOS_ENABLE_EVM_DEBUG_RPC` is compiled in.
/// `eth_getProof` is unconditionally unsupported: TOS EVM commits
/// state via TOS-native cell hashes, not Ethereum MPT proofs, so the
/// dispatcher always returns -32601 for that method. There is no
/// profile or policy toggle that re-enables it.
///
/// `ValidatorMinimal` is the safest default: it pins consensus nodes
/// behind the "minimal" surface (stop heavy read-only RPC from
/// competing for the global EVM state mutex). `FollowerPublic` is for
/// dedicated public RPC replicas that don't run consensus.
/// `AdminLocal` is for local-only operator endpoints / conformance
/// suites that need the full RPC API at the higher 30M gas cap. The
/// new profile MUST be set via `set_evm_rpc_profile()`; do NOT scatter
/// per-flag setters across the codebase.
enum class EvmRpcProfile {
    ValidatorMinimal,   ///< validator nodes — minimal heavy read-only RPC
    FollowerPublic,     ///< follower / RPC replica — heavy RPC enabled with limits
    AdminLocal,         ///< local admin / conformance — full caps, debug methods if compiled in
};

/// Set the active EVM RPC profile. Must be called before serving RPC.
/// Resets per-method rate buckets and inflight counters and re-applies
/// every profile-dependent toggle (gas cap, debug allowlist) atomically.
void set_evm_rpc_profile(EvmRpcProfile profile);

/// Read the currently active EVM RPC profile. Snapshot only — readers
/// must not depend on a stable value across long sequences of
/// requests.
EvmRpcProfile get_evm_rpc_profile();

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

/// In-process per-IP rate-limit configuration.
///
/// The handler dispatcher consults a fixed-size token-bucket table
/// keyed by an FNV1a-32 hash of the source-IP string. Hash collisions
/// share a bucket — that is acceptable: 1024 buckets keep collision
/// probability low for benign traffic, and adversarial collisions
/// only further restrict the attacker.
///
/// Defaults are conservative — burst of 60 / refill of 30 per second
/// is well above any benign wallet's request rate but still costs an
/// attacker an N-fold amplification to flood the global per-method
/// limiters.
struct PerIpRateConfig {
    double requests_per_sec = 30.0;
    double burst = 60.0;
    /// Power of two. Used as a mask (`hash & (table_size - 1)`).
    uint32_t table_size = 1024;
    /// Default OFF; opted-in by the operator (validator-engine flag,
    /// or `evm_workchain::set_per_ip_rate_config`).
    bool enabled = false;
};

/// Apply a new per-IP rate configuration. Resets every bucket to
/// `burst` tokens (so an operator-driven config change does not carry
/// over a drained bucket from the previous policy). `cfg.table_size`
/// must be a power of two that is `<=` the build-time
/// `kPerIpTableSize` cap (1024); larger values silently clamp to the
/// cap, smaller values mask correctly.
void set_per_ip_rate_config(const PerIpRateConfig& cfg);

/// Snapshot of the active per-IP rate configuration. Snapshot only —
/// `enabled` may toggle between this read and the next dispatch.
PerIpRateConfig get_per_ip_rate_config();

/// Returns true if a request from `source_ip` should be allowed
/// through the in-process per-IP gate. Returns false when the bucket
/// is empty; callers MUST translate `false` to JSON-RPC `-32005`
/// (`per-IP rate limit exceeded`). Returns true unconditionally when
/// the gate is disabled or `source_ip` is empty.
bool consume_per_ip_token(std::string_view source_ip);

/// Test helper: refill every per-IP bucket to its burst capacity.
void reset_per_ip_rate_state_for_test();

/// Test helper: returns the FNV1a-32 hash mod `table_size` for a
/// given source-IP string. Used by the regression tests to construct
/// hash collisions deterministically.
uint32_t per_ip_bucket_index_for_test(std::string_view source_ip);

}  // namespace evm_workchain
