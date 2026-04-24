/*
    Uno Workchain — JSON-RPC facade (`uno_*` namespace).

    Mirrors the EVM workchain RPC facade (evm/rpc/handlers.{h,cpp}).
    All `uno_*` methods live on the single executor account at
    (workchain=2, account_id=0x…01) and only ever read the last-committed
    block state (§9.3 of doc/uno-workchain.md — no mempool-projected reads).

    Methods implemented (v1; see design §9.1):
      uno_chainInfo()
      uno_getAnchor()
      uno_getAnchorAtSeqno(seqno)
      uno_getCommitmentTreeFrontier()
      uno_getNullifierStatus(nf_hex)
      uno_getOutputsAtBlock(seqno, from_index, limit)
      uno_getBlockFilter(seqno)
      uno_getOutputsForIvk(ivk_hex)           -- OPT-IN, privacy-weakening
      uno_estimateFee(n_spends, n_outputs)
      uno_sendTransfer(hex_blob)
      uno_getTransactionStatus(tx_hash_hex)
      uno_getMetrics()                        -- K-uno-metrics; Prometheus exposition

    Subscriptions (`uno_subscribe` / `uno_unsubscribe`) are provided in
    rpc/subscriptions.{h,cpp} and mirror `eth_subscribe`.

    NOTE(uno-api-v0): The exact JSON schema for each return object is
    documented inline next to the handler below. Where the design doc
    pins the return shape (e.g. `uno_chainInfo`), we follow it verbatim;
    where it only names the method, we pick a minimal, explicit schema
    (hex strings for binary, decimal for numeric) and call out the
    decision with a `NOTE(uno-api-v0):` comment in the .cpp.
*/
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace uno_workchain {

/// Result of an RPC call: pre-serialised JSON-RPC 2.0 response body.
/// Matches the shape of `evm_workchain::RpcResult`.
struct RpcResult {
    std::string json;
    bool is_error{false};
};

// ===========================================================================
// Accessor contract (RPC ↔ upstream Agents 1 / 2 / 5)
//
// The RPC layer does not know anything about TOS cells, the commitment tree,
// the Plonky3 verifier, or the wire codec. All of that is owned by other
// agents. We communicate with them via the plain structs + function-pointer
// setters below. At validator-engine startup, uno/core/init.{h,cpp} binds
// the real implementations via set_*_fn(...). Until bound, every RPC call
// returns a structured "state unavailable" error, so the process still
// starts cleanly even if uno state has not yet been bootstrapped.
// ===========================================================================

/// Mining-state snapshot used by `uno_getMineState` (wc=2 MineUno PoW).
/// Mirrors the three mutable `mine_*` fields on `UnoShardState`
/// (see `uno/core/state.h`):
///   * `epoch`     — cumulative successful MineUno solves so far (0 at genesis).
///   * `target`    — current PoW difficulty threshold, 32-byte big-endian.
///   * `remaining` — nano-UNO left in the 21 M supply cap.
///
/// Consumed by `tosctl-uno mine`'s `fetch_mine_state()` to pick witness
/// values for the Plonky3 MineUno prover.
struct MineStateSnapshot {
    uint32_t                epoch{0};
    std::array<uint8_t, 32> target{};
    uint64_t                remaining{0};
    // True iff the snapshot reflects state hydrated from a real wc=2
    // ShardState cell (executor account state.data) — not the in-memory
    // construction defaults seeded at process startup. Miners must NOT
    // build proofs against !hydrated snapshots: between validator restart
    // and the first wc=2 compute-phase, the in-memory state has the
    // pre-restart defaults (epoch=0, full supply) which can lag the
    // real chain state. The JSON-RPC handler refuses to serve the
    // snapshot when this is false so `tosctl-uno mine` fails fast
    // rather than searching nonces against a stale target.
    bool                    hydrated{false};
};

/// Per-head snapshot. Populated by Agent 1/2's state reader.
struct HeadStateSnapshot {
    uint32_t    chain_id{0};
    uint32_t    workchain_id{2};
    uint64_t    head_seqno{0};
    uint64_t    anchor_window_size{100};
    uint64_t    min_fee_nano{0};
    uint64_t    fee_per_byte_nano{0};
    uint64_t    fee_per_spend_nano{0};
    uint64_t    fee_per_output_nano{0};
    uint64_t    max_spends_per_tx{4};
    uint64_t    max_outputs_per_tx{4};
    uint8_t     scheme_id{0x01};
    std::array<uint8_t, 32> current_anchor_root{};
    std::array<uint8_t, 32> executor_address{};
    std::vector<std::array<uint8_t, 32>> anchor_window;  // newest-first
};

enum class NullifierState : uint8_t {
    Unknown = 0,
    Spent   = 1,
};

struct NullifierStatusResult {
    NullifierState state{NullifierState::Unknown};
    std::optional<uint64_t> block_seqno;
};

enum class AdmissionRejectReason : uint8_t {
    None             = 0,
    Malformed        = 1,
    WrongChainId     = 2,
    BadVersion       = 3,
    ExpiryOutOfRange = 4,
    TooManySpends    = 5,
    TooManyOutputs   = 6,
    FeeBelowMin      = 7,
    StaleAnchor      = 8,
    DuplicateNf      = 9,
    DuplicateCm      = 10,
    BadPoint         = 11,
    NullifierSeen    = 12,
    BadSpendAuthSig  = 13,
    UnavailableState = 14,
};

struct AdmissionResult {
    bool                    ok{false};
    AdmissionRejectReason   reason{AdmissionRejectReason::None};
    std::array<uint8_t, 32> tx_hash{};
};

enum class TxStatusKind : uint8_t {
    Unknown  = 0,
    Pending  = 1,
    Included = 2,
    Rejected = 3,
};

struct TxStatusResult {
    TxStatusKind            kind{TxStatusKind::Unknown};
    std::optional<uint64_t> block_seqno;
    std::string             reason;  // populated for Rejected
};

/// Per-output raw bytes as handed up from Agent 2's end-of-block indexer.
/// Kept here (not only in filter-service.h) so consumers that only include
/// handlers.h still see the accessor types that depend on it.
struct OutputRecord {
    uint64_t    global_index{0};
    std::string bytes;    // raw OutputDescription wire bytes
};

// --- Accessor function-pointer types ---------------------------------------

using HeadStateFn          = HeadStateSnapshot (*)();
using MineStateFn          = MineStateSnapshot (*)();
using AnchorAtSeqnoFn      = std::optional<std::array<uint8_t, 32>> (*)(uint64_t);
using FrontierFn           = std::vector<std::array<uint8_t, 32>> (*)();
using NullifierLookupFn    = NullifierStatusResult (*)(const uint8_t nf[32]);
using AdmissionCheckFn     = AdmissionResult (*)(const uint8_t* tx_bytes, size_t tx_len);
using EstimateFeeFn        = uint64_t (*)(uint32_t n_spends, uint32_t n_outputs);
using TxStatusLookupFn     = TxStatusResult (*)(const uint8_t tx_hash[32]);
using OutputsForIvkFn      = std::vector<OutputRecord> (*)(const uint8_t ivk[32]);

// --- Accessor setters (called from uno/core/init.cpp) ----------------------

void set_head_state_fn(HeadStateFn fn);
void set_mine_state_fn(MineStateFn fn);
void set_anchor_at_seqno_fn(AnchorAtSeqnoFn fn);
void set_frontier_fn(FrontierFn fn);
void set_nullifier_lookup_fn(NullifierLookupFn fn);
void set_admission_check_fn(AdmissionCheckFn fn);
void set_estimate_fee_fn(EstimateFeeFn fn);
void set_tx_status_fn(TxStatusLookupFn fn);
void set_outputs_for_ivk_fn(OutputsForIvkFn fn);

/// Returns true iff the given method name belongs to the `uno_*` namespace
/// handled by this facade. The json-rpc-server uses this for dispatch.
bool is_uno_rpc_method(const std::string& method) noexcept;

/// Handle a single `uno_*` request.
///
/// @param method  Method name, e.g. "uno_sendTransfer".
/// @param params  The raw JSON params array as a string (same convention as
///                `evm_workchain::handle_eth_rpc`).
/// @param id      Request id to echo back verbatim in the response envelope.
/// @return        Pre-serialised JSON-RPC response, or std::nullopt if the
///                method is not in the `uno_*` registry.
std::optional<RpcResult> handle_uno_rpc(
    const std::string& method,
    const std::string& params,
    const std::string& id);

// ---------------------------------------------------------------------------
// Test / integration hooks
// ---------------------------------------------------------------------------

/// Read the current MineUno consensus state through the installed
/// `MineStateFn` accessor. Used by the validator-engine JSON-RPC handler
/// `uno_getMineState` (see `validator-engine/json-rpc-server-uno.cpp`).
/// Returns `std::nullopt` if no accessor has been bound yet (the UnoState
/// singleton was not initialised) — caller emits a structured JSON-RPC
/// "state unavailable" error in that case.
std::optional<MineStateSnapshot> get_mine_state_snapshot();

/// Reset all per-process RPC state (rate limiter, cached head snapshot, any
/// sticky dispatch state). Intended for unit tests only.
void reset_uno_rpc_state_for_test();

/// Enable or disable RPC-level rate limiting.
/// Disabled by default so test harnesses do not trip it. Production call
/// sites (validator-engine startup) should pass `true`.
void enable_uno_rpc_rate_limit(bool enable);

// ---------------------------------------------------------------------------
// Admission-path hook for uno_sendTransfer
//
// `uno_sendTransfer` runs the §4.3a mempool admission subset locally before
// forwarding the raw bytes as an external message to the wc=2 executor.
// The actual submit path is platform-specific (wraps liteServer_sendMessage
// in production; captures via this hook in tests). Agent 5's transaction
// codec + signature verifiers are invoked transparently; this hook is only
// for the "after admission, submit as external message" step.
// ---------------------------------------------------------------------------

/// Callback signature for external-message submission.
/// @param tx_bytes  Raw Transfer wire bytes (already passed admission).
/// @param tx_hash   32-byte BLAKE3 hash of canonical bytes (§4.3 step 3).
/// @return          true on submit success (goes into mempool / ext msg queue).
using SubmitExternalMessageFn = bool(*)(const std::string& tx_bytes,
                                        const uint8_t tx_hash[32]);

/// Install the external-message submit hook. If unset, `uno_sendTransfer`
/// still runs admission checks but reports a capability error on submit.
void set_submit_external_message_hook(SubmitExternalMessageFn fn);

}  // namespace uno_workchain
