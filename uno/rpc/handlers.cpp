/*
    Uno Workchain — JSON-RPC facade implementation.

    Surface:  §9.1 of doc/uno-workchain.md
    Shape:    mirrors evm/rpc/handlers.cpp (stateless, single-entry dispatch,
              token-bucket rate limit, pre-serialised JSON-RPC 2.0 responses).

    Dependencies (forward-declared):
      * Agent 1/2's state accessors:
          uno_workchain::snapshot_head_state()   -> HeadStateSnapshot
          uno_workchain::anchor_at_seqno(seqno)  -> optional<bits256>
          uno_workchain::commitment_tree_frontier() -> vector<bytes32>
          uno_workchain::nullifier_lookup(nf)    -> NullifierStatus
      * Agent 5's transaction codec + admission checks:
          uno_workchain::admission::check(raw)   -> AdmissionResult
      * Agent 5's tx-status index:
          uno_workchain::tx_status_lookup(hash)  -> TxStatus

    None of these are in tree yet. We declare them in this file as
    weak-link function pointers (`std::atomic<... (*)(...)>`) with safe
    "unavailable" defaults that return structured JSON-RPC errors. Agents
    1/2/5 install their real implementations from uno/core/init.cpp.
    This keeps the RPC compilation unit self-contained and the tests
    drive-by-hand buildable.

    NOTE(uno-api-v0): JSON schema conventions used below when the doc
    only names a method:
      * 32-byte binary values (nullifiers, commitments, anchors, tx hashes)
        are 64-char lowercase hex without 0x prefix, per Orchard tooling
        convention. `ivk_hex` follows the same rule.
      * uint64 block seqnos, output indices, fees are JSON numbers (decimal).
      * Hex blobs for uno_sendTransfer accept an optional leading "0x".
*/
#include "uno/rpc/handlers.h"

#include "uno/rpc/filter-service.h"
#include "uno/rpc/metrics.h"
#include "uno/rpc/subscriptions.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace uno_workchain {

// ===========================================================================
// Rate limiting (copies evm/rpc/handlers.cpp's token-bucket pattern)
// ===========================================================================

namespace {

constexpr uint64_t kMaxRpcRequestsPerSec = 100;
constexpr uint64_t kMaxRpcBurst          = 1000;
constexpr uint64_t kMaxSendTxPerSec      = 20;    // tighter: admission does work
constexpr uint64_t kMaxSendTxBurst       = 50;
constexpr size_t   kMaxRpcParamsSize     = 1u << 20;  // 1 MB
constexpr size_t   kMaxSendTxHexSize     = 256 * 1024;  // 256 KB hex ≈ 128 KB binary

struct RateLimiter {
    std::mutex mutex;
    uint64_t   tokens;
    uint64_t   max_tokens;
    uint64_t   refill_rate;
    uint64_t   last_refill;

    RateLimiter(uint64_t max_tok, uint64_t rate)
        : tokens(max_tok), max_tokens(max_tok), refill_rate(rate),
          last_refill(static_cast<uint64_t>(
              std::chrono::duration_cast<std::chrono::seconds>(
                  std::chrono::steady_clock::now().time_since_epoch()).count())) {}

    void refill() {
        uint64_t now = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
        if (now > last_refill) {
            uint64_t added = (now - last_refill) * refill_rate;
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
                std::chrono::steady_clock::now().time_since_epoch()).count());
    }
};

RateLimiter g_rpc_limiter{kMaxRpcBurst, kMaxRpcRequestsPerSec};
RateLimiter g_sendtx_limiter{kMaxSendTxBurst, kMaxSendTxPerSec};
bool        g_rate_limit_enabled = false;

}  // namespace

void enable_uno_rpc_rate_limit(bool enable) {
    g_rate_limit_enabled = enable;
    if (enable) {
        g_rpc_limiter.reset();
        g_sendtx_limiter.reset();
    }
}

// ===========================================================================
// JSON-RPC envelope helpers
// ===========================================================================

namespace {

std::string json_escape(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (unsigned char c : in) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[7];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", (unsigned)c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    return out;
}

std::string make_result(const std::string& id, const std::string& result_json) {
    return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":" + result_json + "}";
}

std::string make_error(const std::string& id, int code, const std::string& msg) {
    return "{\"jsonrpc\":\"2.0\",\"id\":" + id +
           ",\"error\":{\"code\":" + std::to_string(code) +
           ",\"message\":\"" + json_escape(msg) + "\"}}";
}

std::string dec(uint64_t v) {
    return std::to_string((unsigned long long)v);
}

std::string quote_json(const std::string& s) {
    return "\"" + json_escape(s) + "\"";
}

std::string to_hex(const uint8_t* data, size_t len) {
    static const char* H = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[2 * i]     = H[(data[i] >> 4) & 0x0f];
        out[2 * i + 1] = H[data[i] & 0x0f];
    }
    return out;
}

bool from_hex_byte(char c, uint8_t& out) {
    if (c >= '0' && c <= '9') { out = (uint8_t)(c - '0'); return true; }
    if (c >= 'a' && c <= 'f') { out = (uint8_t)(c - 'a' + 10); return true; }
    if (c >= 'A' && c <= 'F') { out = (uint8_t)(c - 'A' + 10); return true; }
    return false;
}

/// Decode a hex string into a fixed-size output buffer. Accepts an optional
/// leading 0x. Returns true iff the input had exactly 2*N non-0x hex chars.
template <size_t N>
bool hex_to_fixed(const std::string& s, std::array<uint8_t, N>& out) {
    const char* p = s.c_str();
    size_t      n = s.size();
    if (n >= 2 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) { p += 2; n -= 2; }
    if (n != 2 * N) return false;
    for (size_t i = 0; i < N; ++i) {
        uint8_t hi, lo;
        if (!from_hex_byte(p[2 * i], hi))     return false;
        if (!from_hex_byte(p[2 * i + 1], lo)) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

bool hex_to_bytes(const std::string& s, std::vector<uint8_t>& out) {
    const char* p = s.c_str();
    size_t      n = s.size();
    if (n >= 2 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) { p += 2; n -= 2; }
    if (n % 2 != 0) return false;
    out.resize(n / 2);
    for (size_t i = 0; i < n / 2; ++i) {
        uint8_t hi, lo;
        if (!from_hex_byte(p[2 * i], hi))     return false;
        if (!from_hex_byte(p[2 * i + 1], lo)) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

// ---------------------------------------------------------------------------
// Extremely permissive params parser.
//
// The validator-engine wraps array-style params for us (we always get the raw
// JSON params-array text). We don't pull in a full JSON dep here — the calls
// in §9.1 are all { } or [ ] of hex strings + small ints. We extract the i-th
// JSON string literal or the i-th JSON number. Matches evm/rpc's approach.
// ---------------------------------------------------------------------------

/// Extract the N-th JSON string literal from `params` (0-indexed). Returns
/// false if not enough strings were present.
bool extract_nth_string(const std::string& params, size_t n, std::string& out) {
    size_t pos = 0;
    size_t seen = 0;
    while (pos < params.size()) {
        // Skip to the next unescaped double-quote
        if (params[pos] != '"') { ++pos; continue; }
        size_t start = pos + 1;
        size_t end   = start;
        while (end < params.size()) {
            if (params[end] == '\\' && end + 1 < params.size()) { end += 2; continue; }
            if (params[end] == '"') break;
            ++end;
        }
        if (end >= params.size()) return false;
        if (seen == n) {
            out.assign(params, start, end - start);
            return true;
        }
        ++seen;
        pos = end + 1;
    }
    return false;
}

/// Extract the N-th JSON number literal (0-indexed) that occurs OUTSIDE any
/// string. Returns it as a uint64; negatives / fractions / too-large values
/// are rejected as parse errors.
bool extract_nth_uint(const std::string& params, size_t n, uint64_t& out) {
    size_t pos  = 0;
    size_t seen = 0;
    while (pos < params.size()) {
        char c = params[pos];
        if (c == '"') {
            // Skip over the whole string, honouring backslash escapes.
            ++pos;
            while (pos < params.size()) {
                if (params[pos] == '\\' && pos + 1 < params.size()) { pos += 2; continue; }
                if (params[pos] == '"') { ++pos; break; }
                ++pos;
            }
            continue;
        }
        if (std::isdigit(static_cast<unsigned char>(c))) {
            size_t start = pos;
            while (pos < params.size() && std::isdigit(static_cast<unsigned char>(params[pos]))) ++pos;
            if (seen == n) {
                try {
                    out = std::stoull(params.substr(start, pos - start));
                    return true;
                } catch (...) { return false; }
            }
            ++seen;
            continue;
        }
        ++pos;
    }
    return false;
}

}  // namespace

// ===========================================================================
// Upstream accessor hooks — set by Agent 1/2/5 at init time.
// ===========================================================================
//
// The accessors are std::atomic function pointers with nullptr defaults.
// When unset, every handler returns a JSON-RPC "uno state unavailable" error
// so that the RPC layer is runnable without upstream — useful both for the
// test scaffolding and for "RPC module loaded but state not bootstrapped"
// edge cases at validator-engine startup.
//
// The accessor types + setters are declared in uno/rpc/handlers.h so that
// upstream registration code can include exactly one header to bind.

namespace {

std::atomic<HeadStateFn>         g_head_state{nullptr};
std::atomic<AnchorAtSeqnoFn>     g_anchor_at_seqno{nullptr};
std::atomic<FrontierFn>          g_frontier{nullptr};
std::atomic<NullifierLookupFn>   g_nullifier_lookup{nullptr};
std::atomic<AdmissionCheckFn>    g_admission_check{nullptr};
std::atomic<EstimateFeeFn>       g_estimate_fee{nullptr};
std::atomic<TxStatusLookupFn>    g_tx_status{nullptr};
std::atomic<OutputsForIvkFn>     g_outputs_for_ivk{nullptr};
std::atomic<SubmitExternalMessageFn> g_submit_ext{nullptr};

}  // namespace

void set_submit_external_message_hook(SubmitExternalMessageFn fn) {
    g_submit_ext.store(fn, std::memory_order_release);
}

// Setter definitions for the upstream-accessor hooks declared in handlers.h.
// Agents 1/2/5 call these from uno/core/init.cpp at validator-engine startup.
void set_head_state_fn(HeadStateFn fn)                 { g_head_state.store(fn); }
void set_anchor_at_seqno_fn(AnchorAtSeqnoFn fn)        { g_anchor_at_seqno.store(fn); }
void set_frontier_fn(FrontierFn fn)                    { g_frontier.store(fn); }
void set_nullifier_lookup_fn(NullifierLookupFn fn)     { g_nullifier_lookup.store(fn); }
void set_admission_check_fn(AdmissionCheckFn fn)       { g_admission_check.store(fn); }
void set_estimate_fee_fn(EstimateFeeFn fn)             { g_estimate_fee.store(fn); }
void set_tx_status_fn(TxStatusLookupFn fn)             { g_tx_status.store(fn); }
void set_outputs_for_ivk_fn(OutputsForIvkFn fn)        { g_outputs_for_ivk.store(fn); }

void reset_uno_rpc_state_for_test() {
    g_rpc_limiter.reset();
    g_sendtx_limiter.reset();
    g_rate_limit_enabled = false;
    g_head_state.store(nullptr);
    g_anchor_at_seqno.store(nullptr);
    g_frontier.store(nullptr);
    g_nullifier_lookup.store(nullptr);
    g_admission_check.store(nullptr);
    g_estimate_fee.store(nullptr);
    g_tx_status.store(nullptr);
    g_outputs_for_ivk.store(nullptr);
    g_submit_ext.store(nullptr);
    reset_filter_service_for_test();
    global_uno_subscription_manager().reset_for_test();
}

// ===========================================================================
// JSON-RPC error codes (§9.1 vocabulary; stable by convention)
// ===========================================================================

namespace {
constexpr int kErrInvalidParams       = -32602;
constexpr int kErrInternal            = -32603;
constexpr int kErrRateLimited         = -32005;
constexpr int kErrTooLarge            = -32600;
constexpr int kErrStateUnavailable    = -32010;  // upstream not wired
constexpr int kErrNotReadyYet         = -32011;  // filter for seqno not committed
constexpr int kErrAdmissionRejected   = -32020;  // sendTransfer pre-filter
constexpr int kErrSubmitUnavailable   = -32021;  // no external-msg hook
}  // namespace

// ===========================================================================
// Per-method handlers
// ===========================================================================

namespace {

// ---- uno_chainInfo --------------------------------------------------------

std::optional<RpcResult> handle_chain_info(const std::string& /*params*/,
                                            const std::string& id) {
    auto fn = g_head_state.load(std::memory_order_acquire);
    if (!fn) {
        return RpcResult{make_error(id, kErrStateUnavailable,
                                    "uno head state unavailable"), true};
    }
    auto snap = fn();

    // NOTE(uno-api-v0): active_schemes is a JSON array of hex-encoded
    // single-byte scheme ids. v1 ships exactly ["01"].
    std::string json = "{";
    json += "\"chain_id\":"            + dec(snap.chain_id) + ",";
    json += "\"workchain_id\":"        + dec(snap.workchain_id) + ",";
    json += "\"head_seqno\":"          + dec(snap.head_seqno) + ",";
    json += "\"executor\":"            + quote_json(to_hex(snap.executor_address.data(), 32)) + ",";
    json += "\"active_schemes\":[\""   + to_hex(&snap.scheme_id, 1) + "\"],";
    json += "\"anchor_window_size\":"  + dec(snap.anchor_window_size);
    json += "}";
    return RpcResult{make_result(id, json), false};
}

// ---- uno_getAnchor --------------------------------------------------------

std::optional<RpcResult> handle_get_anchor(const std::string& /*params*/,
                                            const std::string& id) {
    auto fn = g_head_state.load(std::memory_order_acquire);
    if (!fn) {
        return RpcResult{make_error(id, kErrStateUnavailable,
                                    "uno head state unavailable"), true};
    }
    auto snap = fn();

    std::string window = "[";
    for (size_t i = 0; i < snap.anchor_window.size(); ++i) {
        if (i) window += ",";
        window += quote_json(to_hex(snap.anchor_window[i].data(), 32));
    }
    window += "]";

    std::string json = "{";
    json += "\"commitment_tree_root\":" + quote_json(to_hex(snap.current_anchor_root.data(), 32)) + ",";
    json += "\"head_seqno\":"           + dec(snap.head_seqno) + ",";
    json += "\"anchor_window\":"        + window;
    json += "}";
    return RpcResult{make_result(id, json), false};
}

// ---- uno_getAnchorAtSeqno -------------------------------------------------

std::optional<RpcResult> handle_get_anchor_at_seqno(const std::string& params,
                                                     const std::string& id) {
    uint64_t seqno = 0;
    if (!extract_nth_uint(params, 0, seqno)) {
        return RpcResult{make_error(id, kErrInvalidParams,
                                    "expected [uint seqno]"), true};
    }
    auto fn = g_anchor_at_seqno.load(std::memory_order_acquire);
    if (!fn) {
        return RpcResult{make_error(id, kErrStateUnavailable,
                                    "uno anchor index unavailable"), true};
    }
    auto anchor = fn(seqno);
    if (!anchor) {
        return RpcResult{make_result(id, "null"), false};
    }
    std::string json = "{";
    json += "\"seqno\":"  + dec(seqno) + ",";
    json += "\"anchor\":" + quote_json(to_hex(anchor->data(), 32));
    json += "}";
    return RpcResult{make_result(id, json), false};
}

// ---- uno_getCommitmentTreeFrontier ----------------------------------------

std::optional<RpcResult> handle_get_frontier(const std::string& /*params*/,
                                              const std::string& id) {
    auto fn = g_frontier.load(std::memory_order_acquire);
    if (!fn) {
        return RpcResult{make_error(id, kErrStateUnavailable,
                                    "uno frontier unavailable"), true};
    }
    auto frontier = fn();
    std::string json = "{\"frontier\":[";
    for (size_t i = 0; i < frontier.size(); ++i) {
        if (i) json += ",";
        json += quote_json(to_hex(frontier[i].data(), 32));
    }
    json += "],\"depth\":" + dec(frontier.size()) + "}";
    return RpcResult{make_result(id, json), false};
}

// ---- uno_getNullifierStatus ------------------------------------------------

std::optional<RpcResult> handle_get_nullifier_status(const std::string& params,
                                                      const std::string& id) {
    std::string nf_hex;
    if (!extract_nth_string(params, 0, nf_hex)) {
        return RpcResult{make_error(id, kErrInvalidParams,
                                    "expected [string nf_hex]"), true};
    }
    std::array<uint8_t, 32> nf{};
    if (!hex_to_fixed<32>(nf_hex, nf)) {
        return RpcResult{make_error(id, kErrInvalidParams,
                                    "nf must be 32-byte hex"), true};
    }
    auto fn = g_nullifier_lookup.load(std::memory_order_acquire);
    if (!fn) {
        return RpcResult{make_error(id, kErrStateUnavailable,
                                    "uno nullifier set unavailable"), true};
    }
    auto status = fn(nf.data());
    std::string json = "{";
    json += "\"spent\":";
    json += (status.state == NullifierState::Spent ? "true" : "false");
    if (status.state == NullifierState::Spent && status.block_seqno.has_value()) {
        json += ",\"block_seqno\":" + dec(*status.block_seqno);
    }
    json += "}";
    return RpcResult{make_result(id, json), false};
}

// ---- uno_getOutputsAtBlock -------------------------------------------------

std::optional<RpcResult> handle_get_outputs_at_block(const std::string& params,
                                                      const std::string& id) {
    uint64_t seqno = 0, from_idx = 0, limit = 0;
    if (!extract_nth_uint(params, 0, seqno)   ||
        !extract_nth_uint(params, 1, from_idx) ||
        !extract_nth_uint(params, 2, limit)) {
        return RpcResult{make_error(id, kErrInvalidParams,
                                    "expected [uint seqno, uint from_index, uint limit]"), true};
    }
    if (limit == 0 || limit > kMaxOutputsPerPage) {
        limit = kMaxOutputsPerPage;
    }
    auto page = fetch_outputs_at_block(seqno, from_idx, limit);
    if (!page) {
        return RpcResult{make_error(id, kErrNotReadyYet,
                                    "block outputs not yet indexed"), true};
    }
    std::string outs = "[";
    for (size_t i = 0; i < page->outputs.size(); ++i) {
        if (i) outs += ",";
        outs += "{\"index\":" + dec(page->outputs[i].global_index);
        // raw OutputDescription wire bytes are already stored as hex here.
        // We surface them directly so wallet code doesn't need to know the
        // TLV layout.
        std::vector<uint8_t> tmp(page->outputs[i].bytes.begin(),
                                 page->outputs[i].bytes.end());
        outs += ",\"bytes\":" + quote_json(to_hex(tmp.data(), tmp.size())) + "}";
    }
    outs += "]";
    std::string json = "{";
    json += "\"seqno\":"          + dec(page->block_seqno) + ",";
    json += "\"from_index\":"     + dec(page->from_index) + ",";
    json += "\"total_in_block\":" + dec(page->total_in_block) + ",";
    json += "\"outputs\":"        + outs;
    json += "}";
    return RpcResult{make_result(id, json), false};
}

// ---- uno_getBlockFilter ----------------------------------------------------

std::optional<RpcResult> handle_get_block_filter(const std::string& params,
                                                  const std::string& id) {
    uint64_t seqno = 0;
    if (!extract_nth_uint(params, 0, seqno)) {
        return RpcResult{make_error(id, kErrInvalidParams,
                                    "expected [uint seqno]"), true};
    }
    auto blob = fetch_block_filter(seqno);
    if (!blob) {
        return RpcResult{make_error(id, kErrNotReadyYet,
                                    "filter for this seqno not yet committed"), true};
    }
    std::vector<uint8_t> tmp(blob->gcs_bytes.begin(), blob->gcs_bytes.end());
    std::string json = "{";
    json += "\"seqno\":"           + dec(blob->block_seqno) + ",";
    json += "\"filter_tag_bits\":" + dec(blob->filter_tag_bits) + ",";
    json += "\"p\":"               + dec(blob->p_param) + ",";
    json += "\"gcs\":"             + quote_json(to_hex(tmp.data(), tmp.size()));
    json += "}";
    return RpcResult{make_result(id, json), false};
}

// ---- uno_getOutputsForIvk  (OPT-IN, privacy-weakening — §9.2) --------------

std::optional<RpcResult> handle_get_outputs_for_ivk(const std::string& params,
                                                     const std::string& id) {
    std::string ivk_hex;
    if (!extract_nth_string(params, 0, ivk_hex)) {
        return RpcResult{make_error(id, kErrInvalidParams,
                                    "expected [string ivk_hex]"), true};
    }
    std::array<uint8_t, 32> ivk{};
    if (!hex_to_fixed<32>(ivk_hex, ivk)) {
        return RpcResult{make_error(id, kErrInvalidParams,
                                    "ivk must be 32-byte hex"), true};
    }

    // HARD REQUIREMENT (§9.2): log a privacy warning to the server log every
    // time this handler is invoked, so operators can audit their own use.
    std::fprintf(stderr,
        "[uno_rpc] PRIVACY WARNING: uno_getOutputsForIvk invoked; server has\n"
        "                            received an ivk and will trial-decrypt\n"
        "                            on behalf of the client. This weakens\n"
        "                            privacy — server learns which outputs\n"
        "                            belong to this wallet. Never enable this\n"
        "                            in a public-facing node without explicit\n"
        "                            operator and user consent.\n");

    auto fn = g_outputs_for_ivk.load(std::memory_order_acquire);
    if (!fn) {
        // Note the warning still fired above — that is intentional: the
        // privacy warning is about *intent*, not successful execution.
        return RpcResult{make_error(id, kErrStateUnavailable,
                                    "uno server-assisted scan backend unavailable"), true};
    }
    auto matches = fn(ivk.data());

    // §9.2 also says the response body itself SHOULD include a `warning`
    // field so unsophisticated wallet UIs that dump "warning" straight to
    // screen will surface it even without our other best-effort channels.
    std::string outs = "[";
    for (size_t i = 0; i < matches.size(); ++i) {
        if (i) outs += ",";
        outs += "{\"index\":" + dec(matches[i].global_index);
        std::vector<uint8_t> tmp(matches[i].bytes.begin(), matches[i].bytes.end());
        outs += ",\"bytes\":" + quote_json(to_hex(tmp.data(), tmp.size())) + "}";
    }
    outs += "]";

    std::string json = "{";
    json += "\"matches\":" + outs + ",";
    json += "\"warning\":" + quote_json(
        "server-assisted scan: this RPC exposes your ivk to the server; "
        "server learns which on-chain outputs belong to you. "
        "Prefer compact-filter scan (uno_getBlockFilter + uno_getOutputsAtBlock).");
    json += "}";
    return RpcResult{make_result(id, json), false};
}

// ---- uno_estimateFee ------------------------------------------------------

std::optional<RpcResult> handle_estimate_fee(const std::string& params,
                                              const std::string& id) {
    uint64_t n_spends = 0, n_outputs = 0;
    if (!extract_nth_uint(params, 0, n_spends) ||
        !extract_nth_uint(params, 1, n_outputs)) {
        return RpcResult{make_error(id, kErrInvalidParams,
                                    "expected [uint n_spends, uint n_outputs]"), true};
    }
    // Delegate to the chain-config-aware estimator if registered; otherwise
    // compute a best-effort estimate from the snapshot.
    uint64_t fee = 0;
    if (auto fn = g_estimate_fee.load(std::memory_order_acquire)) {
        fee = fn(static_cast<uint32_t>(n_spends), static_cast<uint32_t>(n_outputs));
    } else if (auto hs = g_head_state.load(std::memory_order_acquire)) {
        auto snap = hs();
        // Tx-size estimate: base 128 bytes of header + ~150 per spend + ~1200 per
        // output (dominated by mlkem_ct ~1.1 KB). This is an order-of-magnitude
        // rough cut; the real estimator in Agent 5 uses the exact encoding.
        uint64_t est_bytes = 128 + n_spends * 150 + n_outputs * 1200;
        fee = snap.min_fee_nano
            + snap.fee_per_byte_nano   * est_bytes
            + snap.fee_per_spend_nano  * n_spends
            + snap.fee_per_output_nano * n_outputs;
    } else {
        return RpcResult{make_error(id, kErrStateUnavailable,
                                    "uno fee config unavailable"), true};
    }
    std::string json = "{";
    json += "\"fee_nano\":"  + dec(fee) + ",";
    json += "\"n_spends\":"  + dec(n_spends) + ",";
    json += "\"n_outputs\":" + dec(n_outputs);
    json += "}";
    return RpcResult{make_result(id, json), false};
}

// ---- uno_sendTransfer -----------------------------------------------------
//
// §4.3a admission subset (syntax, anchor, LRU, sigs), then external-message
// submit. Plonky3 proof verify is DELIBERATELY not run here — it is the
// expensive step and is deferred to the compute phase (§4.3 step 4).

std::optional<RpcResult> handle_send_transfer(const std::string& params,
                                               const std::string& id) {
    if (g_rate_limit_enabled && !g_sendtx_limiter.try_consume()) {
        return RpcResult{make_error(id, kErrRateLimited,
                                    "uno_sendTransfer rate limit exceeded"), true};
    }

    std::string blob_hex;
    if (!extract_nth_string(params, 0, blob_hex)) {
        return RpcResult{make_error(id, kErrInvalidParams,
                                    "expected [string hex_blob]"), true};
    }
    if (blob_hex.size() > kMaxSendTxHexSize) {
        return RpcResult{make_error(id, kErrTooLarge,
                                    "hex_blob exceeds max tx size"), true};
    }
    std::vector<uint8_t> bytes;
    if (!hex_to_bytes(blob_hex, bytes)) {
        return RpcResult{make_error(id, kErrInvalidParams,
                                    "hex_blob is not valid hex"), true};
    }

    auto admit = g_admission_check.load(std::memory_order_acquire);
    if (!admit) {
        return RpcResult{make_error(id, kErrStateUnavailable,
                                    "uno admission check unavailable"), true};
    }
    auto ar = admit(bytes.data(), bytes.size());
    if (!ar.ok) {
        std::string why;
        switch (ar.reason) {
            case AdmissionRejectReason::Malformed:        why = "malformed"; break;
            case AdmissionRejectReason::WrongChainId:     why = "wrong chain_id"; break;
            case AdmissionRejectReason::BadVersion:       why = "bad version / scheme_id"; break;
            case AdmissionRejectReason::ExpiryOutOfRange: why = "expiry_block out of range"; break;
            case AdmissionRejectReason::TooManySpends:    why = "spend_count out of [1,4]"; break;
            case AdmissionRejectReason::TooManyOutputs:   why = "output_count out of [1,4]"; break;
            case AdmissionRejectReason::FeeBelowMin:      why = "fee below minimum"; break;
            case AdmissionRejectReason::StaleAnchor:      why = "anchor not in window"; break;
            case AdmissionRejectReason::DuplicateNf:      why = "duplicate nullifier within tx"; break;
            case AdmissionRejectReason::DuplicateCm:      why = "duplicate commitment within tx"; break;
            case AdmissionRejectReason::BadPoint:         why = "ristretto point decompression failed"; break;
            case AdmissionRejectReason::NullifierSeen:    why = "nullifier already spent (LRU hit)"; break;
            case AdmissionRejectReason::BadSpendAuthSig:  why = "bad spend_auth_sig"; break;
            case AdmissionRejectReason::UnavailableState: why = "state unavailable"; break;
            default:                                       why = "rejected"; break;
        }
        return RpcResult{make_error(id, kErrAdmissionRejected,
                                    "admission rejected: " + why), true};
    }

    auto submit = g_submit_ext.load(std::memory_order_acquire);
    if (!submit) {
        return RpcResult{make_error(id, kErrSubmitUnavailable,
                                    "external-message submit hook not installed"), true};
    }
    std::string tx_str(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    if (!submit(tx_str, ar.tx_hash.data())) {
        return RpcResult{make_error(id, kErrInternal,
                                    "ext-message submit failed"), true};
    }

    std::string hash_hex = to_hex(ar.tx_hash.data(), 32);
    std::string json = "{\"tx_hash\":" + quote_json(hash_hex) + "}";
    return RpcResult{make_result(id, json), false};
}

// ---- uno_getTransactionStatus ---------------------------------------------

std::optional<RpcResult> handle_get_transaction_status(const std::string& params,
                                                        const std::string& id) {
    std::string tx_hex;
    if (!extract_nth_string(params, 0, tx_hex)) {
        return RpcResult{make_error(id, kErrInvalidParams,
                                    "expected [string tx_hash_hex]"), true};
    }
    std::array<uint8_t, 32> h{};
    if (!hex_to_fixed<32>(tx_hex, h)) {
        return RpcResult{make_error(id, kErrInvalidParams,
                                    "tx_hash must be 32-byte hex"), true};
    }
    auto fn = g_tx_status.load(std::memory_order_acquire);
    if (!fn) {
        return RpcResult{make_error(id, kErrStateUnavailable,
                                    "uno tx status index unavailable"), true};
    }
    auto st = fn(h.data());
    std::string json = "{";
    switch (st.kind) {
        case TxStatusKind::Pending:
            json += "\"status\":\"pending\"";
            break;
        case TxStatusKind::Included:
            json += "\"status\":\"included\"";
            if (st.block_seqno) json += ",\"block_seqno\":" + dec(*st.block_seqno);
            break;
        case TxStatusKind::Rejected:
            json += "\"status\":\"rejected\"";
            if (!st.reason.empty()) json += ",\"reason\":" + quote_json(st.reason);
            break;
        case TxStatusKind::Unknown:
        default:
            json += "\"status\":\"unknown\"";
            break;
    }
    json += "}";
    return RpcResult{make_result(id, json), false};
}

// ---- uno_subscribe / uno_unsubscribe / uno_getSubscription -----------------
//
// Mirrors eth_subscribe. Kept minimal: three channels (includedTx, newHead,
// newAnchor). The polling variant (`uno_getSubscription`) is the drain path;
// WebSocket push is a deferred follow-up.

std::optional<RpcResult> handle_subscribe(const std::string& params,
                                           const std::string& id) {
    std::string channel;
    if (!extract_nth_string(params, 0, channel)) {
        return RpcResult{make_error(id, kErrInvalidParams,
                                    "expected [string channel]"), true};
    }
    UnoSubscriptionType t;
    if      (channel == "includedTx") t = UnoSubscriptionType::IncludedTx;
    else if (channel == "newHead")    t = UnoSubscriptionType::NewHead;
    else if (channel == "newAnchor")  t = UnoSubscriptionType::NewAnchor;
    else {
        return RpcResult{make_error(id, kErrInvalidParams,
                                    "unknown subscription channel: " + channel), true};
    }
    uint64_t sub_id = global_uno_subscription_manager().subscribe(t);
    std::string json = quote_json(to_hex(reinterpret_cast<const uint8_t*>(&sub_id), sizeof(sub_id)));
    return RpcResult{make_result(id, json), false};
}

std::optional<RpcResult> handle_unsubscribe(const std::string& params,
                                             const std::string& id) {
    std::string sub_id_hex;
    if (!extract_nth_string(params, 0, sub_id_hex)) {
        return RpcResult{make_error(id, kErrInvalidParams,
                                    "expected [string sub_id]"), true};
    }
    std::array<uint8_t, sizeof(uint64_t)> raw{};
    if (!hex_to_fixed<sizeof(uint64_t)>(sub_id_hex, raw)) {
        return RpcResult{make_error(id, kErrInvalidParams,
                                    "sub_id must be 8-byte hex"), true};
    }
    uint64_t sub_id = 0;
    std::memcpy(&sub_id, raw.data(), sizeof(sub_id));
    bool ok = global_uno_subscription_manager().unsubscribe(sub_id);
    return RpcResult{make_result(id, ok ? "true" : "false"), false};
}

// ---- uno_getMetrics (K-uno-metrics) ---------------------------------------
//
// Returns the Prometheus text-format exposition of every `uno_*` metric as
// a single JSON string field. No separate HTTP endpoint — operators scrape
// this through the existing JSON-RPC facade and pipe the `metrics` field
// into their time-series store. Content is self-describing (# HELP / # TYPE
// preamble on every family).

std::optional<RpcResult> handle_get_metrics(const std::string& /*params*/,
                                             const std::string& id) {
    std::string exposition = global_metrics_registry().render_prometheus();
    std::string json = "{";
    json += "\"content_type\":\"text/plain; version=0.0.4\",";
    json += "\"metrics\":" + quote_json(exposition);
    json += "}";
    return RpcResult{make_result(id, json), false};
}

std::optional<RpcResult> handle_get_subscription(const std::string& params,
                                                  const std::string& id) {
    std::string sub_id_hex;
    if (!extract_nth_string(params, 0, sub_id_hex)) {
        return RpcResult{make_error(id, kErrInvalidParams,
                                    "expected [string sub_id]"), true};
    }
    std::array<uint8_t, sizeof(uint64_t)> raw{};
    if (!hex_to_fixed<sizeof(uint64_t)>(sub_id_hex, raw)) {
        return RpcResult{make_error(id, kErrInvalidParams,
                                    "sub_id must be 8-byte hex"), true};
    }
    uint64_t sub_id = 0;
    std::memcpy(&sub_id, raw.data(), sizeof(sub_id));
    auto events = global_uno_subscription_manager().poll(sub_id);
    std::string json = "[";
    for (size_t i = 0; i < events.size(); ++i) {
        if (i) json += ",";
        json += events[i].json;
    }
    json += "]";
    return RpcResult{make_result(id, json), false};
}

}  // namespace

// ===========================================================================
// Public entry points
// ===========================================================================

bool is_uno_rpc_method(const std::string& method) noexcept {
    return method == "uno_chainInfo" ||
           method == "uno_getAnchor" ||
           method == "uno_getAnchorAtSeqno" ||
           method == "uno_getCommitmentTreeFrontier" ||
           method == "uno_getNullifierStatus" ||
           method == "uno_getOutputsAtBlock" ||
           method == "uno_getBlockFilter" ||
           method == "uno_getOutputsForIvk" ||
           method == "uno_estimateFee" ||
           method == "uno_sendTransfer" ||
           method == "uno_getTransactionStatus" ||
           method == "uno_getMetrics" ||
           method == "uno_subscribe" ||
           method == "uno_unsubscribe" ||
           method == "uno_getSubscription";
}

std::optional<RpcResult> handle_uno_rpc(
    const std::string& method,
    const std::string& params,
    const std::string& id) {

    if (params.size() > kMaxRpcParamsSize) {
        return RpcResult{make_error(id, kErrTooLarge,
                                    "request params exceed max size"), true};
    }

    if (g_rate_limit_enabled && method != "uno_sendTransfer") {
        // sendTransfer has its own, tighter limiter applied in the handler.
        if (!g_rpc_limiter.try_consume()) {
            return RpcResult{make_error(id, kErrRateLimited, "rate limit exceeded"), true};
        }
    }

    if (method == "uno_chainInfo")                 return handle_chain_info(params, id);
    if (method == "uno_getAnchor")                 return handle_get_anchor(params, id);
    if (method == "uno_getAnchorAtSeqno")          return handle_get_anchor_at_seqno(params, id);
    if (method == "uno_getCommitmentTreeFrontier") return handle_get_frontier(params, id);
    if (method == "uno_getNullifierStatus")        return handle_get_nullifier_status(params, id);
    if (method == "uno_getOutputsAtBlock")         return handle_get_outputs_at_block(params, id);
    if (method == "uno_getBlockFilter")            return handle_get_block_filter(params, id);
    if (method == "uno_getOutputsForIvk")          return handle_get_outputs_for_ivk(params, id);
    if (method == "uno_estimateFee")               return handle_estimate_fee(params, id);
    if (method == "uno_sendTransfer")              return handle_send_transfer(params, id);
    if (method == "uno_getTransactionStatus")      return handle_get_transaction_status(params, id);
    if (method == "uno_getMetrics")                return handle_get_metrics(params, id);
    if (method == "uno_subscribe")                 return handle_subscribe(params, id);
    if (method == "uno_unsubscribe")               return handle_unsubscribe(params, id);
    if (method == "uno_getSubscription")           return handle_get_subscription(params, id);

    return std::nullopt;
}

}  // namespace uno_workchain
