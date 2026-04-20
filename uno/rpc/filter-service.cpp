/*
    Uno Workchain — filter-service implementation.

    This file is intentionally a thin adapter layer. The real work happens
    upstream:
      * Agent 2's uno/core/block-filter.* compiles the per-block GCS filter
        at the end-of-block hook (§5.7, §7.7 step 9).
      * Agent 1/2's uno/core/state.* and cell-state.* maintain the
        per-block output index.

    This file stores the function pointers registered at init time and
    forwards calls. When either backend is not registered, the corresponding
    fetch returns std::nullopt; the RPC layer turns that into a JSON-RPC
    "filter not ready for this seqno" error.
*/
#include "uno/rpc/filter-service.h"

#include <atomic>

namespace uno_workchain {

namespace {

std::atomic<FilterFetchFn>  g_filter_fetch{nullptr};
std::atomic<OutputsFetchFn> g_outputs_fetch{nullptr};

}  // namespace

void set_filter_fetch_backend(FilterFetchFn fn) {
    g_filter_fetch.store(fn, std::memory_order_release);
}

void set_outputs_fetch_backend(OutputsFetchFn fn) {
    g_outputs_fetch.store(fn, std::memory_order_release);
}

void reset_filter_service_for_test() {
    g_filter_fetch.store(nullptr, std::memory_order_release);
    g_outputs_fetch.store(nullptr, std::memory_order_release);
}

std::optional<BlockFilterBlob> fetch_block_filter(uint64_t seqno) {
    auto fn = g_filter_fetch.load(std::memory_order_acquire);
    if (fn == nullptr) return std::nullopt;
    return fn(seqno);
}

std::optional<OutputsPage> fetch_outputs_at_block(uint64_t seqno,
                                                  uint64_t from_index,
                                                  uint64_t limit) {
    auto fn = g_outputs_fetch.load(std::memory_order_acquire);
    if (fn == nullptr) return std::nullopt;
    if (limit > kMaxOutputsPerPage) limit = kMaxOutputsPerPage;
    return fn(seqno, from_index, limit);
}

}  // namespace uno_workchain
