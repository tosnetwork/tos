/*
    Uno Workchain — end-of-block filter serving + paginated output fetch.

    Backend for:
      uno_getBlockFilter(seqno)        — per-block GCS compact filter (§9.1)
      uno_getOutputsAtBlock(seqno, from_index, limit)
                                       — paginated raw OutputDescription slab

    The GCS filter is a DERIVED, non-consensus artefact. It is compiled at
    end-of-block by Agent 2's block-filter accumulator (uno/core/block-filter.*);
    this service just caches and serves it. If the request asks for a seqno
    whose filter has not yet been committed, we return an explicit "not ready"
    JSON-RPC error rather than a stale or empty filter.

    The output slab is the concatenation of all OutputDescriptions in a block
    in the exact order they were applied by §4.3 step 5 (apply_transfer). The
    wire encoding is the one defined by Agent 5 in uno/core/cell-codec.* and
    uno/core/transaction.*; this service only indexes by (seqno, idx) and
    returns raw bytes.

    NOTE(uno-api-v0): the interface between this service and Agent 2's
    accumulator is left abstract — we call a C++ accessor, not a specific
    callback. If Agent 2 ships a different shape, the adapter change is
    localised to filter-service.cpp.
*/
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "uno/rpc/handlers.h"   // for OutputRecord (shared contract type)

namespace uno_workchain {

/// A paginated slice of OutputDescriptions for one block.
struct OutputsPage {
    uint64_t                  block_seqno{0};
    uint64_t                  from_index{0};
    uint64_t                  total_in_block{0};
    std::vector<OutputRecord> outputs;
};

/// Result of a compact-filter fetch.
struct BlockFilterBlob {
    uint64_t    block_seqno{0};
    uint8_t     filter_tag_bits{16};   // ships as 16 in v1; widens surface for v2
    uint64_t    p_param{0};             // GCS P parameter; 0 ⇒ filter empty
    std::string gcs_bytes;              // raw GCS-encoded bytes
};

/// Fetch the (cached) per-block GCS filter.
/// Returns nullopt if seqno is beyond current head OR filter has not yet
/// been committed by the end-of-block hook.
std::optional<BlockFilterBlob> fetch_block_filter(uint64_t seqno);

/// Fetch a paginated OutputDescription slice for one block.
///
/// @param seqno       Block sequence number.
/// @param from_index  Zero-based offset into the block's output list.
/// @param limit       Max entries to return (clamped to kMaxOutputsPerPage).
/// @return            std::nullopt if seqno is not yet committed.
std::optional<OutputsPage> fetch_outputs_at_block(uint64_t seqno,
                                                  uint64_t from_index,
                                                  uint64_t limit);

/// Max outputs returned by a single uno_getOutputsAtBlock call. Rejects
/// client pagination requests above this to cap worst-case payload size.
constexpr uint64_t kMaxOutputsPerPage = 1024;

// ---------------------------------------------------------------------------
// Backend-registration surface
//
// Agent 2's block-filter accumulator + Agent 1's per-block output index will
// be registered via the two setters below at validator-engine startup, from
// uno/core/init.{h,cpp}. Until registered, the service returns "not ready"
// JSON-RPC errors, which keeps the RPC compile clean while upstream is still
// being built.
// ---------------------------------------------------------------------------

using FilterFetchFn  = std::optional<BlockFilterBlob>(*)(uint64_t seqno);
using OutputsFetchFn = std::optional<OutputsPage>(*)(uint64_t seqno,
                                                     uint64_t from_index,
                                                     uint64_t limit);

void set_filter_fetch_backend(FilterFetchFn fn);
void set_outputs_fetch_backend(OutputsFetchFn fn);

/// Test helper: drop registered backends (restores "not ready" behaviour).
void reset_filter_service_for_test();

}  // namespace uno_workchain
