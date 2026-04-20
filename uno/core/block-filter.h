/*
    Uno Workchain (wc=2) — per-block compact filter (§2.8, §9.1).

    Purpose: every `OutputDescription` carries a 16-bit `filter_tag`
    (§2.8 and §4.1). At end of block the validator collects all filter tags
    in the block and compiles them into a Golomb-Coded-Set (GCS) filter for
    the `uno_getBlockFilter` RPC (§9.1). Wallets fetch one compact filter
    per block, match against their own tags, and trial-decrypt only on hit
    — rejecting ~99.99% of non-matching outputs before any AEAD work (§5.8).

    **Not consensus state.** The filter is a derived view of the block; it
    is recomputed by each node and is not folded into the ShardState root.
    This module therefore exposes only an in-memory accumulator + compiled
    byte blob; there is no cell-serialization path.

    GCS parameter choice (v1):
      - P = 19 (Golomb parameter → false-positive rate 2^-P ≈ 1/524288)
      - M = 2^19 = 524288 (hash output range)
    These mirror BIP-158 for Bitcoin compact filters, giving a comfortable
    false-positive rate well below the 2^-16 native filter-tag width. The
    dominant source of FPs for wallets is the 16-bit filter-tag birthday;
    GCS FP is additive and negligible relative to that.

    TODO: the doc does not pin (P, M). Before main net freeze, confirm with
    Agent 5 / Agent 6 (they own RPC) whether wallet SDKs expect a different
    pair. If a different value is adopted, document it alongside the
    `uno_getBlockFilter` RPC contract (§9.1).

    Source: TOS-specific (not copied from upstream).
*/
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace uno_workchain {

/// Filter-tag width is pinned at 16 bits (§2.8, §4.1).
static constexpr std::size_t kFilterTagBits = 16;

/// Golomb-Rice parameter P. False-positive rate = 2^-P.
/// v1 default: 19 (BIP-158).
static constexpr std::uint32_t kGcsP = 19;

/// Hash output range for GCS. v1 default: 2^19.
/// TODO: revisit if wallet SDKs prefer BIP-158's M = N * 2^P with per-block
/// N-dependent M (the "natural" BIP-158 parameterization).
static constexpr std::uint64_t kGcsM = std::uint64_t{1} << 19;

/// Per-block accumulator of filter tags. Populated by `compute-phase.cpp`
/// during §4.3 step 6: for each Output in an accepted tx, the tag is added
/// here. At end-of-block, `compile()` emits the GCS byte blob; the RPC
/// layer serves that blob under `uno_getBlockFilter`.
class BlockFilterBuilder {
  public:
    BlockFilterBuilder();

    /// Add one 16-bit filter tag. Duplicates are allowed at the accumulator
    /// level; the GCS encoder dedups during `compile()` (sorted + uniq).
    void add(std::uint16_t tag);

    /// Number of tags currently buffered.
    std::size_t size() const noexcept { return tags_.size(); }

    /// True iff no tags have been added.
    bool empty() const noexcept { return tags_.empty(); }

    /// Reset for the next block. Called by the compute phase after
    /// `compile()` has been handed to the RPC layer.
    void reset() noexcept { tags_.clear(); }

    /// Compile the accumulated tags into a GCS byte blob. The result is a
    /// stand-alone self-describing buffer:
    ///
    ///   N        : varint     // number of tags
    ///   body     : N hashed values encoded as sorted-differences in
    ///                          Golomb-Rice (P = kGcsP, M = kGcsM)
    ///
    /// The blob is suitable for transport over RPC; it carries no header
    /// binding to the block (caller — RPC layer — is expected to wrap with
    /// block seqno / hash).
    std::vector<std::uint8_t> compile() const;

    /// Test whether `tag` would match a compiled GCS blob. Kept here to
    /// share the hashing convention between compiler and matcher; wallets
    /// replicate this function. Returns true iff the tag is present (with
    /// GCS false-positive rate 2^-P on top of the native 16-bit tag FP).
    static bool match(const std::vector<std::uint8_t>& compiled_blob, std::uint16_t tag);

  private:
    std::vector<std::uint16_t> tags_;
};

// ---------------------------------------------------------------------------
// Lower-level helpers, exposed for tests and wallet SDKs.
// ---------------------------------------------------------------------------

/// Map a 16-bit filter tag into [0, kGcsM). Deterministic and consensus-free
/// (the filter itself is not consensus, but the hash must agree between the
/// validator producing the blob and the wallet matching it).
///
/// v1 implementation: SipHash-free, zero-keyed "universal" mapping
/// — a 64-bit multiply-and-shift reduction. This keeps the module free of a
/// crypto dependency for a non-consensus-critical path.
///
/// TODO: if Agent 3 prefers a keyed SipHash here for parity with BIP-158,
/// swap this out. The wallet SDK must match bit-for-bit.
std::uint64_t gcs_hash_tag(std::uint16_t tag) noexcept;

}  // namespace uno_workchain
