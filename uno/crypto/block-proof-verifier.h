// SPDX-License-Identifier: GPL-3.0-only
//
// uno/crypto/block-proof-verifier.h — C++ bridge to the Rust block-level
// aggregated-proof verifier.
//
// This header is the public surface consumed by the validator's block-
// ingestion / compute-phase path when verifying an aggregated block proof
// carried in `BlockExtra` (§2.3 aggregator wire format). It replaces the
// per-Transfer Plonky3 verify (`plonky3-verifier.h`) with a single block-
// level call over the monolithic verifier AIR stood up in Phase A6-1.5.
//
// It wraps the auto-generated C header produced by cbindgen from the
// `uno_plonky3_ffi` Rust crate, exposing:
//
//   * `BlockExtraView` — RAII wrapper over the decoded `UnoBlockExtra`
//     header + owned aggregated-proof buffer (the Rust side allocates;
//     the C++ side frees on destruction via `uno_block_extra_owned_free`).
//   * `BlockProofVerifier` — RAII wrapper over the opaque
//     `UnoBlockVerifierHandle`; mirrors `Plonky3Verifier` exactly.
//
// ## Contract
//
// * A single `BlockProofVerifier` instance is expected per validator
//   process; it is thread-safe and may be shared across the block-
//   validation worker pool by `const&` (the Rust-side handle is stateless;
//   `StarkConfig` is re-derived per call).
// * `verify(view, pi)` is a pure function of its inputs — no wall-clock,
//   no OS RNG, no allocator state leakage. The Rust side enforces this.
// * Never throws across the FFI boundary; every error is reported through
//   the `VerifyResult` enum imported from `plonky3-verifier.h`.
//
// ## Scope
//
// This bridge is the A6-3 landing for the aggregation workplan (see
// `doc/uno-aggregation-design.md`). It consumes the A6-2 FFI surface
// (ABI version 3). A6-4 will wire `BlockProofVerifier::verify` into the
// validator's block-acceptance path; this header is the contract the
// validator imports.

#pragma once

#include <cstddef>
#include <cstdint>
#include <utility>

// Pull in VerifyResult + kExpectedAbiVersion + the cbindgen-generated C
// header. `plonky3-verifier.h` already opens/closes the `extern "C"`
// block around `uno_plonky3_ffi.h`, so we inherit its declarations here
// without redeclaring them (and without fighting ODR).
#include "uno/crypto/plonky3-verifier.h"

namespace uno::crypto {

// RAII wrapper around a successfully-decoded `UnoBlockExtraParsed`.
//
// Ownership model:
//
//   * On a successful decode, the Rust side hands us a heap-allocated
//     aggregated-proof buffer inside the `UnoBlockExtraParsed` struct.
//     The C++ side is responsible for freeing it via
//     `uno_block_extra_owned_free` exactly once.
//   * `BlockExtraView` owns that buffer for its lifetime; moving the
//     view transfers ownership; copying is forbidden (the underlying
//     Rust allocation is a unique resource).
//   * Accessors return borrowed views (pointer / length / span-like
//     pairs) into the owned buffer; they remain valid until the
//     `BlockExtraView` is destroyed or moved-from.
//
// Usage:
//
//     auto maybe_view = uno::crypto::BlockExtraView::decode(bytes, len);
//     if (!maybe_view.has_value()) { /* reject block */ }
//     const auto& view = maybe_view.value();
//     auto r = verifier.verify(view, pi);
//
// `decode(...)` is a static factory that returns a lightweight
// `BlockExtraDecodeResult` holding either the view or the underlying
// FFI status code, without throwing. The result type is defined at
// namespace scope below this class (it can't be a nested member
// because it needs `BlockExtraView` as a value type).
class BlockExtraView {
 public:
  // Construct an empty (not-yet-decoded) view. Primarily for use as a
  // default in `DecodeResult` on failure paths; an empty view's
  // accessors return zeros / null pointers and its destructor is a
  // no-op.
  BlockExtraView() noexcept = default;

  // Non-copyable: the owned aggregated-proof buffer is a unique
  // resource.
  BlockExtraView(const BlockExtraView&)            = delete;
  BlockExtraView& operator=(const BlockExtraView&) = delete;

  // Movable: transfer ownership of the parsed struct (including its
  // owned proof buffer). Moved-from instance is left in the "empty"
  // state (null proof pointer, zero lengths) and its destructor is a
  // no-op.
  BlockExtraView(BlockExtraView&& other) noexcept
      : parsed_(other.parsed_), owned_(other.owned_) {
    other.owned_  = false;
    other.parsed_ = UnoBlockExtraParsed{};
  }
  BlockExtraView& operator=(BlockExtraView&& other) noexcept {
    if (this != &other) {
      destroy();
      parsed_       = other.parsed_;
      owned_        = other.owned_;
      other.owned_  = false;
      other.parsed_ = UnoBlockExtraParsed{};
    }
    return *this;
  }

  ~BlockExtraView() { destroy(); }

  // Decode `bytes[0..len]` as a `UnoBlockExtra` wire blob. Returns a
  // `BlockExtraDecodeResult` carrying either a populated view or the
  // specific FFI status code.
  //
  // On success, the returned view owns the aggregated-proof payload
  // and will free it on destruction. On failure, no allocation is
  // retained.
  //
  // This method is `noexcept`; errors are reported via the returned
  // status. Null `bytes` with `len == 0` is legal and yields
  // `kProofDecodeFailed` (the wire format requires a 40-byte header).
  //
  // Definition of this function lives below the class body (after
  // `BlockExtraDecodeResult` is declared) so that the result type is
  // complete at the point of use.
  [[nodiscard]] static inline struct BlockExtraDecodeResult
  decode(const std::uint8_t* bytes, std::size_t len) noexcept;

  // Accessors. All are `noexcept`; on an empty / moved-from view they
  // return zero-valued equivalents (the `tx_pi_merkle_root` will read as
  // 32 zero bytes).

  [[nodiscard]] std::uint8_t  scheme_id()   const noexcept { return parsed_.scheme_id; }
  [[nodiscard]] std::uint8_t  version()     const noexcept { return parsed_.version; }
  [[nodiscard]] std::uint16_t n_transfers() const noexcept { return parsed_.n_transfers; }

  // Pointer to the 32-byte BLAKE3 root over per-Tx PI hashes. Valid
  // for the lifetime of this view; never null (the Rust decoder
  // always populates this field on Ok).
  [[nodiscard]] const std::uint8_t* tx_pi_merkle_root() const noexcept {
    return parsed_.tx_pi_merkle_root;
  }

  // Borrowed view over the aggregated-proof bytes. Returned as a
  // `(ptr, len)` pair to avoid dragging in `<span>` on toolchains
  // where it is still behind a feature flag. Caller MUST NOT free
  // the pointer — ownership remains with the `BlockExtraView`.
  //
  // On an empty view, returns `{nullptr, 0}`.
  [[nodiscard]] std::pair<const std::uint8_t*, std::size_t>
  aggregated_proof() const noexcept {
    return {parsed_.aggregated_proof_ptr, parsed_.aggregated_proof_len};
  }

  // True iff this view owns a decoded payload (i.e. it was produced
  // by a successful `decode()` and has not been moved-from).
  [[nodiscard]] bool has_payload() const noexcept { return owned_; }

 private:
  void destroy() noexcept {
    if (owned_) {
      uno_block_extra_owned_free(parsed_);
      owned_  = false;
      parsed_ = UnoBlockExtraParsed{};
    }
  }

  // The raw parsed struct as returned by the Rust decoder. When
  // `owned_` is true, we are responsible for freeing
  // `parsed_.aggregated_proof_ptr` exactly once via the FFI.
  UnoBlockExtraParsed parsed_{};
  bool                owned_{false};
};

// Result of a `BlockExtraView::decode` attempt. On success,
// `status == VerifyResult::kOk` and `view` holds the owned parsed
// output; on failure, `view` is empty and `status` reports the
// specific decode error (mirrors the mapping table in
// `uno_block_extra_decode` docs).
//
// This is the C++-side equivalent of `std::expected<BlockExtraView,
// VerifyResult>` — spelled as a tagged aggregate so the header stays
// usable under plain C++20 without `<expected>` (GCC 13+) or a vendored
// `tl::expected`.
struct BlockExtraDecodeResult {
  VerifyResult    status;
  BlockExtraView  view;

  // True iff the decode succeeded and `view` is populated.
  [[nodiscard]] bool has_value() const noexcept {
    return status == VerifyResult::kOk;
  }

  // Convenience: accessors for the success case. Caller is
  // responsible for checking `has_value()` first; calling `value()`
  // on a failed result yields the empty default-constructed view.
  [[nodiscard]] const BlockExtraView& value() const& noexcept { return view; }
  [[nodiscard]] BlockExtraView&& value() && noexcept { return std::move(view); }
};

inline BlockExtraDecodeResult
BlockExtraView::decode(const std::uint8_t* bytes, std::size_t len) noexcept {
  BlockExtraDecodeResult result{VerifyResult::kOk, BlockExtraView{}};
  UnoBlockExtraBytes in{};
  in.ptr = bytes;
  in.len = len;
  UnoBlockExtraParsed out{};
  const std::int32_t rc = uno_block_extra_decode(in, &out);
  if (rc != static_cast<std::int32_t>(VerifyResult::kOk)) {
    result.status = static_cast<VerifyResult>(rc);
    return result;
  }
  result.view.parsed_ = out;
  result.view.owned_  = true;
  return result;
}

// RAII wrapper around an `UnoBlockVerifierHandle`.
//
// Usage (mirrors `Plonky3Verifier`):
//
//     uno::crypto::BlockProofVerifier verifier;
//     if (!verifier.init()) { /* abort startup */ }
//     ...
//     auto view = uno::crypto::BlockExtraView::decode(extra_bytes, len);
//     if (!view.has_value()) { /* reject block */ }
//     auto r = verifier.verify(view.value(), pi);
//     if (r != VerifyResult::kOk) { /* reject block */ }
//
// `init()` is separated from the constructor so a failed Rust-side
// initialization can be surfaced to the caller without exceptions.
class BlockProofVerifier {
 public:
  BlockProofVerifier() noexcept = default;

  // Non-copyable: the underlying handle is a unique resource.
  BlockProofVerifier(const BlockProofVerifier&)            = delete;
  BlockProofVerifier& operator=(const BlockProofVerifier&) = delete;

  // Movable: transfer handle ownership.
  BlockProofVerifier(BlockProofVerifier&& other) noexcept
      : handle_(other.handle_) {
    other.handle_ = nullptr;
  }
  BlockProofVerifier& operator=(BlockProofVerifier&& other) noexcept {
    if (this != &other) {
      destroy();
      handle_       = other.handle_;
      other.handle_ = nullptr;
    }
    return *this;
  }

  ~BlockProofVerifier() { destroy(); }

  // Initialize the underlying Rust verifier and cross-check the ABI
  // version. Returns true on success; false means either the handle
  // could not be constructed or the Rust static-lib ABI version does
  // not match the compiled C++ header (`kExpectedAbiVersion` == 3 at
  // A6-2/A6-3).
  //
  // Safe to call only once per instance; a second call while already
  // initialized is a no-op that returns true.
  bool init() noexcept {
    if (handle_ != nullptr) {
      return true;
    }
    if (uno_plonky3_abi_version() != kExpectedAbiVersion) {
      // ABI-version skew is unrecoverable: the Rust-side staticlib was
      // built from a different tree than this header. Caller must
      // refuse to start the validator.
      return false;
    }
    const std::int32_t rc = uno_block_verifier_init(&handle_);
    return rc == static_cast<std::int32_t>(VerifyResult::kOk) && handle_ != nullptr;
  }

  // Verify the aggregated proof contained in `view` against the
  // block-level public inputs `pi`.
  //
  // Return value:
  //   - `kOk` → proof verified; block may be accepted.
  //   - any other value → proof rejected; caller MUST fail the block.
  //
  // This method is `const` and thread-safe; the block-validation
  // worker pool may share one verifier instance via `const&`.
  [[nodiscard]] VerifyResult verify(const BlockExtraView&            view,
                                    const UnoBlockPublicInputsView&  pi) const noexcept {
    const auto [proof_ptr, proof_len] = view.aggregated_proof();
    return verify(proof_ptr, proof_len, pi);
  }

  // Lower-level overload: verify raw proof bytes directly. Useful when
  // the caller already has a borrowed slice (e.g. from a pre-parsed
  // wire buffer) and does not want to round-trip through a
  // `BlockExtraView`.
  //
  // `proof_bytes` may be null iff `proof_len == 0` (the trivially-
  // empty case is forwarded to Rust which returns `kProofDecodeFailed`
  // or `kVerifyFailed` depending on the AIR's rules).
  [[nodiscard]] VerifyResult verify(const std::uint8_t*              proof_bytes,
                                    std::size_t                      proof_len,
                                    const UnoBlockPublicInputsView&  pi) const noexcept {
    if (handle_ == nullptr) {
      return VerifyResult::kNullPointer;
    }
    Plonky3ProofBytes p{};
    p.ptr = proof_bytes;
    p.len = proof_len;
    const std::int32_t rc = uno_block_verifier_verify(handle_, &pi, p);
    return static_cast<VerifyResult>(rc);
  }

  // Test-only: report whether `init()` has completed successfully.
  [[nodiscard]] bool is_initialized() const noexcept { return handle_ != nullptr; }

 private:
  void destroy() noexcept {
    if (handle_ != nullptr) {
      uno_block_verifier_free(handle_);
      handle_ = nullptr;
    }
  }

  UnoBlockVerifierHandle* handle_{nullptr};
};

}  // namespace uno::crypto
