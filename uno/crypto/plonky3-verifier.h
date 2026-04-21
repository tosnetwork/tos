// SPDX-License-Identifier: GPL-3.0-only
//
// uno/crypto/plonky3-verifier.h — C++ bridge to the Rust Plonky3 verifier.
//
// This header is the public surface consumed by `uno/core/compute-phase.cpp`
// (Agent 5) when verifying a `Transfer`'s ZK proof during the consensus-
// critical compute-phase path (design doc §4.3 step 4).
//
// It wraps the auto-generated C header produced by cbindgen from the
// `uno_plonky3_ffi` Rust crate, exposing a C++-idiomatic RAII class and
// a status enum that shadows the Rust-side wire codes.
//
// ## Contract
//
// * A single `Plonky3Verifier` instance is expected per validator process;
//   it is thread-safe (§13 P.3 parallel verify) and may be shared across
//   the compute-phase worker pool by `const&`.
// * `verify(proof_bytes, public_inputs)` is a pure function of its inputs.
//   No wall-clock, no OS RNG, no hashmap iteration — the Rust side enforces.
// * Never throws across the FFI boundary; every error is reported through
//   the `VerifyResult` enum.
//
// ## Scope
//
// This bridge is the P.0 / P.2-bootstrap surface (per design doc §13).
// The `verify()` method currently authenticates the Minimum Viable AIR
// (see `uno/plonky3-ffi/src/transfer_air.rs`), not the full Transfer AIR.
// Once Agent 3 lands the real Poseidon2-Goldilocks primitives and Agent 4
// expands `transfer_air.rs` to cover all nine §4.2 claims, this header
// stays byte-for-byte compatible — the C ABI is intentionally proof-format-
// agnostic.

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

// Include the cbindgen-generated C header. The include path is configured
// by Agent 5's top-level CMakeLists.txt as
//   target_include_directories(uno_workchain PRIVATE plonky3-ffi/include)
// so that this translation unit resolves `uno_plonky3_ffi.h` without
// duplicating the generated header into this directory.
extern "C" {
#include "uno_plonky3_ffi.h"
}

namespace uno::crypto {

// Mirror of `Plonky3Status` from the Rust FFI, in a stable C++-side spelling.
// Renumbering is a breaking change (see `lib.rs` docs).
enum class VerifyResult : std::int32_t {
  kOk                          = 0,
  kProofDecodeFailed           = 1,
  kPublicInputDecodeFailed     = 2,
  kPublicInputLengthMismatch   = 3,
  kVerifyFailed                = 4,
  kWitnessInvalid              = 5,
  kNullPointer                 = 6,
  kLengthTooLarge              = 7,
  kInternalError               = 99,
};

// Human-readable label for diagnostic logging. Never user-visible.
inline const char* verify_result_label(VerifyResult r) noexcept {
  switch (r) {
    case VerifyResult::kOk:                        return "Ok";
    case VerifyResult::kProofDecodeFailed:         return "ProofDecodeFailed";
    case VerifyResult::kPublicInputDecodeFailed:   return "PublicInputDecodeFailed";
    case VerifyResult::kPublicInputLengthMismatch: return "PublicInputLengthMismatch";
    case VerifyResult::kVerifyFailed:              return "VerifyFailed";
    case VerifyResult::kWitnessInvalid:            return "WitnessInvalid";
    case VerifyResult::kNullPointer:               return "NullPointer";
    case VerifyResult::kLengthTooLarge:            return "LengthTooLarge";
    case VerifyResult::kInternalError:             return "InternalError";
  }
  return "Unknown";
}

// ABI version the C++ side expects from the linked Rust staticlib.
// Must match `uno_plonky3_abi_version()`. Bumped together on any layout
// change to the FFI structs.
//
// v2 (A6-1): adds UnoBlockExtra{Bytes,Parsed} structs + the three
// block-wire-format entry points. Existing Plonky3Verifier surface
// unchanged; new C++ consumers of the block wire format link against
// the same lib.
//
// v3 (A6-2): adds UnoBlockPublicInputsView struct + UnoBlockVerifierHandle
// opaque type + init/free/verify entry points. The block-level verifier
// (A6-3 RAII wrapper) uses these to replace per-Tx Plonky3 verify with
// one block-level aggregated-proof verify.
inline constexpr std::uint32_t kExpectedAbiVersion = 3;

// RAII wrapper around an `UnoPlonky3VerifierHandle`.
//
// Usage:
//
//     uno::crypto::Plonky3Verifier verifier;
//     if (!verifier.init()) { /* abort startup */ }
//     ...
//     auto r = verifier.verify(proof_bytes, proof_len, pi_bytes, pi_len);
//     if (r != VerifyResult::kOk) { /* reject tx */ }
//
// `init()` is separated from the constructor so a failed Rust-side
// initialization can be surfaced to the caller without exceptions.
class Plonky3Verifier {
 public:
  Plonky3Verifier() noexcept = default;

  // Non-copyable: the underlying handle is a unique resource.
  Plonky3Verifier(const Plonky3Verifier&)            = delete;
  Plonky3Verifier& operator=(const Plonky3Verifier&) = delete;

  // Movable: transfer handle ownership.
  Plonky3Verifier(Plonky3Verifier&& other) noexcept
      : handle_(other.handle_) {
    other.handle_ = nullptr;
  }
  Plonky3Verifier& operator=(Plonky3Verifier&& other) noexcept {
    if (this != &other) {
      destroy();
      handle_ = other.handle_;
      other.handle_ = nullptr;
    }
    return *this;
  }

  ~Plonky3Verifier() { destroy(); }

  // Initialize the underlying Rust verifier and cross-check the ABI
  // version. Returns true on success; false means either the handle
  // could not be constructed (OOM, Plonky3 config failure) or the
  // Rust static-lib ABI version does not match the compiled C++ header.
  //
  // Safe to call only once per instance; a second call while already
  // initialized is a no-op that returns true.
  bool init() noexcept {
    if (handle_ != nullptr) {
      return true;
    }
    if (uno_plonky3_abi_version() != kExpectedAbiVersion) {
      // ABI-version skew is unrecoverable: the Rust-side staticlib was
      // built from a different tree than this header. Caller must refuse
      // to start the validator.
      return false;
    }
    const std::int32_t rc = uno_plonky3_verifier_init(&handle_);
    return rc == static_cast<std::int32_t>(VerifyResult::kOk) && handle_ != nullptr;
  }

  // Verify a serialized proof against the wire-encoded public inputs.
  //
  // `proof_bytes` + `proof_len`: the serialized Plonky3 STARK proof
  //   (postcard format) as pulled from the `Transfer.zk_proof` cell.
  // `public_inputs_bytes` + `public_inputs_len`: the canonical
  //   Goldilocks-element wire encoding as defined in design doc §4.3
  //   step 4.
  //
  // Return value:
  //   - `kOk` → proof verified; consensus may proceed.
  //   - any other value → proof rejected; caller MUST fail the tx.
  //
  // This method is `const` and thread-safe; the compute-phase worker
  // pool may share one verifier instance via `const&`.
  VerifyResult verify(const std::uint8_t* proof_bytes, std::size_t proof_len,
                      const std::uint8_t* public_inputs_bytes,
                      std::size_t       public_inputs_len) const noexcept {
    if (handle_ == nullptr) {
      return VerifyResult::kNullPointer;
    }
    Plonky3ProofBytes p{};
    p.ptr = proof_bytes;
    p.len = proof_len;
    Plonky3PublicInputs pi{};
    pi.ptr = public_inputs_bytes;
    pi.len = public_inputs_len;
    const std::int32_t rc = uno_plonky3_verify(handle_, p, pi);
    return static_cast<VerifyResult>(rc);
  }

  // Test-only: report whether `init()` has completed successfully.
  bool is_initialized() const noexcept { return handle_ != nullptr; }

 private:
  void destroy() noexcept {
    if (handle_ != nullptr) {
      uno_plonky3_verifier_free(handle_);
      handle_ = nullptr;
    }
  }

  Plonky3VerifierHandle* handle_{nullptr};
};

}  // namespace uno::crypto
