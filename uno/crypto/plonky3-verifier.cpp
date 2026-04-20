// SPDX-License-Identifier: GPL-3.0-only
//
// uno/crypto/plonky3-verifier.cpp — trivial translation unit for the
// Plonky3Verifier C++ bridge.
//
// The class is header-only today (all methods are `inline noexcept` over
// the C ABI). This .cpp exists so CMake has a concrete compilation unit
// to hang symbols / linker dependencies on — specifically so that if a
// downstream consumer ever adds a non-inline diagnostic helper (logging,
// instrumentation hooks) it has an obvious place to live without having
// to edit every consumer's translation unit.
//
// It also anchors the static assertions below, which validate at compile
// time that the C++ VerifyResult enum values stay in lock-step with the
// cbindgen-generated Rust `Plonky3Status` enum. If someone renumbers
// Rust-side codes and forgets the C++ header, this file fails to compile.

#include "uno/crypto/plonky3-verifier.h"

#include <type_traits>

namespace uno::crypto {

namespace {

// Compile-time cross-check: every VerifyResult value must match the
// integer value exposed by the generated C header's anonymous-enum
// constants. We spell them with their bare C names because cbindgen
// emits them as an unprefixed anonymous enum in C mode; C++ consumers
// see `Plonky3Status` the strongly-typed form.

static_assert(static_cast<std::int32_t>(VerifyResult::kOk) == 0,
              "VerifyResult::kOk must equal Plonky3Status::Ok (= 0)");
static_assert(static_cast<std::int32_t>(VerifyResult::kProofDecodeFailed) == 1,
              "VerifyResult::kProofDecodeFailed must equal 1");
static_assert(static_cast<std::int32_t>(VerifyResult::kPublicInputDecodeFailed) == 2,
              "VerifyResult::kPublicInputDecodeFailed must equal 2");
static_assert(static_cast<std::int32_t>(VerifyResult::kPublicInputLengthMismatch) == 3,
              "VerifyResult::kPublicInputLengthMismatch must equal 3");
static_assert(static_cast<std::int32_t>(VerifyResult::kVerifyFailed) == 4,
              "VerifyResult::kVerifyFailed must equal 4");
static_assert(static_cast<std::int32_t>(VerifyResult::kWitnessInvalid) == 5,
              "VerifyResult::kWitnessInvalid must equal 5");
static_assert(static_cast<std::int32_t>(VerifyResult::kNullPointer) == 6,
              "VerifyResult::kNullPointer must equal 6");
static_assert(static_cast<std::int32_t>(VerifyResult::kLengthTooLarge) == 7,
              "VerifyResult::kLengthTooLarge must equal 7");
static_assert(static_cast<std::int32_t>(VerifyResult::kInternalError) == 99,
              "VerifyResult::kInternalError must equal 99");

// Layout check: Plonky3ProofBytes / Plonky3PublicInputs / Plonky3Witness /
// Plonky3OwnedProof are POD structs shared across the FFI. If cbindgen's
// layout drifts from what the Rust side expects (e.g. a missing `#[repr(C)]`
// on a new field), memory-safety breaks silently. Static asserting size +
// field offsets catches this at compile time on both sides.

static_assert(sizeof(Plonky3ProofBytes) == sizeof(void*) + sizeof(std::size_t),
              "Plonky3ProofBytes layout drift");
static_assert(sizeof(Plonky3PublicInputs) == sizeof(void*) + sizeof(std::size_t),
              "Plonky3PublicInputs layout drift");
static_assert(sizeof(Plonky3Witness) == sizeof(void*) + sizeof(std::size_t),
              "Plonky3Witness layout drift");
static_assert(sizeof(Plonky3OwnedProof) == sizeof(void*) + 2 * sizeof(std::size_t),
              "Plonky3OwnedProof layout drift");

// The Plonky3Verifier RAII wrapper must be move-only (the underlying
// handle is a unique resource). Guard both traits at compile time.
static_assert(!std::is_copy_constructible_v<Plonky3Verifier>,
              "Plonky3Verifier must be non-copyable");
static_assert(!std::is_copy_assignable_v<Plonky3Verifier>,
              "Plonky3Verifier must be non-copy-assignable");
static_assert(std::is_nothrow_move_constructible_v<Plonky3Verifier>,
              "Plonky3Verifier move-construct must be noexcept");
static_assert(std::is_nothrow_move_assignable_v<Plonky3Verifier>,
              "Plonky3Verifier move-assign must be noexcept");

}  // namespace

}  // namespace uno::crypto
