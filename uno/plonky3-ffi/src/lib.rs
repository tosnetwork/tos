//! uno_plonky3_ffi — Rust crate exposing a Plonky3 STARK verifier + reference
//! prover to the TOS C++ validator via a minimal C ABI.
//!
//! Design doc §13 P.0 / P.2 bootstrap (see `doc/uno-workchain.md`).
//!
//! # What this is
//!
//! This crate is the **scaffolding** for the Uno workchain's proof system. It:
//!
//! 1. Implements a Minimum Viable AIR — a single Poseidon2-Goldilocks hash
//!    (4-to-1 compression) combined with a single-step Merkle path check and
//!    a u64 range assertion (see [`transfer_air`]).
//! 2. Exposes a reference prover + verifier over that MVP AIR (see
//!    [`prover`] and [`verifier`]).
//! 3. Wraps both in a C ABI suitable for the C++ validator to consume
//!    (this file).
//!
//! It is **not** the production Transfer circuit. The production AIR will
//! implement all nine claims in §4.2 of the design doc (tree-membership at
//! depth 32, note opening, hash-chain ownership, nullifier correctness,
//! range, spend-auth binding, well-formed commitment, per-output range,
//! value conservation). The scaffolding here only proves the *toolchain*
//! end-to-end; it does not prove anything consensus-meaningful.
//!
//! # C ABI contract
//!
//! All public functions:
//!
//! - Return an `i32` [`Plonky3Status`] code; see that enum for values.
//! - Take opaque handles by raw pointer; handles are allocated by `*_init`
//!   and freed by `*_free`. Never mutated once handed to C.
//! - Take byte buffers as `(const uint8_t*, size_t)` pairs. Buffers are
//!   borrowed for the duration of the call only; callees copy internally
//!   if they need to retain anything (they do not).
//! - Are **panic-free** at the ABI boundary. We set `panic = "abort"` in
//!   Cargo.toml, and every FFI entry point is wrapped in
//!   `std::panic::catch_unwind` so that a panic in Plonky3 internals
//!   cannot unwind through C++ frames. A caught panic is reported as
//!   [`Plonky3Status::InternalError`].
//!
//! # Determinism
//!
//! The verifier path uses no system clock, no OS entropy, no thread-local
//! state, no floating point. Cross-validator replay parity is a hard
//! invariant (§4.3 of the design doc). The reference prover is *also*
//! deterministic given identical witnesses, seeded by a ChaCha RNG whose
//! seed is a hash of the public inputs — not OS entropy — so that P.2
//! test fixtures are byte-identical across machines.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![allow(clippy::missing_safety_doc)]

use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;

pub mod transfer_air;
pub mod prover;
pub mod verifier;

/// Result codes returned across the C ABI.
///
/// These are stable wire values; renumbering is a breaking change. C++ side
/// mirrors this enum in `uno/crypto/plonky3-verifier.h`.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plonky3Status {
    /// Verification succeeded / prover produced a valid proof.
    Ok = 0,
    /// The proof bytes could not be deserialized into a Plonky3 proof.
    ProofDecodeFailed = 1,
    /// Public-input bytes could not be decoded into field elements.
    PublicInputDecodeFailed = 2,
    /// Public-input vector length does not match the AIR's declared length.
    PublicInputLengthMismatch = 3,
    /// Plonky3 STARK verify returned a constraint-violation error.
    VerifyFailed = 4,
    /// A prover-only entry point was called but the witness was invalid
    /// (e.g. out-of-range value, inconsistent Merkle siblings).
    WitnessInvalid = 5,
    /// The caller passed a null pointer where a non-null one was required.
    NullPointer = 6,
    /// A length argument was larger than `isize::MAX` (ABI guard).
    LengthTooLarge = 7,
    /// Rust-side panic caught at FFI boundary. Indicates a bug in this
    /// crate or the pinned Plonky3 rev; never returned in correct usage.
    InternalError = 99,
}

impl Plonky3Status {
    /// Expose the i32 wire value. Used by the C++ bridge to populate its
    /// own enum without pulling in the Rust type.
    #[inline]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

// ---------------------------------------------------------------------------
// Opaque handle types
// ---------------------------------------------------------------------------

/// Opaque handle to an initialized Plonky3 verifier.
///
/// Constructed by [`uno_plonky3_verifier_init`] and destroyed by
/// [`uno_plonky3_verifier_free`]. Internally holds the Plonky3 `StarkConfig`
/// and a reference to the statically-configured MVP AIR instance.
///
/// Thread-safety: the handle is `Send + Sync` and may be used concurrently
/// from multiple threads. This is required by design doc §13 P.3 (parallel
/// verify across `num_cores` workers is an activation prerequisite).
pub struct Plonky3VerifierHandle {
    inner: Arc<verifier::MvpVerifier>,
}

/// Opaque handle to an initialized Plonky3 reference prover.
///
/// Constructed by [`uno_plonky3_prover_init`], destroyed by
/// [`uno_plonky3_prover_free`]. Not used by the validator; used by
/// `tosctl` for witness-generation and by integration tests.
pub struct Plonky3ProverHandle {
    inner: Arc<prover::MvpProver>,
}

// ---------------------------------------------------------------------------
// FFI-visible buffer descriptors
// ---------------------------------------------------------------------------

/// Borrowed byte slice passed across the FFI. Matches C `struct { const
/// uint8_t* ptr; uintptr_t len; }`.
///
/// The buffer is valid for the duration of the FFI call only; the Rust
/// side may read but not retain it.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Plonky3ProofBytes {
    /// Pointer to the first byte of the serialized proof.
    pub ptr: *const u8,
    /// Length in bytes.
    pub len: usize,
}

/// Borrowed byte slice containing the canonical public-input encoding.
///
/// # Wire format (decision #5 / §4.3 step 4)
///
/// Each Goldilocks element serializes as 8 bytes little-endian u64
/// (canonical Plonky3 form: `Goldilocks::from_canonical_u64` /
/// `Goldilocks::from_wrapped_u64`). 256-bit inputs split into 4 × u64 LE
/// chunks, each reduced mod `p_Goldilocks = 2^64 - 2^32 + 1`. The
/// verifier decodes via `transfer_air::decode_public_inputs`, which
/// rejects non-canonical limbs (v ≥ p) to close off a wire-encoding
/// malleability vector.
///
/// Production Transfer AIR element order is §4.3 step 4 bullets 1–7:
/// scheme_id, chain_id, expiry_block, fee, anchor (4 limbs), and per
/// spend/output the corresponding nf/rk/cm/epk/filter_tag fields. Total
/// byte length: `64 + 64·spend_count + 72·output_count`.
///
/// Cross-impl byte parity is enforced by the golden fixture
/// `uno/test/golden/public-inputs-v1.hex` — produced by the C++ encoder
/// (`uno/core/transaction.cpp :: build_plonky3_public_inputs`) and
/// checked by this crate's `tests/public_input_fixture.rs`. Any wire
/// drift is a scheme_id bump.
///
/// The MVP AIR shipped in P.0 uses a simpler 4-element schema (3 → 4
/// elements after decision #1's claim-3 extension); see
/// `transfer_air::MvpWitness::public_inputs_bytes`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Plonky3PublicInputs {
    /// Pointer to the first byte of the public-input encoding.
    pub ptr: *const u8,
    /// Length in bytes. Must be a multiple of 8 (Goldilocks byte width).
    pub len: usize,
}

/// Borrowed witness bytes for the reference prover. Layout is MVP-AIR
/// specific and defined in [`transfer_air::MvpWitness::encode`].
///
/// # P.2 note — witness wire length
///
/// With the P.2 upgrade (real Poseidon2-Goldilocks compression for
/// claims 1/2/3/4 — see `transfer_air` module doc), the encoded
/// witness grew from 32 B (MVP) to **64 B**. The extra 32 B carry
/// single-field-element proxies for `pk_d`, `rcm`, `nk`, `pos` needed
/// to evaluate the claim-2 (note opening) and claim-4 (nullifier)
/// Poseidon2 inputs inside the AIR. This is a **prover-only** wire
/// change: consensus-binding bytes (`Plonky3PublicInputs` and the
/// proof bytes consumed by `uno_plonky3_verify`) are unaffected. No
/// ABI version bump is required because the witness descriptor is a
/// length-prefixed byte slice, not a fixed-size struct.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Plonky3Witness {
    /// Pointer to the first byte of the encoded witness.
    pub ptr: *const u8,
    /// Length in bytes.
    pub len: usize,
}

/// Owned output buffer used by the prover to return a serialized proof.
/// The Rust side allocates via `Box::into_raw`; the caller must free via
/// [`uno_plonky3_proof_free`] exactly once.
///
/// Layout must match the C side byte-for-byte.
#[repr(C)]
pub struct Plonky3OwnedProof {
    /// Heap-allocated buffer (aligned to `u8`). Never null on Ok return.
    pub ptr: *mut u8,
    /// Length in bytes.
    pub len: usize,
    /// Capacity in bytes (needed for correct `Vec` reconstruction on free).
    pub cap: usize,
}

impl Plonky3OwnedProof {
    const EMPTY: Self = Self {
        ptr: std::ptr::null_mut(),
        len: 0,
        cap: 0,
    };
}

// ---------------------------------------------------------------------------
// Helpers (Rust-internal, not exposed across FFI)
// ---------------------------------------------------------------------------

/// Run a closure and map any panic to `InternalError`. All FFI entry points
/// go through this wrapper so that a Plonky3 `.unwrap()` or similar can
/// never unwind across the C ABI.
fn ffi_guard<F: FnOnce() -> Plonky3Status>(f: F) -> i32 {
    match panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(s) => s.as_i32(),
        Err(_) => Plonky3Status::InternalError.as_i32(),
    }
}

/// Convert an FFI `(ptr, len)` pair into a Rust slice, with null + length
/// validation. Returns `None` iff the caller passed an invalid descriptor.
///
/// # Safety
/// Caller must ensure that, if `ptr` is non-null, `[ptr, ptr+len)` is a
/// valid, readable, non-mutated memory region for the call duration.
unsafe fn slice_from_parts<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() {
        return None;
    }
    if len > isize::MAX as usize {
        return None;
    }
    // SAFETY: caller upholds validity; isize bound checked above.
    Some(unsafe { std::slice::from_raw_parts(ptr, len) })
}

// ---------------------------------------------------------------------------
// Verifier FFI surface
// ---------------------------------------------------------------------------

/// Initialize a Plonky3 verifier and return an opaque handle to it.
///
/// On success, writes a non-null handle pointer to `out_handle` and returns
/// [`Plonky3Status::Ok`]. On failure, `*out_handle` is set to null.
///
/// The caller owns the returned handle and **must** call
/// [`uno_plonky3_verifier_free`] exactly once when done.
///
/// # Safety
/// `out_handle` must be a valid, aligned, writable `*mut *mut
/// Plonky3VerifierHandle` pointer.
#[no_mangle]
pub unsafe extern "C" fn uno_plonky3_verifier_init(
    out_handle: *mut *mut Plonky3VerifierHandle,
) -> i32 {
    ffi_guard(|| {
        if out_handle.is_null() {
            return Plonky3Status::NullPointer;
        }
        let handle = Box::new(Plonky3VerifierHandle {
            inner: Arc::new(verifier::MvpVerifier::new()),
        });
        // SAFETY: caller promises out_handle is a valid, writable pointer.
        unsafe {
            *out_handle = Box::into_raw(handle);
        }
        Plonky3Status::Ok
    })
}

/// Free a verifier handle previously returned by [`uno_plonky3_verifier_init`].
///
/// Safe to call with a null pointer (no-op). Must not be called twice for
/// the same non-null pointer.
///
/// # Safety
/// `handle` must have been returned by [`uno_plonky3_verifier_init`] and
/// not freed.
#[no_mangle]
pub unsafe extern "C" fn uno_plonky3_verifier_free(handle: *mut Plonky3VerifierHandle) {
    if handle.is_null() {
        return;
    }
    // Drop via Box reconstruction. catch_unwind to be safe — Arc drop is
    // panic-safe in stable Rust but the rule at the FFI boundary is
    // "never unwind."
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: caller guarantees the pointer came from init() and is
        // not yet freed.
        drop(unsafe { Box::from_raw(handle) });
    }));
}

/// Verify a Plonky3 STARK proof of the MVP AIR against the given public
/// inputs.
///
/// Returns:
/// - [`Plonky3Status::Ok`] iff the proof is valid for the public inputs.
/// - A specific decode / mismatch / verify error code otherwise.
///
/// This is the entry point called from the validator's compute phase (via
/// Agent 5's `Plonky3Verifier::verify(proof_bytes, public_inputs)` C++
/// wrapper).
///
/// # Safety
/// `handle` must be a live handle from [`uno_plonky3_verifier_init`]. The
/// `proof` and `public_inputs` buffers must be valid for reads of their
/// declared lengths for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn uno_plonky3_verify(
    handle: *const Plonky3VerifierHandle,
    proof: Plonky3ProofBytes,
    public_inputs: Plonky3PublicInputs,
) -> i32 {
    ffi_guard(|| {
        if handle.is_null() {
            return Plonky3Status::NullPointer;
        }
        // SAFETY: caller guarantees handle validity.
        let handle = unsafe { &*handle };

        let Some(proof_bytes) = (unsafe { slice_from_parts(proof.ptr, proof.len) }) else {
            return Plonky3Status::NullPointer;
        };
        let Some(pi_bytes) =
            (unsafe { slice_from_parts(public_inputs.ptr, public_inputs.len) })
        else {
            return Plonky3Status::NullPointer;
        };

        handle.inner.verify(proof_bytes, pi_bytes)
    })
}

// ---------------------------------------------------------------------------
// Prover FFI surface (reference prover; NOT called from consensus path)
// ---------------------------------------------------------------------------

/// Initialize a reference prover and return an opaque handle.
///
/// # Safety
/// `out_handle` must be a valid writable pointer.
#[no_mangle]
pub unsafe extern "C" fn uno_plonky3_prover_init(
    out_handle: *mut *mut Plonky3ProverHandle,
) -> i32 {
    ffi_guard(|| {
        if out_handle.is_null() {
            return Plonky3Status::NullPointer;
        }
        let handle = Box::new(Plonky3ProverHandle {
            inner: Arc::new(prover::MvpProver::new()),
        });
        // SAFETY: caller promise.
        unsafe {
            *out_handle = Box::into_raw(handle);
        }
        Plonky3Status::Ok
    })
}

/// Free a prover handle.
///
/// # Safety
/// Same rules as [`uno_plonky3_verifier_free`].
#[no_mangle]
pub unsafe extern "C" fn uno_plonky3_prover_free(handle: *mut Plonky3ProverHandle) {
    if handle.is_null() {
        return;
    }
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: caller guarantees ownership.
        drop(unsafe { Box::from_raw(handle) });
    }));
}

/// Run the reference prover against a witness, producing a serialized proof.
///
/// On `Ok`, `*out_proof` is populated with a heap-allocated buffer that the
/// caller must free via [`uno_plonky3_proof_free`]. On any non-Ok return,
/// `*out_proof` is set to an empty descriptor.
///
/// This is a **reference** implementation suitable for test fixtures and
/// `tosctl`; it is not optimized for wallet-side proving performance. The
/// production prover (P.2 full Transfer AIR) will be written in a later
/// iteration.
///
/// # Safety
/// - `handle` must be from [`uno_plonky3_prover_init`].
/// - `witness` buffer must be valid for the call.
/// - `out_proof` must be a valid writable pointer.
#[no_mangle]
pub unsafe extern "C" fn uno_plonky3_prove(
    handle: *const Plonky3ProverHandle,
    witness: Plonky3Witness,
    out_proof: *mut Plonky3OwnedProof,
) -> i32 {
    ffi_guard(|| {
        if handle.is_null() || out_proof.is_null() {
            return Plonky3Status::NullPointer;
        }
        // SAFETY: caller promises.
        unsafe {
            *out_proof = Plonky3OwnedProof::EMPTY;
        }
        let handle = unsafe { &*handle };

        let Some(witness_bytes) = (unsafe { slice_from_parts(witness.ptr, witness.len) })
        else {
            return Plonky3Status::NullPointer;
        };

        match handle.inner.prove(witness_bytes) {
            Ok((proof_bytes, public_inputs_bytes)) => {
                // We return the proof + its derived public-input vector
                // concatenated: [u32_le proof_len][proof_bytes][pi_bytes].
                // This lets tosctl pull both out with one allocation; the
                // verify FFI takes them as separate slices.
                let mut out = Vec::with_capacity(4 + proof_bytes.len() + public_inputs_bytes.len());
                out.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
                out.extend_from_slice(&proof_bytes);
                out.extend_from_slice(&public_inputs_bytes);
                out.shrink_to_fit();

                let mut boxed = out.into_boxed_slice();
                let ptr = boxed.as_mut_ptr();
                let len = boxed.len();
                // We stored exactly `len` capacity after shrink_to_fit +
                // into_boxed_slice; `cap == len` is correct.
                std::mem::forget(boxed);
                // SAFETY: out_proof is non-null & writable per caller.
                unsafe {
                    *out_proof = Plonky3OwnedProof {
                        ptr,
                        len,
                        cap: len,
                    };
                }
                Plonky3Status::Ok
            }
            Err(status) => status,
        }
    })
}

/// Free a buffer previously returned by [`uno_plonky3_prove`].
///
/// # Safety
/// `proof.ptr` must have come from a prior `uno_plonky3_prove` call and
/// must not have been freed. Other fields of `proof` must be unchanged.
#[no_mangle]
pub unsafe extern "C" fn uno_plonky3_proof_free(proof: Plonky3OwnedProof) {
    if proof.ptr.is_null() || proof.cap == 0 {
        return;
    }
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: reconstruct the Vec we forgot in `prove`.
        unsafe {
            let _ = Vec::from_raw_parts(proof.ptr, proof.len, proof.cap);
        }
    }));
}

// ---------------------------------------------------------------------------
// Version / ABI probe
// ---------------------------------------------------------------------------

/// Returns the ABI revision of this crate. The C++ bridge checks this at
/// `Plonky3Verifier::init()` to catch a version-skew between the shipped
/// Rust static-lib and the compiled C++ header.
///
/// Current value: 1. Bump on any layout change to `Plonky3OwnedProof`,
/// `Plonky3ProofBytes`, `Plonky3PublicInputs`, `Plonky3Witness`, or
/// `Plonky3Status`, or on any addition/removal of FFI entry points.
#[no_mangle]
pub extern "C" fn uno_plonky3_abi_version() -> u32 {
    1
}

// ---------------------------------------------------------------------------
// Integration tests (Rust-side; exercise the FFI surface end-to-end).
// ---------------------------------------------------------------------------
#[cfg(test)]
mod ffi_tests {
    use super::*;

    /// Prove + verify round-trip via the C ABI with a VALID witness.
    ///
    /// Corresponds to design doc §13 P.0 done-when: "Minimal AIR produces
    /// and verifies; FFI round-trip works".
    #[test]
    fn ffi_roundtrip_valid_witness() {
        // Init verifier.
        let mut v: *mut Plonky3VerifierHandle = std::ptr::null_mut();
        let rc = unsafe { uno_plonky3_verifier_init(&mut v) };
        assert_eq!(rc, Plonky3Status::Ok.as_i32());
        assert!(!v.is_null());

        // Init prover.
        let mut p: *mut Plonky3ProverHandle = std::ptr::null_mut();
        let rc = unsafe { uno_plonky3_prover_init(&mut p) };
        assert_eq!(rc, Plonky3Status::Ok.as_i32());
        assert!(!p.is_null());

        // Build a valid witness via the transfer_air module helper.
        let witness = transfer_air::MvpWitness::deterministic_valid(0x1234_5678_9abc_def0);
        let witness_bytes = witness.encode();

        // Prove.
        let mut out_proof = Plonky3OwnedProof::EMPTY;
        let rc = unsafe {
            uno_plonky3_prove(
                p,
                Plonky3Witness {
                    ptr: witness_bytes.as_ptr(),
                    len: witness_bytes.len(),
                },
                &mut out_proof,
            )
        };
        assert_eq!(rc, Plonky3Status::Ok.as_i32(), "prove must succeed");
        assert!(!out_proof.ptr.is_null());

        // Unpack [u32 proof_len][proof][public_inputs].
        let owned =
            unsafe { std::slice::from_raw_parts(out_proof.ptr, out_proof.len) }.to_vec();
        let proof_len = u32::from_le_bytes([owned[0], owned[1], owned[2], owned[3]]) as usize;
        let proof_bytes = &owned[4..4 + proof_len];
        let pi_bytes = &owned[4 + proof_len..];

        // Verify.
        let rc = unsafe {
            uno_plonky3_verify(
                v,
                Plonky3ProofBytes {
                    ptr: proof_bytes.as_ptr(),
                    len: proof_bytes.len(),
                },
                Plonky3PublicInputs {
                    ptr: pi_bytes.as_ptr(),
                    len: pi_bytes.len(),
                },
            )
        };
        assert_eq!(
            rc,
            Plonky3Status::Ok.as_i32(),
            "verify of valid proof must succeed"
        );

        // Cleanup.
        unsafe { uno_plonky3_proof_free(out_proof) };
        unsafe { uno_plonky3_prover_free(p) };
        unsafe { uno_plonky3_verifier_free(v) };
    }

    /// Adversarial witness: flip one bit in the Merkle sibling, then
    /// submit the resulting proof but with the HONEST public inputs (as
    /// if the adversary were trying to convince the verifier that the
    /// honest `parent` was computed from the perturbed `sibling` — which
    /// it wasn't).
    ///
    /// The prover may succeed or fail. Either way, verify under the
    /// honest public inputs MUST reject.
    #[test]
    fn ffi_adversarial_witness_rejected() {
        let mut v: *mut Plonky3VerifierHandle = std::ptr::null_mut();
        let mut p: *mut Plonky3ProverHandle = std::ptr::null_mut();
        unsafe { uno_plonky3_verifier_init(&mut v) };
        unsafe { uno_plonky3_prover_init(&mut p) };

        // Honest witness + its declared public inputs.
        let honest_witness =
            transfer_air::MvpWitness::deterministic_valid(0xcafe_f00d_dead_beef);
        let honest_pi_bytes = honest_witness.public_inputs_bytes();

        // Adversary's tampered witness: flip a sibling bit.
        let mut bad_witness = honest_witness.clone();
        bad_witness.merkle_sibling[0] ^= 1;
        let bad_witness_bytes = bad_witness.encode();

        let mut out_proof = Plonky3OwnedProof::EMPTY;
        let rc = unsafe {
            uno_plonky3_prove(
                p,
                Plonky3Witness {
                    ptr: bad_witness_bytes.as_ptr(),
                    len: bad_witness_bytes.len(),
                },
                &mut out_proof,
            )
        };

        // Outcome A (debug build): the DebugConstraintBuilder path may
        // have detected inconsistency and aborted. That's correct and
        // sufficient — no proof was produced that an adversary could
        // use.
        //
        // Outcome B: the prover returned a proof; we must verify that
        // proof against HONEST public inputs and confirm rejection.
        if rc == Plonky3Status::WitnessInvalid.as_i32() {
            // Outcome A — caught pre-proof.
        } else if rc == Plonky3Status::Ok.as_i32() {
            // Outcome B — prover succeeded on self-consistent PI. Extract
            // the proof and re-verify against the HONEST PI.
            let owned =
                unsafe { std::slice::from_raw_parts(out_proof.ptr, out_proof.len) }.to_vec();
            let proof_len =
                u32::from_le_bytes([owned[0], owned[1], owned[2], owned[3]]) as usize;
            let proof_bytes = &owned[4..4 + proof_len];

            let rc = unsafe {
                uno_plonky3_verify(
                    v,
                    Plonky3ProofBytes {
                        ptr: proof_bytes.as_ptr(),
                        len: proof_bytes.len(),
                    },
                    Plonky3PublicInputs {
                        ptr: honest_pi_bytes.as_ptr(),
                        len: honest_pi_bytes.len(),
                    },
                )
            };
            assert_ne!(
                rc,
                Plonky3Status::Ok.as_i32(),
                "verify MUST reject a proof-of-corrupt-witness against HONEST public inputs"
            );

            unsafe { uno_plonky3_proof_free(out_proof) };
        } else {
            panic!("unexpected prove return code: {rc}");
        }

        unsafe { uno_plonky3_prover_free(p) };
        unsafe { uno_plonky3_verifier_free(v) };
    }

    /// The ABI-version probe must return a positive integer.
    #[test]
    fn abi_version_probe() {
        assert_eq!(uno_plonky3_abi_version(), 1);
    }
}
