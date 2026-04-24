//! uno_plonky3_ffi — Rust crate exposing a Plonky3 STARK verifier + reference
//! prover to the TOS C++ validator via a minimal C ABI.
//!
//! Design doc §13 P.2 / P.3 implementation surface (see
//! `doc/uno-workchain.md`).
//!
//! # What this is
//!
//! This crate is the Rust-side proof-system implementation for the Uno
//! workchain. It:
//!
//! 1. Implements the Uno Transfer AIR over the full §4.1 envelope
//!    (`1..4` spends × `1..4` outputs) with real Poseidon2-Goldilocks
//!    constraints, Merkle-path checks, nullifier derivation and
//!    in-circuit balance enforcement (see [`transfer_air`]).
//! 2. Exposes the reference prover + consensus-critical verifier over that
//!    AIR (see [`prover`] and [`verifier`]).
//! 3. Wraps both in a C ABI suitable for the C++ validator to consume
//!    (this file).
//!
//! Plonky3 provides the generic STARK proving/verifying machinery; this
//! crate supplies the Uno-specific AIR, public-input encoding, shape
//! dispatch, parameter pinning and FFI boundary needed to make that
//! machinery usable from the validator.
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
#![allow(missing_docs)]
#![allow(clippy::missing_safety_doc)]

use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;

pub mod aggregator;
pub mod alpha_reduction_air;
pub mod block_wire_format;
pub mod challenger_air;
pub mod compression_path_air;
pub mod fiat_shamir;
pub mod fold_air;
pub mod fri_arith;
pub mod fri_verify;
pub mod leaf_hash_air;
pub mod merkle_path;
pub mod merkle_path_air;
pub mod monolithic_verifier_air;
mod monolithic_verifier_columns;
mod monolithic_verifier_trace;
pub mod ood_eval;
pub mod open_input;
pub mod permute;
pub mod prover;
pub mod query_verifier_air;
pub mod range16_air;
pub mod transfer_air;
mod transfer_columns;
mod transfer_preimage;
mod transfer_sponge;
mod transfer_witness;
pub mod mine_uno_air;
mod mine_uno_columns;
pub mod mine_uno_witness;
pub mod verifier;
pub mod verifier_air;

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
/// [`uno_plonky3_verifier_free`]. Internally holds the Plonky3
/// `StarkConfig` and the two-AIR (`MvpTransferAir` + `Range16Air`)
/// batch-stark verifier with the cross-AIR u16 range-check LogUp
/// wired — the full M-P2 production path as of Phase 5 (commit
/// migrating from the pre-M-P2 uni-stark verifier).
///
/// Thread-safety: the handle is `Send + Sync` and may be used
/// concurrently from multiple threads. Required by design doc §13
/// P.3 (parallel verify across `num_cores` workers is an activation
/// prerequisite).
pub struct Plonky3VerifierHandle {
    inner: Arc<verifier::MvpBatchVerifier>,
}

/// Opaque handle to an initialized Plonky3 prover.
///
/// Constructed by [`uno_plonky3_prover_init`], destroyed by
/// [`uno_plonky3_prover_free`]. Used by `tosctl` wallets for
/// witness-to-proof generation. Internally runs the production
/// batch-stark prover with cross-AIR u16 range-check
/// (`MvpBatchProver::prove_with_range_check`) so the proof bytes
/// returned here verify against [`Plonky3VerifierHandle`] on the
/// validator side.
pub struct Plonky3ProverHandle {
    inner: Arc<prover::MvpBatchProver>,
}

/// Opaque handle to an initialized block-level aggregated-proof verifier.
///
/// Constructed by [`uno_block_verifier_init`] and destroyed by
/// [`uno_block_verifier_free`]. Wraps the A6-1.5 real `verify_block`
/// function (monolithic AIR + Plonky3 `uni_stark::verify`).
///
/// A single validator process is expected to hold ONE of these handles,
/// shared across the compute-phase worker pool by `const&`. Thread-safe
/// by construction (the wrapped verify is stateless; the `StarkConfig`
/// is re-derived per call from `prover::build_config`).
pub struct UnoBlockVerifierHandle {
    /// A sentinel: verify functions are stateless today, so the handle
    /// carries no hot state. Kept as an opaque struct for ABI stability
    /// — a future `Arc<AggregatedBlockVerifier>` can drop in without
    /// breaking the C++ side.
    _phantom: (),
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

/// Borrowed witness bytes for the reference prover. Layout is defined in
/// [`transfer_air::MvpWitness::encode`].
///
/// # Witness wire length (P.2 scale-to-envelope)
///
/// The witness encoding is length-variable across the §4.1 envelope:
///
/// ```text
/// witness_len = 18 + 64·n_spends + 40·n_outputs
/// ```
///
/// — `1 ≤ n_spends, n_outputs ≤ 4`. Prior slices (A4 MVP → N-P2 real
/// Poseidon2) shipped a fixed 64 B witness at (1, 1). This slice
/// replaces the fixed shape with a shape header (`u8 n_spends || u8
/// n_outputs`) followed by per-spend and per-output records. The
/// witness is a **prover-only** wire format and does not affect the
/// consensus-binding public-input or proof bytes.
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
            inner: Arc::new(verifier::MvpBatchVerifier::new()),
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
        let Some(pi_bytes) = (unsafe { slice_from_parts(public_inputs.ptr, public_inputs.len) })
        else {
            return Plonky3Status::NullPointer;
        };

        // Phase 5: route through the batch-stark + cross-AIR u16 range-
        // check path. Proof bytes must be a postcard-encoded
        // `BatchProof<MvpConfig>`; legacy `Proof<MvpConfig>` uni-stark
        // bytes are rejected with `ProofDecodeFailed`.
        handle.inner.verify_with_range_check(proof_bytes, pi_bytes)
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
pub unsafe extern "C" fn uno_plonky3_prover_init(out_handle: *mut *mut Plonky3ProverHandle) -> i32 {
    ffi_guard(|| {
        if out_handle.is_null() {
            return Plonky3Status::NullPointer;
        }
        let handle = Box::new(Plonky3ProverHandle {
            inner: Arc::new(prover::MvpBatchProver::new()),
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

        let Some(witness_bytes) = (unsafe { slice_from_parts(witness.ptr, witness.len) }) else {
            return Plonky3Status::NullPointer;
        };

        // Phase 5: route through the batch-stark + cross-AIR u16 range-
        // check path. Returns postcard-encoded `BatchProof<MvpConfig>`
        // bytes + unchanged `MvpWitness::public_inputs_bytes()` bytes.
        match handle.inner.prove_with_range_check(witness_bytes) {
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
                    *out_proof = Plonky3OwnedProof { ptr, len, cap: len };
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
// A6-1: UnoBlockExtra wire-format FFI surface
//
// C++ consumers (validator / mempool / collator) use these to framing-
// decode the block-level aggregated-proof container before handing the
// opaque proof payload to the aggregated verifier (A6-2). Errors surface
// BEFORE any proof buffer is allocated, so a malformed block header
// cannot cause an allocator-based DoS.
//
// Layout of the C-side view is deliberately flat byte buffers, not a
// mirrored C struct — the Rust decoder does the framing, the C++ side
// just passes bytes through. This lets the wire format evolve under a
// `scheme_id`-bump without an ABI break.
// ---------------------------------------------------------------------------

/// Borrowed byte buffer passed across the FFI for wire-format decode.
#[repr(C)]
pub struct UnoBlockExtraBytes {
    /// Raw bytes of an encoded `UnoBlockExtra` (header + proof).
    pub ptr: *const u8,
    /// Length in bytes.
    pub len: usize,
}

/// Parsed header fields the C++ side needs to inspect. The aggregated
/// proof payload is returned separately via an owned buffer — the
/// caller frees it via [`uno_block_extra_owned_free`].
///
/// Layout must match the C side byte-for-byte. `scheme_id` / `version`
/// are tagged by the Rust decoder against the accepted set, so the C
/// caller can trust the fields it receives.
#[repr(C)]
pub struct UnoBlockExtraParsed {
    /// Matches `UNO_AGGREGATOR_SCHEME_ID_V1` at launch.
    pub scheme_id: u8,
    /// Matches `UNO_AGGREGATOR_VERSION_V1` at launch.
    pub version: u8,
    /// Padding for alignment; always written as 0.
    pub _pad0: u16,
    /// 0..=BLOCK_TX_CAP. Already bounds-checked by decoder.
    pub n_transfers: u16,
    /// Padding for alignment; always written as 0.
    pub _pad1: u16,
    /// BLAKE3 root over per-Tx PI hashes (inclusion order).
    pub tx_pi_merkle_root: [u8; 32],
    /// Heap-allocated aggregated proof payload (opaque to this layer).
    /// Callers MUST free via [`uno_block_extra_owned_free`] exactly once.
    pub aggregated_proof_ptr: *mut u8,
    /// Bytes in the aggregated proof payload.
    pub aggregated_proof_len: usize,
    /// Allocation capacity needed to reconstruct the `Vec` on free.
    pub aggregated_proof_cap: usize,
}

impl UnoBlockExtraParsed {
    const EMPTY: Self = Self {
        scheme_id: 0,
        version: 0,
        _pad0: 0,
        n_transfers: 0,
        _pad1: 0,
        tx_pi_merkle_root: [0u8; 32],
        aggregated_proof_ptr: std::ptr::null_mut(),
        aggregated_proof_len: 0,
        aggregated_proof_cap: 0,
    };
}

/// Decode an encoded `UnoBlockExtra` into [`UnoBlockExtraParsed`].
///
/// Error mapping (wire-layer only; the aggregated proof itself is NOT
/// verified here — call [`uno_block_verifier_verify`] separately):
///
/// | `DecodeError`           | `Plonky3Status`                |
/// |-------------------------|--------------------------------|
/// | `ShortHeader`           | `ProofDecodeFailed` (1)        |
/// | `UnknownSchemeId`       | `ProofDecodeFailed` (1)        |
/// | `UnknownVersion`        | `ProofDecodeFailed` (1)        |
/// | `TooManyTransfers`      | `ProofDecodeFailed` (1)        |
/// | `ProofTooLarge`         | `LengthTooLarge` (7)           |
/// | `ProofLengthMismatch`   | `ProofDecodeFailed` (1)        |
///
/// # Safety
/// - `bytes.ptr` / `bytes.len` must describe a valid, readable region.
/// - `out` must be a valid, aligned, writable pointer to an
///   `UnoBlockExtraParsed`. Previous contents are overwritten.
/// - On non-Ok return, `*out` is cleared to `EMPTY` and caller must
///   NOT free; on Ok return, caller MUST free via
///   [`uno_block_extra_owned_free`] exactly once.
#[no_mangle]
pub unsafe extern "C" fn uno_block_extra_decode(
    bytes: UnoBlockExtraBytes,
    out: *mut UnoBlockExtraParsed,
) -> i32 {
    ffi_guard(|| {
        if out.is_null() {
            return Plonky3Status::NullPointer;
        }
        // SAFETY: caller upholds writability.
        unsafe {
            *out = UnoBlockExtraParsed::EMPTY;
        }

        let input = match unsafe { slice_from_parts(bytes.ptr, bytes.len) } {
            Some(s) => s,
            None => return Plonky3Status::NullPointer,
        };

        let decoded = match block_wire_format::decode(input) {
            Ok(d) => d,
            Err(block_wire_format::DecodeError::ProofTooLarge { .. }) => {
                return Plonky3Status::LengthTooLarge;
            }
            Err(_) => {
                return Plonky3Status::ProofDecodeFailed;
            }
        };

        // Move the proof bytes into a heap-stable Vec, hand ownership
        // to the caller via raw parts. Mirrors `uno_plonky3_prove`'s
        // pattern so the caller's free path is identical.
        let mut proof_vec = decoded.aggregated_proof;
        let ptr = proof_vec.as_mut_ptr();
        let len = proof_vec.len();
        let cap = proof_vec.capacity();
        std::mem::forget(proof_vec);

        // SAFETY: caller upholds writability of `out`.
        unsafe {
            *out = UnoBlockExtraParsed {
                scheme_id: decoded.aggregator_scheme_id,
                version: decoded.aggregator_version,
                _pad0: 0,
                n_transfers: decoded.n_transfers,
                _pad1: 0,
                tx_pi_merkle_root: decoded.tx_pi_merkle_root,
                aggregated_proof_ptr: ptr,
                aggregated_proof_len: len,
                aggregated_proof_cap: cap,
            };
        }

        Plonky3Status::Ok
    })
}

/// Free the heap buffer owned by a previously-returned
/// [`UnoBlockExtraParsed`]. Idempotent iff called exactly once per
/// successful decode — double-free is undefined behavior.
///
/// # Safety
/// `parsed.aggregated_proof_ptr` must have come from
/// [`uno_block_extra_decode`] and must not have been freed. The other
/// fields must be unchanged from the decode call.
#[no_mangle]
pub unsafe extern "C" fn uno_block_extra_owned_free(parsed: UnoBlockExtraParsed) {
    if parsed.aggregated_proof_ptr.is_null() || parsed.aggregated_proof_cap == 0 {
        return;
    }
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: reconstruct the Vec leaked in `decode`.
        unsafe {
            let _ = Vec::from_raw_parts(
                parsed.aggregated_proof_ptr,
                parsed.aggregated_proof_len,
                parsed.aggregated_proof_cap,
            );
        }
    }));
}

/// Encode a fresh `UnoBlockExtra` v1 from its constituent fields.
/// Primarily intended for tests and for tooling that needs to emit a
/// canonical wire blob (collator side). The validator path only needs
/// [`uno_block_extra_decode`].
///
/// Returns a heap-allocated byte buffer via `out_bytes`; caller MUST
/// free via [`uno_plonky3_proof_free`] (shares the same allocator
/// discipline — a `Plonky3OwnedProof`-shaped Vec).
///
/// # Safety
/// - `tx_pi_merkle_root` must be a valid 32-byte readable region.
/// - `proof_bytes` must be a valid readable region of `proof_len` bytes
///   (or null with `proof_len == 0`).
/// - `out_bytes` must be a valid, aligned, writable `*mut
///   Plonky3OwnedProof`. Previous contents are overwritten.
#[no_mangle]
pub unsafe extern "C" fn uno_block_extra_encode_v1(
    n_transfers: u16,
    tx_pi_merkle_root: *const u8,
    proof_bytes: *const u8,
    proof_len: usize,
    out_bytes: *mut Plonky3OwnedProof,
) -> i32 {
    ffi_guard(|| {
        if out_bytes.is_null() || tx_pi_merkle_root.is_null() {
            return Plonky3Status::NullPointer;
        }
        // SAFETY: caller upholds writability of `out_bytes`.
        unsafe {
            *out_bytes = Plonky3OwnedProof::EMPTY;
        }

        // Bounds check: n_transfers must fit BLOCK_TX_CAP and proof_len
        // must fit the wire-format cap. Mirror `UnoBlockExtra::v1` which
        // panics on violation; here we return typed errors instead.
        if n_transfers as usize > crate::aggregator::BLOCK_TX_CAP {
            return Plonky3Status::WitnessInvalid;
        }
        if proof_len > block_wire_format::UNO_BLOCK_EXTRA_MAX_PROOF_BYTES as usize {
            return Plonky3Status::LengthTooLarge;
        }

        let proof_slice = match unsafe { slice_from_parts(proof_bytes, proof_len) } {
            Some(s) => s,
            None => return Plonky3Status::NullPointer,
        };

        // SAFETY: caller promised tx_pi_merkle_root[..32] is readable.
        let root: [u8; 32] = unsafe {
            let mut r = [0u8; 32];
            std::ptr::copy_nonoverlapping(tx_pi_merkle_root, r.as_mut_ptr(), 32);
            r
        };

        let extra = block_wire_format::UnoBlockExtra::v1(
            n_transfers,
            root,
            crate::aggregator::AggregatedProof {
                bytes: proof_slice.to_vec(),
            },
        );
        let mut encoded = block_wire_format::encode(&extra);
        let ptr = encoded.as_mut_ptr();
        let len = encoded.len();
        let cap = encoded.capacity();
        std::mem::forget(encoded);

        // SAFETY: caller upholds writability of `out_bytes`.
        unsafe {
            *out_bytes = Plonky3OwnedProof { ptr, len, cap };
        }

        Plonky3Status::Ok
    })
}

// ---------------------------------------------------------------------------
// A6-2: Block-level aggregated-proof verifier FFI surface
//
// Sits on top of the A6-1.5 `aggregator::verify_block` function.
// The C++ validator holds ONE handle, shared across the compute-phase
// worker pool (thread-safe — verify is stateless).
//
// PI binding status (A6-1.6): the AIR NOW binds the 8 PI fields
// (chain_id, block_seqno, anchor_seqno, n_transfers, 4× u64 LE chunks
// of tx_pi_merkle_root) to 8 public-input columns via a row-0 boundary
// + unconditional persistence. The C++ validator still MAY cross-check
// PI at the consensus layer as defence-in-depth, but the STARK itself
// now rejects a proof whose PI doesn't match the bytes baked inside.
// ---------------------------------------------------------------------------

/// Flat view of [`BlockPublicInputs`] passed across the FFI. Layout
/// matches C `struct` packing: 8-byte-aligned fields, u16 padding
/// explicit.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct UnoBlockPublicInputsView {
    /// Matches `BlockPublicInputs.chain_id`.
    pub chain_id: u32,
    /// Padding for 8-byte alignment.
    pub _pad0: u32,
    /// Matches `BlockPublicInputs.block_seqno`.
    pub block_seqno: u64,
    /// Matches `BlockPublicInputs.anchor_seqno`.
    pub anchor_seqno: u64,
    /// Matches `BlockPublicInputs.n_transfers` (0..=BLOCK_TX_CAP).
    pub n_transfers: u16,
    /// Padding for 8-byte alignment.
    pub _pad1: [u8; 6],
    /// Matches `BlockPublicInputs.tx_pi_merkle_root`.
    pub tx_pi_merkle_root: [u8; 32],
}

/// Initialize the block-level aggregated-proof verifier. Returns an
/// opaque handle that the caller owns and MUST free via
/// [`uno_block_verifier_free`] exactly once.
///
/// # Safety
/// `out_handle` must be a valid, aligned, writable
/// `*mut *mut UnoBlockVerifierHandle` pointer.
#[no_mangle]
pub unsafe extern "C" fn uno_block_verifier_init(
    out_handle: *mut *mut UnoBlockVerifierHandle,
) -> i32 {
    ffi_guard(|| {
        if out_handle.is_null() {
            return Plonky3Status::NullPointer;
        }
        let handle = Box::new(UnoBlockVerifierHandle { _phantom: () });
        // SAFETY: caller upholds writability.
        unsafe {
            *out_handle = Box::into_raw(handle);
        }
        Plonky3Status::Ok
    })
}

/// Free a verifier handle previously returned by
/// [`uno_block_verifier_init`]. Idempotent for a null pointer.
///
/// # Safety
/// `handle` must be from [`uno_block_verifier_init`] and not already
/// freed. Passing null is safe and a no-op.
#[no_mangle]
pub unsafe extern "C" fn uno_block_verifier_free(handle: *mut UnoBlockVerifierHandle) {
    if handle.is_null() {
        return;
    }
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: caller guarantees handle came from a Box::into_raw
        // in `uno_block_verifier_init` and hasn't been freed.
        unsafe {
            drop(Box::from_raw(handle));
        }
    }));
}

/// Verify an aggregated block proof against its public inputs.
///
/// | return               | meaning                                        |
/// |----------------------|------------------------------------------------|
/// | `kOk` (0)            | Proof cryptographically verified against PI.   |
/// | `kProofDecodeFailed` | Postcard decode failed (malformed bytes).      |
/// | `kVerifyFailed`      | STARK verify returned an error.                |
/// | `kNullPointer`       | `handle` / `pi` / `proof.ptr` null invalid.    |
/// | `kInternalError`     | Panic inside Rust (should not happen).         |
///
/// # Safety
/// - `handle` must be a live handle from [`uno_block_verifier_init`].
/// - `pi` must point to a valid [`UnoBlockPublicInputsView`].
/// - `proof.ptr` / `proof.len` must describe a valid readable region
///   (or ptr null with `len == 0` for the trivially-empty case).
#[no_mangle]
pub unsafe extern "C" fn uno_block_verifier_verify(
    handle: *const UnoBlockVerifierHandle,
    pi: *const UnoBlockPublicInputsView,
    proof: Plonky3ProofBytes,
) -> i32 {
    ffi_guard(|| {
        if handle.is_null() || pi.is_null() {
            return Plonky3Status::NullPointer;
        }

        let pi_view = unsafe { &*pi };
        let pi_rust = aggregator::BlockPublicInputs {
            chain_id: pi_view.chain_id,
            block_seqno: pi_view.block_seqno,
            anchor_seqno: pi_view.anchor_seqno,
            n_transfers: pi_view.n_transfers,
            tx_pi_merkle_root: pi_view.tx_pi_merkle_root,
        };

        let proof_slice = match unsafe { slice_from_parts(proof.ptr, proof.len) } {
            Some(s) => s,
            None => return Plonky3Status::NullPointer,
        };
        let agg_proof = aggregator::AggregatedProof {
            bytes: proof_slice.to_vec(),
        };

        match aggregator::verify_block(&pi_rust, &agg_proof) {
            Ok(()) => Plonky3Status::Ok,
            Err(aggregator::BlockVerifyError::ProofMalformed) => Plonky3Status::ProofDecodeFailed,
            Err(aggregator::BlockVerifyError::StarkVerifyFailed) => Plonky3Status::VerifyFailed,
        }
    })
}

// ---------------------------------------------------------------------------
// MineUno prove / verify FFI surface (Phase 3 — final wiring)
//
// The MineUno AIR ships with a single shape (no `n_spends × n_outputs`
// dispatch). Prove and verify take byte buffers directly — no opaque
// handle is needed because the underlying `StarkConfig` is cheap to
// rebuild per call (the Transfer path holds one only because a handle
// was already baked into the wider Phase 5 lifecycle). Matching the
// simpler shape keeps the MineUno FFI easy to consume from wc=2
// wallets / tosctl.
//
// Memory discipline mirrors `uno_plonky3_prove`: on `Ok` the proof +
// public-input buffer is returned concatenated as
// `[u32 LE proof_len][proof_bytes][public_input_bytes]` via a heap
// `Plonky3OwnedProof`. Callers free with [`uno_plonky3_proof_free`].
// ---------------------------------------------------------------------------

/// Run the MineUno STARK prover against a canonical
/// [`crate::mine_uno_witness::MineUnoWitness`] wire encoding.
///
/// On `Ok`, `*out_proof` is populated with a heap-allocated buffer
/// containing `[u32 LE proof_len][proof_bytes][public_input_bytes]`; the
/// caller MUST free via [`uno_plonky3_proof_free`] exactly once. On any
/// non-Ok return, `*out_proof` is cleared to an empty descriptor and the
/// caller must NOT attempt to free it.
///
/// # Safety
/// - `witness` must describe a valid, readable byte range (`ptr` non-
///   null and `[ptr, ptr+len)` readable for the duration of the call),
///   or an empty descriptor (`len == 0`). The bytes must be a canonical
///   wire-encoded `MineUnoWitness` (see `mine_uno_witness::MINE_UNO_WITNESS_BYTES`).
/// - `out_proof` must be a valid, aligned, writable pointer to a
///   `Plonky3OwnedProof`. Previous contents are overwritten.
#[no_mangle]
pub unsafe extern "C" fn uno_mine_uno_prove(
    witness: Plonky3Witness,
    out_proof: *mut Plonky3OwnedProof,
) -> i32 {
    ffi_guard(|| {
        if out_proof.is_null() {
            return Plonky3Status::NullPointer;
        }
        // SAFETY: caller guarantees writability of out_proof.
        unsafe {
            *out_proof = Plonky3OwnedProof::EMPTY;
        }

        let Some(witness_bytes) = (unsafe { slice_from_parts(witness.ptr, witness.len) }) else {
            return Plonky3Status::NullPointer;
        };

        match prover::prove_mine_uno(witness_bytes) {
            Ok((proof_bytes, public_inputs_bytes)) => {
                // Concatenated owned layout: `[u32 LE proof_len][proof][pi]`.
                // Mirrors `uno_plonky3_prove` so the caller-side free path
                // is identical across the two prove entry points.
                let mut out = Vec::with_capacity(4 + proof_bytes.len() + public_inputs_bytes.len());
                out.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
                out.extend_from_slice(&proof_bytes);
                out.extend_from_slice(&public_inputs_bytes);
                out.shrink_to_fit();

                let mut boxed = out.into_boxed_slice();
                let ptr = boxed.as_mut_ptr();
                let len = boxed.len();
                std::mem::forget(boxed);
                // SAFETY: out_proof is non-null & writable per caller.
                unsafe {
                    *out_proof = Plonky3OwnedProof { ptr, len, cap: len };
                }
                Plonky3Status::Ok
            }
            Err(status) => status,
        }
    })
}

/// Verify a MineUno STARK proof against its public-input bytes.
///
/// Returns:
/// - [`Plonky3Status::Ok`] iff the proof is valid for the public inputs.
/// - A specific decode / length / verify error code otherwise.
///
/// # Safety
/// - `proof` and `public_inputs` buffers must each describe a valid
///   readable byte range for the duration of the call (or an empty
///   descriptor with `len == 0`).
#[no_mangle]
pub unsafe extern "C" fn uno_mine_uno_verify(
    proof: Plonky3ProofBytes,
    public_inputs: Plonky3PublicInputs,
) -> i32 {
    ffi_guard(|| {
        let Some(proof_bytes) = (unsafe { slice_from_parts(proof.ptr, proof.len) }) else {
            return Plonky3Status::NullPointer;
        };
        let Some(pi_bytes) = (unsafe { slice_from_parts(public_inputs.ptr, public_inputs.len) })
        else {
            return Plonky3Status::NullPointer;
        };
        verifier::verify_mine_uno(proof_bytes, pi_bytes)
    })
}

// ---------------------------------------------------------------------------
// Version / ABI probe
// ---------------------------------------------------------------------------

/// Returns the ABI revision of this crate. The C++ bridge checks this at
/// `Plonky3Verifier::init()` to catch a version-skew between the shipped
/// Rust static-lib and the compiled C++ header.
///
/// Current value: 4 (bumped from 3 by Phase 3 final wiring, which adds
/// [`uno_mine_uno_prove`] and [`uno_mine_uno_verify`] to the FFI surface
/// for the MineUno AIR). Bump on any layout change to existing FFI
/// structs or any addition/removal of FFI entry points.
///
/// History:
/// - v1 → v2 (A6-1): UnoBlockExtra{Bytes,Parsed} + wire-format entry points.
/// - v2 → v3 (A6-2): UnoBlockPublicInputsView + block-verifier handle.
/// - v3 → v4 (MineUno Phase 3): uno_mine_uno_prove / uno_mine_uno_verify
///   for the MineUno AIR.
#[no_mangle]
pub extern "C" fn uno_plonky3_abi_version() -> u32 {
    4
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

        // Build a valid 1-spend / 1-output witness via the transfer_air
        // module helper. P.2 scale-to-envelope: the MvpWitness API now
        // takes explicit shape parameters.
        let witness = transfer_air::MvpWitness::deterministic_valid(1, 1, 0x1234_5678_9abc_def0);
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
        let owned = unsafe { std::slice::from_raw_parts(out_proof.ptr, out_proof.len) }.to_vec();
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
            transfer_air::MvpWitness::deterministic_valid(1, 1, 0xcafe_f00d_dead_beef);
        let honest_pi_bytes = honest_witness.public_inputs_bytes();

        // Adversary's tampered witness: flip a sibling bit of spend 0's
        // diversifier `d` proxy.
        let mut bad_witness = honest_witness.clone();
        bad_witness.spends[0].d[0] ^= 1;
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
            let proof_len = u32::from_le_bytes([owned[0], owned[1], owned[2], owned[3]]) as usize;
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
    /// v4 added `uno_mine_uno_prove` / `uno_mine_uno_verify`.
    #[test]
    fn abi_version_probe() {
        assert_eq!(uno_plonky3_abi_version(), 4);
    }

    // =======================================================================
    // A6-1 UnoBlockExtra FFI — round-trip + error-path coverage
    // =======================================================================

    fn sample_encoded_block_extra(proof_len: usize) -> Vec<u8> {
        // Build with the safe Rust builder, encode, then pass the
        // bytes through the FFI decoder. This validates that the
        // FFI decoder is byte-for-byte compatible with the Rust one.
        let proof = crate::aggregator::AggregatedProof {
            bytes: (0..proof_len).map(|i| i as u8).collect(),
        };
        let extra = block_wire_format::UnoBlockExtra::v1(3, [0x7e; 32], proof);
        block_wire_format::encode(&extra)
    }

    #[test]
    fn block_extra_ffi_decode_round_trip() {
        let encoded = sample_encoded_block_extra(128);
        let mut parsed = UnoBlockExtraParsed::EMPTY;

        let rc = unsafe {
            uno_block_extra_decode(
                UnoBlockExtraBytes {
                    ptr: encoded.as_ptr(),
                    len: encoded.len(),
                },
                &mut parsed,
            )
        };
        assert_eq!(rc, Plonky3Status::Ok.as_i32());
        assert_eq!(
            parsed.scheme_id,
            block_wire_format::UNO_AGGREGATOR_SCHEME_ID_V1
        );
        assert_eq!(parsed.version, block_wire_format::UNO_AGGREGATOR_VERSION_V1);
        assert_eq!(parsed.n_transfers, 3);
        assert_eq!(parsed.tx_pi_merkle_root, [0x7e; 32]);
        assert_eq!(parsed.aggregated_proof_len, 128);
        assert!(!parsed.aggregated_proof_ptr.is_null());

        // Inspect first + last byte of returned proof buffer.
        unsafe {
            let slice = std::slice::from_raw_parts(
                parsed.aggregated_proof_ptr,
                parsed.aggregated_proof_len,
            );
            assert_eq!(slice[0], 0);
            assert_eq!(slice[127], 127);
        }

        // Free the owned buffer; must not leak.
        unsafe {
            uno_block_extra_owned_free(parsed);
        }
    }

    #[test]
    fn block_extra_ffi_decode_null_out_returns_null_pointer() {
        let encoded = sample_encoded_block_extra(32);
        let rc = unsafe {
            uno_block_extra_decode(
                UnoBlockExtraBytes {
                    ptr: encoded.as_ptr(),
                    len: encoded.len(),
                },
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, Plonky3Status::NullPointer.as_i32());
    }

    #[test]
    fn block_extra_ffi_decode_null_input_returns_null_pointer() {
        let mut parsed = UnoBlockExtraParsed::EMPTY;
        let rc = unsafe {
            uno_block_extra_decode(
                UnoBlockExtraBytes {
                    ptr: std::ptr::null(),
                    len: 64,
                },
                &mut parsed,
            )
        };
        assert_eq!(rc, Plonky3Status::NullPointer.as_i32());
        assert!(parsed.aggregated_proof_ptr.is_null());
    }

    #[test]
    fn block_extra_ffi_decode_short_header_rejects() {
        let short = vec![0u8; 10];
        let mut parsed = UnoBlockExtraParsed::EMPTY;
        let rc = unsafe {
            uno_block_extra_decode(
                UnoBlockExtraBytes {
                    ptr: short.as_ptr(),
                    len: short.len(),
                },
                &mut parsed,
            )
        };
        assert_eq!(rc, Plonky3Status::ProofDecodeFailed.as_i32());
        assert!(parsed.aggregated_proof_ptr.is_null());
    }

    #[test]
    fn block_extra_ffi_decode_unknown_scheme_rejects() {
        let mut encoded = sample_encoded_block_extra(16);
        encoded[0] = 0xff; // unknown scheme_id
        let mut parsed = UnoBlockExtraParsed::EMPTY;
        let rc = unsafe {
            uno_block_extra_decode(
                UnoBlockExtraBytes {
                    ptr: encoded.as_ptr(),
                    len: encoded.len(),
                },
                &mut parsed,
            )
        };
        assert_eq!(rc, Plonky3Status::ProofDecodeFailed.as_i32());
    }

    #[test]
    fn block_extra_ffi_decode_proof_too_large_rejects() {
        // Forge a header claiming proof_len > cap (no need to allocate
        // it; the FFI decoder should reject before attempting a read).
        let mut bytes = vec![0u8; block_wire_format::UNO_BLOCK_EXTRA_HEADER_BYTES];
        bytes[0] = block_wire_format::UNO_AGGREGATOR_SCHEME_ID_V1;
        bytes[1] = block_wire_format::UNO_AGGREGATOR_VERSION_V1;
        let bad_len = block_wire_format::UNO_BLOCK_EXTRA_MAX_PROOF_BYTES + 1;
        bytes[36..40].copy_from_slice(&bad_len.to_le_bytes());
        let mut parsed = UnoBlockExtraParsed::EMPTY;
        let rc = unsafe {
            uno_block_extra_decode(
                UnoBlockExtraBytes {
                    ptr: bytes.as_ptr(),
                    len: bytes.len(),
                },
                &mut parsed,
            )
        };
        assert_eq!(rc, Plonky3Status::LengthTooLarge.as_i32());
    }

    #[test]
    fn block_extra_ffi_encode_round_trip() {
        let proof_bytes: Vec<u8> = (0..256u32).map(|i| i as u8).collect();
        let root = [0x5a; 32];
        let mut out = Plonky3OwnedProof::EMPTY;
        let rc = unsafe {
            uno_block_extra_encode_v1(
                // v1 BLOCK_TX_CAP = 4; use boundary value.
                4,
                root.as_ptr(),
                proof_bytes.as_ptr(),
                proof_bytes.len(),
                &mut out,
            )
        };
        assert_eq!(rc, Plonky3Status::Ok.as_i32());
        assert!(!out.ptr.is_null());
        assert_eq!(
            out.len,
            block_wire_format::UNO_BLOCK_EXTRA_HEADER_BYTES + 256
        );

        // Feed the encoded bytes back through the decode FFI.
        let mut parsed = UnoBlockExtraParsed::EMPTY;
        let rc = unsafe {
            uno_block_extra_decode(
                UnoBlockExtraBytes {
                    ptr: out.ptr,
                    len: out.len,
                },
                &mut parsed,
            )
        };
        assert_eq!(rc, Plonky3Status::Ok.as_i32());
        assert_eq!(parsed.n_transfers, 4);
        assert_eq!(parsed.tx_pi_merkle_root, root);
        assert_eq!(parsed.aggregated_proof_len, 256);

        unsafe {
            uno_block_extra_owned_free(parsed);
            uno_plonky3_proof_free(out);
        }
    }

    #[test]
    fn block_extra_ffi_encode_rejects_n_transfers_overflow() {
        let mut out = Plonky3OwnedProof::EMPTY;
        let bad_n = (crate::aggregator::BLOCK_TX_CAP + 1) as u16;
        let rc = unsafe {
            uno_block_extra_encode_v1(bad_n, [0u8; 32].as_ptr(), std::ptr::null(), 0, &mut out)
        };
        assert_eq!(rc, Plonky3Status::WitnessInvalid.as_i32());
        assert!(out.ptr.is_null());
    }

    #[test]
    fn block_extra_ffi_owned_free_is_null_safe() {
        // Freeing the EMPTY parsed struct must be a no-op (null ptr + 0
        // cap) — mirrors `uno_plonky3_proof_free` null-safety.
        unsafe {
            uno_block_extra_owned_free(UnoBlockExtraParsed::EMPTY);
        }
    }

    // =======================================================================
    // A6-2 UnoBlockVerifier FFI — round-trip + error-path coverage
    //
    // These tests instantiate the handle, feed a real A6-1.5-generated
    // proof through the FFI, and confirm rejection paths.
    // =======================================================================

    fn sample_pi_view() -> UnoBlockPublicInputsView {
        UnoBlockPublicInputsView {
            chain_id: 7,
            _pad0: 0,
            block_seqno: 1,
            anchor_seqno: 0,
            n_transfers: 1,
            _pad1: [0u8; 6],
            tx_pi_merkle_root: [0u8; 32],
        }
    }

    /// Build a real A6-1.5 block proof for a 1-bundle toy trace, then
    /// pass its bytes through the A6-2 FFI verify entry point. Must
    /// return kOk.
    #[test]
    fn block_verifier_ffi_round_trip() {
        use crate::merkle_path::{compress_pair_ref, hash_leaf_row_ref};
        use crate::monolithic_verifier_air::{AlphaStep, BundleSpec, FoldRound, MerkleOpening};
        use crate::prover::Challenge;
        use p3_field::BasedVectorSpace;
        use p3_goldilocks::{default_goldilocks_poseidon2_8, Goldilocks};

        fn gl(v: u64) -> Goldilocks {
            Goldilocks::new(v)
        }
        fn ext(a: u64, b: u64) -> Challenge {
            Challenge::from_basis_coefficients_fn(|i| if i == 0 { gl(a) } else { gl(b) })
        }

        let perm = default_goldilocks_poseidon2_8();
        let leaf: Vec<Goldilocks> = (0..8u64).map(|j| gl(100 + j * 17 + 1)).collect();
        let sib_leaf: Vec<Goldilocks> = (0..8u64).map(|j| gl(200 + j * 23 + 3)).collect();
        let dig = hash_leaf_row_ref(&perm, &leaf);
        let sib = hash_leaf_row_ref(&perm, &sib_leaf);
        let root = compress_pair_ref(&perm, &dig, &sib);

        let alpha_steps = vec![AlphaStep {
            p_at_x: gl(7),
            p_at_z: ext(11, 13),
            z: ext(17, 19),
            x: gl(23),
        }];
        let opening = vec![sib];
        let mp = vec![MerkleOpening {
            leaf: &leaf,
            opening_proof: &opening,
            index: 0,
            expected_root: root,
        }];
        let fold_rounds = vec![FoldRound {
            sibling: ext(29, 31),
            beta: ext(37, 41),
            domain_index: 0b01,
            log_height: 3,
        }];
        let bundle = BundleSpec {
            initial_alpha_pow: ext(1, 0),
            initial_ro: ext(0, 0),
            alpha: ext(3, 5),
            alpha_steps: &alpha_steps,
            merkle_paths: &mp,
            fold_rounds: &fold_rounds,
        };

        let pi_rust = aggregator::BlockPublicInputs {
            chain_id: 7,
            block_seqno: 1,
            anchor_seqno: 0,
            n_transfers: 1,
            tx_pi_merkle_root: [0u8; 32],
        };
        let proof =
            aggregator::prove_block(&pi_rust, std::slice::from_ref(&bundle), 16).expect("prove");

        // Init handle.
        let mut handle: *mut UnoBlockVerifierHandle = std::ptr::null_mut();
        let rc = unsafe { uno_block_verifier_init(&mut handle) };
        assert_eq!(rc, Plonky3Status::Ok.as_i32());
        assert!(!handle.is_null());

        // Verify via FFI.
        let pi_view = sample_pi_view();
        let rc = unsafe {
            uno_block_verifier_verify(
                handle,
                &pi_view,
                Plonky3ProofBytes {
                    ptr: proof.bytes.as_ptr(),
                    len: proof.bytes.len(),
                },
            )
        };
        assert_eq!(rc, Plonky3Status::Ok.as_i32());

        unsafe { uno_block_verifier_free(handle) };
    }

    #[test]
    fn block_verifier_ffi_rejects_garbage_proof() {
        let mut handle: *mut UnoBlockVerifierHandle = std::ptr::null_mut();
        unsafe { uno_block_verifier_init(&mut handle) };
        let pi_view = sample_pi_view();

        let junk = b"definitely-not-a-stark-proof".to_vec();
        let rc = unsafe {
            uno_block_verifier_verify(
                handle,
                &pi_view,
                Plonky3ProofBytes {
                    ptr: junk.as_ptr(),
                    len: junk.len(),
                },
            )
        };
        assert_eq!(rc, Plonky3Status::ProofDecodeFailed.as_i32());

        unsafe { uno_block_verifier_free(handle) };
    }

    #[test]
    fn block_verifier_ffi_rejects_null_handle() {
        let pi_view = sample_pi_view();
        let bytes = vec![1u8, 2, 3];
        let rc = unsafe {
            uno_block_verifier_verify(
                std::ptr::null(),
                &pi_view,
                Plonky3ProofBytes {
                    ptr: bytes.as_ptr(),
                    len: bytes.len(),
                },
            )
        };
        assert_eq!(rc, Plonky3Status::NullPointer.as_i32());
    }

    #[test]
    fn block_verifier_ffi_rejects_null_pi() {
        let mut handle: *mut UnoBlockVerifierHandle = std::ptr::null_mut();
        unsafe { uno_block_verifier_init(&mut handle) };
        let bytes = vec![1u8, 2, 3];
        let rc = unsafe {
            uno_block_verifier_verify(
                handle,
                std::ptr::null(),
                Plonky3ProofBytes {
                    ptr: bytes.as_ptr(),
                    len: bytes.len(),
                },
            )
        };
        assert_eq!(rc, Plonky3Status::NullPointer.as_i32());
        unsafe { uno_block_verifier_free(handle) };
    }

    #[test]
    fn block_verifier_ffi_init_null_out_rejects() {
        let rc = unsafe { uno_block_verifier_init(std::ptr::null_mut()) };
        assert_eq!(rc, Plonky3Status::NullPointer.as_i32());
    }

    #[test]
    fn block_verifier_ffi_free_null_is_noop() {
        // No observable state — just must not crash.
        unsafe { uno_block_verifier_free(std::ptr::null_mut()) };
    }

    // =======================================================================
    // MineUno FFI — Phase 3 final wiring
    //
    // Exercises the C-ABI `uno_mine_uno_prove` + `uno_mine_uno_verify`
    // entry points on a deterministic witness. Mirrors the Transfer FFI
    // round-trip test (`ffi_roundtrip_valid_witness`) so a breakage in
    // either path trips independently.
    // =======================================================================

    /// Prove + verify round-trip through the MineUno C ABI. Equivalent to
    /// `mine_uno_air::tests::mine_uno_air_prove_verify_roundtrip` but
    /// routed through the pointer-based FFI surface, including the
    /// `[u32 proof_len][proof][pi]` owned-buffer layout.
    #[test]
    fn mine_uno_ffi_roundtrip_valid_witness() {
        use crate::mine_uno_witness::MineUnoWitness;

        // Deterministic witness (same fixture as the in-Rust roundtrip).
        let w = MineUnoWitness::deterministic_valid(0, 0xC0FF_EE);
        let witness_bytes = w.encode();

        // Prove.
        let mut out_proof = Plonky3OwnedProof::EMPTY;
        let rc = unsafe {
            uno_mine_uno_prove(
                Plonky3Witness {
                    ptr: witness_bytes.as_ptr(),
                    len: witness_bytes.len(),
                },
                &mut out_proof,
            )
        };
        assert_eq!(
            rc,
            Plonky3Status::Ok.as_i32(),
            "uno_mine_uno_prove must succeed"
        );
        assert!(!out_proof.ptr.is_null());

        // Unpack [u32 LE proof_len][proof_bytes][public_inputs_bytes].
        let owned = unsafe { std::slice::from_raw_parts(out_proof.ptr, out_proof.len) }.to_vec();
        assert!(owned.len() >= 4);
        let proof_len = u32::from_le_bytes([owned[0], owned[1], owned[2], owned[3]]) as usize;
        assert!(owned.len() >= 4 + proof_len);
        let proof_bytes = &owned[4..4 + proof_len];
        let pi_bytes = &owned[4 + proof_len..];

        // PI byte length == `N_PUBLIC_INPUTS * 8` (= 96) for the single
        // MineUno shape.
        assert_eq!(pi_bytes.len(), crate::mine_uno_air::PUBLIC_INPUT_BYTES);

        // Verify.
        let rc = unsafe {
            uno_mine_uno_verify(
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
            "uno_mine_uno_verify must accept a valid proof"
        );

        // Cleanup.
        unsafe { uno_plonky3_proof_free(out_proof) };
    }

    /// Tampering with the public-input bytes must cause verify to reject.
    /// Flipping a bit of `output_cm` decouples the PI from the proof
    /// transcript — the STARK verifier MUST NOT return Ok.
    #[test]
    fn mine_uno_ffi_rejects_tampered_public_inputs() {
        use crate::mine_uno_witness::MineUnoWitness;

        let w = MineUnoWitness::deterministic_valid(3, 0xDEAD_BEEF);
        let witness_bytes = w.encode();

        let mut out_proof = Plonky3OwnedProof::EMPTY;
        let rc = unsafe {
            uno_mine_uno_prove(
                Plonky3Witness {
                    ptr: witness_bytes.as_ptr(),
                    len: witness_bytes.len(),
                },
                &mut out_proof,
            )
        };
        assert_eq!(rc, Plonky3Status::Ok.as_i32());

        let owned = unsafe { std::slice::from_raw_parts(out_proof.ptr, out_proof.len) }.to_vec();
        let proof_len = u32::from_le_bytes([owned[0], owned[1], owned[2], owned[3]]) as usize;
        let proof_bytes = &owned[4..4 + proof_len];
        let mut pi_bytes = owned[4 + proof_len..].to_vec();
        // Flip a low-bit in the first limb of output_cm (byte offset
        // PI_OUTPUT_CM_BASE*8 = 16 inside the PI byte vector).
        pi_bytes[16] ^= 0x01;

        let rc = unsafe {
            uno_mine_uno_verify(
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
        assert_ne!(
            rc,
            Plonky3Status::Ok.as_i32(),
            "verify MUST reject a tampered-PI proof"
        );

        unsafe { uno_plonky3_proof_free(out_proof) };
    }

    /// A malformed witness (wrong byte length) is rejected by the decode
    /// step with `WitnessInvalid`, and `*out_proof` must stay empty so a
    /// naive caller that always free()'s cannot double-free nothing.
    #[test]
    fn mine_uno_ffi_rejects_short_witness() {
        let short = vec![0u8; 10];
        let mut out_proof = Plonky3OwnedProof::EMPTY;
        let rc = unsafe {
            uno_mine_uno_prove(
                Plonky3Witness {
                    ptr: short.as_ptr(),
                    len: short.len(),
                },
                &mut out_proof,
            )
        };
        assert_eq!(rc, Plonky3Status::WitnessInvalid.as_i32());
        assert!(out_proof.ptr.is_null());
        assert_eq!(out_proof.len, 0);
        assert_eq!(out_proof.cap, 0);
    }

    /// `uno_mine_uno_prove` with a null `out_proof` must return
    /// `NullPointer` and not crash.
    #[test]
    fn mine_uno_ffi_prove_null_out_rejects() {
        let rc = unsafe {
            uno_mine_uno_prove(
                Plonky3Witness {
                    ptr: std::ptr::null(),
                    len: 0,
                },
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, Plonky3Status::NullPointer.as_i32());
    }
}
