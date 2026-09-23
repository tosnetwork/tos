/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Poseidon2 over the BLS12-381 scalar field, t=8, with the parameters frozen
//! in [`crate::poseidon2_params`].
//!
//! This mirrors `crypto/vm/poseidon2ops.cpp` instruction for instruction. The
//! two implementations are held together by two things that cannot both drift
//! quietly: the manifest digest, which each rebuilds from its own vendored
//! tables, and the known-answer vectors, which come from a third implementation
//! -- the pinned upstream reference that generated them.

use crate::poseidon2_params::{
    MANIFEST_TAG, MAT_DIAG8_BE, MAT_INTERNAL8_BE, MODULUS_BE, RC8_BE, ROUNDS_F, ROUNDS_F_BEGINNING,
    ROUNDS_P, ROUNDS_TOTAL, SBOX_ALPHA, STATE_WIDTH,
};
use std::sync::OnceLock;

/// A canonical field element, 32 bytes big-endian. Inputs are rejected rather
/// than reduced, so this type only ever holds values below the modulus.
pub type FieldBytes = [u8; 32];

/// True when `value` is a canonical field element: below the modulus, which
/// also means it fits. Nothing is reduced; a caller holding a larger value has
/// a different value, not the same one written differently.
pub fn is_canonical(value: &FieldBytes) -> bool {
    value[..] < MODULUS_BE[..]
}

fn fr_from_be(bytes: &FieldBytes) -> blst::blst_fr {
    let mut scalar = blst::blst_scalar::default();
    let mut value = blst::blst_fr::default();
    // SAFETY: both buffers are fixed-size and fully initialised; blst reads 32
    // bytes and writes one field element.
    unsafe {
        blst::blst_scalar_from_bendian(&mut scalar, bytes.as_ptr());
        blst::blst_fr_from_scalar(&mut value, &scalar);
    }
    value
}

fn fr_to_be(value: &blst::blst_fr) -> FieldBytes {
    let mut scalar = blst::blst_scalar::default();
    let mut out = [0u8; 32];
    // SAFETY: as above, with the direction reversed.
    unsafe {
        blst::blst_scalar_from_fr(&mut scalar, value);
        blst::blst_bendian_from_scalar(out.as_mut_ptr(), &scalar);
    }
    out
}

/// Runs one blst field operation into an output blst writes in full.
///
/// `blst_fr::default()` would zero the thirty-two bytes first, and every one
/// of them is then overwritten. A permutation does on the order of eight
/// hundred of these, so the zeroing is not free: it is about a tenth of what
/// the permutation costs.
macro_rules! fr_op {
    ($call:expr) => {{
        let mut out = std::mem::MaybeUninit::<blst::blst_fr>::uninit();
        // SAFETY: blst writes the whole element before returning, so the
        // value is initialised by the time it is read. The inputs are
        // initialised field elements.
        unsafe {
            $call(out.as_mut_ptr());
            out.assume_init()
        }
    }};
}

fn add(a: &blst::blst_fr, b: &blst::blst_fr) -> blst::blst_fr {
    fr_op!(|out| blst::blst_fr_add(out, a, b))
}

fn mul(a: &blst::blst_fr, b: &blst::blst_fr) -> blst::blst_fr {
    fr_op!(|out| blst::blst_fr_mul(out, a, b))
}

fn sqr(a: &blst::blst_fr) -> blst::blst_fr {
    fr_op!(|out| blst::blst_fr_sqr(out, a))
}

fn sbox(x: &blst::blst_fr) -> blst::blst_fr {
    const _: () = assert!(SBOX_ALPHA == 5, "the S-box below is written for alpha = 5");
    let squared = sqr(x);
    let quartic = sqr(&squared);
    mul(&quartic, x)
}

struct Tables {
    diag: [blst::blst_fr; STATE_WIDTH],
    rc: [[blst::blst_fr; STATE_WIDTH]; ROUNDS_TOTAL],
}

fn tables() -> &'static Tables {
    static TABLES: OnceLock<Tables> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut diag = [blst::blst_fr::default(); STATE_WIDTH];
        for (slot, bytes) in diag.iter_mut().zip(MAT_DIAG8_BE.iter()) {
            *slot = fr_from_be(bytes);
        }
        let mut rc = [[blst::blst_fr::default(); STATE_WIDTH]; ROUNDS_TOTAL];
        for (row, source) in rc.iter_mut().zip(RC8_BE.iter()) {
            for (slot, bytes) in row.iter_mut().zip(source.iter()) {
                *slot = fr_from_be(bytes);
            }
        }
        Tables { diag, rc }
    })
}

/// The cheap 4x4 MDS block, applied to each quarter of the state.
fn matmul_m4(x: &mut [blst::blst_fr]) {
    let t0 = add(&x[0], &x[1]);
    let t1 = add(&x[2], &x[3]);
    let t2 = add(&add(&x[1], &x[1]), &t1);
    let t3 = add(&add(&x[3], &x[3]), &t0);
    let four_t1 = add(&add(&t1, &t1), &add(&t1, &t1));
    let t4 = add(&four_t1, &t3);
    let four_t0 = add(&add(&t0, &t0), &add(&t0, &t0));
    let t5 = add(&four_t0, &t2);
    let t6 = add(&t3, &t5);
    let t7 = add(&t2, &t4);
    x[0] = t6;
    x[1] = t5;
    x[2] = t7;
    x[3] = t4;
}

fn matmul_external(s: &mut [blst::blst_fr; STATE_WIDTH]) {
    let (first, second) = s.split_at_mut(4);
    matmul_m4(first);
    matmul_m4(second);
    let mut stored = [blst::blst_fr::default(); 4];
    for (lane, slot) in stored.iter_mut().enumerate() {
        *slot = add(&s[lane], &s[4 + lane]);
    }
    for (lane, slot) in s.iter_mut().enumerate() {
        *slot = add(slot, &stored[lane % 4]);
    }
}

fn matmul_internal(s: &mut [blst::blst_fr; STATE_WIDTH]) {
    let diag = &tables().diag;
    let mut sum = s[0];
    for value in s.iter().skip(1) {
        sum = add(&sum, value);
    }
    for (lane, slot) in s.iter_mut().enumerate() {
        *slot = add(&mul(slot, &diag[lane]), &sum);
    }
}

/// Runs the pinned permutation over eight canonical field elements.
pub fn permute(state: &[FieldBytes; STATE_WIDTH]) -> [FieldBytes; STATE_WIDTH] {
    let tables = tables();
    let mut s = [blst::blst_fr::default(); STATE_WIDTH];
    for (slot, bytes) in s.iter_mut().zip(state.iter()) {
        *slot = fr_from_be(bytes);
    }

    matmul_external(&mut s);
    let partial_end = ROUNDS_F_BEGINNING + ROUNDS_P;
    for round in 0..ROUNDS_F_BEGINNING {
        for (lane, slot) in s.iter_mut().enumerate() {
            *slot = sbox(&add(slot, &tables.rc[round][lane]));
        }
        matmul_external(&mut s);
    }
    for round in ROUNDS_F_BEGINNING..partial_end {
        s[0] = sbox(&add(&s[0], &tables.rc[round][0]));
        matmul_internal(&mut s);
    }
    for round in partial_end..ROUNDS_TOTAL {
        for (lane, slot) in s.iter_mut().enumerate() {
            *slot = sbox(&add(slot, &tables.rc[round][lane]));
        }
        matmul_external(&mut s);
    }

    let mut out = [[0u8; 32]; STATE_WIDTH];
    for (slot, value) in out.iter_mut().zip(s.iter()) {
        *slot = fr_to_be(value);
    }
    out
}

/// Rebuilds the frozen manifest byte stream from the vendored tables, so a
/// table that drifts is caught by a digest rather than by reading it.
pub fn manifest_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MANIFEST_TAG);
    out.extend_from_slice(&MODULUS_BE);
    out.push(STATE_WIDTH as u8);
    out.push(SBOX_ALPHA as u8);
    out.push(ROUNDS_F as u8);
    out.push(ROUNDS_P as u8);
    for value in MAT_DIAG8_BE.iter() {
        out.extend_from_slice(value);
    }
    for row in MAT_INTERNAL8_BE.iter() {
        for value in row.iter() {
            out.extend_from_slice(value);
        }
    }
    for row in RC8_BE.iter() {
        for value in row.iter() {
            out.extend_from_slice(value);
        }
    }
    out
}

#[cfg(test)]
#[path = "tests/test_poseidon2.rs"]
mod tests;
