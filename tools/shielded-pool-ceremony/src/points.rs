/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Transcript bytes into curve points, with this chain's own library deciding
//! what counts as a point.
//!
//! The transcript stores points in the uncompressed IETF encoding: big-endian
//! x then y, forty-eight bytes a coordinate, an Fp2 coordinate's c1 part
//! first, and the top three bits of the first byte carrying the compression,
//! infinity and sort flags. That is the same encoding ruling A1 fixes for V1
//! wire bytes, which is why the same library reads both.
//!
//! Two things have to be true of every point and only one of them is obvious.
//! It has to be **on the curve**, which a malformed file would fail. It also
//! has to be **in the prime-order subgroup**, which a malicious file would
//! pass the first check and fail the second -- and a small-order point in a
//! powers-of-tau string is a way to make later pairing checks say nothing.
//! blst separates the two, and both are required here.
//!
//! arkworks stays the arithmetic; blst is only the gate. Every point is
//! rebuilt into arkworks form and then serialized back, and the bytes must
//! come out identical. A decoder that agreed with blst about validity but
//! disagreed about *which* point it was would otherwise go unnoticed.

use ark_bls12_381::{Fq, Fq2, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};

use crate::error::{Error, Result};

/// A big-endian 48-byte field element, refused if it is not reduced.
///
/// `from_be_bytes_mod_order` would silently accept an over-large encoding by
/// reducing it, and two different byte strings mapping to one point is exactly
/// the ambiguity a canonical encoding exists to remove.
fn fq_from_be(bytes: &[u8], what: &str) -> Result<Fq> {
    if bytes.len() != 48 {
        return Err(Error::Point(format!("{what}: {} bytes, not 48", bytes.len())));
    }
    let value = Fq::from_be_bytes_mod_order(bytes);
    let round_trip = value.into_bigint().to_bytes_be();
    let mut padded = [0u8; 48];
    padded[48 - round_trip.len()..].copy_from_slice(&round_trip);
    if padded != bytes {
        return Err(Error::Point(format!(
            "{what}: the coordinate is not reduced, so these bytes are not canonical"
        )));
    }
    Ok(value)
}

fn fq_to_be(value: &Fq) -> [u8; 48] {
    let digits = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 48];
    out[48 - digits.len()..].copy_from_slice(&digits);
    out
}

/// The flag bits the IETF encoding keeps in the first byte.
const COMPRESSED: u8 = 0x80;
const INFINITY: u8 = 0x40;
const SORT: u8 = 0x20;

/// One uncompressed G1 point, as blst reads it and arkworks holds it.
pub fn g1_from_uncompressed(bytes: &[u8]) -> Result<G1Affine> {
    if bytes.len() != 96 {
        return Err(Error::Point(format!("G1: {} bytes, not 96", bytes.len())));
    }
    // blst decides. It checks the encoding, the curve equation and -- with
    // `in_g1` -- the subgroup, which is the check a hostile transcript is
    // trying to get past.
    let mut affine = blst::blst_p1_affine::default();
    // SAFETY: `bytes` is 96 long, the width blst reads for an uncompressed G1,
    // and `affine` is a valid out-parameter.
    let status = unsafe { blst::blst_p1_deserialize(&mut affine, bytes.as_ptr()) };
    if status != blst::BLST_ERROR::BLST_SUCCESS {
        return Err(Error::Point(format!("blst refused a G1 point: {status:?}")));
    }
    // SAFETY: `affine` was just filled by a successful deserialize.
    if !unsafe { blst::blst_p1_affine_in_g1(&affine) } {
        return Err(Error::Point(
            "a G1 point is on the curve but outside the prime-order subgroup".into(),
        ));
    }

    let first = bytes[0];
    if first & COMPRESSED != 0 {
        return Err(Error::Point("the compression flag is set on an uncompressed point".into()));
    }
    let point = if first & INFINITY != 0 {
        if first & SORT != 0 || bytes[1..].iter().any(|byte| *byte != 0) || first != INFINITY {
            return Err(Error::Point("the point at infinity carries bits it should not".into()));
        }
        G1Affine::identity()
    } else {
        let x = fq_from_be(&bytes[..48], "G1.x")?;
        let y = fq_from_be(&bytes[48..], "G1.y")?;
        G1Affine::new_unchecked(x, y)
    };

    // And the decoder agrees with blst about which point, not merely that
    // there is one.
    if g1_to_uncompressed(&point) != bytes {
        return Err(Error::Point("re-encoding a G1 point did not reproduce its bytes".into()));
    }
    Ok(point)
}

pub fn g1_to_uncompressed(point: &G1Affine) -> [u8; 96] {
    let mut out = [0u8; 96];
    if point.infinity {
        out[0] = INFINITY;
        return out;
    }
    out[..48].copy_from_slice(&fq_to_be(&point.x));
    out[48..].copy_from_slice(&fq_to_be(&point.y));
    out
}

pub fn g2_from_uncompressed(bytes: &[u8]) -> Result<G2Affine> {
    if bytes.len() != 192 {
        return Err(Error::Point(format!("G2: {} bytes, not 192", bytes.len())));
    }
    let mut affine = blst::blst_p2_affine::default();
    // SAFETY: `bytes` is 192 long, the width blst reads for an uncompressed
    // G2, and `affine` is a valid out-parameter.
    let status = unsafe { blst::blst_p2_deserialize(&mut affine, bytes.as_ptr()) };
    if status != blst::BLST_ERROR::BLST_SUCCESS {
        return Err(Error::Point(format!("blst refused a G2 point: {status:?}")));
    }
    // SAFETY: `affine` was just filled by a successful deserialize.
    if !unsafe { blst::blst_p2_affine_in_g2(&affine) } {
        return Err(Error::Point(
            "a G2 point is on the curve but outside the prime-order subgroup".into(),
        ));
    }

    let first = bytes[0];
    if first & COMPRESSED != 0 {
        return Err(Error::Point("the compression flag is set on an uncompressed point".into()));
    }
    let point = if first & INFINITY != 0 {
        if bytes[1..].iter().any(|byte| *byte != 0) || first != INFINITY {
            return Err(Error::Point("the point at infinity carries bits it should not".into()));
        }
        G2Affine::identity()
    } else {
        // c1 before c0, which is the part of this encoding most likely to be
        // written the other way round by someone reading a different spec.
        let x =
            Fq2::new(fq_from_be(&bytes[48..96], "G2.x.c0")?, fq_from_be(&bytes[..48], "G2.x.c1")?);
        let y = Fq2::new(
            fq_from_be(&bytes[144..], "G2.y.c0")?,
            fq_from_be(&bytes[96..144], "G2.y.c1")?,
        );
        G2Affine::new_unchecked(x, y)
    };

    if g2_to_uncompressed(&point) != bytes {
        return Err(Error::Point("re-encoding a G2 point did not reproduce its bytes".into()));
    }
    Ok(point)
}

pub fn g2_to_uncompressed(point: &G2Affine) -> [u8; 192] {
    let mut out = [0u8; 192];
    if point.infinity {
        out[0] = INFINITY;
        return out;
    }
    out[..48].copy_from_slice(&fq_to_be(&point.x.c1));
    out[48..96].copy_from_slice(&fq_to_be(&point.x.c0));
    out[96..144].copy_from_slice(&fq_to_be(&point.y.c1));
    out[144..].copy_from_slice(&fq_to_be(&point.y.c0));
    out
}

/// Reads a whole section: `points` elements of `width` bytes each.
pub fn g1_section(bytes: &[u8], points: usize) -> Result<Vec<G1Affine>> {
    if bytes.len() != points * 96 {
        return Err(Error::Slice(format!(
            "a G1 section of {points} points should be {} bytes and is {}",
            points * 96,
            bytes.len()
        )));
    }
    bytes.chunks_exact(96).map(g1_from_uncompressed).collect()
}

pub fn g2_section(bytes: &[u8], points: usize) -> Result<Vec<G2Affine>> {
    if bytes.len() != points * 192 {
        return Err(Error::Slice(format!(
            "a G2 section of {points} points should be {} bytes and is {}",
            points * 192,
            bytes.len()
        )));
    }
    bytes.chunks_exact(192).map(g2_from_uncompressed).collect()
}

/// A point that is on the curve and outside the prime-order subgroup.
///
/// For tests only, and public because the tests that need it are integration
/// tests. It is the point a hostile transcript would carry: valid against the
/// curve equation, worthless in a pairing, and invisible to any check that
/// stops at `is_on_curve`.
pub fn a_point_outside_the_subgroup() -> G1Affine {
    use ark_ec::{AffineRepr, CurveGroup};
    // Walk x until the curve equation has a root, then take the point without
    // clearing the cofactor. The result is on the curve; its order is a
    // multiple of a cofactor factor, so it is not in G1.
    let mut x = Fq::from(1u64);
    loop {
        if let Some(point) = G1Affine::get_point_from_x_unchecked(x, false) {
            if !point.is_zero() && !point.is_in_correct_subgroup_assuming_on_curve() {
                return point;
            }
            // Clearing the cofactor of a point already in the subgroup gives
            // nothing new, so keep walking.
            let _ = point.mul_by_cofactor_to_group().into_affine();
        }
        x += Fq::from(1u64);
    }
}
