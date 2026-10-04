// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Verification of one-level HSS (RFC 8554) signatures for the rescue fee gate
//! (PQCHECKSIG_SUITE suite 4); exactly one profile, LMS_SHA256_M32_H20 / LMOTS_SHA256_N32_W4. Written independently of the C++ VM's
//! verifier; the cross-VM parity scenarios must agree byte for byte on results and gas.

use chain_block::sha256_digest_slices;

const N: usize = 32;
const D_PBLC: [u8; 2] = [0x80, 0x80];
const D_MESG: [u8; 2] = [0x81, 0x81];
const D_LEAF: [u8; 2] = [0x82, 0x82];
const D_INTR: [u8; 2] = [0x83, 0x83];

pub(super) const PUBLIC_KEY_BYTES: usize = 4 + 4 + 4 + 16 + 32;
pub(super) const MAX_SIGNATURE_BYTES: usize = 4 + 4 + (4 + 32 + 67 * 32) + 4 + 20 * 32; // 2,832
pub(super) const MAX_MESSAGE_BYTES: usize = 8192;

#[derive(Clone, Copy)]
struct Ots {
    w: u32,
    p: u32,
    ls: u32,
    max_steps: u32,
}

/// The single admitted fee profile: LMOTS_SHA256_N32_W4 (RFC 8554 Table 1, type 3) under
/// LMS_SHA256_M32_H20 (Table 2, type 8). max_steps is the checksum-aware maximum of chain steps.
fn ots_params(code: u32) -> Option<Ots> {
    match code {
        3 => Some(Ots { w: 4, p: 67, ls: 4, max_steps: 990 }),
        _ => None,
    }
}

fn lms_height(code: u32) -> Option<u32> {
    match code {
        8 => Some(20),
        _ => None,
    }
}

fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    let b = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn blocks(bytes: usize) -> Option<usize> {
    Some(bytes.checked_add(9 + 63)? / 64)
}

/// Worst-case SHA-256 compressions to verify any signature on a message of this length under
/// this key, or None for an unsupported profile or an oversized message.
pub(super) fn worst_compressions(public_key: &[u8], message_bytes: usize) -> Option<u64> {
    if public_key.len() != PUBLIC_KEY_BYTES || message_bytes > MAX_MESSAGE_BYTES {
        return None;
    }
    if be32(public_key, 0)? != 1 {
        return None;
    }
    let h = lms_height(be32(public_key, 4)?)? as usize;
    let ots = ots_params(be32(public_key, 8)?)?;
    let q_hash = blocks((16 + 4 + 2 + N).checked_add(message_bytes)?)?;
    let k_hash = blocks((16 + 4 + 2usize).checked_add(N.checked_mul(ots.p as usize)?)?)?;
    let chain = (ots.max_steps as usize).checked_mul(blocks(16 + 4 + 2 + 1 + N)?)?;
    let path = blocks(16 + 4 + 2 + N)?.checked_add(h.checked_mul(blocks(16 + 4 + 2 + 2 * N)?)?)?;
    let total = q_hash.checked_add(k_hash)?.checked_add(chain)?.checked_add(path)?;
    u64::try_from(total).ok()
}

fn coef(s: &[u8], i: usize, w: u32) -> u32 {
    let w = w as usize;
    let mask = (1u32 << w) - 1;
    let byte = u32::from(s[(i * w) / 8]);
    let shift = 8 - (w * (i % (8 / w)) + w);
    (byte >> shift) & mask
}

pub(super) enum Outcome {
    Valid,
    Invalid,
    Malformed,
}

pub(super) fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Outcome {
    if worst_compressions(public_key, message.len()).is_none() {
        return Outcome::Malformed;
    }
    let (Some(lms_type), Some(ots_type)) = (be32(public_key, 4), be32(public_key, 8)) else {
        return Outcome::Malformed;
    };
    let (Some(h), Some(ots)) = (lms_height(lms_type), ots_params(ots_type)) else {
        return Outcome::Malformed;
    };
    let ident = &public_key[12..28];
    let root = &public_key[28..60];
    let ots_len = 4 + N + ots.p as usize * N;
    let lms_len = 4 + ots_len + 4 + h as usize * N;
    if signature.len() != 4 + lms_len {
        return Outcome::Malformed;
    }
    if be32(signature, 0) != Some(0) {
        return Outcome::Invalid; // Nspk = L - 1 = 0
    }
    let ls = &signature[4..];
    let Some(q) = be32(ls, 0) else {
        return Outcome::Malformed;
    };
    if u64::from(q) >= (1u64 << h)
        || be32(ls, 4) != Some(ots_type)
        || be32(ls, 4 + ots_len) != Some(lms_type)
    {
        return Outcome::Invalid;
    }
    let c = &ls[8..8 + N];
    let y = &ls[8 + N..8 + N + ots.p as usize * N];
    let path = &ls[4 + ots_len + 4..];
    let qb = q.to_be_bytes();

    let digest = sha256_digest_slices(&[ident, &qb, &D_MESG, c, message]);
    let mut qc = [0u8; N + 2];
    qc[..N].copy_from_slice(&digest);
    let maxv = (1u32 << ots.w) - 1;
    let mut sum = 0u32;
    for i in 0..(N * 8) / ots.w as usize {
        sum += maxv - coef(&qc, i, ots.w);
    }
    sum <<= ots.ls;
    qc[N] = (sum >> 8) as u8;
    qc[N + 1] = sum as u8;

    let mut keys = Vec::with_capacity(ots.p as usize * N);
    for i in 0..ots.p as usize {
        let mut tmp = [0u8; N];
        tmp.copy_from_slice(&y[i * N..(i + 1) * N]);
        let ib = (i as u16).to_be_bytes();
        for j in coef(&qc, i, ots.w)..maxv {
            tmp = sha256_digest_slices(&[ident, &qb, &ib, &[j as u8], &tmp]);
        }
        keys.extend_from_slice(&tmp);
    }
    let kc = sha256_digest_slices(&[ident, &qb, &D_PBLC, &keys]);

    let mut node = (1u32 << h) + q;
    let mut tmp = sha256_digest_slices(&[ident, &node.to_be_bytes(), &D_LEAF, &kc]);
    let mut i = 0usize;
    while node > 1 {
        let parent = node / 2;
        let sibling = &path[i * N..(i + 1) * N];
        tmp = if node & 1 == 1 {
            sha256_digest_slices(&[ident, &parent.to_be_bytes(), &D_INTR, sibling, &tmp])
        } else {
            sha256_digest_slices(&[ident, &parent.to_be_bytes(), &D_INTR, &tmp, sibling])
        };
        node = parent;
        i += 1;
    }
    if tmp.as_slice() == root {
        Outcome::Valid
    } else {
        Outcome::Invalid
    }
}
