// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Complete, bounded encrypted snapshots. Authentication covers the exact page
//! list, order and total size. This is not a business schema, a filesystem store,
//! a freshness assertion or protection against replacing a whole older snapshot.
use crate::{
    sealed::{Kind, RecordCipher, MAX_PLAINTEXT_BYTES, MAX_SEALED_BYTES},
    Error, Result,
};
use rand::RngCore;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

pub const MAX_SNAPSHOT_BYTES: usize = 32 * 1024 * 1024;
const MAX_PAGES: usize = 32;
const RECORD_OVERHEAD: usize = MAX_SEALED_BYTES - MAX_PLAINTEXT_BYTES;
const MANIFEST_BASE: usize = 44;
const ENTRY_BYTES: usize = 36;
const MAX_MANIFEST: usize = MANIFEST_BASE + MAX_PAGES * ENTRY_BYTES;
pub const MAX_ENCODED_BYTES: usize =
    12 + MAX_MANIFEST + RECORD_OVERHEAD + MAX_SNAPSHOT_BYTES + MAX_PAGES * RECORD_OVERHEAD;
const MAGIC: &[u8; 8] = b"TSSN\x01\0\0\0";

/// Restored bytes remain unverified application state. The caller must decode
/// its bounded schema and obtain current chain proofs before presenting balance.
pub struct Restored {
    pub generation: [u8; 32],
    pub plaintext: Zeroizing<Vec<u8>>,
}

fn purpose(kind: Kind) -> Result<()> {
    match kind {
        Kind::State | Kind::Backup => Ok(()),
        Kind::Journal => Err(Error::InvalidInput),
    }
}
fn take<'a>(bytes: &mut &'a [u8], size: usize) -> Result<&'a [u8]> {
    let head = bytes.get(..size).ok_or(Error::InvalidInput)?;
    *bytes = bytes.get(size..).ok_or(Error::InvalidInput)?;
    Ok(head)
}
fn integer(bytes: &mut &[u8]) -> Result<usize> {
    let raw: [u8; 4] = take(bytes, 4)?.try_into().map_err(|_| Error::InvalidInput)?;
    usize::try_from(u32::from_be_bytes(raw)).map_err(|_| Error::Limit)
}
fn put_integer(out: &mut Vec<u8>, value: usize) -> Result<()> {
    out.extend_from_slice(&u32::try_from(value).map_err(|_| Error::Limit)?.to_be_bytes());
    Ok(())
}
fn page_count(size: usize) -> Result<usize> {
    size.checked_add(MAX_PLAINTEXT_BYTES - 1).map(|n| n / MAX_PLAINTEXT_BYTES).ok_or(Error::Limit)
}

/// Caller owns and clears borrowed plaintext. Pages are encrypted directly into
/// one output buffer; only one temporary page is retained during assembly.
pub fn seal(cipher: &RecordCipher, kind: Kind, plaintext: &[u8]) -> Result<Vec<u8>> {
    seal_generated(cipher, kind, plaintext).map(|(encoded, _)| encoded)
}

pub(crate) fn seal_generated(
    cipher: &RecordCipher,
    kind: Kind,
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 32])> {
    purpose(kind)?;
    if plaintext.len() > MAX_SNAPSHOT_BYTES {
        return Err(Error::Limit);
    }
    let count = page_count(plaintext.len())?;
    let manifest_size = count
        .checked_mul(ENTRY_BYTES)
        .and_then(|n| n.checked_add(MANIFEST_BASE))
        .ok_or(Error::Limit)?;
    let manifest_sealed = manifest_size.checked_add(RECORD_OVERHEAD).ok_or(Error::Limit)?;
    let prefix = manifest_sealed.checked_add(12).ok_or(Error::Limit)?;
    let total = count
        .checked_mul(RECORD_OVERHEAD)
        .and_then(|n| n.checked_add(plaintext.len()))
        .and_then(|n| n.checked_add(prefix))
        .ok_or(Error::Limit)?;
    let mut out = Vec::new();
    out.try_reserve_exact(total).map_err(|_| Error::Limit)?;
    out.extend_from_slice(MAGIC);
    put_integer(&mut out, manifest_sealed)?;
    out.resize(prefix, 0);
    let mut generation = [0; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut generation).map_err(|_| Error::Crypto)?;
    let mut manifest = Vec::with_capacity(manifest_size);
    manifest.extend_from_slice(b"SM01");
    manifest.extend_from_slice(&generation);
    put_integer(&mut manifest, plaintext.len())?;
    put_integer(&mut manifest, count)?;
    for (index, page) in plaintext.chunks(MAX_PLAINTEXT_BYTES).enumerate() {
        let sequence =
            u64::try_from(index).map_err(|_| Error::Limit)?.checked_add(1).ok_or(Error::Limit)?;
        let sealed = cipher.seal(kind, sequence, page)?;
        put_integer(&mut manifest, sealed.len())?;
        manifest.extend_from_slice(&Sha3_256::digest(&sealed));
        out.extend_from_slice(&sealed);
    }
    let sealed = cipher.seal(kind, 0, &manifest)?;
    if sealed.len() != manifest_sealed || out.len() != total {
        return Err(Error::InvalidInput);
    }
    out.get_mut(12..prefix).ok_or(Error::InvalidInput)?.copy_from_slice(&sealed);
    Ok((out, generation))
}

/// Refuses incomplete, reordered, mixed or extra pages before allocating the
/// complete plaintext. Peak plaintext allocation is the declared total plus
/// one page. The supplied ciphertext and output each have independent caps.
pub fn open(cipher: &RecordCipher, kind: Kind, encoded: &[u8]) -> Result<Restored> {
    purpose(kind)?;
    if encoded.len() > MAX_ENCODED_BYTES {
        return Err(Error::Limit);
    }
    let mut input = encoded;
    if take(&mut input, 8)? != MAGIC {
        return Err(Error::InvalidInput);
    }
    let manifest_len = integer(&mut input)?;
    if manifest_len > MAX_MANIFEST + RECORD_OVERHEAD {
        return Err(Error::Limit);
    }
    let manifest = cipher.open(kind, 0, take(&mut input, manifest_len)?)?;
    let mut fields = manifest.as_slice();
    if take(&mut fields, 4)? != b"SM01" {
        return Err(Error::InvalidInput);
    }
    let generation = take(&mut fields, 32)?.try_into().map_err(|_| Error::InvalidInput)?;
    let total = integer(&mut fields)?;
    let count = integer(&mut fields)?;
    if total > MAX_SNAPSHOT_BYTES || count > MAX_PAGES {
        return Err(Error::Limit);
    }
    if count != page_count(total)? || fields.len() != count * ENTRY_BYTES {
        return Err(Error::InvalidInput);
    }
    let mut pages = Vec::with_capacity(count);
    let mut remaining_plain = total;
    for _ in 0..count {
        let size = integer(&mut fields)?;
        let hash = take(&mut fields, 32)?;
        let plain_size = remaining_plain.min(MAX_PLAINTEXT_BYTES);
        let expected_size = plain_size.checked_add(RECORD_OVERHEAD).ok_or(Error::Limit)?;
        if size != expected_size {
            return Err(Error::InvalidInput);
        }
        let page = take(&mut input, size)?;
        if Sha3_256::digest(page).as_slice() != hash {
            return Err(Error::Crypto);
        }
        pages.push(page);
        remaining_plain = remaining_plain.checked_sub(plain_size).ok_or(Error::InvalidInput)?;
    }
    if !input.is_empty() || remaining_plain != 0 {
        return Err(Error::InvalidInput);
    }
    let mut plaintext = Zeroizing::new(Vec::new());
    plaintext.try_reserve_exact(total).map_err(|_| Error::Limit)?;
    for (index, page) in pages.into_iter().enumerate() {
        let sequence =
            u64::try_from(index).map_err(|_| Error::Limit)?.checked_add(1).ok_or(Error::Limit)?;
        let decoded = cipher.open(kind, sequence, page)?;
        plaintext.extend_from_slice(&decoded);
    }
    if plaintext.len() != total {
        return Err(Error::InvalidInput);
    }
    Ok(Restored { generation, plaintext })
}
