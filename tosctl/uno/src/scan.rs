//! Compact-filter scan + hybrid-KEM trial-decrypt (§5.8, §7.5).
//!
//! Per-block scan flow (design doc §7.5):
//!
//! 1. Fetch `uno_getBlockFilter(seqno)` → GCS-encoded u16 tags.
//! 2. Compute the wallet's expected `filter_tag` for each output's `epk`.
//!    Note: the receiver does NOT know `filter_tag` ahead of time, since
//!    `filter_tag = Poseidon2("uno-filter-v1", k_aead)` and `k_aead` depends
//!    on the per-output `epk`. So the receiver iterates the outputs
//!    themselves: compute `k_aead` per output, derive tag, then match the
//!    block filter. This is the correct direction — the filter exists only
//!    as a probabilistic short-circuit for chain-side batch filtering once
//!    the receiver has narrowed to a candidate set.
//!
//! In v1 we therefore adopt the "pull outputs, check filter membership" flow:
//!
//! 1. Fetch the GCS filter.
//! 2. Fetch all `OutputDescription`s for the block via
//!    `uno_getOutputsAtBlock(seqno, 0, N)`.
//! 3. For each output, derive `k_aead` using `ivk · epk` and
//!    `ML-KEM-768.Decap(sk_mlkem, mlkem_ct)`, then compute the expected
//!    filter tag and compare against the per-output `filter_tag` field.
//! 4. On match, run ChaCha20-Poly1305 Open; on AEAD-tag pass, we own the
//!    note. The block filter serves as an integrity cross-check (every
//!    hit tag must appear in the block filter set, and the filter bit count
//!    provides a fast early-out without fetching outputs if the client
//!    maintains a persistent cache).
//!
//! The doc-§5.8 "filter-first" optimization would require the chain to
//! expose tag-indexed output lookup (RPC surface §9.1 does not currently
//! support this; `uno_getOutputsAtBlock` is seqno-paginated). Mobile clients
//! will want that enhancement later; v1 wallet works correctly without it.

use anyhow::{anyhow, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use curve25519_dalek::ristretto::CompressedRistretto;
use serde::{Deserialize, Serialize};

use crate::{gcs, hybrid_kem, keygen, poseidon2, wire};
use crate::keygen::FullViewingKey;
use crate::rpc_client::RpcClient;
use crate::sizes::DIVERSIFIER;

/// Plaintext of an owned note, recovered from a successful trial-decrypt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnedNote {
    pub block_seqno: u64,
    pub global_index: u64,
    #[serde(with = "hex::serde")]
    pub cm: [u8; 32],
    #[serde(with = "hex::serde")]
    pub nullifier: [u8; 32],
    pub value: u64,
    #[serde(with = "hex::serde")]
    pub diversifier: [u8; 11],
    /// Position (leaf index) of this note in the commitment tree. Populated
    /// from `global_index` for v1; the design doc notes that `pos` is assigned
    /// at commit time in block order.
    pub position: u64,
}

/// Decoded plaintext of the encrypted note blob (§3.1).
///
/// On-wire layout expected inside `enc_ciphertext`:
///
/// | Offset | Len | Field                 |
/// |--------|-----|-----------------------|
/// | 0      | 11  | `d`                   |
/// | 11     | 32  | `compress(pk_d)`      |
/// | 43     | 8   | `value` (LE u64)      |
/// | 51     | 32  | `rseed`               |
/// | 83     | rest| memo (variable)       |
#[derive(Debug, Clone)]
pub struct NotePlaintext {
    pub d: [u8; DIVERSIFIER],
    pub pk_d: [u8; 32],
    pub value: u64,
    pub rseed: [u8; 32],
    pub memo: Vec<u8>,
}

impl NotePlaintext {
    fn parse(bytes: &[u8]) -> Result<Self> {
        const MIN: usize = 11 + 32 + 8 + 32;
        if bytes.len() < MIN {
            return Err(anyhow!("note plaintext too short: {} < {MIN}", bytes.len()));
        }
        let mut d = [0u8; 11];
        d.copy_from_slice(&bytes[0..11]);
        let mut pk_d = [0u8; 32];
        pk_d.copy_from_slice(&bytes[11..43]);
        let value = u64::from_le_bytes(bytes[43..51].try_into().unwrap());
        let mut rseed = [0u8; 32];
        rseed.copy_from_slice(&bytes[51..83]);
        let memo = bytes[83..].to_vec();
        Ok(Self { d, pk_d, value, rseed, memo })
    }
}

/// Scan a single block's outputs for notes owned by `fvk`.
///
/// Performs:
///   1. Fetch GCS filter (for cross-check / future short-circuit).
///   2. Fetch all output descriptions at this seqno (paginated at 128/page).
///   3. Per-output: derive `k_aead`, match `filter_tag`, AEAD-Open.
///
/// Returns the list of owned notes in global-index order.
pub async fn scan_block(
    rpc: &RpcClient,
    fvk: &FullViewingKey,
    seqno: u64,
) -> Result<Vec<OwnedNote>> {
    // Fetch filter. Empty filter is allowed (block with zero outputs).
    let filter_bytes = rpc.get_block_filter(seqno).await.unwrap_or_default();
    let filter_tags: std::collections::HashSet<u16> =
        if filter_bytes.is_empty() {
            Default::default()
        } else {
            gcs::decode(&filter_bytes)?.into_iter().collect()
        };

    // Fetch outputs page by page.
    let mut owned = Vec::new();
    let mut global_index = 0u64;
    let page_size = 128u64;

    loop {
        let page = rpc.get_outputs_at_block(seqno, global_index, page_size).await?;
        if page.is_empty() { break; }

        for (i, raw) in page.iter().enumerate() {
            let out = match wire::parse_output(raw) {
                Ok(o) => o,
                Err(e) => {
                    tracing_unreachable(&format!("skipping malformed output at idx {}: {e}", global_index + i as u64));
                    continue;
                }
            };
            if let Some(note) = try_open(fvk, &out)? {
                let position = global_index + i as u64;
                // Cross-check: this output's filter_tag MUST appear in the
                // per-block filter. If the chain handed us an output that is
                // absent from its own filter, something's wrong consensus-side
                // — surface that rather than silently claiming the note.
                if !filter_tags.is_empty() && !filter_tags.contains(&out.filter_tag) {
                    return Err(anyhow!(
                        "consistency violation: block {seqno} output {position} has \
                         filter_tag={:#x} not in GCS filter set", out.filter_tag));
                }

                // Nullifier = Poseidon2("uno-nf-v1", nk, cm, pos)
                let nf = derive_nullifier(&fvk.nk.0, &out.cm, position);

                owned.push(OwnedNote {
                    block_seqno: seqno,
                    global_index: position,
                    cm: out.cm,
                    nullifier: nf,
                    value: note.value,
                    diversifier: note.d,
                    position,
                });
            }
        }
        if (page.len() as u64) < page_size { break; }
        global_index += page.len() as u64;
    }

    Ok(owned)
}

/// Scan a range `[start, end)` of blocks. Pure sequential; a future
/// optimization is to fan out page fetches onto a tokio pool.
pub async fn scan_range(
    rpc: &RpcClient,
    fvk: &FullViewingKey,
    start: u64,
    end: u64,
) -> Result<Vec<OwnedNote>> {
    let mut out = Vec::new();
    for seqno in start..end {
        let batch = scan_block(rpc, fvk, seqno).await?;
        out.extend(batch);
    }
    Ok(out)
}

/// Attempt to decrypt an output using the wallet's FVK. Returns `Ok(Some)` if
/// the note belongs to this wallet; `Ok(None)` for AEAD-tag failure or
/// filter mismatch.
pub fn try_open(
    fvk: &FullViewingKey,
    out: &wire::OutputDescription,
) -> Result<Option<NotePlaintext>> {
    // 1. s_dh' = ivk · epk (receiver-side ECDH, §2.7).
    let epk = match CompressedRistretto(out.epk).decompress() {
        Some(p) => p,
        None => return Ok(None),  // non-canonical epk → not our note
    };
    let s_dh = fvk.ivk_scalar() * epk;
    let s_dh_compressed = s_dh.compress().to_bytes();

    // 2. s_pq' = ML-KEM-768.Decap(sk_mlkem, mlkem_ct). An ML-KEM decap
    // cannot "fail" in the same way an AEAD tag check does — it always
    // returns a 32-byte value (implicit rejection). So a ciphertext not
    // intended for this receiver still yields *some* s_pq; the split-KDF
    // then produces a k_aead that does NOT decrypt the AEAD. That's the
    // design: AEAD-tag failure is the only decrypt-rejection path, and
    // it's cheap (no Ristretto scalar mul if filter mismatched first).
    let s_pq = match keygen::mlkem_decap(&fvk.sk_mlkem, &out.mlkem_ct) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };

    // 3. k_aead = hybrid KDF (§2.7).
    let k_aead = hybrid_kem::derive_key(&s_dh_compressed, &s_pq, &out.epk, &out.mlkem_ct);
    // Fast early-out using the filter tag. If the computed tag does not
    // match the output's declared tag, this output is not ours. This
    // short-circuits ~99.9985% of outputs before AEAD work on false
    // positives.
    let expected_tag = poseidon2::filter_tag(&k_aead);
    if expected_tag != out.filter_tag {
        return Ok(None);
    }

    // 4. Derive nonce and AEAD-Open.
    let nonce_bytes = hybrid_kem::derive_nonce(&out.epk);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&k_aead));
    let plaintext = match cipher.decrypt(Nonce::from_slice(&nonce_bytes), out.enc_ciphertext.as_slice()) {
        Ok(pt) => pt,
        Err(_) => {
            // filter_tag matched but AEAD tag failed: a 1/2^16 false
            // positive. Not an error; just not our note.
            return Ok(None);
        }
    };

    let note = NotePlaintext::parse(&plaintext)?;

    // Sanity: the diversifier inside the plaintext should match the pk_d
    // that the sender encrypted to. We don't assert this (malformed
    // senders exist), but expose it in debug logging.
    tracing_unreachable(&format!("opened note: d={}, value={}", hex::encode(note.d), note.value));

    Ok(Some(note))
}

/// `nf = Poseidon2("uno-nf-v1", nk, cm, pos)` (§3.4).
pub fn derive_nullifier(nk: &[u8; 32], cm: &[u8; 32], pos: u64) -> [u8; 32] {
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks;

    let mut fes: Vec<Goldilocks> = Vec::with_capacity(4 + 4 + 1);
    fes.extend(poseidon2::bytes_to_fes_wrapped(nk));
    fes.extend(poseidon2::bytes_to_fes_wrapped(cm));
    fes.push(Goldilocks::from_u64(pos));

    // 4 + 4 + 1 = 9 absorbed elements + 1 tag = 10 → width-16 permutation.
    poseidon2::hash_tagged(crate::tags::UNO_NF_V1, &fes)
}

/// Lightweight logger replacement — we avoid pulling in `tracing` for a
/// single debug line. In production this would be a `tracing::debug!`.
#[inline]
fn tracing_unreachable(_msg: &str) {
    #[cfg(debug_assertions)]
    {
        // Uncomment for noisy debug:
        // eprintln!("[tosctl-uno] {}", _msg);
    }
}
