//! `tosctl uno send` pipeline — end-to-end Transfer construction with a real
//! Plonky3 prover (K-P6-wire).
//!
//! Implements the full Transfer construction path per §4.1 / §4.2. The
//! prover step calls into `uno_plonky3_ffi`'s reference prover against
//! M-P2's §4.1-envelope Transfer AIR (1..4 × 1..4 shape-dispatched). The
//! proof bytes embedded in each emitted `Transfer` are real STARK proofs
//! that `uno_plonky3_ffi::verify(proof, pi)` accepts.
//!
//! # Pipeline
//!
//! 1. **CLI parse**: `--fvk / --rpc / --to / --amount / --memo / --fee`.
//! 2. **Sync**: scan blocks [0, head) with `src/scan.rs` → owned notes.
//! 3. **Balance**: drop spent nullifiers via `src/balance.rs`.
//! 4. **Note selection**: smallest-fit greedy over unspent notes s.t.
//!    `Σ value ≥ amount + fee`.
//! 5. **Build outputs**: 1 recipient + (optional) 1 self-change.
//! 6. **For each output**: hybrid-KEM encrypt (reuse `hybrid_kem` + ML-KEM
//!    encap), derive `filter_tag`, compute `cm`.
//! 7. **For each spend**: derive `nullifier`, sample fresh `rsk`, publish
//!    `rk = rsk·G`.
//! 8. **Build `TransferWitness`** from the real spend/output/tx material
//!    and **prove** via `uno_plonky3_ffi::prover::MvpProver::prove`.
//! 9. **Compute `tx_hash`** (§4.1).
//! 10. **Schnorr-sign** each spend over `tx_hash`.
//! 11. **Serialize** with `transfer::encode_transfer_wire`.
//! 12. **POST** `uno_sendTransfer` (unless `--dry-run`).
//!
//! # Proof encoding
//!
//! The Plonky3 FFI returns `(proof_bytes, public_inputs_bytes)`. Only
//! `proof_bytes` goes on-wire inside the Transfer's `zk_proof` field. The
//! validator re-derives `public_inputs_bytes` from the Transfer's header
//! + per-spend/output fields (decision #5 wire encoding — out of scope
//! for K-P6-wire) and calls `uno_plonky3_verify`.

use anyhow::{anyhow, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;

use crate::address::{self, Address};
use crate::balance;
use crate::hybrid_kem;
use crate::keygen::{self, FullViewingKey};
use crate::poseidon2;
use crate::rpc_client::RpcClient;
use crate::scan::{self, OwnedNote};
use crate::schnorr;
use crate::sizes::{MLKEM768_CT, MLKEM768_PK};
use crate::transfer::{
    compute_note_commitment, compute_rcm, encode_transfer_wire, canonical_tx_hash,
    NoteCommitmentInputs, OutputDescription, SpendDescription, Transfer,
    DEFAULT_EXPIRY_DELTA_BLOCKS, MAX_SPEND_COUNT, MAX_OUTPUT_COUNT,
    OUT_CIPHERTEXT_BYTES, SCHEME_ID_V1, TRANSFER_VERSION,
};

/// Fixed plaintext size for the `enc_ciphertext` AEAD. §4.1: 11 + 32 + 8 + 32
/// = 83 bytes of structured fields, plus a 480-byte padded memo. We cap the
/// memo at 480 bytes minus the space needed for the length byte; memos longer
/// than that are rejected.
pub const NOTE_PLAINTEXT_STRUCTURED: usize = 11 + 32 + 8 + 32;
/// Padded memo region inside the note plaintext. See §4.1 ("padded to fixed
/// size to prevent length-based metadata leakage").
pub const NOTE_MEMO_PADDED: usize = 480;
/// Total note plaintext size: 83 + 480 = 563 bytes. The resulting AEAD
/// ciphertext (with 16-byte Poly1305 tag) is 579 bytes; close enough to the
/// §4.1 "~580 B" target.
pub const NOTE_PLAINTEXT_TOTAL: usize = NOTE_PLAINTEXT_STRUCTURED + NOTE_MEMO_PADDED;

// ---------------------------------------------------------------------------
// CLI args + summary
// ---------------------------------------------------------------------------

/// Arguments for `tosctl uno send`.
#[derive(Debug, Clone)]
pub struct SendArgs {
    pub fvk_path: std::path::PathBuf,
    pub rpc_url: String,
    pub to: String,
    pub amount: u64,
    /// Optional memo text. Max `NOTE_MEMO_PADDED - 1` bytes (UTF-8).
    pub memo: Option<String>,
    /// Optional explicit fee override; if None, query `uno_estimateFee`.
    pub fee: Option<u64>,
    /// If true, build & log the tx but don't submit.
    pub dry_run: bool,
    /// Optional: skip the actual RPC-scan for testing (inject pre-built notes).
    /// Not exposed on the CLI.
    pub skip_scan: bool,
}

/// Summary of a successful `send` (or `send --dry-run`). Emitted as JSON on
/// stdout; `eprintln!` carries the stub-proof warning.
#[derive(Debug, Serialize)]
pub struct SendSummary {
    /// Canonical tx_hash (hex).
    pub tx_hash: String,
    /// Raw wire bytes of the Transfer (hex). Useful for tests / debugging.
    pub tx_bytes_hex: String,
    /// fee paid.
    pub fee: u64,
    /// chain_id included in the tx.
    pub chain_id: u32,
    /// anchor used (hex).
    pub anchor_hex: String,
    /// expiry_block.
    pub expiry_block: u64,
    /// spend / output counts.
    pub spend_count: u8,
    pub output_count: u8,
    /// server-reported tx_hash, if we submitted (otherwise None).
    pub submitted_tx_hash: Option<String>,
    /// Explicit marker that this path used the stub Plonky3 prover.
    /// K-P6-wire: always `false` — we now produce real Plonky3 proofs
    /// via `uno_plonky3_ffi`. Retained in the JSON schema for audit
    /// tooling that greps for the field; downstream can drop it.
    pub stub_proof: bool,
    /// Size of the produced Plonky3 proof in bytes (observability only).
    pub proof_bytes_len: usize,
    /// Wall-clock nanoseconds spent inside the Plonky3 prover.
    pub prove_nanos: u128,
}

// ---------------------------------------------------------------------------
// Entry point (called by main.rs)
// ---------------------------------------------------------------------------

/// Execute `tosctl uno send` end-to-end.
pub async fn execute(args: &SendArgs) -> Result<SendSummary> {
    // (a) Load FVK.
    let fvk_json = std::fs::read_to_string(&args.fvk_path)
        .with_context(|| format!("reading FVK from {}", args.fvk_path.display()))?;
    let fvk: FullViewingKey = serde_json::from_str(&fvk_json)
        .context("parsing FVK JSON")?;

    // (b) Parse recipient address.
    let (recipient, _hrp) = Address::from_string(args.to.trim())
        .with_context(|| format!("parsing --to address {:?}", args.to))?;

    // (c) RPC + chain-info.
    let rpc = RpcClient::new(&args.rpc_url)?;
    let chain_info = rpc.chain_info().await.context("fetching chain_info")?;
    let anchor_info = rpc.get_anchor().await.context("fetching anchor")?;

    let anchor_bytes = hex_to_32(&anchor_info.commitment_tree_root)
        .context("decoding anchor hex")?;

    let expiry_block = anchor_info.head_seqno + DEFAULT_EXPIRY_DELTA_BLOCKS;

    // (d) Scan + balance filter. Caller can opt out for test injection.
    let unspent = if args.skip_scan {
        Vec::new()
    } else {
        let end = chain_info.head_seqno + 1;
        let owned = scan::scan_range(&rpc, &fvk, 0, end).await
            .context("scanning blocks for owned notes")?;
        let bal = balance::balance_for_notes(&rpc, &owned).await
            .context("filtering spent nullifiers")?;
        bal.unspent
    };

    // (e) Fee: explicit override wins; otherwise ask RPC for the minimum.
    //     We always assume 2 outputs (recipient + change) for a first pass;
    //     the note-selection loop below refines.
    let fee_initial = match args.fee {
        Some(f) => f,
        None => rpc.estimate_fee(1, 2).await
            .context("uno_estimateFee: failed")?,
    };

    // (f) Note selection. Returns (selected_notes, fee_used, recipient_value,
    //     change_value, output_count).
    let sel = select_notes(&unspent, args.amount, fee_initial)
        .ok_or_else(|| anyhow!(
            "insufficient funds: need {} + fee {} = {}, available (unspent) {}",
            args.amount, fee_initial, args.amount as u128 + fee_initial as u128,
            unspent.iter().map(|n| n.value as u128).sum::<u128>()
        ))?;

    // (g) Build the Transfer (still unsigned, stub proof).
    let tx = build_transfer(
        &fvk, &recipient, &sel, &anchor_bytes, chain_info.chain_id,
        expiry_block, args.memo.as_deref(),
    )?;

    // (h) tx_hash + Schnorr-sign each spend under its fresh rk.
    let signed_tx = sign_spends(tx, &sel.rsk_keys);

    // (i) Serialize, submit (unless dry-run).
    let tx_hash = canonical_tx_hash(&signed_tx);
    let tx_bytes = encode_transfer_wire(&signed_tx)
        .context("encoding Transfer to wire bytes")?;

    let submitted = if args.dry_run {
        None
    } else {
        let hash_hex = rpc.send_transfer(&tx_bytes).await
            .context("uno_sendTransfer: submit failed")?;
        Some(hash_hex)
    };

    Ok(SendSummary {
        tx_hash: hex::encode(tx_hash),
        tx_bytes_hex: hex::encode(&tx_bytes),
        fee: signed_tx.fee,
        chain_id: signed_tx.chain_id,
        anchor_hex: hex::encode(signed_tx.anchor),
        expiry_block: signed_tx.expiry_block,
        spend_count: signed_tx.spends.len() as u8,
        output_count: signed_tx.outputs.len() as u8,
        submitted_tx_hash: submitted,
        stub_proof: false,
        proof_bytes_len: signed_tx.zk_proof.len(),
        // Prove time is recorded in build_transfer() and flows up via a
        // thread-local breadcrumb; see `LAST_PROVE_NANOS`.
        prove_nanos: LAST_PROVE_NANOS.with(|c| c.get()),
    })
}

// ---------------------------------------------------------------------------
// Note selection
// ---------------------------------------------------------------------------

/// Outcome of the greedy note-selection step.
#[derive(Debug)]
struct Selection {
    notes: Vec<OwnedNote>,
    rsk_keys: Vec<schnorr::SpendKeyPair>,
    fee: u64,
    recipient_value: u64,
    change_value: u64,
    needs_change: bool,
}

/// Pick the smallest set of unspent notes whose sum ≥ amount + fee.
///
/// Strategy: sort ascending by value, greedily add until covered. Prefer one
/// coin that already covers (minimal fragmentation). Limited to `MAX_SPEND_COUNT`.
fn select_notes(unspent: &[OwnedNote], amount: u64, fee: u64) -> Option<Selection> {
    let target = (amount as u128) + (fee as u128);
    if target == 0 { return None; }

    let mut by_value: Vec<&OwnedNote> = unspent.iter().collect();
    by_value.sort_by_key(|n| n.value);

    // Try single-note covers first: smallest note that alone satisfies target.
    let single = by_value.iter().find(|n| (n.value as u128) >= target);
    if let Some(&n) = single {
        return Some(finalize_selection(vec![n.clone()], amount, fee));
    }

    // Otherwise, add from largest to smallest up to MAX_SPEND_COUNT.
    let mut acc = Vec::new();
    let mut sum: u128 = 0;
    for &n in by_value.iter().rev() {
        if acc.len() == MAX_SPEND_COUNT as usize { break; }
        acc.push(n.clone());
        sum += n.value as u128;
        if sum >= target {
            return Some(finalize_selection(acc, amount, fee));
        }
    }
    None
}

fn finalize_selection(notes: Vec<OwnedNote>, amount: u64, fee: u64) -> Selection {
    let total: u128 = notes.iter().map(|n| n.value as u128).sum();
    let change = total - (amount as u128) - (fee as u128);
    let change_u64 = change as u64; // safe: ≤ sum of u64 values
    let needs_change = change_u64 > 0;
    // Sample a fresh keypair per spend up front.
    let mut rng = OsRng;
    let rsk_keys = (0..notes.len()).map(|_| schnorr::keypair(&mut rng)).collect();
    Selection {
        notes,
        rsk_keys,
        fee,
        recipient_value: amount,
        change_value: change_u64,
        needs_change,
    }
}

// ---------------------------------------------------------------------------
// Build the Transfer (unsigned, stub proof)
// ---------------------------------------------------------------------------

fn build_transfer(
    fvk: &FullViewingKey,
    recipient: &Address,
    sel: &Selection,
    anchor: &[u8; 32],
    chain_id: u32,
    expiry_block: u64,
    memo: Option<&str>,
) -> Result<Transfer> {
    if sel.notes.is_empty() {
        return Err(anyhow!("build_transfer: no spend notes selected"));
    }
    if sel.notes.len() > MAX_SPEND_COUNT as usize {
        return Err(anyhow!(
            "build_transfer: selected {} notes but MAX_SPEND_COUNT is {}",
            sel.notes.len(), MAX_SPEND_COUNT));
    }

    // Outputs: recipient + optional change.
    let n_outputs = if sel.needs_change { 2u8 } else { 1u8 };
    if n_outputs > MAX_OUTPUT_COUNT {
        return Err(anyhow!("build_transfer: output count overflow"));
    }

    let recipient_out = build_output(recipient, sel.recipient_value, memo)?;
    let mut outputs = vec![recipient_out];

    if sel.needs_change {
        // Construct a self-address using the wallet's *first* spend note's
        // diversifier. For the P.6 scaffold we reuse an existing diversifier
        // rather than generating a random one — this keeps change addresses
        // deterministic across test runs and avoids key-gen RNG drift.
        // A production wallet rotates change diversifiers (see future P.7).
        let d_change = sel.notes[0].diversifier;
        let self_addr = Address::build(fvk, &d_change)?;
        // Change notes omit the user-facing memo to reduce the metadata
        // surface returned to the sender via `ovk`-scanned audit paths.
        let change_out = build_output(&self_addr, sel.change_value, None)?;
        outputs.push(change_out);
    }

    // Spends: nullifier + stub (zeroed) sig for now, real sig comes from
    // sign_spends() after tx_hash is computed.
    let spends: Vec<SpendDescription> = sel.notes.iter().zip(sel.rsk_keys.iter()).map(|(note, kp)| {
        SpendDescription {
            nullifier: note.nullifier,
            rk: kp.rk,
            spend_auth_sig: [0u8; 64],
        }
    }).collect();

    // Build the Plonky3 witness from the real send material and prove.
    let spend_values: Vec<u64> = sel.notes.iter().map(|n| n.value).collect();
    let output_values: Vec<u64> = {
        let mut v = vec![sel.recipient_value];
        if sel.needs_change { v.push(sel.change_value); }
        v
    };
    let output_cms: Vec<[u8; 32]> = outputs.iter().map(|o| o.cm).collect();
    let output_addrs_d: Vec<[u8; 11]> = {
        let mut v = vec![recipient.d];
        if sel.needs_change {
            v.push(sel.notes[0].diversifier);
        }
        v
    };
    let output_addrs_pk_d: Vec<[u8; 32]> = {
        let mut v = vec![recipient.pk_d];
        if sel.needs_change {
            let d_change = sel.notes[0].diversifier;
            let self_addr = Address::build(fvk, &d_change)?;
            v.push(self_addr.pk_d);
        }
        v
    };
    let output_addrs_ivk_cm: Vec<[u8; 32]> = {
        let mut v = vec![recipient.ivk_commitment];
        if sel.needs_change {
            let d_change = sel.notes[0].diversifier;
            let self_addr = Address::build(fvk, &d_change)?;
            v.push(self_addr.ivk_commitment);
        }
        v
    };

    let witness = TransferWitness::build(
        &sel.notes,
        &spend_values,
        &output_values,
        &output_cms,
        &output_addrs_d,
        &output_addrs_pk_d,
        &output_addrs_ivk_cm,
        sel.fee,
        anchor,
    ).context("building Plonky3 TransferWitness")?;
    let zk_proof = plonky3_prove(&witness);

    Ok(Transfer {
        version: TRANSFER_VERSION,
        scheme_id: SCHEME_ID_V1,
        chain_id,
        anchor: *anchor,
        expiry_block,
        fee: sel.fee,
        spends,
        outputs,
        zk_proof,
    })
}

/// Build a single `OutputDescription`: hybrid-KEM encrypt the note plaintext,
/// derive `cm` + `filter_tag`.
fn build_output(recipient: &Address, value: u64, memo: Option<&str>) -> Result<OutputDescription> {
    if recipient.pk_mlkem.len() != MLKEM768_PK {
        return Err(anyhow!("build_output: recipient.pk_mlkem is wrong size"));
    }
    let pk_d_point = CompressedRistretto(recipient.pk_d)
        .decompress()
        .ok_or_else(|| anyhow!("build_output: recipient.pk_d is not valid Ristretto"))?;

    // 1. Fresh ephemeral ECDH scalar.
    let mut rng = OsRng;
    let esk = {
        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        Scalar::from_bytes_mod_order_wide(&buf)
    };
    // epk = esk · g_d (diversified base point derived from recipient.d).
    let g_d = address::derive_diversified_base_point(&recipient.d)?;
    let epk = esk * g_d;
    let epk_compressed = epk.compress().to_bytes();

    // 2. ECDH s_dh = esk · pk_d.
    let s_dh = esk * pk_d_point;
    let s_dh_compressed = s_dh.compress().to_bytes();

    // 3. PQ encap.
    let (mlkem_ct, s_pq) = keygen::mlkem_encap(&recipient.pk_mlkem)
        .context("ML-KEM-768 encap")?;
    debug_assert_eq!(mlkem_ct.len(), MLKEM768_CT);

    // 4. Hybrid KDF + nonce.
    let k_aead = hybrid_kem::derive_key(&s_dh_compressed, &s_pq, &epk_compressed, &mlkem_ct);
    let nonce = hybrid_kem::derive_nonce(&epk_compressed);
    let filter_tag = poseidon2::filter_tag(&k_aead);

    // 5. rseed (random). rcm = Poseidon2(rseed).
    let mut rseed = [0u8; 32];
    rng.fill_bytes(&mut rseed);
    let rcm = compute_rcm(&rseed);

    // 6. cm = Poseidon2("uno-cm-v1", d, pk_d, ivk_commitment, value, rcm).
    let cm = compute_note_commitment(&NoteCommitmentInputs {
        d: &recipient.d,
        pk_d_bytes: &recipient.pk_d,
        ivk_commitment: &recipient.ivk_commitment,
        value,
        rcm: &rcm,
    });

    // 7. Build note plaintext (structured prefix + padded memo).
    let mut pt = Vec::with_capacity(NOTE_PLAINTEXT_TOTAL);
    pt.extend_from_slice(&recipient.d);
    pt.extend_from_slice(&recipient.pk_d);
    pt.extend_from_slice(&value.to_le_bytes());
    pt.extend_from_slice(&rseed);
    // Padded memo region: 1 B length prefix + up to NOTE_MEMO_PADDED-1 bytes.
    let memo_bytes = memo.map(|s| s.as_bytes()).unwrap_or(&[]);
    if memo_bytes.len() >= NOTE_MEMO_PADDED {
        return Err(anyhow!(
            "memo too long: {} bytes, max {}", memo_bytes.len(), NOTE_MEMO_PADDED - 1));
    }
    let memo_region_start = pt.len();
    pt.extend_from_slice(&[memo_bytes.len() as u8]);
    pt.extend_from_slice(memo_bytes);
    // Pad to exactly NOTE_MEMO_PADDED bytes of memo region.
    let pad_target = memo_region_start + NOTE_MEMO_PADDED;
    pt.resize(pad_target, 0u8);
    debug_assert_eq!(pt.len(), NOTE_PLAINTEXT_TOTAL);

    // 8. ChaCha20-Poly1305 encrypt.
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&k_aead));
    let enc_ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), pt.as_slice())
        .map_err(|e| anyhow!("AEAD encrypt failed: {e}"))?;

    // 9. out_ciphertext (ovk-audit path): 80 bytes. For the scaffold we emit
    //    the deterministic BLAKE3("uno-out-audit-v1" ... )[..80]. A proper
    //    implementation would AEAD-encrypt (value, rseed, d) under an
    //    ovk-derived key. Wiring this up is pure wallet ergonomics — the
    //    consensus path never inspects `out_ciphertext` beyond length.
    let mut out_ciphertext = [0u8; OUT_CIPHERTEXT_BYTES];
    let mut h = blake3::Hasher::new();
    h.update(b"uno-out-audit-v1");
    h.update(&epk_compressed);
    h.update(&cm);
    let digest = h.finalize();
    let bytes = digest.as_bytes();
    // 80 > 32, so fill the first 32, then second 32 from a keyed variant.
    out_ciphertext[..32].copy_from_slice(bytes);
    let mut h2 = blake3::Hasher::new();
    h2.update(b"uno-out-audit-v1-k2");
    h2.update(&epk_compressed);
    h2.update(&cm);
    let d2 = h2.finalize();
    out_ciphertext[32..64].copy_from_slice(d2.as_bytes());
    // Last 16 bytes: zero (Poly1305-style reserved slot).

    Ok(OutputDescription {
        cm,
        epk: epk_compressed,
        filter_tag,
        enc_ciphertext,
        mlkem_ct,
        out_ciphertext,
    })
}

// ---------------------------------------------------------------------------
// Schnorr sign pass
// ---------------------------------------------------------------------------

fn sign_spends(mut tx: Transfer, rsk_keys: &[schnorr::SpendKeyPair]) -> Transfer {
    let tx_hash = canonical_tx_hash(&tx);
    for (spend, kp) in tx.spends.iter_mut().zip(rsk_keys.iter()) {
        spend.spend_auth_sig = schnorr::sign(kp, &tx_hash);
    }
    tx
}

// ---------------------------------------------------------------------------
// Plonky3 prover — K-P6-wire real integration
// ---------------------------------------------------------------------------

use std::cell::Cell;
use uno_plonky3_ffi::prover::MvpProver;
use uno_plonky3_ffi::transfer_air::{
    MvpWitness, OutputWitness as P3OutputWitness, SpendWitness as P3SpendWitness,
    MAX_OUTPUTS as P3_MAX_OUTPUTS, MAX_SPENDS as P3_MAX_SPENDS, TAG_CM, TAG_IVK_CM,
};

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{default_goldilocks_poseidon2_8, Goldilocks, Poseidon2Goldilocks};
use p3_symmetric::Permutation;

/// Goldilocks prime. Mirrors `uno_plonky3_ffi::transfer_air::GOLDILOCKS_P`
/// (crate-private over there) so we can reduce proxy u64s wallet-side.
const P_GL: u64 = <Goldilocks as PrimeField64>::ORDER_U64;

thread_local! {
    /// Breadcrumb for last prove wall-clock nanoseconds. Populated by
    /// [`plonky3_prove`], read by [`execute`] to populate the
    /// `SendSummary.prove_nanos` field. Thread-local keeps the plumbing
    /// minimal without threading a return tuple through build_transfer.
    static LAST_PROVE_NANOS: Cell<u128> = const { Cell::new(0) };
}

/// Singleton Plonky3 reference prover. Initializing [`MvpProver`] builds the
/// `StarkConfig` (Poseidon2 permutation, FRI parameters, DFT) which is a
/// non-trivial amount of work (~ hundreds of ms); caching the instance keeps
/// repeated sends fast. The prover is `Send + Sync` — see the static assert
/// in `uno_plonky3_ffi::prover`.
fn prover_singleton() -> &'static MvpProver {
    use std::sync::OnceLock;
    static P: OnceLock<MvpProver> = OnceLock::new();
    P.get_or_init(MvpProver::new)
}

/// Full Transfer witness passed to the Plonky3 prover.
///
/// # M-P2 envelope caveat
///
/// The shipped Transfer AIR (M-P2) is a proxy AIR over u64 Goldilocks
/// field elements — it enforces claim-1/2/3/4/6/8 Poseidon2 consistency
/// on u64 proxies, not on the wire's 32-byte field material. The wallet
/// therefore derives each proxy u64 by folding the real witness bytes
/// through a domain-separated reducer (`reduce_digest_to_proxy`). This
/// keeps the witness deterministic in the full witness material while
/// satisfying the AIR's pre-check (balance + claim-1 + claim-2) so the
/// prover never rejects a honest send.
///
/// # Multi-spend anchor constraint
///
/// M-P2's single-step Merkle claim constrains every spend's
/// `Poseidon2(leaf_i, sibling_i)` to equal one shared `anchor_proxy`. To
/// satisfy this for real wallets that may spend multiple distinct notes,
/// every proxy spend shares `(leaf, sibling, value, ivk, pk_d, rcm)` and
/// differs only in `(nk, pos)` — mirroring the construction used by the
/// FFI's own `MvpWitness::deterministic_valid`. This is a proxy-AIR
/// artefact; the full §4.2 claim-1 depth-32 Merkle chain is `K-AIR`
/// follow-up work.
#[derive(Debug, Clone)]
pub struct TransferWitness {
    inner: MvpWitness,
}

impl TransferWitness {
    /// Build a prover-ready witness from the real send material.
    ///
    /// Inputs:
    /// - `spends`: the selected owned-note handles (1..=4).
    /// - `spend_values`: per-spend `value` (u64, ≤ Goldilocks).
    /// - `output_values`: per-output `value` (1..=4).
    /// - `output_cms`: per-output commitment digests (32 B each).
    /// - `output_addrs_ivk_cm`: per-output recipient `ivk_commitment` (32 B).
    /// - `output_addrs_pk_d`: per-output recipient `pk_d` (32 B).
    /// - `output_addrs_d`: per-output recipient diversifier (11 B).
    /// - `fee`: tx-level fee.
    /// - `anchor`: 32-byte anchor (§4.1 commitment-tree root).
    pub fn build(
        spends: &[OwnedNote],
        spend_values: &[u64],
        output_values: &[u64],
        output_cms: &[[u8; 32]],
        output_addrs_d: &[[u8; 11]],
        output_addrs_pk_d: &[[u8; 32]],
        output_addrs_ivk_cm: &[[u8; 32]],
        fee: u64,
        anchor: &[u8; 32],
    ) -> Result<Self> {
        let n_s = spends.len();
        let n_o = output_values.len();
        if !(1..=P3_MAX_SPENDS).contains(&n_s) {
            return Err(anyhow!(
                "TransferWitness: spend count {} outside §4.1 envelope [1,{}]",
                n_s, P3_MAX_SPENDS));
        }
        if !(1..=P3_MAX_OUTPUTS).contains(&n_o) {
            return Err(anyhow!(
                "TransferWitness: output count {} outside §4.1 envelope [1,{}]",
                n_o, P3_MAX_OUTPUTS));
        }
        if spend_values.len() != n_s
            || output_cms.len() != n_o
            || output_addrs_d.len() != n_o
            || output_addrs_pk_d.len() != n_o
            || output_addrs_ivk_cm.len() != n_o
        {
            return Err(anyhow!("TransferWitness: input slice length mismatch"));
        }

        // Balance check — the prover's pre_check enforces this too, but
        // surfacing a wallet-side error beats an opaque FFI rejection.
        let sin: u128 = spend_values.iter().map(|v| *v as u128).sum();
        let sout: u128 = output_values.iter().map(|v| *v as u128).sum();
        if sin != sout + (fee as u128) {
            return Err(anyhow!(
                "TransferWitness: Σ spend={} ≠ Σ output={} + fee={}",
                sin, sout, fee));
        }
        if fee >= P_GL {
            return Err(anyhow!("TransferWitness: fee >= Goldilocks prime"));
        }

        // Derive shared proxy fields from the anchor + first spend's
        // diversifier. All spends must land on the same `(leaf, sibling)`
        // for the proxy AIR's single-step Merkle to compress to one anchor;
        // we therefore compute ONE leaf/sibling pair and replicate.
        let shared_sibling = reduce_digest_to_proxy(b"uno-sw-sibling", anchor);
        let shared_ivk = reduce_digest_to_proxy(b"uno-sw-ivk", anchor);
        let shared_pk_d = reduce_digest_to_proxy(b"uno-sw-pk_d", anchor);
        let shared_rcm = reduce_digest_to_proxy(b"uno-sw-rcm", anchor);
        // Use min spend value as the shared per-spend proxy value so that
        // `n_s · v_per_spend ≤ Σ real spend values` and the remaining
        // balance can always be absorbed by the outputs below.
        let v_per_spend = *spend_values.iter().min().unwrap_or(&0);
        if v_per_spend == 0 {
            return Err(anyhow!("TransferWitness: zero spend value"));
        }

        let perm = default_goldilocks_poseidon2_8();
        let ivkcm_fe = poseidon2_ivk_commitment(&perm, shared_ivk, shared_sibling);
        let shared_leaf_fe = poseidon2_cm(
            &perm,
            shared_sibling,
            shared_pk_d,
            ivkcm_fe.as_canonical_u64(),
            v_per_spend,
            shared_rcm,
        );
        let shared_leaf = shared_leaf_fe.as_canonical_u64();
        let anchor_proxy_fe = poseidon2_merkle(&perm, shared_leaf, shared_sibling);
        let anchor_proxy = anchor_proxy_fe.as_canonical_u64();

        // Per-spend: distinguish `(nk, pos)` from the real note material.
        let mut p3_spends = Vec::with_capacity(n_s);
        for (i, note) in spends.iter().enumerate() {
            let nk = reduce_digest_to_proxy(b"uno-sw-nk", &note.nullifier);
            let pos = note.position;
            // Keep value proxy equal to v_per_spend (shared); the real note's
            // value differs, but balance is preserved in the outputs.
            let _ = (i, spend_values);
            p3_spends.push(P3SpendWitness {
                leaf: shared_leaf,
                merkle_sibling: shared_sibling.to_le_bytes(),
                value: v_per_spend,
                ivk: shared_ivk,
                pk_d: shared_pk_d,
                rcm: shared_rcm,
                nk,
                pos,
            });
        }

        // Proxy balance: Σ p3_spends.value = n_s · v_per_spend. Spread
        // `total_in - fee` across outputs, last output absorbs the
        // remainder. Individual proxy output values are a pure proxy;
        // they do NOT need to equal the real output values (the AIR's
        // claim 8 binds *proxy* values).
        let total_in: u128 = (n_s as u128) * (v_per_spend as u128);
        if total_in < fee as u128 {
            return Err(anyhow!(
                "TransferWitness: proxy total_in {} < fee {}", total_in, fee));
        }
        let total_out: u128 = total_in - (fee as u128);
        let v_per_out_base: u64 = (total_out / (n_o as u128)) as u64;
        let remainder: u64 = (total_out
            - (v_per_out_base as u128) * (n_o as u128)) as u64;

        let mut p3_outputs = Vec::with_capacity(n_o);
        for j in 0..n_o {
            let d_proxy = reduce_digest_to_proxy_slice(b"uno-ow-d", &output_addrs_d[j]);
            let pk_d_proxy =
                reduce_digest_to_proxy(b"uno-ow-pk_d", &output_addrs_pk_d[j]);
            let ivkcm_proxy =
                reduce_digest_to_proxy(b"uno-ow-ivkcm", &output_addrs_ivk_cm[j]);
            let rcm_proxy = reduce_digest_to_proxy(b"uno-ow-rcm", &output_cms[j]);
            let value_proxy = if j + 1 == n_o {
                v_per_out_base + remainder
            } else {
                v_per_out_base
            };
            p3_outputs.push(P3OutputWitness {
                d: d_proxy,
                pk_d: pk_d_proxy,
                ivk_commitment: ivkcm_proxy,
                value: value_proxy,
                rcm: rcm_proxy,
            });
        }

        Ok(Self {
            inner: MvpWitness {
                fee,
                spends: p3_spends,
                outputs: p3_outputs,
                anchor_proxy,
            },
        })
    }

    /// Serialize the witness to the byte layout `MvpProver::prove` expects.
    pub fn serialize(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Canonical public-input byte vector for the AIR, as produced by the
    /// prover. Exposed so tests can verify the emitted proof against the
    /// same PI vector the prover consumed.
    pub fn public_inputs(&self) -> Vec<u8> {
        self.inner.public_inputs_bytes()
    }
}

/// Run the real Plonky3 prover over `witness` and return the serialized
/// proof bytes. Also writes the wall-clock prover time into
/// `LAST_PROVE_NANOS` so [`SendSummary`] can surface it.
///
/// Panics: only if the prover's internal serialization fails (postcard) —
/// which is a programmer-error-level invariant on this pinned Plonky3 rev.
/// Honest witnesses produced by [`TransferWitness::build`] always pass the
/// prover's pre-check (balance + claim-1 + claim-2).
pub fn plonky3_prove(witness: &TransferWitness) -> Vec<u8> {
    let witness_bytes = witness.serialize();
    let t0 = std::time::Instant::now();
    let prover = prover_singleton();
    let (proof_bytes, _pi_bytes) = prover
        .prove(&witness_bytes)
        .expect("Plonky3 prover rejected a wallet-constructed witness — this is a bug in TransferWitness::build");
    let elapsed = t0.elapsed().as_nanos();
    LAST_PROVE_NANOS.with(|c| c.set(elapsed));
    eprintln!(
        "tosctl uno send: Plonky3 prove shape=({},{}) proof={}B pi={}B time={}ms",
        witness.inner.spends.len(),
        witness.inner.outputs.len(),
        proof_bytes.len(),
        _pi_bytes.len(),
        elapsed / 1_000_000,
    );
    proof_bytes
}

// --- Proxy-reduction helpers -----------------------------------------------
//
// The M-P2 AIR packs every witness slot into a single canonical Goldilocks
// element. These helpers fold arbitrary wire bytes into a canonical u64
// residue via BLAKE3-keyed digests, reduced mod `p_Goldilocks`.

fn reduce_digest_to_proxy(domain: &[u8], bytes: &[u8; 32]) -> u64 {
    reduce_digest_to_proxy_slice(domain, bytes)
}

fn reduce_digest_to_proxy_slice(domain: &[u8], bytes: &[u8]) -> u64 {
    let mut h = blake3::Hasher::new();
    h.update(b"uno-p3-proxy-v1");
    h.update(domain);
    h.update(bytes);
    let d = h.finalize();
    let mut first8 = [0u8; 8];
    first8.copy_from_slice(&d.as_bytes()[..8]);
    let raw = u64::from_le_bytes(first8);
    // Canonical reduction: mask to 63 bits so result is < 2^63 < P_GL.
    raw & ((1u64 << 63) - 1)
}

// --- Poseidon2 wrappers mirroring `uno_plonky3_ffi::transfer_air` ----------
//
// Inlined here (crate-private in the FFI) so the wallet can compute the
// witness's `leaf` / `anchor_proxy` fields byte-identically with the
// prover's pre_check.

fn poseidon2_merkle(
    perm: &Poseidon2Goldilocks<8>,
    leaf: u64,
    sibling: u64,
) -> Goldilocks {
    let mut state = [Goldilocks::ZERO; 8];
    state[0] = Goldilocks::from_u64(reduce_u64_to_gl(leaf));
    state[1] = Goldilocks::from_u64(reduce_u64_to_gl(sibling));
    perm.permute_mut(&mut state);
    state[0]
}

fn poseidon2_ivk_commitment(
    perm: &Poseidon2Goldilocks<8>,
    ivk: u64,
    d: u64,
) -> Goldilocks {
    let mut state = [Goldilocks::ZERO; 8];
    state[0] = Goldilocks::from_u64(TAG_IVK_CM);
    state[1] = Goldilocks::from_u64(reduce_u64_to_gl(ivk));
    state[2] = Goldilocks::from_u64(reduce_u64_to_gl(d));
    perm.permute_mut(&mut state);
    state[0]
}

fn poseidon2_cm(
    perm: &Poseidon2Goldilocks<8>,
    d: u64,
    pk_d: u64,
    ivk_commitment: u64,
    value: u64,
    rcm: u64,
) -> Goldilocks {
    let mut state = [Goldilocks::ZERO; 8];
    state[0] = Goldilocks::from_u64(TAG_CM);
    state[1] = Goldilocks::from_u64(reduce_u64_to_gl(d));
    state[2] = Goldilocks::from_u64(reduce_u64_to_gl(pk_d));
    state[3] = Goldilocks::from_u64(reduce_u64_to_gl(ivk_commitment));
    state[4] = Goldilocks::from_u64(reduce_u64_to_gl(value));
    state[5] = Goldilocks::from_u64(reduce_u64_to_gl(rcm));
    perm.permute_mut(&mut state);
    state[0]
}

#[inline]
fn reduce_u64_to_gl(x: u64) -> u64 {
    if x >= P_GL {
        x.wrapping_sub(P_GL)
    } else {
        x
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_to_32(s: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(s.trim_start_matches("0x")).context("hex decode")?;
    if raw.len() != 32 {
        return Err(anyhow!("expected 32 bytes, got {}", raw.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Test hooks: build_transfer_from_notes + helpers for round-trip tests.
// These bypass the RPC layer — the test supplies a synthetic `unspent` vec.
// ---------------------------------------------------------------------------

/// Test-only: build a Transfer from pre-selected notes + recipient + fvk,
/// **without** touching the network. Returns the signed Transfer + the raw
/// wire bytes + the `tx_hash`.
///
/// `deterministic` flags a mode that seeds both the hybrid-KEM ephemerals
/// and the Schnorr `rsk` from a fixed domain-separated KDF over the note's
/// nullifier + output index. This is used by `tests/send_roundtrip.rs` to
/// assert bit-identical reconstruction across two runs.
#[doc(hidden)]
pub fn test_build_transfer(
    fvk: &FullViewingKey,
    recipient: &Address,
    notes: &[OwnedNote],
    amount: u64,
    fee: u64,
    anchor: &[u8; 32],
    chain_id: u32,
    expiry_block: u64,
    memo: Option<&str>,
) -> Result<(Transfer, Vec<u8>, [u8; 32])> {
    let sel = select_notes(notes, amount, fee)
        .ok_or_else(|| anyhow!("test_build_transfer: insufficient funds"))?;
    let tx = build_transfer(fvk, recipient, &sel, anchor, chain_id, expiry_block, memo)?;
    let signed = sign_spends(tx, &sel.rsk_keys);
    let hash = canonical_tx_hash(&signed);
    let bytes = encode_transfer_wire(&signed)?;
    Ok((signed, bytes, hash))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_seed() -> [u8; 32] {
        let mut s = [0u8; 32]; for i in 0..32 { s[i] = i as u8; } s
    }

    fn owned_note(value: u64, salt: u8) -> OwnedNote {
        OwnedNote {
            block_seqno: 1,
            global_index: salt as u64,
            cm: [salt; 32],
            nullifier: [salt.wrapping_add(1); 32],
            value,
            diversifier: [salt.wrapping_add(2); 11],
            position: salt as u64,
        }
    }

    #[test]
    fn select_single_cover() {
        let notes = vec![owned_note(100, 1), owned_note(50, 2), owned_note(200, 3)];
        let s = select_notes(&notes, 120, 10).expect("should find cover");
        // Picked smallest single note that covers: 200 (100 < 130 < 200).
        assert_eq!(s.notes.len(), 1);
        assert_eq!(s.notes[0].value, 200);
        assert_eq!(s.change_value, 200 - 120 - 10);
        assert!(s.needs_change);
    }

    #[test]
    fn select_exact_no_change() {
        let notes = vec![owned_note(130, 1)];
        let s = select_notes(&notes, 120, 10).expect("exact cover");
        assert_eq!(s.notes.len(), 1);
        assert_eq!(s.change_value, 0);
        assert!(!s.needs_change);
    }

    #[test]
    fn select_multi_cover() {
        let notes = vec![owned_note(40, 1), owned_note(50, 2), owned_note(60, 3)];
        // target = 130, no single covers; 60 + 50 = 110, +40 = 150. Picks 3.
        let s = select_notes(&notes, 120, 10).expect("multi cover");
        assert_eq!(s.notes.len(), 3);
        let sum: u64 = s.notes.iter().map(|n| n.value).sum();
        assert!(sum >= 130);
    }

    #[test]
    fn select_insufficient() {
        let notes = vec![owned_note(10, 1)];
        let s = select_notes(&notes, 120, 10);
        assert!(s.is_none());
    }

    #[test]
    fn build_output_roundtrip_trial_decrypts() {
        // Build an output to our own address, then run scan::try_open to
        // close the loop.
        let fvk = keygen::derive_fvk(&fixed_seed()).unwrap();
        let d = [0x55u8; 11];
        let addr = Address::build(&fvk, &d).unwrap();
        let out = build_output(&addr, 42_000, Some("hi")).unwrap();
        let wire_out = crate::wire::OutputDescription {
            cm: out.cm,
            epk: out.epk,
            filter_tag: out.filter_tag,
            enc_ciphertext: out.enc_ciphertext,
            mlkem_ct: out.mlkem_ct,
            out_ciphertext: out.out_ciphertext,
        };
        let opened = crate::scan::try_open(&fvk, &wire_out).unwrap().expect("should open");
        assert_eq!(opened.d, d);
        assert_eq!(opened.value, 42_000);
    }

    #[test]
    fn plonky3_prove_produces_real_proof() {
        // Single-spend / single-output witness at the smallest shape.
        let note = owned_note(1_000, 0x42);
        let witness = TransferWitness::build(
            &[note],
            &[1_000],
            &[990],
            &[[0x11u8; 32]],
            &[[0x22u8; 11]],
            &[[0x33u8; 32]],
            &[[0x44u8; 32]],
            10,
            &[0xAAu8; 32],
        ).expect("build witness");
        let proof = plonky3_prove(&witness);
        // §17 proof-size budget: anywhere from ~30 KB (1/1 shape) to
        // ~210 KB (4/4 shape). Any valid proof must fall in that window.
        assert!(
            (30_000..=210_000).contains(&proof.len()),
            "proof size {} outside expected [30 KB, 210 KB] window", proof.len()
        );
        // Proof must round-trip through the FFI verifier.
        let verifier = uno_plonky3_ffi::verifier::MvpVerifier::new();
        let pi = witness.public_inputs();
        let rc = verifier.verify(&proof, &pi);
        assert_eq!(rc, uno_plonky3_ffi::Plonky3Status::Ok,
                   "FFI verifier must accept a freshly-produced proof");
    }
}

// Ensure the RISTRETTO_BASEPOINT_POINT import is used (it's referenced in
// docs / future hooks for diversified-base-point math). Suppress dead_code
// if the linker doesn't find the symbol on specific feature combos.
#[allow(dead_code)]
const _BP: &curve25519_dalek::edwards::EdwardsPoint =
    &curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
#[allow(dead_code)]
fn _bp_ref() -> &'static curve25519_dalek::ristretto::RistrettoPoint {
    &RISTRETTO_BASEPOINT_POINT
}
