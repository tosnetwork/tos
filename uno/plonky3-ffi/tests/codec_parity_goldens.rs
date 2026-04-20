//! K-codec-parity — Rust ↔ C++ byte-parity golden generator.
//!
//! This integration test pins the four §4.1 Transfer shapes (1/1, 1/2, 2/3,
//! 4/4) as deterministic fixtures and, on every `cargo test` invocation,
//! REGENERATES `uno/test/golden/codec-parity-v1.hex` with the Rust-computed
//! derived fields: per-output `ivk_commitment` / `cm`, per-spend `nf`, the
//! canonical §4.1 `tx_hash` preimage + BLAKE3 output, and the §4.3-step-4
//! Plonky3 public-input bytes.
//!
//! The C++ half lives at `uno/test/test-codec-parity.cpp`; it reads the
//! same fixture file and asserts byte-equality against the
//! `uno_workchain::` codec surface (`compute_note_commitment`,
//! `build_plonky3_public_inputs`, and a locally-assembled tx_hash preimage
//! that plugs the pinned cell-root hashes in for `enc_ciphertext` /
//! `mlkem_ct`).
//!
//! Primitive parity: we reproduce `uno/crypto/poseidon2.cpp`'s
//! `pack_domain_tag` + `hash_with_tag_and_fp` sponge here byte-for-byte,
//! which is the same sponge `tosctl/uno/src/poseidon2.rs::hash_tagged`
//! uses. All Poseidon2 permutations route through the Plonky3
//! `default_goldilocks_poseidon2_{8,16}` instances — i.e., the exact same
//! constants the prover and verifier use. That shared dependency is the
//! load-bearing invariant: any drift in Poseidon2 round constants breaks
//! both the AIR and this fixture at the same commit.
//!
//! Would have caught: the §3.1 `rcm` tag-truncation bug
//! (K-genesis-distribution) where the C++ side sliced `"uno-rcm-v1"` to 9
//! bytes instead of 10; the resulting `rcm` values silently diverged from
//! Rust, which would have tripped the `cm_hex` assertion on the very first
//! 1/1 record had this test existed at the time.
//!
//! Regenerate with:
//!     cd uno/plonky3-ffi && cargo test --release --test codec_parity_goldens

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{default_goldilocks_poseidon2_16, Goldilocks};
use p3_symmetric::Permutation;

const P_GL: u64 = Goldilocks::ORDER_U64;
const DIGEST: usize = 32;

// ---------------------------------------------------------------------------
// Poseidon2-Goldilocks tagged sponge — byte-for-byte mirror of
// `uno/crypto/poseidon2.cpp::hash_with_tag_and_fp` and
// `tosctl/uno/src/poseidon2.rs::hash_tagged`. The wire-level contract is
// §2.2 of doc/uno-workchain.md; any drift here is a consensus bug.
// ---------------------------------------------------------------------------

fn load_wrapped(limb: u64) -> Goldilocks {
    let v = if limb >= P_GL { limb - P_GL } else { limb };
    Goldilocks::from_u64(v)
}

fn bytes_to_fes_wrapped(bytes: &[u8]) -> Vec<Goldilocks> {
    assert!(bytes.len() % 8 == 0);
    bytes
        .chunks_exact(8)
        .map(|c| load_wrapped(u64::from_le_bytes(c.try_into().unwrap())))
        .collect()
}

fn fes_to_digest(fes: &[Goldilocks; 4]) -> [u8; DIGEST] {
    let mut out = [0u8; DIGEST];
    for i in 0..4 {
        let v = fes[i].as_canonical_u64();
        out[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    out
}

fn pack_tag_block(tag: &[u8]) -> [Goldilocks; 8] {
    // Matches C++ `pack_domain_tag` exactly: load 8-byte LE chunks as u64
    // into Goldilocks, zero-pad the final partial chunk, trailing slots
    // are zero. All Uno domain tags are pure ASCII and ≤ 16 B, so the
    // per-limb canonical assertion is vacuous in practice.
    let mut out = [Goldilocks::ZERO; 8];
    let n = tag.len().min(64);
    let full = (n / 8).min(8);
    for i in 0..full {
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&tag[i * 8..i * 8 + 8]);
        let v = u64::from_le_bytes(limb);
        assert!(v < P_GL, "tag chunk not canonical (non-ASCII?)");
        out[i] = Goldilocks::from_u64(v);
    }
    let rem = n - full * 8;
    if rem > 0 && full < 8 {
        let mut buf = [0u8; 8];
        buf[..rem].copy_from_slice(&tag[full * 8..full * 8 + rem]);
        let v = u64::from_le_bytes(buf);
        assert!(v < P_GL);
        out[full] = Goldilocks::from_u64(v);
    }
    out
}

/// `Poseidon2(tag, fes...)` — byte-identical to the C++ sponge.
fn hash_tagged(tag: &[u8], fes: &[Goldilocks]) -> [u8; DIGEST] {
    let perm16 = default_goldilocks_poseidon2_16();
    let tag_block = pack_tag_block(tag);
    if fes.len() <= 8 {
        let mut state = [Goldilocks::ZERO; 16];
        state[..8].copy_from_slice(&tag_block);
        for (i, f) in fes.iter().enumerate() {
            state[8 + i] = *f;
        }
        perm16.permute_mut(&mut state);
        return fes_to_digest(&[state[0], state[1], state[2], state[3]]);
    }
    // Iterated width-16 sponge; rate 8 (low), capacity 8 (high, pre-seeded
    // with the tag). Matches `hash_with_tag_and_fp`'s `n > 8` branch.
    let mut state = [Goldilocks::ZERO; 16];
    state[8..].copy_from_slice(&tag_block);
    let mut i = 0usize;
    while i + 8 <= fes.len() {
        for j in 0..8 {
            state[j] = state[j] + fes[i + j];
        }
        perm16.permute_mut(&mut state);
        i += 8;
    }
    let rem = fes.len() - i;
    if rem > 0 {
        for j in 0..rem {
            state[j] = state[j] + fes[i + j];
        }
        state[rem] = state[rem] + Goldilocks::ONE;
        perm16.permute_mut(&mut state);
    } else {
        state[0] = state[0] + Goldilocks::ONE;
        perm16.permute_mut(&mut state);
    }
    fes_to_digest(&[state[0], state[1], state[2], state[3]])
}

fn hash_tagged_bytes(tag: &[u8], bytes: &[u8]) -> [u8; DIGEST] {
    let fes = bytes_to_fes_wrapped(bytes);
    hash_tagged(tag, &fes)
}

// ---------------------------------------------------------------------------
// Domain primitives (§3.2 / §2.6 / §3.4)
// ---------------------------------------------------------------------------

/// `rcm = Poseidon2("uno-rcm-v1", rseed)` (§3.1). Absorbs 4 LE limbs of the
/// 32-byte rseed; output is the canonical 32-byte digest form.
fn compute_rcm(rseed: &[u8; 32]) -> [u8; 32] {
    hash_tagged_bytes(b"uno-rcm-v1", rseed)
}

/// `ivk_commitment = Poseidon2("uno-ivk-cm-v1", ivk, d)` (§2.6 / decision #1).
/// Input packing: `ivk` → 4 fes (wrapped-load LE); `d` (11 B) padded to 16
/// B → 2 fes. Total 6 absorbed elements.
fn compute_ivk_commitment(ivk: &[u8; 32], d: &[u8; 11]) -> [u8; 32] {
    let mut fes = bytes_to_fes_wrapped(ivk);
    let mut padded = [0u8; 16];
    padded[..11].copy_from_slice(d);
    fes.extend(bytes_to_fes_wrapped(&padded));
    hash_tagged(b"uno-ivk-cm-v1", &fes)
}

/// `cm = Poseidon2("uno-cm-v1", d, pk_d, ivk_commitment, value, rcm)`
/// (§3.2 / decision #1). Packing matches C++
/// `uno_workchain::compute_note_commitment` exactly: 15 absorbed fes →
/// width-16 single-block sponge.
fn compute_note_commitment(
    d: &[u8; 11],
    pk_d: &[u8; 32],
    ivk_commitment: &[u8; 32],
    value: u64,
    rcm: &[u8; 32],
) -> [u8; 32] {
    let mut fes: Vec<Goldilocks> = Vec::with_capacity(15);
    let mut padded = [0u8; 16];
    padded[..11].copy_from_slice(d);
    fes.extend(bytes_to_fes_wrapped(&padded));
    fes.extend(bytes_to_fes_wrapped(pk_d));
    fes.extend(bytes_to_fes_wrapped(ivk_commitment));
    let v = if value >= P_GL { value - P_GL } else { value };
    fes.push(Goldilocks::from_u64(v));
    fes.extend(bytes_to_fes_wrapped(rcm));
    assert_eq!(fes.len(), 15);
    hash_tagged(b"uno-cm-v1", &fes)
}

/// `nf = Poseidon2("uno-nf-v1", nk, cm, pos)` (§3.4).
///
/// Input packing: `nk` → 4 fes, `cm` → 4 fes, `pos` → 1 fe. 9 absorbed fes
/// trigger the iterated branch of the width-16 sponge.
fn derive_nullifier(nk: &[u8; 32], cm: &[u8; 32], pos: u64) -> [u8; 32] {
    let mut fes: Vec<Goldilocks> = Vec::with_capacity(9);
    fes.extend(bytes_to_fes_wrapped(nk));
    fes.extend(bytes_to_fes_wrapped(cm));
    let v = if pos >= P_GL { pos - P_GL } else { pos };
    fes.push(Goldilocks::from_u64(v));
    hash_tagged(b"uno-nf-v1", &fes)
}

// ---------------------------------------------------------------------------
// §4.3 step 4 public-input encoder — mirror of
// `uno/core/transaction.cpp::build_plonky3_public_inputs`.
// ---------------------------------------------------------------------------

fn encode_u64_strict(x: u64) -> [u8; 8] {
    assert!(x < P_GL, "u64 public input {x} >= p_Goldilocks");
    x.to_le_bytes()
}

fn encode_256(bytes: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for limb in 0..4 {
        let chunk: [u8; 8] = bytes[limb * 8..(limb + 1) * 8].try_into().unwrap();
        let mut v = u64::from_le_bytes(chunk);
        if v >= P_GL {
            v -= P_GL;
        }
        out[limb * 8..(limb + 1) * 8].copy_from_slice(&v.to_le_bytes());
    }
    out
}

fn build_public_inputs(tx: &FixtureTransfer) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + 64 * tx.spends.len() + 72 * tx.outputs.len());
    out.extend_from_slice(&(tx.scheme_id as u64).to_le_bytes());
    out.extend_from_slice(&(tx.chain_id as u64).to_le_bytes());
    out.extend_from_slice(&encode_u64_strict(tx.expiry_block));
    out.extend_from_slice(&encode_u64_strict(tx.fee));
    out.extend_from_slice(&encode_256(&tx.anchor));
    for s in &tx.spends {
        out.extend_from_slice(&encode_256(&s.nullifier));
        out.extend_from_slice(&encode_256(&s.rk));
    }
    for o in &tx.outputs {
        out.extend_from_slice(&encode_256(&o.cm));
        out.extend_from_slice(&encode_256(&o.epk));
        out.extend_from_slice(&(o.filter_tag as u64).to_le_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// §4.1 canonical tx_hash — mirror of
// `uno/core/transaction.cpp::canonical_tx_hash`. Large cell-ref payloads
// (`enc_ciphertext`, `mlkem_ct`) appear in the preimage as their 32-byte
// cell-root hashes; here we pin those hashes as fixture inputs so the
// BLAKE3 output is a pure function of data this file and the C++ test both
// see.
// ---------------------------------------------------------------------------

fn canonical_tx_hash_preimage(tx: &FixtureTransfer) -> Vec<u8> {
    // 56 header + 64·n_s + (32+32+2+32+32+80)·n_o bytes.
    let mut buf: Vec<u8> = Vec::with_capacity(
        56 + tx.spends.len() * 64 + tx.outputs.len() * (32 + 32 + 2 + 32 + 32 + 80),
    );
    buf.push(1u8); // version
    buf.push(tx.scheme_id);
    buf.extend_from_slice(&tx.chain_id.to_be_bytes());
    buf.extend_from_slice(&tx.anchor);
    buf.extend_from_slice(&tx.expiry_block.to_be_bytes());
    buf.extend_from_slice(&tx.fee.to_be_bytes());
    buf.push(tx.spends.len() as u8);
    buf.push(tx.outputs.len() as u8);
    for s in &tx.spends {
        buf.extend_from_slice(&s.nullifier);
        buf.extend_from_slice(&s.rk);
    }
    for o in &tx.outputs {
        buf.extend_from_slice(&o.cm);
        buf.extend_from_slice(&o.epk);
        buf.extend_from_slice(&o.filter_tag.to_be_bytes());
        buf.extend_from_slice(&o.enc_ct_hash);
        buf.extend_from_slice(&o.mlkem_ct_hash);
        buf.extend_from_slice(&o.out_ciphertext);
    }
    buf
}

fn canonical_tx_hash(tx: &FixtureTransfer) -> [u8; 32] {
    let preimage = canonical_tx_hash_preimage(tx);
    let mut out = [0u8; 32];
    let hash = blake3::hash(&preimage);
    out.copy_from_slice(hash.as_bytes());
    out
}

// ---------------------------------------------------------------------------
// Fixture Transfer (test-only): linear LE/BE dump of the fields the C++
// codec consumes. Keyed by shape; four shapes total.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct FixtureSpend {
    nullifier: [u8; 32],
    rk: [u8; 32],
    // "witness inputs" captured here so the C++ side can independently
    // recompute the nullifier and match.
    nk: [u8; 32],
    cm_input_for_nf: [u8; 32],
    pos: u64,
}

#[derive(Clone, Debug)]
struct FixtureOutput {
    // Wire fields (fill into uno_workchain::OutputDescription).
    cm: [u8; 32],
    epk: [u8; 32],
    filter_tag: u16,
    out_ciphertext: [u8; 80],
    // Pinned cell-root hashes — plugged into the tx_hash preimage on both
    // sides. Real cells are constructed by the C++ test with whatever
    // payloads it likes; only these 32-byte values matter to tx_hash.
    enc_ct_hash: [u8; 32],
    mlkem_ct_hash: [u8; 32],

    // "cm witness inputs" captured for C++ parity check.
    d: [u8; 11],
    pk_d: [u8; 32],
    ivk_commitment: [u8; 32],
    value: u64,
    rcm: [u8; 32],

    // Keys that feed `ivk_commitment` so the C++ side can recompute.
    ivk: [u8; 32],
    // Seed for `rcm` = Poseidon2("uno-rcm-v1", rseed).
    rseed: [u8; 32],
}

#[derive(Clone, Debug)]
struct FixtureTransfer {
    scheme_id: u8,
    chain_id: u32,
    expiry_block: u64,
    fee: u64,
    anchor: [u8; 32],
    spends: Vec<FixtureSpend>,
    outputs: Vec<FixtureOutput>,
}

// ---------------------------------------------------------------------------
// Deterministic generator. Each fixture-byte is derived from `(shape_id,
// role, index, slot)` via a FNV-1a scramble keyed on a global seed. No
// `rand` / no OS entropy — identical output on every host.
// ---------------------------------------------------------------------------

const FIXTURE_SEED: u64 = 0x1234_5678_9ABC_DEF0;

fn scramble(shape_id: u64, role: u64, index: u64, slot: u64) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &x in &[FIXTURE_SEED, shape_id, role, index, slot] {
        h ^= x;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

fn fill_bytes(shape_id: u64, role: u64, index: u64, out: &mut [u8]) {
    for (i, b) in out.iter_mut().enumerate() {
        let slot = (i / 8) as u64;
        let chunk = scramble(shape_id, role, index, slot);
        *b = (chunk >> (8 * (i % 8))) as u8;
    }
}

fn build_fixture(n_spends: usize, n_outputs: usize) -> FixtureTransfer {
    let shape_id = (n_spends as u64) * 10 + (n_outputs as u64);

    let mut anchor = [0u8; 32];
    fill_bytes(shape_id, 0, 0, &mut anchor);

    let mut spends = Vec::with_capacity(n_spends);
    for i in 0..n_spends {
        let idx = i as u64;
        let mut nk = [0u8; 32];
        fill_bytes(shape_id, 1, idx, &mut nk);
        let mut cm_for_nf = [0u8; 32];
        fill_bytes(shape_id, 2, idx, &mut cm_for_nf);
        let pos = scramble(shape_id, 3, idx, 0) & ((1u64 << 32) - 1);
        let nullifier = derive_nullifier(&nk, &cm_for_nf, pos);
        let mut rk = [0u8; 32];
        fill_bytes(shape_id, 4, idx, &mut rk);

        spends.push(FixtureSpend {
            nullifier,
            rk,
            nk,
            cm_input_for_nf: cm_for_nf,
            pos,
        });
    }

    let mut outputs = Vec::with_capacity(n_outputs);
    for j in 0..n_outputs {
        let idx = j as u64;
        let mut d = [0u8; 11];
        // Generate 11 bytes using slot 0's chunk.
        let chunk0 = scramble(shape_id, 10, idx, 0);
        let chunk1 = scramble(shape_id, 10, idx, 1);
        for i in 0..8 {
            d[i] = (chunk0 >> (8 * i)) as u8;
        }
        for i in 0..3 {
            d[8 + i] = (chunk1 >> (8 * i)) as u8;
        }
        let mut pk_d = [0u8; 32];
        fill_bytes(shape_id, 11, idx, &mut pk_d);
        let mut ivk = [0u8; 32];
        fill_bytes(shape_id, 12, idx, &mut ivk);
        let mut rseed = [0u8; 32];
        fill_bytes(shape_id, 13, idx, &mut rseed);

        let value = (scramble(shape_id, 14, idx, 0) & ((1u64 << 40) - 1)) + 1;

        let rcm = compute_rcm(&rseed);
        let ivk_commitment = compute_ivk_commitment(&ivk, &d);
        let cm = compute_note_commitment(&d, &pk_d, &ivk_commitment, value, &rcm);

        let mut epk = [0u8; 32];
        fill_bytes(shape_id, 15, idx, &mut epk);

        // filter_tag from a derived Poseidon2 hash (deterministic, in [0, 2^16)).
        let filter_tag = (scramble(shape_id, 16, idx, 0) & 0xFFFF) as u16;

        let mut out_ciphertext = [0u8; 80];
        fill_bytes(shape_id, 17, idx, &mut out_ciphertext);
        let mut enc_ct_hash = [0u8; 32];
        fill_bytes(shape_id, 18, idx, &mut enc_ct_hash);
        let mut mlkem_ct_hash = [0u8; 32];
        fill_bytes(shape_id, 19, idx, &mut mlkem_ct_hash);

        outputs.push(FixtureOutput {
            cm,
            epk,
            filter_tag,
            out_ciphertext,
            enc_ct_hash,
            mlkem_ct_hash,
            d,
            pk_d,
            ivk_commitment,
            value,
            rcm,
            ivk,
            rseed,
        });
    }

    FixtureTransfer {
        scheme_id: 0x01,
        chain_id: 0x0000_0002, // "uno" wc
        // Well under p_Goldilocks so encode_u64_strict is happy.
        expiry_block: 100_000 + shape_id * 1_000,
        fee: 1_000 + shape_id * 10,
        anchor,
        spends,
        outputs,
    }
}

// ---------------------------------------------------------------------------
// Fixture-internal linear dump — the byte layout C++ test parses. Same
// conventions as `public-inputs-v1.hex` (u8/u16/u32/u64 little-endian
// *within the dump*; fields that the C++ codec reads big-endian on the
// wire are NOT rewritten — the C++ test's `decode_fixture_transfer`
// constructs a `uno_workchain::Transfer` from the dumped fields, and the
// codec-binding encoders/decoders are exercised through that struct).
// ---------------------------------------------------------------------------

fn encode_fixture_transfer(tx: &FixtureTransfer) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(tx.scheme_id);
    out.extend_from_slice(&tx.chain_id.to_le_bytes());
    out.extend_from_slice(&tx.expiry_block.to_le_bytes());
    out.extend_from_slice(&tx.fee.to_le_bytes());
    out.push(tx.spends.len() as u8);
    out.push(tx.outputs.len() as u8);
    out.extend_from_slice(&tx.anchor);
    for s in &tx.spends {
        out.extend_from_slice(&s.nullifier);
        out.extend_from_slice(&s.rk);
        out.extend_from_slice(&s.nk);
        out.extend_from_slice(&s.cm_input_for_nf);
        out.extend_from_slice(&s.pos.to_le_bytes());
    }
    for o in &tx.outputs {
        out.extend_from_slice(&o.cm);
        out.extend_from_slice(&o.epk);
        out.extend_from_slice(&o.filter_tag.to_le_bytes());
        out.extend_from_slice(&o.out_ciphertext);
        out.extend_from_slice(&o.enc_ct_hash);
        out.extend_from_slice(&o.mlkem_ct_hash);
        // cm witness inputs (so the C++ side recomputes cm independently).
        out.extend_from_slice(&o.d);
        out.extend_from_slice(&o.pk_d);
        out.extend_from_slice(&o.ivk_commitment);
        out.extend_from_slice(&o.value.to_le_bytes());
        out.extend_from_slice(&o.rcm);
        out.extend_from_slice(&o.ivk);
        out.extend_from_slice(&o.rseed);
    }
    out
}

// ---------------------------------------------------------------------------
// Hex + fixture-file writer.
// ---------------------------------------------------------------------------

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

fn golden_path() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("..")
        .join("test")
        .join("golden")
        .join("codec-parity-v1.hex")
}

#[test]
fn regenerate_codec_parity_goldens() {
    // Four §4.1 shapes covering the 1..4 × 1..4 envelope's corners and a
    // mid-shape that exercises unequal spend/output counts.
    let shapes: &[(usize, usize)] = &[(1, 1), (1, 2), (2, 3), (4, 4)];

    let path = golden_path();
    let mut file = fs::File::create(&path)
        .unwrap_or_else(|e| panic!("failed to create {}: {e}", path.display()));

    let header = r##"# uno/test/golden/codec-parity-v1.hex
#
# K-codec-parity — cross-impl byte-parity golden fixtures for the §4.1
# Transfer codec primitives of doc/uno-workchain.md.
#
# Generated by (Rust):
#   cd uno/plonky3-ffi && cargo test --release --test codec_parity_goldens
#
# Consumed by (C++):
#   uno/test/test-codec-parity.cpp (CMake target: test-uno-codec-parity)
#
# Each record pins one deterministic (n_spends, n_outputs) Transfer and the
# Rust-side values for every consensus-critical derived field:
#
#   * `transfer_hex`:   fixture-internal linear dump. Layout:
#       u8  scheme_id
#       u32 LE chain_id
#       u64 LE expiry_block
#       u64 LE fee
#       u8  spend_count
#       u8  output_count
#       32 B anchor
#       per spend:  32 B nullifier || 32 B rk || 32 B nk ||
#                    32 B cm_input_for_nf || u64 LE pos
#       per output: 32 B cm || 32 B epk || u16 LE filter_tag ||
#                    80 B out_ciphertext ||
#                    32 B enc_ct_hash (pinned cell-root hash) ||
#                    32 B mlkem_ct_hash (pinned cell-root hash) ||
#                    11 B d || 32 B pk_d || 32 B ivk_commitment ||
#                    u64 LE value || 32 B rcm || 32 B ivk || 32 B rseed
#
#   * `pubinput_hex`:   §4.3 step 4 public-input byte encoding of the
#                        decoded Transfer. `64 + 64·n_s + 72·n_o` bytes.
#   * `tx_hash_hex`:    32 B canonical §4.1 BLAKE3 tx_hash, computed over
#                        the preimage that plugs `enc_ct_hash` / `mlkem_ct_hash`
#                        directly into the cell-hash slots.
#   * `cm_hex[j]`:      32 B recomputed note commitment
#                        `Poseidon2("uno-cm-v1", d, pk_d, ivk_cm, value, rcm)`.
#   * `ivk_commitment_hex[j]`: 32 B recomputed `Poseidon2("uno-ivk-cm-v1",
#                        ivk, d)`.
#   * `nf_hex[i]`:      32 B recomputed `Poseidon2("uno-nf-v1", nk,
#                        cm_input_for_nf, pos)`.
#
# Record format:
#   shape: <n_spends>,<n_outputs>
#   transfer_hex: <hex>
#   pubinput_hex: <hex>
#   tx_hash_hex:  <hex>
#   cm_hex:       <hex> (× n_outputs, concatenated)
#   ivk_commitment_hex: <hex> (× n_outputs, concatenated)
#   nf_hex:       <hex> (× n_spends, concatenated)
#   # blank line separates records
#
# DO NOT edit by hand; regenerate via the cargo-test command above.

"##;
    file.write_all(header.as_bytes()).unwrap();

    for &(n_s, n_o) in shapes {
        let tx = build_fixture(n_s, n_o);
        let transfer_bytes = encode_fixture_transfer(&tx);
        let pubinput_bytes = build_public_inputs(&tx);
        let tx_hash = canonical_tx_hash(&tx);

        let mut cm_concat = Vec::with_capacity(32 * n_o);
        let mut ivk_cm_concat = Vec::with_capacity(32 * n_o);
        for o in &tx.outputs {
            cm_concat.extend_from_slice(&o.cm);
            ivk_cm_concat.extend_from_slice(&o.ivk_commitment);
        }
        let mut nf_concat = Vec::with_capacity(32 * n_s);
        for s in &tx.spends {
            nf_concat.extend_from_slice(&s.nullifier);
        }

        writeln!(file, "shape: {},{}", n_s, n_o).unwrap();
        writeln!(file, "transfer_hex: {}", to_hex(&transfer_bytes)).unwrap();
        writeln!(file, "pubinput_hex: {}", to_hex(&pubinput_bytes)).unwrap();
        writeln!(file, "tx_hash_hex: {}", to_hex(&tx_hash)).unwrap();
        writeln!(file, "cm_hex: {}", to_hex(&cm_concat)).unwrap();
        writeln!(file, "ivk_commitment_hex: {}", to_hex(&ivk_cm_concat)).unwrap();
        writeln!(file, "nf_hex: {}", to_hex(&nf_concat)).unwrap();
        writeln!(file).unwrap();
    }

    file.sync_all().unwrap();

    eprintln!(
        "test-codec-parity-goldens: wrote {} with {} shape records",
        path.display(),
        shapes.len(),
    );
}

// ---------------------------------------------------------------------------
// Self-consistency: the golden generator is pure; running it twice must
// produce byte-identical output. Also sanity-check that `nf_hex` depends
// on `nk` (catches a trivial copy-paste bug in the scrambler).
// ---------------------------------------------------------------------------

#[test]
fn golden_generator_is_deterministic() {
    let a = build_fixture(2, 3);
    let b = build_fixture(2, 3);
    assert_eq!(encode_fixture_transfer(&a), encode_fixture_transfer(&b));
    assert_eq!(canonical_tx_hash(&a), canonical_tx_hash(&b));
    assert_eq!(build_public_inputs(&a), build_public_inputs(&b));
}

#[test]
fn nf_changes_when_nk_changes() {
    let tx = build_fixture(2, 3);
    let s0 = &tx.spends[0];
    let nf_orig = derive_nullifier(&s0.nk, &s0.cm_input_for_nf, s0.pos);
    let mut nk_twisted = s0.nk;
    nk_twisted[0] ^= 1;
    let nf_twisted = derive_nullifier(&nk_twisted, &s0.cm_input_for_nf, s0.pos);
    assert_ne!(nf_orig, nf_twisted);
}

#[test]
fn cm_changes_when_value_changes() {
    let tx = build_fixture(1, 1);
    let o = &tx.outputs[0];
    let cm_a =
        compute_note_commitment(&o.d, &o.pk_d, &o.ivk_commitment, o.value, &o.rcm);
    let cm_b = compute_note_commitment(
        &o.d,
        &o.pk_d,
        &o.ivk_commitment,
        o.value.wrapping_add(1),
        &o.rcm,
    );
    assert_eq!(cm_a, o.cm, "generator cm must match the recomputation");
    assert_ne!(cm_a, cm_b);
}
