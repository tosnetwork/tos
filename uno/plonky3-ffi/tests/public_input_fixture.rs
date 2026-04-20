//! Rust-side cross-check of the Plonky3 public-input byte encoding
//! (decision #5, §4.3 step 4 of `doc/uno-workchain.md`).
//!
//! This is the Rust half of the consensus-binding encoder-parity gate.
//! The C++ half lives at `uno/test/test-public-input-fixture.cpp`. Both
//! read the same `uno/test/golden/public-inputs-v1.hex` fixture and
//! MUST produce byte-identical output for every record.
//!
//! Encoding rules (mirrors `uno/core/transaction.cpp`):
//!   * `encode_u64(x)` — assert `x < p_Goldilocks`; emit 8 B LE.
//!   * `encode_256(b)` — split 32 B into 4 × u64 LE; reduce each chunk
//!     mod `p_Goldilocks`; re-emit each canonical limb in LE.
//!   * Element order: scheme_id, chain_id, expiry_block, fee, anchor,
//!     per-spend (nf, rk), per-output (cm, epk, filter_tag).

use std::fs;
use std::path::{Path, PathBuf};

const P: u64 = 0xFFFF_FFFF_0000_0001;

fn encode_u64(x: u64) -> [u8; 8] {
    assert!(x < P, "u64 {x} >= p_Goldilocks");
    x.to_le_bytes()
}

fn encode_u64_nonstrict(x: u64) -> [u8; 8] {
    // For u8 / u16 / u32 inputs we never exceed p, so the strict check is
    // vacuous; we expose this path so the fixture-internal reader can
    // accept arbitrary small values without needing to know the field.
    x.to_le_bytes()
}

fn encode_256(bytes: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for limb in 0..4 {
        let chunk: [u8; 8] = bytes[limb * 8..(limb + 1) * 8].try_into().unwrap();
        let mut v = u64::from_le_bytes(chunk);
        if v >= P {
            // Single subtraction suffices: p > 2^63, so u64 - p fits.
            v -= P;
        }
        out[limb * 8..(limb + 1) * 8].copy_from_slice(&v.to_le_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// Fixture-internal Transfer layout (see the fixture file header comment).
// Linear LE dump of the struct fields that `build_plonky3_public_inputs`
// reads — NOT the §4.1 BoC wire format.
// ---------------------------------------------------------------------------

struct FixtureTransfer {
    scheme_id: u8,
    chain_id: u32,
    expiry_block: u64,
    fee: u64,
    anchor: [u8; 32],
    spends: Vec<FixtureSpend>,
    outputs: Vec<FixtureOutput>,
}

struct FixtureSpend {
    nullifier: [u8; 32],
    rk: [u8; 32],
}

struct FixtureOutput {
    cm: [u8; 32],
    epk: [u8; 32],
    filter_tag: u16,
}

fn decode_fixture_transfer(bytes: &[u8]) -> Option<FixtureTransfer> {
    let mut off = 0usize;
    if bytes.len() < 1 + 4 + 8 + 8 + 1 + 1 + 32 {
        return None;
    }
    let scheme_id = bytes[off]; off += 1;
    let chain_id = u32::from_le_bytes(bytes[off..off + 4].try_into().ok()?); off += 4;
    let expiry_block = u64::from_le_bytes(bytes[off..off + 8].try_into().ok()?); off += 8;
    let fee = u64::from_le_bytes(bytes[off..off + 8].try_into().ok()?); off += 8;
    let sc = bytes[off]; off += 1;
    let oc = bytes[off]; off += 1;
    let mut anchor = [0u8; 32];
    anchor.copy_from_slice(&bytes[off..off + 32]); off += 32;

    let need = off + (sc as usize) * 64 + (oc as usize) * (32 + 32 + 2);
    if bytes.len() < need { return None; }

    let mut spends = Vec::with_capacity(sc as usize);
    for _ in 0..sc {
        let mut nf = [0u8; 32];
        nf.copy_from_slice(&bytes[off..off + 32]); off += 32;
        let mut rk = [0u8; 32];
        rk.copy_from_slice(&bytes[off..off + 32]); off += 32;
        spends.push(FixtureSpend { nullifier: nf, rk });
    }
    let mut outputs = Vec::with_capacity(oc as usize);
    for _ in 0..oc {
        let mut cm = [0u8; 32];
        cm.copy_from_slice(&bytes[off..off + 32]); off += 32;
        let mut epk = [0u8; 32];
        epk.copy_from_slice(&bytes[off..off + 32]); off += 32;
        let filter_tag = u16::from_le_bytes(bytes[off..off + 2].try_into().ok()?); off += 2;
        outputs.push(FixtureOutput { cm, epk, filter_tag });
    }
    if off != bytes.len() { return None; }

    Some(FixtureTransfer {
        scheme_id,
        chain_id,
        expiry_block,
        fee,
        anchor,
        spends,
        outputs,
    })
}

fn build_public_inputs(tx: &FixtureTransfer) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        64 + 64 * tx.spends.len() + 72 * tx.outputs.len()
    );
    out.extend_from_slice(&encode_u64_nonstrict(tx.scheme_id as u64));
    out.extend_from_slice(&encode_u64_nonstrict(tx.chain_id as u64));
    out.extend_from_slice(&encode_u64(tx.expiry_block));
    out.extend_from_slice(&encode_u64(tx.fee));
    out.extend_from_slice(&encode_256(&tx.anchor));
    for s in &tx.spends {
        out.extend_from_slice(&encode_256(&s.nullifier));
        out.extend_from_slice(&encode_256(&s.rk));
    }
    for o in &tx.outputs {
        out.extend_from_slice(&encode_256(&o.cm));
        out.extend_from_slice(&encode_256(&o.epk));
        out.extend_from_slice(&encode_u64_nonstrict(o.filter_tag as u64));
    }
    out
}

// ---------------------------------------------------------------------------
// Fixture parser
// ---------------------------------------------------------------------------

struct Record {
    transfer_hex: String,
    pubinput_hex: String,
}

fn parse_fixture_file(path: &Path) -> Vec<Record> {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let mut records = Vec::new();
    let mut cur_transfer: Option<String> = None;
    let mut cur_pubinput: Option<String> = None;
    for (line_no, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim_end();
        if line.is_empty() || line.starts_with('#') { continue; }
        let (k, rest) = match line.split_once(':') {
            Some((k, rest)) => (k.trim(), rest.trim()),
            None => panic!("fixture line {}: no ':' separator: {line}", line_no + 1),
        };
        match k {
            "transfer_hex" => cur_transfer = Some(rest.to_string()),
            "pubinput_hex" => cur_pubinput = Some(rest.to_string()),
            other => panic!("fixture line {}: unknown key {other:?}", line_no + 1),
        }
        if let (Some(t), Some(p)) = (cur_transfer.as_ref(), cur_pubinput.as_ref()) {
            records.push(Record {
                transfer_hex: t.clone(),
                pubinput_hex: p.clone(),
            });
            cur_transfer = None;
            cur_pubinput = None;
        }
    }
    assert!(cur_transfer.is_none() && cur_pubinput.is_none(),
            "fixture file ends with unpaired transfer_hex/pubinput_hex");
    records
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex string length {} is odd", s.len());
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let n = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => 10 + (c - b'a'),
            b'A'..=b'F' => 10 + (c - b'A'),
            _ => panic!("non-hex char {:?}", c as char),
        }
    };
    let mut i = 0;
    while i < s.len() {
        out.push((n(b[i]) << 4) | n(b[i + 1]));
        i += 2;
    }
    out
}

fn fixture_path() -> PathBuf {
    // Crate root is uno/plonky3-ffi/; the fixture lives at the repo's
    // uno/test/golden/public-inputs-v1.hex, i.e. "../test/golden/..." from
    // CARGO_MANIFEST_DIR.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("..").join("test").join("golden").join("public-inputs-v1.hex")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn fixture_records_match_byte_for_byte() {
    let path = fixture_path();
    let records = parse_fixture_file(&path);
    assert!(!records.is_empty(), "fixture must contain at least one record");

    for (idx, rec) in records.iter().enumerate() {
        let tx_bytes = hex_decode(&rec.transfer_hex);
        let expected = hex_decode(&rec.pubinput_hex);
        let tx = decode_fixture_transfer(&tx_bytes)
            .unwrap_or_else(|| panic!("record {idx}: decode_fixture_transfer failed"));

        // Length assertion per §4.3 step 4 / decision #5.
        let expected_len = 64 + 64 * tx.spends.len() + 72 * tx.outputs.len();
        assert_eq!(
            expected.len(),
            expected_len,
            "record {idx}: fixture pubinput byte length mismatch (got {}, \
             expected {} per §4.3 step 4 formula)",
            expected.len(),
            expected_len,
        );

        let got = build_public_inputs(&tx);
        assert_eq!(
            got.len(),
            expected_len,
            "record {idx}: Rust encoder length mismatch",
        );
        assert_eq!(
            got,
            expected,
            "record {idx}: public-input byte mismatch.\n  got:      {}\n  expected: {}",
            hex_to_string(&got),
            hex_to_string(&expected),
        );
    }
}

fn hex_to_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
