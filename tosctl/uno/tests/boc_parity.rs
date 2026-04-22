//! V1-3c-beta cross-language byte-parity test harness.
//!
//! Round-trip `Transfer`s through the production C++ decoder:
//!
//!   Rust Transfer  ──encode_transfer_boc──▶  BoC bytes
//!                                              │
//!                                              ▼
//!                            stdin of `boc-parity-bridge` (C++)
//!                                              │
//!                                              ▼
//!                            uno_workchain::decode_transfer_bytes
//!                                              │
//!                                              ▼
//!                            stdout: line-based Transfer dump
//!                                              │
//!                                              ▼
//!                            Rust: parse, compare to original
//!
//! The C++ bridge is built by `uno/test/CMakeLists.txt`'s
//! `boc-parity-bridge` target. Its absolute path is provided to this
//! test via the `BOC_PARITY_BRIDGE` environment variable at BUILD time
//! (picked up by `build.rs` → `rustc-env`). If unset / file missing,
//! every test SKIPs cleanly.
//!
//! Guards:
//!   - `option_env!("BOC_PARITY_BRIDGE")` resolves at compile time to
//!     None if the env var was not set when the test binary was
//!     compiled, so `cargo test` in an untouched workspace (no cmake
//!     build, no env var) SKIPs silently.
//!   - The bridge path is also probed at runtime; if it disappeared
//!     between build and test, we SKIP too.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use tosctl_uno::boc_encode::encode_transfer_boc;
use tosctl_uno::transfer::{
    OutputDescription, SpendDescription, Transfer, SCHEME_ID_V1, TRANSFER_VERSION,
};

// ---------------------------------------------------------------------------
// Skip helper
// ---------------------------------------------------------------------------

/// Returns `Some(path)` iff the bridge was compiled-in via `BOC_PARITY_BRIDGE`
/// AND the binary exists on disk right now. Prints a SKIP line to stderr and
/// returns None otherwise.
fn bridge_path(test_name: &str) -> Option<&'static str> {
    match option_env!("BOC_PARITY_BRIDGE") {
        None => {
            eprintln!(
                "SKIP {test_name}: BOC_PARITY_BRIDGE not set at build time \
                 (build the C++ helper with `cmake --build <build> --target \
                 boc-parity-bridge` and rebuild with \
                 BOC_PARITY_BRIDGE=$(realpath <build>/uno/test/boc-parity-bridge))"
            );
            None
        }
        Some(p) if !Path::new(p).exists() => {
            eprintln!("SKIP {test_name}: bridge binary not found at {p}");
            None
        }
        Some(p) => Some(p),
    }
}

// ---------------------------------------------------------------------------
// Replica of `boc_encode::tests::sample_transfer` (public APIs only)
// ---------------------------------------------------------------------------

/// Build a deterministic Transfer for the cross-process harness. Mirrors
/// the shape-sweep pattern of `boc_encode::tests::sample_transfer` but
/// uses only publicly-exported types, so this test does not depend on
/// `#[cfg(test)]` internals of the crate.
///
/// Sizing note (V1-3c-beta + V1-3c-gamma): production transfers carry
/// enc_ciphertext ≈ 580 B and mlkem_ct = 1088 B — both chunked into
/// multi-cell linear chains by `encode_transfer_boc`. The C++ decoder's
/// §17 walk-depth gate was originally implemented via
/// `cell_depth_bounded(c) + 1 <= 5` which (per TOS cell-depth semantics)
/// descended into the chunk chains and tripped on any mlkem_ct ≥ 2
/// cells — rejecting honest v1 Transfers. V1-3c-gamma replaced that
/// with `structural_walk_depth`, which follows only the structural
/// tree (root → per_item → cont) and skips enc_ct / mlkem_ct / zk_proof
/// refs. The enc_ct / mlkem_ct / zk_proof subchains carry their own
/// `kChunkChainMaxChunks = 8192` bound.
///
/// With the gate fixed, this test runs at REALISTIC v1 payload sizes:
///   - enc_ciphertext: 579 B (~5 cells)
///   - mlkem_ct:      1088 B (~9 cells)  — the original trigger case
///   - zk_proof:     520 KB (~4096 cells) — full measured per-Tx proof
///
/// This exercises:
///   - every Transfer header field,
///   - full 1..=4 × 1..=4 spend/output shape dispatch,
///   - per-spend and per-output inline-cell + continuation-ref layout,
///   - multi-chunk chain-chain traversal through the C++ decoder's
///     `load_bytes_from_chunk_chain` with realistic chunk counts,
///   - BLAKE3 content-binding of the three variable-length payloads.
fn sample_transfer(n_spends: usize, n_outputs: usize) -> Transfer {
    let mut spends = Vec::with_capacity(n_spends);
    for i in 0..n_spends {
        let mut spend = SpendDescription {
            nullifier: [0u8; 32],
            rk: [0u8; 32],
            spend_auth_sig: [0u8; 64],
        };
        spend.nullifier[0] = i as u8;
        spend.rk[0] = (i + 0x10) as u8;
        spend.spend_auth_sig[0] = (i + 0x20) as u8;
        // Distinct high / tail bytes so any field-swap bug shows up.
        spend.nullifier[31] = 0xED;
        spend.rk[31] = 0xEF;
        spend.spend_auth_sig[63] = 0xFE;
        spends.push(spend);
    }
    let mut outputs = Vec::with_capacity(n_outputs);
    for j in 0..n_outputs {
        // Realistic v1 shape sizes (V1-3c-gamma): enc_ct ~579 B
        // (~5 cells), mlkem_ct 1088 B (~9 cells). These trigger the
        // multi-chunk chain traversal in the C++ decoder that was
        // broken by the pre-gamma walk-depth gate.
        let mut enc_ct = vec![0u8; 579];
        for (idx, b) in enc_ct.iter_mut().enumerate() {
            *b = (idx as u8).wrapping_mul(0x11).wrapping_add(j as u8);
        }
        let mut mlkem_ct = vec![0u8; 1088];
        for (idx, b) in mlkem_ct.iter_mut().enumerate() {
            *b = (idx as u8).wrapping_mul(0x13).wrapping_add(j as u8);
        }
        let mut output = OutputDescription {
            cm: [0u8; 32],
            epk: [0u8; 32],
            filter_tag: 0x4200 | (j as u16),
            enc_ciphertext: enc_ct,
            mlkem_ct,
            out_ciphertext: [0u8; 80],
        };
        output.cm[0] = (j + 0x30) as u8;
        output.cm[31] = 0xC1;
        output.epk[0] = (j + 0x40) as u8;
        output.epk[31] = 0xE1;
        output.out_ciphertext[0] = (j + 0x50) as u8;
        output.out_ciphertext[79] = 0x7F;
        outputs.push(output);
    }

    // zk_proof: 520 KB realistic v1 typical-shape size (~4096 cells).
    // V1-3c-gamma lets this traverse the full chunk chain through the
    // daemon's decoder.
    let mut zk_proof = vec![0u8; 520 * 1024];
    for (i, b) in zk_proof.iter_mut().enumerate() {
        *b = (i & 0xFF) as u8;
    }

    Transfer {
        version: TRANSFER_VERSION,
        scheme_id: SCHEME_ID_V1,
        chain_id: 0xCAFE_BABE,
        anchor: {
            let mut a = [0u8; 32];
            a[0] = 0xA0;
            a[31] = 0x0A;
            a
        },
        expiry_block: 0x1234_5678_9ABC_DEF0,
        fee: 100_000,
        spends,
        outputs,
        zk_proof,
    }
}

// ---------------------------------------------------------------------------
// Output-parser: consumes stdout of `boc-parity-bridge`
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct SpendRow {
    index: usize,
    nullifier: [u8; 32],
    rk: [u8; 32],
    sig: [u8; 64],
}

#[derive(Debug, Clone)]
struct OutputRow {
    index: usize,
    cm: [u8; 32],
    epk: [u8; 32],
    filter_tag: u16,
    out_ct: [u8; 80],
    enc_ct_blake3: [u8; 32],
    mlkem_ct_blake3: [u8; 32],
}

#[derive(Debug)]
struct Summary {
    version: u8,
    scheme_id: u8,
    chain_id: u32,
    anchor: [u8; 32],
    expiry_block: u64,
    fee: u64,
    spend_count: u8,
    output_count: u8,
    tx_hash: [u8; 32],
    spends: Vec<SpendRow>,
    outputs: Vec<OutputRow>,
    zk_proof_blake3: [u8; 32],
}

impl Summary {
    fn new() -> Self {
        Self {
            version: 0,
            scheme_id: 0,
            chain_id: 0,
            anchor: [0u8; 32],
            expiry_block: 0,
            fee: 0,
            spend_count: 0,
            output_count: 0,
            tx_hash: [0u8; 32],
            spends: Vec::new(),
            outputs: Vec::new(),
            zk_proof_blake3: [0u8; 32],
        }
    }
}

fn hex_to_fixed<const N: usize>(s: &str) -> Result<[u8; N], String> {
    if s.len() != 2 * N {
        return Err(format!(
            "hex field: expected {} chars, got {}",
            2 * N,
            s.len()
        ));
    }
    let mut out = [0u8; N];
    for i in 0..N {
        let hi =
            u8::from_str_radix(&s[2 * i..2 * i + 1], 16).map_err(|e| format!("hex parse: {e}"))?;
        let lo = u8::from_str_radix(&s[2 * i + 1..2 * i + 2], 16)
            .map_err(|e| format!("hex parse: {e}"))?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn parse_stdout(stdout: &str) -> Result<Summary, String> {
    let mut lines = stdout
        .lines()
        .map(|l| l.trim_end())
        .filter(|l| !l.is_empty());

    let first = lines.next().ok_or_else(|| "empty stdout".to_string())?;
    if first != "BOC_PARITY_V1" {
        return Err(format!(
            "bridge protocol mismatch: expected 'BOC_PARITY_V1' header, got {first:?}"
        ));
    }

    let mut s = Summary::new();

    for line in lines {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }
        match tokens[0] {
            "version" => {
                s.version = tokens
                    .get(1)
                    .ok_or("missing value for version")?
                    .parse()
                    .map_err(|e| format!("version parse: {e}"))?;
            }
            "scheme_id" => {
                s.scheme_id = tokens
                    .get(1)
                    .ok_or("missing value for scheme_id")?
                    .parse()
                    .map_err(|e| format!("scheme_id parse: {e}"))?;
            }
            "chain_id" => {
                s.chain_id = tokens
                    .get(1)
                    .ok_or("missing value for chain_id")?
                    .parse()
                    .map_err(|e| format!("chain_id parse: {e}"))?;
            }
            "anchor" => {
                s.anchor = hex_to_fixed::<32>(tokens.get(1).ok_or("missing anchor")?)?;
            }
            "expiry_block" => {
                s.expiry_block = tokens
                    .get(1)
                    .ok_or("missing expiry_block")?
                    .parse()
                    .map_err(|e| format!("expiry_block parse: {e}"))?;
            }
            "fee" => {
                s.fee = tokens
                    .get(1)
                    .ok_or("missing fee")?
                    .parse()
                    .map_err(|e| format!("fee parse: {e}"))?;
            }
            "spend_count" => {
                s.spend_count = tokens
                    .get(1)
                    .ok_or("missing spend_count")?
                    .parse()
                    .map_err(|e| format!("spend_count parse: {e}"))?;
            }
            "output_count" => {
                s.output_count = tokens
                    .get(1)
                    .ok_or("missing output_count")?
                    .parse()
                    .map_err(|e| format!("output_count parse: {e}"))?;
            }
            "tx_hash" => {
                s.tx_hash = hex_to_fixed::<32>(tokens.get(1).ok_or("missing tx_hash")?)?;
            }
            "spend" => {
                // spend <i> nullifier <hex-64> rk <hex-64> sig <hex-128>
                if tokens.len() != 8 {
                    return Err(format!(
                        "spend line: expected 8 tokens, got {} in {line:?}",
                        tokens.len()
                    ));
                }
                let idx: usize = tokens[1].parse().map_err(|e| format!("spend idx: {e}"))?;
                let row = SpendRow {
                    index: idx,
                    nullifier: hex_to_fixed::<32>(tokens[3])?,
                    rk: hex_to_fixed::<32>(tokens[5])?,
                    sig: hex_to_fixed::<64>(tokens[7])?,
                };
                s.spends.push(row);
            }
            "output" => {
                // output <j> cm <hex> epk <hex> filter_tag <u16> out_ct <hex>
                //        enc_ct_blake3 <hex> mlkem_ct_blake3 <hex>
                if tokens.len() != 14 {
                    return Err(format!(
                        "output line: expected 14 tokens, got {} in {line:?}",
                        tokens.len()
                    ));
                }
                let idx: usize = tokens[1].parse().map_err(|e| format!("output idx: {e}"))?;
                let filter_tag: u16 = tokens[7].parse().map_err(|e| format!("filter_tag: {e}"))?;
                let row = OutputRow {
                    index: idx,
                    cm: hex_to_fixed::<32>(tokens[3])?,
                    epk: hex_to_fixed::<32>(tokens[5])?,
                    filter_tag,
                    out_ct: hex_to_fixed::<80>(tokens[9])?,
                    enc_ct_blake3: hex_to_fixed::<32>(tokens[11])?,
                    mlkem_ct_blake3: hex_to_fixed::<32>(tokens[13])?,
                };
                s.outputs.push(row);
            }
            "zk_proof_blake3" => {
                s.zk_proof_blake3 =
                    hex_to_fixed::<32>(tokens.get(1).ok_or("missing zk_proof_blake3")?)?;
            }
            _ => {
                return Err(format!("unknown bridge output line: {line:?}"));
            }
        }
    }

    Ok(s)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn blake3_of(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

struct BridgeRun {
    stdout: String,
    stderr: String,
    status_code: Option<i32>,
}

/// Spawn the bridge, pipe `bytes` via stdin, capture stdout+stderr+exit code.
fn run_bridge(bridge: &str, bytes: &[u8]) -> BridgeRun {
    let mut child = Command::new(bridge)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {bridge}: {e}"));
    {
        let mut stdin = child.stdin.take().expect("bridge stdin");
        stdin
            .write_all(bytes)
            .unwrap_or_else(|e| panic!("write bridge stdin: {e}"));
    }
    let output = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("wait bridge: {e}"));
    BridgeRun {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        status_code: output.status.code(),
    }
}

/// Assert the bridge round-trip yields a Summary that matches `tx`. Returns
/// a contextual message on mismatch (empty on success).
fn compare_summary(tx: &Transfer, s: &Summary) -> Result<(), String> {
    if s.version != tx.version {
        return Err(format!("version: rust={} cxx={}", tx.version, s.version));
    }
    if s.scheme_id != tx.scheme_id {
        return Err(format!(
            "scheme_id: rust={} cxx={}",
            tx.scheme_id, s.scheme_id
        ));
    }
    if s.chain_id != tx.chain_id {
        return Err(format!(
            "chain_id: rust={:#x} cxx={:#x}",
            tx.chain_id, s.chain_id
        ));
    }
    if s.anchor != tx.anchor {
        return Err("anchor mismatch".to_string());
    }
    if s.expiry_block != tx.expiry_block {
        return Err(format!(
            "expiry_block: rust={} cxx={}",
            tx.expiry_block, s.expiry_block
        ));
    }
    if s.fee != tx.fee {
        return Err(format!("fee: rust={} cxx={}", tx.fee, s.fee));
    }
    if usize::from(s.spend_count) != tx.spends.len() {
        return Err(format!(
            "spend_count: rust={} cxx={}",
            tx.spends.len(),
            s.spend_count
        ));
    }
    if usize::from(s.output_count) != tx.outputs.len() {
        return Err(format!(
            "output_count: rust={} cxx={}",
            tx.outputs.len(),
            s.output_count
        ));
    }
    if s.spends.len() != tx.spends.len() {
        return Err(format!(
            "spend-row count: rust={} cxx={}",
            tx.spends.len(),
            s.spends.len()
        ));
    }
    if s.outputs.len() != tx.outputs.len() {
        return Err(format!(
            "output-row count: rust={} cxx={}",
            tx.outputs.len(),
            s.outputs.len()
        ));
    }
    for (i, (rs, cs)) in tx.spends.iter().zip(s.spends.iter()).enumerate() {
        if cs.index != i {
            return Err(format!("spend[{i}].index: cxx={}", cs.index));
        }
        if cs.nullifier != rs.nullifier {
            return Err(format!("spend[{i}].nullifier mismatch"));
        }
        if cs.rk != rs.rk {
            return Err(format!("spend[{i}].rk mismatch"));
        }
        if cs.sig != rs.spend_auth_sig {
            return Err(format!("spend[{i}].spend_auth_sig mismatch"));
        }
    }
    for (j, (ro, co)) in tx.outputs.iter().zip(s.outputs.iter()).enumerate() {
        if co.index != j {
            return Err(format!("output[{j}].index: cxx={}", co.index));
        }
        if co.cm != ro.cm {
            return Err(format!("output[{j}].cm mismatch"));
        }
        if co.epk != ro.epk {
            return Err(format!("output[{j}].epk mismatch"));
        }
        if co.filter_tag != ro.filter_tag {
            return Err(format!(
                "output[{j}].filter_tag: rust={:#x} cxx={:#x}",
                ro.filter_tag, co.filter_tag
            ));
        }
        if co.out_ct != ro.out_ciphertext {
            return Err(format!("output[{j}].out_ciphertext mismatch"));
        }
        let enc_hash = blake3_of(&ro.enc_ciphertext);
        if co.enc_ct_blake3 != enc_hash {
            return Err(format!(
                "output[{j}].enc_ciphertext BLAKE3 mismatch — \
                 possible C++/Rust wire-format divergence (re-check V1-3b)"
            ));
        }
        let mlkem_hash = blake3_of(&ro.mlkem_ct);
        if co.mlkem_ct_blake3 != mlkem_hash {
            return Err(format!(
                "output[{j}].mlkem_ct BLAKE3 mismatch — \
                 possible C++/Rust wire-format divergence (re-check V1-3b)"
            ));
        }
    }
    let zk_hash = blake3_of(&tx.zk_proof);
    if s.zk_proof_blake3 != zk_hash {
        return Err("zk_proof BLAKE3 mismatch — \
                    possible C++/Rust wire-format divergence (re-check V1-3b)"
            .to_string());
    }
    // tx_hash: intentionally not compared to a Rust-side expected value
    // here — V1-3c-gamma owns reconciling the canonical_tx_hash formula
    // between the flat Rust encoder and the cell-root hash-based C++
    // encoder. We still assert the bridge produced a non-zero hash (a
    // trivial well-formedness check).
    if s.tx_hash == [0u8; 32] {
        return Err("tx_hash is all-zero — decoder likely didn't populate it".to_string());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn rust_encode_cxx_decode_round_trip_typical_shape() {
    let bridge = match bridge_path("rust_encode_cxx_decode_round_trip_typical_shape") {
        Some(p) => p,
        None => return,
    };
    let tx = sample_transfer(1, 2);
    let bytes = encode_transfer_boc(&tx).expect("encode_transfer_boc");
    let run = run_bridge(bridge, &bytes);
    assert_eq!(
        run.status_code,
        Some(0),
        "bridge non-zero exit: status={:?} stderr={}",
        run.status_code,
        run.stderr
    );
    let summary = parse_stdout(&run.stdout).unwrap_or_else(|e| {
        panic!(
            "parse bridge stdout: {e}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            run.stdout, run.stderr
        )
    });
    if let Err(msg) = compare_summary(&tx, &summary) {
        panic!(
            "field mismatch: {msg}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            run.stdout, run.stderr
        );
    }
}

#[test]
fn rust_encode_cxx_decode_sweep_all_shapes() {
    let bridge = match bridge_path("rust_encode_cxx_decode_sweep_all_shapes") {
        Some(p) => p,
        None => return,
    };
    let mut failed: Vec<(usize, usize, String)> = Vec::new();
    for n_s in 1..=4 {
        for n_o in 1..=4 {
            let tx = sample_transfer(n_s, n_o);
            let bytes =
                encode_transfer_boc(&tx).unwrap_or_else(|e| panic!("encode {n_s}/{n_o}: {e}"));
            let run = run_bridge(bridge, &bytes);
            if run.status_code != Some(0) {
                failed.push((
                    n_s,
                    n_o,
                    format!("bridge exit={:?} stderr={}", run.status_code, run.stderr),
                ));
                continue;
            }
            let summary = match parse_stdout(&run.stdout) {
                Ok(s) => s,
                Err(e) => {
                    failed.push((n_s, n_o, format!("parse: {e}")));
                    continue;
                }
            };
            if let Err(msg) = compare_summary(&tx, &summary) {
                failed.push((n_s, n_o, msg));
            }
        }
    }
    assert!(
        failed.is_empty(),
        "{} of 16 shapes failed:\n{}",
        failed.len(),
        failed
            .iter()
            .map(|(s, o, m)| format!("  {s}/{o}: {m}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn cxx_decode_rejects_garbage() {
    let bridge = match bridge_path("cxx_decode_rejects_garbage") {
        Some(p) => p,
        None => return,
    };
    // Pure garbage — extremely unlikely to parse as a valid BoC magic header.
    let garbage: Vec<u8> = (0u8..=255).chain(0..=128).collect();
    let run = run_bridge(bridge, &garbage);
    assert_eq!(
        run.status_code,
        Some(1),
        "bridge should exit 1 on garbage; got {:?}\nstderr: {}",
        run.status_code,
        run.stderr
    );
    assert!(
        run.stderr.contains("decode_failed:"),
        "stderr should contain 'decode_failed:'; got: {}",
        run.stderr
    );
}

#[test]
fn cxx_decode_rejects_truncated_boc() {
    let bridge = match bridge_path("cxx_decode_rejects_truncated_boc") {
        Some(p) => p,
        None => return,
    };
    let tx = sample_transfer(2, 2);
    let bytes = encode_transfer_boc(&tx).expect("encode_transfer_boc");
    assert!(bytes.len() > 64, "bytes too short to truncate meaningfully");
    // Drop the last quarter so std_boc_deserialize rejects before the
    // Transfer decoder runs.
    let truncated = &bytes[..bytes.len() * 3 / 4];
    let run = run_bridge(bridge, truncated);
    assert_eq!(
        run.status_code,
        Some(1),
        "bridge should exit 1 on truncated BoC; got {:?}\nstderr: {}",
        run.status_code,
        run.stderr
    );
    assert!(
        run.stderr.contains("decode_failed:"),
        "stderr should contain 'decode_failed:'; got: {}",
        run.stderr
    );
}
