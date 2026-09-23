/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! On-chain Groth16 verification, sections 10.1 and 17.
//!
//! The proofs here were produced by the circuit tool with a real prover and
//! written to `tools/shielded-pool-circuit/fixtures/`. Verifying them in the VM
//! is the strongest cross-implementation evidence this project has: an
//! arkworks prover, a blst verifier inside TVM, and a byte format that ruling
//! A1 pinned so that nothing converts anything in between.
//!
//! The keys are development keys from a fixed seed. The fixture says so in a
//! field of its own, and so does this file: the toxic waste is known and these
//! must never verify a real transaction.

use serde_json::Value;

use chain_block::{BuilderData, Cell, IBitstring, MsgAddressInt, Serializable, StateInit};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func_with_stdlib};
use tos_vm::stack::StackItem;

const TOS: u64 = 1_000_000_000;
const ACTIVE_VERSION: u32 = 18;
const INPUT_COUNT: usize = 18;

fn fixture() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../tools/shielded-pool-circuit/fixtures/groth16-development.json"
    );
    let text = std::fs::read_to_string(path).expect("the development fixture");
    serde_json::from_str(&text).expect("the fixture is JSON")
}

fn hex_bytes(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("hex"))
        .collect()
}

/// The canonical 1248-byte chain of section 13.1: nine full cells and a
/// 105-byte tail.
fn byte_chain(bytes: &[u8]) -> Cell {
    let pieces: Vec<&[u8]> = bytes.chunks(127).collect();
    let mut chain: Option<Cell> = None;
    for piece in pieces.iter().rev() {
        let mut builder = BuilderData::new();
        builder.append_raw(piece, piece.len() * 8).expect("a chunk");
        if let Some(next) = chain {
            builder.checked_append_reference(next).expect("a chain reference");
        }
        chain = Some(builder.into_cell().expect("a chain cell"));
    }
    chain.expect("a chain")
}

/// Section 13.3: A and C in the root, B behind its only reference.
fn proof_cell(a: &[u8], b: &[u8], c: &[u8]) -> Cell {
    let mut b_cell = BuilderData::new();
    b_cell.append_raw(b, 768).expect("B");
    let mut root = BuilderData::new();
    root.append_raw(a, 384).expect("A");
    root.append_raw(c, 384).expect("C");
    root.checked_append_reference(b_cell.into_cell().expect("B cell")).expect("B reference");
    root.into_cell().expect("a proof")
}

/// Eighteen field elements as six cells of three, linked.
fn inputs_chain(values: &[String]) -> Cell {
    assert_eq!(values.len(), INPUT_COUNT, "the vector is not eighteen long");
    let mut chain: Option<Cell> = None;
    for group in values.chunks(3).rev() {
        let mut builder = BuilderData::new();
        for value in group {
            let bytes = decimal_to_bytes(value);
            builder.append_raw(&bytes, 256).expect("a field element");
        }
        if let Some(next) = chain {
            builder.checked_append_reference(next).expect("a chain reference");
        }
        chain = Some(builder.into_cell().expect("an inputs cell"));
    }
    chain.expect("an inputs chain")
}

fn decimal_to_bytes(text: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for ch in text.bytes() {
        let mut carry = (ch - b'0') as u32;
        for byte in out.iter_mut().rev() {
            let value = (*byte as u32) * 10 + carry;
            *byte = (value & 0xff) as u8;
            carry = value >> 8;
        }
        assert_eq!(carry, 0, "value does not fit in 256 bits: {text}");
    }
    out
}

const PROBE: &str = r#"
;; Eighteen field elements out of six linked cells of three.
tuple read_inputs(cell chain) impure {
  tuple inputs = empty_tuple();
  int groups = 0;
  while (groups < 6) {
    slice s = chain.begin_parse();
    throw_unless(300, s.slice_bits() == 768);
    int index = 0;
    while (index < 3) {
      inputs = inputs.tpush(s~load_uint(256));
      index = index + 1;
    }
    groups = groups + 1;
    if (groups < 6) {
      throw_unless(300, s.slice_refs() == 1);
      chain = s~load_ref();
    } else {
      throw_unless(300, s.slice_refs() == 0);
    }
  }
  return inputs;
}

int p_verify(cell vk, cell proof, cell inputs_chain) method_id {
  (slice ac, slice b) = groth16_proof_parse(proof);
  slice a = ac~load_bits(384);
  slice c = ac~load_bits(384);
  groth16_require_valid(vk, a, b, c, read_inputs(inputs_chain));
  return 1;
}

int p_vk_alpha_first_byte(cell vk) method_id {
  (slice alpha, _, _, _, _) = vk_points(vk);
  return alpha~load_uint(8);
}
() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure { }
() recv_external(slice in_msg) impure { }
"#;

struct Probe {
    bc: Blockchain,
    addr: MsgAddressInt,
}

impl Probe {
    fn deploy() -> Self {
        let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)
            .expect("blockchain at version 17");
        let payer = bc.treasury("deployer", 1_000 * TOS).expect("treasury");
        let library = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../crypto/smartcont/shielded");
        // A directory of this call's own. These probes are written from several tests at
        // once, and a shared path is truncated under a concurrent `func` reading it.
        let probe_dir = tempfile::tempdir().expect("a directory for the probe");
        let probe_path = probe_dir.path().join("tos_shielded_groth16_probe.fc");
        std::fs::write(&probe_path, PROBE).expect("write probe");
        let code = compile_func_with_stdlib(&[
            std::path::PathBuf::from(format!("{library}/domains.fc")),
            std::path::PathBuf::from(format!("{library}/empty-roots.fc")),
            std::path::PathBuf::from(format!("{library}/notes.fc")),
            std::path::PathBuf::from(format!("{library}/auth.fc")),
            std::path::PathBuf::from(format!("{library}/payload.fc")),
            std::path::PathBuf::from(format!("{library}/domain.fc")),
            std::path::PathBuf::from(format!("{library}/transact.fc")),
            std::path::PathBuf::from(format!("{library}/groth16.fc")),
            probe_path,
        ])
        .expect("compile the shielded library (needs build/crypto/func)");
        let mut data = BuilderData::new();
        data.append_u32(0).unwrap();
        let si = StateInit::with_code_and_data(code, data.into_cell().unwrap());
        let hash = si.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
        let addr = MsgAddressInt::with_params(0, hash).unwrap();
        bc.send_message(
            MessageBuilder::internal(payer.address(), &addr, 2 * TOS)
                .bounce(false)
                .state_init(si)
                .body(Cell::default())
                .build(),
        )
        .expect("deploy")
        .expect_success();
        Self { bc, addr }
    }

    fn verify(&self, vk: &Cell, proof: &Cell, inputs: &Cell) -> (i32, i64) {
        let result = self
            .bc
            .run_get_method(
                &self.addr,
                "p_verify",
                vec![
                    StackItem::Cell(vk.clone()),
                    StackItem::Cell(proof.clone()),
                    StackItem::Cell(inputs.clone()),
                ],
            )
            .expect("p_verify should run");
        (result.exit_code, result.gas_used)
    }
}

// ---------------------------------------------------------------------------

#[test]
fn the_development_proof_verifies_in_the_vm_and_its_mutations_do_not() {
    let fixture = fixture();
    let vk_hex = fixture["verifying_key"]["hex"].as_str().expect("the verifying key");
    let vk_bytes = hex_bytes(vk_hex);
    assert_eq!(vk_bytes.len(), 1248, "the verifying key is not 1248 bytes");
    let vk = byte_chain(&vk_bytes);

    let probe = Probe::deploy();

    // The chain reader finds the key where section 10.1 puts it: alpha first.
    let alpha_byte = probe
        .bc
        .run_get_method(&probe.addr, "p_vk_alpha_first_byte", vec![StackItem::Cell(vk.clone())])
        .expect("p_vk_alpha_first_byte");
    assert_eq!(alpha_byte.exit_code, 0, "the verifying key could not be read");
    assert_eq!(
        alpha_byte.stack.last().unwrap().as_integer().unwrap().to_string(),
        vk_bytes[0].to_string(),
        "alpha does not start where the stream does"
    );

    let vectors = fixture["vectors"].as_array().expect("the vectors");
    assert_eq!(vectors.len(), 5, "the fixture no longer has five vectors");

    let mut verified = 0;
    let mut rejected = 0;
    for vector in vectors {
        let name = vector["name"].as_str().expect("a name");
        let must_verify = vector["must_verify"].as_bool().expect("a verdict");
        let proof = proof_cell(
            &hex_bytes(vector["proof"]["a_hex"].as_str().expect("A")),
            &hex_bytes(vector["proof"]["b_hex"].as_str().expect("B")),
            &hex_bytes(vector["proof"]["c_hex"].as_str().expect("C")),
        );
        let inputs: Vec<String> = vector["public_inputs_decimal"]
            .as_array()
            .expect("the inputs")
            .iter()
            .map(|value| value.as_str().expect("a decimal").to_string())
            .collect();
        let (exit, gas) = probe.verify(&vk, &proof, &inputs_chain(&inputs));
        if must_verify {
            assert_eq!(exit, 0, "{name}: a proof the prover accepts was rejected in the VM");
            eprintln!("{name}: verified in {gas} gas");
            verified += 1;
        } else {
            assert_eq!(exit, 262, "{name}: a proof the prover rejects was accepted in the VM");
            rejected += 1;
        }
    }
    assert_eq!(verified, 1, "no valid proof was exercised");
    assert_eq!(rejected, 4, "the mutated vectors were not all exercised");
}

#[test]
fn a_public_input_the_proof_did_not_commit_to_is_rejected() {
    let fixture = fixture();
    let vk = byte_chain(&hex_bytes(fixture["verifying_key"]["hex"].as_str().unwrap()));
    let valid = &fixture["vectors"][0];
    let proof = proof_cell(
        &hex_bytes(valid["proof"]["a_hex"].as_str().unwrap()),
        &hex_bytes(valid["proof"]["b_hex"].as_str().unwrap()),
        &hex_bytes(valid["proof"]["c_hex"].as_str().unwrap()),
    );
    let inputs: Vec<String> = valid["public_inputs_decimal"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    let probe = Probe::deploy();
    assert_eq!(probe.verify(&vk, &proof, &inputs_chain(&inputs)).0, 0, "the baseline failed");

    // Every slot: changing any one of the eighteen has to break the proof, or
    // that slot is not bound by it.
    for index in 0..INPUT_COUNT {
        let mut tampered = inputs.clone();
        tampered[index] = if tampered[index] == "0" { "1".to_string() } else { "0".to_string() };
        assert_eq!(
            probe.verify(&vk, &proof, &inputs_chain(&tampered)).0,
            262,
            "public input {index} was changed and the proof still verified"
        );
    }
}

#[test]
fn a_verifying_key_chain_that_is_not_the_frozen_shape_is_refused() {
    let fixture = fixture();
    let bytes = hex_bytes(fixture["verifying_key"]["hex"].as_str().unwrap());
    let probe = Probe::deploy();
    let valid = &fixture["vectors"][0];
    let proof = proof_cell(
        &hex_bytes(valid["proof"]["a_hex"].as_str().unwrap()),
        &hex_bytes(valid["proof"]["b_hex"].as_str().unwrap()),
        &hex_bytes(valid["proof"]["c_hex"].as_str().unwrap()),
    );
    let inputs = inputs_chain(
        &valid["public_inputs_decimal"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect::<Vec<_>>(),
    );

    // One byte short: the key runs out before the last IC point is complete.
    let short = byte_chain(&bytes[..bytes.len() - 1]);
    assert_eq!(probe.verify(&short, &proof, &inputs).0, 260, "a short key was read anyway");

    // One byte long: the chain holds something after the key.
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(probe.verify(&byte_chain(&long), &proof, &inputs).0, 261, "a long key was accepted");

    // A cell whose data is not a whole number of bytes.
    let mut ragged = BuilderData::new();
    ragged.append_raw(&bytes[..100], 799).unwrap();
    ragged.checked_append_reference(byte_chain(&bytes[100..])).unwrap();
    assert_eq!(
        probe.verify(&ragged.into_cell().unwrap(), &proof, &inputs).0,
        261,
        "a chain cell with a partial byte was accepted"
    );

    // A chain whose final cell carries a successor. The key is all there and
    // ends where it should; what is wrong is that something hangs off it.
    let mut tail = BuilderData::new();
    tail.append_raw(&bytes[9 * 127..], 105 * 8).unwrap();
    tail.checked_append_reference(Cell::default()).unwrap();
    let mut chain = tail.into_cell().unwrap();
    for index in (0..9).rev() {
        let mut builder = BuilderData::new();
        builder.append_raw(&bytes[index * 127..(index + 1) * 127], 127 * 8).unwrap();
        builder.checked_append_reference(chain).unwrap();
        chain = builder.into_cell().unwrap();
    }
    assert_eq!(
        probe.verify(&chain, &proof, &inputs).0,
        261,
        "a final chain cell with a successor was accepted"
    );

    // A chain cell with two successors. One reference means "the chain goes
    // on"; none means "it ends here"; two is neither, and the cell that
    // catches a dangling tail cannot catch this.
    let mut forked = BuilderData::new();
    forked.append_raw(&bytes[..127], 127 * 8).unwrap();
    forked.checked_append_reference(byte_chain(&bytes[127..])).unwrap();
    forked.checked_append_reference(Cell::default()).unwrap();
    assert_eq!(
        probe.verify(&forked.into_cell().unwrap(), &proof, &inputs).0,
        261,
        "a chain cell with two successors was accepted"
    );

    // And the canonical chain still verifies, so the cases above are about
    // shape and not about having broken the key.
    assert_eq!(probe.verify(&byte_chain(&bytes), &proof, &inputs).0, 0);
}
