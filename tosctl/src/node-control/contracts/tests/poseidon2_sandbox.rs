/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! The Poseidon2 instruction pair reached from FunC, in the VM, through the
//! sandbox.
//!
//! The VM tests prove the instruction. This proves the last hop: that a FunC
//! `asm` wrapper pushes its arguments in the order the instruction expects,
//! that a domain constant compiled into a contract is the one the reference
//! used, and that the version gate is still there when the instruction is
//! reached this way rather than by hand-assembled bytecode.
//!
//! What it deliberately does **not** establish: what the seven field inputs of
//! any of these structures mean. The note layout belongs to the pool
//! specification, and inventing one here would produce vectors that agree only
//! with themselves.

use chain_block::poseidon2::permute;
use chain_block::poseidon2_kat::DOMAINS;
use tos_sandbox::{Blockchain, MessageBuilder, compile_func_with_stdlib};
use tos_vm::stack::StackItem;
use tos_vm::stack::integer::IntegerData;

use chain_block::{BuilderData, Cell, IBitstring, MsgAddressInt, Serializable, StateInit};

const TOS: u64 = 1_000_000_000;
const ACTIVE_VERSION: u32 = 18;
/// The version POSEIDON2_PERM8 and POSEIDON2_HASH7 shipped in, which is not
/// the version this suite runs at. They were the same number until
/// POSEIDON2_PATH7 raised the ceiling to 18, and a test that wrote
/// `ACTIVE_VERSION - 1` for "before this instruction existed" quietly started
/// asking whether the instruction exists at 17, where it does.
const POSEIDON2_MIN_VERSION: u32 = 17;

/// Every structure the work order names, with the domain label it is built on.
/// The wrapper in the contract binds the domain; the test binds nothing.
const STRUCTURES: [(&str, &str); 6] = [
    ("commit_node", "COMMIT-NODE"),
    ("imt_leaf", "IMT-LEAF"),
    ("imt_node", "IMT-NODE"),
    ("owner_commitment", "OWNER-COMMITMENT"),
    ("note_body", "NOTE-BODY"),
    ("nullifier", "NULLIFIER"),
];

fn domain_of(label: &str) -> [u8; 32] {
    DOMAINS
        .iter()
        .find(|(name, _)| *name == label)
        .unwrap_or_else(|| panic!("unknown domain label {label}"))
        .1
}

fn dec(bytes: &[u8; 32]) -> String {
    // Decimal rendering of a big-endian 256-bit value, done by hand so the
    // source of the contract's constants has no arithmetic dependency.
    let mut digits = vec![0u8];
    for &byte in bytes {
        let mut carry = byte as u32;
        for digit in digits.iter_mut() {
            let value = (*digit as u32) * 256 + carry;
            *digit = (value % 10) as u8;
            carry = value / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    digits.iter().rev().map(|d| (b'0' + d) as char).collect()
}

fn probe_source() -> String {
    let mut src = String::from(
        r#"
;; The two instructions, reached the way a contract would reach them.
int h7(int domain, int a0, int a1, int a2, int a3, int a4, int a5, int a6)
  asm "POSEIDON2_HASH7";
(int, int, int, int, int, int, int, int) perm8(
    int a0, int a1, int a2, int a3, int a4, int a5, int a6, int a7)
  asm "POSEIDON2_PERM8";

;; The instruction with nothing wrapped around it, to separate a wrapper
;; mistake from an instruction mistake.
int raw_h7(int domain, int a0, int a1, int a2, int a3, int a4, int a5, int a6) method_id {
  return h7(domain, a0, a1, a2, a3, a4, a5, a6);
}

(int, int, int, int, int, int, int, int) raw_perm8(
    int a0, int a1, int a2, int a3, int a4, int a5, int a6, int a7) method_id {
  return perm8(a0, a1, a2, a3, a4, a5, a6, a7);
}

() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure { }
() recv_external(slice in_msg) impure { }
"#,
    );
    // One wrapper per structure, each carrying its own domain constant.
    for (method, label) in STRUCTURES {
        let value = dec(&domain_of(label));
        src.push_str(&format!(
            "
int domain_{method}() asm \"{value} PUSHINT\";
int {method}(int a0, int a1, int a2, int a3, int a4, int a5, int a6) method_id {{
  return h7(domain_{method}(), a0, a1, a2, a3, a4, a5, a6);
}}
"
        ));
    }
    src
}

/// Seven deterministic field inputs. Small values, so that a wrong push order
/// is visible as a wrong answer rather than hidden by symmetry.
fn inputs() -> [[u8; 32]; 7] {
    let mut out = [[0u8; 32]; 7];
    for (index, value) in out.iter_mut().enumerate() {
        value[31] = (index as u8) * 7 + 3;
    }
    out
}

fn reference_h7(domain: &[u8; 32], fields: &[[u8; 32]; 7]) -> [u8; 32] {
    let mut state = [[0u8; 32]; 8];
    state[0] = *domain;
    state[1..].copy_from_slice(fields);
    permute(&state)[0]
}

struct Probe {
    bc: Blockchain,
    addr: MsgAddressInt,
}

impl Probe {
    fn deploy(version: u32) -> Self {
        let mut bc = Blockchain::with_global_version_and_base_workchain(version)
            .expect("blockchain at the requested version");
        let payer = bc.treasury("deployer", 1_000 * TOS).expect("treasury");
        // A directory of this call's own. These probes are written from several tests at
        // once, and a shared path is truncated under a concurrent `func` reading it.
        let probe_dir = tempfile::tempdir().expect("a directory for the probe");
        let path = probe_dir.path().join("tos_poseidon2_probe.fc");
        std::fs::write(&path, probe_source()).expect("write probe source");
        let code =
            compile_func_with_stdlib(&[path]).expect("compile the probe (needs build/crypto/func)");
        let mut data = BuilderData::new();
        data.append_u64(0).unwrap();
        let si = StateInit::with_code_and_data(code, data.into_cell().unwrap());
        let addr_hash = si.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
        let addr = MsgAddressInt::with_params(0, addr_hash).unwrap();
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

    fn call(&self, method: &str, args: &[[u8; 32]]) -> Result<Vec<String>, i32> {
        let stack: Vec<StackItem> = args
            .iter()
            .map(|value| {
                StackItem::integer(
                    IntegerData::from_str_radix(&dec(value), 10).expect("argument as integer"),
                )
            })
            .collect();
        let result = self
            .bc
            .run_get_method(&self.addr, method, stack)
            .unwrap_or_else(|e| panic!("{method}: {e}"));
        if result.exit_code != 0 {
            return Err(result.exit_code);
        }
        Ok(result
            .stack
            .iter()
            .map(|item| {
                item.as_integer().unwrap_or_else(|_| panic!("{method}: non-integer")).to_string()
            })
            .collect())
    }
}

#[test]
fn a_func_wrapper_reaches_the_instruction_with_the_arguments_in_the_right_order() {
    let probe = Probe::deploy(ACTIVE_VERSION);
    let fields = inputs();

    // The bare instruction first: if this is wrong, nothing else here means anything.
    let mut args = vec![domain_of("COMMIT-NODE")];
    args.extend_from_slice(&fields);
    let raw = probe.call("raw_h7", &args).expect("raw_h7 ran");
    let expected = dec(&reference_h7(&domain_of("COMMIT-NODE"), &fields));
    assert_eq!(raw.last().unwrap(), &expected, "the bare instruction disagrees with the reference");
    assert!(expected.len() > 8, "the value looks truncated; the comparison proved nothing");

    // Argument order is load-bearing: two inputs swapped must change the answer.
    let mut swapped = args.clone();
    swapped.swap(1, 2);
    let other = probe.call("raw_h7", &swapped).expect("raw_h7 ran");
    assert_ne!(other.last().unwrap(), &expected, "swapping two arguments changed nothing");

    // And so is the permutation's output order.
    let mut state = [[0u8; 32]; 8];
    state[0] = domain_of("COMMIT-NODE");
    state[1..].copy_from_slice(&fields);
    let lanes = probe.call("raw_perm8", &state).expect("raw_perm8 ran");
    let reference = permute(&state);
    assert_eq!(lanes.len(), 8, "PERM8 did not return eight values");
    for (lane, value) in lanes.iter().enumerate() {
        assert_eq!(value, &dec(&reference[lane]), "PERM8 lane {lane} came back in the wrong place");
    }
    assert_eq!(lanes[0], expected, "HASH7 is not lane 0 of PERM8 as seen from FunC");
}

#[test]
fn each_structure_carries_its_own_domain_constant() {
    let probe = Probe::deploy(ACTIVE_VERSION);
    let fields = inputs();
    let mut seen: Vec<(String, String)> = Vec::new();

    for (method, label) in STRUCTURES {
        let produced = probe.call(method, &fields).expect("wrapper ran");
        let expected = dec(&reference_h7(&domain_of(label), &fields));
        assert_eq!(
            produced.last().unwrap(),
            &expected,
            "{method}: the constant compiled into the contract is not the {label} domain"
        );
        seen.push((method.to_string(), expected));
    }

    // The domains must actually separate the structures: the same seven inputs
    // under two labels must not collide, or the separation is decorative.
    for (index, (name, value)) in seen.iter().enumerate() {
        for (other_name, other_value) in seen.iter().skip(index + 1) {
            assert_ne!(value, other_value, "{name} and {other_name} agree on the same inputs");
        }
    }
}

#[test]
fn the_instruction_is_not_reachable_from_func_before_its_version() {
    let probe = Probe::deploy(POSEIDON2_MIN_VERSION - 1);
    let fields = inputs();
    let mut args = vec![domain_of("COMMIT-NODE")];
    args.extend_from_slice(&fields);
    let exit =
        probe.call("raw_h7", &args).expect_err("the instruction must not exist at version 16");
    assert_eq!(exit, 6, "expected an invalid-opcode exit, got {exit}");
}
