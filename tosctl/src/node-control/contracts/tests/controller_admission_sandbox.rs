/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! What the frozen controller admission check costs, measured on the check itself.
//!
//! The elector will admit a first stake by proving one fact about its sender: that the
//! account was deployed with a controller code the configuration admits. The check is
//! four steps — the proof's shape, the address it reconstructs, the code hash its pruned
//! branch carries, and the policy lookup — and this file implements exactly those four
//! and measures them, so the carrier and the gas the design was sized against are numbers
//! rather than estimates before the contracts that will carry them exist.
//!
//! Nothing here is the production path. It is the frozen check, run in isolation, to find
//! out what it costs.

use chain_block::{Cell, GetRepresentationHash, MsgAddressInt, Serializable, StateInit};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func_with_stdlib};
use tos_vm::stack::{StackItem, integer::IntegerData};

const TOS: u64 = 1_000_000_000;

/// The refusal reasons the frozen gate list names, each reachable on its own.
const ERROR_PROOF_SHAPE: i32 = 80;
const ERROR_ADDRESS_MISMATCH: i32 = 81;
const ERROR_CODE_NOT_ADMITTED: i32 = 82;
const ERROR_POLICY_ABSENT: i32 = 83;

fn repo_root() -> std::path::PathBuf {
    std::env::var("TOS_ROOT").map(std::path::PathBuf::from).unwrap_or_else(|_| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(4)
            .expect("repository root")
            .to_path_buf()
    })
}

fn probe_code() -> Cell {
    let probe = std::env::temp_dir().join("tos_controller_admission_probe.fc");
    std::fs::write(
        &probe,
        r#"
const int ctl::error::proof_shape = 80;
const int ctl::error::address_mismatch = 81;
const int ctl::error::code_not_admitted = 82;
const int ctl::error::policy_absent = 83;

;; The four steps the design freezes, in the order it freezes them, taken from the
;; library the elector uses rather than from a copy of it.
int probe_admit(cell proof, int expected_address, cell policy) method_id {
  (int code_hash, int status) = pq::controller_code_hash?(proof, expected_address);
  throw_if(ctl::error::proof_shape, status == pq::proof::bad_shape);
  throw_if(ctl::error::address_mismatch, status == pq::proof::bad_address);
  throw_if(ctl::error::policy_absent, cell_null?(policy));
  throw_unless(ctl::error::code_not_admitted, pq::controller_admitted?(policy, code_hash));
  return code_hash;
}
() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure {
}
"#,
    )
    .expect("probe source");
    compile_func_with_stdlib(&[
        repo_root().join("crypto/smartcont/pq-bytes.fc"),
        repo_root().join("crypto/smartcont/pq-validator.fc"),
        probe,
    ])
    .expect("the probe compiles")
}

fn deploy(chain: &mut Blockchain) -> MsgAddressInt {
    let state = StateInit::with_code_and_data(probe_code(), Cell::default());
    let address = MsgAddressInt::with_params(
        -1,
        state.write_to_new_cell().expect("state").into_cell().expect("state cell").hash(0),
    )
    .expect("address");
    let deployer = chain.treasury("controller-admission-funder", 1_000 * TOS).expect("funding");
    chain
        .send_message(
            MessageBuilder::internal(deployer.address(), &address, 100 * TOS)
                .bounce(false)
                .state_init(state)
                .body(Cell::default())
                .build(),
        )
        .expect("deployment")
        .expect_success();
    address
}

fn pruned_branch(hash: &chain_block::UInt256, depth: u16) -> Cell {
    use chain_block::IBitstring;
    let mut branch = chain_block::BuilderData::new();
    branch.set_type(chain_block::CellType::PrunedBranch);
    branch.append_u8(u8::from(chain_block::CellType::PrunedBranch)).expect("the type byte");
    branch.append_u8(1).expect("one stored hash, at merkle depth zero");
    branch.append_raw(hash.as_slice(), 256).expect("the pruned hash");
    branch.append_u16(depth).expect("the pruned depth");
    branch.into_cell().expect("a pruned branch")
}

fn prune_children(root: &Cell) -> Cell {
    let mut partial = chain_block::BuilderData::with_raw(root.data().to_vec(), root.bit_length())
        .expect("the root's own bits");
    for index in 0..root.references_count() {
        let child = root.reference(index).expect("a child");
        partial
            .checked_append_reference(pruned_branch(&child.repr_hash(), child.repr_depth()))
            .expect("a pruned child");
    }
    partial.into_cell().expect("a partial tree")
}

/// A controller-sized account: code of a few kilobytes, and data holding a root key.
fn controller_state_init(code_seed: u8) -> Cell {
    use chain_block::IBitstring;
    // A code cell chain in the shape a compiled contract has, so the pruned proof is
    // measured against something the size of a real controller rather than a stub.
    let mut chain: Option<Cell> = None;
    for index in (0..24u8).rev() {
        let mut cell = chain_block::BuilderData::new();
        cell.append_raw(&vec![code_seed ^ index; 127], 1016).expect("code bytes");
        if let Some(next) = chain.take() {
            cell.checked_append_reference(next).expect("the continuation");
        }
        chain = Some(cell.into_cell().expect("a code cell"));
    }

    let mut key = chain_block::BuilderData::new();
    key.append_raw(&vec![0x5a; 96], 768).expect("a root key stand-in");
    let mut data = chain_block::BuilderData::new();
    data.append_u64(7).expect("epoch");
    data.append_u64(3).expect("nonce");
    data.checked_append_reference(key.into_cell().expect("key cell")).expect("root key");

    StateInit::with_code_and_data(chain.expect("code"), data.into_cell().expect("data cell"))
        .write_to_new_cell()
        .expect("state init")
        .into_cell()
        .expect("state init cell")
}

/// Every distinct cell in a tree, and the bits they hold.
fn tree_size(root: &Cell) -> (usize, usize) {
    fn walk(
        cell: &Cell,
        seen: &mut std::collections::HashSet<chain_block::UInt256>,
        bits: &mut usize,
    ) {
        if !seen.insert(cell.repr_hash()) {
            return;
        }
        *bits += cell.bit_length();
        for index in 0..cell.references_count() {
            walk(&cell.reference(index).expect("a reference"), seen, bits);
        }
    }
    let mut seen = std::collections::HashSet::new();
    let mut bits = 0;
    walk(root, &mut seen, &mut bits);
    (seen.len(), bits)
}

/// The configuration's admitted controller codes, at the frozen bound of eight.
fn policy(admitted: &[chain_block::UInt256]) -> StackItem {
    let mut dict = chain_block::HashmapE::with_bit_len(256);
    for code in admitted {
        dict.set(
            chain_block::SliceData::load_builder(
                chain_block::BuilderData::with_raw(code.as_slice().to_vec(), 256).expect("a key"),
            )
            .expect("a key slice"),
            &chain_block::SliceData::default(),
        )
        .expect("insert");
    }
    match chain_block::HashmapType::data(&dict) {
        Some(root) => StackItem::Cell(root.clone()),
        None => StackItem::None,
    }
}

fn admit(
    chain: &Blockchain,
    probe: &MsgAddressInt,
    proof: Cell,
    address: &chain_block::UInt256,
    policy: StackItem,
) -> (i32, i64) {
    let result = chain
        .run_get_method_with_gas(
            probe,
            "probe_admit",
            vec![
                StackItem::Cell(proof),
                StackItem::integer(IntegerData::from_unsigned_bytes_be(address.as_slice())),
                policy,
            ],
            1_000_000_000,
        )
        .expect("the probe answers");
    (result.exit_code, result.gas_used)
}

/// What the admission check costs, and what the proof adds to a request.
#[test]
fn the_admission_check_is_measured_on_the_check_itself() {
    let mut chain = Blockchain::with_global_version(16).expect("a chain");
    chain.set_workchain(-1);
    let probe = deploy(&mut chain);

    let state_init = controller_state_init(0xa1);
    let address = state_init.repr_hash();
    let proof = prune_children(&state_init);
    let code_hash = state_init.reference(0).expect("code").repr_hash();

    let (whole_cells, whole_bits) = tree_size(&state_init);
    let (proof_cells, proof_bits) = tree_size(&proof);

    // Eight admitted codes, the frozen bound, with the real one placed last so the lookup
    // is not measured on the cheapest possible dictionary.
    let mut admitted: Vec<chain_block::UInt256> =
        (0u8..7).map(|seed| chain_block::UInt256::from_slice(&[seed; 32])).collect();
    admitted.push(code_hash);

    let (exit, gas) = admit(&chain, &probe, proof.clone(), &address, policy(&admitted));
    assert_eq!(exit, 0, "the frozen check refused a proof it must admit");

    eprintln!(
        "controller state init: {whole_cells} cells, {whole_bits} bits\n\
         proof carried:         {proof_cells} cells, {proof_bits} bits\n\
         admission check:       {gas} gas"
    );

    // The proof must not grow with the controller it proves. That is the whole reason it
    // is pruned, and the reason the carrier can be sized once.
    let bigger = controller_state_init(0xc3);
    let bigger_proof = prune_children(&bigger);
    assert_eq!(
        tree_size(&bigger_proof),
        (proof_cells, proof_bits),
        "the proof's size depends on the account it proves"
    );
    assert!(
        proof_cells < whole_cells,
        "the proof is not smaller than the state init it stands for"
    );
}

/// What the proof adds to a stake request, measured on the carrier the design freezes.
///
/// The branch asserts elsewhere that a stake request is 34 cells and 30352 bits. That
/// figure stops being the wire freeze at N3.3A, because a first registration now carries
/// the proof as well, and this is the number that replaces it.
#[test]
fn the_first_stake_carrier_is_measured_with_its_proof() {
    use chain_block::IBitstring;

    let state_init = controller_state_init(0xa1);
    let proof = prune_children(&state_init);

    // The same shape the elector reads today, plus the proof the frozen carrier adds.
    let stored = |bytes: &[u8]| -> Cell {
        chain_block::pq_bytes::pack_pq_bytes(bytes, chain_block::pq_bytes::PQ_BYTES_HARD_MAX)
            .expect("bytes of admitted length")
    };
    let mut body = chain_block::BuilderData::new();
    body.append_u32(0x5051_7374).expect("operation");
    body.append_u64(1).expect("query id");
    body.append_u16(1).expect("algorithm");
    body.checked_append_reference(stored(&vec![0xa7; 1312])).expect("public key");
    body.append_u32(1_789_434_000).expect("election");
    body.append_u32(0x10000).expect("max factor");
    body.append_raw(&[0xd0; 32], 256).expect("adnl address");
    body.checked_append_reference(stored(&vec![0u8; 2420])).expect("signature");
    let mut bare = body.clone();
    bare.append_bit_zero().expect("no controller proof");
    let without = bare.into_cell().expect("a stake body");
    body.append_bit_one().expect("a proof is present");
    body.checked_append_reference(proof.clone()).expect("the controller proof");
    let with = body.into_cell().expect("a first-stake body");

    let (bare_cells, bare_bits) = tree_size(&without);
    let (full_cells, full_bits) = tree_size(&with);
    let (proof_cells, proof_bits) = tree_size(&proof);

    eprintln!(
        "stake request without proof: {bare_cells} cells, {bare_bits} bits\n\
         first stake with proof:      {full_cells} cells, {full_bits} bits\n\
         the proof alone:             {proof_cells} cells, {proof_bits} bits"
    );

    assert_eq!(
        (bare_cells, bare_bits),
        (34, 30_353),
        "the request this measures is no longer the one the branch asserts elsewhere"
    );
    assert_eq!((full_cells, full_bits), (37, 30_934), "the first-stake carrier changed shape");
}

/// Each refusal the frozen gate list names, reached on its own and costing little.
#[test]
fn each_refusal_is_reachable_and_cheap() {
    use chain_block::IBitstring;
    let mut chain = Blockchain::with_global_version(16).expect("a chain");
    chain.set_workchain(-1);
    let probe = deploy(&mut chain);

    let state_init = controller_state_init(0xa1);
    let address = state_init.repr_hash();
    let proof = prune_children(&state_init);
    let code_hash = state_init.reference(0).expect("code").repr_hash();
    let admitted = vec![code_hash];

    // A well-formed proof of an account whose code nothing admits.
    let other = controller_state_init(0xc3);
    let (exit, unadmitted_gas) =
        admit(&chain, &probe, prune_children(&other), &other.repr_hash(), policy(&admitted));
    assert_eq!(exit, ERROR_CODE_NOT_ADMITTED, "an unadmitted code was admitted");

    // The same proof presented for somebody else's address.
    let (exit, _) = admit(&chain, &probe, proof.clone(), &other.repr_hash(), policy(&admitted));
    assert_eq!(exit, ERROR_ADDRESS_MISMATCH, "a proof was accepted for another address");

    // No policy at all: fail closed.
    let (exit, _) = admit(&chain, &probe, proof.clone(), &address, StackItem::None);
    assert_eq!(exit, ERROR_POLICY_ABSENT, "admission succeeded with no policy installed");

    // A child that is an ordinary cell rather than a pruned branch: the shape is wrong
    // even though the hashes could be made to agree.
    let mut unpruned =
        chain_block::BuilderData::with_raw(state_init.data().to_vec(), state_init.bit_length())
            .expect("the root's own bits");
    unpruned
        .checked_append_reference(state_init.reference(0).expect("code"))
        .expect("an unpruned code");
    unpruned
        .checked_append_reference(pruned_branch(
            &state_init.reference(1).expect("data").repr_hash(),
            state_init.reference(1).expect("data").repr_depth(),
        ))
        .expect("a pruned data branch");
    let (exit, _) = admit(
        &chain,
        &probe,
        unpruned.into_cell().expect("a mixed tree"),
        &address,
        policy(&admitted),
    );
    assert_eq!(exit, ERROR_PROOF_SHAPE, "a proof carrying a whole subtree was accepted");

    // Each rule about the proof's shape needs an input only it refuses, or removing it
    // changes no verdict and the rule is held by its neighbours rather than by a test.
    let branches = |bits: usize, value: u8, refs: usize| -> Cell {
        let mut root = chain_block::BuilderData::new();
        root.append_bits(value as usize, bits).expect("the shape bits");
        for index in 0..refs {
            let child = state_init.reference(index.min(1)).expect("a child");
            root.checked_append_reference(pruned_branch(&child.repr_hash(), child.repr_depth()))
                .expect("a pruned child");
        }
        root.into_cell().expect("a shaped root")
    };

    // Two references and the right tag, but a bit too many: only the bit count refuses it.
    let (exit, _) = admit(&chain, &probe, branches(6, 0b001100, 2), &address, policy(&admitted));
    assert_eq!(exit, ERROR_PROOF_SHAPE, "a root with the wrong bit count was accepted");

    // The right bits, one reference short: only the reference count refuses it.
    let (exit, _) = admit(&chain, &probe, branches(5, 0b00110, 1), &address, policy(&admitted));
    assert_eq!(exit, ERROR_PROOF_SHAPE, "a root missing a child was accepted");

    // The right size, the wrong tag: a state init that says it carries no code.
    let (exit, _) = admit(&chain, &probe, branches(5, 0b00000, 2), &address, policy(&admitted));
    assert_eq!(exit, ERROR_PROOF_SHAPE, "a root claiming no code was accepted");

    // A root that is not a state init shape at all.
    let mut nonsense = chain_block::BuilderData::new();
    nonsense.append_raw(&[0xff; 4], 32).expect("bits");
    let (exit, _) =
        admit(&chain, &probe, nonsense.into_cell().expect("nonsense"), &address, policy(&admitted));
    assert_eq!(exit, ERROR_PROOF_SHAPE, "a cell that is not a state init was accepted");

    eprintln!("unadmitted code refused at {unadmitted_gas} gas");
}
