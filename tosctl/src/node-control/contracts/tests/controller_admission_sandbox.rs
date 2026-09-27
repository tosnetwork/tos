/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! What the frozen controller admission check costs, measured on the check itself.
//!
//! The elector will admit a first stake by proving one fact about its sender: that the
//! account was deployed with a controller code the configuration admits. The sender
//! carries four numbers — the hash and depth of its code and of its data — and the check
//! rebuilds the state init from them, requires the result to be the sender's address, and
//! looks the proven code hash up in the policy. This file implements exactly that and
//! measures it, so the carrier and the gas are numbers rather than estimates.
//!
//! Nothing here is the production path. It is the frozen check, run in isolation, to find
//! out what it costs.

use chain_block::{Cell, GetRepresentationHash, MsgAddressInt, Serializable, StateInit};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func_with_stdlib};
use tos_vm::stack::{StackItem, integer::IntegerData};

const TOS: u64 = 1_000_000_000;

/// The refusal reasons the frozen gate list names, each reachable on its own.
const ERROR_WITNESS_SHAPE: i32 = 80;
/// The machine's own refusal to read a cell whose content was pruned away.
const ERROR_PRUNED_CELL_ACCESS: i32 = 15;
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
    let probe = std::env::temp_dir().join(format!(
        "tos_controller_admission_probe-{}-{:?}.fc",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(
        &probe,
        r#"
const int ctl::error::proof_shape = 80;
const int ctl::error::address_mismatch = 81;
const int ctl::error::code_not_admitted = 82;
const int ctl::error::policy_absent = 83;

;; The four steps the design freezes, in the order it freezes them, taken from the
;; library the elector uses rather than from a copy of it.
int probe_admit(cell witness, int expected_address, cell policy) method_id {
  (int code_hash, int status) = pq::controller_code_hash?(witness, expected_address);
  throw_if(ctl::error::proof_shape, status == pq::witness::bad_shape);
  throw_if(ctl::error::address_mismatch, status == pq::witness::bad_address);
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

/// `controller_birth_witness_v1`: the hash and depth of each child of a state init, in
/// the order the state init holds them.
fn birth_witness(root: &Cell) -> Cell {
    witness_of(
        &root.reference(0).expect("code").repr_hash(),
        root.reference(0).expect("code").repr_depth(),
        &root.reference(1).expect("data").repr_hash(),
        root.reference(1).expect("data").repr_depth(),
    )
}

fn witness_of(
    code_hash: &chain_block::UInt256,
    code_depth: u16,
    data_hash: &chain_block::UInt256,
    data_depth: u16,
) -> Cell {
    use chain_block::IBitstring;
    let mut witness = chain_block::BuilderData::new();
    witness.append_raw(code_hash.as_slice(), 256).expect("the code hash");
    witness.append_u16(code_depth).expect("the code depth");
    witness.append_raw(data_hash.as_slice(), 256).expect("the data hash");
    witness.append_u16(data_depth).expect("the data depth");
    witness.into_cell().expect("a birth witness")
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
    let proof = birth_witness(&state_init);
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
    let bigger_proof = birth_witness(&bigger);
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
/// figure stops being the original wire freeze, because a first registration now carries
/// the proof as well, and this is the number that replaces it.
#[test]
fn the_first_stake_carrier_is_measured_with_its_proof() {
    use chain_block::IBitstring;

    let state_init = controller_state_init(0xa1);
    let proof = birth_witness(&state_init);

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
    assert_eq!((full_cells, full_bits), (35, 30_897), "the first-stake carrier changed shape");
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
    let proof = birth_witness(&state_init);
    let code_hash = state_init.reference(0).expect("code").repr_hash();
    let admitted = vec![code_hash];

    // A well-formed proof of an account whose code nothing admits.
    let other = controller_state_init(0xc3);
    let (exit, unadmitted_gas) =
        admit(&chain, &probe, birth_witness(&other), &other.repr_hash(), policy(&admitted));
    assert_eq!(exit, ERROR_CODE_NOT_ADMITTED, "an unadmitted code was admitted");

    // The same proof presented for somebody else's address.
    let (exit, _) = admit(&chain, &probe, proof.clone(), &other.repr_hash(), policy(&admitted));
    assert_eq!(exit, ERROR_ADDRESS_MISMATCH, "a proof was accepted for another address");

    // No policy at all: fail closed.
    let (exit, _) = admit(&chain, &probe, proof.clone(), &address, StackItem::None);
    assert_eq!(exit, ERROR_POLICY_ABSENT, "admission succeeded with no policy installed");

    // A child that is an ordinary cell rather than a pruned branch: the shape is wrong
    // even though the hashes could be made to agree.
    // Each rule about the witness needs an input only it refuses, or removing the rule
    // changes no verdict and it is held by its neighbours rather than by a test.
    let code = state_init.reference(0).expect("code");
    let data = state_init.reference(1).expect("data");

    // A sender trying to supply a branch rather than the numbers to rebuild one. The
    // virtual machine refuses before the contract does: a pruned cell's content is absent
    // by definition, so reading one is its own error and the shape rule below never sees
    // it. Recorded because it is the refusal an operator would actually meet.
    let mut pruned = chain_block::BuilderData::new();
    pruned.set_type(chain_block::CellType::PrunedBranch);
    pruned.append_u8(u8::from(chain_block::CellType::PrunedBranch)).expect("the type byte");
    pruned.append_u8(1).expect("one level");
    pruned.append_raw(code.repr_hash().as_slice(), 256).expect("a hash");
    pruned.append_u16(code.repr_depth()).expect("a depth");
    let (exit, _) = admit(
        &chain,
        &probe,
        pruned.into_cell().expect("a pruned witness"),
        &address,
        policy(&admitted),
    );
    assert_eq!(exit, ERROR_PRUNED_CELL_ACCESS, "a pruned witness was read rather than refused");

    // An exotic cell the machine will let the contract look at, so the contract's own
    // rule is the one that answers. Without this the rule would be held by the machine
    // and removing it would change no verdict.
    let mut library = chain_block::BuilderData::new();
    library.set_type(chain_block::CellType::LibraryReference);
    library.append_u8(u8::from(chain_block::CellType::LibraryReference)).expect("the type byte");
    library.append_raw(code.repr_hash().as_slice(), 256).expect("the library hash");
    let (exit, _) = admit(
        &chain,
        &probe,
        library.into_cell().expect("a library witness"),
        &address,
        policy(&admitted),
    );
    assert_eq!(exit, ERROR_WITNESS_SHAPE, "an exotic witness was accepted");

    // One bit too few and one too many: only the bit count refuses either.
    for bits in [543usize, 545] {
        let mut wrong = chain_block::BuilderData::new();
        while wrong.length_in_bits() + 64 <= bits {
            wrong.append_u64(0).expect("sixty-four bits");
        }
        while wrong.length_in_bits() < bits {
            wrong.append_bit_zero().expect("a bit");
        }
        assert_eq!(wrong.length_in_bits(), bits, "the fixture did not build what it meant to");
        let (exit, _) = admit(
            &chain,
            &probe,
            wrong.into_cell().expect("a witness of the wrong length"),
            &address,
            policy(&admitted),
        );
        assert_eq!(exit, ERROR_WITNESS_SHAPE, "a witness of {bits} bits was accepted");
    }

    // The right 544 bits, carrying a reference it has no business carrying.
    let mut with_child =
        chain_block::BuilderData::with_raw(birth_witness(&state_init).data().to_vec(), 544)
            .expect("the witness bits");
    with_child.checked_append_reference(Cell::default()).expect("a stray reference");
    let (exit, _) = admit(
        &chain,
        &probe,
        with_child.into_cell().expect("a witness with a child"),
        &address,
        policy(&admitted),
    );
    assert_eq!(exit, ERROR_WITNESS_SHAPE, "a witness carrying a reference was accepted");

    // A depth the state-init root could not be built over. Refused before anything is
    // built, so the request is answered rather than thrown over.
    let (exit, _) = admit(
        &chain,
        &probe,
        witness_of(&code.repr_hash(), 1024, &data.repr_hash(), data.repr_depth()),
        &address,
        policy(&admitted),
    );
    assert_eq!(exit, ERROR_WITNESS_SHAPE, "a code depth past the ceiling was accepted");
    let (exit, _) = admit(
        &chain,
        &probe,
        witness_of(&code.repr_hash(), code.repr_depth(), &data.repr_hash(), 1024),
        &address,
        policy(&admitted),
    );
    assert_eq!(exit, ERROR_WITNESS_SHAPE, "a data depth past the ceiling was accepted");

    // Every field, mutated one at a time and within its bounds, so each reaches the
    // address binding and is refused there rather than for its shape.
    let flipped = |hash: &chain_block::UInt256| {
        let mut bytes = hash.as_slice().to_vec();
        bytes[31] ^= 1;
        chain_block::UInt256::from_slice(&bytes)
    };
    for (what, witness) in [
        (
            "the code hash",
            witness_of(
                &flipped(&code.repr_hash()),
                code.repr_depth(),
                &data.repr_hash(),
                data.repr_depth(),
            ),
        ),
        (
            "the code depth",
            witness_of(
                &code.repr_hash(),
                code.repr_depth() + 1,
                &data.repr_hash(),
                data.repr_depth(),
            ),
        ),
        (
            "the data hash",
            witness_of(
                &code.repr_hash(),
                code.repr_depth(),
                &flipped(&data.repr_hash()),
                data.repr_depth(),
            ),
        ),
        (
            "the data depth",
            witness_of(
                &code.repr_hash(),
                code.repr_depth(),
                &data.repr_hash(),
                data.repr_depth() + 1,
            ),
        ),
        (
            "the two halves swapped",
            witness_of(&data.repr_hash(), data.repr_depth(), &code.repr_hash(), code.repr_depth()),
        ),
    ] {
        let (exit, _) = admit(&chain, &probe, witness, &address, policy(&admitted));
        assert_eq!(exit, ERROR_ADDRESS_MISMATCH, "a witness with {what} changed was accepted");
    }

    eprintln!("unadmitted code refused at {unadmitted_gas} gas");
}
