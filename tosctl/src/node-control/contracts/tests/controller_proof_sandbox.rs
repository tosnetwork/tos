/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! The first gate of N3.3A: can a contract recover an account's address from a proof of
//! its state init with both children pruned?
//!
//! The validator controller design rests on this. An account can only be initialized with
//! a state init whose hash is its address, so a caller presenting one has proved what the
//! account was deployed as. Presenting the whole state init would mean carrying the
//! controller's code in every first stake, so the design carries a partial tree instead:
//! the root's own bits, and a pruned branch in place of each child.
//!
//! That works only if the virtual machine computes the level-zero hash, which is the one
//! the pruned branches carry. `cell_hash` does not: it is `HASHCU`, the highest-level
//! hash, and a tree holding pruned branches has a level above zero. The design is written
//! on `CHASHI 0`, and this file shows both halves of that claim rather than the
//! convenient one alone.

use chain_block::{Cell, GetRepresentationHash, MsgAddressInt, Serializable, StateInit};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func_with_stdlib};
use tos_vm::stack::{StackItem, integer::IntegerData};

const TOS: u64 = 1_000_000_000;

fn repo_root() -> std::path::PathBuf {
    std::env::var("TOS_ROOT").map(std::path::PathBuf::from).unwrap_or_else(|_| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(4)
            .expect("repository root")
            .to_path_buf()
    })
}

/// Both hashes of the same cell, so the two can be compared on identical input.
fn probe_code() -> Cell {
    let probe = std::env::temp_dir().join("tos_controller_proof_probe.fc");
    std::fs::write(
        &probe,
        r#"
int level_zero_hash(cell c) asm "0 CHASHI";

int probe_level_zero_hash(cell c) method_id {
  return level_zero_hash(c);
}
int probe_cell_hash(cell c) method_id {
  return cell_hash(c);
}
() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure {
}
"#,
    )
    .expect("probe source");
    let _ = repo_root();
    compile_func_with_stdlib(&[probe]).expect("the probe compiles")
}

fn deploy(chain: &mut Blockchain) -> MsgAddressInt {
    let state = StateInit::with_code_and_data(probe_code(), Cell::default());
    let address = MsgAddressInt::with_params(
        -1,
        state.write_to_new_cell().expect("state").into_cell().expect("state cell").hash(0),
    )
    .expect("address");
    let deployer = chain.treasury("controller-proof-funder", 1_000 * TOS).expect("funding");
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

/// A pruned branch standing in for a child: it carries that child's level-zero hash and
/// depth and nothing else. Its own level is one, which is what makes the parent's
/// highest-level hash differ from the original's.
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

/// The same tree with every child replaced by a pruned branch.
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

/// A state init shaped like a real one: code with a child of its own, and data.
fn state_init_of(code_seed: u8, data_seed: u8) -> Cell {
    use chain_block::IBitstring;
    let mut inner = chain_block::BuilderData::new();
    inner.append_raw(&vec![code_seed ^ 0xff; 96], 768).expect("more code");
    let mut code = chain_block::BuilderData::new();
    code.append_raw(&vec![code_seed; 64], 512).expect("code bits");
    code.checked_append_reference(inner.into_cell().expect("a code child")).expect("code child");

    let mut data = chain_block::BuilderData::new();
    data.append_u64(7).expect("epoch");
    data.append_u64(3).expect("nonce");
    data.append_raw(&vec![data_seed; 32], 256).expect("a root key stand-in");

    StateInit::with_code_and_data(
        code.into_cell().expect("code cell"),
        data.into_cell().expect("data cell"),
    )
    .write_to_new_cell()
    .expect("state init")
    .into_cell()
    .expect("state init cell")
}

fn hash_of(chain: &Blockchain, probe: &MsgAddressInt, method: &str, cell: Cell) -> String {
    let result = chain
        .run_get_method(probe, method, vec![StackItem::Cell(cell)])
        .expect("the probe answers");
    assert_eq!(result.exit_code, 0, "{method} failed");
    result.stack.last().expect("a hash").as_integer().expect("an integer").to_string()
}

fn as_integer(hash: &chain_block::UInt256) -> String {
    IntegerData::from_unsigned_bytes_be(hash.as_slice()).to_string()
}

/// The claim the design is written on, and the claim it is written against.
#[test]
fn a_pruned_state_init_recovers_its_address_only_at_level_zero() {
    let mut chain = Blockchain::with_global_version(16).expect("a chain");
    chain.set_workchain(-1);
    let probe = deploy(&mut chain);

    let state_init = state_init_of(0xa1, 0xb2);
    let address = state_init.repr_hash();
    let partial = prune_children(&state_init);

    // A fixture only proves something if the proof is smaller than what it proves.
    assert!(
        partial.repr_depth() < state_init.repr_depth(),
        "the partial tree is as deep as the original, so nothing was pruned"
    );

    assert_eq!(
        hash_of(&chain, &probe, "probe_level_zero_hash", partial.clone()),
        as_integer(&address),
        "the level-zero hash of the pruned tree is not the address it has to prove"
    );

    assert_ne!(
        hash_of(&chain, &probe, "probe_cell_hash", partial),
        as_integer(&address),
        "cell_hash recovered the address, so the design's reason for specifying CHASHI 0 is \
         wrong and the two are interchangeable here"
    );

    // On the unpruned original the two agree, which is why the distinction is easy to miss
    // until a proof is involved.
    assert_eq!(
        hash_of(&chain, &probe, "probe_cell_hash", state_init.clone()),
        as_integer(&address),
        "the original tree does not hash to its own address"
    );
    assert_eq!(
        hash_of(&chain, &probe, "probe_level_zero_hash", state_init),
        as_integer(&address),
        "the original tree's level-zero hash is not its address"
    );
}

/// Substituting either child's commitment has to change the address the proof recovers.
#[test]
fn a_substituted_branch_does_not_recover_the_address() {
    let mut chain = Blockchain::with_global_version(16).expect("a chain");
    chain.set_workchain(-1);
    let probe = deploy(&mut chain);

    let state_init = state_init_of(0xa1, 0xb2);
    let address = as_integer(&state_init.repr_hash());
    let other = state_init_of(0xc3, 0xd4);

    for (index, what) in [(0usize, "code"), (1usize, "data")] {
        let mut forged =
            chain_block::BuilderData::with_raw(state_init.data().to_vec(), state_init.bit_length())
                .expect("the root's own bits");
        for position in 0..state_init.references_count() {
            let source = if position == index { &other } else { &state_init };
            let child = source.reference(position).expect("a child");
            forged
                .checked_append_reference(pruned_branch(&child.repr_hash(), child.repr_depth()))
                .expect("a pruned child");
        }
        let forged = forged.into_cell().expect("a forged partial tree");
        assert_ne!(
            hash_of(&chain, &probe, "probe_level_zero_hash", forged),
            address,
            "a proof carrying another account's {what} recovered this account's address"
        );
    }
}
