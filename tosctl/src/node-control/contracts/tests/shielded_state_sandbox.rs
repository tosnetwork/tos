/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Section 13 of the V1 implementation profile: the persistent state root, the
//! config store and the verifying-key chain, with the genesis state of 13.2.
//!
//! There is no admin key and no upgrade path in this design, so anything that
//! reaches persistent state is there for good. That is why the shape is checked
//! on the way in as well as on the way out, and why the immutable config is
//! re-validated on every parse rather than trusted because genesis wrote it: a
//! state cell can be handed to this code by anything that can build a cell.

use chain_block::{BuilderData, Cell, IBitstring, MsgAddressInt, Serializable, StateInit};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func_with_stdlib};
use tos_vm::stack::StackItem;
use tos_vm::stack::integer::IntegerData;

mod shielded_pool_library;

const TOS: u64 = 1_000_000_000;
const ACTIVE_VERSION: u32 = 18;
const MAGIC: u32 = 0x5350_5631;
const VERSION: u16 = 1;
const INDEX_SENTINEL: u64 = 1 << 32;
const EPOCH_NONE: u32 = 0xffff_ffff;
const VK_BYTES: usize = 1248;

type Field = [u8; 32];

fn dec(bytes: &Field) -> String {
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

fn field(seed: u8) -> Field {
    [seed; 32]
}

/// Coins are a VarUInteger 16: four bits of byte length, then the bytes.
fn store_coins(builder: &mut BuilderData, amount: u128) {
    let bytes = amount.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    let length = bytes.len() - first;
    builder.append_bits(length, 4).expect("coin length");
    if length > 0 {
        builder.append_raw(&bytes[first..], length * 8).expect("coin bytes");
    }
}

fn denomination_chain(amounts: &[u128]) -> Cell {
    let mut chain: Option<Cell> = None;
    for amount in amounts.iter().rev() {
        let mut builder = BuilderData::new();
        store_coins(&mut builder, *amount);
        if let Some(next) = chain {
            builder.checked_append_reference(next).expect("chain reference");
        }
        chain = Some(builder.into_cell().expect("a denomination node"));
    }
    chain.expect("at least one denomination")
}

struct Config {
    profile_hash: Field,
    poseidon_hash: Field,
    vk_hash: Field,
    withdrawal_fee: u128,
    denominations: Vec<u128>,
}

impl Config {
    fn sample() -> Self {
        Config {
            profile_hash: field(0x11),
            poseidon_hash: field(0x22),
            vk_hash: field(0x33),
            withdrawal_fee: 50_000_000,
            denominations: vec![TOS as u128, 10 * TOS as u128, 100 * TOS as u128],
        }
    }

    fn cell(&self) -> Cell {
        self.cell_with_count(self.denominations.len() as u8)
    }

    fn cell_with_count(&self, count: u8) -> Cell {
        let mut builder = BuilderData::new();
        builder.append_raw(&self.profile_hash, 256).expect("profile hash");
        builder.append_raw(&self.poseidon_hash, 256).expect("poseidon hash");
        builder.append_raw(&self.vk_hash, 256).expect("vk hash");
        store_coins(&mut builder, self.withdrawal_fee);
        builder.append_u8(count).expect("count");
        builder
            .checked_append_reference(denomination_chain(&self.denominations))
            .expect("denominations");
        builder.into_cell().expect("a config store")
    }
}

/// The canonical verifying-key chain: nine full cells and a 105-byte tail.
fn vk_chain() -> Cell {
    vk_chain_of(&(0..VK_BYTES).map(|i| (i % 251) as u8).collect::<Vec<u8>>(), 127, 105)
}

fn vk_chain_of(bytes: &[u8], chunk: usize, tail: usize) -> Cell {
    let mut cells: Vec<&[u8]> = Vec::new();
    let mut offset = 0;
    while offset + chunk <= bytes.len().saturating_sub(tail) {
        cells.push(&bytes[offset..offset + chunk]);
        offset += chunk;
    }
    cells.push(&bytes[offset..]);
    let mut chain: Option<Cell> = None;
    for piece in cells.iter().rev() {
        let mut builder = BuilderData::new();
        builder.append_raw(piece, piece.len() * 8).expect("a vk chunk");
        if let Some(next) = chain {
            builder.checked_append_reference(next).expect("chain reference");
        }
        chain = Some(builder.into_cell().expect("a vk cell"));
    }
    chain.expect("a vk chain")
}

const PROBE: &str = r#"
cell p_genesis(int commit_root, int nullifier_root, int reserve, cell config, cell vk) method_id {
  return state_genesis(commit_root, nullifier_root, reserve, config, vk);
}
(int, int, int, int, int, int, int) p_scalars(cell state) method_id {
  (int cr, int cn, int nr, int nn, int epoch, int liability, int reserve,
   cell f, cell a, cell c, cell v) = state_parse(state);
  return (cr, cn, nr, nn, epoch, liability, reserve);
}
;; Every slot of the frontier the state carries, summed. At genesis they are
;; all zero, and reading them at all is the assertion: `frontier_level_read`
;; refuses a store whose shape is not the one section 13.1 fixes.
int p_frontier_sum(cell state) method_id {
  (_, _, _, _, _, _, _, cell frontier, _, _, _) = state_parse(state);
  int total = 0;
  int level = 0;
  cell node = frontier;
  while (level < tree_depth()) {
    int last = level == (tree_depth() - 1);
    (int v0, int v1, int v2, int v3, int v4, int v5, int v6, cell next) =
      frontier_level_read(node, last);
    total = total + v0 + v1 + v2 + v3 + v4 + v5 + v6;
    node = next;
    level = level + 1;
  }
  return total;
}
int p_parse_exit(cell state) method_id {
  state_parse(state);
  return 0;
}
cell p_rebuild(cell state) method_id {
  (int cr, int cn, int nr, int nn, int epoch, int liability, int reserve,
   cell f, cell a, cell c, cell v) = state_parse(state);
  return state_build(cr, cn, nr, nn, epoch, liability, reserve, f, a, c, v);
}
int p_config(cell config) method_id {
  (_, _, _, int fee, int count, _) = config_parse(config);
  return (fee * 100) + count;
}
int p_has_denomination(cell config, int amount) method_id {
  return config_has_denomination(config, amount);
}
int p_vk_ok(cell vk) method_id { vk_require_canonical(vk); return 1; }
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
        let probe_path = probe_dir.path().join("tos_shielded_state_probe.fc");
        std::fs::write(&probe_path, PROBE).expect("write probe");
        let code = compile_func_with_stdlib(&[
            format!("{library}/domains.fc").into(),
            format!("{library}/empty-roots.fc").into(),
            format!("{library}/notes.fc").into(),
            format!("{library}/tree.fc").into(),
            format!("{library}/anchors.fc").into(),
            format!("{library}/state.fc").into(),
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

    fn call(&self, method: &str, args: Vec<StackItem>) -> Result<Vec<StackItem>, i32> {
        let result = self
            .bc
            .run_get_method(&self.addr, method, args)
            .unwrap_or_else(|e| panic!("{method}: {e}"));
        if result.exit_code != 0 {
            return Err(result.exit_code);
        }
        Ok(result.stack)
    }

    fn field_arg(value: &Field) -> StackItem {
        StackItem::integer(IntegerData::from_str_radix(&dec(value), 10).expect("a field element"))
    }

    fn genesis(&self, config: &Cell, vk: &Cell, reserve: u64) -> Result<Cell, i32> {
        let stack = self.call(
            "p_genesis",
            vec![
                Self::field_arg(&field(0xaa)),
                Self::field_arg(&field(0xbb)),
                StackItem::int(reserve as i64),
                StackItem::Cell(config.clone()),
                StackItem::Cell(vk.clone()),
            ],
        )?;
        Ok(stack.last().expect("a state").as_cell().expect("a cell").clone())
    }

    fn scalars(&self, state: &Cell) -> Result<Vec<String>, i32> {
        let stack = self.call("p_scalars", vec![StackItem::Cell(state.clone())])?;
        Ok(stack.iter().map(|item| item.as_integer().expect("integer").to_string()).collect())
    }

    fn exit(&self, method: &str, args: Vec<StackItem>) -> i32 {
        self.call(method, args).err().unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------

#[test]
fn genesis_is_the_state_section_13_2_describes() {
    let probe = Probe::deploy();
    let config = Config::sample().cell();
    let vk = vk_chain();
    let state = probe.genesis(&config, &vk, 5 * TOS).expect("genesis");

    let scalars = probe.scalars(&state).expect("parse");
    assert_eq!(scalars.len(), 7);
    assert_eq!(scalars[0], dec(&field(0xaa)), "the commitment root is not the empty root given");
    assert_eq!(scalars[1], "0", "the commitment counter does not start at zero");
    assert_eq!(scalars[2], dec(&field(0xbb)), "the nullifier root is not the genesis root given");
    assert_eq!(scalars[3], "1", "the nullifier counter does not start at one");
    assert_eq!(scalars[4], EPOCH_NONE.to_string(), "last_anchor_epoch is not the sentinel");
    assert_eq!(scalars[5], "0", "liability does not start at zero");
    assert_eq!(scalars[6], (5 * TOS).to_string(), "the reserve floor was not carried through");

    // Both rings are present and empty, and the frontier is twelve levels of
    // zeros -- which is a shape, not an absence, so it is read rather than
    // asked about: `frontier_level_read` throws on anything else.
    let sum = probe.call("p_frontier_sum", vec![StackItem::Cell(state.clone())]).expect("call");
    assert_eq!(
        sum.last().expect("a result").as_integer().expect("integer").to_string(),
        "0",
        "the genesis frontier is not eighty-four zeros"
    );

    // Parsing and rebuilding must be the identity, or the state a transaction
    // writes back is not the state it read.
    let rebuilt = probe.call("p_rebuild", vec![StackItem::Cell(state.clone())]).expect("rebuild");
    assert_eq!(
        rebuilt.last().expect("a state").as_cell().expect("a cell").repr_hash(),
        state.repr_hash(),
        "parse and rebuild are not the identity"
    );
}

#[test]
fn a_state_root_that_is_not_the_frozen_shape_is_refused() {
    let probe = Probe::deploy();
    let config = Config::sample().cell();
    let vk = vk_chain();
    let good = probe.genesis(&config, &vk, 5 * TOS).expect("genesis");
    assert_eq!(probe.exit("p_scalars", vec![StackItem::Cell(good.clone())]), 0);

    let rebuild = |magic: u32, version: u16, extra_bits: usize, refs: usize| -> Cell {
        let mut builder = BuilderData::new();
        builder.append_u32(magic).unwrap();
        builder.append_u16(version).unwrap();
        builder.append_raw(&field(0xaa), 256).unwrap();
        builder.append_u64(0).unwrap();
        builder.append_raw(&field(0xbb), 256).unwrap();
        builder.append_u64(1).unwrap();
        builder.append_u32(EPOCH_NONE).unwrap();
        store_coins(&mut builder, 0);
        store_coins(&mut builder, 5 * TOS as u128);
        if extra_bits > 0 {
            builder.append_bits(0, extra_bits).unwrap();
        }
        for index in 0..refs {
            let child = if index == 0 {
                // The real store, so that a state which is wrong in the way
                // this case names is not also wrong in a way that throws the
                // same code first.
                shielded_pool_library::frontier_holder()
            } else if index == 2 {
                config.clone()
            } else if index == 3 {
                vk.clone()
            } else {
                let mut holder = BuilderData::new();
                for _ in 0..2 {
                    let mut ring = BuilderData::new();
                    ring.append_bit_zero().unwrap();
                    holder.checked_append_reference(ring.into_cell().unwrap()).unwrap();
                }
                holder.into_cell().unwrap()
            };
            builder.checked_append_reference(child).unwrap();
        }
        builder.into_cell().expect("a state root")
    };

    assert_eq!(
        probe.exit("p_scalars", vec![StackItem::Cell(rebuild(MAGIC, VERSION, 0, 4))]),
        0,
        "the hand-built canonical state was refused, so the cases below prove nothing"
    );
    assert_eq!(
        probe.exit("p_scalars", vec![StackItem::Cell(rebuild(MAGIC ^ 1, VERSION, 0, 4))]),
        180,
        "a wrong magic was accepted"
    );
    assert_eq!(
        probe.exit("p_scalars", vec![StackItem::Cell(rebuild(MAGIC, VERSION + 1, 0, 4))]),
        180,
        "a wrong version was accepted"
    );
    assert_eq!(
        probe.exit("p_scalars", vec![StackItem::Cell(rebuild(MAGIC, VERSION, 1, 4))]),
        181,
        "a trailing bit was accepted"
    );
    assert_eq!(
        probe.exit("p_scalars", vec![StackItem::Cell(rebuild(MAGIC, VERSION, 0, 3))]),
        181,
        "three references were accepted"
    );
}

/// A state whose frontier reference is an absent maybe is refused.
///
/// The holder can express absence and the store cannot: a level chain always
/// has a root cell, so there is no frontier a pool could have written that
/// this state is. Refusing it in the parser rather than at the first append
/// is what keeps a malformed state from being read at all, and this is the
/// only input that reaches that line.
#[test]
fn a_state_without_a_frontier_is_refused() {
    let probe = Probe::deploy();
    let config = Config::sample().cell();
    let vk = vk_chain();

    let state = |frontier: Cell| -> Cell {
        let mut builder = BuilderData::new();
        builder.append_u32(MAGIC).unwrap();
        builder.append_u16(VERSION).unwrap();
        builder.append_raw(&field(0xaa), 256).unwrap();
        builder.append_u64(0).unwrap();
        builder.append_raw(&field(0xbb), 256).unwrap();
        builder.append_u64(1).unwrap();
        builder.append_u32(EPOCH_NONE).unwrap();
        store_coins(&mut builder, 0);
        store_coins(&mut builder, 5 * TOS as u128);
        builder.checked_append_reference(frontier).unwrap();
        let mut anchors = BuilderData::new();
        for _ in 0..2 {
            let mut ring = BuilderData::new();
            ring.append_bit_zero().unwrap();
            anchors.checked_append_reference(ring.into_cell().unwrap()).unwrap();
        }
        builder.checked_append_reference(anchors.into_cell().unwrap()).unwrap();
        builder.checked_append_reference(config.clone()).unwrap();
        builder.checked_append_reference(vk.clone()).unwrap();
        builder.into_cell().expect("a state root")
    };

    let mut absent = BuilderData::new();
    absent.append_bit_zero().unwrap();
    let absent = absent.into_cell().unwrap();

    // The same state with a real store parses, so the refusal below is about
    // the frontier and not about anything else in the cell.
    assert_eq!(
        probe.exit(
            "p_parse_exit",
            vec![StackItem::Cell(state(shielded_pool_library::frontier_holder()))]
        ),
        0,
        "a state carrying the deployed frontier was refused"
    );
    assert_eq!(
        probe.exit("p_parse_exit", vec![StackItem::Cell(state(absent))]),
        181,
        "a state whose frontier reference holds nothing was accepted"
    );
}

#[test]
fn a_counter_above_the_sentinel_is_not_a_state() {
    let probe = Probe::deploy();
    let config = Config::sample().cell();
    let vk = vk_chain();
    let build = |commitment: u64, nullifier: u64| -> Cell {
        let mut builder = BuilderData::new();
        builder.append_u32(MAGIC).unwrap();
        builder.append_u16(VERSION).unwrap();
        builder.append_raw(&field(0xaa), 256).unwrap();
        builder.append_u64(commitment).unwrap();
        builder.append_raw(&field(0xbb), 256).unwrap();
        builder.append_u64(nullifier).unwrap();
        builder.append_u32(EPOCH_NONE).unwrap();
        store_coins(&mut builder, 0);
        store_coins(&mut builder, 5 * TOS as u128);
        builder.checked_append_reference(shielded_pool_library::frontier_holder()).unwrap();
        let mut anchors = BuilderData::new();
        for _ in 0..2 {
            let mut ring = BuilderData::new();
            ring.append_bit_zero().unwrap();
            anchors.checked_append_reference(ring.into_cell().unwrap()).unwrap();
        }
        builder.checked_append_reference(anchors.into_cell().unwrap()).unwrap();
        builder.checked_append_reference(config.clone()).unwrap();
        builder.checked_append_reference(vk.clone()).unwrap();
        builder.into_cell().expect("a state root")
    };

    // The sentinel itself is representable; anything past it is not a state.
    assert_eq!(probe.exit("p_scalars", vec![StackItem::Cell(build(INDEX_SENTINEL, 1))]), 0);
    assert_eq!(
        probe.exit("p_scalars", vec![StackItem::Cell(build(INDEX_SENTINEL + 1, 1))]),
        182,
        "a commitment counter past the sentinel was accepted"
    );
    assert_eq!(
        probe.exit("p_scalars", vec![StackItem::Cell(build(0, INDEX_SENTINEL + 1))]),
        182,
        "a nullifier counter past the sentinel was accepted"
    );
}

#[test]
fn the_config_is_revalidated_rather_than_trusted() {
    let probe = Probe::deploy();
    let sample = Config::sample();
    let good = sample.cell();
    assert_eq!(probe.exit("p_config", vec![StackItem::Cell(good.clone())]), 0);

    // The fee is an amount: positive, and under the same ceiling as every
    // other amount. Ruling A2's deployment-side half.
    let mut zero_fee = Config::sample();
    zero_fee.withdrawal_fee = 0;
    assert_eq!(
        probe.exit("p_config", vec![StackItem::Cell(zero_fee.cell())]),
        184,
        "a zero withdrawal fee was accepted"
    );
    // The ceiling ruling A2 asks for is enforced by the wire type, not by a
    // throw: Coins is a VarUInteger 16, so the largest amount it can carry is
    // 2^120 - 1 and 2^120 has no encoding. The check is that the boundary is
    // where the profile says, not that some unreachable guard exists.
    let mut edge_fee = Config::sample();
    edge_fee.withdrawal_fee = (1u128 << 120) - 1;
    assert_eq!(
        probe.exit("p_config", vec![StackItem::Cell(edge_fee.cell())]),
        0,
        "the largest amount Coins can carry was refused"
    );
    let mut over = Config::sample();
    over.withdrawal_fee = 1u128 << 120;
    assert_eq!(
        probe.exit("p_config", vec![StackItem::Cell(over.cell())]),
        183,
        "2^120 produced a parsable config, so Coins is not the ceiling after all"
    );

    // The denomination list: bounded, positive, strictly increasing, and
    // exactly as long as the count says.
    let mut unsorted = Config::sample();
    unsorted.denominations = vec![10 * TOS as u128, TOS as u128];
    assert_eq!(
        probe.exit("p_config", vec![StackItem::Cell(unsorted.cell())]),
        188,
        "an unsorted denomination list was accepted"
    );
    let mut duplicate = Config::sample();
    duplicate.denominations = vec![TOS as u128, TOS as u128];
    assert_eq!(
        probe.exit("p_config", vec![StackItem::Cell(duplicate.cell())]),
        188,
        "a duplicated denomination was accepted"
    );
    let mut zero = Config::sample();
    zero.denominations = vec![0, TOS as u128];
    assert_eq!(
        probe.exit("p_config", vec![StackItem::Cell(zero.cell())]),
        187,
        "a zero denomination was accepted"
    );
    let mut too_many = Config::sample();
    too_many.denominations = (1..=17u128).map(|n| n * TOS as u128).collect();
    assert_eq!(
        probe.exit("p_config", vec![StackItem::Cell(too_many.cell())]),
        185,
        "seventeen denominations were accepted"
    );
    assert_eq!(
        probe.exit("p_config", vec![StackItem::Cell(sample.cell_with_count(0))]),
        185,
        "an empty denomination list was accepted"
    );

    // A chain longer than the count is a different list that starts the same.
    assert_eq!(
        probe.exit("p_config", vec![StackItem::Cell(sample.cell_with_count(2))]),
        186,
        "a chain longer than its count was accepted"
    );

    // A second reference on the config store itself: the denominations are one
    // reference and there is nowhere for another to belong.
    let mut two_refs = BuilderData::new();
    two_refs.append_raw(&sample.profile_hash, 256).unwrap();
    two_refs.append_raw(&sample.poseidon_hash, 256).unwrap();
    two_refs.append_raw(&sample.vk_hash, 256).unwrap();
    store_coins(&mut two_refs, sample.withdrawal_fee);
    two_refs.append_u8(sample.denominations.len() as u8).unwrap();
    two_refs.checked_append_reference(denomination_chain(&sample.denominations)).unwrap();
    two_refs.checked_append_reference(Cell::default()).unwrap();
    assert_eq!(
        probe.exit("p_config", vec![StackItem::Cell(two_refs.into_cell().unwrap())]),
        183,
        "a config store with a second reference was accepted"
    );

    // And one with no reference at all. This is the half of the reference rule
    // that can fire on its own: a store with too many is caught by nothing
    // being left over, but a store with none has no denominations to read, and
    // it must be this module that says so rather than a cell underflow.
    let mut no_refs = BuilderData::new();
    no_refs.append_raw(&sample.profile_hash, 256).unwrap();
    no_refs.append_raw(&sample.poseidon_hash, 256).unwrap();
    no_refs.append_raw(&sample.vk_hash, 256).unwrap();
    store_coins(&mut no_refs, sample.withdrawal_fee);
    no_refs.append_u8(sample.denominations.len() as u8).unwrap();
    assert_eq!(
        probe.exit("p_config", vec![StackItem::Cell(no_refs.into_cell().unwrap())]),
        183,
        "a config store with no denominations was not refused by this module"
    );

    // And the list is usable, or none of the above means anything.
    for amount in &sample.denominations {
        let stack = probe
            .call(
                "p_has_denomination",
                vec![StackItem::Cell(good.clone()), StackItem::int(*amount as i64)],
            )
            .expect("lookup");
        assert_ne!(
            stack.last().unwrap().as_integer().unwrap().to_string(),
            "0",
            "a configured denomination was not found"
        );
    }
    let stack = probe
        .call("p_has_denomination", vec![StackItem::Cell(good), StackItem::int(3 * TOS as i64)])
        .expect("lookup");
    assert_eq!(
        stack.last().unwrap().as_integer().unwrap().to_string(),
        "0",
        "an amount that is not a denomination was found"
    );
}

#[test]
fn the_verifying_key_chain_is_the_frozen_shape() {
    let probe = Probe::deploy();
    assert_eq!(
        probe.exit("p_vk_ok", vec![StackItem::Cell(vk_chain())]),
        0,
        "the canonical chain was refused"
    );

    let bytes: Vec<u8> = (0..VK_BYTES).map(|i| (i % 251) as u8).collect();
    // A different split of the same 1248 bytes: a chunk that carries a
    // reference must fill its cell, so only one layout is canonical.
    let mut uneven = BuilderData::new();
    uneven.append_raw(&bytes[..126], 126 * 8).unwrap();
    uneven.checked_append_reference(vk_chain_of(&bytes[126..], 127, 105 + 1)).unwrap();
    assert_eq!(
        probe.exit("p_vk_ok", vec![StackItem::Cell(uneven.into_cell().unwrap())]),
        189,
        "a short leading cell was accepted"
    );

    // One byte short and one byte long.
    let short: Vec<u8> = bytes[..VK_BYTES - 1].to_vec();
    assert_eq!(
        probe.exit("p_vk_ok", vec![StackItem::Cell(vk_chain_of(&short, 127, 104))]),
        189,
        "a 1247-byte chain was accepted"
    );
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(
        probe.exit("p_vk_ok", vec![StackItem::Cell(vk_chain_of(&long, 127, 106))]),
        189,
        "a 1249-byte chain was accepted"
    );

    // A final cell that still carries a successor.
    let mut trailing = BuilderData::new();
    trailing.append_raw(&bytes[VK_BYTES - 105..], 105 * 8).unwrap();
    trailing.checked_append_reference(Cell::default()).unwrap();
    let mut chain = trailing.into_cell().unwrap();
    for index in (0..9).rev() {
        let mut builder = BuilderData::new();
        builder.append_raw(&bytes[index * 127..(index + 1) * 127], 127 * 8).unwrap();
        builder.checked_append_reference(chain).unwrap();
        chain = builder.into_cell().unwrap();
    }
    assert_eq!(
        probe.exit("p_vk_ok", vec![StackItem::Cell(chain)]),
        189,
        "a final cell with a successor was accepted"
    );
}

#[test]
fn genesis_refuses_a_configuration_it_would_have_to_live_with() {
    let probe = Probe::deploy();
    let vk = vk_chain();
    let mut bad_fee = Config::sample();
    bad_fee.withdrawal_fee = 0;
    assert_eq!(
        probe.genesis(&bad_fee.cell(), &vk, 5 * TOS).unwrap_err(),
        184,
        "genesis accepted a zero withdrawal fee"
    );
    assert_eq!(
        probe.genesis(&Config::sample().cell(), &vk, 0).unwrap_err(),
        184,
        "genesis accepted a zero reserve floor"
    );
    let short: Vec<u8> = (0..VK_BYTES - 1).map(|i| (i % 251) as u8).collect();
    assert_eq!(
        probe
            .genesis(&Config::sample().cell(), &vk_chain_of(&short, 127, 104), 5 * TOS)
            .unwrap_err(),
        189,
        "genesis accepted a verifying key of the wrong length"
    );
}
