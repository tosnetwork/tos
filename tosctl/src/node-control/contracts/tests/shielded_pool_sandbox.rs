/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! The shielded pool contract's deposit path, sections 12.1, 14.1 and 16.1.
//!
//! The earlier deposit probe established that these rules are enforceable in
//! this VM. This is the other half: a contract that obeys them, deployed with a
//! real genesis state and driven by real internal messages.
//!
//! Two of the checks here are the ones the whole design rests on.
//!
//! The depositor cannot choose its note. It sends an owner commitment and a
//! payload; the contract computes the note from the amount it actually admitted
//! and the leaf index it actually assigned, and the suite compares that against
//! a tree rebuilt from every leaf rather than against the contract's own idea
//! of what it did.
//!
//! The contract never calls ACCEPT, which is not the same as the funding
//! inequality and is not shown by a refusal the message could afford. It is
//! shown by a message too small to pay for its own gas: it must die on the gas
//! it bought, and the pool's balance must not move.

use sha2::{Digest, Sha256};

use chain_block::poseidon2::permute;
use chain_block::poseidon2_kat::{DOMAINS, EMPTY_ROOTS};
use chain_block::{
    BuilderData, Cell, IBitstring, MsgAddressInt, Serializable, StateInit, TrComputePhase,
};
use tos_sandbox::{Blockchain, MessageBuilder, SendResult, compile_func_with_stdlib};

mod shielded_pool_library;

const TOS: u64 = 1_000_000_000;
const ACTIVE_VERSION: u32 = 18;
const DEPTH: usize = 12;
const ARITY: usize = 7;

const MAGIC: u32 = 0x5350_5631;
const VERSION: u16 = 1;
const EPOCH_NONE: u32 = 0xffff_ffff;

const OP_DEPOSIT: u32 = 0x5348_5001;
const OP_TRANSACT: u32 = 0x5348_5002;
const OP_RESERVE_TOPUP: u32 = 0x5348_5003;
/// Not one of the three. The contract has to refuse an operation it does
/// not have before it parses anything that follows it.
const OP_UNKNOWN: u32 = 0x5348_50ff;

/// Section 14.1, frozen by the production rule
/// C = max(10,000, round_up_10,000(ceil(M * 5 / 4))).
///
/// The maximum is measured with both anchor rings full, not against a pool
/// that has just been deployed: a pool whose rings are still empty costs
/// 157,205 for the same deposit. The frontier no longer contributes any
/// growth -- the store is a level chain rather than a dictionary, and its
/// dearest append is a pool's first -- so the rings are the whole of it.
/// `deposit_in_a_mature_pool.rs` in the crosscheck crate is what measures it.
///
/// Read out of the contract, never written down here. A ceiling copied into a
/// test is a number this file can check against itself while the deployed
/// contract says something else entirely.
fn deposit_gas_ceiling() -> i64 {
    shielded_pool_library::gas_ceiling("deposit_gas_ceiling")
}
/// The upper bound `gas_ceiling_bound.rs` derives for the deposit path, not
/// the largest deposit anybody built. A maximum over a product space cannot
/// be measured, and this number used to be the best of a handful of points
/// with the word maximum attached; it is now the measured cost of one
/// deposit plus, for each variable call the path makes, the span of that call
/// over the whole of its own domain.
const DEPOSIT_DERIVED_BOUND_GAS: i64 = 176_694;
/// ConfigParam 21 of this chain's zero state, which
/// `chain_gas_envelope_sandbox.rs` generates and holds against the
/// executor's table.
const BASECHAIN_GAS_LIMIT: i64 = 30_000_000;
/// Section 14.1, frozen by the production rule: a top-up executes no
/// Poseidon2, so the tariff cannot move it, and 10,000 is the rule's floor.
fn topup_gas_ceiling() -> i64 {
    shielded_pool_library::gas_ceiling("topup_gas_ceiling")
}
/// The same on the deployed configuration and on the shorter denomination
/// list most of this file uses, which is not an assumption:
/// `a_reserve_top_up_adds_balance_and_nothing_else` measures both and requires
/// them equal. A top-up never parses the state cell, so it has no read of the
/// configuration to grow -- unlike the deposit and transact maxima, which were
/// both low for exactly that reason until they were re-measured.
// 2,380 until section 15.4's `recovery_charge` became a get method: a larger
// method dictionary costs every entry point about a hundred gas to dispatch
// through. The D6 ceiling does not move -- 2,480 x 5/4 still rounds to the
// 10,000 floor -- but the measurement it was ruled from does, and a pinned
// number that is no longer what the path costs is a number nobody can check.
/// A top-up never parses the state cell, touches no dictionary and moves no
/// tree, so its domain is the query id and that is a fixed sixty-four bits.
/// Its bound and its measurement are the same number, which is true of no
/// other path here.
const TOPUP_DERIVED_BOUND_GAS: i64 = 2_480;
/// ConfigParam 21 of this chain's zero state, beyond the flat segment.
/// The basechain compute fee for `gas`, priced as ConfigParam21 prices it: a
/// flat 667 for the first hundred gas, then 436,907 per 65,536 gas with the
/// division rounded up.
///
/// This was `gas * NANOTOS_PER_GAS` with NANOTOS_PER_GAS = 400 while the
/// price was 26,214,400, which divides by 65,536 exactly. Neither of the two
/// prices since does, so a flat multiplier is no longer the same arithmetic
/// the VM does, and the tests now do the VM's.
const fn compute_fee(gas: u64) -> u64 {
    const FLAT_LIMIT: u64 = 100;
    const FLAT_PRICE: u64 = 667;
    const GAS_PRICE: u64 = 436_907;
    if gas <= FLAT_LIMIT {
        FLAT_PRICE
    } else {
        FLAT_PRICE + ((gas - FLAT_LIMIT) * GAS_PRICE).div_ceil(65_536)
    }
}
const RESERVE_FLOOR: u64 = 5 * TOS;
/// What a deposit must carry beyond its principal: the ceiling the contract
/// declares, priced by the same arithmetic the VM uses -- not what the path
/// will actually spend.
fn deposit_compute_fee() -> u64 {
    compute_fee(deposit_gas_ceiling() as u64)
}

type Field = [u8; 32];
const ZERO: Field = [0u8; 32];

// ---------------------------------------------------------------------------
// Reference: the note and the tree, rebuilt from every leaf.

fn domain(label: &str) -> Field {
    DOMAINS.iter().find(|(name, _)| *name == label).expect("a domain label").1
}

fn h7(domain: Field, args: [Field; 7]) -> Field {
    let mut state = [[0u8; 32]; 8];
    state[0] = domain;
    state[1..].copy_from_slice(&args);
    permute(&state)[0]
}

fn note_body_commitment(owner: Field, amount: Field, data_hash: Field) -> Field {
    h7(domain("NOTE-BODY"), [owner, amount, data_hash, ZERO, ZERO, ZERO, ZERO])
}

fn note_commitment(body: Field, leaf_index: Field) -> Field {
    h7(domain("NOTE-COMMITMENT"), [body, leaf_index, ZERO, ZERO, ZERO, ZERO, ZERO])
}

fn commit_node(children: [Field; 7]) -> Field {
    h7(domain("COMMIT-NODE"), children)
}

fn naive_root(leaves: &[Field]) -> Field {
    let mut level_nodes = leaves.to_vec();
    for level in 0..DEPTH {
        while level_nodes.len() % ARITY != 0 {
            level_nodes.push(EMPTY_ROOTS[level]);
        }
        let mut next = Vec::with_capacity(level_nodes.len() / ARITY);
        for group in level_nodes.chunks(ARITY) {
            let mut children = [ZERO; 7];
            children.copy_from_slice(group);
            next.push(commit_node(children));
        }
        if next.is_empty() {
            next.push(EMPTY_ROOTS[level + 1]);
        }
        level_nodes = next;
    }
    level_nodes[0]
}

/// The modulus, for the one place the profile allows a reduction: a hash the
/// contract computes itself.
fn reduce(digest: [u8; 32]) -> Field {
    let m =
        from_dec("52435875175126190479447740508185965837690552500527637822603658699938581184513");
    let mut value = digest;
    while value[..] >= m[..] {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for index in (0..32).rev() {
            let mut diff = value[index] as i16 - m[index] as i16 - borrow;
            borrow = if diff < 0 {
                diff += 256;
                1
            } else {
                0
            };
            out[index] = diff as u8;
        }
        value = out;
    }
    value
}

fn output_data_hash(bytes: &[u8]) -> Field {
    let mut hasher = Sha256::new();
    hasher.update(b"TOS-SHIELDED-OUTPUT-DATA-v1");
    hasher.update(bytes);
    reduce(hasher.finalize().into())
}

// ---------------------------------------------------------------------------

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

fn from_dec(text: &str) -> Field {
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

fn amount_field(amount: u64) -> Field {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&amount.to_be_bytes());
    out
}

fn store_coins(builder: &mut BuilderData, amount: u128) {
    let bytes = amount.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    let length = bytes.len() - first;
    builder.append_bits(length, 4).expect("coin length");
    if length > 0 {
        builder.append_raw(&bytes[first..], length * 8).expect("coin bytes");
    }
}

const DENOMINATIONS: [u64; 3] = [TOS, 10 * TOS, 100 * TOS];
/// The list section 12.1 really deploys with. Most tests here want the
/// shorter one, because the amounts they send are easier to read; anything
/// that measures what a path *costs* has to use this one, since the contract
/// walks the list to validate an amount.
const DEPLOYED_DENOMINATIONS: [u64; 4] = [TOS, 10 * TOS, 100 * TOS, 1_000 * TOS];

fn denomination_chain(denominations: &[u64]) -> Cell {
    let mut chain: Option<Cell> = None;
    for amount in denominations.iter().rev() {
        let mut builder = BuilderData::new();
        store_coins(&mut builder, *amount as u128);
        if let Some(next) = chain {
            builder.checked_append_reference(next).expect("chain reference");
        }
        chain = Some(builder.into_cell().expect("a denomination"));
    }
    chain.expect("a chain")
}

fn config_store(denominations: &[u64]) -> Cell {
    let mut builder = BuilderData::new();
    builder.append_raw(&[0x11; 32], 256).unwrap();
    builder.append_raw(&[0x22; 32], 256).unwrap();
    builder.append_raw(&[0x33; 32], 256).unwrap();
    store_coins(&mut builder, 50_000_000);
    builder.append_u8(denominations.len() as u8).unwrap();
    builder.checked_append_reference(denomination_chain(denominations)).unwrap();
    builder.into_cell().expect("a config store")
}

fn vk_store() -> Cell {
    let bytes: Vec<u8> = (0..1248).map(|i| (i % 251) as u8).collect();
    let mut chain: Option<Cell> = None;
    let pieces: Vec<&[u8]> = bytes.chunks(127).collect();
    for piece in pieces.iter().rev() {
        let mut builder = BuilderData::new();
        builder.append_raw(piece, piece.len() * 8).unwrap();
        if let Some(next) = chain {
            builder.checked_append_reference(next).unwrap();
        }
        chain = Some(builder.into_cell().unwrap());
    }
    chain.expect("a vk chain")
}

/// The 1233-byte payload as nine full cells and a ninety-byte tail.
fn output_data(seed: u8) -> (Cell, Vec<u8>) {
    let bytes: Vec<u8> = (0..1233u32).map(|i| (i as u8) ^ seed).collect();
    let pieces: Vec<&[u8]> = bytes.chunks(127).collect();
    let mut chain: Option<Cell> = None;
    for piece in pieces.iter().rev() {
        let mut builder = BuilderData::new();
        builder.append_raw(piece, piece.len() * 8).unwrap();
        if let Some(next) = chain {
            builder.checked_append_reference(next).unwrap();
        }
        chain = Some(builder.into_cell().unwrap());
    }
    (chain.expect("a payload"), bytes)
}

fn empty_ring_holder() -> Cell {
    let mut builder = BuilderData::new();
    builder.append_bit_zero().unwrap();
    builder.into_cell().unwrap()
}

fn genesis_state(denominations: &[u64]) -> Cell {
    let mut builder = BuilderData::new();
    builder.append_u32(MAGIC).unwrap();
    builder.append_u16(VERSION).unwrap();
    builder.append_raw(&EMPTY_ROOTS[DEPTH], 256).unwrap();
    builder.append_u64(0).unwrap();
    builder.append_raw(&[0x5a; 32], 256).unwrap(); // the IMT genesis root; untouched here
    builder.append_u64(1).unwrap();
    builder.append_u32(EPOCH_NONE).unwrap();
    store_coins(&mut builder, 0);
    store_coins(&mut builder, RESERVE_FLOOR as u128);
    builder.checked_append_reference(shielded_pool_library::frontier_holder()).unwrap();
    let mut anchors = BuilderData::new();
    anchors.checked_append_reference(empty_ring_holder()).unwrap();
    anchors.checked_append_reference(empty_ring_holder()).unwrap();
    builder.checked_append_reference(anchors.into_cell().unwrap()).unwrap();
    builder.checked_append_reference(config_store(denominations)).unwrap();
    builder.checked_append_reference(vk_store()).unwrap();
    builder.into_cell().expect("the genesis state")
}

fn deposit_body(amount: u64, owner: &Field, payload: Cell) -> Cell {
    let mut builder = BuilderData::new();
    builder.append_u32(OP_DEPOSIT).unwrap();
    builder.append_u64(1).unwrap(); // query id
    store_coins(&mut builder, amount as u128);
    builder.append_raw(owner, 256).unwrap();
    builder.checked_append_reference(payload).unwrap();
    builder.into_cell().expect("a deposit body")
}

struct Pool {
    bc: Blockchain,
    addr: MsgAddressInt,
    payer: tos_sandbox::Treasury,
    leaves: Vec<Field>,
}

impl Pool {
    fn deploy() -> Self {
        Self::deploy_with(&DENOMINATIONS)
    }

    /// A pool whose configuration store carries exactly `denominations`.
    /// Anything measuring a path's cost deploys with `DEPLOYED_DENOMINATIONS`;
    /// a measurement taken against a list nobody deploys is a measurement of a
    /// different contract.
    fn deploy_with(denominations: &[u64]) -> Self {
        let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)
            .expect("blockchain at version 17");
        bc.set_workchain(0);
        let payer = bc.treasury("depositor", 100_000 * TOS).expect("treasury");
        let code = compile_func_with_stdlib(&shielded_pool_library::pool_sources())
            .expect("compile the pool (needs build/crypto/func)");
        let si = StateInit::with_code_and_data(code, genesis_state(denominations));
        let hash = si.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
        let addr = MsgAddressInt::with_params(0, hash).unwrap();
        // The deploy value is reserve, not liability.
        bc.send_message(
            MessageBuilder::internal(payer.address(), &addr, 20 * TOS)
                .bounce(false)
                .state_init(si)
                .body(Cell::default())
                .build(),
        )
        .expect("deploy")
        .expect_success();
        Self { bc, addr, payer, leaves: Vec::new() }
    }

    fn get(&self, method: &str) -> String {
        let result = self
            .bc
            .run_get_method(&self.addr, method, vec![])
            .unwrap_or_else(|e| panic!("{method}: {e}"));
        assert_eq!(result.exit_code, 0, "{method} exited {}", result.exit_code);
        result.stack.last().expect("a result").as_integer().expect("integer").to_string()
    }

    fn balance(&self) -> u64 {
        self.bc
            .get_account(&self.addr)
            .and_then(|a| a.balance().and_then(|c| c.coins.as_u64()))
            .expect("the pool has a balance")
    }

    fn send(&mut self, value: u64, body: Cell) -> SendResult {
        let msg = MessageBuilder::internal(self.payer.address(), &self.addr, value)
            .bounce(true)
            .body(body)
            .build();
        self.bc.send_message(msg).expect("send")
    }

    /// Both readings of the backing invariant: the contract's own, and the
    /// account state the test can see.
    fn assert_backed(&self, at: &str) {
        let balance = self.balance();
        let liability: u64 = self.get("native_liability").parse().expect("liability");
        let reserve: u64 = self.get("reserve_floor").parse().expect("reserve");
        assert!(
            balance >= liability + reserve,
            "{at}: balance {balance} < liability {liability} + reserve {reserve}"
        );
        assert_ne!(self.get("backed"), "0", "{at}: the contract disagrees with the account state");
    }

    fn deposit(&mut self, amount: u64, owner: &Field, seed: u8) -> SendResult {
        let (payload, bytes) = output_data(seed);
        let result =
            self.send(amount + deposit_compute_fee(), deposit_body(amount, owner, payload));
        let body = note_body_commitment(*owner, amount_field(amount), output_data_hash(&bytes));
        let index = self.leaves.len() as u64;
        self.leaves.push(note_commitment(body, amount_field(index)));
        result
    }
}

fn compute_phase(result: &SendResult) -> chain_block::TrComputePhaseVm {
    match result.read_primary_description().compute_ph {
        TrComputePhase::Vm(vm) => vm,
        TrComputePhase::Skipped(s) => panic!("compute was skipped: {:?}", s.reason),
    }
}

// ---------------------------------------------------------------------------

#[test]
fn a_deposit_is_the_note_the_contract_computed_at_the_index_it_assigned() {
    let mut pool = Pool::deploy();
    pool.assert_backed("after deploy");
    assert_eq!(pool.get("native_liability"), "0", "deploy value is reserve, not liability");
    assert_eq!(pool.get("commitment_root"), dec(&EMPTY_ROOTS[DEPTH]), "genesis root is not empty");

    let owner = [7u8; 32];
    for (step, amount) in [TOS, 10 * TOS, TOS, 100 * TOS].into_iter().enumerate() {
        pool.deposit(amount, &owner, step as u8).expect_success();
        assert_eq!(
            pool.get("commitment_next_index"),
            (step + 1).to_string(),
            "the leaf counter did not advance by exactly one"
        );
        assert_eq!(
            pool.get("commitment_root"),
            dec(&naive_root(&pool.leaves)),
            "after deposit {step} the root is not the tree of every leaf so far"
        );
        pool.assert_backed("after a deposit");
    }

    let total: u64 = TOS + 10 * TOS + TOS + 100 * TOS;
    assert_eq!(
        pool.get("native_liability"),
        total.to_string(),
        "liability is not the sum admitted"
    );
}

#[test]
fn the_depositor_cannot_choose_its_note() {
    let mut pool = Pool::deploy();
    let owner = [9u8; 32];

    // The same owner and payload at two amounts give different notes, so the
    // amount is bound; and the note recorded is the one for the amount the
    // contract admitted, not for any larger one.
    pool.deposit(TOS, &owner, 0).expect_success();
    let small_root = pool.get("commitment_root");

    let (_, bytes) = output_data(0);
    let hundred_body =
        note_body_commitment(owner, amount_field(100 * TOS), output_data_hash(&bytes));
    let hundred_leaf = note_commitment(hundred_body, amount_field(0));
    assert_ne!(
        small_root,
        dec(&naive_root(&[hundred_leaf])),
        "a one-TOS deposit produced the note of a hundred-TOS one"
    );
    assert_eq!(small_root, dec(&naive_root(&pool.leaves)), "the note is not the admitted amount's");

    // And the leaf index is the contract's: the same note deposited twice sits
    // at two indices and hashes differently.
    pool.deposit(TOS, &owner, 0).expect_success();
    assert_eq!(pool.get("commitment_root"), dec(&naive_root(&pool.leaves)));
    assert_ne!(pool.leaves[0], pool.leaves[1], "the leaf index does not reach the commitment");
}

#[test]
fn a_message_that_cannot_pay_for_its_own_gas_never_reaches_the_pools_balance() {
    let mut pool = Pool::deploy();
    let before = pool.balance();
    let (payload, _) = output_data(0);

    // Well formed, and carrying exactly a thousand gas against a path that
    // needs six figures. The value is derived from this chain's price rather
    // than written down, because a price change would otherwise turn this
    // into a message that can afford the path and the test would pass for the
    // wrong reason. Note where the harm would be: a message that passes the
    // funding rule has necessarily bought enough gas for the whole ceiling, so
    // no accepted deposit can run out. The only thing an ACCEPT buys an
    // attacker is carrying a message that CANNOT pay past the point where it
    // would have stopped -- so the case has to be a message that never gets
    // that far.
    let result = pool.send(compute_fee(1_000), deposit_body(TOS, &[3u8; 32], payload));
    let vm = compute_phase(&result);
    let used: i64 = vm.gas_used.to_string().parse().expect("gas used");
    assert!(used > 0, "instrument check: the VM must have executed something");
    assert_eq!(
        vm.exit_code, -14,
        "the message must die on the gas it bought ({used} used), not on a later check; an exit \
         from deeper in the contract means it was handed gas it did not pay for"
    );
    assert!(
        pool.balance() >= before,
        "the pool funded a message that could not pay for itself: {before} -> {}",
        pool.balance()
    );
    assert_eq!(pool.get("native_liability"), "0", "a starved message was credited");
    assert_eq!(pool.get("commitment_next_index"), "0", "a starved message appended a leaf");
    pool.assert_backed("after a starved deposit");
}

#[test]
fn the_gas_ceiling_does_not_depend_on_how_much_money_arrived() {
    let mut pool = Pool::deploy();
    let (payload, _) = output_data(0);

    // A hundred TOS buys a quarter of a billion gas at the sandbox's price.
    // The ceiling is what the handler runs under, not that.
    let result =
        pool.send(100 * TOS + deposit_compute_fee(), deposit_body(100 * TOS, &[1u8; 32], payload));
    result.expect_success();
    let vm = compute_phase(&result);
    let used: i64 = vm.gas_used.to_string().parse().expect("gas used");
    // Measured at 127,425 on this executor, so the path fits its ceiling with
    // about four times the room. The number is not pinned exactly: what has to
    // hold is that it fits.
    assert!(
        used < deposit_gas_ceiling(),
        "the largest legal deposit uses {used} gas and does not fit its own ceiling"
    );

    // Section 14's deployment invariant, in full:
    //
    //     MEASURED_MAX_VALID_GAS < operation_gas_ceiling <= workchain gas_limit
    //
    // The middle term is the contract's own and the right one is the chain's.
    // A ceiling above what the chain grants buys nothing, because SETGASLIMIT
    // cannot raise a transaction above the network's limit; a ceiling below
    // what the path needs stops the path. Both halves are asserted here rather
    // than left to whoever next changes one of the three numbers.
    let deposit_ceiling = deposit_gas_ceiling();
    let topup_ceiling = topup_gas_ceiling();
    assert!(
        deposit_ceiling <= BASECHAIN_GAS_LIMIT,
        "the deposit ceiling ({deposit_ceiling}) is above what this chain grants a \
         transaction ({BASECHAIN_GAS_LIMIT}), so it can never take effect"
    );
    assert!(
        topup_ceiling <= BASECHAIN_GAS_LIMIT,
        "the top-up ceiling ({topup_ceiling}) is above what this chain grants a transaction"
    );
    // And the frozen ceiling still satisfies the rule it was frozen by:
    // C = max(10,000, round_up_10,000(ceil(M * 5 / 4))). A top-up's measured
    // maximum is far below the floor, so the floor is what binds.
    let by_rule = |measured: i64| -> i64 {
        let with_headroom = (measured * 5 + 3) / 4;
        10_000.max((with_headroom + 9_999) / 10_000 * 10_000)
    };
    assert_eq!(
        topup_ceiling,
        by_rule(TOPUP_DERIVED_BOUND_GAS),
        "the top-up ceiling is no longer the one the production rule gives"
    );
    assert_eq!(
        deposit_ceiling,
        by_rule(DEPOSIT_DERIVED_BOUND_GAS),
        "the deposit ceiling is no longer the one the production rule gives"
    );

    // What this does NOT establish, stated so it is not mistaken for evidence:
    // the transaction description records the admission limit, which is the
    // lesser of the config limit and what the message value bought, and it is
    // not updated by SETGASLIMIT. So the recorded limit here is the config's,
    // not the ceiling.
    let recorded: i64 = vm.gas_limit.to_string().parse().expect("gas limit");
    assert!(
        recorded >= used,
        "the recorded admission limit is below the gas actually used, which cannot happen"
    );

    // No legal deposit workload comes near 500,000 gas, so nothing here can be
    // made to exceed the ceiling and the cap's protective effect is not
    // observable from a passing transaction. A mutation proves the call is
    // live -- lowering the ceiling below what the path needs turns every
    // deposit red -- but REMOVING it entirely changes nothing this suite can
    // see. Section 19 gate 24 is therefore not closed by this file.
}

#[test]
fn a_deposit_must_fund_its_principal_and_its_execution() {
    let mut pool = Pool::deploy();
    let before = pool.balance();
    let (payload, _) = output_data(0);

    // Exactly the principal, nothing for execution.
    pool.send(TOS, deposit_body(TOS, &[5u8; 32], payload.clone())).expect_exit_code(203);
    // One nanotos short of the whole requirement.
    pool.send(TOS + deposit_compute_fee() - 1, deposit_body(TOS, &[5u8; 32], payload.clone()))
        .expect_exit_code(203);
    // And the boundary itself is enough.
    pool.send(TOS + deposit_compute_fee(), deposit_body(TOS, &[5u8; 32], payload)).expect_success();

    assert_eq!(pool.get("native_liability"), TOS.to_string(), "only the funded deposit counted");
    assert!(pool.balance() > before, "the accepted deposit did not add its principal");
    pool.assert_backed("after a refused and an accepted deposit");
}

#[test]
fn only_a_configured_denomination_and_the_frozen_body_shape_are_accepted() {
    let mut pool = Pool::deploy();
    let owner = [2u8; 32];
    let (payload, _) = output_data(0);

    // An amount that is not on the list, one either side of one that is.
    for amount in [TOS + 1, TOS - 1, 5 * TOS] {
        pool.send(amount + deposit_compute_fee(), deposit_body(amount, &owner, payload.clone()))
            .expect_exit_code(202);
    }

    // A body with a trailing bit, and one with a second reference.
    let mut trailing = BuilderData::new();
    trailing.append_u32(OP_DEPOSIT).unwrap();
    trailing.append_u64(1).unwrap();
    store_coins(&mut trailing, TOS as u128);
    trailing.append_raw(&owner, 256).unwrap();
    trailing.append_bit_zero().unwrap();
    trailing.checked_append_reference(payload.clone()).unwrap();
    pool.send(TOS + deposit_compute_fee(), trailing.into_cell().unwrap()).expect_exit_code(200);

    let mut two_refs = BuilderData::new();
    two_refs.append_u32(OP_DEPOSIT).unwrap();
    two_refs.append_u64(1).unwrap();
    store_coins(&mut two_refs, TOS as u128);
    two_refs.append_raw(&owner, 256).unwrap();
    two_refs.checked_append_reference(payload.clone()).unwrap();
    two_refs.checked_append_reference(Cell::default()).unwrap();
    pool.send(TOS + deposit_compute_fee(), two_refs.into_cell().unwrap()).expect_exit_code(200);

    // And a body with no payload at all. This is the half of the reference
    // rule that fires on its own: too many references is caught by nothing
    // being left over, but none at all has no payload to hash, and it must be
    // this contract that says so rather than a cell underflow.
    let mut no_ref = BuilderData::new();
    no_ref.append_u32(OP_DEPOSIT).unwrap();
    no_ref.append_u64(1).unwrap();
    store_coins(&mut no_ref, TOS as u128);
    no_ref.append_raw(&owner, 256).unwrap();
    pool.send(TOS + deposit_compute_fee(), no_ref.into_cell().unwrap()).expect_exit_code(200);

    // An operation this contract does not have. It has to be one of none of
    // them: OP_TRANSACT used to stand in here, and once transact was built
    // this case stopped testing the dispatch and started testing that
    // handler's body shape instead.
    assert!(
        ![OP_DEPOSIT, OP_TRANSACT, OP_RESERVE_TOPUP].contains(&OP_UNKNOWN),
        "the unknown operation is one the contract has"
    );
    let mut other = BuilderData::new();
    other.append_u32(OP_UNKNOWN).unwrap();
    pool.send(TOS + deposit_compute_fee(), other.into_cell().unwrap()).expect_exit_code(201);

    assert_eq!(pool.get("commitment_next_index"), "0", "a refused message appended a leaf");
    assert_eq!(pool.get("native_liability"), "0", "a refused message was credited");
    pool.assert_backed("after refusals");
}

/// Sections 12.3 and 16.4: reserve without a note.
#[test]
fn a_reserve_top_up_adds_balance_and_nothing_else() {
    let mut pool = Pool::deploy();
    pool.deposit(TOS, &[8u8; 32], 0).expect_success();
    let root = pool.get("commitment_root");
    let liability = pool.get("native_liability");
    let index = pool.get("commitment_next_index");
    let before = pool.balance();

    let mut body = BuilderData::new();
    body.append_u32(OP_RESERVE_TOPUP).unwrap();
    body.append_u64(7).unwrap();
    let top_up = body.into_cell().unwrap();
    let result = pool.send(4 * TOS, top_up.clone());
    result.expect_success();
    // The measurement the top-up ceiling's rule is applied to. The rule's
    // floor is far above it, so this does not move the ceiling -- it is
    // printed and checked so that the number in the contract's comment is one
    // something still produces.
    let used: i64 = compute_phase(&result).gas_used.to_string().parse().expect("gas used");
    eprintln!("a reserve top-up: {used} gas");

    // The same measurement on the configuration section 12.1 actually deploys,
    // which is four denominations rather than the three most of this file
    // uses -- and it comes first, because it is the reason the number below
    // may be pinned from a three-denomination pool at all.
    //
    // The deposit and transact maxima were both wrong for a while because they
    // were taken against a shorter list: the contract walks it to validate an
    // amount. So "measured on the deployed configuration" is a claim to check,
    // not to assert in a comment. Here it holds for a reason worth writing
    // down: `handle_reserve_topup` never parses the state cell, and
    // `recv_internal` does not parse it before dispatching, so this path has
    // no read of the configuration to grow. The day someone adds one, these
    // two stop being equal, and the pinned figure below stops meaning what it
    // says.
    let mut deployed = Pool::deploy_with(&DEPLOYED_DENOMINATIONS);
    deployed.deposit(TOS, &[8u8; 32], 0).expect_success();
    let on_deployed = deployed.send(4 * TOS, top_up.clone());
    on_deployed.expect_success();
    let deployed_used: i64 =
        compute_phase(&on_deployed).gas_used.to_string().parse().expect("gas used");
    assert_eq!(
        deployed_used, used,
        "a top-up costs {deployed_used} gas on the deployed four denominations against {used} \
         on three, so this path now reads the configuration and the figure the ceiling was \
         ruled from was taken on the wrong pool"
    );

    assert_eq!(
        used, TOPUP_DERIVED_BOUND_GAS,
        "a top-up costs {used} gas, not the {TOPUP_DERIVED_BOUND_GAS} the ceiling was ruled from"
    );

    assert!(pool.balance() > before + 3 * TOS, "the top-up did not become balance");
    assert_eq!(pool.get("native_liability"), liability, "a top-up became liability");
    assert_eq!(pool.get("commitment_root"), root, "a top-up moved the tree");
    assert_eq!(pool.get("commitment_next_index"), index, "a top-up assigned a leaf");
    pool.assert_backed("after a top-up");

    // It still has to pay for its own bounded compute. The funding rule is
    // msg_value >= get_compute_fee(0, ceiling); on this chain's schedule the
    // flat segment costs exactly its own gas at the same price, so that comes
    // to the ceiling times the price per gas. The pair of sends below is what
    // checks that identity: if it were wrong, one of them would not behave.
    let fee = compute_fee(topup_gas_ceiling() as u64);
    pool.send(fee - 1, top_up.clone()).expect_exit_code(203);
    pool.send(fee, top_up).expect_success();

    // And it carries no payload: a reference or a trailing bit is a different
    // message.
    let mut with_ref = BuilderData::new();
    with_ref.append_u32(OP_RESERVE_TOPUP).unwrap();
    with_ref.append_u64(7).unwrap();
    with_ref.checked_append_reference(Cell::default()).unwrap();
    pool.send(4 * TOS, with_ref.into_cell().unwrap()).expect_exit_code(200);

    let mut trailing = BuilderData::new();
    trailing.append_u32(OP_RESERVE_TOPUP).unwrap();
    trailing.append_u64(7).unwrap();
    trailing.append_bit_zero().unwrap();
    pool.send(4 * TOS, trailing.into_cell().unwrap()).expect_exit_code(200);

    assert_eq!(pool.get("native_liability"), liability, "a refused top-up changed liability");
    pool.assert_backed("after refused top-ups");
}

#[test]
fn a_plain_top_up_and_a_bounce_change_no_shielded_state() {
    let mut pool = Pool::deploy();
    pool.deposit(TOS, &[4u8; 32], 0).expect_success();
    let root = pool.get("commitment_root");
    let liability = pool.get("native_liability");
    let before = pool.balance();

    // A message with no body at all: the pool takes the money as reserve.
    pool.send(3 * TOS, Cell::default()).expect_success();
    assert_eq!(pool.get("commitment_root"), root, "a top-up moved the tree");
    assert_eq!(pool.get("native_liability"), liability, "a top-up became liability");
    assert!(pool.balance() > before, "the top-up did not arrive");
    pool.assert_backed("after a top-up");
}
