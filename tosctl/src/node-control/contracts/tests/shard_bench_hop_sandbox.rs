/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Sandbox (offline TVM, real action phase) tests for the shard-scaling bench
//! contract `bench/shard/hop.fc`.
//!
//! Every hop the contract sends uses a send mode that ignores action errors,
//! so an action phase can report success while a send was skipped. These
//! tests therefore check what each transaction actually emitted: the number
//! of messages, their destinations, values, StateInit and bodies, the action
//! phase's skipped-action count, and the sender's balance afterwards.

use chain_block::{
    BuilderData, Cell, IBitstring, Message, MsgAddressInt, Serializable, SliceData, StateInit,
    TrComputePhase, Transaction, TransactionDescr,
};
use tos_sandbox::{Blockchain, MessageBuilder, Treasury, compile_func_with_stdlib};

#[path = "fixtures/current_network.rs"]
mod current_network;

const TOS: u64 = 1_000_000_000;
const OP_DEPLOY: u32 = 0x6470_6c79;
const OP_START: u32 = 0x7374_6172;
const OP_HOP: u32 = 0x686f_7031;
const FLAG_WITH_INIT: u8 = 1;
const FLAG_VERIFY_SENDER: u8 = 2;
const ERR_BAD_RANGE: i32 = 101;
const ERR_BAD_PARAMS: i32 = 102;
const ERR_BAD_SENDER: i32 = 103;
const SALT: u64 = 0x5eed_0000_0000_0001;
const ACCOUNTS: u32 = 8;
const FUNDING: u64 = TOS;

fn hop_code() -> Cell {
    let source =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../bench/shard/hop.fc");
    compile_func_with_stdlib(&[source])
        .expect("compile bench/shard/hop.fc (needs build/crypto/func and fift)")
}

#[derive(Clone, Copy)]
struct Params {
    remaining: u32,
    forks: u8,
    local: u16,
    depth: u8,
    deadline: u32,
    accounts: u32,
    flags: u8,
}

fn params(b: &mut BuilderData, p: &Params, payload: Option<&Cell>) {
    b.append_u32(p.remaining).unwrap();
    b.append_u8(p.forks).unwrap();
    b.append_u16(p.local).unwrap();
    b.append_u8(p.depth).unwrap();
    b.append_u32(p.deadline).unwrap();
    b.append_u32(p.accounts).unwrap();
    b.append_u8(p.flags).unwrap();
    match payload {
        Some(cell) => {
            b.append_bit_one().unwrap();
            b.checked_append_reference(cell.clone()).unwrap();
        }
        None => {
            b.append_bit_zero().unwrap();
        }
    }
}

fn start_body(chains: u8, p: &Params, payload: Option<&Cell>) -> Cell {
    let mut b = BuilderData::new();
    b.append_u32(OP_START).unwrap();
    b.append_u8(chains).unwrap();
    params(&mut b, p, payload);
    b.into_cell().unwrap()
}

fn hop_body(from: u32, p: &Params, payload: Option<&Cell>) -> Cell {
    let mut b = BuilderData::new();
    b.append_u32(OP_HOP).unwrap();
    b.append_u32(from).unwrap();
    params(&mut b, p, payload);
    b.into_cell().unwrap()
}

fn deploy_body(lo: u32, hi: u32) -> Cell {
    let mut b = BuilderData::new();
    b.append_u32(OP_DEPLOY).unwrap();
    b.append_u32(lo).unwrap();
    b.append_u32(hi).unwrap();
    b.into_cell().unwrap()
}

/// A hop body as the contract wrote it, field by field.
#[derive(Debug, PartialEq)]
struct HopBody {
    from: u32,
    remaining: u32,
    forks: u8,
    local: u16,
    depth: u8,
    deadline: u32,
    accounts: u32,
    flags: u8,
    payload: Option<Cell>,
}

fn read_hop(message: &Message) -> HopBody {
    let mut s: SliceData = message.body().cloned().expect("a hop carries a body");
    assert_eq!(s.get_next_u32().unwrap(), OP_HOP, "a forwarded message is a hop");
    let from = s.get_next_u32().unwrap();
    let remaining = s.get_next_u32().unwrap();
    let forks = s.get_next_byte().unwrap();
    let local = s.get_next_u16().unwrap();
    let depth = s.get_next_byte().unwrap();
    let deadline = s.get_next_u32().unwrap();
    let accounts = s.get_next_u32().unwrap();
    let flags = s.get_next_byte().unwrap();
    let payload =
        if s.get_next_bit().unwrap() { Some(s.checked_drain_reference().unwrap()) } else { None };
    assert_eq!(s.remaining_bits(), 0, "nothing follows the hop fields");
    HopBody { from, remaining, forks, local, depth, deadline, accounts, flags, payload }
}

/// What one real transaction did: its compute result, its action phase and
/// the messages it emitted.
struct Outcome {
    aborted: bool,
    exit_code: Option<i32>,
    skipped_actions: i16,
    msgs_created: i16,
    outbound: Vec<Message>,
}

fn outcome(transaction: &Transaction, outbound: Vec<Message>) -> Outcome {
    let TransactionDescr::Ordinary(description) = transaction.read_description().unwrap() else {
        panic!("expected an ordinary transaction");
    };
    let exit_code = match description.compute_ph {
        TrComputePhase::Vm(vm) => Some(vm.exit_code),
        TrComputePhase::Skipped(_) => None,
    };
    let (skipped_actions, msgs_created) = match description.action {
        Some(action) => {
            assert!(action.success, "the action phase must succeed: {action:?}");
            (action.skipped_actions, action.msgs_created)
        }
        None => (0, 0),
    };
    Outcome { aborted: description.aborted, exit_code, skipped_actions, msgs_created, outbound }
}

fn value(message: &Message) -> u64 {
    message.int_header().expect("internal message").value.coins.as_u64().unwrap()
}

fn hash_bytes(address: &MsgAddressInt) -> Vec<u8> {
    let mut hash = address.address().clone();
    hash.get_next_bytes(32).unwrap()
}

struct Fixture {
    bc: Blockchain,
    treasury: Treasury,
    code: Cell,
}

impl Fixture {
    fn new() -> Self {
        let mut bc =
            Blockchain::with_global_version_and_base_workchain(current_network::global_version())
                .expect("blockchain");
        let treasury = bc.treasury("hop-funder", 1_000_000 * TOS).expect("treasury");
        Fixture { bc, treasury, code: hop_code() }
    }

    fn state_init(&self, id: u32) -> StateInit {
        let mut data = BuilderData::new();
        data.append_u32(id).unwrap();
        data.append_u64(SALT).unwrap();
        data.checked_append_reference(self.code.clone()).unwrap();
        StateInit::with_code_and_data(self.code.clone(), data.into_cell().unwrap())
    }

    fn address(&self, id: u32) -> MsgAddressInt {
        let hash = self.state_init(id).write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
        MsgAddressInt::with_params(0, hash).unwrap()
    }

    fn id_of(&self, address: &MsgAddressInt) -> u32 {
        (0..ACCOUNTS)
            .find(|id| &self.address(*id) == address)
            .unwrap_or_else(|| panic!("{address} is not a copy of this family"))
    }

    fn balance(&self, address: &MsgAddressInt) -> u64 {
        self.bc
            .get_account(address)
            .expect("account")
            .balance()
            .expect("balance")
            .coins
            .as_u64()
            .unwrap()
    }

    fn is_active(&self, address: &MsgAddressInt) -> bool {
        self.bc.get_account(address).and_then(|a| a.state_init()).and_then(|s| s.code()).is_some()
    }

    /// Deploys copies 0 .. ACCOUNTS-1 through the contract's own deployment tree.
    fn deploy(&mut self) {
        let message = MessageBuilder::internal(
            self.treasury.address(),
            &self.address(0),
            ACCOUNTS as u64 * FUNDING,
        )
        .bounce(false)
        .state_init(self.state_init(0))
        .body(deploy_body(0, ACCOUNTS))
        .build();
        let result = self.bc.send_message(message).expect("deployment");
        for (at, transaction) in &result.transactions {
            let o = outcome(transaction, Vec::new());
            assert!(!o.aborted, "deployment transaction at {at} aborted ({:?})", o.exit_code);
            assert_eq!(o.skipped_actions, 0, "deployment at {at} skipped a send");
        }
        // The root and each copy it or its subtree deployed: one transaction per copy.
        assert_eq!(result.transaction_count(), ACCOUNTS as usize);
    }

    fn execute(&mut self, message: Message) -> Outcome {
        let (_, transaction, outbound) = self.bc.execute_one(message).expect("execute");
        outcome(&transaction, outbound)
    }

    fn from_treasury(&self, to: u32, body: Cell, value: u64) -> Message {
        MessageBuilder::internal(self.treasury.address(), &self.address(to), value)
            .bounce(false)
            .body(body)
            .build()
    }
}

fn light(remaining: u32, forks: u8, deadline: u32) -> Params {
    Params { remaining, forks, local: 0, depth: 0, deadline, accounts: ACCOUNTS, flags: 0 }
}

#[test]
fn deployment_tree_activates_every_copy_with_its_share() {
    let mut f = Fixture::new();
    f.deploy();
    for id in 0..ACCOUNTS {
        let address = f.address(id);
        assert!(f.is_active(&address), "copy {id} is deployed");
        let balance = f.balance(&address);
        // Each copy keeps its share less the fees of its own deployment step.
        assert!(balance > FUNDING / 2 && balance <= FUNDING, "copy {id} holds {balance}");
    }
}

#[test]
fn deployment_refuses_a_range_that_is_not_its_own() {
    let mut f = Fixture::new();
    f.deploy();
    let o = f.execute(f.from_treasury(3, deploy_body(2, 8), TOS));
    assert!(o.aborted);
    assert_eq!(o.exit_code, Some(ERR_BAD_RANGE));
    assert!(o.outbound.is_empty());
}

#[test]
fn start_launches_every_chain_and_keeps_the_root_balance() {
    let mut f = Fixture::new();
    f.deploy();
    let root = f.address(0);
    let before = f.balance(&root);
    let deadline = f.bc.now() + 100;
    let p = light(5, 2, deadline);
    let load = 30 * TOS;
    let o = f.execute(f.from_treasury(0, start_body(3, &p, None), load));
    assert!(!o.aborted, "start aborted ({:?})", o.exit_code);
    assert_eq!((o.skipped_actions, o.msgs_created), (0, 3));
    assert_eq!(o.outbound.len(), 3);
    let mut sent = 0;
    for message in &o.outbound {
        f.id_of(&message.dst().unwrap());
        assert!(message.state_init().is_none(), "light hops carry no StateInit");
        let hop = read_hop(message);
        assert_eq!(
            hop,
            HopBody {
                from: 0,
                remaining: 5,
                forks: 2,
                local: 0,
                depth: 0,
                deadline,
                accounts: ACCOUNTS,
                flags: 0,
                payload: None
            }
        );
        sent += value(message);
    }
    // The chains carry the load value, net of fees; the root keeps its own balance.
    assert!(sent > load * 9 / 10 && sent < load, "chains carry {sent} of {load}");
    let after = f.balance(&root);
    assert!(after <= before && after > before - TOS / 100, "root balance {before} -> {after}");
}

#[test]
fn a_hop_forks_in_two_then_forwards_one_and_keeps_each_balance() {
    let mut f = Fixture::new();
    f.deploy();
    let deadline = f.bc.now() + 100;
    let start =
        f.execute(f.from_treasury(0, start_body(1, &light(4, 1, deadline), None), 10 * TOS));
    let first = start.outbound[0].clone();
    let at = first.dst().unwrap();
    let id = f.id_of(&at);
    let before = f.balance(&at);
    let carried = value(&first);

    let fork = f.execute(first);
    assert!(!fork.aborted, "fork aborted ({:?})", fork.exit_code);
    assert_eq!((fork.skipped_actions, fork.msgs_created), (0, 2));
    for message in &fork.outbound {
        f.id_of(&message.dst().unwrap());
        let hop = read_hop(message);
        assert_eq!((hop.from, hop.remaining, hop.forks), (id, 3, 0));
    }
    let halves: Vec<u64> = fork.outbound.iter().map(value).collect();
    assert_eq!(halves[0], carried / 2, "the first child carries half the incoming value");
    assert!(halves[1] > carried / 4 && halves[1] < carried / 2, "the second carries the rest");
    let after = f.balance(&at);
    assert!(after <= before && after > before - TOS / 100, "fork balance {before} -> {after}");

    let next = fork.outbound[0].clone();
    let forward = f.execute(next);
    assert!(!forward.aborted);
    assert_eq!((forward.skipped_actions, forward.msgs_created), (0, 1));
    assert_eq!(read_hop(&forward.outbound[0]).remaining, 2);
}

#[test]
fn a_chain_ends_at_zero_remaining_and_after_its_deadline() {
    let mut f = Fixture::new();
    f.deploy();
    let now = f.bc.now();
    let spent = f.execute(f.from_treasury(2, hop_body(1, &light(0, 0, now + 100), None), TOS));
    assert!(!spent.aborted && spent.outbound.is_empty() && spent.msgs_created == 0);
    let late = f.execute(f.from_treasury(2, hop_body(1, &light(5, 0, now - 1), None), TOS));
    assert!(!late.aborted && late.outbound.is_empty() && late.msgs_created == 0);
}

#[test]
fn local_hops_stay_in_their_shard() {
    let mut f = Fixture::new();
    f.deploy();
    let deadline = f.bc.now() + 100;
    let p = Params {
        remaining: 40,
        forks: 0,
        local: 65535,
        depth: 1,
        deadline,
        accounts: ACCOUNTS,
        flags: 0,
    };
    let mut message = f.from_treasury(0, hop_body(0, &p, None), 10 * TOS);
    let mut shard = None;
    for step in 0..20 {
        let at = message.dst().unwrap();
        let here = hash_bytes(&at)[0] >> 7;
        if let Some(previous) = shard {
            assert_eq!(here, previous, "hop {step} left its shard");
        }
        shard = Some(here);
        let o = f.execute(message);
        assert!(!o.aborted && o.skipped_actions == 0 && o.outbound.len() == 1, "hop {step}");
        message = o.outbound[0].clone();
    }
}

#[test]
fn with_init_attaches_the_target_state_init() {
    let mut f = Fixture::new();
    f.deploy();
    let deadline = f.bc.now() + 100;
    let mut p = light(3, 0, deadline);
    p.flags = FLAG_WITH_INIT;
    let o = f.execute(f.from_treasury(0, start_body(2, &p, None), 5 * TOS));
    assert_eq!((o.skipped_actions, o.outbound.len()), (0, 2));
    for message in &o.outbound {
        let id = f.id_of(&message.dst().unwrap());
        let init = message.state_init().expect("a with-init hop carries the StateInit");
        assert_eq!(init, &f.state_init(id));
        assert_eq!(read_hop(message).flags, FLAG_WITH_INIT);
    }
}

#[test]
fn the_payload_rides_every_hop_unchanged() {
    let mut f = Fixture::new();
    f.deploy();
    let deadline = f.bc.now() + 100;
    let mut payload = BuilderData::new();
    payload.append_raw(&[0xA5; 100], 800).unwrap();
    let payload = payload.into_cell().unwrap();
    let start = f.execute(f.from_treasury(
        0,
        start_body(1, &light(3, 1, deadline), Some(&payload)),
        5 * TOS,
    ));
    let fork = f.execute(start.outbound[0].clone());
    assert_eq!(fork.outbound.len(), 2);
    for message in fork.outbound.iter().chain(start.outbound.iter()) {
        assert_eq!(read_hop(message).payload.map(|c| c.repr_hash()), Some(payload.repr_hash()));
    }
}

#[test]
fn verify_sender_accepts_the_named_copy_and_refuses_anyone_else() {
    let mut f = Fixture::new();
    f.deploy();
    let deadline = f.bc.now() + 100;
    let mut p = light(4, 0, deadline);
    p.flags = FLAG_VERIFY_SENDER;
    // A genuine chain: the start sends hops from copy 0 that name copy 0.
    let start = f.execute(f.from_treasury(0, start_body(1, &p, None), 5 * TOS));
    let genuine = f.execute(start.outbound[0].clone());
    assert!(!genuine.aborted, "a genuine hop is accepted ({:?})", genuine.exit_code);
    assert_eq!(genuine.outbound.len(), 1);
    // A hop from the treasury naming copy 3 is refused with the flag set ...
    let forged = f.execute(f.from_treasury(5, hop_body(3, &p, None), TOS));
    assert!(forged.aborted);
    assert_eq!(forged.exit_code, Some(ERR_BAD_SENDER));
    assert!(forged.outbound.is_empty());
    // ... and accepted without it: the check is the flag, not an accident.
    let unchecked = f.execute(f.from_treasury(5, hop_body(3, &light(4, 0, deadline), None), TOS));
    assert!(!unchecked.aborted && unchecked.outbound.len() == 1);
}

#[test]
fn unknown_flags_are_refused() {
    let mut f = Fixture::new();
    f.deploy();
    let mut p = light(4, 0, f.bc.now() + 100);
    p.flags = 4;
    let o = f.execute(f.from_treasury(0, start_body(1, &p, None), TOS));
    assert!(o.aborted);
    assert_eq!(o.exit_code, Some(ERR_BAD_PARAMS));
}
