/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! The multisig wallet (crypto/smartcont/multisig-wallet-code.fc) deploys one order contract
//! (multisig-order-code.fc) per proposal. These tests compile both sources and drive the
//! whole message flow in the sandbox: proposal, deployment, approvals and their replies,
//! execution, parameter updates that make older orders stale, expiry, and forged or
//! malformed messages at every step.

use chain_block::{
    BuilderData, Cell, CurrencyCollection, Deserializable, IBitstring, InternalMessageHeader,
    Message, MsgAddressInt, Serializable, SliceData, StateInit,
};
use tos_sandbox::{Blockchain, MessageBuilder, SendResult, Treasury, compile_func_with_stdlib};
use tos_vm::stack::StackItem;

const TOS: u64 = 1_000_000_000;
const NOW: u32 = 1_800_000_000;
const DAY: u32 = 86_400;

const OP_NEW_ORDER: u32 = 0x27bace9f;
const OP_APPROVE: u32 = 0x9c205aee;
const OP_EXECUTE: u32 = 0xe71e90bc;
const OP_APPROVE_ACCEPTED: u32 = 0xcbd6e9fd;
const OP_APPROVE_REJECTED: u32 = 0x3f9143b6;
const OP_RECLAIM: u32 = 0xc79429cd;
const OP_EXECUTE_INTERNAL: u32 = 0xead7f19d;
const ACTION_SEND: u32 = 0x94f8724f;
const ACTION_UPDATE: u32 = 0xe9973598;
const NEXT_SEQNO: u64 = u64::MAX;

const ERROR_INVALID_CONFIG: i32 = 0x1a01;
const ERROR_INVALID_SEQNO: i32 = 0x1a02;
const ERROR_UNKNOWN_SIGNER: i32 = 0x1a03;
const ERROR_ALREADY_APPROVED: i32 = 0x1a04;
const ERROR_ALREADY_EXECUTED: i32 = 0x1a05;
const ERROR_EXPIRED: i32 = 0x1a06;
const ERROR_UNAUTHORIZED_EXECUTE: i32 = 0x1a07;
const ERROR_STALE_SIGNERS: i32 = 0x1a08;
const ERROR_UNAUTHORIZED_PROPOSER: i32 = 0x1a0a;
const ERROR_INSUFFICIENT_VALUE: i32 = 0x1a0d;
const ERROR_INVALID_ACTION: i32 = 0x1a0e;
const ERROR_UNAUTHORIZED_INIT: i32 = 0x1a0f;
const ERROR_ALREADY_INITIALIZED: i32 = 0x1a10;
const ERROR_NOT_INITIALIZED: i32 = 0x1a11;
const ERROR_NOT_RECLAIMABLE: i32 = 0x1a12;

fn smartcont(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../crypto/smartcont").join(name)
}

fn cell(build: impl FnOnce(&mut BuilderData)) -> Cell {
    let mut b = BuilderData::new();
    build(&mut b);
    b.into_cell().expect("cell")
}

fn address_dict(entries: &[(u8, &MsgAddressInt)]) -> Option<Cell> {
    let mut dict = chain_block::HashmapE::with_bit_len(8);
    for (index, address) in entries {
        let key = SliceData::load_builder(BuilderData::with_raw(vec![*index], 8).unwrap()).unwrap();
        let value = SliceData::load_cell(address.serialize().unwrap()).unwrap();
        dict.set(key, &value).unwrap();
    }
    chain_block::HashmapType::data(&dict).cloned()
}

/// An outbound message as the multisig sends it: src addr_none, inline empty body.
fn transfer(dest: &MsgAddressInt, value: u64) -> Cell {
    let header = InternalMessageHeader {
        bounce: false,
        dst: dest.clone(),
        value: CurrencyCollection::with_coins(value),
        ..Default::default()
    };
    Message::with_int_header_and_body(header, SliceData::load_cell(Cell::default()).unwrap())
        .serialize_as_is()
        .unwrap()
        .0
        .into_cell()
        .unwrap()
}

fn send_action(message: Cell, next: Option<Cell>) -> Cell {
    cell(|b| {
        b.append_u32(ACTION_SEND).unwrap();
        b.append_u8(1).unwrap(); // pay fees separately
        b.checked_append_reference(message).unwrap();
        append_maybe_ref(b, next);
    })
}

fn update_action(
    threshold: u8,
    signers: Cell,
    proposers: Option<Cell>,
    next: Option<Cell>,
) -> Cell {
    cell(|b| {
        b.append_u32(ACTION_UPDATE).unwrap();
        b.append_u8(threshold).unwrap();
        b.checked_append_reference(signers).unwrap();
        append_maybe_ref(b, proposers);
        append_maybe_ref(b, next);
    })
}

fn append_maybe_ref(b: &mut BuilderData, value: Option<Cell>) {
    match value {
        Some(c) => {
            b.append_bits(1, 1).unwrap();
            b.checked_append_reference(c).unwrap();
        }
        None => {
            b.append_bits(0, 1).unwrap();
        }
    }
}

struct Fixture {
    bc: Blockchain,
    multisig: MsgAddressInt,
    order_code: Cell,
    signers: Vec<Treasury>,
    proposer: Treasury,
    outsider: Treasury,
    target: Treasury,
}

impl Fixture {
    fn new() -> Self {
        Self::with_threshold(2)
    }

    fn with_threshold(threshold: u8) -> Self {
        Self::with_wallet(threshold, 0)
    }

    /// A wallet whose signers are alice, bob, carol and `extra_signers` more addresses.
    fn with_wallet(threshold: u8, extra_signers: u8) -> Self {
        let mut bc = Blockchain::with_global_version_and_base_workchain(14).expect("blockchain");
        bc.set_now(NOW);
        let funder = bc.treasury("funder", 10_000 * TOS).expect("funder");
        let signers: Vec<Treasury> = ["alice", "bob", "carol"]
            .iter()
            .map(|n| bc.treasury(n, 1_000 * TOS).expect("signer"))
            .collect();
        let proposer = bc.treasury("dave", 1_000 * TOS).expect("proposer");
        let outsider = bc.treasury("eve", 1_000 * TOS).expect("outsider");
        let target = bc.treasury("target", 1_000 * TOS).expect("target");
        let order_code = compile_func_with_stdlib(&[smartcont("multisig-order-code.fc")])
            .expect("compile order");
        let wallet_code = compile_func_with_stdlib(&[smartcont("multisig-wallet-code.fc")])
            .expect("compile multisig");
        let extra: Vec<MsgAddressInt> = (0..extra_signers)
            .map(|i| {
                let mut account = [0x60u8; 32];
                account[31] = i;
                MsgAddressInt::with_params(0, chain_block::UInt256::from(account)).unwrap()
            })
            .collect();
        let mut entries: Vec<(u8, &MsgAddressInt)> =
            vec![(0, signers[0].address()), (1, signers[1].address()), (2, signers[2].address())];
        for (i, address) in extra.iter().enumerate() {
            entries.push((3 + i as u8, address));
        }
        let signer_count = entries.len() as u8;
        let signer_dict = address_dict(&entries).expect("signers");
        let proposer_dict = address_dict(&[(0, proposer.address())]);
        let data = cell(|b| {
            b.append_u64(0).unwrap();
            b.append_u8(threshold).unwrap();
            b.append_u8(signer_count).unwrap();
            b.checked_append_reference(signer_dict).unwrap();
            append_maybe_ref(b, proposer_dict);
            b.checked_append_reference(order_code.clone()).unwrap();
        });
        let init = StateInit::with_code_and_data(wallet_code, data);
        let hash = init.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
        let multisig = MsgAddressInt::with_params(0, hash).unwrap();
        let deploy = MessageBuilder::internal(funder.address(), &multisig, 500 * TOS)
            .bounce(false)
            .state_init(init)
            .build();
        bc.send_message(deploy).expect("deploy").expect_success();
        Self { bc, multisig, order_code, signers, proposer, outsider, target }
    }

    fn signer(&self, index: usize) -> MsgAddressInt {
        self.signers[index].address().clone()
    }

    fn balance(&self, address: &MsgAddressInt) -> u64 {
        self.bc
            .get_account(address)
            .and_then(|account| account.balance().cloned())
            .and_then(|balance| balance.coins.as_u64())
            .unwrap_or(0)
    }

    fn estimate(&self, actions: &Cell, expires_at: u32) -> u64 {
        let result = self
            .bc
            .run_get_method(
                &self.multisig,
                "get_order_estimate",
                vec![StackItem::cell(actions.clone()), StackItem::int(expires_at as i64)],
            )
            .expect("estimate")
            .expect_success()
            .int_at(0);
        u64::try_from(result).expect("estimate fits")
    }

    fn order_address(&self, seqno: u64) -> MsgAddressInt {
        let slice = self
            .bc
            .run_get_method(&self.multisig, "get_order_address", vec![StackItem::int(seqno as i64)])
            .expect("order address")
            .expect_success()
            .slice_at(0);
        MsgAddressInt::construct_from(&mut slice.clone()).expect("address")
    }

    fn multisig_int(&self, index: usize) -> i128 {
        self.bc
            .run_get_method(&self.multisig, "get_multisig_data", vec![])
            .expect("multisig data")
            .expect_success()
            .int_at(index)
    }

    fn order_int(&self, order: &MsgAddressInt, index: usize) -> i128 {
        self.bc
            .run_get_method(order, "get_order_data", vec![])
            .expect("order data")
            .expect_success()
            .int_at(index)
    }

    #[allow(clippy::too_many_arguments)]
    fn propose(
        &mut self,
        from: &MsgAddressInt,
        is_signer: bool,
        index: u8,
        requested_seqno: u64,
        expires_at: u32,
        actions: Cell,
        value: u64,
    ) -> SendResult {
        let body = cell(|b| {
            b.append_u32(OP_NEW_ORDER).unwrap();
            b.append_u64(1).unwrap();
            b.append_u64(requested_seqno).unwrap();
            b.append_bits(if is_signer { 1 } else { 0 }, 1).unwrap();
            b.append_u8(index).unwrap();
            b.append_u32(expires_at).unwrap();
            b.checked_append_reference(actions).unwrap();
        });
        let msg = MessageBuilder::internal(from, &self.multisig, value).body(body).build();
        self.bc.send_message(msg).expect("deliver proposal")
    }

    /// A funded proposal from the proposer, paying exactly the multisig's own quote.
    fn propose_paid(&mut self, actions: Cell) -> SendResult {
        let expires_at = self.bc.now() + DAY;
        let value = self.estimate(&actions, expires_at);
        let proposer = self.proposer.address().clone();
        self.propose(&proposer, false, 0, NEXT_SEQNO, expires_at, actions, value)
    }

    fn approve(&mut self, order: &MsgAddressInt, from: &MsgAddressInt, index: u8) -> SendResult {
        let body = cell(|b| {
            b.append_u32(OP_APPROVE).unwrap();
            b.append_u64(7).unwrap();
            b.append_u8(index).unwrap();
        });
        let msg = MessageBuilder::internal(from, order, TOS).body(body).build();
        self.bc.send_message(msg).expect("deliver approval")
    }
}

/// Exit code of the compute phase of the transaction on `address` in `result`.
fn exit_code_on(result: &SendResult, address: &MsgAddressInt) -> i32 {
    let tx = result.transactions_for(address).into_iter().next().expect("transaction on address");
    match tx.read_description().expect("description") {
        chain_block::TransactionDescr::Ordinary(d) => match d.compute_ph {
            chain_block::TrComputePhase::Vm(vm) => vm.exit_code,
            other => panic!("compute skipped: {other:?}"),
        },
        other => panic!("unexpected description {other:?}"),
    }
}

/// The reply an order sent back to an approver: (op, exit code for rejections).
fn approval_reply(result: &SendResult, order: &MsgAddressInt) -> (u32, Option<u32>) {
    let tx = result.transactions_for(order).into_iter().next().expect("order transaction");
    let mut found = None;
    tx.iterate_out_msgs(|msg| {
        if let Some(body) = msg.body() {
            let mut body = body.clone();
            let op = body.get_next_u32().unwrap();
            if op == OP_APPROVE_ACCEPTED || op == OP_APPROVE_REJECTED {
                body.get_next_u64().unwrap();
                let code = if op == OP_APPROVE_REJECTED {
                    Some(body.get_next_u32().unwrap())
                } else {
                    None
                };
                found = Some((op, code));
            }
        }
        Ok(true)
    })
    .unwrap();
    found.expect("approval reply")
}

fn assert_received(before: u64, after: u64, value: u64, what: &str) {
    let received = after.checked_sub(before).unwrap_or_else(|| panic!("{what}: balance fell"));
    assert!(
        received <= value && received + TOS / 1_000 > value,
        "{what}: received {received}, sent {value}"
    );
}

#[test]
fn proposal_approvals_and_execution() {
    let mut f = Fixture::new();
    let actions = send_action(transfer(f.target.address(), 5 * TOS), None);
    let result = f.propose_paid(actions);
    assert_eq!(exit_code_on(&result, &f.multisig), 0);
    let order = f.order_address(0);
    assert_eq!(exit_code_on(&result, &order), 0, "order must deploy and initialise");
    assert_eq!(f.multisig_int(0), 1, "seqno 0 consumed");
    assert_eq!(f.order_int(&order, 0), -1, "order initialised");
    assert_eq!(f.order_int(&order, 7), 0, "no approvals yet");

    let target_before = f.balance(f.target.address());
    let alice = f.signer(0);
    let r = f.approve(&order, &alice, 0);
    assert_eq!(approval_reply(&r, &order), (OP_APPROVE_ACCEPTED, None));
    assert_eq!(
        f.balance(f.target.address()),
        target_before,
        "one approval of two executes nothing"
    );

    let carol = f.signer(2);
    let r = f.approve(&order, &carol, 2);
    assert_eq!(approval_reply(&r, &order), (OP_APPROVE_ACCEPTED, None));
    assert_eq!(exit_code_on(&r, &f.multisig), 0, "the parent must run the execute");
    assert_received(target_before, f.balance(f.target.address()), 5 * TOS, "order payout");
    assert_eq!(f.order_int(&order, 4), -1, "order marked executed");

    // A further approval is refused with a reply, and executes nothing again.
    let bob = f.signer(1);
    let r = f.approve(&order, &bob, 1);
    assert_eq!(
        approval_reply(&r, &order),
        (OP_APPROVE_REJECTED, Some(ERROR_ALREADY_EXECUTED as u32))
    );
}

#[test]
fn a_signer_proposal_counts_as_its_approval() {
    let mut f = Fixture::new();
    let actions = send_action(transfer(f.target.address(), TOS), None);
    let expires_at = NOW + DAY;
    let value = f.estimate(&actions, expires_at);
    let bob = f.signer(1);
    f.propose(&bob, true, 1, NEXT_SEQNO, expires_at, actions, value);
    let order = f.order_address(0);
    assert_eq!(f.order_int(&order, 7), 1, "the proposing signer's approval is recorded");
    let target_before = f.balance(f.target.address());
    let alice = f.signer(0);
    f.approve(&order, &alice, 0);
    assert_received(
        target_before,
        f.balance(f.target.address()),
        TOS,
        "payout after the second approval",
    );
}

#[test]
fn a_signer_proposal_can_execute_on_its_own() {
    // With threshold 1, the proposing signer's own approval fires the order inside the
    // proposal's message cascade.
    let mut f = Fixture::with_threshold(1);
    let actions = send_action(transfer(f.target.address(), 2 * TOS), None);
    let expires_at = NOW + DAY;
    let value = f.estimate(&actions, expires_at);
    let target_before = f.balance(f.target.address());
    let carol = f.signer(2);
    let r = f.propose(&carol, true, 2, NEXT_SEQNO, expires_at, actions, value);
    let order = f.order_address(0);
    assert_eq!(exit_code_on(&r, &order), 0);
    assert_eq!(f.order_int(&order, 4), -1, "executed on init");
    assert_received(
        target_before,
        f.balance(f.target.address()),
        2 * TOS,
        "payout from the proposal alone",
    );
}

#[test]
fn proposals_are_authorised_paid_fresh_and_well_formed() {
    let mut f = Fixture::new();
    let actions = send_action(transfer(f.target.address(), TOS), None);
    let expires_at = NOW + DAY;
    let value = f.estimate(&actions, expires_at);
    let eve = f.outsider.address().clone();
    let dave = f.proposer.address().clone();
    let alice = f.signer(0);

    let r = f.propose(&eve, false, 0, NEXT_SEQNO, expires_at, actions.clone(), value);
    assert_eq!(exit_code_on(&r, &f.multisig), ERROR_UNAUTHORIZED_PROPOSER, "outsider");
    let r = f.propose(&dave, true, 0, NEXT_SEQNO, expires_at, actions.clone(), value);
    assert_eq!(
        exit_code_on(&r, &f.multisig),
        ERROR_UNAUTHORIZED_PROPOSER,
        "proposer claiming a signer slot"
    );
    let r = f.propose(&alice, false, 0, NEXT_SEQNO, expires_at, actions.clone(), value);
    assert_eq!(
        exit_code_on(&r, &f.multisig),
        ERROR_UNAUTHORIZED_PROPOSER,
        "signer claiming a proposer slot"
    );

    let r = f.propose(&dave, false, 0, NEXT_SEQNO, expires_at, actions.clone(), value / 2);
    assert_eq!(exit_code_on(&r, &f.multisig), ERROR_INSUFFICIENT_VALUE, "underpaid");
    let r = f.propose(&dave, false, 0, NEXT_SEQNO, NOW, actions.clone(), value);
    assert_eq!(exit_code_on(&r, &f.multisig), ERROR_EXPIRED, "already expired");
    let r = f.propose(&dave, false, 0, 5, expires_at, actions.clone(), value);
    assert_eq!(exit_code_on(&r, &f.multisig), ERROR_INVALID_SEQNO, "skipping ahead");

    let unknown = cell(|b| {
        b.append_u32(0x1234_5678).unwrap();
        b.append_bits(0, 1).unwrap();
    });
    let r = f.propose(&dave, false, 0, NEXT_SEQNO, expires_at, unknown, value);
    assert_eq!(exit_code_on(&r, &f.multisig), ERROR_INVALID_ACTION, "unknown action");
    let one_signer = address_dict(&[(0, &alice)]).unwrap();
    let impossible = update_action(2, one_signer, None, None);
    let r = f.propose(&dave, false, 0, NEXT_SEQNO, expires_at, impossible, value);
    assert_eq!(
        exit_code_on(&r, &f.multisig),
        ERROR_INVALID_CONFIG,
        "update to an unreachable threshold"
    );

    assert_eq!(f.multisig_int(0), 0, "no refused proposal consumed a seqno");
    // The quote is enough, and the explicit next seqno works like the wildcard.
    let r = f.propose(&dave, false, 0, 0, expires_at, actions, value);
    assert_eq!(exit_code_on(&r, &f.multisig), 0);
    assert_eq!(f.multisig_int(0), 1);
}

#[test]
fn approvals_are_checked_and_answered() {
    let mut f = Fixture::new();
    f.propose_paid(send_action(transfer(f.target.address(), TOS), None));
    let order = f.order_address(0);
    let eve = f.outsider.address().clone();
    let alice = f.signer(0);

    let r = f.approve(&order, &eve, 0);
    assert_eq!(
        approval_reply(&r, &order),
        (OP_APPROVE_REJECTED, Some(ERROR_UNKNOWN_SIGNER as u32))
    );
    let r = f.approve(&order, &alice, 1);
    assert_eq!(
        approval_reply(&r, &order),
        (OP_APPROVE_REJECTED, Some(ERROR_UNKNOWN_SIGNER as u32)),
        "wrong index"
    );
    f.approve(&order, &alice, 0);
    let r = f.approve(&order, &alice, 0);
    assert_eq!(
        approval_reply(&r, &order),
        (OP_APPROVE_REJECTED, Some(ERROR_ALREADY_APPROVED as u32))
    );
    assert_eq!(f.order_int(&order, 7), 1, "only the valid approval counts");
}

#[test]
fn expired_orders_cannot_fire() {
    let mut f = Fixture::new();
    f.propose_paid(send_action(transfer(f.target.address(), TOS), None));
    let order = f.order_address(0);
    let alice = f.signer(0);
    let bob = f.signer(1);
    f.approve(&order, &alice, 0);
    f.bc.set_now(NOW + DAY + 1);
    let target_before = f.balance(f.target.address());
    let r = f.approve(&order, &bob, 1);
    assert_eq!(approval_reply(&r, &order), (OP_APPROVE_REJECTED, Some(ERROR_EXPIRED as u32)));
    assert_eq!(f.balance(f.target.address()), target_before);
}

#[test]
fn an_update_makes_older_orders_stale() {
    let mut f = Fixture::new();
    // Order 0 pays out; order 1 replaces the signer set (dropping carol).
    f.propose_paid(send_action(transfer(f.target.address(), TOS), None));
    let alice = f.signer(0);
    let bob = f.signer(1);
    let new_signers = address_dict(&[(0, &alice), (1, &bob)]).unwrap();
    f.propose_paid(update_action(2, new_signers, None, None));
    let stale_order = f.order_address(0);
    let update_order = f.order_address(1);

    f.approve(&update_order, &alice, 0);
    let r = f.approve(&update_order, &bob, 1);
    assert_eq!(exit_code_on(&r, &f.multisig), 0, "update executes");
    assert_eq!(f.multisig_int(1), 2, "threshold unchanged at 2");

    // Order 0 still collects its approvals and fires, but the parent refuses it.
    let target_before = f.balance(f.target.address());
    f.approve(&stale_order, &alice, 0);
    let r = f.approve(&stale_order, &bob, 1);
    assert_eq!(exit_code_on(&r, &f.multisig), ERROR_STALE_SIGNERS);
    assert_eq!(f.balance(f.target.address()), target_before, "a stale order must not pay out");
}

#[test]
fn forged_execute_and_init_are_refused() {
    let mut f = Fixture::new();
    f.propose_paid(send_action(transfer(f.target.address(), TOS), None));
    let order = f.order_address(0);
    let eve = f.outsider.address().clone();
    let alice = f.signer(0);

    // An execute claiming order 0, sent by someone else.
    let signer_dict =
        f.bc.run_get_method(&f.multisig, "get_multisig_data", vec![])
            .expect("data")
            .expect_success()
            .cell_at(2);
    let body = cell(|b| {
        b.append_u32(OP_EXECUTE).unwrap();
        b.append_u64(0).unwrap();
        b.append_u64(0).unwrap();
        b.append_u32(NOW + DAY).unwrap();
        b.append_u8(2).unwrap();
        b.append_raw(signer_dict.repr_hash().as_slice(), 256).unwrap();
        b.checked_append_reference(send_action(transfer(&eve, 100 * TOS), None)).unwrap();
    });
    let forged = MessageBuilder::internal(&eve, &f.multisig, TOS).body(body).build();
    let r = f.bc.send_message(forged).expect("deliver");
    assert_eq!(exit_code_on(&r, &f.multisig), ERROR_UNAUTHORIZED_EXECUTE);

    // A second init of the order from anyone but the parent.
    let init = cell(|b| {
        b.append_u32(0x16b7a4fb).unwrap();
        b.append_u64(0).unwrap();
        b.append_u8(1).unwrap();
        b.checked_append_reference(address_dict(&[(0, &eve)]).unwrap()).unwrap();
        b.append_u32(NOW + DAY).unwrap();
        b.checked_append_reference(send_action(transfer(&eve, TOS), None)).unwrap();
        b.append_bits(0, 1).unwrap();
    });
    let msg = MessageBuilder::internal(&alice, &order, TOS).body(init.clone()).build();
    let r = f.bc.send_message(msg).expect("deliver");
    assert_eq!(exit_code_on(&r, &order), ERROR_UNAUTHORIZED_INIT);

    // Even the parent cannot initialise an order twice.
    let msg = MessageBuilder::internal(&f.multisig, &order, TOS).body(init).build();
    let r = f.bc.send_message(msg).expect("deliver");
    assert_eq!(exit_code_on(&r, &order), ERROR_ALREADY_INITIALIZED);
    assert_eq!(f.order_int(&order, 3), 2, "the original threshold stands");
}

#[test]
fn an_order_deployed_ahead_of_its_parent_cannot_be_approved() {
    let mut f = Fixture::new();
    // Order addresses are public: anyone can deploy the next one with its StateInit and
    // try to approve it before the parent's init arrives.
    let init_data = cell(|b| {
        f.multisig.write_to(b).unwrap();
        b.append_u64(0).unwrap();
    });
    let state = StateInit::with_code_and_data(f.order_code.clone(), init_data);
    let order = f.order_address(0);
    let alice = f.signer(0);
    let approve = cell(|b| {
        b.append_u32(OP_APPROVE).unwrap();
        b.append_u64(7).unwrap();
        b.append_u8(0).unwrap();
    });
    let msg = MessageBuilder::internal(&alice, &order, TOS).state_init(state).body(approve).build();
    let r = f.bc.send_message(msg).expect("deliver");
    assert_eq!(exit_code_on(&r, &order), ERROR_NOT_INITIALIZED);

    // The parent's own proposal still initialises it normally afterwards.
    let r = f.propose_paid(send_action(transfer(f.target.address(), TOS), None));
    assert_eq!(exit_code_on(&r, &order), 0);
    assert_eq!(f.order_int(&order, 0), -1);
}

fn text_comment(text: &str) -> Cell {
    cell(|b| {
        b.append_u32(0).unwrap();
        b.append_raw(text.as_bytes(), text.len() * 8).unwrap();
    })
}

#[test]
fn signers_can_approve_with_a_text_comment() {
    let mut f = Fixture::new();
    f.propose_paid(send_action(transfer(f.target.address(), TOS), None));
    let order = f.order_address(0);
    let alice = f.signer(0);
    let bob = f.signer(1);
    let eve = f.outsider.address().clone();
    let target_before = f.balance(f.target.address());

    let msg = MessageBuilder::internal(&eve, &order, TOS).body(text_comment("approve")).build();
    let r = f.bc.send_message(msg).expect("deliver");
    assert_eq!(exit_code_on(&r, &order), ERROR_UNKNOWN_SIGNER, "a non-signer's text approval");

    let msg = MessageBuilder::internal(&alice, &order, TOS).body(text_comment("approve")).build();
    let r = f.bc.send_message(msg).expect("deliver");
    assert_eq!(approval_reply(&r, &order).0, OP_APPROVE_ACCEPTED);
    assert_eq!(f.order_int(&order, 7), 1);
    let msg = MessageBuilder::internal(&bob, &order, TOS).body(text_comment("approve")).build();
    f.bc.send_message(msg).expect("deliver");
    assert_received(
        target_before,
        f.balance(f.target.address()),
        TOS,
        "payout after two text approvals",
    );

    let msg = MessageBuilder::internal(&alice, &order, TOS).body(text_comment("hello")).build();
    let r = f.bc.send_message(msg).expect("deliver");
    assert_eq!(exit_code_on(&r, &order), 0xffff, "any other comment is refused, not swallowed");
}

#[test]
fn an_expired_order_hands_its_balance_back() {
    let mut f = Fixture::new();
    f.propose_paid(send_action(transfer(f.target.address(), TOS), None));
    let order = f.order_address(0);
    let eve = f.outsider.address().clone();
    let reclaim = cell(|b| {
        b.append_u32(OP_RECLAIM).unwrap();
        b.append_u64(0).unwrap();
    });
    let msg = MessageBuilder::internal(&eve, &order, TOS / 10).body(reclaim.clone()).build();
    let r = f.bc.send_message(msg).expect("deliver");
    assert_eq!(exit_code_on(&r, &order), ERROR_NOT_RECLAIMABLE, "not before expiry");

    f.bc.set_now(NOW + DAY + 1);
    let order_balance = f.balance(&order);
    let parent_before = f.balance(&f.multisig);
    assert!(order_balance > 0);
    let msg = MessageBuilder::internal(&eve, &order, TOS / 10).body(reclaim).build();
    let r = f.bc.send_message(msg).expect("deliver");
    assert_eq!(exit_code_on(&r, &order), 0);
    assert!(
        f.balance(&f.multisig) > parent_before + order_balance - TOS / 1_000,
        "the funds return to the parent"
    );
    assert!(
        f.bc.get_account(&order).map(|a| a.is_none()).unwrap_or(true),
        "the order is destroyed"
    );
}

#[test]
fn an_executed_order_cannot_be_reclaimed() {
    let mut f = Fixture::new();
    f.propose_paid(send_action(transfer(f.target.address(), TOS), None));
    let order = f.order_address(0);
    let alice = f.signer(0);
    let bob = f.signer(1);
    f.approve(&order, &alice, 0);
    f.approve(&order, &bob, 1);
    f.bc.set_now(NOW + DAY + 1);
    let reclaim = cell(|b| {
        b.append_u32(OP_RECLAIM).unwrap();
        b.append_u64(0).unwrap();
    });
    let msg = MessageBuilder::internal(&alice, &order, TOS / 10).body(reclaim).build();
    let r = f.bc.send_message(msg).expect("deliver");
    assert_eq!(exit_code_on(&r, &order), ERROR_NOT_RECLAIMABLE);
}

#[test]
fn execute_internal_runs_further_actions_only_for_the_wallet_itself() {
    let mut f = Fixture::new();
    let inner = send_action(
        transfer(f.target.address(), TOS),
        Some(send_action(transfer(f.target.address(), 2 * TOS), None)),
    );
    let body = cell(|b| {
        b.append_u32(OP_EXECUTE_INTERNAL).unwrap();
        b.append_u64(0).unwrap();
        b.checked_append_reference(inner.clone()).unwrap();
    });
    let to_self = {
        let header = InternalMessageHeader {
            bounce: false,
            dst: f.multisig.clone(),
            value: CurrencyCollection::with_coins(TOS),
            ..Default::default()
        };
        Message::with_int_header_and_body(header, SliceData::load_cell(body.clone()).unwrap())
            .serialize_as_is()
            .unwrap()
            .0
            .into_cell()
            .unwrap()
    };
    f.propose_paid(send_action(to_self, None));
    let order = f.order_address(0);
    let alice = f.signer(0);
    let bob = f.signer(1);
    let target_before = f.balance(f.target.address());
    f.approve(&order, &alice, 0);
    f.approve(&order, &bob, 1);
    assert_received(target_before, f.balance(f.target.address()), 3 * TOS, "both chained sends");

    let eve = f.outsider.address().clone();
    let msg = MessageBuilder::internal(&eve, &f.multisig, TOS).body(body).build();
    let r = f.bc.send_message(msg).expect("deliver");
    assert_eq!(exit_code_on(&r, &f.multisig), ERROR_UNAUTHORIZED_EXECUTE);
}

#[test]
fn the_wallet_cannot_propose_or_be_made_a_member() {
    let mut f = Fixture::new();
    let actions = send_action(transfer(f.target.address(), TOS), None);
    let expires_at = NOW + DAY;
    let value = f.estimate(&actions, expires_at);
    let me = f.multisig.clone();
    let r = f.propose(&me, false, 0, NEXT_SEQNO, expires_at, actions, value);
    assert_eq!(exit_code_on(&r, &f.multisig), ERROR_UNAUTHORIZED_PROPOSER);

    let alice = f.signer(0);
    let with_self = address_dict(&[(0, &alice), (1, &me)]).unwrap();
    let dave = f.proposer.address().clone();
    let update = update_action(1, with_self, None, None);
    let r = f.propose(&dave, false, 0, NEXT_SEQNO, expires_at, update, value);
    assert_eq!(exit_code_on(&r, &f.multisig), ERROR_INVALID_CONFIG, "self as a signer");
    let only_alice = address_dict(&[(0, &alice)]).unwrap();
    let self_proposer = address_dict(&[(0, &me)]);
    let update = update_action(1, only_alice, self_proposer, None);
    let r = f.propose(&dave, false, 0, NEXT_SEQNO, expires_at, update, value);
    assert_eq!(exit_code_on(&r, &f.multisig), ERROR_INVALID_CONFIG, "self as a proposer");
}

#[test]
fn a_large_wallet_executes_a_large_order_paid_at_the_quote() {
    // 64 signers and 50 actions: the sizes at which a fixed, small-point profile left
    // proposals underfunded. Paying exactly the quote must carry the order all the way.
    let mut f = Fixture::with_wallet(2, 61);
    let mut chain = None;
    for _ in 0..50 {
        chain = Some(send_action(transfer(f.target.address(), TOS / 100), chain));
    }
    let r = f.propose_paid(chain.unwrap());
    let order = f.order_address(0);
    assert_eq!(exit_code_on(&r, &order), 0, "the order initialises");
    let alice = f.signer(0);
    let bob = f.signer(1);
    let target_before = f.balance(f.target.address());
    f.approve(&order, &alice, 0);
    let r = f.approve(&order, &bob, 1);
    assert_eq!(exit_code_on(&r, &f.multisig), 0, "the parent executes all 50 actions");
    assert_received(
        target_before,
        f.balance(f.target.address()),
        50 * (TOS / 100),
        "all 50 transfers",
    );
}
