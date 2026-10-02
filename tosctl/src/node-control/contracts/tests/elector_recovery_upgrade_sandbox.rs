/*
 * Copyright (C) 2026 TOS Network.
 * Licensed under the GNU General Public License v3.0.
 */

//! Native upgrade controls for a paid recovery whose confirmation is still in flight.
//! Prior credits are seeded at a drained boundary and backed by a real transfer.
//! Every recovery, ACK, upgrade and retry below executes the transaction action phase.

use chain_block::{
    BuilderData, Cell, Coins, Deserializable, HashmapE, HashmapType, IBitstring,
    Message, MsgAddressInt, Serializable, SliceData, Transaction,
};
use std::path::PathBuf;
use tos_sandbox::{Blockchain, MessageBuilder, compile_func_with_stdlib, generate_zerostate_state};

const TOS: u64 = 1_000_000_000;
const QUERY: u64 = (1_u64 << 63) + 1;
const RECOVER: u32 = 0x47657432;
const RECOVERED: u32 = 0xf96f7332;
const ACK: u32 = 0x47656132;
const CONFIRMED: u32 = 0x47656133;
const UPGRADE: u32 = 0x4e436f64;

struct Fixture {
    chain: Blockchain,
    elector: MsgAddressInt,
    config: MsgAddressInt,
    owner: MsgAddressInt,
}

fn root() -> PathBuf {
    PathBuf::from(std::env::var("TOS_ROOT").expect("TOS_ROOT must name the tested checkout"))
}

fn maybe_cell(cs: &mut SliceData) -> Option<Cell> {
    cs.get_next_bit().expect("presence").then(|| cs.checked_drain_reference().expect("reference"))
}

impl Fixture {
    fn new(label: &str) -> Self {
        let state = generate_zerostate_state(root().join("crypto/smartcont/gen-zerostate.fif"))
            .expect("real zerostate tooling is required");
        let config = state.read_custom().expect("masterchain").expect("extra").config().clone();
        let elector = MsgAddressInt::with_standart(
            None, -1, config.elector_address().expect("elector address"),
        ).expect("elector");
        let config_address = MsgAddressInt::with_standart(
            None, -1, config.config_address().expect("config address"),
        ).expect("config");
        let mut account = state.read_accounts().expect("accounts")
            .account(&elector.address()).expect("lookup").expect("elector present")
            .read_account().expect("elector account");
        // Compile the file under test, even if generated zerostate artifacts are stale.
        account.set_code(compile_func_with_stdlib(&[root().join("crypto/smartcont/elector-code.fc")])
            .expect("the actual elector must compile"));
        let mut chain = Blockchain::with_config(config).expect("native blockchain");
        chain.set_workchain(-1);
        chain.set_account(elector.clone(), account);
        let treasury = chain.treasury(label, 10_000 * TOS).expect("funded owner");
        let owner = treasury.address().clone();
        chain.send_message(treasury.build_message(&elector, 1_000 * TOS, false, None))
            .expect("actual collateral transfer").expect_success();
        let mut fixture = Self { chain, elector, config: config_address, owner };
        fixture.credit(50 * TOS);
        fixture
    }

    fn data(&self) -> Cell {
        self.chain.get_account(&self.elector).expect("elector").get_data().expect("data")
    }

    fn code(&self) -> Cell {
        self.chain.get_account(&self.elector).expect("elector").get_code().expect("code")
    }

    fn metadata(&self) -> Option<Cell> {
        let mut cs = SliceData::load_cell(self.data()).expect("root");
        for _ in 0..3 { maybe_cell(&mut cs); }
        Coins::construct_from(&mut cs).expect("purse");
        cs.get_next_u32().expect("active ID");
        cs.get_next_bits(256).expect("active hash");
        let extra = if cs.remaining_bits() == 0 { None } else { maybe_cell(&mut cs) };
        assert_eq!((cs.remaining_bits(), cs.remaining_references()), (0, 0));
        extra
    }

    fn credit(&mut self, amount: u64) {
        let metadata = self.metadata();
        let mut credits = HashmapE::with_bit_len(256);
        if amount != 0 {
            let mut value = BuilderData::new();
            Coins::new(amount).write_to(&mut value).expect("credit amount");
            credits.set_builder(self.owner.address().clone(), &value).expect("credit");
        }
        let mut data = BuilderData::new();
        data.append_bit_zero().expect("no active election");
        if let Some(book) = HashmapType::data(&credits) {
            data.append_bit_one().expect("credit presence");
            data.checked_append_reference(book.clone()).expect("credit book");
        } else {
            data.append_bit_zero().expect("no credits");
        }
        data.append_bit_zero().expect("no frozen rounds");
        Coins::new(0).write_to(&mut data).expect("purse");
        data.append_u32(0).expect("active ID");
        data.append_raw(&[0; 32], 256).expect("active hash");
        if let Some(extra) = metadata {
            data.append_bit_one().expect("metadata presence");
            data.checked_append_reference(extra).expect("unchanged recovery history");
        }
        let mut account = self.chain.get_account(&self.elector).expect("elector").clone();
        account.set_data(data.into_cell().expect("drained boundary"));
        self.chain.set_account(self.elector.clone(), account);
    }

    fn message(&self, op: u32, query: u64) -> Message {
        let mut body = BuilderData::new();
        body.append_u32(op).expect("op");
        body.append_u64(query).expect("query");
        MessageBuilder::internal(&self.owner, &self.elector, 20 * TOS)
            .body(body.into_cell().expect("body")).build()
    }

    fn step(&mut self, message: Message) -> (Transaction, Vec<Message>) {
        let destination = message.dst().expect("destination");
        let before = self.chain.get_account(&destination).expect("account")
            .balance().expect("balance").coins.as_u128();
        let incoming = message.int_header().expect("header").value.coins.as_u128();
        let (_, tx, out) = self.chain.execute_one(message).expect("native compute and action");
        let after = self.chain.get_account(&destination).expect("account")
            .balance().expect("balance").coins.as_u128();
        let outgoing: u128 = out.iter().map(|m| {
            let h = m.int_header().expect("internal");
            h.value.coins.as_u128() + h.fwd_fee.as_u128()
        }).sum();
        assert_eq!(before + incoming, after + outgoing + tx.total_fees().coins.as_u128());
        (tx, out)
    }

    fn send(&mut self, op: u32, query: u64) -> Vec<Message> {
        let message = self.message(op, query);
        let (tx, out) = self.step(message);
        assert!(!tx.read_description().expect("description").is_aborted(), "owner operation");
        out
    }

    fn acknowledge_first_payment(&mut self) {
        let out = self.send(RECOVER, QUERY);
        assert_eq!(reply(&out), (RECOVERED, QUERY));
        assert!(out[0].int_header().expect("payment").value.coins.as_u128() >= u128::from(50 * TOS));
        let payment = out.into_iter().next().expect("payment");
        assert!(!payment.int_header().expect("header").bounce);
        // Deliver the real non-bounce value. The wallet callback is not the subject
        // of this elector-side control; the existing pool suite covers its receiver.
        let (_, onward) = self.step(payment);
        assert!(onward.is_empty());
        let confirmation = self.send(ACK, QUERY);
        assert_eq!(reply(&confirmation), (CONFIRMED, QUERY));
        // Deliberately do not deliver the confirmation, matching the review interleaving.
    }

    fn upgrade(&mut self, code: Cell, hook: bool) -> (Transaction, Vec<Message>) {
        let mut body = BuilderData::new();
        body.append_u32(UPGRADE).expect("op");
        body.append_u64(800).expect("query");
        body.checked_append_reference(code).expect("target code");
        if hook { body.append_bit_one().expect("hook marker"); }
        // The fixture injects the authorized configuration-contract source; it does
        // not simulate a governance vote or send a transaction to any live chain.
        let message = MessageBuilder::internal(&self.config, &self.elector, 20 * TOS)
            .body(body.into_cell().expect("upgrade request")).build();
        self.step(message)
    }
}

fn reply(out: &[Message]) -> (u32, u64) {
    assert_eq!(out.len(), 1, "exactly one response");
    let mut body = out[0].body().expect("body").clone();
    (body.get_next_u32().expect("opcode"), body.get_next_u64().expect("query"))
}

fn target(source: &str) -> Cell {
    let directory = tempfile::tempdir().expect("target directory");
    let path = directory.path().join("target.fc");
    std::fs::write(&path, source).expect("write controlled target");
    compile_func_with_stdlib(&[path]).expect("negative target must really compile")
}

#[test]
fn same_code_upgrade_retains_confirmation_and_old_query_replay_protection() {
    for hook in [false, true] {
        let mut f = Fixture::new("recovery-compatible-upgrade");
        f.acknowledge_first_payment();
        let data = f.data();
        let code = f.code();
        let (tx, out) = f.upgrade(code.clone(), hook);
        assert!(!tx.read_description().expect("description").is_aborted());
        assert_eq!(reply(&out), (0xce436f64, 800));
        assert_eq!(f.code(), code);
        assert_eq!(f.data(), data, "upgrade must retain remote confirmation evidence");
        let out = f.send(ACK, QUERY);
        assert_eq!(reply(&out), (CONFIRMED, QUERY), "lost confirmation must remain repairable");
        f.credit(70 * TOS);
        let later_credit = f.data();
        assert!(f.send(RECOVER, QUERY).is_empty(), "old query must not consume later credit");
        assert_eq!(f.data(), later_credit);
        let out = f.send(RECOVER, QUERY + 1);
        assert_eq!(reply(&out), (RECOVERED, QUERY + 1));
        let mut body = out[0].body().expect("body").clone();
        body.get_next_u32().expect("op"); body.get_next_u64().expect("query");
        assert_eq!(Coins::construct_from(&mut body).expect("business credit").as_u128(), u128::from(70 * TOS));
    }
}

#[test]
fn target_without_matching_recovery_format_cannot_take_over_history() {
    let missing = target("() recv_internal(slice body) impure { }\n");
    let wrong = target("() recv_internal(slice body) impure { }\nint recovery_upgrade_format() impure method_id(1667) { return 0; }\n");
    for code in [missing, wrong] {
        for hook in [false, true] {
            let mut f = Fixture::new("recovery-incompatible-upgrade");
            f.acknowledge_first_payment();
            let original_code = f.code();
            let original_data = f.data();
            let (tx, _) = f.upgrade(code.clone(), hook);
            assert!(tx.read_description().expect("description").is_aborted(), "incompatible target must be rejected");
            assert_eq!(f.code(), original_code);
            assert_eq!(f.data(), original_data);
            assert_eq!(reply(&f.send(ACK, QUERY)), (CONFIRMED, QUERY));
        }
    }
}

#[test]
fn a_declared_compatible_hook_cannot_drop_recovery_metadata() {
    let destructive = target(concat!(
        "() recv_internal(slice body) impure { }\n",
        "int recovery_upgrade_format() impure method_id(1667) { return 0x52435632; }\n",
        "() after_code_upgrade(slice sender, slice body, int query) impure method_id(1666) { set_data(begin_cell().end_cell()); }\n",
    ));
    let mut f = Fixture::new("recovery-destructive-hook");
    f.acknowledge_first_payment();
    let original_code = f.code();
    let original_data = f.data();
    let (tx, _) = f.upgrade(destructive, true);
    assert!(tx.read_description().expect("description").is_aborted());
    assert_eq!(f.code(), original_code, "failed hook must not install its code");
    assert_eq!(f.data(), original_data, "failed hook must not delete confirmation evidence");
    assert_eq!(reply(&f.send(ACK, QUERY)), (CONFIRMED, QUERY));
}

#[test]
fn never_used_empty_history_preserves_legacy_installation_boundary() {
    let code = target("() recv_internal(slice body) impure { }\n");
    let mut f = Fixture::new("unused-upgrade-boundary");
    f.credit(0);
    assert!(f.metadata().is_none());
    let data = f.data();
    let (tx, out) = f.upgrade(code.clone(), false);
    assert!(!tx.read_description().expect("description").is_aborted());
    assert_eq!(reply(&out), (0xce436f64, 800));
    assert_eq!(f.code(), code);
    assert_eq!(f.data(), data);
}

#[test]
fn outstanding_payment_receipt_still_blocks_installation() {
    let mut f = Fixture::new("outstanding-upgrade-boundary");
    let out = f.send(RECOVER, QUERY);
    assert_eq!(reply(&out), (RECOVERED, QUERY));
    let code = f.code();
    let data = f.data();
    let (tx, out) = f.upgrade(code.clone(), false);
    assert!(!tx.read_description().expect("description").is_aborted());
    assert_eq!(reply(&out), (0xffffffff, 800));
    assert_eq!(f.code(), code);
    assert_eq!(f.data(), data);
}
