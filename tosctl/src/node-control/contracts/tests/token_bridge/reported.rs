/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! T-R: reported transfers and the balance report (SETTLEMENT-PROTOCOL.md
//! section 20).
//!
//! S is the paying wallet, P its owner, R the recipient's wallet. Every test
//! runs with the model on: supply and balances are conserved after every
//! transaction, a reported transfer ends at most once (I10), and the tests
//! check that each one ended exactly once when the network is quiet. With
//! TOKEN_BRIDGE_TRACE_DIR set, every transaction is replayed in the native
//! engine as well.

use chain_block::{
    BuilderData, Cell, Coins, Deserializable, GlobalCapabilities, HashmapE, HashmapType,
    IBitstring, Message, MsgAddressInt, Serializable, SliceData, Transaction, UInt256,
};
use tos_sandbox::MessageBuilder;
use tos_vm::stack::StackItem;

use crate::burn::minted;
use crate::harness::*;
use crate::model::ReportedBody;

/// The token-rail actor's report margin (USDC settlement design, section 4.4).
const REPORT_MARGIN: u128 = 10;
/// A stand-in for the actor's PRE_ACCEPT_GAS, which the actor release fixes.
/// The wallet only carries the report value the payer chooses; this is what a
/// payer funds it from.
const PRE_ACCEPT_GAS: u64 = 5_000;

fn gas_fee(net: &Net, gas: u64) -> u128 {
    net.bc.config_params().gas_prices(false).expect("gas prices").calc_gas_fee(gas).expect("a fee")
        as u128
}

fn fwd_fee(net: &Net, bits: u64, cells: u64) -> u128 {
    net.bc.config_params().fwd_prices(false).expect("forward prices").calc_fwd_fee(bits, cells)
}

/// The value a payer attaches for its own report: the actor's formula, with
/// the stand-in gas. transfer_delivered is a header and one body cell.
fn report_funding(net: &Net) -> u128 {
    REPORT_MARGIN * gas_fee(net, PRE_ACCEPT_GAS) + fwd_fee(net, 32 + 64 + 124 + 267, 1)
}

/// What the report must buy at P before P raises its gas limit, at the
/// network's current prices. R pays the report's forwarding (mode 1).
fn report_cost_now(net: &Net) -> u128 {
    gas_fee(net, PRE_ACCEPT_GAS)
}

fn declared_u64(name: &str) -> u64 {
    declared(name) as u64
}

/// The longest payload chain S admits: its body to R is the root and the
/// chain, REPORTED_BODY_CELLS cells in all.
fn largest_chain() -> usize {
    declared("REPORTED_BODY_CELLS") as usize - 1
}

/// Sends `r` from `p` through `p`'s wallet with `value` and lets every
/// consequence run.
fn send_reported(net: &mut Net, p: &MsgAddressInt, r: &Reported, value: u128) -> Transaction {
    let msg = net.reported_message(p, p, r, value);
    net.send(msg)
}

/// Sends `r` with exactly one nanotos more than the wallet requires.
fn send_funded(net: &mut Net, p: &MsgAddressInt, r: &Reported) -> Transaction {
    let need = net.reported_need(p, r);
    send_reported(net, p, r, need + 1)
}

/// Every message sent since delivery `from` to `to` with opcode `op`.
fn sent_to(net: &Net, from: usize, to: &MsgAddressInt, op: u32) -> Vec<Message> {
    net.delivered[from..]
        .iter()
        .flat_map(|d| d.outs.iter())
        .filter(|m| is_to(m, to) && body_op(m) == Some(op))
        .cloned()
        .collect()
}

/// Every transaction since `from` whose incoming message has opcode `op`.
fn legs(net: &Net, from: usize, op: u32) -> Vec<Transaction> {
    net.delivered[from..]
        .iter()
        .filter(|d| !d.msg.int_header().is_some_and(|h| h.bounced) && body_op(&d.msg) == Some(op))
        .map(|d| d.tx.clone())
        .collect()
}

/// Every transaction since `from` that handled a bounced reported transfer.
fn bounce_legs(net: &Net, from: usize) -> Vec<Transaction> {
    net.delivered[from..]
        .iter()
        .filter(|d| crate::model::reported_bounce(&d.msg).is_some())
        .map(|d| d.tx.clone())
        .collect()
}

/// (query id, amount) of a transfer_refused.
fn refused_fields(m: &Message) -> (u64, u128) {
    let mut s = m.body().expect("a body").clone();
    let op = s.get_next_u32().unwrap();
    assert!(op == OP_TRANSFER_REFUSED || op == OP_TRANSFER_REREPORTED, "a refusal report");
    let query_id = s.get_next_u64().unwrap();
    let amount = Coins::construct_from(&mut s).unwrap().as_u128();
    (query_id, amount)
}

/// (query id, balance) of a take_balance.
fn balance_fields(m: &Message) -> (u64, u128) {
    let mut s = m.body().expect("a body").clone();
    assert_eq!(s.get_next_u32().unwrap(), OP_TAKE_BALANCE);
    let query_id = s.get_next_u64().unwrap();
    let balance = Coins::construct_from(&mut s).unwrap().as_u128();
    (query_id, balance)
}

/// I10, the other half: once the network is quiet, every reported transfer
/// sent has ended, exactly once.
fn assert_every_reported_transfer_ended(net: &Net) {
    assert!(net.queue.is_empty(), "the network is quiet");
    for ((_, query_id), (sent, delivered, refused)) in &net.model.reported {
        assert_eq!(
            *sent,
            delivered + refused,
            "I10: reported transfer {query_id} was sent {sent} times and ended {} times",
            delivered + refused
        );
    }
}

/// A bounced copy of `p`'s message reached `p`: the paying wallet refused it.
fn bounced_to(net: &Net, from: usize, p: &MsgAddressInt) -> usize {
    net.delivered[from..]
        .iter()
        .flat_map(|d| d.outs.iter())
        .filter(|m| is_to(m, p) && m.int_header().is_some_and(|h| h.bounced))
        .count()
}

/// A plain transfer body from `from` to `to`, with every field chosen.
fn transfer_body(
    query_id: u64,
    amount: u128,
    to: &MsgAddressInt,
    response: &MsgAddressInt,
    forward: u128,
    payload: &Payload,
) -> Cell {
    cell(|b| {
        b.append_u32(OP_TRANSFER).unwrap().append_u64(query_id).unwrap();
        coins(b, amount);
        to.write_to(b).unwrap();
        response.write_to(b).unwrap();
        b.append_bit_zero().unwrap(); // no custom payload
        coins(b, forward);
        match payload {
            Payload::Chain(cells) => {
                b.append_bit_one().unwrap();
                b.checked_append_reference(payload_chain(*cells)).unwrap();
            }
            _ => {
                b.append_bit_zero().unwrap();
            }
        }
    })
}

/// Refuses `r` at R by taking ConfigParam 79 away while S's message is in
/// flight: R throws in its compute phase. The configuration comes back once
/// the refusal is reported.
fn refuse_at_r(net: &mut Net, p: &MsgAddressInt, r: &Reported) {
    let need = net.reported_need(p, r);
    let msg = net.reported_message(p, p, r, need + 1);
    succeeded(&net.send_one(msg));
    net.remove_config();
    net.settle();
    net.configure();
}

// ---------------------------------------------------------------------------
// T-R1: delivered
// ---------------------------------------------------------------------------

/// T-R1: R credits the tokens and reports the delivery to P in one
/// transaction; the notification and the excess go out as for a transfer.
#[test]
fn t_r1_delivered_reports_once_to_the_payer() {
    let mut net = minted();
    let p = net.user(0);
    let q = net.user(1);
    let z = net.user(2);
    let mut r = Reported::to(&q, 7, 300);
    r.forward_tos_amount = (TOS / 10).into();
    r.response = Some(z.clone());
    r.payload = Payload::Chain(2);
    r.report_tos_amount = report_funding(&net);
    let start = net.delivered.len();
    // a TOS above the need leaves an excess for the response destination
    let need = net.reported_need(&p, &r);
    succeeded(&send_reported(&mut net, &p, &r, need + u128::from(TOS)));
    assert_eq!((net.tokens(&p), net.tokens(&q)), (700, 300), "the tokens moved once");
    let delivered = sent_to(&net, start, &p, OP_TRANSFER_DELIVERED);
    assert_eq!(delivered.len(), 1, "one delivery report to P");
    assert_eq!(value_of(&delivered[0]), r.report_tos_amount, "the report carries its value");
    assert!(!delivered[0].int_header().unwrap().bounce, "the report is not bounceable");
    let notified = sent_to(&net, start, &q, OP_TRANSFER_NOTIFICATION);
    assert_eq!(notified.len(), 1, "one notification to R's owner");
    assert_eq!(
        value_of(&notified[0]),
        r.forward_tos_amount,
        "the notification carries the forward"
    );
    assert_eq!(sent_to(&net, start, &z, OP_EXCESSES).len(), 1, "the excess goes to the response");
    assert!(sent_to(&net, start, &p, OP_TRANSFER_REFUSED).is_empty(), "no refusal");
    assert_eq!(net.refusals_count(&p), 0, "nothing recorded at S");
    // The same to an existing R, with nothing forwarded: no notification.
    let start = net.delivered.len();
    succeeded(&send_funded(&mut net, &p, &Reported::to(&q, 8, 100)));
    assert_eq!(net.tokens(&q), 400);
    assert!(sent_to(&net, start, &q, OP_TRANSFER_NOTIFICATION).is_empty(), "nothing forwarded");
    assert_eq!(sent_to(&net, start, &p, OP_TRANSFER_DELIVERED).len(), 1);
    // A transfer to oneself is delivered like any other.
    succeeded(&send_funded(&mut net, &p, &Reported::to(&p, 9, 50)));
    assert_eq!(net.tokens(&p), 600, "a self-transfer moves nothing");
    assert_every_reported_transfer_ended(&net);
}

// ---------------------------------------------------------------------------
// T-R2: refused at R
// ---------------------------------------------------------------------------

fn assert_refused(net: &Net, start: usize, p: &MsgAddressInt, query_id: u64, amount: u128) {
    assert_eq!(net.refusal(p, query_id), amount as i128, "S records the refusal");
    let refused = sent_to(net, start, p, OP_TRANSFER_REFUSED);
    assert_eq!(refused.len(), 1, "one refusal report to P");
    assert_eq!(refused_fields(&refused[0]), (query_id, amount), "the report names the transfer");
    assert!(sent_to(net, start, p, OP_TRANSFER_DELIVERED).is_empty(), "never delivered");
}

/// T-R2: R fails in its compute phase (ConfigParam 79 is gone): its bounce
/// makes S restore the tokens, record the refusal and report it.
#[test]
fn t_r2_refused_at_r_by_a_compute_failure() {
    let mut net = minted();
    let p = net.user(0);
    let q = net.user(1);
    let r = Reported::to(&q, 9, 250);
    let start = net.delivered.len();
    refuse_at_r(&mut net, &p, &r);
    let at_r = legs(&net, start, OP_INTERNAL_TRANSFER_REPORTED);
    assert_eq!(at_r.len(), 1);
    refused_with(&at_r[0], err("no_bridge_config"));
    assert!(outcome(&at_r[0]).bounced, "R's refusal bounces to S");
    assert_eq!(bounce_legs(&net, start).len(), 1, "S handles the bounce once");
    succeeded(&bounce_legs(&net, start)[0]);
    assert_eq!((net.tokens(&p), net.tokens(&q)), (1_000, 0), "the tokens are back at S");
    assert_refused(&net, start, &p, 9, 250);
    assert_every_reported_transfer_ended(&net);
}

/// T-R2: R's supply bound refuses a credit that would pass MAX_SUPPLY, and the
/// refusal comes back like any other.
#[test]
fn t_r2_refused_at_r_by_its_supply_bound() {
    let mut net = minted();
    let p = net.user(0);
    let q = net.user(1);
    succeeded(&send_funded(&mut net, &p, &Reported::to(&q, 1, 1)));
    // R holds almost everything Coins can count: a test-only state, so the
    // model's supply sum is off from here on.
    net.model.enabled = false;
    net.patch_wallet(&q, |w| w.balance = MAX_SUPPLY - 10);
    let start = net.delivered.len();
    succeeded(&send_funded(&mut net, &p, &Reported::to(&q, 2, 100)));
    let at_r = legs(&net, start, OP_INTERNAL_TRANSFER_REPORTED);
    refused_with(&at_r[0], err("supply_bound"));
    assert_eq!(net.tokens(&p), 999, "the tokens are back at S");
    assert_refused(&net, start, &p, 2, 100);
}

/// T-R2: R runs out of its capped gas (a test-only build with a small
/// R_GAS_LIMIT). The capped gas leaves the bounce funded, so S still restores.
#[test]
fn t_r2_refused_at_r_out_of_its_capped_gas() {
    let cap = 8_000u64;
    let _variant = use_codes(wallet_variant("r-gas", move |s| {
        let line = format!("const int R_GAS_LIMIT = {};", declared("R_GAS_LIMIT"));
        assert!(s.contains(&line), "the wallet declares R_GAS_LIMIT");
        s.replace(&line, &format!("const int R_GAS_LIMIT = {cap};"))
    }));
    let mut net = minted();
    let p = net.user(0);
    let q = net.user(1);
    let r = Reported::to(&q, 4, 400);
    let start = net.delivered.len();
    succeeded(&send_funded(&mut net, &p, &r));
    let at_r = legs(&net, start, OP_INTERNAL_TRANSFER_REPORTED);
    assert_eq!(at_r.len(), 1);
    let o = outcome(&at_r[0]);
    assert!(o.aborted, "R runs out of its capped gas");
    assert_eq!(o.exit_code, Some(-14), "R runs out of its capped gas");
    assert!(o.gas_used <= cap + 1, "the cap stops R: {} gas", o.gas_used);
    assert!(o.bounced, "the capped gas leaves the bounce funded");
    assert_eq!(net.tokens(&p), 1_000, "the tokens are back at S");
    assert_refused(&net, start, &p, 4, 400);
    assert_every_reported_transfer_ended(&net);
}

/// T-R2: R fails in its action phase, with the credit computed: the
/// notification (first case) or the delivery report (second case) cannot be
/// sent. +16 bounces R's message, the credit rolls back with it, and the
/// action fine leaves the bounce funded.
#[test]
fn t_r2_refused_at_r_by_an_action_failure() {
    let mut net = minted();
    let p = net.user(0);
    let q = net.user(1);
    let limit = net.max_msg_cells();
    for (query_id, forward, payload, cells) in
        [(5u64, TOS / 10, Payload::Chain(4), 3u32), (6, 0, Payload::Inline(8), 0)]
    {
        let mut r = Reported::to(&q, query_id, 100);
        r.forward_tos_amount = forward.into();
        r.payload = payload;
        let need = net.reported_need(&p, &r);
        let msg = net.reported_message(&p, &p, &r, need + 1);
        let start = net.delivered.len();
        succeeded(&net.send_one(msg));
        // R's own sends exceed the limit; S's message to R is already out.
        net.set_max_msg_cells(cells);
        net.settle();
        net.set_max_msg_cells(limit);
        let at_r = legs(&net, start, OP_INTERNAL_TRANSFER_REPORTED);
        let o = outcome(&at_r[0]);
        assert_eq!(o.exit_code, Some(0), "R's compute phase succeeds");
        assert!(!o.action_ok, "R's action phase fails");
        assert!(o.bounced, "the action failure bounces R's message to S");
        assert_eq!(net.tokens(&q), 0, "R's credit rolled back");
        assert_refused(&net, start, &p, query_id, 100);
    }
    assert_eq!(net.tokens(&p), 1_000, "every refused amount is back at S");
    assert_every_reported_transfer_ended(&net);
}

/// T-R2: a bounce whose value cannot pay S's handler is paid from S's own
/// balance once S raises its gas limit: the restore and the record commit, and
/// the report that the bounce cannot fund is skipped instead of rolling them
/// back. The bounce falls short because the gas price rises between R's leg
/// and S's, with no storage reserve or bridge gas in the value, and a deep
/// refusals dictionary makes S's handler its dearest.
#[test]
fn t_r2_a_short_bounce_is_paid_from_the_paying_wallet() {
    let mut net = minted();
    let p = net.user(0);
    let q = net.user(1);
    fill_refusals_deep(&mut net, &p, 0x5555_0000_0000_0000);
    // No storage reserve and no bridge gas: the bounce carries back only the
    // network-priced margins of S's and R's compute.
    net.wallet_min_storage = 0;
    net.wallet_gas = 0;
    net.configure();
    let r = Reported { report_tos_amount: 0, ..Reported::to(&q, 0x5555_0000_0000_0000, 100) };
    let need = net.reported_need(&p, &r);
    let msg = net.reported_message(&p, &p, &r, need + 1);
    let start = net.delivered.len();
    succeeded(&net.send_one(msg));
    net.remove_config();
    net.deliver_until(|m| crate::model::reported_bounce(m).is_some());
    net.configure();
    let bounced_value = value_of(net.queue.front().expect("the bounce"));
    let gas = net.gas_price(false);
    let factor = (bounced_value / gas_fee(&net, declared_u64("S_BOUNCE_GAS") / 4) + 2) as u64;
    net.set_gas_price(false, gas * factor);
    net.settle();
    let bounce = bounce_legs(&net, start);
    assert_eq!(bounce.len(), 1, "the bounce reaches S");
    let o = outcome(&bounce[0]);
    let handler_fee = gas_fee(&net, o.gas_used);
    net.set_gas_price(false, gas);
    assert!(!o.aborted, "S's handler commits");
    assert!(
        bounced_value < handler_fee,
        "the bounce ({bounced_value}) is short of S's handler ({handler_fee})"
    );
    assert_eq!(net.tokens(&p), 1_000, "the tokens are back at S");
    assert_eq!(net.refusal(&p, r.query_id), 100, "S records the refusal");
    assert!(
        sent_to(&net, start, &p, OP_TRANSFER_REFUSED).is_empty(),
        "the report the bounce could not pay is skipped"
    );
    // Anyone may fund the report again.
    let msg = net.wallet_query(net.stranger.address(), &p, OP_REREPORT_REFUSAL, r.query_id, TOS);
    let start = net.delivered.len();
    succeeded(&net.send(msg));
    assert_eq!(
        refused_fields(&sent_to(&net, start, &p, OP_TRANSFER_REREPORTED)[0]),
        (r.query_id, 100)
    );
    assert_every_reported_transfer_ended(&net);
}

/// Replaces `owner`'s refusals with the deepest shape around `key` that
/// REFUSALS_LIMIT allows: the keys `key xor 2^i` for every i below the limit
/// less one, so a refusal of `key` walks and rebuilds a fork for each, and
/// brings the wallet to its limit.
fn fill_refusals_deep(net: &mut Net, owner: &MsgAddressInt, key: u64) {
    let others = declared_u64("REFUSALS_LIMIT") - 1;
    net.patch_wallet(owner, |w| {
        let mut d = HashmapE::with_bit_len(64);
        let value = SliceData::load_cell(cell(|b| coins(b, 1))).unwrap();
        for i in 0..others {
            let mut k = BuilderData::new();
            k.append_u64(key ^ (1u64 << i)).unwrap();
            d.set(SliceData::load_builder(k).unwrap(), &value).unwrap();
        }
        w.refusals = d.data().cloned();
        w.refusals_count = others as u16;
    });
    let wallet = account_hash(&net.wallet_of(owner));
    net.model.refusal_records.retain(|(w, _), _| *w != wallet);
}

/// T-R2: with no storage reserve in ConfigParam 79 and no bridge gas, an R
/// that runs out of its capped gas (a test-only build) still bounces funded:
/// the value S required prices S's own compute from the network, so nothing of
/// R's budget depends on the reserve. No token is lost.
#[test]
fn t_r2_out_of_gas_at_r_is_funded_without_a_storage_reserve() {
    let _variant = use_codes(wallet_variant("r-gas-no-reserve", |s| {
        let line = format!("const int R_GAS_LIMIT = {};", declared("R_GAS_LIMIT"));
        assert!(s.contains(&line), "the wallet declares R_GAS_LIMIT");
        s.replace(&line, "const int R_GAS_LIMIT = 8000;")
    }));
    let mut net = minted();
    let p = net.user(0);
    let q = net.user(1);
    net.wallet_min_storage = 0;
    net.wallet_gas = 0;
    net.configure();
    for (query_id, payload) in [(91u64, Payload::Inline(0)), (92, Payload::Chain(largest_chain()))]
    {
        let r = Reported { report_tos_amount: 0, payload, ..Reported::to(&q, query_id, 100) };
        let start = net.delivered.len();
        succeeded(&send_funded(&mut net, &p, &r));
        let at_r = legs(&net, start, OP_INTERNAL_TRANSFER_REPORTED);
        let o = outcome(&at_r[0]);
        assert_eq!(o.exit_code, Some(-14), "R runs out of its capped gas");
        assert!(o.bounced, "the bounce is funded without a storage reserve");
        assert_eq!(net.tokens(&p), 1_000, "no token is lost");
        assert_eq!(net.refusal(&p, query_id), 100, "S records the refusal");
    }
    assert_every_reported_transfer_ended(&net);
}

/// T-R2: two reported transfers under one query id, both in flight and both
/// refused. The record keeps their total, so the second refusal does not lose
/// the first; each report names its own amount, and a re-report names the
/// total. Clearing removes the record whole.
#[test]
fn t_r2_a_second_refusal_under_one_query_id_adds_to_the_record() {
    let mut net = minted();
    let p = net.user(0);
    let q = net.user(1);
    let start = net.delivered.len();
    for amount in [100u128, 30] {
        let r = Reported::to(&q, 95, amount);
        let need = net.reported_need(&p, &r);
        let msg = net.reported_message(&p, &p, &r, need + 1);
        succeeded(&net.send_one(msg));
    }
    net.remove_config();
    net.settle();
    net.configure();
    assert_eq!(net.tokens(&p), 1_000, "both amounts are back at S");
    assert_eq!(net.refusal(&p, 95), 130, "the record keeps both refusals");
    assert_eq!(net.refusals_count(&p), 1, "one record, one count");
    let mut reports: Vec<(u64, u128)> =
        sent_to(&net, start, &p, OP_TRANSFER_REFUSED).iter().map(refused_fields).collect();
    reports.sort();
    assert_eq!(reports, vec![(95, 30), (95, 100)], "each report names its own amount");
    let start = net.delivered.len();
    let msg = net.wallet_query(net.stranger.address(), &p, OP_REREPORT_REFUSAL, 95, TOS);
    succeeded(&net.send(msg));
    assert_eq!(refused_fields(&sent_to(&net, start, &p, OP_TRANSFER_REREPORTED)[0]), (95, 130));
    let msg = net.wallet_query(&p, &p, OP_CLEAR_REFUSAL, 95, TOS);
    succeeded(&net.send(msg));
    assert_eq!(net.refusal(&p, 95), -1, "clearing removes the whole record");
    assert_eq!(net.refusals_count(&p), 0, "and its count");
    assert_every_reported_transfer_ended(&net);
}

// ---------------------------------------------------------------------------
// T-R3: S fails in its action phase
// ---------------------------------------------------------------------------

/// T-R3: S's message to R cannot be sent (its StateInit is over the message
/// limit). +16 bounces P's message back to P, and nothing at S changes.
#[test]
fn t_r3_an_action_failure_at_s_bounces_to_the_payer() {
    let mut net = minted();
    let p = net.user(0);
    let q = net.user(1);
    let limit = net.max_msg_cells();
    let r = Reported::to(&q, 3, 300);
    let need = net.reported_need(&p, &r);
    let msg = net.reported_message(&p, &p, &r, need + 1);
    net.set_max_msg_cells(4);
    let before = net.state_hashes();
    let start = net.delivered.len();
    let tx = net.send(msg);
    net.set_max_msg_cells(limit);
    let o = outcome(&tx);
    assert_eq!(o.exit_code, Some(0), "S's compute phase succeeds");
    assert!(!o.action_ok, "S's action phase fails");
    assert!(o.bounced, "S's action failure bounces P's message");
    assert_eq!(bounced_to(&net, start, &p), 1, "P gets its message back");
    assert_unchanged(&net, &before, "an action failure at S");
    assert!(legs(&net, start, OP_INTERNAL_TRANSFER_REPORTED).is_empty(), "nothing reached R");
    assert_eq!(net.tokens(&p), 1_000);
    assert_every_reported_transfer_ended(&net);
}

// ---------------------------------------------------------------------------
// T-R4: every refusal at S
// ---------------------------------------------------------------------------

fn raw_address(build: impl FnOnce(&mut BuilderData)) -> Cell {
    cell(build)
}

/// T-R4: each check S makes in its compute phase refuses, bounces P's message
/// to P and changes nothing.
#[test]
fn t_r4_every_refusal_at_the_paying_wallet_bounces_and_changes_nothing() {
    let mut net = minted();
    let p = net.user(0);
    let q = net.user(1);
    let hash = account_hash(&q);
    let stranger = net.stranger.address().clone();
    let base = Reported::to(&q, 12, 100);
    let mut cases: Vec<(&str, MsgAddressInt, Reported, Option<u128>, i32)> = Vec::new();
    cases.push((
        "not the owner",
        stranger.clone(),
        base.clone(),
        None,
        err("unauthorized_transfer"),
    ));
    cases.push((
        "zero amount",
        p.clone(),
        Reported { amount: 0, ..base.clone() },
        None,
        err("not_enough_funds"),
    ));
    cases.push((
        "above the balance",
        p.clone(),
        Reported { amount: 1_001, ..base.clone() },
        None,
        err("not_enough_funds"),
    ));
    let none = raw_address(|b| {
        b.append_bits(0, 2).unwrap();
    });
    let masterchain = raw_address(|b| {
        MsgAddressInt::with_params(-1, UInt256::from_slice(&hash)).unwrap().write_to(b).unwrap();
    });
    let anycast = raw_address(|b| {
        b.append_bits(0b10, 2).unwrap();
        b.append_bit_one().unwrap();
        b.append_bits(5, 5).unwrap();
        b.append_bits(0b10101, 5).unwrap();
        b.append_i8(0).unwrap();
        b.append_raw(&hash, 256).unwrap();
    });
    let var = raw_address(|b| {
        b.append_bits(0b11, 2).unwrap();
        b.append_bit_zero().unwrap();
        b.append_bits(256, 9).unwrap();
        b.append_i32(0).unwrap();
        b.append_raw(&hash, 256).unwrap();
    });
    for (what, destination) in [("the masterchain", masterchain), ("no address", none)] {
        cases.push((
            what,
            p.clone(),
            Reported { destination, ..base.clone() },
            None,
            err("not_canonical_destination"),
        ));
    }
    // Since global version 10 the VM refuses to load anycast and addr_var
    // addresses at all (a cell underflow), before the canonical check.
    for (what, destination) in [("anycast", anycast), ("addr_var", var)] {
        cases.push((what, p.clone(), Reported { destination, ..base.clone() }, None, 9));
    }
    cases.push((
        "no forward payload",
        p.clone(),
        Reported { payload: Payload::Absent, ..base.clone() },
        None,
        err("malformed_forward_payload"),
    ));
    cases.push((
        "a body over the cell cap",
        p.clone(),
        Reported { payload: Payload::Chain(largest_chain() + 1), ..base.clone() },
        None,
        err("payload_too_large"),
    ));
    let need = net.reported_need(&p, &base);
    cases.push(("exactly the need", p.clone(), base.clone(), Some(need), err("not_enough_tos")));
    for (what, sender, r, value, code) in cases {
        let value = value.unwrap_or(need + TOS as u128);
        let msg = net.reported_message(&sender, &p, &r, value);
        let before = net.state_hashes();
        let start = net.delivered.len();
        let tx = net.send(msg);
        assert_eq!(outcome(&tx).exit_code, Some(code), "{what}: S refuses with {code}");
        refused_with(&tx, code);
        assert!(outcome(&tx).bounced, "{what}: the refusal bounces to the sender");
        assert_eq!(bounced_to(&net, start, &sender), 1, "{what}: the sender gets its message back");
        assert_unchanged(&net, &before, what);
        assert!(
            legs(&net, start, OP_INTERNAL_TRANSFER_REPORTED).is_empty(),
            "{what}: nothing sent"
        );
    }
    // ConfigParam 79 absent: S cannot price the transfer and refuses it.
    net.remove_config();
    let msg = net.reported_message(&p, &p, &base, need + TOS as u128);
    let start = net.delivered.len();
    let tx = net.send(msg);
    refused_with(&tx, err("no_bridge_config"));
    assert_eq!(bounced_to(&net, start, &p), 1, "no configuration: the refusal bounces to P");
    net.configure();
    // need + 1 is enough
    succeeded(&send_reported(&mut net, &p, &base, need + 1));
    assert_eq!(net.tokens(&q), 100);
    assert_every_reported_transfer_ended(&net);
}

// ---------------------------------------------------------------------------
// T-R5: the value check is priced from the network
// ---------------------------------------------------------------------------

/// Total cells and bits of `c`, its root included, each distinct cell once.
fn size_of(c: &Cell) -> (u64, u64) {
    size_in(c, &mut std::collections::HashSet::new())
}

fn size_in(c: &Cell, seen: &mut std::collections::HashSet<UInt256>) -> (u64, u64) {
    fn visit(c: &Cell, seen: &mut std::collections::HashSet<UInt256>, n: &mut (u64, u64)) {
        if !seen.insert(c.repr_hash()) {
            return;
        }
        n.0 += 1;
        n.1 += c.bit_length() as u64;
        for i in 0..c.references_count() {
            visit(&c.reference(i).unwrap(), seen, n);
        }
    }
    let mut n = (0, 0);
    visit(c, seen, &mut n);
    n
}

/// The need recomputed here, term by term, from the message S actually sent:
/// S prices the message as it builds it, before the network fills in its
/// source, times and fees, so the root is that of the relaxed message (flags,
/// destination, zero value, 108 bits of zeroed fields with the StateInit and
/// body flags) and the rest is the StateInit and the body as sent.
fn need_from_terms(net: &Net, sent: &Message, r: &Reported) -> u128 {
    let init = sent.state_init().expect("a StateInit").serialize().unwrap();
    let body = settlement_body(sent).into_cell().unwrap();
    let mut seen = std::collections::HashSet::new();
    let mut n = (1u64, 6 + 267 + 4 + 108);
    for c in [&init, &body] {
        let (cells, bits) = size_in(c, &mut seen);
        n.0 += cells;
        n.1 += bits;
    }
    let (cells, bits) = n;
    let (body_cells, _) = size_of(&body);
    // R's compute, its bounce and its fine at REPORT_MARGIN times the price
    let margin = declared("REPORT_MARGIN") as u128;
    let compute = margin * gas_fee(net, declared_u64("R_GAS_LIMIT")).max(net.wallet_gas.into())
        + gas_fee(net, declared_u64("S_TRANSFER_GAS"));
    r.forward_tos_amount
        + r.report_tos_amount
        + fwd_fee(net, bits, cells)
        + margin * fwd_fee(net, 32 + 256, 1)
        + compute
        + margin * fwd_fee(net, 0, body_cells + 2)
        + u128::from(net.wallet_min_storage)
}

/// T-R5: with ConfigParam 79's wallet_gas_consumption set far too low, the
/// value check still prices R's compute at the network's gas price, and R is
/// funded: the transfer at exactly the need is delivered.
#[test]
fn t_r5_a_low_bridge_gas_price_cannot_underfund_the_recipient() {
    let mut net = minted();
    let p = net.user(0);
    let q = net.user(1);
    let mut r = Reported::to(&q, 21, 100);
    r.forward_tos_amount = (TOS / 10).into();
    r.payload = Payload::Chain(3);
    let configured = net.reported_need(&p, &r);
    net.wallet_gas = 1;
    net.configure();
    let low = net.reported_need(&p, &r);
    let network = gas_fee(&net, declared_u64("R_GAS_LIMIT"));
    assert!(network > 1, "the network price of R_GAS_LIMIT is above the mis-set bridge gas");
    assert_eq!(
        configured - low,
        declared("REPORT_MARGIN") as u128 * (u128::from(TOS / 50) - network),
        "the network-priced compute term replaces the mis-set bridge gas"
    );
    let start = net.delivered.len();
    succeeded(&send_reported(&mut net, &p, &r, low + 1));
    let sent = sent_to(&net, start, &net.wallet_of(&q), OP_INTERNAL_TRANSFER_REPORTED);
    assert_eq!(need_from_terms(&net, &sent[0], &r), low, "the need is the sum of its terms");
    let at_r = legs(&net, start, OP_INTERNAL_TRANSFER_REPORTED);
    succeeded(&at_r[0]);
    assert!(
        gas_fee(&net, outcome(&at_r[0]).gas_used) <= network,
        "R's compute is within what S priced"
    );
    assert_eq!(net.tokens(&q), 100, "delivered at exactly the network-priced need");
    assert_eq!(sent_to(&net, start, &p, OP_TRANSFER_DELIVERED).len(), 1);
    // A bridge price above the network's is used as is.
    net.wallet_gas = TOS / 50;
    net.configure();
    let start = net.delivered.len();
    succeeded(&send_funded(&mut net, &p, &Reported { query_id: 22, ..r.clone() }));
    let sent = sent_to(&net, start, &net.wallet_of(&q), OP_INTERNAL_TRANSFER_REPORTED);
    let r22 = Reported { query_id: 22, ..r };
    assert_eq!(
        need_from_terms(&net, &sent[0], &r22),
        configured,
        "the need is the sum of its terms"
    );
    assert_every_reported_transfer_ended(&net);
}

// ---------------------------------------------------------------------------
// T-R6: prices change between the legs
// ---------------------------------------------------------------------------

/// Sends `r` and scales the basechain's gas and forwarding prices by `factor`
/// before R runs. Returns the start of the run.
fn with_prices_raised(net: &mut Net, p: &MsgAddressInt, r: &Reported, factor: u64) -> usize {
    let need = net.reported_need(p, r);
    let msg = net.reported_message(p, p, r, need + 1);
    let start = net.delivered.len();
    succeeded(&net.send_one(msg));
    let gas = net.gas_price(false);
    net.set_gas_price(false, gas * factor);
    net.scale_forward_prices(false, factor, 1);
    net.settle();
    net.set_gas_price(false, gas);
    net.scale_forward_prices(false, 1, factor);
    start
}

/// T-R6: gas and forwarding prices rise between S and R by less than
/// REPORT_MARGIN: R delivers, and the report still pays for the payer's
/// pre-accept work at the new prices.
#[test]
fn t_r6_a_price_rise_within_the_report_margin_is_absorbed() {
    let mut net = minted();
    let p = net.user(0);
    let q = net.user(1);
    let mut r = Reported::to(&q, 31, 100);
    r.report_tos_amount = report_funding(&net);
    let factor = 9;
    let cost_at_old = report_cost_now(&net);
    let start = with_prices_raised(&mut net, &p, &r, factor);
    let delivered = sent_to(&net, start, &p, OP_TRANSFER_DELIVERED);
    assert_eq!(delivered.len(), 1, "R delivers after the rise");
    assert!(
        value_of(&delivered[0]) >= cost_at_old * u128::from(factor),
        "the report pays for P's pre-accept work at {factor} times the prices"
    );
    assert_eq!(net.tokens(&q), 100);
    assert_every_reported_transfer_ended(&net);
}

/// T-R6: the same rise with nothing in ConfigParam 79 to absorb it: no storage
/// reserve, no bridge gas and no report value, at exactly the need and to a
/// fresh R. R's compute, its bounce and its action fine are priced with
/// REPORT_MARGIN, so up to that factor every transfer still ends, delivered or
/// refused, and no token is lost.
#[test]
fn t_r6_a_rise_within_the_margin_ends_every_transfer_without_a_reserve() {
    let mut net = minted();
    let p = net.user(0);
    net.wallet_min_storage = 0;
    net.wallet_gas = 0;
    net.configure();
    for (i, factor) in [7u64, 8, 9].into_iter().enumerate() {
        let fresh = MsgAddressInt::with_params(0, UInt256::from([0x60 + i as u8; 32])).unwrap();
        let r = Reported { report_tos_amount: 0, ..Reported::to(&fresh, 101 + i as u64, 10) };
        let start = with_prices_raised(&mut net, &p, &r, factor);
        let delivered = sent_to(&net, start, &p, OP_TRANSFER_DELIVERED).len();
        let refused = net.refusal(&p, r.query_id) >= 0;
        assert_eq!(
            usize::from(refused) + delivered,
            1,
            "at {factor} times the prices the transfer ends once"
        );
    }
    assert_every_reported_transfer_ended(&net);
}

/// T-R6: just beyond the margin, with no reserve, no bridge gas and no report
/// value. R spends at most half of R_GAS_LIMIT, so at 11 times the prices it
/// still delivers and the tokens are conserved. The guarantee stops at the
/// margin: SETTLEMENT-PROTOCOL.md section 20.7 records where, measured, a
/// transfer stops ending (30 times the prices without a reserve).
#[test]
fn t_r6_just_beyond_the_margin_without_a_reserve_it_still_delivers() {
    let mut net = minted();
    let p = net.user(0);
    net.wallet_min_storage = 0;
    net.wallet_gas = 0;
    net.configure();
    let factor = REPORT_MARGIN as u64 + 1;
    let fresh = MsgAddressInt::with_params(0, UInt256::from([0x6f; 32])).unwrap();
    let r = Reported { report_tos_amount: 0, ..Reported::to(&fresh, 111, 10) };
    let start = with_prices_raised(&mut net, &p, &r, factor);
    assert_eq!(sent_to(&net, start, &p, OP_TRANSFER_DELIVERED).len(), 1, "R still delivers");
    assert_eq!(net.tokens(&fresh), 10, "the tokens moved once");
    assert_every_reported_transfer_ended(&net);
}

/// T-R6: a rise beyond REPORT_MARGIN. R itself is still funded by its margins
/// (R_GAS_LIMIT is twice its use, and the storage reserve), so it delivers and
/// the tokens are conserved, but the report no longer pays for the payer's
/// pre-accept work: this is the bound B2 of the design, outside which a
/// delivery report can be lost.
#[test]
fn t_r6_a_price_rise_beyond_the_report_margin_leaves_the_report_short() {
    let mut net = minted();
    let p = net.user(0);
    let q = net.user(1);
    let mut r = Reported::to(&q, 32, 100);
    r.report_tos_amount = report_funding(&net);
    // the least whole factor at which the report falls short
    let factor = (r.report_tos_amount / report_cost_now(&net) + 1) as u64;
    eprintln!("T-R6 beyond the margin: prices times {factor}");
    assert!(factor > REPORT_MARGIN as u64, "beyond the margin");
    let start = with_prices_raised(&mut net, &p, &r, factor);
    let delivered = sent_to(&net, start, &p, OP_TRANSFER_DELIVERED);
    assert_eq!(delivered.len(), 1, "R still delivers");
    assert_eq!(net.tokens(&q), 100, "the tokens moved once");
    let gas = net.gas_price(false);
    net.set_gas_price(false, gas * factor);
    net.scale_forward_prices(false, factor, 1);
    let cost_now = report_cost_now(&net);
    net.set_gas_price(false, gas);
    net.scale_forward_prices(false, 1, factor);
    assert!(
        value_of(&delivered[0]) < cost_now,
        "beyond the margin the report no longer pays for P's pre-accept work"
    );
    assert_every_reported_transfer_ended(&net);
}

// ---------------------------------------------------------------------------
// T-R7: re-report, clear, duplicate query ids
// ---------------------------------------------------------------------------

/// T-R7: a recorded refusal blocks its query id, is re-reported for anyone who
/// funds it, and is cleared only by the owner; then the query id is free.
#[test]
fn t_r7_rereport_clear_and_a_duplicate_query_id() {
    let mut net = minted();
    let p = net.user(0);
    let q = net.user(1);
    let stranger = net.stranger.address().clone();
    let r = Reported::to(&q, 41, 200);
    refuse_at_r(&mut net, &p, &r);
    refuse_at_r(&mut net, &p, &Reported::to(&q, 42, 10));
    assert_eq!(net.refusals_count(&p), 2, "two refusals recorded");
    // a duplicate query id is refused at S while its refusal is recorded
    let start = net.delivered.len();
    let tx = send_funded(&mut net, &p, &r);
    refused_with(&tx, err("refusal_pending"));
    assert_eq!(bounced_to(&net, start, &p), 1, "the duplicate bounces to P");
    // anyone may fund a re-report; the record stays
    let start = net.delivered.len();
    let msg = net.wallet_query(&stranger, &p, OP_REREPORT_REFUSAL, 41, TOS);
    let tx = net.send(msg);
    succeeded(&tx);
    let refused = sent_to(&net, start, &p, OP_TRANSFER_REREPORTED);
    assert_eq!(refused.len(), 1, "the refusal is reported again");
    assert_eq!(refused_fields(&refused[0]), (41, 200));
    assert!(
        sent_to(&net, start, &p, OP_TRANSFER_REFUSED).is_empty(),
        "a re-report is not a new refusal"
    );
    assert_eq!(net.refusal(&p, 41), 200, "a re-report keeps the record");
    // a re-report that pays for its compute but not for the report's
    // forwarding fails in its action phase and keeps the record
    let short = gas_fee(&net, outcome(&tx).gas_used) + fwd_fee(&net, 0, 0) / 2;
    let before = net.state_hashes();
    let msg = net.wallet_query(&stranger, &p, OP_REREPORT_REFUSAL, 41, short as u64);
    let tx = net.send(msg);
    assert_eq!(outcome(&tx).exit_code, Some(0), "the short re-report computes");
    assert!(outcome(&tx).aborted, "an unfunded re-report fails");
    assert_unchanged(&net, &before, "an unfunded re-report");
    // a re-report of an unknown query id sends nothing
    let start = net.delivered.len();
    let msg = net.wallet_query(&stranger, &p, OP_REREPORT_REFUSAL, 99, TOS);
    succeeded(&net.send(msg));
    assert!(
        sent_to(&net, start, &p, OP_TRANSFER_REREPORTED).is_empty(),
        "a re-report of an unknown query sends nothing"
    );
    // only the owner clears
    let msg = net.wallet_query(&stranger, &p, OP_CLEAR_REFUSAL, 41, TOS);
    refused_with(&net.send(msg), err("unauthorized_transfer"));
    assert_eq!(net.refusal(&p, 41), 200, "a stranger cannot clear a refusal");
    let msg = net.wallet_query(&p, &p, OP_CLEAR_REFUSAL, 41, TOS);
    succeeded(&net.send(msg));
    assert_eq!(net.refusal(&p, 41), -1, "the owner clears it");
    assert_eq!(net.refusals_count(&p), 1, "the other stays");
    // clearing an absent record changes nothing
    let msg = net.wallet_query(&p, &p, OP_CLEAR_REFUSAL, 41, TOS);
    succeeded(&net.send(msg));
    // nothing to re-report once cleared
    let start = net.delivered.len();
    let msg = net.wallet_query(&stranger, &p, OP_REREPORT_REFUSAL, 41, TOS);
    succeeded(&net.send(msg));
    assert!(
        sent_to(&net, start, &p, OP_TRANSFER_REREPORTED).is_empty(),
        "a cleared refusal is not reported"
    );
    // the query id is free again
    succeeded(&send_funded(&mut net, &p, &r));
    assert_eq!(net.tokens(&q), 200, "the query id is reusable once cleared");
    assert_every_reported_transfer_ended(&net);
}

// ---------------------------------------------------------------------------
// T-R8: spoofed reports
// ---------------------------------------------------------------------------

/// T-R8: nobody but R can tell P that its transfer was delivered, and nobody
/// but S that it was refused. An excess for P's query id, another sender's
/// delivery, a forged incoming transfer naming P, a wallet of another token,
/// and a forged refusal or bounce sent to S are all told apart or refused.
#[test]
fn t_r8_spoofed_reports_are_told_apart_or_refused() {
    let mut net = minted();
    let p = net.user(0);
    let q = net.user(1);
    let stranger = net.stranger.address().clone();
    net.swap_to(&stranger, 50);
    // P's transfer 51 is in flight.
    let r = Reported::to(&q, 51, 100);
    let need = net.reported_need(&p, &r);
    let msg = net.reported_message(&p, &p, &r, need + 1);
    succeeded(&net.send_one(msg));
    let held = net.take(|m| body_op(m) == Some(OP_INTERNAL_TRANSFER_REPORTED));
    net.model.held += 100;
    let start = net.delivered.len();
    // (a) the stranger's genuine transfer with P as response and P's query id:
    // P gets an excess, which proves nothing, and no delivery report.
    let wallet = net.wallet_of(&stranger);
    let spoof = MessageBuilder::internal(&stranger, &wallet, TOS)
        .body(transfer_body(51, 1, &q, &p, 0, &Payload::Inline(0)))
        .build();
    succeeded(&net.send(spoof));
    assert_eq!(sent_to(&net, start, &p, OP_EXCESSES).len(), 1, "the excess reaches P");
    // (b) the stranger's own reported transfer reports to the stranger
    succeeded(&send_funded(&mut net, &stranger, &Reported::to(&q, 51, 1)));
    assert_eq!(
        sent_to(&net, start, &stranger, OP_TRANSFER_DELIVERED).len(),
        1,
        "it reports to its own payer"
    );
    // (c) a forged incoming transfer naming P as its sender is refused by R
    let forged_body = settlement_body(&held).into_cell().unwrap();
    let forge = MessageBuilder::internal(&stranger, &net.wallet_of(&q), TOS)
        .bounce(true)
        .body(forged_body.clone())
        .build();
    let tx = net.send(forge);
    refused_with(&tx, err("unauthorized_incoming_transfer"));
    // (d) a wallet of another token is not P's wallet of this one
    net.start_swap_token(&p, 20, 0x5b);
    net.settle();
    let foreign = net.wallet_in(&net.minter_of(0x5b), &p);
    // (on chain only that wallet's code could send it; non-bounceable here, so
    // no bounce credits that wallet with tokens it never sent)
    let forge = MessageBuilder::internal(&foreign, &net.wallet_of(&q), TOS)
        .bounce(false)
        .body(forged_body)
        .build();
    refused_with(&net.send(forge), err("unauthorized_incoming_transfer"));
    assert!(
        sent_to(&net, start, &p, OP_TRANSFER_DELIVERED).is_empty(),
        "no delivery report reached P"
    );
    // (e) a forged refusal, a forged bounce (not flagged as one) and the other
    // reports sent to S are unknown operations there
    let s = net.wallet_of(&p);
    let mut fake_bounce = BuilderData::new();
    fake_bounce.append_u32(0xffff_ffff).unwrap();
    fake_bounce.append_u32(OP_INTERNAL_TRANSFER_REPORTED).unwrap();
    fake_bounce.append_u64(51).unwrap();
    coins(&mut fake_bounce, 100);
    let fakes = [
        cell(|b| {
            b.append_u32(OP_TRANSFER_REFUSED).unwrap().append_u64(51).unwrap();
            coins(b, 100);
        }),
        fake_bounce.into_cell().unwrap(),
        cell(|b| {
            b.append_u32(OP_TRANSFER_DELIVERED).unwrap().append_u64(51).unwrap();
            coins(b, 100);
            q.write_to(b).unwrap();
        }),
        cell(|b| {
            b.append_u32(OP_TAKE_BALANCE).unwrap().append_u64(51).unwrap();
            coins(b, 5_000);
        }),
    ];
    for body in fakes {
        let before = net.state_hashes();
        let tx =
            net.send(MessageBuilder::internal(&stranger, &s, TOS).bounce(true).body(body).build());
        refused_with(&tx, err("unknown_op"));
        assert_unchanged(&net, &before, "a forged report at S");
    }
    assert_eq!(net.tokens(&p), 900, "S's balance is untouched");
    assert_eq!(net.refusals_count(&p), 0, "nothing recorded");
    // the real transfer ends as delivered, once
    let start = net.delivered.len();
    net.model.held -= 100;
    net.send(held);
    assert_eq!(
        sent_to(&net, start, &p, OP_TRANSFER_DELIVERED).len(),
        1,
        "the real delivery reaches P"
    );
    assert_every_reported_transfer_ended(&net);
}

// ---------------------------------------------------------------------------
// T-R9: the balance report
// ---------------------------------------------------------------------------

/// T-R9: the owner, and only the owner, learns the balance as the wallet holds
/// it, including a debit whose transfer is still in flight.
#[test]
fn t_r9_provide_balance_answers_the_owner_only() {
    let mut net = minted();
    let p = net.user(0);
    let q = net.user(1);
    let stranger = net.stranger.address().clone();
    let start = net.delivered.len();
    let msg = net.wallet_query(&p, &p, OP_PROVIDE_BALANCE, 61, TOS);
    succeeded(&net.send(msg));
    let answers = sent_to(&net, start, &p, OP_TAKE_BALANCE);
    assert_eq!(answers.len(), 1, "one answer");
    assert_eq!(balance_fields(&answers[0]), (61, 1_000));
    assert!(value_of(&answers[0]) > 0, "the answer carries the remaining value");
    let msg = net.wallet_query(&stranger, &p, OP_PROVIDE_BALANCE, 62, TOS);
    refused_with(&net.send(msg), err("unauthorized_transfer"));
    // a debit in flight is already out of the balance
    let r = Reported::to(&q, 63, 300);
    let need = net.reported_need(&p, &r);
    let msg = net.reported_message(&p, &p, &r, need + 1);
    succeeded(&net.send_one(msg));
    let held = net.take(|m| body_op(m) == Some(OP_INTERNAL_TRANSFER_REPORTED));
    net.model.held += 300;
    let start = net.delivered.len();
    let msg = net.wallet_query(&p, &p, OP_PROVIDE_BALANCE, 64, TOS);
    succeeded(&net.send(msg));
    assert_eq!(balance_fields(&sent_to(&net, start, &p, OP_TAKE_BALANCE)[0]), (64, 700));
    net.model.held -= 300;
    net.send(held);
    assert_every_reported_transfer_ended(&net);
}

// ---------------------------------------------------------------------------
// T-R10: the dependency on capBounceMsgBody
// ---------------------------------------------------------------------------

/// A refusal at R, checked as T-R2 checks it.
fn refusal_is_restored(cap_bounce_body: bool) {
    let mut net = minted();
    net.set_capability(GlobalCapabilities::CapBounceMsgBody as u64, cap_bounce_body);
    let p = net.user(0);
    let q = net.user(1);
    let start = net.delivered.len();
    refuse_at_r(&mut net, &p, &Reported::to(&q, 71, 300));
    assert_eq!(net.tokens(&p), 1_000, "the tokens are back at S");
    assert_refused(&net, start, &p, 71, 300);
}

/// T-R10: S identifies R's bounce from the 256 bits of body that
/// capBounceMsgBody keeps. With the capability on the refusal is restored;
/// with it off the bounce is empty and the suite fails, which pins the
/// dependency.
#[test]
fn t_r10_the_suite_fails_without_cap_bounce_msg_body() {
    refusal_is_restored(true);
    let without = std::panic::catch_unwind(|| refusal_is_restored(false));
    let message = without
        .expect_err("without capBounceMsgBody the refusal cannot be restored")
        .downcast_ref::<String>()
        .cloned()
        .unwrap_or_default();
    assert!(message.contains("I1:"), "it fails on conservation: {message}");
}

// ---------------------------------------------------------------------------
// T-R11: gas per leg
// ---------------------------------------------------------------------------

/// T-R11: every leg measured at its largest body and its dearest state, with
/// the most each used reported. R_GAS_LIMIT and S_BOUNCE_GAS are at least
/// twice the most measured (every transaction of the suite is held to this as
/// it runs), and the storage reserve covers S_BOUNCE_GAS, which S's bounce
/// handler may buy from it.
#[test]
fn t_r11_gas_per_leg_is_within_its_constants() {
    let mut net = Net::new();
    let p = net.user(0);
    let q = net.user(1);
    let z = net.user(2);
    // the largest amount Coins can hold
    net.swap(MAX_SUPPLY);
    let mut seen: std::collections::BTreeMap<&str, u64> = Default::default();
    let mut note = |what: &'static str, tx: &Transaction| {
        let gas = outcome(tx).gas_used;
        let e = seen.entry(what).or_insert(0);
        *e = (*e).max(gas);
    };
    let shapes = [
        (Payload::Inline(0), 0u128, None),
        (Payload::Inline(180), TOS as u128, Some(z.clone())),
        (Payload::Chain(largest_chain()), TOS as u128, Some(z.clone())),
    ];
    // Delivered transfers take query ids from one range, refusals from another
    // whose keys are 3 * 2^20 apart: no refusal key is ever one bit away from
    // another key, so the deep neighbours never collide with a later transfer.
    let mut query_id = 0x1000_0000_0000_0000u64;
    let mut refused_id = 0xa000_0000_0000_0000u64;
    for (payload, forward, response) in shapes.iter().cloned() {
        for amount in [1u128, MAX_SUPPLY / 16] {
            query_id += 1;
            let r = Reported {
                payload: payload.clone(),
                forward_tos_amount: forward,
                response: response.clone(),
                report_tos_amount: (10 * TOS).into(),
                ..Reported::to(&q, query_id, amount)
            };
            // a TOS above the need: R also sends the excess
            let start = net.delivered.len();
            let need = net.reported_need(&p, &r);
            succeeded(&send_reported(&mut net, &p, &r, need + u128::from(TOS)));
            note("S reported_transfer", &legs(&net, start, OP_REPORTED_TRANSFER)[0]);
            note(
                "R internal_transfer_reported",
                &legs(&net, start, OP_INTERNAL_TRANSFER_REPORTED)[0],
            );
            // the same refused at R, against S's deepest refusals
            refused_id += 3 << 20;
            let query_id = refused_id;
            fill_refusals_deep(&mut net, &p, query_id);
            let start = net.delivered.len();
            refuse_at_r(&mut net, &p, &Reported { query_id, ..r.clone() });
            // S's own leg, looking the query id up at the deepest path the limit allows
            note("S reported_transfer", &legs(&net, start, OP_REPORTED_TRANSFER)[0]);
            note("S bounce (refusals at the limit, 31 forks deep)", &bounce_legs(&net, start)[0]);
            let msg = net.wallet_query(&z, &p, OP_REREPORT_REFUSAL, query_id, TOS);
            let start = net.delivered.len();
            succeeded(&net.send(msg));
            note("S rereport_refusal", &legs(&net, start, OP_REREPORT_REFUSAL)[0]);
            let msg = net.wallet_query(&p, &p, OP_CLEAR_REFUSAL, query_id, TOS);
            let start = net.delivered.len();
            succeeded(&net.send(msg));
            note("S clear_refusal", &legs(&net, start, OP_CLEAR_REFUSAL)[0]);
            let msg = net.wallet_query(&p, &p, OP_PROVIDE_BALANCE, query_id, TOS);
            let start = net.delivered.len();
            succeeded(&net.send(msg));
            note("S provide_balance", &legs(&net, start, OP_PROVIDE_BALANCE)[0]);
        }
    }
    // a fresh R, deployed by the transfer, with every send it can make
    for (i, (payload, response)) in [
        (Payload::Inline(0), None),
        (Payload::Inline(180), Some(z.clone())),
        (Payload::Chain(largest_chain()), Some(z.clone())),
    ]
    .into_iter()
    .enumerate()
    {
        let fresh = MsgAddressInt::with_params(0, UInt256::from([0x30 + i as u8; 32])).unwrap();
        let r = Reported {
            payload,
            response,
            forward_tos_amount: u128::from(TOS),
            report_tos_amount: (10 * TOS).into(),
            ..Reported::to(&fresh, 1 + i as u64, MAX_SUPPLY / 16)
        };
        let need = net.reported_need(&p, &r);
        let start = net.delivered.len();
        succeeded(&send_reported(&mut net, &p, &r, need + u128::from(TOS)));
        note("R internal_transfer_reported", &legs(&net, start, OP_INTERNAL_TRANSFER_REPORTED)[0]);
    }
    let fresh = net.user(3);
    let start = net.delivered.len();
    refuse_at_r(&mut net, &p, &Reported::to(&fresh, 2, 5));
    note("S bounce (refusals empty)", &bounce_legs(&net, start)[0]);
    for (what, gas) in &seen {
        eprintln!("T-R11 gas: {what:<36} {gas:>7}");
    }
    let r_max = seen["R internal_transfer_reported"];
    let t_max = seen["S reported_transfer"];
    eprintln!("T-R11 S_TRANSFER_GAS {} for S at most {t_max}", declared("S_TRANSFER_GAS"));
    assert!(
        2 * t_max <= declared_u64("S_TRANSFER_GAS"),
        "S_TRANSFER_GAS is at least twice S's most"
    );
    let s_max = seen["S bounce (refusals at the limit, 31 forks deep)"]
        .max(seen["S bounce (refusals empty)"]);
    eprintln!("T-R11 R_GAS_LIMIT {} for R at most {r_max}", declared("R_GAS_LIMIT"));
    eprintln!("T-R11 S_BOUNCE_GAS {} for the bounce at most {s_max}", declared("S_BOUNCE_GAS"));
    assert!(2 * r_max <= declared_u64("R_GAS_LIMIT"), "R_GAS_LIMIT is at least twice R's most");
    assert!(
        2 * s_max <= declared_u64("S_BOUNCE_GAS"),
        "S_BOUNCE_GAS is at least twice the bounce's most"
    );
    let reserve = u128::from(net.wallet_min_storage);
    assert!(
        declared("REPORT_MARGIN") as u128 * gas_fee(&net, declared_u64("S_BOUNCE_GAS")) <= reserve,
        "the storage reserve covers S_BOUNCE_GAS at REPORT_MARGIN times the gas price"
    );
    assert!(
        gas_fee(&net, seen["S reported_transfer"]) <= reserve,
        "the storage reserve, which S passes on to R, covers S's own compute"
    );
}

// ---------------------------------------------------------------------------
// T-R12: the mint path does no scaling
// ---------------------------------------------------------------------------

/// T-R12: a token with 6 decimals, like Ethereum USDC: the vote's amount in
/// source units lands in the wallet unchanged, the supply counts it unchanged,
/// and the minter reports the source decimals.
#[test]
fn t_r12_the_mint_path_credits_source_units_unscaled() {
    let mut net = Net::new();
    let user = net.user(0);
    let token = cell(|t| {
        t.append_u32(CHAIN_ID).unwrap();
        t.append_raw(&[0x6c; 20], 160).unwrap();
        t.append_u8(6).unwrap();
    });
    let minter = {
        let r = net.get(&net.bridge, "get_minter_address", vec![StackItem::cell(token.clone())]);
        MsgAddressInt::construct_from(&mut r.slice_at(0)).expect("a minter")
    };
    let amount: u128 = 1_234_567;
    let n = net.next_nonce;
    net.next_nonce += 1;
    succeeded(&net.pay(n));
    let voting = cell(|b| {
        b.append_u8(0).unwrap();
        b.append_u32(GENERATION).unwrap();
        b.append_u64(n).unwrap();
        b.append_u32(CHAIN_ID).unwrap();
        b.append_raw(&EVM_BRIDGE, 160).unwrap();
        b.append_raw(&account_hash(&user), 256).unwrap();
        coins(b, amount);
        b.checked_append_reference(token.clone()).unwrap();
    });
    let vote = net.vote(n + 100, voting);
    net.send(vote);
    let wallet = net.wallet_in(&minter, &user);
    let balance = net.get(&wallet, "get_wallet_data", vec![]).int_at(0) as u128;
    assert_eq!(balance, amount, "the wallet holds the vote's amount in source units");
    assert_eq!(net.supply_state_of(&minter).0, amount as i128, "the supply counts it unscaled");
    let data = net.get(&minter, "get_wrapped_token_data", vec![]);
    assert_eq!(data.int_at(0), i128::from(CHAIN_ID), "the source chain");
    assert_eq!(data.int_at(2), 6, "the minter reports the source's 6 decimals");
}

// ---------------------------------------------------------------------------
// T-R13: the ordinary notification bounces now
// ---------------------------------------------------------------------------

/// T-R13: the behaviour change in ordinary transfers. The receiving wallet
/// sends its notification with +16, so a notification that fails in the action
/// phase bounces the transfer and the sender's wallet restores the tokens.
/// Before, the credit rolled back and nothing came back.
#[test]
fn t_r13_a_failed_ordinary_notification_returns_the_tokens() {
    let mut net = minted();
    let p = net.user(0);
    let q = net.user(1);
    let limit = net.max_msg_cells();
    let wallet = net.wallet_of(&p);
    let msg = MessageBuilder::internal(&p, &wallet, TOS)
        .body(transfer_body(81, 300, &q, &p, (TOS / 10).into(), &Payload::Chain(4)))
        .build();
    let start = net.delivered.len();
    succeeded(&net.send_one(msg));
    net.set_max_msg_cells(3);
    net.settle();
    net.set_max_msg_cells(limit);
    let at_r = legs(&net, start, OP_INTERNAL_TRANSFER);
    let o = outcome(&at_r[0]);
    assert!(!o.action_ok, "the notification fails in R's action phase");
    assert!(o.bounced, "the failed notification bounces the transfer");
    assert_eq!((net.tokens(&p), net.tokens(&q)), (1_000, 0), "the tokens are back at the sender");
    // an ordinary transfer's bounce is not a reported refusal
    assert_eq!(net.refusals_count(&p), 0, "an ordinary bounce records no refusal");
    assert!(
        sent_to(&net, start, &p, OP_TRANSFER_REFUSED).is_empty(),
        "an ordinary bounce sends no transfer_refused"
    );
}

/// T-R14: the largest body S admits, REPORTED_BODY_CELLS cells, is delivered
/// with its whole payload forwarded, S's compute stays within S_TRANSFER_GAS
/// (the harness holds every S leg to half of it), and one cell more is
/// refused by S and by the quote alike.
#[test]
fn t_r14_the_largest_payload_is_delivered_and_one_cell_more_is_refused() {
    let mut net = minted();
    let p = net.user(0);
    let q = net.user(1);
    let r = Reported {
        payload: Payload::Chain(largest_chain()),
        forward_tos_amount: (TOS / 10).into(),
        ..Reported::to(&q, 97, 300)
    };
    let start = net.delivered.len();
    succeeded(&send_funded(&mut net, &p, &r));
    let s = legs(&net, start, OP_REPORTED_TRANSFER);
    let gas = outcome(&s[0]).gas_used;
    assert!(2 * gas <= declared_u64("S_TRANSFER_GAS"), "S used {gas} gas at the largest body");
    assert_eq!(net.tokens(&q), 300, "delivered at the largest body");
    let notified = sent_to(&net, start, &q, OP_TRANSFER_NOTIFICATION);
    assert_eq!(notified.len(), 1, "the whole payload is forwarded");
    let over = Reported { payload: Payload::Chain(largest_chain() + 1), query_id: 98, ..r };
    let wallet = net.wallet_of(&p);
    assert!(
        net.try_get(&wallet, "get_reported_transfer_need", vec![StackItem::cell(over.body())])
            .is_none(),
        "the quote refuses a body over the cap"
    );
    let start = net.delivered.len();
    let tx = send_reported(&mut net, &p, &over, u128::from(10 * TOS));
    refused_with(&tx, err("payload_too_large"));
    assert_eq!(bounced_to(&net, start, &p), 1, "the refusal bounces to P");
    assert_every_reported_transfer_ended(&net);
}

/// T-R15: the refusal limit. With REFUSALS_LIMIT records S refuses a new
/// reported transfer (714). A transfer already in flight when the limit is
/// reached is still refused cleanly: its tokens come back and its report goes
/// out, but no record is kept. Clearing one record admits a transfer again, and
/// its refusal is recorded. The counter follows every step (I11).
#[test]
fn t_r15_the_refusal_limit_bounds_the_records_and_loses_no_token() {
    let mut net = minted();
    let p = net.user(0);
    let q = net.user(1);
    let limit = declared("REFUSALS_LIMIT");
    fill_refusals_deep(&mut net, &p, 0x7700_0000_0000_0000);
    assert_eq!(net.refusals_count(&p), limit - 1, "one below the limit");
    // two transfers in flight, both admitted below the limit, both refused
    let start = net.delivered.len();
    for (query_id, amount) in [(201u64, 40u128), (202, 60)] {
        let r = Reported::to(&q, query_id, amount);
        let need = net.reported_need(&p, &r);
        let msg = net.reported_message(&p, &p, &r, need + 1);
        succeeded(&net.send_one(msg));
    }
    net.remove_config();
    net.settle();
    net.configure();
    assert_eq!(net.tokens(&p), 1_000, "both refused transfers are back at S");
    assert_eq!(net.refusals_count(&p), limit, "the first refusal reaches the limit");
    assert_eq!(net.refusal(&p, 201), 40, "the first is recorded");
    assert_eq!(net.refusal(&p, 202), -1, "the one at the limit is not recorded");
    let mut reports: Vec<(u64, u128)> =
        sent_to(&net, start, &p, OP_TRANSFER_REFUSED).iter().map(refused_fields).collect();
    reports.sort();
    assert_eq!(reports, vec![(201, 40), (202, 60)], "both are reported");
    // at the limit S refuses new reported transfers
    let start = net.delivered.len();
    let tx = send_funded(&mut net, &p, &Reported::to(&q, 203, 10));
    refused_with(&tx, err("refusals_full"));
    assert_eq!(bounced_to(&net, start, &p), 1, "the refusal bounces to P");
    // clearing one admits a transfer again, and its refusal is recorded
    let msg = net.wallet_query(&p, &p, OP_CLEAR_REFUSAL, 201, TOS);
    succeeded(&net.send(msg));
    assert_eq!(net.refusals_count(&p), limit - 1, "clearing counts down");
    refuse_at_r(&mut net, &p, &Reported::to(&q, 204, 25));
    assert_eq!(net.refusal(&p, 204), 25, "a refusal after clearing is recorded");
    assert_eq!(net.refusals_count(&p), limit, "and counted");
    assert_eq!(net.tokens(&p), 1_000, "no token is lost");
    assert_every_reported_transfer_ended(&net);
}

/// The opcodes the suite uses are the ones op-codes.fc declares.
#[test]
fn t_r_opcodes_match_the_sources() {
    for (name, value) in [
        ("op::reported_transfer", OP_REPORTED_TRANSFER),
        ("op::internal_transfer_reported", OP_INTERNAL_TRANSFER_REPORTED),
        ("op::transfer_delivered", OP_TRANSFER_DELIVERED),
        ("op::transfer_refused", OP_TRANSFER_REFUSED),
        ("op::transfer_rereported", OP_TRANSFER_REREPORTED),
        ("op::rereport_refusal", OP_REREPORT_REFUSAL),
        ("op::clear_refusal", OP_CLEAR_REFUSAL),
        ("op::provide_balance", OP_PROVIDE_BALANCE),
        ("op::take_balance", OP_TAKE_BALANCE),
        ("op::transfer_notification", OP_TRANSFER_NOTIFICATION),
    ] {
        assert_eq!(declared(name), i128::from(value), "{name}");
    }
    assert_eq!(
        declared("REPORT_MARGIN"),
        REPORT_MARGIN as i128,
        "the wallet prices R with the payer's report margin"
    );
    let _ = ReportedBody::of;
}
