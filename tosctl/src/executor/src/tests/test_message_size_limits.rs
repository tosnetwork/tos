/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! Outbound message size limits in the action phase, on both sides of each
//! limit. The native engine (crypto/block/transaction.cpp) refuses a message
//! whose body and init exceed `max_msg_cells` or `max_msg_bits`, or the cells
//! the sender's funds can pay a fine for, with result code 40; a special
//! account is refused the same way and only pays no fine.

use super::*;
use chain_block::{
    BuilderData, ConfigParamEnum, ConfigParams, IBitstring, InternalMessageHeader, MsgAddressInt,
    Serializable, SliceData, UInt256,
};

const VALUE: u64 = 1_000_000_000;

fn config(max_msg_cells: u32, max_msg_bits: u32) -> BlockchainConfig {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/real_boc/default_config.boc");
    let mut params = ConfigParams::construct_from_file(path).expect("the fixture configuration");
    let mut limits = params.size_limits_config().expect("size limits");
    limits.max_msg_cells = max_msg_cells;
    limits.max_msg_bits = max_msg_bits;
    params.set_config(ConfigParamEnum::ConfigParam43(limits)).expect("param 43");
    BlockchainConfig::with_config(params).expect("a configuration")
}

fn leaf(tag: u8, bits: usize) -> Cell {
    let mut b = BuilderData::new();
    b.append_u8(tag).unwrap();
    b.append_raw(&vec![0xa5; bits / 8], bits - 8).unwrap();
    b.into_cell().unwrap()
}

/// A body of three distinct cells: a root holding two leaves.
fn body() -> Cell {
    let mut root = BuilderData::new();
    root.append_u32(0x1234_5678).unwrap();
    root.checked_append_reference(leaf(1, 200)).unwrap();
    root.checked_append_reference(leaf(2, 300)).unwrap();
    root.into_cell().unwrap()
}

/// What the native engine counts for a message: every distinct cell of its
/// serialized form but the root, and their bits. Counted here from the
/// message as the handler left it, independently of the counter under test.
fn counted(msg: &Message) -> (u64, u64) {
    fn walk(
        c: &Cell,
        seen: &mut std::collections::HashSet<UInt256>,
        cells: &mut u64,
        bits: &mut u64,
    ) {
        for i in 0..c.references_count() {
            let r = c.reference(i).unwrap();
            if seen.insert(r.repr_hash()) {
                *cells += 1;
                *bits += r.bit_length() as u64;
                walk(&r, seen, cells, bits);
            }
        }
    }
    let root = msg.serialize().unwrap();
    let (mut cells, mut bits) = (0, 0);
    walk(&root, &mut std::collections::HashSet::new(), &mut cells, &mut bits);
    (cells, bits)
}

fn addr(byte: u8) -> MsgAddressInt {
    MsgAddressInt::with_standart(None, 0, [byte; 32].into()).unwrap()
}

/// Sends the three-cell message with `balance` and returns the handler's
/// result and the fine it charged.
fn send(
    cfg: &BlockchainConfig,
    balance: u64,
    special: bool,
    mode: u8,
) -> (std::result::Result<CurrencyCollection, i32>, Coins, Message) {
    let b = body();
    let header = InternalMessageHeader::with_addresses(
        addr(1),
        addr(2),
        CurrencyCollection::with_coins(VALUE),
    );
    let mut msg = Message::with_int_header_and_body(header, SliceData::load_cell(b).unwrap());
    let mut phase = TrActionPhase::default();
    let mut acc_balance = CurrencyCollection::with_coins(balance);
    let mut msg_balance = CurrencyCollection::default();
    let res = outmsg_action_handler(
        &mut phase,
        mode,
        &mut msg,
        &mut acc_balance,
        &mut msg_balance,
        &Coins::zero(),
        cfg,
        special,
        &addr(1),
        &Coins::zero(),
        &mut false,
    );
    (res, phase.action_fine, msg)
}

/// The message's counts, from a send under generous limits.
fn size() -> (u64, u64) {
    let (res, _, msg) = send(&config(1 << 13, 1 << 21), PLENTY, false, 0);
    assert!(res.is_ok(), "the probe is sent: {res:?}");
    let (cells, bits) = counted(&msg);
    assert!(cells >= 2 && bits > 0, "the body's cells are counted: {cells} cells");
    (cells, bits)
}

const PLENTY: u64 = 1_000 * VALUE;

#[test]
fn a_message_at_the_cell_limit_is_sent_and_one_above_it_is_refused() {
    let (cells, bits) = size();
    let (res, _, _) = send(&config(cells as u32, bits as u32 + 1000), PLENTY, false, 0);
    assert!(res.is_ok(), "at the limit: {res:?}");
    let (res, fine, _) = send(&config(cells as u32 - 1, bits as u32 + 1000), PLENTY, false, 0);
    assert_eq!(res, Err(RESULT_CODE_INVALID_BALANCE), "one cell over the limit");
    assert!(!fine.is_zero(), "the visited cells are fined");
}

#[test]
fn a_message_at_the_bit_limit_is_sent_and_one_above_it_is_refused() {
    let (cells, bits) = size();
    let (res, _, _) = send(&config(cells as u32 + 10, bits as u32), PLENTY, false, 0);
    assert!(res.is_ok(), "at the limit: {res:?}");
    let (res, _, _) = send(&config(cells as u32 + 10, bits as u32 - 1), PLENTY, false, 0);
    assert_eq!(res, Err(RESULT_CODE_INVALID_BALANCE), "one bit over the limit");
}

#[test]
fn a_special_account_is_refused_too_and_pays_no_fine() {
    let (cells, bits) = size();
    let (res, _, _) = send(&config(cells as u32, bits as u32), PLENTY, true, 0);
    assert!(res.is_ok(), "at the limits: {res:?}");
    let (res, fine, _) = send(&config(cells as u32 - 1, bits as u32), PLENTY, true, 0);
    assert_eq!(res, Err(RESULT_CODE_INVALID_BALANCE));
    assert!(fine.is_zero(), "a special account pays no fine");
    let (res, _, _) = send(&config(cells as u32, bits as u32 - 1), PLENTY, true, 0);
    assert_eq!(res, Err(RESULT_CODE_INVALID_BALANCE));
}

#[test]
fn the_cells_a_sender_can_fine_for_bound_the_message() {
    let (cells, bits) = size();
    let cfg = config(1 << 13, 1 << 21);
    let fine_per_cell = (cfg.get_fwd_prices(false).cell_price >> 16) / 4;
    assert!(fine_per_cell > 0, "the fixture fines cells");
    // a balance that fines exactly `cells` cells passes the size check; the
    // send then fails for funds, not for size
    let (res, _, _) = send(&cfg, fine_per_cell * cells, false, 0);
    assert_ne!(res, Err(RESULT_CODE_INVALID_BALANCE), "funds for every cell: {res:?}");
    // one cell's fine short: refused for size, fined for the cells it covers
    let (res, fine, _) = send(&cfg, fine_per_cell * cells - 1, false, 0);
    assert_eq!(res, Err(RESULT_CODE_INVALID_BALANCE), "funds for one cell less");
    assert_eq!(fine, Coins::from(fine_per_cell * (cells - 1)), "fined for max_cells, not more");
    let _ = bits;
}

#[test]
fn ignore_errors_skips_an_oversized_message() {
    let (cells, bits) = size();
    let (res, _, _) =
        send(&config(cells as u32 - 1, bits as u32), PLENTY, false, SENDMSG_IGNORE_ERROR);
    assert_eq!(res, Err(RESULT_CODE_SKIPPED));
}
