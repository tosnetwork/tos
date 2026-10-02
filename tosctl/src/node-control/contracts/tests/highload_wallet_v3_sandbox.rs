/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! The high-volume wallet (crypto/smartcont/highload-wallet-v3-code.fc) accepts any number
//! of concurrent signed requests and each query id at most once while it is fresh. These
//! tests deploy the compiled source into the sandbox and drive it with real signed external
//! messages: a transfer, a replay, every pre-acceptance rejection, a request that fails
//! only after acceptance, a batch, and a replay attempted after the wallet has forgotten
//! the query id.

use chain_block::{
    BuilderData, Cell, Coins, CurrencyCollection, IBitstring, InternalMessageHeader, Message,
    MsgAddressInt, Serializable, SliceData, StateInit,
};
use ed25519_dalek::{Signer as _, SigningKey};
use tos_sandbox::{
    Blockchain, MessageBuilder, SandboxResult, SendResult, Treasury, compile_func_with_stdlib,
};
use tos_vm::stack::StackItem;

const TOS: u64 = 1_000_000_000;
const SUBWALLET_ID: u32 = 0x5157;
const TIMEOUT: u32 = 3_600;
const NOW: u32 = 1_800_000_000;
const SEND_MODE_PAY_FEES_SEPARATELY: u8 = 1;
const OP_INTERNAL_TRANSFER: u32 = 0xae42e5a4;

const ERROR_INVALID_SIGNATURE: i32 = 33;
const ERROR_INVALID_SUBWALLET_ID: i32 = 34;
const ERROR_INVALID_TIMEOUT: i32 = 38;
const ERROR_ALREADY_PROCESSED: i32 = 0x1701;
const ERROR_INVALID_QUERY_ID: i32 = 0x1702;
const ERROR_INVALID_CREATED_AT: i32 = 0x1703;

fn smartcont(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../crypto/smartcont").join(name)
}

fn wallet_code() -> Cell {
    compile_func_with_stdlib(&[smartcont("highload-wallet-v3-code.fc")])
        .expect("compile highload wallet")
}

fn cell(build: impl FnOnce(&mut BuilderData)) -> Cell {
    let mut b = BuilderData::new();
    build(&mut b);
    b.into_cell().expect("cell")
}

/// An outbound internal message as a wallet signs it: src addr_none, serialized the way
/// the node's own wallets serialize it.
fn relaxed_message(
    dest: &MsgAddressInt,
    value: u64,
    body: Cell,
    state_init: Option<StateInit>,
) -> Cell {
    let header = InternalMessageHeader {
        bounce: false,
        dst: dest.clone(),
        value: CurrencyCollection::with_coins(value),
        ..Default::default()
    };
    let mut message =
        Message::with_int_header_and_body(header, SliceData::load_cell(body).unwrap());
    if let Some(init) = state_init {
        message.set_state_init(init);
    }
    message.serialize_as_is().unwrap().0.into_cell().unwrap()
}

fn relaxed_transfer(dest: &MsgAddressInt, value: u64) -> Cell {
    relaxed_message(dest, value, Cell::default(), None)
}

/// Same transfer, but carrying a StateInit, which the wallet refuses to send.
fn relaxed_transfer_with_state_init(dest: &MsgAddressInt, value: u64) -> Cell {
    relaxed_message(
        dest,
        value,
        Cell::default(),
        Some(StateInit::with_code_and_data(Cell::default(), Cell::default())),
    )
}

fn append_dict(b: &mut BuilderData, root: Option<Cell>) {
    match root {
        Some(root) => {
            b.append_bits(1, 1).unwrap();
            b.checked_append_reference(root).unwrap();
        }
        None => {
            b.append_bits(0, 1).unwrap();
        }
    }
}

/// A replay dictionary with every one of its 8192 rows present: the largest state a
/// generation can reach. Rows hold no set bits, so every id is still unused.
fn full_generation() -> Cell {
    let row = cell(|b| {
        b.append_raw(&[0u8; 128], 1023).unwrap();
    });
    let mut dict = chain_block::HashmapE::with_bit_len(13);
    for shift in 0u32..8192 {
        let mut key = BuilderData::new();
        key.append_bits(shift as usize, 13).unwrap();
        dict.setref(SliceData::load_builder(key).unwrap(), row.clone()).unwrap();
    }
    chain_block::HashmapType::data(&dict).cloned().expect("non-empty dictionary")
}

/// An internal message whose destination is addr_none: well-formed enough for the
/// wallet's parser, but never deliverable.
fn transfer_to_nowhere(value: u64) -> Cell {
    cell(|b| {
        b.append_bits(0b0100, 4).unwrap(); // int_msg_info$0 ihr_disabled
        b.append_bits(0, 2).unwrap(); // src: addr_none
        b.append_bits(0, 2).unwrap(); // dest: addr_none
        Coins::new(value).write_to(b).unwrap();
        b.append_bits(0, 1).unwrap();
        b.append_bits(0, 4).unwrap(); // extra_flags
        b.append_bits(0, 4).unwrap(); // fwd_fee
        b.append_u64(0).unwrap();
        b.append_u32(0).unwrap();
        b.append_bits(0, 1).unwrap();
        b.append_bits(0, 1).unwrap();
    })
}

/// A transfer that also carries an extra currency.
fn transfer_with_extra_currency(dest: &MsgAddressInt, value: u64) -> Cell {
    let mut amount = CurrencyCollection::with_coins(value);
    amount.set_other(7, 1_000).unwrap();
    let header = InternalMessageHeader {
        bounce: false,
        dst: dest.clone(),
        value: amount,
        ..Default::default()
    };
    Message::with_int_header_and_body(header, SliceData::load_cell(Cell::default()).unwrap())
        .serialize_as_is()
        .unwrap()
        .0
        .into_cell()
        .unwrap()
}

struct Request {
    subwallet_id: u32,
    message: Cell,
    send_mode: u8,
    query_id: u32,
    created_at: u64,
    timeout: u32,
}

struct Fixture {
    bc: Blockchain,
    wallet: MsgAddressInt,
    key: SigningKey,
    target: Treasury,
}

impl Fixture {
    fn new() -> Self {
        Self::with_guard(None, None, 0)
    }

    /// A wallet deployed with the given replay dictionaries and clean time.
    fn with_guard(old_queries: Option<Cell>, queries: Option<Cell>, last_clean_time: u64) -> Self {
        // Genesis global version, with basechain admitted so the wallet can pay out to
        // basechain accounts.
        let mut bc = Blockchain::with_global_version_and_base_workchain(14).expect("blockchain");
        bc.set_now(NOW);
        let funder = bc.treasury("funder", 1_000 * TOS).expect("funder");
        let target = bc.treasury("target", 1_000 * TOS).expect("target");
        let key = SigningKey::from_bytes(&[0x51; 32]);
        let data = cell(|b| {
            b.append_raw(key.verifying_key().as_bytes(), 256).unwrap();
            b.append_u32(SUBWALLET_ID).unwrap();
            append_dict(b, old_queries.clone());
            append_dict(b, queries.clone());
            b.append_u64(last_clean_time).unwrap();
            b.append_bits(TIMEOUT as usize, 22).unwrap();
        });
        let init = StateInit::with_code_and_data(wallet_code(), data);
        let hash = init.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
        let wallet = MsgAddressInt::with_params(0, hash).unwrap();
        let deploy = MessageBuilder::internal(funder.address(), &wallet, 100 * TOS)
            .bounce(false)
            .state_init(init)
            .build();
        bc.send_message(deploy).expect("deploy").expect_success();
        Self { bc, wallet, key, target }
    }

    fn request(&self, query_id: u32, message: Cell) -> Request {
        Request {
            subwallet_id: SUBWALLET_ID,
            message,
            send_mode: SEND_MODE_PAY_FEES_SEPARATELY,
            query_id,
            created_at: (self.bc.now() - 1) as u64,
            timeout: TIMEOUT,
        }
    }

    fn signed(&self, request: &Request, key: &SigningKey) -> Cell {
        let inner = cell(|b| {
            b.append_u32(request.subwallet_id).unwrap();
            b.checked_append_reference(request.message.clone()).unwrap();
            b.append_u8(request.send_mode).unwrap();
            b.append_bits(request.query_id as usize, 23).unwrap();
            b.append_u64(request.created_at).unwrap();
            b.append_bits(request.timeout as usize, 22).unwrap();
        });
        let signature = key.sign(inner.repr_hash().as_slice()).to_bytes();
        cell(|b| {
            b.checked_append_reference(inner).unwrap();
            b.append_raw(&signature, 512).unwrap();
        })
    }

    fn send(&mut self, body: Cell) -> SandboxResult<SendResult> {
        let body = SliceData::load_cell(body).expect("body slice");
        self.bc.send_message(MessageBuilder::external(&self.wallet).body_slice(body).build())
    }

    fn send_signed(&mut self, request: &Request) -> SandboxResult<SendResult> {
        let body = self.signed(request, &self.key.clone());
        self.send(body)
    }

    fn expect_rejected(&mut self, body: Cell, exit_code: i32) {
        let error = match self.send(body) {
            Ok(_) => panic!("request must be rejected before acceptance"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains(&format!("exit code: {exit_code}")),
            "expected exit code {exit_code}, got {error}"
        );
    }

    fn balance(&self, address: &MsgAddressInt) -> u64 {
        self.bc
            .get_account(address)
            .and_then(|account| account.balance().cloned())
            .and_then(|balance| balance.coins.as_u64())
            .expect("balance")
    }

    fn processed(&self, query_id: u32, need_clean: bool) -> bool {
        self.bc
            .run_get_method(
                &self.wallet,
                "processed?",
                vec![
                    StackItem::int(query_id as i64),
                    StackItem::int(if need_clean { -1 } else { 0 }),
                ],
            )
            .expect("processed?")
            .expect_success()
            .int_at(0)
            != 0
    }

    fn get_int(&self, method: &str) -> i128 {
        self.bc
            .run_get_method(&self.wallet, method, vec![])
            .expect(method)
            .expect_success()
            .int_at(0)
    }
}

/// The receiving account pays its own small storage and compute fees on arrival, so a
/// transfer of `value` raises its balance by slightly less than `value`.
fn assert_received(before: u64, after: u64, value: u64, what: &str) {
    let received = after.checked_sub(before).unwrap_or_else(|| panic!("{what}: balance fell"));
    assert!(
        received <= value && received + TOS / 1_000 > value,
        "{what}: received {received}, sent {value}"
    );
}

#[test]
fn signed_transfer_executes_once() {
    let mut f = Fixture::new();
    let before = f.balance(f.target.address());
    let request = f.request(7, relaxed_transfer(f.target.address(), 3 * TOS));
    f.send_signed(&request).expect("accepted").expect_success();
    assert_received(before, f.balance(f.target.address()), 3 * TOS, "transfer");
    assert!(f.processed(7, false), "query id must be recorded");
    assert!(!f.processed(8, false));

    // The identical signed request again: refused before acceptance, nothing moves.
    let replay = f.signed(&request, &f.key.clone());
    let after_first = f.balance(f.target.address());
    f.expect_rejected(replay, ERROR_ALREADY_PROCESSED);
    assert_eq!(f.balance(f.target.address()), after_first, "a rejected replay moves nothing");
}

#[test]
fn concurrent_requests_need_no_ordering() {
    let mut f = Fixture::new();
    let before = f.balance(f.target.address());
    // Ids from different rows and bit positions, out of order.
    for query_id in [5 * 1024 + 9, 3, 1022, 8191 * 1024] {
        let request = f.request(query_id, relaxed_transfer(f.target.address(), TOS));
        f.send_signed(&request).expect("accepted").expect_success();
    }
    assert_received(before, f.balance(f.target.address()), 4 * TOS, "four concurrent transfers");
}

#[test]
fn every_pre_acceptance_check_rejects() {
    let mut f = Fixture::new();
    let message = relaxed_transfer(f.target.address(), TOS);

    let request = f.request(1, message.clone());
    let impostor = SigningKey::from_bytes(&[0x99; 32]);
    let forged = f.signed(&request, &impostor);
    f.expect_rejected(forged, ERROR_INVALID_SIGNATURE);

    let mut other_subwallet = f.request(2, message.clone());
    other_subwallet.subwallet_id = SUBWALLET_ID + 1;
    let body = f.signed(&other_subwallet, &f.key.clone());
    f.expect_rejected(body, ERROR_INVALID_SUBWALLET_ID);

    let mut other_timeout = f.request(3, message.clone());
    other_timeout.timeout = TIMEOUT + 1;
    let body = f.signed(&other_timeout, &f.key.clone());
    f.expect_rejected(body, ERROR_INVALID_TIMEOUT);

    let mut stale = f.request(4, message.clone());
    stale.created_at = (NOW - TIMEOUT) as u64;
    let body = f.signed(&stale, &f.key.clone());
    f.expect_rejected(body, ERROR_INVALID_CREATED_AT);

    let mut future = f.request(5, message.clone());
    future.created_at = (NOW + 1) as u64;
    let body = f.signed(&future, &f.key.clone());
    f.expect_rejected(body, ERROR_INVALID_CREATED_AT);

    let bad_bit = f.request(1023, message.clone());
    let body = f.signed(&bad_bit, &f.key.clone());
    f.expect_rejected(body, ERROR_INVALID_QUERY_ID);

    // None of them consumed an id.
    for query_id in [1, 2, 3, 4, 5] {
        assert!(!f.processed(query_id, false), "rejected request {query_id} must not be recorded");
    }
    // The freshness edge that is accepted: one second inside the window.
    let mut edge = f.request(6, message);
    edge.created_at = (NOW - TIMEOUT + 1) as u64;
    f.send_signed(&edge).expect("accepted").expect_success();
}

#[test]
fn a_request_that_fails_after_acceptance_still_consumes_its_id() {
    let mut f = Fixture::new();
    let before = f.balance(f.target.address());
    let request = f.request(42, relaxed_transfer_with_state_init(f.target.address(), TOS));
    // Accepted (fees paid, state committed), then the outbound message is refused.
    f.send_signed(&request).expect("accepted");
    assert_eq!(f.balance(f.target.address()), before, "a StateInit message must not be sent");
    assert!(f.processed(42, false), "the id is consumed even though nothing was sent");
    let replay = f.signed(&request, &f.key.clone());
    f.expect_rejected(replay, ERROR_ALREADY_PROCESSED);
}

#[test]
fn batch_through_internal_transfer_to_self() {
    let mut f = Fixture::new();
    let before = f.balance(f.target.address());
    // Action list of three sends: out_list$_ prev:^OutList action_send_msg#0ec3c86d mode:uint8 ^msg
    let mut actions = Cell::default();
    for value in [TOS, 2 * TOS, 3 * TOS] {
        let msg = relaxed_transfer(f.target.address(), value);
        let prev = actions;
        actions = cell(|b| {
            b.checked_append_reference(prev).unwrap();
            b.append_u32(0x0ec3c86d).unwrap();
            b.append_u8(SEND_MODE_PAY_FEES_SEPARATELY).unwrap();
            b.checked_append_reference(msg).unwrap();
        });
    }
    let body = cell(|b| {
        b.append_u32(OP_INTERNAL_TRANSFER).unwrap();
        b.append_u64(0).unwrap();
        b.checked_append_reference(actions).unwrap();
    });
    let to_self = relaxed_message(&f.wallet, 10 * TOS, body.clone(), None);
    let request = f.request(100, to_self);
    f.send_signed(&request).expect("accepted").expect_success();
    assert_received(before, f.balance(f.target.address()), 6 * TOS, "three batched sends");

    // The same op from anyone but the wallet itself installs nothing.
    let outsider_before = f.balance(f.target.address());
    let forged = MessageBuilder::internal(f.target.address(), &f.wallet, TOS).body(body).build();
    let result = f.bc.send_message(forged).expect("deliver");
    result.expect_success().expect_out_msgs(0);
    assert!(
        f.balance(f.target.address()) <= outsider_before,
        "no batch may pay out for an outsider"
    );
}

#[test]
fn a_batch_cannot_replace_the_wallet_code() {
    let mut f = Fixture::new();
    let code_before =
        f.bc.get_account(&f.wallet).and_then(|a| a.get_code_hash()).expect("code hash");
    // action_set_code#ad4de08e new_code:^Cell, followed by an ordinary send.
    let hostile_code = cell(|b| {
        b.append_u32(0xdead_c0de).unwrap();
    });
    let set_code = cell(|b| {
        b.checked_append_reference(Cell::default()).unwrap();
        b.append_u32(0xad4de08e).unwrap();
        b.checked_append_reference(hostile_code).unwrap();
    });
    let actions = cell(|b| {
        b.checked_append_reference(set_code).unwrap();
        b.append_u32(0x0ec3c86d).unwrap();
        b.append_u8(SEND_MODE_PAY_FEES_SEPARATELY).unwrap();
        b.checked_append_reference(relaxed_transfer(f.target.address(), TOS)).unwrap();
    });
    let body = cell(|b| {
        b.append_u32(OP_INTERNAL_TRANSFER).unwrap();
        b.append_u64(0).unwrap();
        b.checked_append_reference(actions).unwrap();
    });
    let request = f.request(200, relaxed_message(&f.wallet, 10 * TOS, body, None));
    f.send_signed(&request).expect("accepted").expect_success();
    let code_after =
        f.bc.get_account(&f.wallet).and_then(|a| a.get_code_hash()).expect("code hash");
    assert_eq!(code_after, code_before, "the wallet must keep its own code after any batch");
    // and it still works
    let next = f.request(201, relaxed_transfer(f.target.address(), TOS));
    f.send_signed(&next).expect("accepted").expect_success();
}

#[test]
fn forgotten_ids_are_still_protected_by_freshness() {
    let mut f = Fixture::new();
    let request = f.request(9, relaxed_transfer(f.target.address(), TOS));
    f.send_signed(&request).expect("accepted").expect_success();
    // A fresh wallet's clean time is 0, so its first request rotates and stamps it.
    assert_eq!(f.get_int("get_last_clean_time"), NOW as i128);

    // Past two timeouts the next request drops both generations.
    f.bc.set_now(NOW + 2 * TIMEOUT + 1);
    assert!(f.processed(9, false), "still stored until a request rotates");
    assert!(!f.processed(9, true), "the next rotation forgets it");
    let next = f.request(10, relaxed_transfer(f.target.address(), TOS));
    f.send_signed(&next).expect("accepted").expect_success();
    assert!(!f.processed(9, false), "rotation dropped the old id");
    assert_eq!(f.get_int("get_last_clean_time"), (NOW + 2 * TIMEOUT + 1) as i128);

    // Replaying the forgotten request fails on its timestamp, not on the bitmap.
    let replay = f.signed(&request, &f.key.clone());
    f.expect_rejected(replay, ERROR_INVALID_CREATED_AT);
}

#[test]
fn getters_report_configuration() {
    let f = Fixture::new();
    assert_eq!(f.get_int("get_subwallet_id"), SUBWALLET_ID as i128);
    assert_eq!(f.get_int("get_timeout"), TIMEOUT as i128);
}

#[test]
fn a_full_replay_dictionary_still_fits_the_gas_credit() {
    // Both generations at their maximum size and no rotation due: every request pays for
    // the deepest lookups. Only reads may run before acceptance, or such a wallet would
    // stop accepting anything until a timeout passed.
    let full = full_generation();
    let mut f = Fixture::with_guard(Some(full.clone()), Some(full), NOW as u64);
    let before = f.balance(f.target.address());
    let request = f.request(5 * 1024 + 7, relaxed_transfer(f.target.address(), TOS));
    f.send_signed(&request).expect("accepted within the credit").expect_success();
    assert_received(before, f.balance(f.target.address()), TOS, "transfer from a full wallet");
    assert!(f.processed(5 * 1024 + 7, false));
}

#[test]
fn undeliverable_requests_still_consume_their_id() {
    // The wallet forces IGNORE_ERRORS onto every send, so an undeliverable message is
    // skipped rather than failing the action phase, and the request's id stays used.
    // (This sandbox's executor skips these messages either way; the property is pinned
    // on the node's executor by emulator/test/highload-wallet-action-phase-fixture.cpp.)
    let mut f = Fixture::new();
    for (query_id, message) in [
        (11, transfer_to_nowhere(TOS)),
        (12, transfer_with_extra_currency(f.target.address(), TOS)),
    ] {
        let before = f.balance(f.target.address());
        let request = f.request(query_id, message);
        f.send_signed(&request).expect("accepted");
        assert_eq!(f.balance(f.target.address()), before, "request {query_id} must not send");
        assert!(f.processed(query_id, false), "request {query_id} must consume its id");
        let replay = f.signed(&request, &f.key.clone());
        f.expect_rejected(replay, ERROR_ALREADY_PROCESSED);
    }
}

#[test]
fn processed_reports_unusable_ids_as_unprocessed() {
    let f = Fixture::new();
    for query_id in [1023i64, -1, 1 << 23] {
        let result =
            f.bc.run_get_method(
                &f.wallet,
                "processed?",
                vec![StackItem::int(query_id), StackItem::int(0)],
            )
            .expect("processed?")
            .expect_success()
            .int_at(0);
        assert_eq!(result, 0, "id {query_id}");
    }
}
