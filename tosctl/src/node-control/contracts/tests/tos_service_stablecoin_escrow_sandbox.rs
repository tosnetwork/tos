/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! End-to-end TVM evidence for the TOS Service Protocol fixed-price stablecoin escrow.
//! The release/refund legs execute through the same wallet code used by the
//! local tUSDT deployment instead of substituting native TOS transfers.

use chain_block::{
    BuilderData, Cell, Coins, Deserializable, IBitstring, MsgAddressInt, Serializable, SliceData,
    StateInit, base64_decode, read_single_root_boc,
};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use tos_sandbox::{Blockchain, MessageBuilder, SendResult, Treasury};

const TOS: u64 = 1_000_000_000;
const AMOUNT: u64 = 25_000_000;
const MAGIC_DATA: u32 = 0x4e45_5331;
const MAGIC_TERMS: u32 = 0x4e45_5431;
const MAGIC_AUTH: u32 = 0x4e45_4131;
const MAGIC_RUNTIME: u32 = 0x4e45_5231;
const MAGIC_ROUTE: u32 = 0x4e45_5031;
const MAGIC_QUOTE: u32 = 0x4e41_5131;
const MAGIC_RECEIPT: u32 = 0x4e57_5231;
const MAGIC_INTENT: u32 = 0x4e53_4931;
const MAGIC_TRANSPORT: u32 = 0x4e54_4231;
const MAGIC_DISPUTE: u32 = 0x4e44_5031;
const OP_RELEASE: u32 = 0x4e45_0001;
const OP_REFUND: u32 = 0x4e45_0002;
const OP_TRANSFER_NOTIFICATION: u32 = 0x7362_d09c;
const OP_INTERNAL_TRANSFER: u32 = 0x178d_4519;
const OP_EXCESSES: u32 = 0xd532_76db;
const OP_TOP_UP: u32 = 0xd372_158c;
const OP_SET_STATUS: u32 = 0xeed2_36d3;
const STATUS_AWAITING: u8 = 0;
const STATUS_FUNDED: u8 = 1;
const STATUS_RELEASE_PENDING: u8 = 2;
const STATUS_REFUND_PENDING: u8 = 3;
const ERR_WRONG_WALLET: i32 = 2302;
const ERR_WRONG_BUYER: i32 = 2303;
const ERR_WRONG_AMOUNT: i32 = 2304;
const ERR_DEADLINE: i32 = 2305;
const ERR_BAD_RECEIPT: i32 = 2306;
const ERR_BAD_SIGNATURE: i32 = 2307;

fn frozen_code(file_name: &str) -> Cell {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../crypto/smartcont")
        .join(file_name);
    let encoded: String =
        std::fs::read_to_string(&path).expect("frozen code").split_whitespace().collect();
    read_single_root_boc(base64_decode(&encoded).expect("base64 code")).expect("code cell")
}

fn escrow_code() -> Cell {
    frozen_code("tos-service-stablecoin-escrow-v1.boc.base64")
}

fn wallet_code() -> Cell {
    frozen_code("test-usdt-wallet-code.boc.base64")
}

fn hash(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn account_id(addr: &MsgAddressInt) -> [u8; 32] {
    addr.address().get_bytestring(0).try_into().expect("32-byte account id")
}

fn empty_cell() -> Cell {
    BuilderData::new().into_cell().unwrap()
}

fn wallet_state_init(
    code: Cell,
    balance: u64,
    owner: &MsgAddressInt,
    master: &MsgAddressInt,
) -> StateInit {
    let mut data = BuilderData::new();
    data.append_bits(0, 4).unwrap();
    Coins::new(balance).write_to(&mut data).unwrap();
    owner.write_to(&mut data).unwrap();
    master.write_to(&mut data).unwrap();
    StateInit::with_code_and_data(code, data.into_cell().unwrap())
}

fn wallet_address(state_init: &StateInit) -> MsgAddressInt {
    let hash = state_init.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
    MsgAddressInt::with_params(0, hash).unwrap()
}

fn status(data: Cell) -> u8 {
    let mut s = SliceData::load_cell(data).unwrap();
    assert_eq!(s.get_next_u32().unwrap(), MAGIC_DATA);
    s.move_by(16).unwrap();
    s.get_next_byte().unwrap()
}

fn wallet_balance(data: Cell) -> u64 {
    let mut s = SliceData::load_cell(data).unwrap();
    s.move_by(4).unwrap();
    Coins::construct_from(&mut s).unwrap().as_u128() as u64
}

struct Fixture {
    bc: Blockchain,
    relayer: Treasury,
    buyer: Treasury,
    master: Treasury,
    escrow: MsgAddressInt,
    own_wallet: MsgAddressInt,
    buyer_wallet: MsgAddressInt,
    provider_wallet: MsgAddressInt,
    quote: Cell,
    signer: SigningKey,
    refund_at: u64,
}

impl Fixture {
    fn new() -> Self {
        let mut bc = Blockchain::with_global_version_and_base_workchain(14).expect("blockchain");
        bc.set_workchain(0);
        let relayer = bc.treasury("tos-service-escrow-relayer", 1_000 * TOS).unwrap();
        let buyer = bc.treasury("tos-service-escrow-buyer", 1_000 * TOS).unwrap();
        let provider = bc.treasury("tos-service-escrow-provider", 1_000 * TOS).unwrap();
        let master = bc.treasury("tos-service-test-usdt-master", 1_000 * TOS).unwrap();
        let signer = SigningKey::from_bytes(&[0x51; 32]);
        let wallet_code = wallet_code();
        let now = u64::from(bc.now());
        let funding_deadline = now + 1_000;
        let refund_at = now + 2_000;

        let mut terms = BuilderData::new();
        terms.append_u32(MAGIC_TERMS).unwrap().append_u16(1).unwrap();
        buyer.address().write_to(&mut terms).unwrap();
        provider.address().write_to(&mut terms).unwrap();
        terms.append_u64(funding_deadline).unwrap().append_u64(refund_at).unwrap();
        let terms = terms.into_cell().unwrap();

        let mut authorization = BuilderData::new();
        authorization
            .append_u32(MAGIC_AUTH)
            .unwrap()
            .append_u16(1)
            .unwrap()
            .append_u256(&signer.verifying_key().to_bytes())
            .unwrap();
        let authorization = authorization.into_cell().unwrap();

        let mut network = BuilderData::new();
        network
            .append_u256(&[0x11; 32])
            .unwrap()
            .append_u256(&[0x22; 32])
            .unwrap()
            .append_u256(&[0x33; 32])
            .unwrap();
        let mut version_name = BuilderData::new();
        version_name.append_raw(b"1.0.0", 40).unwrap();
        let endpoint = b"http://127.0.0.1:8080";
        let mut endpoint_cell = BuilderData::new();
        endpoint_cell.append_raw(endpoint, endpoint.len() * 8).unwrap();
        let mut transport = BuilderData::new();
        transport
            .append_u32(MAGIC_TRANSPORT)
            .unwrap()
            .append_u16(1)
            .unwrap()
            .append_u8(0)
            .unwrap()
            .append_u32(16 << 20)
            .unwrap()
            .checked_append_reference(endpoint_cell.into_cell().unwrap())
            .unwrap();
        let transport = transport.into_cell().unwrap();
        let mut dispute = BuilderData::new();
        dispute
            .append_u32(MAGIC_DISPUTE)
            .unwrap()
            .append_u16(1)
            .unwrap()
            .append_u8(0)
            .unwrap()
            .append_u8(1)
            .unwrap()
            .append_u8(1)
            .unwrap();
        let dispute = dispute.into_cell().unwrap();
        let mut version = BuilderData::new();
        version
            .append_u256(&hash(b"1.0.0"))
            .unwrap()
            .append_u256(&[0x44; 32])
            .unwrap()
            .append_raw(transport.hash(0).as_slice(), 256)
            .unwrap()
            .append_u64(funding_deadline)
            .unwrap()
            .checked_append_reference(version_name.into_cell().unwrap())
            .unwrap();
        let provider_agent = [0x66; 32];
        let mut identity = BuilderData::new();
        identity
            .append_u256(&[0x77; 32])
            .unwrap()
            .append_u256(&provider_agent)
            .unwrap()
            .checked_append_reference(version.into_cell().unwrap())
            .unwrap();
        let mut asset = BuilderData::new();
        asset
            .append_i32(0)
            .unwrap()
            .append_u256(&account_id(master.address()))
            .unwrap()
            .append_u256(&[0x88; 32])
            .unwrap()
            .append_raw(wallet_code.hash(0).as_slice(), 256)
            .unwrap()
            .append_u8(6)
            .unwrap();
        let mut amount_text = BuilderData::new();
        amount_text.append_raw(b"25000000", 64).unwrap();
        let mut economic = BuilderData::new();
        economic
            .append_raw(terms.hash(0).as_slice(), 256)
            .unwrap()
            .append_raw(dispute.hash(0).as_slice(), 256)
            .unwrap()
            .checked_append_reference(asset.into_cell().unwrap())
            .unwrap()
            .checked_append_reference(amount_text.into_cell().unwrap())
            .unwrap();
        let mut quote_authority = BuilderData::new();
        quote_authority.append_raw(authorization.hash(0).as_slice(), 256).unwrap();
        let mut quote = BuilderData::new();
        quote
            .append_u32(MAGIC_QUOTE)
            .unwrap()
            .append_u16(1)
            .unwrap()
            .checked_append_reference(network.into_cell().unwrap())
            .unwrap()
            .checked_append_reference(identity.into_cell().unwrap())
            .unwrap()
            .checked_append_reference(economic.into_cell().unwrap())
            .unwrap()
            .checked_append_reference(quote_authority.into_cell().unwrap())
            .unwrap();
        let quote = quote.into_cell().unwrap();

        let mut route = BuilderData::new();
        route.append_u32(MAGIC_ROUTE).unwrap().append_u16(1).unwrap();
        master.address().write_to(&mut route).unwrap();
        route
            .append_raw(wallet_code.hash(0).as_slice(), 256)
            .unwrap()
            .checked_append_reference(wallet_code.clone())
            .unwrap();
        let route = route.into_cell().unwrap();
        let mut runtime = BuilderData::new();
        runtime
            .append_u32(MAGIC_RUNTIME)
            .unwrap()
            .append_u16(1)
            .unwrap()
            .append_u128(0)
            .unwrap()
            .append_u128(0)
            .unwrap()
            .append_u256(&[0; 32])
            .unwrap()
            .append_u64(0)
            .unwrap()
            .checked_append_reference(route)
            .unwrap()
            .checked_append_reference(transport)
            .unwrap()
            .checked_append_reference(dispute)
            .unwrap();
        let mut data = BuilderData::new();
        data.append_u32(MAGIC_DATA)
            .unwrap()
            .append_u16(1)
            .unwrap()
            .append_u8(STATUS_AWAITING)
            .unwrap()
            .append_raw(quote.hash(0).as_slice(), 256)
            .unwrap()
            .append_raw(terms.hash(0).as_slice(), 256)
            .unwrap()
            .append_raw(authorization.hash(0).as_slice(), 256)
            .unwrap()
            .checked_append_reference(quote.clone())
            .unwrap()
            .checked_append_reference(terms)
            .unwrap()
            .checked_append_reference(authorization)
            .unwrap()
            .checked_append_reference(runtime.into_cell().unwrap())
            .unwrap();
        let escrow_init = StateInit::with_code_and_data(escrow_code(), data.into_cell().unwrap());
        let escrow_hash = escrow_init.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
        let escrow = MsgAddressInt::with_params(0, escrow_hash).unwrap();

        let own_wallet_init = wallet_state_init(wallet_code.clone(), 0, &escrow, master.address());
        let own_wallet = wallet_address(&own_wallet_init);
        let buyer_wallet = wallet_address(&wallet_state_init(
            wallet_code.clone(),
            0,
            buyer.address(),
            master.address(),
        ));
        let provider_wallet = wallet_address(&wallet_state_init(
            wallet_code,
            0,
            provider.address(),
            master.address(),
        ));

        let deploy_escrow = MessageBuilder::internal(relayer.address(), &escrow, 20 * TOS)
            .bounce(false)
            .state_init(escrow_init)
            .body(empty_cell())
            .build();
        bc.send_message(deploy_escrow).unwrap().expect_success();
        let mut derived = bc
            .run_get_method(&escrow, "get_escrow_wallet", vec![])
            .unwrap()
            .expect_success()
            .slice_at(0);
        assert_eq!(MsgAddressInt::construct_from(&mut derived).unwrap(), own_wallet);
        let mut top_up = BuilderData::new();
        top_up.append_u32(OP_TOP_UP).unwrap();
        let deploy_wallet = MessageBuilder::internal(master.address(), &own_wallet, 20 * TOS)
            .bounce(false)
            .state_init(own_wallet_init)
            .body(top_up.into_cell().unwrap())
            .build();
        bc.send_message(deploy_wallet).unwrap().expect_success();

        let mut mint = BuilderData::new();
        mint.append_u32(OP_INTERNAL_TRANSFER).unwrap().append_u64(1).unwrap();
        Coins::new(AMOUNT).write_to(&mut mint).unwrap();
        buyer.address().write_to(&mut mint).unwrap();
        mint.append_bits(0, 2).unwrap();
        Coins::new(0).write_to(&mut mint).unwrap();
        mint.append_bit_zero().unwrap();
        let mint_wallet = MessageBuilder::internal(master.address(), &own_wallet, TOS)
            .body(mint.into_cell().unwrap())
            .build();
        bc.send_message(mint_wallet).unwrap().expect_success();
        assert_eq!(
            wallet_balance(bc.get_account(&own_wallet).unwrap().get_data().unwrap()),
            AMOUNT
        );

        Self {
            bc,
            relayer,
            buyer,
            master,
            escrow,
            own_wallet,
            buyer_wallet,
            provider_wallet,
            quote,
            signer,
            refund_at,
        }
    }

    fn send_from(&mut self, source: &MsgAddressInt, body: Cell, value: u64) -> SendResult {
        let msg = MessageBuilder::internal(source, &self.escrow, value).body(body).build();
        self.bc.send_message(msg).unwrap()
    }

    fn fund_body(&self, amount: u64) -> Cell {
        let mut body = BuilderData::new();
        body.append_u32(OP_TRANSFER_NOTIFICATION).unwrap().append_u64(1).unwrap();
        Coins::new(amount).write_to(&mut body).unwrap();
        self.buyer.address().write_to(&mut body).unwrap();
        body.append_bit_zero().unwrap();
        body.into_cell().unwrap()
    }

    fn fund(&mut self) {
        let source = self.own_wallet.clone();
        let body = self.fund_body(AMOUNT);
        self.send_from(&source, body, TOS).expect_success();
        assert_eq!(self.status(), STATUS_FUNDED);
    }

    fn refund_body(query_id: u64) -> Cell {
        let mut body = BuilderData::new();
        body.append_u32(OP_REFUND).unwrap().append_u64(query_id).unwrap();
        body.into_cell().unwrap()
    }

    fn lock_own_wallet(&mut self) {
        let mut body = BuilderData::new();
        body.append_u32(OP_SET_STATUS).unwrap().append_u64(1).unwrap().append_bits(1, 4).unwrap();
        let message = MessageBuilder::internal(self.master.address(), &self.own_wallet, TOS)
            .body(body.into_cell().unwrap())
            .build();
        self.bc.send_message(message).unwrap().expect_success();
    }

    fn status(&self) -> u8 {
        status(self.bc.get_account(&self.escrow).unwrap().get_data().unwrap())
    }

    fn receipt(&self) -> Cell {
        let mut binding = BuilderData::new();
        binding
            .append_raw(self.quote.hash(0).as_slice(), 256)
            .unwrap()
            .append_u256(&[0xa1; 32])
            .unwrap()
            .append_u256(&[0xa2; 32])
            .unwrap();
        let mut outcome = BuilderData::new();
        outcome
            .append_u256(&[0xa3; 32])
            .unwrap()
            .append_u256(&[0xa4; 32])
            .unwrap()
            .append_u256(&[0xa5; 32])
            .unwrap();
        let mut evidence = BuilderData::new();
        evidence
            .append_u256(&[0xa6; 32])
            .unwrap()
            .append_u256(&[0xa7; 32])
            .unwrap()
            .append_u256(&[0xa8; 32])
            .unwrap();
        let mut economic = BuilderData::new();
        economic.append_u128(AMOUNT as u128).unwrap().append_u256(&[0x66; 32]).unwrap();
        let mut receipt = BuilderData::new();
        receipt
            .append_u32(MAGIC_RECEIPT)
            .unwrap()
            .append_u16(1)
            .unwrap()
            .append_u64(u64::from(self.bc.now()))
            .unwrap()
            .append_i32(0)
            .unwrap()
            .checked_append_reference(binding.into_cell().unwrap())
            .unwrap()
            .checked_append_reference(outcome.into_cell().unwrap())
            .unwrap()
            .checked_append_reference(evidence.into_cell().unwrap())
            .unwrap()
            .checked_append_reference(economic.into_cell().unwrap())
            .unwrap();
        receipt.into_cell().unwrap()
    }

    fn release_body(&self, query_id: u64, receipt: Cell, signer: &SigningKey) -> Cell {
        let mut intent = BuilderData::new();
        intent
            .append_u32(MAGIC_INTENT)
            .unwrap()
            .append_u16(1)
            .unwrap()
            .append_u64(query_id)
            .unwrap()
            .append_u128(AMOUNT as u128)
            .unwrap();
        self.escrow.write_to(&mut intent).unwrap();
        intent
            .append_raw(self.quote.hash(0).as_slice(), 256)
            .unwrap()
            .append_raw(receipt.hash(0).as_slice(), 256)
            .unwrap();
        let signature = signer.sign(intent.into_cell().unwrap().hash(0).as_slice()).to_bytes();
        let mut body = BuilderData::new();
        body.append_u32(OP_RELEASE)
            .unwrap()
            .append_u64(query_id)
            .unwrap()
            .append_raw(&signature, 512)
            .unwrap()
            .checked_append_reference(receipt)
            .unwrap();
        body.into_cell().unwrap()
    }
}

#[test]
fn full_price_funding_and_release_use_stablecoin_wallets() {
    let mut f = Fixture::new();
    f.fund();
    let receipt = f.receipt();
    let body = f.release_body(9, receipt, &f.signer);
    let source = f.relayer.address().clone();
    let result = f.send_from(&source, body, TOS);
    result.expect_success().expect_transaction_count(4);
    assert_eq!(f.status(), STATUS_RELEASE_PENDING);
    assert_eq!(wallet_balance(f.bc.get_account(&f.own_wallet).unwrap().get_data().unwrap()), 0);
    assert_eq!(
        wallet_balance(f.bc.get_account(&f.provider_wallet).unwrap().get_data().unwrap()),
        AMOUNT
    );
    let mut forged_confirmation = BuilderData::new();
    forged_confirmation.append_u32(OP_EXCESSES).unwrap().append_u64(9).unwrap();
    let source = f.provider_wallet.clone();
    f.send_from(&source, forged_confirmation.into_cell().unwrap(), TOS).expect_success();
    assert_eq!(f.status(), STATUS_RELEASE_PENDING);
}

#[test]
fn timeout_refunds_the_complete_stablecoin_balance() {
    let mut f = Fixture::new();
    f.fund();
    f.bc.set_now(f.refund_at as u32);
    let source = f.relayer.address().clone();
    let result = f.send_from(&source, Fixture::refund_body(11), TOS);
    result.expect_success().expect_transaction_count(4);
    assert_eq!(f.status(), STATUS_REFUND_PENDING);
    assert_eq!(
        wallet_balance(f.bc.get_account(&f.buyer_wallet).unwrap().get_data().unwrap()),
        AMOUNT
    );
}

#[test]
fn spoofed_wallet_wrong_amount_and_signature_fail_before_settlement() {
    let mut spoofed = Fixture::new();
    let source = spoofed.relayer.address().clone();
    let body = spoofed.fund_body(AMOUNT);
    spoofed.send_from(&source, body, TOS).expect_aborted().expect_exit_code(ERR_WRONG_WALLET);
    assert_eq!(spoofed.status(), STATUS_AWAITING);

    let mut wrong_amount = Fixture::new();
    let source = wrong_amount.own_wallet.clone();
    let body = wrong_amount.fund_body(AMOUNT - 1);
    wrong_amount.send_from(&source, body, TOS).expect_aborted().expect_exit_code(ERR_WRONG_AMOUNT);
    assert_eq!(wrong_amount.status(), STATUS_AWAITING);

    let mut forged = Fixture::new();
    forged.fund();
    let other = SigningKey::from_bytes(&[0x71; 32]);
    let body = forged.release_body(13, forged.receipt(), &other);
    let source = forged.relayer.address().clone();
    forged.send_from(&source, body, TOS).expect_aborted().expect_exit_code(ERR_BAD_SIGNATURE);
    assert_eq!(forged.status(), STATUS_FUNDED);
}

#[test]
fn lifecycle_replay_deadline_and_buyer_guards_fail_closed() {
    let mut wrong_buyer = Fixture::new();
    let mut body = BuilderData::new();
    body.append_u32(OP_TRANSFER_NOTIFICATION).unwrap().append_u64(1).unwrap();
    Coins::new(AMOUNT).write_to(&mut body).unwrap();
    wrong_buyer.relayer.address().write_to(&mut body).unwrap();
    body.append_bit_zero().unwrap();
    let source = wrong_buyer.own_wallet.clone();
    wrong_buyer
        .send_from(&source, body.into_cell().unwrap(), TOS)
        .expect_aborted()
        .expect_exit_code(ERR_WRONG_BUYER);

    let mut late_funding = Fixture::new();
    late_funding.bc.set_now((late_funding.refund_at - 500) as u32);
    let source = late_funding.own_wallet.clone();
    let body = late_funding.fund_body(AMOUNT);
    late_funding.send_from(&source, body, TOS).expect_aborted().expect_exit_code(ERR_DEADLINE);

    let mut replay = Fixture::new();
    replay.fund();
    let source = replay.own_wallet.clone();
    let body = replay.fund_body(AMOUNT);
    replay.send_from(&source, body, TOS).expect_aborted().expect_exit_code(2301);
    let source = replay.relayer.address().clone();
    replay
        .send_from(&source, Fixture::refund_body(17), TOS)
        .expect_aborted()
        .expect_exit_code(ERR_DEADLINE);

    replay.bc.set_now(replay.refund_at as u32);
    let receipt = replay.receipt();
    let body = replay.release_body(18, receipt, &replay.signer);
    replay.send_from(&source, body, TOS).expect_aborted().expect_exit_code(ERR_DEADLINE);
}

#[test]
fn malformed_receipt_and_wallet_bounce_cannot_finalize_payment() {
    let mut malformed = Fixture::new();
    malformed.fund();
    let mut invalid_receipt = BuilderData::new();
    invalid_receipt.append_u32(0).unwrap();
    let body = malformed.release_body(21, invalid_receipt.into_cell().unwrap(), &malformed.signer);
    let source = malformed.relayer.address().clone();
    malformed.send_from(&source, body, TOS).expect_aborted().expect_exit_code(ERR_BAD_RECEIPT);
    assert_eq!(malformed.status(), STATUS_FUNDED);

    let mut bounced = Fixture::new();
    bounced.fund();
    bounced.lock_own_wallet();
    let receipt = bounced.receipt();
    let body = bounced.release_body(22, receipt, &bounced.signer);
    let source = bounced.relayer.address().clone();
    let result = bounced.send_from(&source, body, TOS);
    result.expect_success().expect_transaction_count(3);
    assert_eq!(bounced.status(), STATUS_FUNDED);
    assert_eq!(
        wallet_balance(bounced.bc.get_account(&bounced.own_wallet).unwrap().get_data().unwrap()),
        AMOUNT
    );
}
