/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! TVM state-transition evidence for Paid Demand escrow V2.
//! Deployment, buyer acceptance, funding, execution and refund are deliberately
//! separate transitions.  These tests exercise the frozen production BOC.

use chain_block::{
    BuilderData, Cell, Coins, Deserializable, IBitstring, MsgAddressInt, Serializable, SliceData,
    StateInit, base64_decode, read_single_root_boc,
};
use ed25519_dalek::{Signer, SigningKey};
use tos_sandbox::{Blockchain, MessageBuilder, SendResult, Treasury};

const TOS: u64 = 1_000_000_000;
const AMOUNT: u64 = 25_000_000;
const MAGIC_DATA: u32 = 0x4e45_5331;
const MAGIC_TERMS: u32 = 0x4e45_5431;
const MAGIC_AUTH: u32 = 0x4e45_4131;
const MAGIC_RUNTIME: u32 = 0x4e45_5231;
const MAGIC_ROUTE: u32 = 0x4e45_5031;
const MAGIC_QUOTE: u32 = 0x4e41_5131;
const MAGIC_PAID_DEMAND: u32 = 0x4e50_4431;
const MAGIC_TRANSPORT: u32 = 0x4e54_4231;
const MAGIC_DISPUTE: u32 = 0x4e44_5031;
const MAGIC_RECEIPT: u32 = 0x4e57_5231;
const MAGIC_INTENT: u32 = 0x4e53_4931;
const OP_RELEASE: u32 = 0x4e45_0001;
const OP_REFUND: u32 = 0x4e45_0002;
const OP_ACCEPT: u32 = 0x4e45_0003;
const OP_TRANSFER_NOTIFICATION: u32 = 0x7362_d09c;
const OP_INTERNAL_TRANSFER: u32 = 0x178d_4519;
const OP_TOP_UP: u32 = 0xd372_158c;
const OP_SET_STATUS: u32 = 0xeed2_36d3;
const STATUS_PENDING: u8 = 0;
const STATUS_AWAITING_FUNDING: u8 = 1;
const STATUS_FUNDED: u8 = 2;
const STATUS_RELEASE_PENDING: u8 = 3;
const STATUS_REFUND_PENDING: u8 = 4;
const ERR_BAD_STATE: i32 = 2401;
const ERR_DEADLINE: i32 = 2405;
const ERR_BAD_RECEIPT: i32 = 2406;
const ERR_BAD_ACCEPTANCE: i32 = 2409;

fn frozen_code(file_name: &str) -> Cell {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../crypto/smartcont")
        .join(file_name);
    let encoded: String =
        std::fs::read_to_string(&path).expect("frozen code").split_whitespace().collect();
    read_single_root_boc(base64_decode(&encoded).expect("base64 code")).expect("code cell")
}

fn hash(value: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
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

fn state(data: Cell) -> (u8, u64) {
    let mut root = SliceData::load_cell(data).unwrap();
    assert_eq!(root.get_next_u32().unwrap(), MAGIC_DATA);
    assert_eq!(root.get_next_u16().unwrap(), 2);
    let status = root.get_next_byte().unwrap();
    root.move_by(256 * 3).unwrap();
    for _ in 0..3 {
        root.checked_drain_reference().unwrap();
    }
    let runtime = root.checked_drain_reference().unwrap();
    let mut runtime = SliceData::load_cell(runtime).unwrap();
    assert_eq!(runtime.get_next_u32().unwrap(), MAGIC_RUNTIME);
    assert_eq!(runtime.get_next_u16().unwrap(), 2);
    runtime.move_by(128 * 2 + 256 + 64).unwrap();
    (status, runtime.get_next_u64().unwrap())
}

fn wallet_balance(data: Cell) -> u64 {
    let mut root = SliceData::load_cell(data).unwrap();
    root.move_by(4).unwrap();
    Coins::construct_from(&mut root).unwrap().as_u128() as u64
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
    quote_hash: [u8; 32],
    offer_digest: [u8; 32],
    signer: SigningKey,
    accept_by: u64,
    funding_deadline: u64,
    execution_deadline: u64,
    refund_at: u64,
}

impl Fixture {
    fn new() -> Self {
        let mut bc = Blockchain::with_global_version_and_base_workchain(14).unwrap();
        bc.set_workchain(0);
        let relayer = bc.treasury("tos-service-v2-relayer", 1_000 * TOS).unwrap();
        let buyer = bc.treasury("tos-service-v2-buyer", 1_000 * TOS).unwrap();
        let provider = bc.treasury("tos-service-v2-provider", 1_000 * TOS).unwrap();
        let master = bc.treasury("tos-service-v2-master", 1_000 * TOS).unwrap();
        let signer = SigningKey::from_bytes(&[0x51; 32]);
        let wallet_code = frozen_code("test-usdt-wallet-code.boc.base64");
        let now = u64::from(bc.now());
        let accept_by = now + 100;
        let funding_deadline = now + 300;
        let execution_deadline = now + 500;
        let refund_at = now + 700;

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
            .append_u64(accept_by)
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
        let offer_digest = [0xab; 32];
        let mut offer = BuilderData::new();
        offer.append_raw(b"signed-provider-offer", 21 * 8).unwrap();
        let offer = offer.into_cell().unwrap();
        let mut extension = BuilderData::new();
        extension
            .append_u32(MAGIC_PAID_DEMAND)
            .unwrap()
            .append_u16(1)
            .unwrap()
            .append_u256(&[0xaa; 32])
            .unwrap()
            .append_u256(&offer_digest)
            .unwrap()
            .append_u64(accept_by)
            .unwrap()
            .append_u64(execution_deadline)
            .unwrap()
            .append_u32(21)
            .unwrap()
            .checked_append_reference(offer)
            .unwrap();
        let mut quote_authority = BuilderData::new();
        quote_authority
            .append_raw(authorization.hash(0).as_slice(), 256)
            .unwrap()
            .checked_append_reference(extension.into_cell().unwrap())
            .unwrap();
        let mut quote = BuilderData::new();
        quote
            .append_u32(MAGIC_QUOTE)
            .unwrap()
            .append_u16(2)
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
        let quote_hash = *quote.hash(0).as_slice();

        let mut route = BuilderData::new();
        route.append_u32(MAGIC_ROUTE).unwrap().append_u16(2).unwrap();
        master.address().write_to(&mut route).unwrap();
        route
            .append_raw(wallet_code.hash(0).as_slice(), 256)
            .unwrap()
            .checked_append_reference(wallet_code.clone())
            .unwrap();
        let mut runtime = BuilderData::new();
        runtime
            .append_u32(MAGIC_RUNTIME)
            .unwrap()
            .append_u16(2)
            .unwrap()
            .append_u128(0)
            .unwrap()
            .append_u128(0)
            .unwrap()
            .append_u256(&[0; 32])
            .unwrap()
            .append_u64(0)
            .unwrap()
            .append_u64(0)
            .unwrap()
            .checked_append_reference(route.into_cell().unwrap())
            .unwrap()
            .checked_append_reference(transport)
            .unwrap()
            .checked_append_reference(dispute)
            .unwrap();
        let mut data = BuilderData::new();
        data.append_u32(MAGIC_DATA)
            .unwrap()
            .append_u16(2)
            .unwrap()
            .append_u8(STATUS_PENDING)
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
        let escrow_init = StateInit::with_code_and_data(
            frozen_code("tos-service-stablecoin-escrow-v2.boc.base64"),
            data.into_cell().unwrap(),
        );
        let escrow_hash = escrow_init.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
        let escrow = MsgAddressInt::with_params(0, escrow_hash).unwrap();
        let own_wallet_init = wallet_state_init(wallet_code, 0, &escrow, master.address());
        let own_wallet = wallet_address(&own_wallet_init);
        let buyer_wallet = wallet_address(&wallet_state_init(
            frozen_code("test-usdt-wallet-code.boc.base64"),
            0,
            buyer.address(),
            master.address(),
        ));
        let provider_wallet = wallet_address(&wallet_state_init(
            frozen_code("test-usdt-wallet-code.boc.base64"),
            0,
            provider.address(),
            master.address(),
        ));

        bc.send_message(
            MessageBuilder::internal(relayer.address(), &escrow, 20 * TOS)
                .bounce(false)
                .state_init(escrow_init)
                .body(empty_cell())
                .build(),
        )
        .unwrap()
        .expect_success();
        let mut top_up = BuilderData::new();
        top_up.append_u32(OP_TOP_UP).unwrap();
        bc.send_message(
            MessageBuilder::internal(master.address(), &own_wallet, 20 * TOS)
                .bounce(false)
                .state_init(own_wallet_init)
                .body(top_up.into_cell().unwrap())
                .build(),
        )
        .unwrap()
        .expect_success();
        let mut mint = BuilderData::new();
        mint.append_u32(OP_INTERNAL_TRANSFER).unwrap().append_u64(1).unwrap();
        Coins::new(AMOUNT).write_to(&mut mint).unwrap();
        buyer.address().write_to(&mut mint).unwrap();
        mint.append_bits(0, 2).unwrap();
        Coins::new(0).write_to(&mut mint).unwrap();
        mint.append_bit_zero().unwrap();
        bc.send_message(
            MessageBuilder::internal(master.address(), &own_wallet, TOS)
                .body(mint.into_cell().unwrap())
                .build(),
        )
        .unwrap()
        .expect_success();

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
            quote_hash,
            offer_digest,
            signer,
            accept_by,
            funding_deadline,
            execution_deadline,
            refund_at,
        }
    }

    fn send(&mut self, sender: &MsgAddressInt, body: Cell) -> SendResult {
        self.bc
            .send_message(MessageBuilder::internal(sender, &self.escrow, TOS).body(body).build())
            .unwrap()
    }

    fn accept_body(&self, query: u64) -> Cell {
        let mut body = BuilderData::new();
        body.append_u32(OP_ACCEPT)
            .unwrap()
            .append_u64(query)
            .unwrap()
            .append_u256(&self.quote_hash)
            .unwrap()
            .append_u256(&self.offer_digest)
            .unwrap();
        body.into_cell().unwrap()
    }

    fn fund_body(&self) -> Cell {
        let mut body = BuilderData::new();
        body.append_u32(OP_TRANSFER_NOTIFICATION).unwrap().append_u64(2).unwrap();
        Coins::new(AMOUNT).write_to(&mut body).unwrap();
        self.buyer.address().write_to(&mut body).unwrap();
        body.append_bit_zero().unwrap();
        body.into_cell().unwrap()
    }

    fn fund(&mut self) {
        let buyer = self.buyer.address().clone();
        let acceptance = self.accept_body(2);
        self.send(&buyer, acceptance).expect_success();
        let wallet = self.own_wallet.clone();
        let funding = self.fund_body();
        self.send(&wallet, funding).expect_success();
        assert_eq!(self.state().0, STATUS_FUNDED);
    }

    fn refund_body(query_id: u64) -> Cell {
        let mut body = BuilderData::new();
        body.append_u32(OP_REFUND).unwrap().append_u64(query_id).unwrap();
        body.into_cell().unwrap()
    }

    fn receipt(&self, outcome: u8) -> Cell {
        let mut binding = BuilderData::new();
        binding
            .append_raw(self.quote.hash(0).as_slice(), 256)
            .unwrap()
            .append_u256(&[0xa1; 32])
            .unwrap()
            .append_u256(&[0xa2; 32])
            .unwrap();
        let mut outcome_cell = BuilderData::new();
        outcome_cell
            .append_u256(&[outcome; 32])
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
            .checked_append_reference(outcome_cell.into_cell().unwrap())
            .unwrap()
            .checked_append_reference(evidence.into_cell().unwrap())
            .unwrap()
            .checked_append_reference(economic.into_cell().unwrap())
            .unwrap();
        receipt.into_cell().unwrap()
    }

    fn release_body(&self, query_id: u64, receipt: Cell) -> Cell {
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
        let signature = self.signer.sign(intent.into_cell().unwrap().hash(0).as_slice()).to_bytes();
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

    fn lock_own_wallet(&mut self) {
        let mut body = BuilderData::new();
        body.append_u32(OP_SET_STATUS).unwrap().append_u64(1).unwrap().append_bits(1, 4).unwrap();
        self.bc
            .send_message(
                MessageBuilder::internal(self.master.address(), &self.own_wallet, TOS)
                    .body(body.into_cell().unwrap())
                    .build(),
            )
            .unwrap()
            .expect_success();
    }

    fn state(&self) -> (u8, u64) {
        state(self.bc.get_account(&self.escrow).unwrap().get_data().unwrap())
    }
}

#[test]
fn deployment_is_not_acceptance_and_only_the_buyer_can_advance_it() {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.state(), (STATUS_PENDING, 0));

    let wallet = fixture.own_wallet.clone();
    let funding = fixture.fund_body();
    // Funding before acceptance is not accepted, but the jettons the wallet
    // already credited must be returned to the funder, never thrown away
    // (throwing would orphan them permanently — BUG-001). The escrow stays in
    // pending_acceptance and emits exactly one return transfer.
    fixture.send(&wallet, funding).expect_success().expect_out_msgs(1);
    assert_eq!(fixture.state(), (STATUS_PENDING, 0));

    let attacker = fixture.relayer.address().clone();
    let acceptance = fixture.accept_body(7);
    fixture.send(&attacker, acceptance).expect_aborted().expect_exit_code(ERR_BAD_ACCEPTANCE);
    assert_eq!(fixture.state(), (STATUS_PENDING, 0));

    let buyer = fixture.buyer.address().clone();
    let acceptance = fixture.accept_body(7);
    fixture.send(&buyer, acceptance.clone()).expect_success();
    let accepted_at = fixture.state().1;
    assert_eq!(fixture.state().0, STATUS_AWAITING_FUNDING);
    assert!(accepted_at > 0 && accepted_at < fixture.accept_by);

    fixture.send(&buyer, acceptance).expect_success();
    assert_eq!(fixture.state(), (STATUS_AWAITING_FUNDING, accepted_at));
}

fn notification_body(query_id: u64, amount: u64, from: &MsgAddressInt) -> Cell {
    let mut body = BuilderData::new();
    body.append_u32(OP_TRANSFER_NOTIFICATION).unwrap().append_u64(query_id).unwrap();
    Coins::new(amount).write_to(&mut body).unwrap();
    from.write_to(&mut body).unwrap();
    body.append_bit_zero().unwrap();
    body.into_cell().unwrap()
}

#[test]
fn rejected_funding_is_returned_to_sender_not_orphaned() {
    // BUG-001 (STON.fi router.func:91-99 refund-with-reason pattern): jettons are
    // credited to the escrow's own wallet before the escrow runs, and the
    // notification is non-bounceable, so a throw on a mismatch cannot un-credit
    // them and would orphan them permanently. Every funding the escrow does not
    // accept must instead be returned to the funder (exactly one outbound
    // transfer), leaving the escrow able to still accept a correct funding.
    let mut fixture = Fixture::new();
    let buyer = fixture.buyer.address().clone();
    fixture.send(&buyer, fixture.accept_body(3)).expect_success();
    assert_eq!(fixture.state().0, STATUS_AWAITING_FUNDING);
    let accepted_at = fixture.state().1;
    let wallet = fixture.own_wallet.clone();

    // Wrong amount from the buyer's own wallet: returned, state unchanged.
    let wrong_amount = notification_body(2, AMOUNT + 1, fixture.buyer.address());
    fixture.send(&wallet, wrong_amount).expect_success().expect_out_msgs(1);
    assert_eq!(fixture.state(), (STATUS_AWAITING_FUNDING, accepted_at));

    // Correct amount but the funder is not the buyer (e.g. an exchange
    // withdrawal whose `from` is the exchange wallet): returned, state unchanged.
    let wrong_from = notification_body(2, AMOUNT, fixture.relayer.address());
    fixture.send(&wallet, wrong_from).expect_success().expect_out_msgs(1);
    assert_eq!(fixture.state(), (STATUS_AWAITING_FUNDING, accepted_at));

    // A correct funding is still accepted and moves no funds out.
    let funding = fixture.fund_body();
    fixture.send(&wallet, funding).expect_success().expect_out_msgs(0);
    assert_eq!(fixture.state(), (STATUS_FUNDED, accepted_at));
}

#[test]
fn funding_after_the_deadline_is_returned_not_orphaned() {
    // BUG-001 latency variant: a funding initiated in time can arrive after
    // funding_deadline. It must be returned to the buyer, not orphaned, and must
    // not consume the awaiting_funding state.
    let mut fixture = Fixture::new();
    let buyer = fixture.buyer.address().clone();
    fixture.send(&buyer, fixture.accept_body(3)).expect_success();
    let accepted_at = fixture.state().1;
    fixture.bc.set_now((fixture.funding_deadline + 1) as u32);
    let wallet = fixture.own_wallet.clone();
    let late = fixture.fund_body();
    fixture.send(&wallet, late).expect_success().expect_out_msgs(1);
    assert_eq!(fixture.state(), (STATUS_AWAITING_FUNDING, accepted_at));
}


#[test]
fn acceptance_replay_is_idempotent_after_late_but_valid_funding() {
    let mut fixture = Fixture::new();
    let buyer = fixture.buyer.address().clone();
    let acceptance = fixture.accept_body(9);
    fixture.send(&buyer, acceptance.clone()).expect_success();
    let accepted_at = fixture.state().1;

    fixture.bc.set_now((fixture.accept_by + 1) as u32);
    assert!(u64::from(fixture.bc.now()) <= fixture.funding_deadline);
    let wallet = fixture.own_wallet.clone();
    let funding = fixture.fund_body();
    fixture.send(&wallet, funding).expect_success();
    assert_eq!(fixture.state(), (STATUS_FUNDED, accepted_at));

    fixture.send(&buyer, acceptance).expect_success();
    assert_eq!(fixture.state(), (STATUS_FUNDED, accepted_at));
}

#[test]
fn late_acceptance_is_rejected_without_consuming_the_transition() {
    let mut fixture = Fixture::new();
    fixture.bc.set_now(fixture.accept_by as u32);
    let buyer = fixture.buyer.address().clone();
    let acceptance = fixture.accept_body(11);
    fixture.send(&buyer, acceptance).expect_aborted().expect_exit_code(ERR_DEADLINE);
    assert_eq!(fixture.state(), (STATUS_PENDING, 0));
}

#[test]
fn release_and_exact_replay_are_idempotent_but_mutations_are_rejected() {
    let mut fixture = Fixture::new();
    fixture.fund();
    let body = fixture.release_body(19, fixture.receipt(0xa3));
    let relayer = fixture.relayer.address().clone();
    fixture.send(&relayer, body.clone()).expect_success().expect_transaction_count(4);
    assert_eq!(fixture.state().0, STATUS_RELEASE_PENDING);
    assert_eq!(
        wallet_balance(
            fixture.bc.get_account(&fixture.provider_wallet).unwrap().get_data().unwrap()
        ),
        AMOUNT
    );

    fixture.send(&relayer, body).expect_success().expect_transaction_count(1);
    assert_eq!(fixture.state().0, STATUS_RELEASE_PENDING);
    assert_eq!(
        wallet_balance(
            fixture.bc.get_account(&fixture.provider_wallet).unwrap().get_data().unwrap()
        ),
        AMOUNT
    );

    let changed_receipt = fixture.release_body(19, fixture.receipt(0xb3));
    fixture.send(&relayer, changed_receipt).expect_aborted().expect_exit_code(ERR_BAD_STATE);
    let changed_query = fixture.release_body(20, fixture.receipt(0xa3));
    fixture.send(&relayer, changed_query).expect_aborted().expect_exit_code(ERR_BAD_STATE);
}

#[test]
fn refund_replay_is_idempotent_and_wallet_bounce_restores_funded_state() {
    let mut refund = Fixture::new();
    refund.fund();
    refund.bc.set_now(refund.refund_at as u32);
    let relayer = refund.relayer.address().clone();
    let body = Fixture::refund_body(31);
    refund.send(&relayer, body.clone()).expect_success().expect_transaction_count(4);
    assert_eq!(refund.state().0, STATUS_REFUND_PENDING);
    assert_eq!(
        wallet_balance(refund.bc.get_account(&refund.buyer_wallet).unwrap().get_data().unwrap()),
        AMOUNT
    );
    refund.send(&relayer, body).expect_success().expect_transaction_count(1);
    assert_eq!(refund.state().0, STATUS_REFUND_PENDING);

    let mut bounced = Fixture::new();
    bounced.fund();
    bounced.lock_own_wallet();
    let body = bounced.release_body(41, bounced.receipt(0xa3));
    let relayer = bounced.relayer.address().clone();
    bounced.send(&relayer, body).expect_success().expect_transaction_count(3);
    assert_eq!(bounced.state().0, STATUS_FUNDED);
    assert_eq!(
        wallet_balance(bounced.bc.get_account(&bounced.own_wallet).unwrap().get_data().unwrap()),
        AMOUNT
    );
}

#[test]
fn release_rejects_receipts_completed_after_the_execution_deadline() {
    let mut fixture = Fixture::new();
    fixture.fund();
    fixture.bc.set_now((fixture.execution_deadline + 1) as u32);
    let body = fixture.release_body(51, fixture.receipt(0xa3));
    let relayer = fixture.relayer.address().clone();
    fixture.send(&relayer, body).expect_aborted().expect_exit_code(ERR_BAD_RECEIPT);
    assert_eq!(fixture.state().0, STATUS_FUNDED);
}
