/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! TVM state-transition evidence for Paid Demand escrow V2.
//! Deployment, buyer acceptance, funding, execution and refund are deliberately
//! separate transitions.  These tests exercise the frozen production BOC.

use chain_block::{
    BuilderData, Cell, Coins, CurrencyCollection, Deserializable, IBitstring, MsgAddressInt,
    Serializable, SliceData, StateInit, base64_decode, read_single_root_boc,
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
const ERR_BAD_CONFIRMATION: i32 = 2408;
const ERR_BAD_ACCEPTANCE: i32 = 2409;
const ERR_INSUFFICIENT_GAS: i32 = 2410;
const OP_EXCESSES: u32 = 0xd53276db;
const OP_JETTON_TRANSFER: u32 = 0x0f8a7ea5;

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

/// Full runtime attribution:
/// (status, funded, settled, receipt_hash, pending_query, accepted_at).
fn runtime_full(data: Cell) -> (u8, u128, u128, [u8; 32], u64, u64) {
    let mut root = SliceData::load_cell(data).unwrap();
    assert_eq!(root.get_next_u32().unwrap(), MAGIC_DATA);
    assert_eq!(root.get_next_u16().unwrap(), 2);
    let status = root.get_next_byte().unwrap();
    root.move_by(256 * 3).unwrap();
    for _ in 0..3 {
        root.checked_drain_reference().unwrap();
    }
    let runtime = root.checked_drain_reference().unwrap();
    let mut r = SliceData::load_cell(runtime).unwrap();
    assert_eq!(r.get_next_u32().unwrap(), MAGIC_RUNTIME);
    assert_eq!(r.get_next_u16().unwrap(), 2);
    let funded = r.get_next_u128().unwrap();
    let settled = r.get_next_u128().unwrap();
    let receipt_hash = r.get_next_u256().unwrap();
    let pending_query = r.get_next_u64().unwrap();
    let accepted_at = r.get_next_u64().unwrap();
    (status, funded, settled, receipt_hash, pending_query, accepted_at)
}

struct Fixture {
    bc: Blockchain,
    relayer: Treasury,
    buyer: Treasury,
    provider: Treasury,
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
    amount: u128,
}

impl Fixture {
    fn new() -> Self {
        // Default fixture: short endpoint + small amount. Max-valid-state variant
        // (120-byte endpoint, 37-digit amount) is new_with(), used by the
        // worst-case settlement-gas boundary tests.
        Self::new_with(b"http://127.0.0.1:8080", AMOUNT as u128)
    }

    fn new_with(endpoint: &[u8], amount: u128) -> Self {
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
        let amount_decimal = amount.to_string();
        let amount_bytes = amount_decimal.as_bytes();
        let mut amount_text = BuilderData::new();
        amount_text.append_raw(amount_bytes, amount_bytes.len() * 8).unwrap();
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
        amount_decimal.parse::<Coins>().unwrap().write_to(&mut mint).unwrap();
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
            provider,
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
            amount,
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
        self.amount.to_string().parse::<Coins>().unwrap().write_to(&mut body).unwrap();
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
        economic.append_u128(self.amount).unwrap().append_u256(&[0x66; 32]).unwrap();
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
            .append_u128(self.amount)
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
        let own = self.own_wallet.clone();
        self.set_wallet_status(&own, 1);
    }

    // Admin (master) sets a vendored-wallet status: bit0=outgoing-locked,
    // bit1=incoming-locked. Locking the escrow's own wallet outgoing (1) forces a
    // first-leg bounce back to the escrow; locking a recipient wallet incoming (2)
    // makes the second leg re-credit the escrow's own wallet with no signal.
    fn set_wallet_status(&mut self, wallet: &MsgAddressInt, status: u64) {
        let mut body = BuilderData::new();
        body.append_u32(OP_SET_STATUS)
            .unwrap()
            .append_u64(1)
            .unwrap()
            .append_bits(status as usize, 4)
            .unwrap();
        self.bc
            .send_message(
                MessageBuilder::internal(self.master.address(), wallet, TOS)
                    .body(body.into_cell().unwrap())
                    .build(),
            )
            .unwrap()
            .expect_success();
    }

    // Deploy a recipient wallet (0 balance) and set it incoming-locked, so a
    // settlement's second leg to it fails and the standard wallet bounces the
    // tokens back to the escrow's own wallet (BUG-002 receive-locked variant).
    fn deploy_incoming_locked(&mut self, owner: MsgAddressInt, wallet: MsgAddressInt) {
        let init = wallet_state_init(
            frozen_code("test-usdt-wallet-code.boc.base64"),
            0,
            &owner,
            self.master.address(),
        );
        let mut top_up = BuilderData::new();
        top_up.append_u32(OP_TOP_UP).unwrap();
        self.bc
            .send_message(
                MessageBuilder::internal(self.master.address(), &wallet, TOS)
                    .bounce(false)
                    .state_init(init)
                    .body(top_up.into_cell().unwrap())
                    .build(),
            )
            .unwrap()
            .expect_success();
        self.set_wallet_status(&wallet, 2);
    }

    fn escrow_balance(&self) -> u64 {
        self.bc
            .get_account(&self.escrow)
            .unwrap()
            .balance()
            .and_then(|cc| cc.coins.as_u64())
            .unwrap()
    }

    // Jetton balances tolerate a not-yet-deployed wallet account (== 0 tokens).
    fn own_wallet_balance(&self) -> u64 {
        self.bc
            .get_account(&self.own_wallet)
            .and_then(|a| a.get_data())
            .map(wallet_balance)
            .unwrap_or(0)
    }

    fn provider_wallet_balance(&self) -> u64 {
        self.bc
            .get_account(&self.provider_wallet)
            .and_then(|a| a.get_data())
            .map(wallet_balance)
            .unwrap_or(0)
    }

    fn buyer_wallet_balance(&self) -> u64 {
        self.bc
            .get_account(&self.buyer_wallet)
            .and_then(|a| a.get_data())
            .map(wallet_balance)
            .unwrap_or(0)
    }

    fn state(&self) -> (u8, u64) {
        state(self.bc.get_account(&self.escrow).unwrap().get_data().unwrap())
    }

    fn runtime(&self) -> (u8, u128, u128, [u8; 32], u64, u64) {
        runtime_full(self.bc.get_account(&self.escrow).unwrap().get_data().unwrap())
    }

    // The escrow's full data-cell hash, for "nothing changed" assertions.
    fn data_hash(&self) -> Vec<u8> {
        self.bc.get_account(&self.escrow).unwrap().get_data_hash().unwrap().as_slice().to_vec()
    }

    fn send_with_value(&mut self, sender: &MsgAddressInt, body: Cell, value: u64) -> SendResult {
        self.bc
            .send_message(MessageBuilder::internal(sender, &self.escrow, value).body(body).build())
            .unwrap()
    }

    // A message with the `bounced` header flag set, from an arbitrary sender --
    // simulating a forged/automatic network bounce (not a genuine call).
    fn send_bounced(&mut self, sender: &MsgAddressInt, body: Cell) -> SendResult {
        let mut msg = MessageBuilder::internal(sender, &self.escrow, TOS).body(body).build();
        msg.int_header_mut().expect("internal header").bounced = true;
        self.bc.send_message(msg).unwrap()
    }

    // Force the escrow's native balance (to exercise the settlement gas pre-check).
    fn set_escrow_balance(&mut self, grams: u64) {
        let mut acc = self.bc.get_account(&self.escrow).unwrap().clone();
        acc.set_balance(CurrencyCollection::with_coins(grams));
        self.bc.set_account(self.escrow.clone(), acc);
    }

    // Credit the escrow's own jetton wallet with `amount` (a mint-style
    // internal_transfer, no notification) so a rejected funding of that exact
    // amount can be proven to return end-to-end.
    fn credit_own_wallet(&mut self, amount: u64, from: &MsgAddressInt) {
        let mut mint = BuilderData::new();
        mint.append_u32(OP_INTERNAL_TRANSFER).unwrap().append_u64(1).unwrap();
        Coins::new(amount).write_to(&mut mint).unwrap();
        from.write_to(&mut mint).unwrap();
        mint.append_bits(0, 2).unwrap();
        Coins::new(0).write_to(&mut mint).unwrap();
        mint.append_bit_zero().unwrap();
        let own = self.own_wallet.clone();
        self.bc
            .send_message(
                MessageBuilder::internal(self.master.address(), &own, TOS)
                    .body(mint.into_cell().unwrap())
                    .build(),
            )
            .unwrap()
            .expect_success();
    }

    fn relayer_wallet(&self) -> MsgAddressInt {
        wallet_address(&wallet_state_init(
            frozen_code("test-usdt-wallet-code.boc.base64"),
            0,
            self.relayer.address(),
            self.master.address(),
        ))
    }

    fn wallet_tokens(&self, wallet: &MsgAddressInt) -> u64 {
        self.bc.get_account(wallet).and_then(|a| a.get_data()).map(wallet_balance).unwrap_or(0)
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
    // pending_acceptance and the full amount is delivered back to the buyer.
    fixture.send(&wallet, funding).expect_success().expect_out_msgs(1);
    assert_eq!(fixture.buyer_wallet_balance(), AMOUNT);
    assert_eq!(fixture.own_wallet_balance(), 0);
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
    // BUG-001 (refund-with-reason pattern from the vendored reference router
    // contract): jettons are
    // credited to the escrow's own wallet before the escrow runs, and the
    // notification is non-bounceable, so a throw on a mismatch cannot un-credit
    // them and would orphan them permanently. Every funding the escrow does not
    // accept must instead be returned to the funder (exactly one outbound
    // transfer), leaving the escrow able to still accept a correct funding.
    let mut f = Fixture::new();
    let buyer = f.buyer.address().clone();
    f.send(&buyer, f.accept_body(3)).expect_success();
    assert_eq!(f.state().0, STATUS_AWAITING_FUNDING);
    let accepted_at = f.state().1;
    let wallet = f.own_wallet.clone();

    // Wrong amount: credit the own wallet a distinct extra W (so the return of W
    // is real from the prestate), notify that W, and prove the buyer's wallet
    // receives exactly W back and the own wallet returns to AMOUNT; state held.
    const W: u64 = 7_000_000;
    f.credit_own_wallet(W, &buyer);
    assert_eq!(f.own_wallet_balance(), AMOUNT + W);
    let wrong_amount = notification_body(2, W, &buyer);
    f.send(&wallet, wrong_amount).expect_success().expect_out_msgs(1);
    assert_eq!(f.buyer_wallet_balance(), W);
    assert_eq!(f.own_wallet_balance(), AMOUNT);
    assert_eq!(f.state(), (STATUS_AWAITING_FUNDING, accepted_at));

    // Correct amount but the funder is not the buyer (e.g. an exchange withdrawal
    // whose `from` is the exchange wallet): the full amount is returned to that
    // funder's real wallet and the own wallet is debited; state held.
    let relayer = f.relayer.address().clone();
    let wrong_from = notification_body(2, AMOUNT, &relayer);
    f.send(&wallet, wrong_from).expect_success().expect_out_msgs(1);
    let relayer_wallet = f.relayer_wallet();
    assert_eq!(f.wallet_tokens(&relayer_wallet), AMOUNT);
    assert_eq!(f.own_wallet_balance(), 0);
    assert_eq!(f.state(), (STATUS_AWAITING_FUNDING, accepted_at));

    // A correct funding is still accepted and moves no funds out.
    f.credit_own_wallet(AMOUNT, &buyer);
    let funding = f.fund_body();
    f.send(&wallet, funding).expect_success().expect_out_msgs(0);
    assert_eq!(f.state(), (STATUS_FUNDED, accepted_at));
}

#[test]
fn funding_after_the_deadline_is_returned_not_orphaned() {
    // BUG-001 latency variant: a funding initiated in time can arrive after
    // funding_deadline. It must be returned to the buyer, not orphaned, and must
    // not consume the awaiting_funding state.
    let mut f = Fixture::new();
    let buyer = f.buyer.address().clone();
    f.send(&buyer, f.accept_body(3)).expect_success();
    let accepted_at = f.state().1;
    f.bc.set_now((f.funding_deadline + 1) as u32);
    let wallet = f.own_wallet.clone();
    let late = f.fund_body();
    f.send(&wallet, late).expect_success().expect_out_msgs(1);
    // The full amount is delivered back to the buyer's real wallet.
    assert_eq!(f.buyer_wallet_balance(), AMOUNT);
    assert_eq!(f.own_wallet_balance(), 0);
    assert_eq!(f.state(), (STATUS_AWAITING_FUNDING, accepted_at));
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

// ---------------------------------------------------------------------------
// Mandatory V1 async-transfer / recovery matrix
// (spec: tos-service-spec/docs/STABLECOIN_ESCROW_TVM_V1.md — "Contract and
// resolver vectors must cover an authenticated bounce followed by old-query
// permissionless replay, old/new attempt races for both release and refund,
// repeated bounce/replay fee consumption, and exact attribution of the one
// accepted pending transition. No vector may assume the new query wins.").
//
// Forged bounced messages are built with the message's bounced header flag set;
// low-native settlement refusal is exercised by replacing the escrow account's
// balance. Both real first-leg bounces (via wallet outgoing-lock) and second-leg
// failures (via recipient incoming-lock) drive the actual vendored wallet.
// ---------------------------------------------------------------------------

const ESCROW_STORAGE_FLOOR: u64 = 50_000_000;

#[test]
fn authenticated_bounce_then_old_query_release_replay_reenters_pending() {
    // Item 1 (release): a first-leg bounce restores funded and clears
    // pending_query; the exact old release message then permissionlessly replays
    // and, once the wallet path works, wins and pays exactly once.
    let mut f = Fixture::new();
    f.fund();
    let accepted_at = f.state().1;
    f.lock_own_wallet();
    let relayer = f.relayer.address().clone();
    let body = f.release_body(41, f.receipt(0xa3));
    f.send(&relayer, body.clone()).expect_success();
    // Bounce restored funded and cleared settled/receipt/pending; accepted_at held.
    let (st, funded, settled, rh, pq, acc) = f.runtime();
    assert_eq!((st, funded, settled, pq, acc), (STATUS_FUNDED, AMOUNT as u128, 0, 0, accepted_at));
    assert_eq!(rh, [0u8; 32]);
    assert_eq!(f.provider_wallet_balance(), 0);
    // Replay the exact old message; it wins and is recorded as the pending settlement.
    let own = f.own_wallet.clone();
    f.set_wallet_status(&own, 0);
    f.send(&relayer, body).expect_success();
    let rh_expect: [u8; 32] = *f.receipt(0xa3).hash(0).as_slice();
    let (st, funded, settled, rh, pq, acc) = f.runtime();
    assert_eq!(
        (st, funded, settled, pq, acc),
        (STATUS_RELEASE_PENDING, AMOUNT as u128, AMOUNT as u128, 41, accepted_at)
    );
    assert_eq!(rh, rh_expect);
    assert_eq!(f.provider_wallet_balance(), AMOUNT);
}

#[test]
fn authenticated_bounce_then_old_query_refund_replay_reenters_pending() {
    // Item 1 (refund).
    let mut f = Fixture::new();
    f.fund();
    f.bc.set_now(f.refund_at as u32);
    f.lock_own_wallet();
    let relayer = f.relayer.address().clone();
    let accepted_at = f.state().1;
    let body = Fixture::refund_body(31);
    f.send(&relayer, body.clone()).expect_success();
    let (st, funded, settled, rh, pq, acc) = f.runtime();
    assert_eq!((st, funded, settled, pq, acc), (STATUS_FUNDED, AMOUNT as u128, 0, 0, accepted_at));
    assert_eq!(rh, [0u8; 32]);
    assert_eq!(f.buyer_wallet_balance(), 0);
    let own = f.own_wallet.clone();
    f.set_wallet_status(&own, 0);
    f.send(&relayer, body).expect_success();
    // Refund records the winning query and never sets settled/receipt fields.
    let (st, funded, settled, rh, pq, acc) = f.runtime();
    assert_eq!(
        (st, funded, settled, pq, acc),
        (STATUS_REFUND_PENDING, AMOUNT as u128, 0, 31, accepted_at)
    );
    assert_eq!(rh, [0u8; 32]);
    assert_eq!(f.buyer_wallet_balance(), AMOUNT);
}

#[test]
fn release_first_valid_transition_wins_and_query_number_is_not_priority() {
    // Item 2 + item 5: whichever valid release is applied first wins and pays
    // exactly once; the other is rejected and moves nothing — regardless of
    // whether the winner's query number is larger or smaller.
    let mut f = Fixture::new();
    f.fund();
    let relayer = f.relayer.address().clone();
    let first = f.release_body(70, f.receipt(0xa3));
    f.send(&relayer, first).expect_success();
    let (st, _, settled, _, pq, _) = f.runtime();
    assert_eq!((st, settled, pq), (STATUS_RELEASE_PENDING, AMOUNT as u128, 70)); // winner recorded
    assert_eq!(f.provider_wallet_balance(), AMOUNT);
    let loser = f.release_body(60, f.receipt(0xa3));
    f.send(&relayer, loser).expect_aborted().expect_exit_code(ERR_BAD_STATE);
    assert_eq!(f.runtime().4, 70); // pending query unchanged by the loser
    assert_eq!(f.provider_wallet_balance(), AMOUNT); // still exactly once

    let mut g = Fixture::new();
    g.fund();
    let r = g.relayer.address().clone();
    let first = g.release_body(60, g.receipt(0xa3));
    g.send(&r, first).expect_success();
    assert_eq!(g.runtime().4, 60); // smaller query first is recorded as the winner
    let loser = g.release_body(70, g.receipt(0xa3));
    g.send(&r, loser).expect_aborted().expect_exit_code(ERR_BAD_STATE);
    assert_eq!(g.runtime().4, 60); // loser did not overwrite the pending query
    assert_eq!(g.provider_wallet_balance(), AMOUNT);
}

#[test]
fn refund_first_valid_transition_wins_and_query_number_is_not_priority() {
    // Item 3 + item 5 for permissionless refund.
    // Larger query first wins.
    let mut f = Fixture::new();
    f.fund();
    f.bc.set_now(f.refund_at as u32);
    let relayer = f.relayer.address().clone();
    f.send(&relayer, Fixture::refund_body(81)).expect_success();
    assert_eq!(f.runtime().4, 81); // pending_query recorded == winner
    assert_eq!(f.buyer_wallet_balance(), AMOUNT);
    f.send(&relayer, Fixture::refund_body(80)).expect_aborted().expect_exit_code(ERR_BAD_STATE);
    assert_eq!(f.buyer_wallet_balance(), AMOUNT);

    // Smaller query first also wins (a "largest query wins" bug would fail here).
    let mut g = Fixture::new();
    g.fund();
    g.bc.set_now(g.refund_at as u32);
    let r = g.relayer.address().clone();
    g.send(&r, Fixture::refund_body(80)).expect_success();
    assert_eq!(g.runtime().4, 80);
    g.send(&r, Fixture::refund_body(81)).expect_aborted().expect_exit_code(ERR_BAD_STATE);
    assert_eq!(g.buyer_wallet_balance(), AMOUNT);
}

#[test]
fn repeated_replay_bounce_consumes_only_fees_and_preserves_reserve_and_jettons() {
    // Item 4: replaying the SAME bounced release conserves jettons, pays the
    // recipient nothing, returns to funded with fields cleared, consumes native
    // fees (bounded by spendable balance above the reserve), and never spends the
    // storage reserve; a working release then still settles exactly once.
    let mut f = Fixture::new();
    f.fund();
    f.lock_own_wallet(); // the first leg bounces on every attempt while locked
    let relayer = f.relayer.address().clone();
    let body = f.release_body(41, f.receipt(0xa3)); // the exact same message, replayed
    const V: u64 = TOS / 2; // 0.5 TOS attached each cycle, above the 0.15 admission floor
    for _ in 0..4 {
        let before = f.escrow_balance();
        f.send_with_value(&relayer, body.clone(), V).expect_success();
        let after = f.escrow_balance();
        let (st, funded, settled, rh, pq, _) = f.runtime();
        assert_eq!((st, funded, settled, pq), (STATUS_FUNDED, AMOUNT as u128, 0, 0));
        assert_eq!(rh, [0u8; 32]);
        assert_eq!(f.own_wallet_balance(), AMOUNT);
        assert_eq!(f.provider_wallet_balance(), 0);
        assert!(after < before + V, "a bounce/replay cycle must consume native fees");
        // The only native outflow is the bounceable payout (which returns minus
        // fees), so per-cycle cost must be fee-scale, not an arbitrary drain.
        assert!(
            before + V - after < TOS / 5,
            "per-cycle native cost must be fee-scale, not a drain"
        );
        assert!(after >= ESCROW_STORAGE_FLOOR, "the storage reserve must never be spent");
    }
    let own = f.own_wallet.clone();
    f.set_wallet_status(&own, 0);
    f.send_with_value(&relayer, body, V).expect_success();
    assert_eq!(f.state().0, STATUS_RELEASE_PENDING);
    assert_eq!(f.provider_wallet_balance(), AMOUNT);
    assert!(f.escrow_balance() >= ESCROW_STORAGE_FLOOR);
}

#[test]
fn provider_receive_locked_release_is_funds_safe_but_pending() {
    // Item 6 (BUG-002 accepted posture): a receive-locked provider wallet makes
    // the second leg re-credit the escrow's own wallet with no signal; the escrow
    // stays release_pending, the provider is unpaid, and no retry double-moves.
    let mut f = Fixture::new();
    f.fund();
    let provider = f.provider.address().clone();
    let pw = f.provider_wallet.clone();
    f.deploy_incoming_locked(provider, pw);
    let relayer = f.relayer.address().clone();
    let body = f.release_body(90, f.receipt(0xa3));
    f.send(&relayer, body).expect_success();
    assert_eq!(f.state().0, STATUS_RELEASE_PENDING);
    assert_eq!(f.provider_wallet_balance(), 0);
    assert_eq!(f.own_wallet_balance(), AMOUNT);
    let retry = f.release_body(91, f.receipt(0xa3));
    f.send(&relayer, retry).expect_aborted().expect_exit_code(ERR_BAD_STATE);
    assert_eq!(f.provider_wallet_balance(), 0);
    assert_eq!(f.own_wallet_balance(), AMOUNT);
}

#[test]
fn buyer_receive_locked_refund_is_funds_safe_but_pending() {
    // Item 7: symmetric for refund with a receive-locked buyer wallet.
    let mut f = Fixture::new();
    f.fund();
    let buyer = f.buyer.address().clone();
    let bw = f.buyer_wallet.clone();
    f.deploy_incoming_locked(buyer, bw);
    f.bc.set_now(f.refund_at as u32);
    let relayer = f.relayer.address().clone();
    let body = Fixture::refund_body(80);
    f.send(&relayer, body).expect_success();
    assert_eq!(f.state().0, STATUS_REFUND_PENDING);
    assert_eq!(f.buyer_wallet_balance(), 0);
    assert_eq!(f.own_wallet_balance(), AMOUNT);
}

fn excesses_body(query_id: u64) -> Cell {
    let mut e = BuilderData::new();
    e.append_u32(OP_EXCESSES).unwrap().append_u64(query_id).unwrap();
    e.into_cell().unwrap()
}

#[test]
fn excesses_is_non_authoritative_and_cannot_alter_a_pending_settlement() {
    // Item 8: a wallet excesses commits only to a caller-selected query id; it is
    // deliberately ignored and can neither confirm nor corrupt a settlement — not
    // even one whose query id it carries. Tested in BOTH pending states, from the
    // plausible recipient-wallet sender, asserting the FULL data cell, jetton
    // balances, and out-messages are unchanged.
    let mut f = Fixture::new();
    f.fund();
    let relayer = f.relayer.address().clone();
    let body = f.release_body(70, f.receipt(0xa3));
    f.send(&relayer, body).expect_success();
    assert_eq!(f.state().0, STATUS_RELEASE_PENDING);
    let before = f.data_hash();
    let (prov_before, own_before) = (f.provider_wallet_balance(), f.own_wallet_balance());
    let pw = f.provider_wallet.clone();
    f.send(&pw, excesses_body(70)).expect_success().expect_out_msgs(0);
    f.send(&relayer, excesses_body(70)).expect_success().expect_out_msgs(0);
    assert_eq!(f.data_hash(), before);
    assert_eq!(f.provider_wallet_balance(), prov_before);
    assert_eq!(f.own_wallet_balance(), own_before);
    assert_eq!(f.state().0, STATUS_RELEASE_PENDING);

    let mut g = Fixture::new();
    g.fund();
    g.bc.set_now(g.refund_at as u32);
    let r = g.relayer.address().clone();
    g.send(&r, Fixture::refund_body(80)).expect_success();
    assert_eq!(g.state().0, STATUS_REFUND_PENDING);
    let before = g.data_hash();
    let bw = g.buyer_wallet.clone();
    g.send(&bw, excesses_body(80)).expect_success().expect_out_msgs(0);
    assert_eq!(g.data_hash(), before);
    assert_eq!(g.state().0, STATUS_REFUND_PENDING);
}

// A bounced escrow->wallet jetton_transfer body: 0xffffffff prefix, then the
// original op::jetton_transfer and query id the handler reads back.
fn bounce_body(query: u64) -> Cell {
    let mut b = BuilderData::new();
    b.append_u32(0xffff_ffff).unwrap();
    b.append_u32(OP_JETTON_TRANSFER).unwrap();
    b.append_u64(query).unwrap();
    b.into_cell().unwrap()
}

#[test]
fn only_an_authentic_own_wallet_bounce_with_the_pending_query_clears_pending() {
    // Item 9: forged/invalid bounced messages must be rejected without state
    // change. Only a real bounce from the escrow's own wallet carrying the stored
    // pending query restores funded (covered elsewhere via wallet locks).
    let mut f = Fixture::new();
    f.fund();
    let relayer = f.relayer.address().clone();
    let body = f.release_body(70, f.receipt(0xa3));
    f.send(&relayer, body).expect_success();
    assert_eq!(f.state().0, STATUS_RELEASE_PENDING);
    let before = f.data_hash();

    // Correct-looking bounce body, but from the wrong sender.
    let bb = bounce_body(70);
    f.send_bounced(&relayer, bb).expect_aborted().expect_exit_code(ERR_BAD_CONFIRMATION);
    assert_eq!(f.data_hash(), before);

    // Authentic sender (own wallet) but the wrong bounced query.
    let own = f.own_wallet.clone();
    f.send_bounced(&own, bounce_body(99)).expect_aborted().expect_exit_code(ERR_BAD_CONFIRMATION);
    assert_eq!(f.data_hash(), before);

    // Bounce in the wrong state: fresh funded escrow, own-wallet bounce, no pending.
    let mut g = Fixture::new();
    g.fund();
    let g_own = g.own_wallet.clone();
    let g_before = g.data_hash();
    g.send_bounced(&g_own, bounce_body(70)).expect_aborted().expect_exit_code(ERR_BAD_CONFIRMATION);
    assert_eq!(g.data_hash(), g_before);
    assert_eq!(g.state().0, STATUS_FUNDED);
}

#[test]
fn settlement_balance_guard_has_no_action_phase_no_funds_gap() {
    // Item 10: locate the exact first balance admitted by the release guard. Every
    // lower candidate must fail in compute with ERR_INSUFFICIENT_GAS (never pass
    // compute and later abort action phase with result code 37), while the first
    // admitted candidate must complete the two-leg transfer and retain the floor.
    let try_release = |value: u64| -> bool {
        let mut f = Fixture::new();
        f.fund();
        let relayer = f.relayer.address().clone();
        f.set_escrow_balance(0);
        let body = f.release_body(70, f.receipt(0xa3));
        let result = f.send_with_value(&relayer, body, value);
        if result.read_primary_description().aborted {
            result.expect_exit_code(ERR_INSUFFICIENT_GAS).expect_out_msgs(0);
            assert_eq!(f.state().0, STATUS_FUNDED);
            assert_eq!(f.provider_wallet_balance(), 0);
            false
        } else {
            result.expect_success();
            assert_eq!(f.state().0, STATUS_RELEASE_PENDING);
            assert_eq!(f.provider_wallet_balance(), AMOUNT);
            assert!(f.escrow_balance() >= ESCROW_STORAGE_FLOOR);
            true
        }
    };

    // The old advertised 0.15-TOS threshold reproduced an action-phase no-funds
    // abort. The new guard must reject it explicitly and admit a funded upper bound.
    let mut rejected = 150_000_000;
    let mut admitted = 1_000_000_000;
    assert!(!try_release(rejected));
    assert!(try_release(admitted));
    while rejected + 1 < admitted {
        let candidate = rejected + (admitted - rejected) / 2;
        if try_release(candidate) {
            admitted = candidate;
        } else {
            rejected = candidate;
        }
    }
    assert_eq!(admitted, rejected + 1);
    assert!(!try_release(rejected));
    assert!(try_release(admitted));

    // Refund has the same configured requirement, but its later timestamp may
    // collect a small storage fee before credit. Locate its externally attached
    // value boundary independently and prove it has the same no-gap property.
    let try_refund = |value: u64| -> bool {
        let mut g = Fixture::new();
        g.fund();
        g.bc.set_now(g.refund_at as u32);
        let relayer = g.relayer.address().clone();
        g.set_escrow_balance(0);
        let result = g.send_with_value(&relayer, Fixture::refund_body(80), value);
        if result.read_primary_description().aborted {
            result.expect_exit_code(ERR_INSUFFICIENT_GAS).expect_out_msgs(0);
            assert_eq!(g.state().0, STATUS_FUNDED);
            assert_eq!(g.buyer_wallet_balance(), 0);
            false
        } else {
            result.expect_success();
            assert_eq!(g.state().0, STATUS_REFUND_PENDING);
            assert_eq!(g.buyer_wallet_balance(), AMOUNT);
            assert!(g.escrow_balance() >= ESCROW_STORAGE_FLOOR);
            true
        }
    };
    let mut refund_rejected = 150_000_000;
    let mut refund_admitted = 1_000_000_000;
    assert!(!try_refund(refund_rejected));
    assert!(try_refund(refund_admitted));
    while refund_rejected + 1 < refund_admitted {
        let candidate = refund_rejected + (refund_admitted - refund_rejected) / 2;
        if try_refund(candidate) {
            refund_admitted = candidate;
        } else {
            refund_rejected = candidate;
        }
    }
    assert_eq!(refund_admitted, refund_rejected + 1);
    assert!(!try_refund(refund_rejected));
    assert!(try_refund(refund_admitted));
}

#[test]
fn settlement_balance_guard_holds_at_maximum_valid_state() {
    // Residual-P2 proof. Drive the two attacker-sizeable compute loops to their
    // maxima: a 120-byte endpoint (validate_transport loop) and a 37-digit
    // (< 2^120) amount (parse_amount_text loop) — the worst-case settlement
    // compute. The balance guard must still admit ONLY balances that fully fund
    // the two-leg transfer, with no compute-pass-then-action-phase-no-funds gap.
    // If settlement_compute_gas_units under-bounded the real worst-case compute,
    // an admitted balance would abort in the action phase (or emit no transfer),
    // failing the admitted-branch assertions below.
    let max_endpoint = [0x61u8; 120]; // 120 printable bytes = max valid endpoint
    let max_amount = (1u128 << 120) - 1; // 37 digits, < 2^120 = max valid amount

    let try_release = |value: u64| -> bool {
        let mut f = Fixture::new_with(&max_endpoint, max_amount);
        f.fund();
        let relayer = f.relayer.address().clone();
        f.set_escrow_balance(0);
        let body = f.release_body(70, f.receipt(0xa3));
        let result = f.send_with_value(&relayer, body, value);
        if result.read_primary_description().aborted {
            result.expect_exit_code(ERR_INSUFFICIENT_GAS).expect_out_msgs(0);
            assert_eq!(f.state().0, STATUS_FUNDED);
            false
        } else {
            result.expect_success().expect_out_msgs(1);
            assert_eq!(f.state().0, STATUS_RELEASE_PENDING);
            assert!(f.escrow_balance() >= ESCROW_STORAGE_FLOOR);
            true
        }
    };
    let mut rejected = 150_000_000;
    let mut admitted = 1_000_000_000;
    assert!(!try_release(rejected));
    assert!(try_release(admitted));
    while rejected + 1 < admitted {
        let candidate = rejected + (admitted - rejected) / 2;
        if try_release(candidate) {
            admitted = candidate;
        } else {
            rejected = candidate;
        }
    }
    assert_eq!(admitted, rejected + 1);
    assert!(!try_release(rejected));
    assert!(try_release(admitted));

    let try_refund = |value: u64| -> bool {
        let mut g = Fixture::new_with(&max_endpoint, max_amount);
        g.fund();
        g.bc.set_now(g.refund_at as u32);
        let relayer = g.relayer.address().clone();
        g.set_escrow_balance(0);
        let result = g.send_with_value(&relayer, Fixture::refund_body(80), value);
        if result.read_primary_description().aborted {
            result.expect_exit_code(ERR_INSUFFICIENT_GAS).expect_out_msgs(0);
            assert_eq!(g.state().0, STATUS_FUNDED);
            false
        } else {
            result.expect_success().expect_out_msgs(1);
            assert_eq!(g.state().0, STATUS_REFUND_PENDING);
            assert!(g.escrow_balance() >= ESCROW_STORAGE_FLOOR);
            true
        }
    };
    let mut r_rejected = 150_000_000;
    let mut r_admitted = 1_000_000_000;
    assert!(!try_refund(r_rejected));
    assert!(try_refund(r_admitted));
    while r_rejected + 1 < r_admitted {
        let candidate = r_rejected + (r_admitted - r_rejected) / 2;
        if try_refund(candidate) {
            r_admitted = candidate;
        } else {
            r_rejected = candidate;
        }
    }
    assert_eq!(r_admitted, r_rejected + 1);
    assert!(!try_refund(r_rejected));
    assert!(try_refund(r_admitted));
}

#[test]
fn rejected_funding_return_actually_delivers_jettons_to_the_funder() {
    // Item 11: the BUG-001 return is proven end-to-end — the funder's real jetton
    // wallet receives the tokens back and the escrow wallet is debited, rather
    // than only emitting a message.
    let mut f = Fixture::new();
    let buyer = f.buyer.address().clone();
    let accept = f.accept_body(3);
    f.send(&buyer, accept).expect_success();
    assert_eq!(f.state().0, STATUS_AWAITING_FUNDING);
    let wallet = f.own_wallet.clone();
    let note = notification_body(2, AMOUNT, f.relayer.address());
    f.send(&wallet, note).expect_success().expect_out_msgs(1);
    let relayer_wallet = wallet_address(&wallet_state_init(
        frozen_code("test-usdt-wallet-code.boc.base64"),
        0,
        f.relayer.address(),
        f.master.address(),
    ));
    assert_eq!(
        wallet_balance(f.bc.get_account(&relayer_wallet).unwrap().get_data().unwrap()),
        AMOUNT
    );
    assert_eq!(f.own_wallet_balance(), 0);
    assert_eq!(f.state().0, STATUS_AWAITING_FUNDING);
}
