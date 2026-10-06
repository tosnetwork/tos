/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! Operator wallets bind the network's global_id (ConfigParam 19) into every
//! signed body. These tests deploy each wallet version into the sandbox,
//! whose config publishes global_id 42, and check that a body signed for that
//! network executes while a body signed for any other network is rejected by
//! the contract before it can spend anything.

use chain_block::{
    Cell, Deserializable, Message, MsgAddressInt, base64_decode, read_single_root_boc,
};
use common::{WalletVersion, signer::Signer, tvm_stack_parser::TvmStackParser};
use contracts::wallet::wallet_contract::{V3R2_CODE, V4R2_CODE_B64, V5R1_CODE_B64};
use contracts::{ContractProvider, SmartContract, Wallet, WalletContract};
use ed25519_dalek::{Signer as _, SigningKey};
use std::sync::Arc;
use tl_api::tos::tvm::StackEntry;
use tos_sandbox::{Blockchain, Treasury, compile_func_with_stdlib};

const TOS: u64 = 1_000_000_000;
/// The value the sandbox publishes in ConfigParam 19.
const GLOBAL_ID: i32 = 42;
/// A neighbouring network identity: same key, same code, same address, but
/// the contract must refuse every body signed with it.
const OTHER_GLOBAL_ID: i32 = GLOBAL_ID + 1;
const SUBWALLET_ID: u32 = 698_983_191;
const WORKCHAIN: i32 = -1;

const V3_WRONG_GLOBAL_ID_EXIT: i32 = 36;
const V4_WRONG_GLOBAL_ID_EXIT: i32 = 36;
const V5_WRONG_GLOBAL_ID_EXIT: i32 = 148;

fn smartcont(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../crypto/smartcont").join(name)
}

#[test]
fn source_compiles_to_the_embedded_wallet_code() {
    let cases = [
        ("wallet3-code.fc", read_single_root_boc(hex::decode(V3R2_CODE).expect("v3 hex"))),
        ("wallet-v4-code.fc", read_single_root_boc(base64_decode(V4R2_CODE_B64).expect("v4 b64"))),
        ("wallet-v5-code.fc", read_single_root_boc(base64_decode(V5R1_CODE_B64).expect("v5 b64"))),
    ];
    for (source, embedded) in cases {
        let compiled = compile_func_with_stdlib(&[smartcont(source)])
            .unwrap_or_else(|e| panic!("compile {source}: {e}"));
        let embedded = embedded.unwrap_or_else(|e| panic!("decode embedded {source}: {e}"));
        assert_eq!(
            compiled.repr_hash(),
            embedded.repr_hash(),
            "embedded {source} BOC must be regenerated whenever the FunC source changes"
        );
    }
}

/// Deterministic in-process signer standing in for the vault-backed one.
struct TestSigner(SigningKey);

#[async_trait::async_trait]
impl Signer for TestSigner {
    async fn public_key(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.0.verifying_key().to_bytes().to_vec())
    }

    async fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(self.0.sign(message).to_bytes().to_vec())
    }
}

/// The sandbox has no RPC surface; every test passes an explicit seqno, so
/// a provider that refuses to be consulted keeps the wallet honest about it.
struct NoProvider;

#[async_trait::async_trait]
impl ContractProvider for NoProvider {
    async fn get_method(
        &self,
        _address: String,
        method: &str,
        _stack: Vec<StackEntry>,
    ) -> anyhow::Result<TvmStackParser> {
        anyhow::bail!("sandbox wallet tests must not query get-method {method} through RPC")
    }

    async fn balance(&self, _address: &MsgAddressInt) -> anyhow::Result<u64> {
        anyhow::bail!("sandbox wallet tests must not query balance through RPC")
    }
}

struct Fixture {
    bc: Blockchain,
    version: WalletVersion,
    secret: [u8; 32],
    address: MsgAddressInt,
    target: Treasury,
}

impl Fixture {
    async fn new(version: WalletVersion) -> Self {
        let mut bc = Blockchain::new().expect("blockchain");
        bc.set_workchain(WORKCHAIN as i8);
        let funder = bc.treasury("funder", 1_000 * TOS).expect("funder");
        let target = bc.treasury("target", 1_000 * TOS).expect("target");
        let secret = [0x42; 32];
        let public_key = SigningKey::from_bytes(&secret).verifying_key().to_bytes();
        let address =
            WalletContract::calculate_address(version, WORKCHAIN, SUBWALLET_ID, &public_key)
                .expect("wallet address");
        // Fund the not-yet-deployed address so the external deploy can pay
        // for its own gas. The account has no code yet, so the executor
        // records this as a credit-only (aborted) transaction; the value
        // still lands.
        let fund = funder.build_message(&address, 50 * TOS, false, None);
        bc.send_message(fund).expect("fund wallet");
        let fixture = Self { bc, version, secret, address, target };
        assert_eq!(fixture.balance_of(&fixture.address), 50 * TOS, "funding must be credited");
        fixture
    }

    fn balance_of(&self, address: &MsgAddressInt) -> u64 {
        self.bc
            .get_account(address)
            .and_then(|account| account.balance().cloned())
            .and_then(|balance| balance.coins.as_u64())
            .expect("account balance")
    }

    async fn wallet(&self, global_id: i32) -> WalletContract {
        let signer = TestSigner(SigningKey::from_bytes(&self.secret));
        let wallet = WalletContract::new(
            Box::new(signer),
            self.version,
            SUBWALLET_ID,
            WORKCHAIN,
            global_id,
            Arc::new(NoProvider),
        )
        .await
        .expect("wallet");
        assert_eq!(
            wallet.address(),
            self.address,
            "the address must not depend on global_id; only signatures do"
        );
        wallet
    }

    /// Builds the external message a wallet signed for `global_id` would
    /// submit: a 1 TOS transfer to the target, deploying the wallet on the
    /// first message.
    async fn signed_transfer(&self, global_id: i32, seqno: u32, deploy: bool) -> Message {
        let wallet = self.wallet(global_id).await;
        let state_init =
            if deploy { Some(wallet.state_init().await.expect("state init")) } else { None };
        let cell = wallet
            .build_message(
                self.target.address().clone(),
                TOS,
                Cell::default(),
                true,
                Some(seqno),
                state_init,
                None,
            )
            .await
            .expect("signed transfer");
        Message::construct_from_cell(cell).expect("external message")
    }

    fn expect_rejected(&mut self, message: Message, exit_code: i32) {
        let error = match self.bc.send_message(message) {
            Ok(_) => panic!("a body signed for another network must not execute"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains(&format!("exit code: {exit_code}")),
            "expected exit code {exit_code}, got {error}"
        );
    }

    fn seqno(&self) -> i128 {
        self.bc
            .run_get_method(&self.address, "seqno", vec![])
            .expect("seqno")
            .expect_success()
            .int_at(0)
    }

    fn target_balance(&self) -> u64 {
        self.balance_of(self.target.address())
    }
}

async fn accepts_own_network_and_rejects_other(version: WalletVersion, exit_code: i32) {
    let mut fixture = Fixture::new(version).await;
    let before = fixture.target_balance();

    // A deploy signed for a neighbouring network is refused before the
    // account is even initialised.
    let foreign_deploy = fixture.signed_transfer(OTHER_GLOBAL_ID, 0, true).await;
    fixture.expect_rejected(foreign_deploy, exit_code);
    assert!(
        fixture.bc.run_get_method(&fixture.address, "seqno", vec![]).is_err(),
        "rejected deploy must leave the account uninitialised"
    );
    assert_eq!(fixture.target_balance(), before);

    // The same key signed for this network deploys and pays.
    let deploy = fixture.signed_transfer(GLOBAL_ID, 0, true).await;
    let result = fixture.bc.send_message(deploy).expect("deploy and transfer");
    result.expect_success();
    assert_eq!(fixture.seqno(), 1, "{version}: seqno advances after an accepted body");
    let after_first = fixture.target_balance();
    assert!(after_first > before, "{version}: target must receive the transfer");

    // A subsequent transfer signed for the other network is rejected and
    // does not consume the seqno or move funds.
    let foreign_transfer = fixture.signed_transfer(OTHER_GLOBAL_ID, 1, false).await;
    fixture.expect_rejected(foreign_transfer, exit_code);
    assert_eq!(fixture.seqno(), 1, "{version}: rejected body must not advance seqno");
    assert_eq!(fixture.target_balance(), after_first);

    // And the honest signer keeps working with the same seqno.
    let transfer = fixture.signed_transfer(GLOBAL_ID, 1, false).await;
    fixture.bc.send_message(transfer).expect("second transfer").expect_success();
    assert_eq!(fixture.seqno(), 2, "{version}: second accepted body advances seqno");
    assert!(fixture.target_balance() > after_first);
}

#[tokio::test]
async fn v3_transfer_is_bound_to_network_global_id() {
    accepts_own_network_and_rejects_other(WalletVersion::V3R2, V3_WRONG_GLOBAL_ID_EXIT).await;
}

#[tokio::test]
async fn v4_transfer_is_bound_to_network_global_id() {
    accepts_own_network_and_rejects_other(WalletVersion::V4R2, V4_WRONG_GLOBAL_ID_EXIT).await;
}

#[tokio::test]
async fn v5_transfer_is_bound_to_network_global_id() {
    accepts_own_network_and_rejects_other(WalletVersion::V5R1, V5_WRONG_GLOBAL_ID_EXIT).await;
}

/// A wallet holding exactly the value plus the reserve `vote offer create` requires
/// still sends: the reserve covers the wallet's whole mode-3 charge, including
/// storage due after a long idle period. Mode 3 ignores action errors, so a reserve
/// below the real charge would show here as the target receiving nothing.
///
/// `debt` puts that much storage debt on the account first, as a wallet carries after
/// its balance once fell short of storage and a later top-up did not clear it: the
/// next external send pays the debt with its storage phase.
async fn the_send_reserve_covers_the_wallet_charge(version: WalletVersion, debt: u64) {
    use contracts::wallet::send_fees::{AccountStorage, SendFeeInputs, wallet_send_reserve};
    let mut fixture = Fixture::new(version).await;
    let deploy = fixture.signed_transfer(GLOBAL_ID, 0, true).await;
    fixture.bc.send_message(deploy).expect("deploy").expect_success();

    // Let storage accrue for a long idle period.
    let idle_until = fixture.bc.now() + 180 * 86_400;
    fixture.bc.set_now(idle_until);

    // A proposal-sized body with a value of many cells.
    let mut value = chain_block::BuilderData::new();
    chain_block::IBitstring::append_u32(&mut value, 1).expect("value");
    let mut value = value.into_cell().expect("value");
    for word in 0..200u32 {
        let mut next = chain_block::BuilderData::new();
        chain_block::IBitstring::append_u32(&mut next, word).expect("value");
        next.checked_append_reference(value).expect("value");
        value = next.into_cell().expect("value");
    }
    let proposal =
        contracts::config_contract::messages::proposal::proposal_cell(100, Some(value), None)
            .expect("proposal");
    let body = contracts::config_contract::messages::proposal::new_proposal_body(
        1, 2_000_000, proposal, false,
    )
    .expect("body");

    let mut account = fixture.bc.get_account(&fixture.address).expect("deployed").clone();
    if debt > 0 {
        account.set_due_payment(Some(chain_block::Coins::from(debt)));
        fixture.bc.set_account(fixture.address.clone(), account.clone());
    }
    let storage = AccountStorage::from_account(&account).expect("storage");
    assert_eq!(storage.due_payment, u128::from(debt));
    let config = fixture.bc.config_params();
    let gas = config.gas_prices(true).expect("gas prices");
    let forward = config.fwd_prices(true).expect("forward prices");
    let storage_prices = config.storage_prices().expect("storage prices").prices().expect("prices");
    let reserve = wallet_send_reserve(&SendFeeInputs {
        gas: &gas,
        forward: &forward,
        storage_prices: &storage_prices,
        storage: &storage,
        now: idle_until,
        body: &body,
    })
    .expect("reserve");

    // The boundary: everything but the reserve is sent.
    let balance = fixture.balance_of(&fixture.address);
    let value = balance - u64::try_from(reserve).expect("reserve fits");
    let target_before = fixture.target_balance();
    let wallet = fixture.wallet(GLOBAL_ID).await;
    let cell = wallet
        .build_message(fixture.target.address().clone(), value, body, true, Some(1), None, None)
        .await
        .expect("signed send");
    let message = Message::construct_from_cell(cell).expect("external message");
    fixture.bc.send_message(message).expect("send").expect_success();
    assert_eq!(fixture.seqno(), 2, "{version}: the wallet accepted the message");
    assert!(
        fixture.target_balance() > target_before,
        "{version}: nothing reached the target; the reserve {reserve} is below the wallet's charge"
    );
    let charge = balance - value - fixture.balance_of(&fixture.address);
    eprintln!("{version}: reserve {reserve}, charge {charge}");
    assert!(
        u128::from(charge) <= reserve,
        "{version}: charge {charge} exceeds the reserve {reserve}"
    );
}

#[tokio::test]
async fn v3_send_reserve_covers_the_wallet_charge() {
    the_send_reserve_covers_the_wallet_charge(WalletVersion::V3R2, 0).await;
}

#[tokio::test]
async fn v4_send_reserve_covers_the_wallet_charge() {
    the_send_reserve_covers_the_wallet_charge(WalletVersion::V4R2, 0).await;
}

#[tokio::test]
async fn v5_send_reserve_covers_the_wallet_charge() {
    the_send_reserve_covers_the_wallet_charge(WalletVersion::V5R1, 0).await;
}

/// Storage debt below the freeze threshold: the next send pays it, and the reserve
/// counts it.
#[tokio::test]
async fn v3_send_reserve_covers_outstanding_storage_debt() {
    the_send_reserve_covers_the_wallet_charge(WalletVersion::V3R2, 2 * TOS).await;
}

#[tokio::test]
async fn v4_send_reserve_covers_outstanding_storage_debt() {
    the_send_reserve_covers_the_wallet_charge(WalletVersion::V4R2, 2 * TOS).await;
}

#[tokio::test]
async fn v5_send_reserve_covers_outstanding_storage_debt() {
    the_send_reserve_covers_the_wallet_charge(WalletVersion::V5R1, 2 * TOS).await;
}
