// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Test-only adapter: actual execution cells with explicitly synthetic proof
//! metadata. Never expose this constructor through a production client API.
use super::*;
use crate::lms_fee_schedule::{Continuity, FeeRoute, IntactState};
use crate::proven_transactions::ProvenTransaction;
use crate::wallet_v5r2::AuthRole;
use crate::wallet_v5r2_genesis::{
    CodeBundle, CodeHashes, GenesisParameters, SuccessorDeployment, WalletGenesis,
};
use crate::wallet_v5r2_pop::{FundedPopReceipts, PopBinding, PopRequest, RescuePolicy};
use crate::wallet_v5r2_wallet_state::{MigrationEvidence, ProvenWalletState};
use chain_block::{Deserializable, ShardAccount, SliceData, Transaction, write_boc};
use serde_json::Value;

fn json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).expect("required execution fixture")).unwrap()
}
fn bytes<const N: usize>(value: &Value) -> [u8; N] {
    hex::decode(value.as_str().unwrap()).unwrap().try_into().unwrap()
}
fn hex_cell(value: &Value) -> Cell {
    read_single_root_boc(hex::decode(value.as_str().unwrap()).unwrap()).unwrap()
}
fn base64_cell(value: &Value) -> Cell {
    read_single_root_boc(
        base64::engine::general_purpose::STANDARD.decode(value.as_str().unwrap()).unwrap(),
    )
    .unwrap()
}
fn enrollment(input: &Value) -> WalletGenesis {
    let p = &input["input"];
    WalletGenesis::new(
        CodeBundle::new(
            hex_cell(&p["wallet_code"]),
            hex_cell(&p["module_code"]),
            hex_cell(&p["vault_code"]),
            CodeHashes {
                wallet: bytes(&p["wallet_pin"]),
                module: bytes(&p["module_pin"]),
                vault: bytes(&p["vault_pin"]),
            },
        )
        .unwrap(),
        GenesisParameters {
            global_id: p["global_id"].as_i64().unwrap().try_into().unwrap(),
            network: bytes(&p["network"]),
            wallet_id: p["wallet_id"].as_u64().unwrap().try_into().unwrap(),
            primary_key: bytes(&p["primary_key"]),
            rescue_key: bytes(&p["rescue_key"]),
            policy: match p["policy"].as_u64().unwrap() {
                1 => RescuePolicy::Ready,
                2 => RescuePolicy::Required,
                _ => panic!("policy"),
            },
            fee_tree_id: bytes(&p["fee_tree_id"]),
            fee_public_key: bytes(&p["fee_public_key"]),
            epoch0: p["epoch0"].as_u64().unwrap().try_into().unwrap(),
        },
    )
    .unwrap()
}
fn account(receipt: &Value, now: u32) -> ProvenAccountState {
    let shard = ShardAccount::construct_from_cell(base64_cell(&receipt["shard_account"])).unwrap();
    let account = shard.read_account().unwrap();
    let root = shard.account_cell();
    ProvenAccountState {
        evidence: ProvenGetterResults {
            live: true,
            checkpoint: MasterchainCheckpoint {
                seqno: 1,
                root_hash: "00".repeat(32),
                file_hash: "00".repeat(32),
            },
            block_gen_utime: now,
            account: ProvenAccount {
                address: account.get_addr().unwrap().to_string(),
                state_hash: root.repr_hash().to_hex_string(),
                balance: account.get_balance().unwrap().coins.to_string(),
                code_hash: account.get_code_hash().unwrap().to_hex_string(),
                data_hash: account.get_data_hash().unwrap().to_hex_string(),
                last_trans_lt: shard.last_trans_lt(),
                gen_utime: now,
            },
            results: vec![],
            request_sha256: "00".repeat(32),
        },
        root,
        account,
        config_params: BTreeMap::new(),
        last_transaction_hash: *shard.last_trans_hash().as_array(),
        anchor_id: [0; 32],
    }
}
fn pop(receipt: &ProvenTransaction) -> PopRequest {
    let message = receipt.transaction().read_in_msg().unwrap().unwrap();
    let mut body = message.body().unwrap().clone();
    assert_eq!(body.get_next_u32().unwrap(), 0x50505333);
    let request = body.checked_drain_reference().unwrap();
    let mut s = SliceData::load_cell(request.clone()).unwrap();
    assert_eq!(s.get_next_u32().unwrap(), 0x504f5033);
    let global_id = s.get_next_int(32).unwrap().try_into().unwrap();
    let network = *s.get_next_hash().unwrap().as_array();
    let role = match s.get_next_byte().unwrap() {
        1 => AuthRole::Primary,
        2 => AuthRole::Rescue,
        _ => panic!("role"),
    };
    let challenge = *s.get_next_hash().unwrap().as_array();
    let valid_until = s.get_next_u32().unwrap();
    let mut parties = SliceData::load_cell(s.checked_drain_reference().unwrap()).unwrap();
    assert_eq!(parties.get_next_int(11).unwrap(), 0x400);
    let wallet = *parties.get_next_hash().unwrap().as_array();
    let module = *parties.get_next_hash().unwrap().as_array();
    let mut keys = SliceData::load_cell(s.checked_drain_reference().unwrap()).unwrap();
    assert_eq!(keys.get_next_byte().unwrap(), 1);
    let primary = *keys.get_next_hash().unwrap().as_array();
    let rescue = *keys.get_next_hash().unwrap().as_array();
    let policy = match keys.get_next_byte().unwrap() {
        1 => RescuePolicy::Ready,
        2 => RescuePolicy::Required,
        _ => panic!("policy"),
    };
    let decoded = PopRequest::new(
        PopBinding { global_id, network, account: wallet, module, challenge, valid_until },
        role,
        policy,
        primary,
        rescue,
        receipt.transaction().now(),
    )
    .unwrap();
    assert_eq!(decoded.cell().repr_hash(), request.repr_hash());
    decoded
}

#[test]
#[ignore = "requires fresh native recovery artifacts; executed explicitly by the dual-VM harness"]
fn recorded_dual_pop_migration_gate() {
    let root = PathBuf::from(
        std::env::var("TOS_V5R2_MIGRATION_FIXTURES").expect("explicit native fixture directory"),
    );
    let output = PathBuf::from(
        std::env::var("TOS_V5R2_MIGRATION_OUTPUT").expect("explicit new submission output"),
    );
    assert!(!output.exists(), "refuse to overwrite migration evidence");
    let initial = json(&root.join("sdk-genesis.json"));
    let next = json(&root.join("sdk-successor.json"));
    let birth = enrollment(&initial);
    let successor =
        SuccessorDeployment::new(enrollment(&next), bytes(&next["input"]["existing_wallet"]))
            .unwrap();
    let read = |name: &str| json(&root.join("recovery").join(format!("{name}.json")));
    let primary_fee_json = read("successor-primary-pop-fee");
    let primary_module_json = read("successor-primary-pop-module");
    let rescue_fee_json = read("successor-pop-fee");
    let rescue_module_json = read("successor-pop-module");
    let now = Transaction::construct_from_cell(base64_cell(&primary_module_json["transaction"]))
        .unwrap()
        .now();
    let vault = account(&primary_fee_json, now);
    let module = account(&primary_module_json, now);
    let primary_fee =
        ProvenTransaction::latest(&vault, base64_cell(&primary_fee_json["transaction"])).unwrap();
    let primary_module =
        ProvenTransaction::latest(&module, base64_cell(&primary_module_json["transaction"]))
            .unwrap();
    let rescue_fee = primary_fee.previous(base64_cell(&rescue_fee_json["transaction"])).unwrap();
    let rescue_module =
        primary_module.previous(base64_cell(&rescue_module_json["transaction"])).unwrap();
    let primary_request = pop(&primary_module);
    let rescue_request = pop(&rescue_module);
    let primary_receipts = FundedPopReceipts {
        fee: &primary_fee,
        module: &primary_module,
        fee_before: account(&rescue_fee_json, now).root,
        module_before: account(&rescue_module_json, now).root,
    };
    let rescue_receipts = FundedPopReceipts {
        fee: &rescue_fee,
        module: &rescue_module,
        fee_before: account(&read("deploy-vault"), now).root,
        module_before: account(&read("deploy-module"), now).root,
    };
    let primary_external = primary_fee.transaction().in_msg_cell().unwrap();
    let rescue_external = rescue_fee.transaction().in_msg_cell().unwrap();
    let wallet = account(&read("lock-wallet"), now);
    let old_module = account(&read("prepare-module"), now);
    let view = ProvenWalletState::bind_initial(&wallet, &old_module, &birth, now, 30).unwrap();
    // This comes from the still-running fixture custody process through its
    // private stdin/stdout channel, not from the accepted chain leaf counter.
    let local = json(&PathBuf::from(
        std::env::var("TOS_V5R2_MIGRATION_CONTINUITY").expect("active custody observation"),
    ));
    let fee_continuity = Continuity::Intact(IntactState {
        route: FeeRoute {
            global_id: local["global_id"].as_i64().unwrap().try_into().unwrap(),
            network: bytes(&local["network"]),
            vault: bytes(&local["vault"]),
            tree_id: bytes(&local["tree_id"]),
            epoch0: local["epoch0"].as_u64().unwrap().try_into().unwrap(),
        },
        next_unreserved: local["next_unreserved"].as_u64().unwrap().try_into().unwrap(),
        last_proven_time: local["last_proven_time"].as_u64().unwrap().try_into().unwrap(),
    });
    let evidence = MigrationEvidence {
        primary_request: &primary_request,
        primary_receipts: &primary_receipts,
        primary_external: &primary_external,
        rescue_request: &rescue_request,
        rescue_receipts: &rescue_receipts,
        rescue_external: &rescue_external,
        vault: &vault,
        fee_continuity,
        policy: None,
    };
    let mut signer =
        wallet_pq_signer::Signer::import_and_wipe(wallet_pq_signer::Role::Rescue, &mut [0x22; 48])
            .unwrap();
    let submission = view
        .sign_migration_submission(
            now,
            now.checked_add(600).unwrap(),
            &successor,
            &evidence,
            &mut signer,
        )
        .unwrap();
    let request =
        view.migration_request(now, now.checked_add(600).unwrap(), &successor, &evidence).unwrap();
    assert_eq!(submission.reference(0).unwrap().repr_hash(), request.cell().repr_hash());
    // Real executions feed the gate; proof metadata above remains synthetic.
    std::fs::write(output, write_boc(&submission).unwrap()).unwrap();
}

#[test]
#[ignore = "requires completed native recovery; executed explicitly after dual-VM replay"]
fn recorded_migration_submission_executed() {
    let root = PathBuf::from(std::env::var("TOS_V5R2_MIGRATION_FIXTURES").unwrap());
    let output = PathBuf::from(std::env::var("TOS_V5R2_MIGRATION_OUTPUT").unwrap());
    let submission = read_single_root_boc(std::fs::read(output).unwrap()).unwrap();
    let read = |name: &str| json(&root.join("recovery").join(format!("{name}.json")));
    let fee_json = read("migrate-fee");
    let module_json = read("migrate-module");
    let wallet_json = read("migrate-wallet");
    let now =
        Transaction::construct_from_cell(base64_cell(&wallet_json["transaction"])).unwrap().now();
    let fee =
        ProvenTransaction::latest(&account(&fee_json, now), base64_cell(&fee_json["transaction"]))
            .unwrap();
    let module = ProvenTransaction::latest(
        &account(&module_json, now),
        base64_cell(&module_json["transaction"]),
    )
    .unwrap();
    let wallet_state = account(&wallet_json, now);
    let wallet =
        ProvenTransaction::latest(&wallet_state, base64_cell(&wallet_json["transaction"])).unwrap();
    let message = module.transaction().read_in_msg().unwrap().unwrap();
    assert_eq!(
        message.body().unwrap().clone().into_cell().unwrap().repr_hash(),
        submission.repr_hash(),
        "executed migration differs from gated signature"
    );
    fee.require_internal_delivery(
        &module,
        module.transaction().in_msg_cell().unwrap().repr_hash().as_array(),
    )
    .unwrap();
    module
        .require_internal_delivery(
            &wallet,
            wallet.transaction().in_msg_cell().unwrap().repr_hash().as_array(),
        )
        .unwrap();
    let birth = enrollment(&json(&root.join("sdk-genesis.json")));
    let next = json(&root.join("sdk-successor.json"));
    let successor =
        SuccessorDeployment::new(enrollment(&next), bytes(&next["input"]["existing_wallet"]))
            .unwrap();
    let successor_module = account(&read("successor-primary-pop-module"), now);
    let installed = ProvenWalletState::bind_successor(
        &wallet_state,
        &successor_module,
        &birth,
        &successor,
        now,
        30,
    )
    .unwrap();
    assert_eq!(installed.epoch(), 3);
    assert_eq!(installed.seqno(), 0);
}

#[cfg(feature = "native-wallet-vault")]
#[path = "wallet_v5r2_recorded_fee_tests.rs"]
mod recorded_fee_tests;
