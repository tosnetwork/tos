//! Offline final-ceremony withdrawal against the exact 0.001 TOS candidate.
//! Public candidate, price snapshot and ceremony inputs only; no network or wallet.
//! Explicitly ignored unless the retained public-input paths are supplied.
mod support;

use chain_block::{read_single_root_boc, ConfigParamEnum};
use shielded_pool_ceremony::{
    audit::{audit, StartingKey},
    record::Directory,
};
use shielded_pool_circuit_crosscheck::{pool::Pool, public_client::PublicClient};
use std::path::{Path, PathBuf};
use support::{Outcome, Perturbation, Withdrawal, ACCEPTER, REFUSER};
use tos_sandbox::Blockchain;

const VK: &str = "49696f52f361817869f68c3ba68d0d5a854737a4133ae4616255ac4a3846778c";
const TRANSCRIPT: &str = "03e67eb4b1cff48c9bc5952992a46d37ae0c32d6ba2f76910f785daca8704579";
const CODE: &str = "ce3b21bc64e392e14065e68665228bcb10e40dd83836ef00574dd90e5ce057cd";
const DATA: &str = "60292fb7bca1c7ebb92a887c893281e9277410c3f7c0a826f2188634700040dd";
const ACCOUNT: &str = "0b29545f6a2690118a7b009a61983980f3fbac3e01624473654e153e06a4ccea";
const AMOUNT: u64 = 1_000_000_000;
const FEE: u64 = 1_000_000;

fn input(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).expect("explicit public fixture path required"))
}

fn bounded(path: &Path) -> Vec<u8> {
    assert!(path.metadata().expect("public fixture metadata").len() <= 1 << 20);
    std::fs::read(path).expect("public fixture")
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.is_ascii() && text.len() % 2 == 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn run(refuse: bool) -> Outcome {
    let candidate = input("TOS_FINAL_POOL_CANDIDATE");
    let fees: serde_json::Value =
        serde_json::from_slice(&bounded(&input("TOS_FINAL_POOL_FEES"))).expect("price snapshot");
    assert_eq!(fees["schema"], "tos.shielded-pool.fee-snapshot.v1");
    assert_eq!(fees["global_id"], 2);
    assert_eq!(fees["global_version"], 16);
    let code = read_single_root_boc(bounded(&candidate.join("code.boc"))).expect("candidate code");
    let data = read_single_root_boc(bounded(&candidate.join("data.boc"))).expect("candidate data");
    assert_eq!(code.repr_hash().to_hex_string(), CODE);
    assert_eq!(data.repr_hash().to_hex_string(), DATA);
    let manifest: serde_json::Value =
        serde_json::from_slice(&bounded(&candidate.join("manifest.json")))
            .expect("candidate manifest");
    assert_eq!(manifest["configuration"]["withdrawal_fee"], FEE.to_string());
    let mut bc = Blockchain::with_global_version_and_base_workchain(16).expect("sandbox");
    let mut config = bc.config_params().clone();
    for number in [8_u32, 18, 19, 20, 21, 24, 25, 31, 43] {
        let row = &fees["parameters"][number.to_string()];
        let bytes = unhex(row["boc_hex"].as_str().expect("config BOC"));
        let digest = shielded_pool_genesis::sha256(&bytes)
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect::<String>();
        assert_eq!(digest, row["boc_sha256"].as_str().expect("config digest"));
        config
            .set_config(
                ConfigParamEnum::construct_from_cell_and_number(
                    read_single_root_boc(bytes).expect("config cell"),
                    number,
                )
                .expect("config decode"),
            )
            .expect("config install");
    }
    bc.set_config(config).expect("actual price cells");
    bc.set_now(fees["chain_time"].as_u64().expect("chain time").try_into().expect("u32 time"));
    let pool = Pool::deploy_candidate(bc, code, data, 2, 100_000_000_000).expect("exact candidate");
    let account = pool.account().expect("candidate address");
    assert_eq!(account.iter().map(|v| format!("{v:02x}")).collect::<String>(), ACCOUNT);
    let directory = Directory::at(input("TOS_FINAL_POOL_CEREMONY"));
    let audited = audit(&directory, &StartingKey::rebuild().expect("ceremony starting key"))
        .expect("full ceremony audit");
    assert_eq!(audited.vk_sha256(), VK);
    assert_eq!(audited.transcript(), TRANSCRIPT);
    let client = PublicClient::load(&directory, &audited, VK, 2, &account).expect("final prover");
    let outcome = support::run_with_pool(
        &Withdrawal {
            denominations: &[AMOUNT, 10 * AMOUNT, 100 * AMOUNT, 1000 * AMOUNT],
            amount: AMOUNT,
            destination_name: if refuse { "final-refuser" } else { "final-accepter" },
            destination_source: if refuse { REFUSER } else { ACCEPTER },
            age: None,
            before_transact: Perturbation { value: Some(11_500_010), ..Default::default() },
        },
        pool,
        client.execution_domain(),
        |public, witness, now| {
            client.prove(public, witness, now).expect("final-key withdrawal proof")
        },
    );
    assert_eq!(outcome.exit, 0);
    assert_eq!(outcome.action, Some(0));
    assert!(!outcome.aborted);
    assert_eq!(outcome.sent_by_the_pool, 1);
    assert_eq!(outcome.nullifier_next_index, "3");
    assert_eq!(outcome.pool_liability_before, u128::from(2 * AMOUNT));
    assert_eq!(outcome.payout_value, Some(u128::from(AMOUNT)));
    assert_eq!(outcome.recipient_credit, Some(u128::from(AMOUNT)));
    assert!(outcome.holds >= outcome.pool_liability_after + outcome.reserve);
    eprintln!("final withdrawal: refused={refuse}, fee={FEE}, gas={}, recovery_gas={}, liability_after={}", outcome.gas, outcome.recovery_gas, outcome.pool_liability_after);
    outcome
}

#[test]
#[ignore = "requires explicit final candidate, audited public ceremony and fee snapshot paths"]
fn final_key_withdrawal_pays_out_with_the_new_fee() {
    let outcome = run(false);
    assert_eq!(outcome.transactions, 2);
    assert_eq!(outcome.recipient_success, Some(true));
    assert_eq!(outcome.refused_at, None);
    assert_eq!(outcome.bounced_from, None);
    assert_eq!(outcome.commitment_next_index, "5");
    assert_eq!(outcome.reserved_recovery_leaves, "1");
    assert_eq!(outcome.pool_liability_after, u128::from(AMOUNT - FEE));
}

#[test]
#[ignore = "requires explicit final candidate, audited public ceremony and fee snapshot paths"]
fn final_key_withdrawal_refusal_bounces_and_recovers() {
    let outcome = run(true);
    assert_eq!(outcome.transactions, 3);
    assert_eq!(outcome.recipient_success, Some(false));
    assert_eq!(outcome.refused_at.as_deref(), Some(outcome.destination.as_str()));
    assert_eq!(outcome.bounced_from.as_deref(), Some(outcome.destination.as_str()));
    assert_eq!(outcome.recovery_exit, 0);
    assert_eq!(outcome.commitment_next_index, "6");
    assert_eq!(outcome.reserved_recovery_leaves, "0");
    assert!(outcome.bounced_value > outcome.recovery_charge);
    assert_eq!(
        outcome.pool_liability_after,
        u128::from(AMOUNT - FEE) + outcome.bounced_value - outcome.recovery_charge
    );
}
