// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Public fixture custody replay. Proof metadata is synthetic, never live evidence.
use super::*;
use crate::{
    lms_fee_journal::FeeJournal,
    lms_fee_vault::{restore_seed_and_wipe, tests::open},
    wallet_v5r2_fee::{FeeClass, FeePayload},
    wallet_v5r2_state::ProvenFeeVault,
};
use secrets_vault::types::secret_id::SecretId;

#[tokio::test]
#[ignore = "requires recorded native fee transactions; invoked explicitly by custody replay"]
async fn recorded_fee_custody_matches_executed_messages() {
    let root = PathBuf::from(std::env::var("TOS_V5R2_FEE_FIXTURES").unwrap());
    let output = PathBuf::from(std::env::var("TOS_V5R2_FEE_OUTPUT").unwrap());
    assert!(!output.exists(), "refuse to overwrite custody evidence");
    let initial = enrollment(&json(&root.join("sdk-genesis.json")));
    let next = json(&root.join("sdk-successor.json"));
    let successor =
        SuccessorDeployment::new(enrollment(&next), bytes(&next["input"]["existing_wallet"]))
            .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let storage_path = dir.path().join("encrypted-fee.json");
    let mut trees: [Option<wallet_pq_signer::fee::FeeTree>; 2] = [None, None];
    let mut journals: [Option<FeeJournal>; 2] = [None, None];
    let mut checked = vec![];
    for (number, route, before, receipt) in [
        (4, 0, "genesis-deployment/vault.json", "lock-fee"),
        (6, 0, "recovery/lock-fee.json", "prepare-fee"),
        (8, 1, "recovery/deploy-vault.json", "successor-pop-fee"),
        (10, 1, "recovery/successor-pop-fee.json", "successor-primary-pop-fee"),
        (12, 0, "recovery/prepare-fee.json", "migrate-fee"),
        (14, 1, "recovery/successor-primary-pop-fee.json", "payment-fee"),
    ] {
        let encoded = json(&root.join(format!("sdk-fee/{number:02}.json")));
        let input = &encoded["input"];
        let now: u32 = input["proven_time"].as_u64().unwrap().try_into().unwrap();
        let leaf: u32 = input["leaf"].as_u64().unwrap().try_into().unwrap();
        let state = account(&json(&root.join(before)), now);
        let view = if route == 0 {
            ProvenFeeVault::bind(&state, &initial, now, 30)
        } else {
            ProvenFeeVault::bind_successor(&state, &successor, now, 30)
        }
        .unwrap();
        let signature = hex::decode(input["signature"].as_str().unwrap()).unwrap();
        let path: [u8; 640] = signature[2192..].try_into().unwrap();
        let id = SecretId::new(if route == 0 { "old-fee" } else { "successor-fee" });
        if journals[route].is_none() {
            let name = if route == 0 {
                "PUBLIC-TEST-ONLY-lms-tree"
            } else {
                "PUBLIC-TEST-ONLY-successor-tree"
            };
            let header = [b"TOSFT001".as_slice(), view.fee_public_key()].concat();
            let input = std::io::Read::chain(
                std::io::Cursor::new(header),
                std::fs::File::open(root.join(name)).unwrap(),
            );
            trees[route] = Some(
                wallet_pq_signer::fee::FeeTree::read_cache(input, view.fee_public_key()).unwrap(),
            );
            let vault = open(&storage_path).await;
            let mut seed = [if route == 0 { 0x44 } else { 0x77 }; 48];
            seed[32..].fill(if route == 0 { 0x55 } else { 0x88 });
            restore_seed_and_wipe(&vault, &id, &mut seed, view.fee_public_key(), leaf, &path)
                .await
                .unwrap();
            assert_eq!(seed, [0; 48], "recorded custody restore retained seed");
            drop(vault);
            let journal_path = dir.path().join(format!("journal-{route}"));
            std::fs::create_dir(&journal_path).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&journal_path, std::fs::Permissions::from_mode(0o700))
                    .unwrap();
            }
            journals[route] =
                Some(FeeJournal::open(&journal_path, view.route(), now - 3600).unwrap());
        }
        let vault = open(&storage_path).await;
        let journal = journals[route].as_mut().unwrap();
        assert_eq!(journal.preview_proven(&view, now).unwrap().leaf, leaf);
        let class = match input["class"].as_u64().unwrap() {
            1 => FeeClass::RescueAuth,
            2 => FeeClass::Pop,
            3 => FeeClass::Prepare,
            _ => panic!("fee class"),
        };
        let payload = || FeePayload::from_submission(class, hex_cell(&input["payload"])).unwrap();
        let deadline = input["deadline"].as_u64().unwrap().try_into().unwrap();
        let value = input["value"].as_str().unwrap().parse().unwrap();
        if route == 1 {
            let mut samples = 0;
            let mismatch = journal
                .sign_proven_fee_from_vault_tree(
                    &vault,
                    &id,
                    &view,
                    || {
                        samples += 1;
                        now
                    },
                    deadline,
                    value,
                    payload(),
                    trees[0].as_ref().unwrap(),
                )
                .await;
            assert!(mismatch.is_err(), "fee tree mismatch accepted");
            assert_eq!(samples, 1, "wrong fee tree reached key loading path");
            assert_eq!(journal.preview_proven(&view, now).unwrap().leaf, leaf);
        }
        let mut samples = 0;
        let stale = journal
            .sign_proven_fee_from_vault_tree(
                &vault,
                &id,
                &view,
                || {
                    samples += 1;
                    if samples <= 2 { now } else { now + 31 }
                },
                deadline,
                value,
                payload(),
                trees[route].as_ref().unwrap(),
            )
            .await;
        assert!(stale.is_err(), "recorded custody accepted stale clock after key loading");
        assert_eq!(
            journal.preview_proven(&view, now).unwrap().leaf,
            leaf,
            "recorded custody stale clock consumed leaf"
        );
        let signed = journal
            .sign_proven_fee_from_vault_tree(
                &vault,
                &id,
                &view,
                || now,
                deadline,
                value,
                payload(),
                trees[route].as_ref().unwrap(),
            )
            .await
            .unwrap();
        let expected = hex_cell(&encoded["output"]["external"]);
        assert_eq!(
            signed.body().repr_hash(),
            expected.repr_hash(),
            "protected custody changed executed fee body"
        );
        assert_eq!(write_boc(signed.body()).unwrap(), write_boc(&expected).unwrap());
        let receipt = json(&root.join(format!("recovery/{receipt}.json")));
        assert_eq!(receipt["details"]["aborted"], false);
        let tx = Transaction::construct_from_cell(base64_cell(&receipt["transaction"])).unwrap();
        let msg = tx.read_in_msg().unwrap().unwrap();
        assert_eq!(
            msg.body().unwrap().clone().into_cell().unwrap().repr_hash(),
            signed.body().repr_hash(),
            "custody body differs from actual executed transaction input"
        );
        drop(vault);
        let cached = journal
            .cached_signature_verified(view.fee_public_key(), leaf, *signed.intent().digest())
            .unwrap();
        assert_eq!(cached, signature, "protected custody retry changed executed signature");
        checked.push(serde_json::json!({"route":route,"leaf":leaf,"body_hash":signed.body().repr_hash().to_hex_string()}));
    }
    assert_eq!(checked.len(), 6);
    std::fs::write(output, serde_json::to_vec_pretty(&serde_json::json!({
        "scope":"Encrypted public test seeds, actual executed bodies, synthetic proof metadata; diagnostic credit 20000",
        "messages":checked,"stale_clock_rejected_without_reservation":true,
        "reopened_encrypted_vault":true,"exact_cached_retry_after_vault_drop":true
    })).unwrap()).unwrap();
}
