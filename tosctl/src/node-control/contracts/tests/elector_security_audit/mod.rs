//! Selection accounting and configuration-sensitive retries, on the real executor.

use super::*;
use chain_block::{BuilderData, HashmapType, IBitstring, Serializable, SliceData};

fn counts(chain: &mut Chain, max: u16, min: u16) {
    let mut value = BuilderData::new();
    value.append_u16(max).expect("maximum");
    value.append_u16(max).expect("main maximum");
    value.append_u16(min).expect("minimum");
    set_contract_parameter(chain, 16, value.into_cell().expect("count configuration"));
}

fn synthetic_code(index: u16) -> chain_block::UInt256 {
    let mut bytes = [0x7c; 32];
    bytes[30..].copy_from_slice(&index.to_be_bytes());
    chain_block::UInt256::from_slice(&bytes)
}

fn failed_record(chain: &Chain) -> (bool, bool, Option<Vec<u8>>) {
    let data =
        chain.blockchain.get_account(&chain.elector).expect("elector").get_data().expect("storage");
    let mut root = SliceData::load_cell(data).expect("storage slice");
    let election = next_dictionary(&mut root, 32);
    let mut fields = SliceData::load_cell(HashmapType::data(&election).expect("open").clone())
        .expect("election slice");
    fields.get_next_u32().expect("start");
    fields.get_next_u32().expect("close");
    next_coins(&mut fields);
    next_coins(&mut fields);
    let failed = fields.get_next_bit().expect("failed");
    let finished = fields.get_next_bit().expect("finished");
    for _ in 0..3 {
        next_dictionary(&mut fields, 256);
    }
    let cache = if fields.remaining_bits() == 0 {
        None
    } else {
        assert_eq!(fields.remaining_bits(), 256, "exact failed-input cache");
        Some(fields.get_next_bits(256).expect("fingerprint"))
    };
    assert_eq!(fields.remaining_references(), 0);
    (failed, finished, cache)
}

fn dictionary(builder: &mut BuilderData, value: &chain_block::HashmapE) {
    if let Some(root) = HashmapType::data(value) {
        builder.append_bit_one().expect("dictionary present");
        builder.checked_append_reference(root.clone()).expect("dictionary root");
    } else {
        builder.append_bit_zero().expect("empty dictionary");
    }
}

fn align_declared_total_with_the_synthetic_book(chain: &mut Chain) {
    let (members, _) = pq_book(chain);
    let mut total = 0u128;
    HashmapType::iterate_slices(&members, |_, mut member| {
        total = total.checked_add(next_coins(&mut member)).expect("fixture total");
        Ok(true)
    })
    .expect("member book");
    let mut account = chain.blockchain.get_account(&chain.elector).expect("elector").clone();
    let mut root = SliceData::load_cell(account.get_data().expect("data")).expect("slice");
    let active = next_dictionary(&mut root, 32);
    let mut fields =
        SliceData::load_cell(HashmapType::data(&active).expect("active").clone()).expect("fields");
    let mut record = BuilderData::new();
    record.append_u32(fields.get_next_u32().expect("time")).expect("time");
    record.append_u32(fields.get_next_u32().expect("close")).expect("close");
    chain_block::Coins::new(u64::try_from(next_coins(&mut fields)).expect("minimum"))
        .write_to(&mut record)
        .expect("minimum");
    next_coins(&mut fields);
    chain_block::Coins::new(u64::try_from(total).expect("bounded fixture total"))
        .write_to(&mut record)
        .expect("total");
    record.checked_append_references_and_data(&fields).expect("flags and books");
    let mut rebuilt = BuilderData::new();
    rebuilt.append_bit_one().expect("election");
    rebuilt.checked_append_reference(record.into_cell().expect("record")).expect("record");
    rebuilt.checked_append_references_and_data(&root).expect("liabilities");
    account.set_data(rebuilt.into_cell().expect("data"));
    chain.blockchain.set_account(chain.elector.clone(), account);
    let mut stored = SliceData::load_cell(
        chain.blockchain.get_account(&chain.elector).expect("elector").get_data().expect("data"),
    )
    .expect("slice");
    let active = next_dictionary(&mut stored, 32);
    let mut record =
        SliceData::load_cell(HashmapType::data(&active).expect("active").clone()).expect("record");
    record.get_next_u32().expect("time");
    record.get_next_u32().expect("close");
    next_coins(&mut record);
    assert_eq!(next_coins(&mut record), total, "fixture must preserve the complete principal book");
}

fn seed_history(chain: &mut Chain, owners: &[(u16, u64)]) {
    let mut account = chain.blockchain.get_account(&chain.elector).expect("elector").clone();
    let mut root = SliceData::load_cell(account.get_data().expect("storage")).expect("slice");
    let election = next_dictionary(&mut root, 32);
    let mut credits = next_dictionary(&mut root, 256);
    for (owner, amount) in owners {
        let key = SliceData::load_builder(
            BuilderData::with_raw(refund_owner(*owner).to_vec(), 256).expect("owner bits"),
        )
        .expect("owner key");
        let mut value = BuilderData::new();
        chain_block::Coins::new(*amount).write_to(&mut value).expect("historic credit");
        credits.set_builder(key, &value).expect("credit entry");
    }
    let mut rebuilt = BuilderData::new();
    dictionary(&mut rebuilt, &election);
    dictionary(&mut rebuilt, &credits);
    rebuilt.checked_append_references_and_data(&root).expect("remaining storage");
    account.set_data(rebuilt.into_cell().expect("elector storage"));
    chain.blockchain.set_account(chain.elector.clone(), account);
}

#[test]
fn every_cap_boundary_conserves_the_increment_without_consuming_historic_credits() {
    for target in [90_000, 100_000, 110_000] {
        for selected in [false, true] {
            let (mut chain, _, election) = open_election("cap-boundary", 400_000 * TOS);
            raise_to_post_quantum_version(&mut chain);
            let stakes = if selected {
                [target, 80_000, 70_000, 60_000]
            } else {
                [target, 140_000, 130_000, 80_000]
            };
            install_synthetic_book_full(&mut chain, 4, 1, &|i, _| refund_owner(i), &|i| {
                stakes[usize::from(i)] * TOS
            });
            counts(&mut chain, 2, 2);
            set_contract_parameter(
                &mut chain,
                17,
                stake_limits(10_000 * TOS, 100_000 * TOS, 40_000 * TOS, 0x10000),
            );
            let history = [(0, 17 * TOS), (1, 31 * TOS), (2, 43 * TOS), (3, 59 * TOS)];
            seed_history(&mut chain, &history);
            for (owner, amount) in history {
                assert_eq!(owed(&chain, &refund_owner(owner)), u128::from(amount));
            }
            assert!(tick_at_close(&mut chain, election, "boundary").next_set_installed);
            let frozen = frozen_by_owner(&chain, election);
            assert_eq!(frozen.contains_key(&refund_owner(0)), selected, "fixture selection");
            for (owner, old_credit) in history {
                let address = refund_owner(owner);
                let increment = owed(&chain, &address)
                    .checked_sub(u128::from(old_credit))
                    .expect("history must remain owed");
                assert_eq!(
                    increment + frozen.get(&address).copied().unwrap_or(0),
                    u128::from(stakes[usize::from(owner)] * TOS),
                    "boundary principal increment: stake={target}, selected={selected}, owner={owner}"
                );
            }
        }
    }
}

#[test]
fn real_pq_single_and_split_stakes_match_at_each_cap_boundary() {
    for target in [90_000, 100_000, 110_000] {
        for split in [false, true] {
            let (mut chain, _, election) = open_election("pq-cap-boundary", 400_000 * TOS);
            raise_to_post_quantum_version(&mut chain);
            let mut owners = Vec::new();
            for i in 0..4u8 {
                let sender = chain
                    .blockchain
                    .treasury(&format!("pq-boundary-{i}"), 400_000 * TOS)
                    .expect("funded owner");
                let key = PqValidator::new(0xc0 + i);
                let amounts =
                    if split { vec![target / 2, target - target / 2] } else { vec![target] };
                for (attempt, amount) in amounts.into_iter().enumerate() {
                    let result = pq_stake(
                        &mut chain,
                        &sender,
                        &key,
                        election,
                        attempt as u64 + 1,
                        (amount + 1) * TOS,
                    );
                    assert_eq!(reply(&result), (STAKE_ACCEPTED, 0), "real boundary inlet");
                }
                owners
                    .push(sender.address().address().get_bytestring(0).try_into().expect("owner"));
            }
            set_contract_parameter(
                &mut chain,
                17,
                stake_limits(10_000 * TOS, 100_000 * TOS, 40_000 * TOS, 0x10000),
            );
            assert!(tick_at_close(&mut chain, election, "real boundary").next_set_installed);
            let frozen = frozen_by_owner(&chain, election);
            for owner in owners {
                assert_eq!(
                    frozen.get(&owner).copied().unwrap_or(0) + owed(&chain, &owner),
                    u128::from(target * TOS),
                    "real PQ boundary conservation: target={target}, split={split}"
                );
            }
        }
    }
}

#[test]
#[ignore = "explicit participant resource profiling, not an acceptance shortcut"]
fn participant_cost_profile_uses_registration_count_not_seated_count() {
    for count in [21u16, 1024, 4097, 8192] {
        let (mut chain, _, election) = open_election("registration-profile", 400_000 * TOS);
        raise_to_post_quantum_version(&mut chain);
        raise_validator_ceiling(&mut chain, 21);
        install_synthetic_book(&mut chain, count, 11_000 * TOS);
        chain.blockchain.set_now(election - chain.elect_end_before);
        let result = chain
            .blockchain
            .tick_tock(&chain.elector, TransactionTickTock::Tick)
            .expect("profile tick");
        eprintln!(
            "registration-profile count={count} gas={} installed={}",
            tick_gas(&result),
            replies(&result).contains(&VALIDATOR_SET_INSTALLED)
        );
        result.expect_success();
    }
}

#[test]
fn the_participant_bound_covers_selection_retirement_cancellation_and_unfreeze() {
    for path in ["all-selected", "mostly-refunded", "retired", "failed"] {
        let (mut chain, _, election) = open_election(path, 400_000 * TOS);
        raise_to_post_quantum_version(&mut chain);
        install_synthetic_book_full(
            &mut chain,
            256,
            if path == "retired" { 64 } else { 256 },
            &|i, _| refund_owner(i),
            &|i| (11_000 + u64::from(i)) * TOS,
        );
        align_declared_total_with_the_synthetic_book(&mut chain);
        counts(&mut chain, if path == "all-selected" { 256 } else { 21 }, 1);
        if path == "retired" {
            admit_only_the_first_synthetic_profile(&mut chain);
        }
        if path == "failed" {
            counts(&mut chain, 257, 257);
        }
        chain.blockchain.set_now(election - chain.elect_end_before);
        let result = chain
            .blockchain
            .tick_tock(&chain.elector, TransactionTickTock::Tick)
            .expect("bounded selection tick");
        result.expect_success();
        let gas = tick_gas(&result);
        eprintln!(
            "participant-bound path={path} selection-gas={gas} replies={:?}",
            replies(&result)
        );
        assert!(gas < 50_000_000, "selection must retain gas headroom: {path}, {gas}");
        if path == "failed" {
            assert!(failed_record(&chain).0);
            chain.blockchain.set_now(election);
            let result = chain
                .blockchain
                .tick_tock(&chain.elector, TransactionTickTock::Tick)
                .expect("cancellation tick");
            result.expect_success();
            eprintln!("participant-bound cancellation-gas={}", tick_gas(&result));
            assert!(tick_gas(&result) < 50_000_000);
        } else if has_past_election(&chain, election) {
            let frozen = frozen_by_owner(&chain, election);
            for i in 0..256u16 {
                assert_eq!(
                    owed(&chain, &refund_owner(i))
                        + frozen.get(&refund_owner(i)).copied().unwrap_or(0),
                    u128::from((11_000 + u64::from(i)) * TOS),
                    "pre-release owner {i}: {path}"
                );
            }
            chain.blockchain.set_now(election + 10 * 365 * 24 * 3600);
            let mut max_gas = 0;
            for _ in 0..8 {
                if !has_past_election(&chain, election) {
                    break;
                }
                let result = chain
                    .blockchain
                    .tick_tock(&chain.elector, TransactionTickTock::Tick)
                    .expect("bounded unfreeze tick");
                result.expect_success();
                max_gas = max_gas.max(tick_gas(&result));
            }
            eprintln!("participant-bound path={path} unfreeze-max-gas={max_gas}");
            assert!(max_gas < 50_000_000);
            assert!(!has_past_election(&chain, election), "bounded book must release");
        } else {
            assert!(
                replies(&result).contains(&0xee764f6f),
                "absence of frozen principal requires an actual configuration refusal"
            );
        }
        for i in 0..256u16 {
            assert_eq!(
                owed(&chain, &refund_owner(i)),
                u128::from((11_000 + u64::from(i)) * TOS),
                "final principal owner {i}: {path}"
            );
        }
    }
}

#[test]
fn an_additional_identity_is_refused_at_the_participant_bound_before_state_changes() {
    let (mut chain, sender, election) = open_election("bounded-registration", 400_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    install_synthetic_book(&mut chain, 256, 11_000 * TOS);
    align_declared_total_with_the_synthetic_book(&mut chain);
    admit_sender_code(&mut chain, &sender);
    let before = chain.blockchain.get_account(&chain.elector).expect("elector").get_data();
    let result =
        pq_stake(&mut chain, &sender, &PqValidator::new(0xcd), election, 901, 12_000 * TOS);
    assert_eq!(reply(&result), (0xee6f454c, 16), "the 257th identity must be refused");
    assert_eq!(
        chain.blockchain.get_account(&chain.elector).expect("elector").get_data(),
        before,
        "a full book must not consume or replace somebody else's registration"
    );
}

#[test]
fn the_last_admitted_participant_can_top_up_without_occupying_another_slot() {
    let (mut chain, sender, election) = open_election("last-participant", 400_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let key = PqValidator::new(0xce);
    install_synthetic_book(&mut chain, 255, 11_000 * TOS);
    align_declared_total_with_the_synthetic_book(&mut chain);
    // Keep the synthetic profile admitted while adding the real funding wallet's code.
    let code = chain
        .blockchain
        .get_account(sender.address())
        .expect("wallet")
        .get_code()
        .expect("wallet code")
        .repr_hash();
    let mut codes = chain_block::HashmapE::with_bit_len(256);
    for hash in [synthetic_code(0), code] {
        codes
            .set(
                SliceData::load_builder(
                    BuilderData::with_raw(hash.as_slice().to_vec(), 256).expect("code"),
                )
                .expect("key"),
                &SliceData::default(),
            )
            .expect("admission");
    }
    let mut policy = BuilderData::new();
    dictionary(&mut policy, &codes);
    set_contract_parameter(&mut chain, 47, policy.into_cell().expect("policy"));
    let result = pq_stake(&mut chain, &sender, &key, election, 910, 12_000 * TOS);
    assert_eq!(reply(&result), (STAKE_ACCEPTED, 0), "the 256th identity must remain admissible");
    let (members, _) = pq_book(&chain);
    assert_eq!(members.len().expect("member count"), 256);
    let initial = pq_stake_of(&chain, &sender);
    let result = pq_stake(&mut chain, &sender, &key, election, 911, 12_000 * TOS);
    assert_eq!(
        reply(&result),
        (STAKE_ACCEPTED, 0),
        "an existing owner must still be able to top up"
    );
    assert_eq!(pq_stake_of(&chain, &sender), initial + u128::from(11_999 * TOS));
    assert_eq!(pq_book(&chain).0.len().expect("member count"), 256);
    let other = chain.blockchain.treasury("participant-overflow", 40_000 * TOS).expect("owner");
    let result = pq_stake(&mut chain, &other, &PqValidator::new(0xcf), election, 912, 12_000 * TOS);
    assert_eq!(reply(&result), (STAKE_RETURNED, 16));
    assert_eq!(pq_book(&chain).0.len().expect("member count"), 256);
}

#[test]
fn an_oversized_import_is_refused_before_a_tick_can_spend_its_gas_budget() {
    let (mut chain, _, election) = open_election("oversized-import", 400_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    install_synthetic_book(&mut chain, 4097, 11_000 * TOS);
    align_declared_total_with_the_synthetic_book(&mut chain);
    let data = chain.blockchain.get_account(&chain.elector).expect("elector").get_data();
    chain.blockchain.set_now(election - chain.elect_end_before);
    let result =
        chain.blockchain.tick_tock(&chain.elector, TransactionTickTock::Tick).expect("tick");
    result.expect_aborted().expect_exit_code(64);
    assert!(
        tick_gas(&result) < 1_000_000,
        "import refusal must traverse at most one bounded prefix"
    );
    assert_eq!(
        chain.blockchain.get_account(&chain.elector).expect("elector").get_data(),
        data,
        "a refused import must retain every owner's original claim for explicit migration"
    );
}

#[test]
fn a_refused_configuration_returns_each_original_once_even_after_late_confirmation() {
    let (mut chain, _, election) = open_election("configuration-refund", 400_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let mut owners = Vec::new();
    let mut shared_adnl = None;
    for i in 0..4u8 {
        let account =
            chain.blockchain.treasury(&format!("config-refund-{i}"), 40_000 * TOS).expect("owner");
        let mut key = PqValidator::new(0x70 + i);
        if i == 0 {
            shared_adnl = Some(key.adnl);
        }
        if i == 1 {
            key.adnl = shared_adnl.expect("duplicate transport identity");
        }
        let result =
            pq_stake(&mut chain, &account, &key, election, 20 + u64::from(i), 11_000 * TOS);
        assert_eq!(reply(&result), (STAKE_ACCEPTED, 0));
        let owner: [u8; 32] =
            account.address().address().get_bytestring(0).try_into().expect("owner");
        owners.push((owner, pq_stake_of(&chain, &account)));
    }
    chain.blockchain.set_now(election - chain.elect_end_before);
    let result =
        chain.blockchain.tick_tock(&chain.elector, TransactionTickTock::Tick).expect("tick");
    result.expect_success();
    assert!(replies(&result).contains(&VALIDATOR_SET_REFUSED), "must reach configuration refusal");
    assert!(!has_past_election(&chain, election));
    assert_eq!(active_election_id(&chain), 0);
    for (owner, placed) in &owners {
        assert_eq!(owed(&chain, owner), *placed);
    }
    for tag in [0xee764f6f, 0xee764f4b, 0xee764f6f] {
        let mut body = BuilderData::new();
        body.append_u32(tag).expect("configuration result");
        body.append_u64(u64::from(election)).expect("election id");
        let result = chain
            .blockchain
            .send_message(
                tos_sandbox::MessageBuilder::internal(&chain.config_contract, &chain.elector, TOS)
                    .body(body.into_cell().expect("reply"))
                    .build(),
            )
            .expect("late reply");
        result.expect_success();
    }
    for offset in [0, 1, 1000] {
        tick_at(&mut chain, election + offset, "after refusal");
    }
    assert!(!has_past_election(&chain, election));
    for (owner, placed) in owners {
        assert_eq!(owed(&chain, &owner), placed, "configuration refusal must not pay twice");
    }
}

#[test]
fn a_fine_is_partitioned_between_claimant_and_purse_once_with_real_transaction_fees() {
    let (mut chain, validators, election) = elect_install_and_rotate();
    let accused = validator_id_at(&chain, index_of(&chain, &validators[3]));
    let complainant =
        chain.blockchain.treasury("fine-conservation", 1_000 * TOS).expect("claimant");
    let result = chain
        .blockchain
        .send_message(complainant.build_message(
            &chain.elector,
            300 * TOS,
            true,
            Some(complaint_body(180, election, &accused)),
        ))
        .expect("complaint");
    assert!(replies(&result).contains(&COMPLAINT_ACCEPTED));
    let complaint = complaint_hashes(&chain, election)[0];
    let owner: [u8; 32] =
        complainant.address().address().get_bytestring(0).try_into().expect("owner");
    let mut key = BuilderData::new();
    key.append_u32(election).expect("election id");
    let mut past = past_elections(&chain)
        .get(SliceData::load_builder(key).expect("key"))
        .expect("lookup")
        .expect("election");
    past.get_next_u32().expect("unfreeze");
    past.get_next_u32().expect("hold");
    past.get_next_bits(256).expect("set");
    next_dictionary(&mut past, 256);
    next_coins(&mut past);
    next_coins(&mut past);
    let complaints = next_dictionary(&mut past, 256);
    let key =
        SliceData::load_builder(BuilderData::with_raw(complaint.to_vec(), 256).expect("hash"))
            .expect("key");
    let mut status = complaints.get(key).expect("lookup").expect("complaint");
    assert_eq!(status.get_next_int(8).expect("status tag"), 0x2d);
    let mut report =
        SliceData::load_cell(status.checked_drain_reference().expect("report")).expect("slice");
    assert_eq!(report.get_next_int(8).expect("complaint tag"), 0xbc);
    report.get_next_bits(256).expect("accused");
    report.checked_drain_reference().expect("description");
    report.get_next_u32().expect("created");
    report.get_next_int(8).expect("severity");
    assert_eq!(report.get_next_bits(256).expect("reward address"), owner);
    let paid = next_coins(&mut report);
    let fine = next_coins(&mut report);
    assert_eq!(fine, u128::from(500 * TOS));
    let expected_reward = (fine / 8).min(paid * 8);
    assert!(expected_reward > 0 && expected_reward < fine, "both destinations must be exercised");
    let frozen_before = past_totals(&chain, election).0;
    let purse_before = elector_purse_and_active_set(&chain).0;
    let credits_before = owed(&chain, &owner);
    let relay = chain.blockchain.treasury("fine-vote-relay", 100 * TOS).expect("relay");
    let mut decisive = false;
    for (round, voter) in validators.iter().take(3).enumerate() {
        let idx = index_of(&chain, voter);
        let signature = voter.sign(&complaint_vote_preimage(&chain, idx, election, &complaint));
        let before = balance_of(&chain, &chain.elector);
        let result = chain
            .blockchain
            .send_message(relay.build_message(
                &chain.elector,
                VOTE_VALUE,
                true,
                Some(complaint_vote_body(
                    200 + round as u64,
                    &signature,
                    idx,
                    election,
                    &complaint,
                )),
            ))
            .expect("vote");
        result.expect_success();
        decisive |= replies(&result).contains(&COMPLAINT_CARRIED);
        let mut fees = 0u128;
        let mut outgoing = 0u128;
        for transaction in result.transactions_for(&chain.elector) {
            fees += transaction.total_fees().coins.as_u128();
            transaction
                .iterate_out_msgs(|message| {
                    if let Some(header) = message.int_header() {
                        outgoing += header.value.coins.as_u128() + header.fwd_fee.as_u128();
                    }
                    Ok(true)
                })
                .expect("outgoing messages");
        }
        assert_eq!(
            before + u128::from(VOTE_VALUE),
            balance_of(&chain, &chain.elector) + fees + outgoing,
            "actual vote value must account for compute, action and forwarding fees"
        );
    }
    assert!(decisive);
    assert_eq!(past_totals(&chain, election).0, frozen_before - fine);
    assert_eq!(owed(&chain, &owner) - credits_before, expected_reward, "claimant fine share");
    assert_eq!(
        elector_purse_and_active_set(&chain).0 - purse_before,
        fine - expected_reward,
        "system fine share"
    );
    assert_eq!(frozen_stake(&chain, election, &accused), frozen_before / 4 - fine);
    let idx = index_of(&chain, &validators[0]);
    let signature = validators[0].sign(&complaint_vote_preimage(&chain, idx, election, &complaint));
    let result = chain
        .blockchain
        .send_message(relay.build_message(
            &chain.elector,
            VOTE_VALUE,
            true,
            Some(complaint_vote_body(210, &signature, idx, election, &complaint)),
        ))
        .expect("replay");
    result.expect_success();
    assert_eq!(past_totals(&chain, election).0, frozen_before - fine);
    assert_eq!(owed(&chain, &owner) - credits_before, expected_reward);
    assert_eq!(elector_purse_and_active_set(&chain).0 - purse_before, fine - expected_reward);
}

fn historical_elector_code() -> chain_block::Cell {
    static CODE: std::sync::OnceLock<chain_block::Cell> = std::sync::OnceLock::new();
    CODE.get_or_init(|| {
        let output = std::process::Command::new("git")
            .current_dir(repo_root())
            .args([
                "show",
                "40a0aa4c9a207ccc06bc2d3d0c9259d56b21100a:crypto/smartcont/elector-code.fc",
            ])
            .output()
            .expect("historical source");
        assert!(output.status.success(), "the exact classic source must be available");
        let source = String::from_utf8(output.stdout).expect("FunC source");
        let file =
            repo_root().join(".git/elector-security-audit-artifacts/completion/classic-elector.fc");
        std::fs::write(&file, source).expect("retained source");
        tos_sandbox::compile_func(&[repo_root().join("crypto/smartcont/stdlib.fc"), file])
            .expect("the genuine classic elector compiles")
    })
    .clone()
}

fn code_upgrade(
    chain: &mut Chain,
    code: chain_block::Cell,
    marker: bool,
) -> tos_sandbox::SendResult {
    let mut body = BuilderData::new();
    body.append_u32(0x4e436f64).expect("upgrade");
    body.append_u64(800).expect("query");
    body.checked_append_reference(code).expect("new code");
    if marker {
        body.append_bit_one().expect("installation hook");
    }
    chain
        .blockchain
        .send_message(
            tos_sandbox::MessageBuilder::internal(&chain.config_contract, &chain.elector, TOS)
                .body(body.into_cell().expect("upgrade body"))
                .build(),
        )
        .expect("configuration upgrade message")
}

#[test]
fn a_real_classic_book_and_creditor_survive_explicit_installation_refusal() {
    let (mut chain, _, election) = open_election("classic-principal", 40_000 * TOS);
    let current_code =
        chain.blockchain.get_account(&chain.elector).expect("elector").get_code().expect("code");
    let owner = refund_owner(17);
    let mut account = chain.blockchain.get_account(&chain.elector).expect("elector").clone();
    let mut root = SliceData::load_cell(account.get_data().expect("data")).expect("slice");
    let active = next_dictionary(&mut root, 32);
    let mut original = SliceData::load_cell(HashmapType::data(&active).expect("election").clone())
        .expect("election fields");
    let at = original.get_next_u32().expect("time");
    let close = original.get_next_u32().expect("close");
    let minimum = next_coins(&mut original);
    let mut members = chain_block::HashmapE::with_bit_len(256);
    let key = SliceData::load_builder(BuilderData::with_raw(vec![0x23; 32], 256).expect("key"))
        .expect("member key");
    let mut member = BuilderData::new();
    chain_block::Coins::new(11_000 * TOS).write_to(&mut member).expect("principal");
    member.append_u32(chain.blockchain.now()).expect("registered");
    member.append_u32(0x10000).expect("factor");
    member.append_raw(&owner, 256).expect("funding account");
    member.append_raw(&[0x24; 32], 256).expect("transport");
    members.set_builder(key, &member).expect("classic member");
    let mut legacy = BuilderData::new();
    legacy.append_u32(at).expect("time");
    legacy.append_u32(close).expect("close");
    chain_block::Coins::new(u64::try_from(minimum).expect("fixture minimum"))
        .write_to(&mut legacy)
        .expect("minimum");
    chain_block::Coins::new(11_000 * TOS).write_to(&mut legacy).expect("principal total");
    dictionary(&mut legacy, &members);
    legacy.append_bit_zero().expect("not failed");
    legacy.append_bit_zero().expect("not finished");
    let mut rebuilt = BuilderData::new();
    rebuilt.append_bit_one().expect("election");
    rebuilt.checked_append_reference(legacy.into_cell().expect("classic record")).expect("record");
    rebuilt.checked_append_references_and_data(&root).expect("other liabilities");
    account.set_data(rebuilt.into_cell().expect("storage"));
    account.set_code(historical_elector_code());
    chain.blockchain.set_account(chain.elector.clone(), account);
    seed_history(&mut chain, &[(17, 37 * TOS)]);
    let valid = chain
        .blockchain
        .run_get_method(&chain.elector, "participant_list", vec![])
        .expect("classic getter");
    assert_eq!(valid.exit_code, 0, "fixture must be valid for the genuine old reader");
    let old_data = chain.blockchain.get_account(&chain.elector).expect("elector").get_data();
    let old_code = chain.blockchain.get_account(&chain.elector).expect("elector").get_code();
    let result = code_upgrade(&mut chain, current_code.clone(), true);
    result.expect_aborted().expect_exit_code(66);
    assert_eq!(
        chain.blockchain.get_account(&chain.elector).expect("elector").get_data(),
        old_data,
        "failed installation must preserve classic members and existing creditor balances"
    );
    assert_eq!(chain.blockchain.get_account(&chain.elector).expect("elector").get_code(), old_code);
    assert_eq!(owed(&chain, &owner), u128::from(37 * TOS));
    // Even bypassing the installer never grants the new parser permission to erase this book.
    let mut account = chain.blockchain.get_account(&chain.elector).expect("elector").clone();
    account.set_code(current_code);
    chain.blockchain.set_account(chain.elector.clone(), account);
    let decoded = chain
        .blockchain
        .run_get_method(&chain.elector, "participant_list_extended", vec![])
        .expect("new reader");
    assert_eq!(decoded.exit_code, 65, "classic presence/flag layout must be refused explicitly");
    assert_eq!(active_election_id_for_classic_fixture(&chain), election);
    assert_eq!(chain.blockchain.get_account(&chain.elector).expect("elector").get_data(), old_data);
}

fn active_election_id_for_classic_fixture(chain: &Chain) -> u32 {
    let mut root = SliceData::load_cell(
        chain.blockchain.get_account(&chain.elector).expect("elector").get_data().expect("data"),
    )
    .expect("slice");
    let active = next_dictionary(&mut root, 32);
    SliceData::load_cell(HashmapType::data(&active).expect("election").clone())
        .expect("record")
        .get_next_u32()
        .expect("original election id")
}

#[test]
fn upgrades_and_rollbacks_require_a_debt_free_boundary_and_preserve_the_root() {
    let mut fresh = launch();
    let code =
        fresh.blockchain.get_account(&fresh.elector).expect("elector").get_code().expect("code");
    let data = fresh.blockchain.get_account(&fresh.elector).expect("elector").get_data();
    let ready = fresh
        .blockchain
        .run_get_method(&fresh.elector, "upgrade_ready", vec![])
        .expect("readiness");
    assert_eq!(ready.exit_code, 0);
    let result = code_upgrade(&mut fresh, historical_elector_code(), false);
    result.expect_success();
    assert_eq!(reply(&result).0, 0xce436f64);
    assert_eq!(fresh.blockchain.get_account(&fresh.elector).expect("elector").get_data(), data);
    let result = code_upgrade(&mut fresh, code.clone(), true);
    result.expect_success();
    assert_eq!(
        fresh.blockchain.get_account(&fresh.elector).expect("elector").get_code(),
        Some(code)
    );
    assert_eq!(fresh.blockchain.get_account(&fresh.elector).expect("elector").get_data(), data);
    for (outcome, phase) in [
        (Outcome::FailedSelection, "cached"),
        (Outcome::Seated, "frozen-only"),
        (Outcome::FailedSelection, "credits-only"),
        (Outcome::Empty, "open"),
    ] {
        let Scenario { mut chain, election, .. } = scenario(outcome);
        if phase == "frozen-only" {
            install_synthetic_book_owned(&mut chain, 4, 11_000 * TOS, 1, &|i, _| refund_owner(i));
            align_declared_total_with_the_synthetic_book(&mut chain);
        }
        if outcome != Outcome::Empty {
            tick_at_close(&mut chain, election, "pre-upgrade");
        }
        if phase == "frozen-only" {
            let mut account =
                chain.blockchain.get_account(&chain.elector).expect("elector").clone();
            let mut root = SliceData::load_cell(account.get_data().expect("data")).expect("slice");
            next_dictionary(&mut root, 32);
            let mut rebuilt = BuilderData::new();
            rebuilt.append_bit_zero().expect("no active book");
            rebuilt.checked_append_references_and_data(&root).expect("frozen liabilities");
            account.set_data(rebuilt.into_cell().expect("data"));
            chain.blockchain.set_account(chain.elector.clone(), account);
            assert_eq!(active_election_id(&chain), 0);
            assert!(has_past_election(&chain, election));
            let mut root = SliceData::load_cell(
                chain
                    .blockchain
                    .get_account(&chain.elector)
                    .expect("elector")
                    .get_data()
                    .expect("data"),
            )
            .expect("slice");
            next_dictionary(&mut root, 32);
            assert_eq!(
                next_dictionary(&mut root, 256).len().expect("credit count"),
                0,
                "frozen-only control must not be masked by another creditor gate"
            );
        }
        if phase == "credits-only" {
            tick_at(&mut chain, election, "cancelled");
            assert_eq!(active_election_id(&chain), 0);
            assert!(!has_past_election(&chain, election));
            assert!(owed(&chain, &refund_owner(0)) > 0);
        }
        let code = chain.blockchain.get_account(&chain.elector).expect("elector").get_code();
        let data = chain.blockchain.get_account(&chain.elector).expect("elector").get_data();
        let result = code_upgrade(&mut chain, historical_elector_code(), false);
        result.expect_success();
        assert_eq!(reply(&result).0, 0xffffffff, "live liabilities must refuse rollback: {phase}");
        assert_eq!(chain.blockchain.get_account(&chain.elector).expect("elector").get_code(), code);
        assert_eq!(chain.blockchain.get_account(&chain.elector).expect("elector").get_data(), data);
    }
}

#[test]
fn over_cap_principal_is_conserved_for_winners_losers_and_shared_owners() {
    let (mut chain, _, election) = open_election("principal-cap", 400_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    install_synthetic_book_full(&mut chain, 6, 2, &|i, _| refund_owner(i % 2), &|i| {
        (100_000 - u64::from(i) * 10_000) * TOS
    });
    counts(&mut chain, 2, 2);
    admit_only_the_first_synthetic_profile(&mut chain);
    set_contract_parameter(
        &mut chain,
        17,
        stake_limits(10_000 * TOS, 20_000 * TOS, 40_000 * TOS, 0x10000),
    );
    assert!(tick_at_close(&mut chain, election, "close").next_set_installed);
    let frozen = frozen_by_owner(&chain, election);
    assert_eq!(frozen.values().sum::<u128>(), 40_000 * u128::from(TOS));
    for owner in 0..2u16 {
        let original: u128 = (0..6u16)
            .filter(|i| i % 2 == owner)
            .map(|i| u128::from((100_000 - u64::from(i) * 10_000) * TOS))
            .sum();
        let address = refund_owner(owner);
        let frozen_amount = frozen.get(&address).copied().unwrap_or(0);
        assert_eq!(
            owed(&chain, &address) + frozen_amount,
            original,
            "owner principal not conserved across selected, losing and retired entries"
        );
    }
}

#[test]
fn real_pq_top_up_above_a_lowered_cap_returns_all_surplus() {
    let (mut chain, _, election) = open_election("signed-cap", 400_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let mut owners = Vec::new();
    for i in 0..4u8 {
        let sender = chain
            .blockchain
            .treasury(&format!("signed-cap-{i}"), 400_000 * TOS)
            .expect("funded sender");
        let key = PqValidator::new(0xc0 + i);
        for (query, value) in [(1, 110_001 * TOS), (2, 40_001 * TOS)] {
            let result = pq_stake(&mut chain, &sender, &key, election, query, value);
            assert_eq!(reply(&result), (STAKE_ACCEPTED, 0), "actual PQ stake accepted");
        }
        owners.push(sender.address().address().get_bytestring(0).try_into().expect("owner"));
    }
    set_contract_parameter(
        &mut chain,
        17,
        stake_limits(10_000 * TOS, 100_000 * TOS, 40_000 * TOS, 0x10000),
    );
    assert!(tick_at_close(&mut chain, election, "lowered cap").next_set_installed);
    let frozen = frozen_by_owner(&chain, election);
    for owner in owners {
        assert_eq!(frozen[&owner], 100_000 * u128::from(TOS));
        assert_eq!(owed(&chain, &owner), 50_000 * u128::from(TOS), "whole top-up surplus credited");
    }
}

#[test]
fn a_failed_selection_retries_after_each_decisive_configuration_change() {
    for parameter in [16, 17, 47] {
        let (mut chain, _, election) = open_election(&format!("retry-{parameter}"), 400_000 * TOS);
        raise_to_post_quantum_version(&mut chain);
        let members = if parameter == 16 { 3 } else { 4 };
        install_synthetic_book_over(&mut chain, members, 30_000 * TOS, 2);
        counts(&mut chain, 4, 4);
        if parameter == 17 {
            set_contract_parameter(
                &mut chain,
                17,
                stake_limits(10_000 * TOS, 10_000 * TOS, 80_000 * TOS, 0x10000),
            );
        } else if parameter == 47 {
            admit_only_the_first_synthetic_profile(&mut chain);
        }
        tick_at_close(&mut chain, election, "failed attempt");
        let (failed, finished, fingerprint) = failed_record(&chain);
        assert!(failed && !finished, "fixture must reach a real failed selection");
        assert!(fingerprint.is_some());
        match parameter {
            16 => counts(&mut chain, 4, 3),
            17 => set_contract_parameter(
                &mut chain,
                17,
                stake_limits(10_000 * TOS, 30_000 * TOS, 80_000 * TOS, 0x10000),
            ),
            47 => set_policy(&mut chain, &[synthetic_code(0), synthetic_code(1)]),
            _ => unreachable!(),
        }
        tick(&mut chain);
        assert!(
            observe(&chain, "retry").next_set_installed,
            "configuration {parameter} changed but a cached failure prevented selection"
        );
        let (failed, finished, cache) = failed_record(&chain);
        assert!(!failed && finished && cache.is_none(), "success clears failed-input cache");
    }
}

#[test]
fn identical_failed_inputs_skip_selection_and_cancel_without_double_credit() {
    let (mut chain, _, election) = open_election("cached-failure", 400_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    install_synthetic_book_owned(&mut chain, 21, 30_000 * TOS, 1, &|i, _| refund_owner(i));
    counts(&mut chain, 31, 22);
    chain.blockchain.set_now(election - chain.elect_end_before);
    let first_gas = tick_gas(&tick(&mut chain));
    let record = failed_record(&chain);
    assert!(record.0 && record.2.is_some(), "selection must have failed and cached its inputs");
    let cached_gas = tick_gas(&tick(&mut chain));
    assert_eq!(failed_record(&chain), record);
    assert!(
        cached_gas < first_gas / 2,
        "unchanged selection ran again: first={first_gas}, cached={cached_gas}"
    );
    eprintln!("failed-selection gas: first={first_gas}, cached={cached_gas}");
    for i in 0..21 {
        assert_eq!(owed(&chain, &refund_owner(i)), 0);
    }
    chain.blockchain.set_now(election);
    tick(&mut chain);
    assert_eq!(active_election_id(&chain), 0);
    for i in 0..21 {
        assert_eq!(owed(&chain, &refund_owner(i)), 30_000 * u128::from(TOS));
    }
    tick(&mut chain);
    for i in 0..21 {
        assert_eq!(owed(&chain, &refund_owner(i)), 30_000 * u128::from(TOS));
    }
}

#[test]
fn a_legacy_failed_record_without_fingerprint_gets_one_new_attempt() {
    let (mut chain, _, election) = open_election("legacy-failure", 400_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    install_synthetic_book(&mut chain, 3, 30_000 * TOS);
    counts(&mut chain, 4, 4);
    tick_at_close(&mut chain, election, "failed selection");
    assert!(failed_record(&chain).2.is_some());

    // Recreate the exact pre-cache wire: the same failed flag and three PQ books,
    // with no uint256 suffix. This changes neither stake nor configuration.
    let mut account = chain.blockchain.get_account(&chain.elector).expect("elector").clone();
    let mut root = SliceData::load_cell(account.get_data().expect("storage")).expect("slice");
    let election_dict = next_dictionary(&mut root, 32);
    let mut old = SliceData::load_cell(HashmapType::data(&election_dict).expect("open").clone())
        .expect("election slice");
    let prefix_bits = old.remaining_bits().checked_sub(256).expect("cached suffix");
    old.shrink_data(..prefix_bits);
    let mut old_cell = BuilderData::new();
    old_cell.checked_append_references_and_data(&old).expect("original PQ record");
    let mut replacement = BuilderData::new();
    replacement.append_bit_one().expect("open election");
    replacement
        .checked_append_reference(old_cell.into_cell().expect("legacy record"))
        .expect("election");
    replacement.checked_append_references_and_data(&root).expect("unchanged remaining state");
    account.set_data(replacement.into_cell().expect("storage"));
    chain.blockchain.set_account(chain.elector.clone(), account);
    assert_eq!(failed_record(&chain), (true, false, None));

    let first = tick_gas(&tick(&mut chain));
    assert!(failed_record(&chain).2.is_some(), "legacy failure re-evaluated and cached");
    let cached = tick_gas(&tick(&mut chain));
    assert!(cached < first, "second identical legacy retry must be skipped");
    counts(&mut chain, 4, 3);
    tick(&mut chain);
    assert!(observe(&chain, "legacy retry").next_set_installed);
}

mod relay;
