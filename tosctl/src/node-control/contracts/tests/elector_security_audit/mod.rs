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

/// The open election's `failed` and `finished` flags, read from storage, with the record
/// required to be exactly the shape the contract writes.
fn failed_record(chain: &Chain) -> (bool, bool) {
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
    next_dictionary(&mut fields, 256);
    let failed = fields.get_next_bit().expect("failed");
    let finished = fields.get_next_bit().expect("finished");
    assert_eq!((fields.remaining_bits(), fields.remaining_references()), (0, 0));
    (failed, finished)
}

fn dictionary(builder: &mut BuilderData, value: &chain_block::HashmapE) {
    if let Some(root) = HashmapType::data(value) {
        builder.append_bit_one().expect("dictionary present");
        builder.checked_append_reference(root.clone()).expect("dictionary root");
    } else {
        builder.append_bit_zero().expect("empty dictionary");
    }
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
            require_post_quantum_version(&chain);
            let stakes = if selected {
                [target, 80_000, 70_000, 60_000]
            } else {
                [target, 140_000, 130_000, 80_000]
            };
            install_synthetic_book_full(&mut chain, 4, &refund_owner, &|i| {
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
            require_post_quantum_version(&chain);
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
        require_post_quantum_version(&chain);
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

/// Registration count bounds every walk over the book: selection, the refund of members
/// not seated, the refund of a refused set, and the release of the frozen stakes. Each is
/// driven at the 256-member bound and has to keep gas headroom and every member's
/// principal. A selection that fails seats nobody and moves no money.
#[test]
fn the_participant_bound_covers_selection_refusal_failure_and_unfreeze() {
    for path in ["all-selected", "mostly-refunded", "failed"] {
        let (mut chain, _, election) = open_election(path, 400_000 * TOS);
        require_post_quantum_version(&chain);
        install_synthetic_book_full(&mut chain, 256, &refund_owner, &|i| {
            (11_000 + u64::from(i)) * TOS
        });
        match path {
            "all-selected" => counts(&mut chain, 256, 1),
            "mostly-refunded" => counts(&mut chain, 21, 1),
            _ => counts(&mut chain, 257, 257),
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
            assert_eq!(failed_record(&chain), (true, false), "the selection did not fail");
            let later = chain
                .blockchain
                .tick_tock(&chain.elector, TransactionTickTock::Tick)
                .expect("a later tick");
            later.expect_success();
            assert!(tick_gas(&later) < 50_000_000);
            for i in 0..256u16 {
                assert_eq!(owed(&chain, &refund_owner(i)), 0, "a failed selection paid owner {i}");
            }
            continue;
        }
        if has_past_election(&chain, election) {
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
    require_post_quantum_version(&chain);
    install_synthetic_book(&mut chain, 256, 11_000 * TOS);
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
    require_post_quantum_version(&chain);
    let key = PqValidator::new(0xce);
    install_synthetic_book(&mut chain, 255, 11_000 * TOS);
    let result = pq_stake(&mut chain, &sender, &key, election, 910, 12_000 * TOS);
    assert_eq!(reply(&result), (STAKE_ACCEPTED, 0), "the 256th identity must remain admissible");
    assert_eq!(pq_book(&chain).len().expect("member count"), 256);
    let initial = pq_stake_of(&chain, &sender);
    let result = pq_stake(&mut chain, &sender, &key, election, 911, 12_000 * TOS);
    assert_eq!(
        reply(&result),
        (STAKE_ACCEPTED, 0),
        "an existing member must still be able to top up"
    );
    assert_eq!(pq_stake_of(&chain, &sender), initial + u128::from(11_999 * TOS));
    assert_eq!(pq_book(&chain).len().expect("member count"), 256);
    let other = chain.blockchain.treasury("participant-overflow", 40_000 * TOS).expect("a wallet");
    let result = pq_stake(&mut chain, &other, &PqValidator::new(0xcf), election, 912, 12_000 * TOS);
    assert_eq!(reply(&result), (STAKE_RETURNED, 16));
    assert_eq!(pq_book(&chain).len().expect("member count"), 256);
}

#[test]
fn a_candidate_restating_anothers_address_is_refused_and_late_installed_replies_pay_nobody() {
    // A duplicate transport address no longer reaches the configuration: the elector
    // refuses the restating candidate at registration (reason 17) and seats the rest. The
    // configuration's own refusal of such a set stays as a backstop. The late duplicate
    // installation replies below must move no money.
    let (mut chain, _, election) = open_election("configuration-refund", 400_000 * TOS);
    require_post_quantum_version(&chain);
    let mut owners = Vec::new();
    let mut shared_adnl = None;
    for i in 0..5u8 {
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
        if i == 1 {
            assert_eq!(reply(&result), (STAKE_RETURNED, 17), "the duplicate address was admitted");
            assert_eq!(pq_member_key_id(&chain, &account), None, "a refused stake was recorded");
            continue;
        }
        assert_eq!(reply(&result), (STAKE_ACCEPTED, 0));
        let owner: [u8; 32] =
            account.address().address().get_bytestring(0).try_into().expect("owner");
        owners.push((owner, pq_stake_of(&chain, &account)));
    }
    chain.blockchain.set_now(election - chain.elect_end_before);
    let result =
        chain.blockchain.tick_tock(&chain.elector, TransactionTickTock::Tick).expect("tick");
    result.expect_success();
    let tags = replies(&result);
    assert!(tags.contains(&VALIDATOR_SET_INSTALLED), "the set was not installed: {tags:02x?}");
    assert!(!tags.contains(&VALIDATOR_SET_REFUSED), "the set was refused: {tags:02x?}");
    for (owner, _) in &owners {
        assert_eq!(owed(&chain, owner), 0, "a seated stake was credited back");
    }
    // Late duplicates of the installation result: nothing is paid.
    for tag in [0xee764f4b, 0xee764f4b] {
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
        for (owner, _) in &owners {
            assert_eq!(owed(&chain, owner), 0, "a late installation reply paid a seated stake");
        }
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

/// Over-cap principal is conserved for the members seated and the members left out: a
/// seated member's stake above the cap is credited at once, and a member left out is
/// credited all of it.
#[test]
fn over_cap_principal_is_conserved_for_winners_and_losers() {
    let (mut chain, _, election) = open_election("principal-cap", 400_000 * TOS);
    require_post_quantum_version(&chain);
    let stake_of = |i: u16| (100_000 - u64::from(i) * 10_000) * TOS;
    install_synthetic_book_full(&mut chain, 6, &refund_owner, &stake_of);
    counts(&mut chain, 2, 2);
    set_contract_parameter(
        &mut chain,
        17,
        stake_limits(10_000 * TOS, 20_000 * TOS, 40_000 * TOS, 0x10000),
    );
    assert!(tick_at_close(&mut chain, election, "close").next_set_installed);
    let frozen = frozen_by_owner(&chain, election);
    assert_eq!(frozen.values().sum::<u128>(), 40_000 * u128::from(TOS));
    assert_eq!(frozen.len(), 2, "two members are seated");
    for i in 0..6u16 {
        let address = refund_owner(i);
        let frozen_amount = frozen.get(&address).copied().unwrap_or(0);
        assert_eq!(
            owed(&chain, &address) + frozen_amount,
            u128::from(stake_of(i)),
            "member {i}'s principal not conserved across selected and losing entries"
        );
    }
}

#[test]
fn real_pq_top_up_above_a_lowered_cap_returns_all_surplus() {
    let (mut chain, _, election) = open_election("signed-cap", 400_000 * TOS);
    require_post_quantum_version(&chain);
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
