//! Selection accounting and configuration-sensitive retries, on the real executor.

use super::*;
use chain_block::{BuilderData, HashmapType, IBitstring, SliceData};

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
