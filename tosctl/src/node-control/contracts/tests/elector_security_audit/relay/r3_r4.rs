//! Native counterexamples for late owner receipts and recovery-confirmation upgrades.
//! These tests require the repository's real FunC/Fift and PQ transaction executor.
use super::*;

fn pay_ready(fixture: &mut Fixture, kick: Message, expected_state: u8) {
    let (tx, out) = step(&mut fixture.chain, kick);
    successful(&tx, "recorded payment");
    let payment = only_to(out, &fixture.pool);
    let (tx, out) = step(&mut fixture.chain, payment);
    successful(&tx, "bound pool settlement");
    assert_eq!(fixture.pool_state(), expected_state);
    let ack = only_to(out, &fixture.validator.address);
    let (tx, _) = step(&mut fixture.chain, ack);
    successful(&tx, "relay cleanup");
    assert!(fixture.pending().is_none());
}

fn open_later_election(fixture: &mut Fixture) -> u32 {
    let until =
        fixture.chain.blockchain.config_params().validator_set().expect("set").utime_until();
    let after_now = fixture.chain.blockchain.now().checked_add(1).expect("time");
    let opens = until.checked_sub(fixture.chain.elect_begin_before).expect("election window");
    fixture.chain.blockchain.set_now(opens.max(after_now));
    tick(&mut fixture.chain);
    let at = u32::try_from(active_election_id(&fixture.chain)).expect("election id");
    assert_ne!(at, 0, "an actual open election is required");
    at
}

#[test]
fn late_root_recovery_is_not_paid_to_a_different_pool() {
    for ready in [false, true] {
        for refused in [false, true] {
            // The root credit comes from a real served and unfrozen round, not
            // from a forged recovery callback or a manually credited balance.
            let (mut fixture, mut roots) = served_and_unfrozen_pool("late-root-recovery");
            fixture.validator = roots.remove(0);
            fixture.pool = deploy_multi_nominator(
                &mut fixture.chain,
                fixture.operator.address(),
                &fixture.validator.address,
            );
            fixture.nominator = None;
            let at = open_later_election(&mut fixture);
            let owner: [u8; 32] = fixture
                .validator
                .address
                .address()
                .get_bytestring(0)
                .try_into()
                .expect("root stake owner");
            let credit = owed(&fixture.chain, &owner);
            assert!(credit >= u128::from(11_001 * TOS), "root must actually own the mature credit");

            let root_order = root_send(
                &fixture,
                &fixture.chain.elector,
                contracts::nominator::recover_stake(44).expect("legacy recovery body"),
            );
            let (tx, out) = step(&mut fixture.chain, root_order);
            successful(&tx, "root emits recovery before the pool relay");
            let root_request = only_to(out, &fixture.chain.elector);
            let capital = balance_of(&fixture.chain, &fixture.validator.address);

            let election = at.checked_add(u32::from(refused)).expect("requested election");
            let stake = begin(&mut fixture, 1, election);
            let mut saved_stake = Some(stake);
            let mut saved_kick = None;
            if ready {
                let (tx, out) = step(&mut fixture.chain, saved_stake.take().expect("stake"));
                successful(&tx, "pool elector response");
                let receipt = only_to(out, &fixture.validator.address);
                let (tx, out) = step(&mut fixture.chain, receipt);
                successful(&tx, "READY before unrelated recovery");
                saved_kick = Some(only_to(out, &fixture.validator.address));
            }

            let (tx, out) = step(&mut fixture.chain, root_request);
            successful(&tx, "actual root-owned credit payment");
            let root_payment = only_to(out, &fixture.validator.address);
            assert_eq!(op(&root_payment), 0xf96f7324);
            let unrelated = value(&root_payment);
            assert!(unrelated >= credit);
            let (tx, _) = step(&mut fixture.chain, root_payment);
            successful(&tx, "accept late owner credit");
            assert_eq!(owed(&fixture.chain, &owner), 0);

            let expected_state = if refused { 0 } else { 2 };
            if let Some(kick) = saved_kick {
                pay_ready(&mut fixture, kick, expected_state);
            } else {
                let (tx, out) = step(&mut fixture.chain, saved_stake.expect("WAIT stake"));
                successful(&tx, "pool elector response after owner recovery");
                let receipt = only_to(out, &fixture.validator.address);
                finish_reply(&mut fixture, receipt, expected_state);
            }
            assert_eq!(
                balance_of(&fixture.chain, &fixture.validator.address),
                capital.checked_add(unrelated).expect("protected capital"),
                "late root recovery must remain with its owner, not the relay beneficiary"
            );
        }
    }
}

#[test]
fn controller_funding_in_wait_and_ready_is_not_relay_change() {
    for ready in [false, true] {
        let mut fixture = Fixture::new("late-controller-funding");
        let capital = balance_of(&fixture.chain, &fixture.validator.address);
        let at = fixture.election;
        let stake = begin(&mut fixture, 1, at);
        let mut saved_stake = Some(stake);
        let mut saved_kick = None;
        if ready {
            let (tx, out) = step(&mut fixture.chain, saved_stake.take().expect("stake"));
            successful(&tx, "elector acceptance");
            let receipt = only_to(out, &fixture.validator.address);
            let (tx, out) = step(&mut fixture.chain, receipt);
            successful(&tx, "READY before funding");
            saved_kick = Some(only_to(out, &fixture.validator.address));
        }
        let funding =
            fixture.operator.build_message(&fixture.validator.address, 500 * TOS, false, None);
        let (tx, out) = step(&mut fixture.chain, funding);
        successful(&tx, "plain controller funding");
        assert!(out.is_empty());
        if let Some(kick) = saved_kick {
            pay_ready(&mut fixture, kick, 2);
        } else {
            let (tx, out) = step(&mut fixture.chain, saved_stake.expect("WAIT stake"));
            successful(&tx, "elector acceptance after funding");
            let receipt = only_to(out, &fixture.validator.address);
            finish_reply(&mut fixture, receipt, 2);
        }
        assert_eq!(
            balance_of(&fixture.chain, &fixture.validator.address),
            capital.checked_add(u128::from(500 * TOS)).expect("capital plus funding"),
            "plain funding must not become the current pool's refund"
        );
    }
}

fn upgrade_message(fixture: &Fixture, code: chain_block::Cell, marker: bool) -> Message {
    let mut body = BuilderData::new();
    body.append_u32(0x4e436f64).expect("upgrade operation");
    body.append_u64(0x7234).expect("upgrade query");
    body.checked_append_reference(code).expect("target code");
    if marker {
        body.append_bit_one().expect("installation hook marker");
    }
    MessageBuilder::internal(&fixture.chain.config_contract, &fixture.chain.elector, 20 * TOS)
        .body(body.into_cell().expect("upgrade body"))
        .build()
}

fn isolate_drained_upgrade_boundary(fixture: &mut Fixture) {
    // This is a synthetic *upgrade precondition*, not a live-fund migration or
    // evidence that deleting other creditors would be safe. Retain the actual
    // paid-recovery book produced by the preceding native message sequence.
    let mut account =
        fixture.chain.blockchain.get_account(&fixture.chain.elector).expect("elector").clone();
    let mut fields = SliceData::load_cell(account.get_data().expect("data")).expect("root");
    next_dictionary(&mut fields, 32);
    next_dictionary(&mut fields, 256);
    next_dictionary(&mut fields, 32);
    let purse = next_coins(&mut fields);
    fields.get_next_u32().expect("active id");
    fields.get_next_bits(256).expect("active hash");
    let mut root = BuilderData::new();
    for _ in 0..3 {
        root.append_bit_zero().expect("isolated empty book");
    }
    Coins::new(u64::try_from(purse).expect("fixture purse")).write_to(&mut root).expect("purse");
    root.append_u32(0).expect("no active id");
    root.append_raw(&[0; 32], 256).expect("no active hash");
    root.checked_append_references_and_data(&fields).expect("original recovery metadata");
    account.set_data(root.into_cell().expect("drained fixture root"));
    fixture.chain.blockchain.set_account(fixture.chain.elector.clone(), account);
}

fn needs_recovery_confirmation(fixture: &Fixture) -> bool {
    let mut root = SliceData::load_cell(
        fixture
            .chain
            .blockchain
            .get_account(&fixture.pool)
            .expect("pool")
            .get_data()
            .expect("pool data"),
    )
    .expect("root");
    let mut config = SliceData::load_cell(root.checked_drain_reference().expect("configuration"))
        .expect("configuration slice");
    let mut protocol = SliceData::load_cell(config.checked_drain_reference().expect("protocol"))
        .expect("protocol slice");
    let last = SliceData::load_cell(protocol.checked_drain_reference().expect("last result"))
        .expect("last result slice");
    last.remaining_references() != 0
}

#[test]
fn same_code_upgrade_preserves_lost_confirmation_repair() {
    let (mut fixture, _) = served_and_unfrozen_pool("lost-confirmation-upgrade");
    let command = pool_command(&fixture, 0x47657424);
    let (tx, out) = step(&mut fixture.chain, command);
    successful(&tx, "pool recovery request");
    let request = only_to(out, &fixture.chain.elector);
    let (tx, out) = step(&mut fixture.chain, request);
    successful(&tx, "elector recovery payment");
    let payment = only_to(out, &fixture.pool);
    let (tx, out) = step(&mut fixture.chain, payment);
    successful(&tx, "pool recovery accounting");
    let ack = only_to(out, &fixture.chain.elector);
    let (tx, out) = step(&mut fixture.chain, ack);
    successful(&tx, "elector clears outstanding amount");
    let lost_confirmation = only_to(out, &fixture.pool);
    assert_eq!(op(&lost_confirmation), 0x47656133);
    // Do not deliver the confirmation. The pool still needs the tombstone.
    assert!(needs_recovery_confirmation(&fixture));
    isolate_drained_upgrade_boundary(&mut fixture);
    let account = fixture.chain.blockchain.get_account(&fixture.chain.elector).expect("elector");
    let before = account.get_data().expect("data");
    let code = account.get_code().expect("code");
    let message = upgrade_message(&fixture, code.clone(), true);
    let (tx, _) = step(&mut fixture.chain, message);
    successful(&tx, "compatible same-code upgrade");
    assert_eq!(
        fixture
            .chain
            .blockchain
            .get_account(&fixture.chain.elector)
            .expect("elector")
            .get_data()
            .expect("data"),
        before,
        "same-code upgrade must retain the recovery confirmation tombstone"
    );
    let command = pool_command(&fixture, 8);
    let (tx, out) = step(&mut fixture.chain, command);
    successful(&tx, "public repair after upgrade");
    let ack = only_to(out, &fixture.chain.elector);
    let (tx, out) = step(&mut fixture.chain, ack);
    successful(&tx, "repeated ACK still has an authoritative answer");
    let confirmation = only_to(out, &fixture.pool);
    assert_eq!(op(&confirmation), 0x47656133);
    let mut confirmation_body = confirmation.body().expect("confirmation body").clone();
    confirmation_body.get_next_u32().expect("confirmation operation");
    let recovery_query = confirmation_body.get_next_u64().expect("recovery query");
    let (tx, _) = step(&mut fixture.chain, confirmation);
    successful(&tx, "pool retires the repaired confirmation");
    assert!(
        !needs_recovery_confirmation(&fixture),
        "ordinary recovery must no longer enter old ACK repair"
    );
    let owner: [u8; 32] = fixture.pool.address().get_bytestring(0).try_into().expect("owner");
    let credit = owed(&fixture.chain, &owner);
    let elector_data = fixture
        .chain
        .blockchain
        .get_account(&fixture.chain.elector)
        .expect("elector")
        .get_data()
        .expect("elector data");
    for _ in 0..2 {
        let repeated =
            recover_message(&fixture.pool, &fixture.chain.elector, 0x47656132, recovery_query);
        let supplied = value(&repeated);
        let (tx, out) = step(&mut fixture.chain, repeated);
        successful(&tx, "duplicate ACK after compatible upgrade");
        let reply = only_to(out, &fixture.pool);
        assert_eq!(op(&reply), 0x47656133);
        assert!(value(&reply) <= supplied, "confirmation cannot repay old principal");
        assert_eq!(owed(&fixture.chain, &owner), credit);
        assert_eq!(
            fixture
                .chain
                .blockchain
                .get_account(&fixture.chain.elector)
                .expect("elector")
                .get_data()
                .expect("elector data"),
            elector_data,
            "repeated confirmation must leave the durable tombstone unchanged"
        );
        let (tx, _) = step(&mut fixture.chain, reply);
        successful(&tx, "duplicate confirmation after pool cleanup");
        assert!(!needs_recovery_confirmation(&fixture));
    }
}

#[test]
fn a_nonempty_recovery_book_requires_the_target_schema() {
    let mut fixture = Fixture::new("upgrade-recovery-schema");
    let owner = fixture.operator.address().clone();
    credit_fixture(&mut fixture.chain, &owner, 50 * TOS, true);
    let request = recover_message(&owner, &fixture.chain.elector, 0x47657432, DOMAIN | 1);
    let (tx, out) = step(&mut fixture.chain, request);
    successful(&tx, "real recovery before upgrade");
    let payment = only_to(out, &owner);
    let (tx, _) = step(&mut fixture.chain, payment);
    successful(&tx, "owner receives recovery");
    let ack = recover_message(&owner, &fixture.chain.elector, 0x47656132, DOMAIN | 1);
    let (tx, _) = step(&mut fixture.chain, ack);
    successful(&tx, "record acknowledged tombstone");
    let current = fixture.chain.blockchain.get_account(&fixture.chain.elector).expect("elector");
    let code = current.get_code().expect("code");
    let data = current.get_data().expect("data");
    let temp = tempfile::tempdir().expect("target fixture");
    let source = temp.path().join("without-recovery-schema.fc");
    std::fs::write(&source,
        "() recv_internal(int value, cell msg, slice body) impure { return (); }\n\
         () after_code_upgrade(slice addr, slice body, int query) impure method_id(1666) { return (); }\n"
    ).expect("target source");
    let unsupported = tos_sandbox::compile_func_with_stdlib(&[source])
        .expect("the incompatible target must actually compile");
    let source = temp.path().join("wrong-recovery-schema.fc");
    std::fs::write(&source,
        "() recv_internal(int value, cell msg, slice body) impure { return (); }\n\
         () after_code_upgrade(slice addr, slice body, int query) impure method_id(1666) { return (); }\n\
         int recovery_upgrade_schema() impure method_id(1667) { return 0; }\n"
    ).expect("wrong-schema target source");
    let wrong_schema =
        tos_sandbox::compile_func_with_stdlib(&[source]).expect("wrong-schema target must compile");
    for (target, marker) in
        [(unsupported.clone(), false), (unsupported, true), (wrong_schema, true)]
    {
        let message = upgrade_message(&fixture, target, marker);
        let (tx, _) = step(&mut fixture.chain, message);
        assert!(
            tx.read_description().expect("description").is_aborted(),
            "missing or wrong recovery schema must refuse installation"
        );
        let current =
            fixture.chain.blockchain.get_account(&fixture.chain.elector).expect("elector");
        assert_eq!(current.get_code().expect("code"), code);
        assert_eq!(
            current.get_data().expect("data"),
            data,
            "refused cutover must preserve recovery evidence"
        );
    }
}
