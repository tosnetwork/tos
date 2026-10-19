/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Gates 7, 18 and 26: a wallet restored from a mnemonic alone, against the
//! real chain.
//!
//! The wallet crate's own tests show the derivations agree with themselves.
//! What they cannot show is that the notes a restored wallet finds are the
//! notes the contract actually minted -- and that is the whole claim. So here
//! the payloads are built by a wallet, the deposits are real messages, the
//! contract computes the note bodies, and then a *second* wallet built from
//! nothing but the same seed is handed the chain's outputs and asked what it
//! owns.
//!
//! The recovering wallet is deliberately a separate value with no state passed
//! to it. If anything it needed were being carried across rather than
//! recomputed, it would find nothing.

mod support;

use std::collections::BTreeSet;

use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::{notes, wire};
use shielded_pool_circuit_crosscheck::pool::{dec, Pool, DENOMINATION};
use shielded_pool_circuit_crosscheck::wire::byte_chain;
use shielded_pool_wallet::delivery::{self, Kind, Plaintext};
use shielded_pool_wallet::import::ChainSlot;
use shielded_pool_wallet::keys::PoolInstance;
use shielded_pool_wallet::scan::{self, ObservedOutput};

const TOS: u64 = 1_000_000_000;
const COMPUTE_FEE: u64 = 3 * TOS;
/// The mnemonic's seed. The mnemonic algorithm itself is the existing TOS one
/// and is not part of this work package; section 2 starts from its 32 bytes.
const SEED: [u8; 32] = [0x7c; 32];

/// One deposit made by a wallet: it chooses an index, builds the payload it
/// will later have to recognise, and lets the contract mint the note.
struct Deposited {
    output: ObservedOutput,
    note_key_index: u64,
    amount: u128,
}

/// A deposit always mints a note for the amount it admitted, so a deposit is
/// always an ordinary output. Dummies exist only as transact outputs, where
/// the circuit allows an amount of zero; that is covered by the transfer test
/// beside this one.
fn deposit(pool: &mut Pool, wallet: &PoolInstance, index: u64) -> Deposited {
    let amount = u128::from(DENOMINATION);
    let plaintext = Plaintext {
        slot: 0,
        kind: Kind::Ordinary,
        amount,
        note_secret: Fr::from(0xbeef_0000u64 + index),
        owner_nf_key_hash: wallet.owner_nf_key_hash(index).expect("an owner hash"),
        note_key_index: index,
        pq_auth_key_hash: wallet.pq_auth_key_hash(index).expect("a key hash"),
    };
    let sealed = delivery::seal(
        &wallet.mlkem_encapsulation_key().expect("a key"),
        wallet.execution_domain(),
        &plaintext,
    )
    .expect("seal the payload");
    assert_eq!(sealed.len(), 1233, "a payload is not the frozen length");

    // A deposit is the contract minting a note from an owner commitment and
    // the amount it actually admitted. The wallet supplies the commitment; it
    // does not supply the note.
    let owner = notes::owner_commitment(
        plaintext.owner_nf_key_hash,
        plaintext.pq_auth_key_hash,
        plaintext.note_secret,
    );
    let deposited = DENOMINATION;
    pool.send(
        deposited + COMPUTE_FEE,
        Pool::deposit_body(deposited, owner, byte_chain(&sealed).expect("payload"))
            .expect("deposit body"),
    )
    .expect("deposit")
    .expect_success();

    let output_data_hash = wire::output_data_hash(&sealed);
    let note_body =
        notes::note_body_commitment(owner, Fr::from(u128::from(deposited)), output_data_hash);
    Deposited {
        output: ObservedOutput {
            slot: 0,
            output_data: sealed,
            chain: ChainSlot { output_data_hash, note_body, recovered: None },
        },
        note_key_index: index,
        amount,
    }
}

/// Gate 18: from the mnemonic and the chain, and nothing else.
#[test]
fn a_wallet_restored_from_the_mnemonic_finds_what_the_contract_minted() {
    let frontier = shielded_pool_circuit::tree::Frontier::new();
    let nullifiers = shielded_pool_circuit::imt::State::genesis();
    let mut pool = Pool::deploy().expect("deploy the pool");
    let domain = wire::execution_domain(
        shielded_pool_circuit_crosscheck::wire::WireProbe::deploy()
            .expect("the wire probe")
            .domain_inputs()
            .expect("the domain inputs")
            .0,
        &pool.account().expect("the pool's account"),
    );

    // The wallet that spends, which chooses indices as it goes.
    let spender = PoolInstance::new(&SEED, domain);
    let mut deposits = Vec::new();
    // Deliberately not consecutive: a restored wallet must find the gaps as
    // well as the notes, or it would reissue index 2 and put two notes under
    // one one-time key.
    for index in [0u64, 1, 4] {
        deposits.push(deposit(&mut pool, &spender, index));
    }

    assert_eq!(
        pool.get("commitment_next_index").expect("next index"),
        "3",
        "the contract did not mint three notes"
    );

    // Now the restored wallet. It is built from the seed and the domain and
    // is handed the chain's outputs; nothing else crosses this line.
    let restored = PoolInstance::new(&SEED, domain);
    let outputs: Vec<ObservedOutput> =
        deposits.iter().map(|deposited| deposited.output.clone()).collect();
    let recovered = scan::recover(&restored, &outputs).expect("recover");

    assert_eq!(recovered.notes.len(), 3, "the restored wallet did not find every note");
    assert_eq!(
        recovered.balance(),
        3 * u128::from(DENOMINATION),
        "a note was found but not counted"
    );
    assert_eq!(
        scan::used_indices(&recovered).into_iter().collect::<Vec<_>>(),
        vec![0, 1, 4],
        "the restored wallet did not find every used index"
    );
    assert!(recovered.diagnostics.is_empty(), "something this wallet sent was refused");

    // Gate 7: the next index is past every index that was used, gaps and all.
    assert_eq!(recovered.next_note_key_index, 5, "an index already in use would be reissued");
    for index in [0u64, 1, 4] {
        assert!(!recovered.may_issue(index), "index {index} would be issued again");
    }
    assert!(recovered.may_issue(8), "the wallet cannot issue any index at all");

    // And the keys it derives for the notes it found are the keys those notes
    // are locked to -- which is what makes them spendable rather than merely
    // visible.
    for deposited in &deposits {
        let found = recovered
            .notes
            .iter()
            .find(|note| note.note_key_index == deposited.note_key_index)
            .expect("a recovered note");
        assert_eq!(found.amount, deposited.amount);
        assert_eq!(
            found.note_body, deposited.output.chain.note_body,
            "the recovered note is not the note the contract published"
        );
    }
}

/// A payload addressed to somebody else is not this wallet's business, and
/// leaves no trace: it does not open, so it is not even a diagnostic.
/// A bounced withdrawal comes back as money the restored wallet can spend.
///
/// The template a withdrawal signs carries no amount -- what a bounce returns
/// depends on forward fees no prover knows in advance -- so the contract mints
/// the note for `msg_value - recovery_charge` when the payout comes home. A
/// wallet that can only ever import the template imports nothing, and a
/// refused withdrawal then strands the sender's money from the sender's point
/// of view. The person who causes that is the recipient, not the sender, which
/// is why this is treated as an availability blocker and not a convenience.
///
/// Everything below crosses the line from the seed and the chain. No wallet
/// database, no kept payload, no device.
#[test]
fn a_bounced_recovery_note_is_spendable_after_a_restore_from_the_mnemonic() {
    let domain = wire::execution_domain(
        shielded_pool_circuit_crosscheck::wire::WireProbe::deploy()
            .expect("the wire probe")
            .domain_inputs()
            .expect("the domain inputs")
            .0,
        &Pool::deploy().expect("deploy the pool").account().expect("the pool's account"),
    );
    let wallet = PoolInstance::new(&SEED, domain);
    let index = 3u64;

    // The recovery payload a withdrawal seals for itself, before it is known
    // whether it will be needed or what it will be worth.
    let plaintext = Plaintext {
        slot: 2,
        kind: Kind::Recovery,
        amount: 0,
        note_secret: Fr::from(0x5eed_0003u64),
        owner_nf_key_hash: wallet.owner_nf_key_hash(index).expect("an owner hash"),
        note_key_index: index,
        pq_auth_key_hash: wallet.pq_auth_key_hash(index).expect("a key hash"),
    };
    let sealed = delivery::seal(
        &wallet.mlkem_encapsulation_key().expect("a key"),
        wallet.execution_domain(),
        &plaintext,
    )
    .expect("seal the recovery payload");
    let output_data_hash = wire::output_data_hash(&sealed);
    let owner = notes::owner_commitment(
        plaintext.owner_nf_key_hash,
        plaintext.pq_auth_key_hash,
        plaintext.note_secret,
    );

    // Before the bounce: the chain carries the template, which is not money.
    let template = wire::recovery_template_hash(owner, output_data_hash);
    let restored = PoolInstance::new(&SEED, domain);
    let before = scan::recover(
        &restored,
        &[ObservedOutput {
            slot: 2,
            output_data: sealed.clone(),
            chain: ChainSlot { output_data_hash, note_body: template, recovered: None },
        }],
    )
    .expect("recover the template");
    assert_eq!(before.notes.len(), 1, "the template was not recognised at all");
    assert_eq!(before.balance(), 0, "a template that has not bounced is not money");
    assert_eq!(before.spendable_notes().count(), 0, "a template was offered as an input");

    // After the bounce: the contract minted the note for what came back less
    // its own charge, and published that body. The amount is read off the
    // chain rather than assumed, which is the only way a wallet can know it.
    let recovered_amount = u128::from(DENOMINATION) - 1_466_669;
    let minted =
        notes::note_body_commitment(owner, Fr::from(recovered_amount), output_data_hash);
    let after = scan::recover(
        &restored,
        &[ObservedOutput {
            slot: 2,
            output_data: sealed.clone(),
            chain: ChainSlot {
                output_data_hash,
                note_body: minted,
                recovered: Some(recovered_amount),
            },
        }],
    )
    .expect("recover the minted note");

    assert_eq!(after.notes.len(), 1, "the minted recovery note was not recognised");
    assert_eq!(
        after.balance(),
        recovered_amount,
        "a bounced recovery note is money and the restored wallet did not count it"
    );
    assert_eq!(
        after.spendable_notes().count(),
        1,
        "the recovery note is not offered as an input, so the money cannot be moved"
    );
    let note = after.spendable_notes().next().expect("the recovery note");
    assert!(note.spendable, "the recovery note imported as unspendable");
    assert_eq!(note.amount, recovered_amount, "the note imported for the wrong amount");
    assert_eq!(note.note_body, minted, "the imported body is not the one the chain published");

    // And it is held to the chain's own body: a wallet told a different amount
    // than the one that was minted must refuse rather than invent a note.
    let lying = scan::recover(
        &restored,
        &[ObservedOutput {
            slot: 2,
            output_data: sealed,
            chain: ChainSlot {
                output_data_hash,
                note_body: minted,
                recovered: Some(recovered_amount + 1),
            },
        }],
    )
    .expect("recover with a wrong amount");
    assert_eq!(lying.notes.len(), 0, "a recovery amount the chain did not mint was accepted");
    assert_eq!(lying.diagnostics.len(), 1, "the mismatch was not reported");

    // Once the chain publishes its nullifier it stops being spendable, by the
    // same reconciliation every other note goes through.
    let mut spent_later = after;
    let key = restored.owner_nf_key(index).expect("the owner key");
    let published: BTreeSet<Fr> = [notes::nullifier(minted, key)].into_iter().collect();
    spent_later.reconcile_spent(&restored, &published).expect("reconcile");
    assert_eq!(spent_later.balance(), 0, "a spent recovery note is still counted as money");
}

#[test]
fn another_wallets_notes_are_invisible_and_silent() {
    let frontier = shielded_pool_circuit::tree::Frontier::new();
    let nullifiers = shielded_pool_circuit::imt::State::genesis();
    let mut pool = Pool::deploy().expect("deploy the pool");
    let domain = wire::execution_domain(
        shielded_pool_circuit_crosscheck::wire::WireProbe::deploy()
            .expect("the wire probe")
            .domain_inputs()
            .expect("the domain inputs")
            .0,
        &pool.account().expect("the pool's account"),
    );

    let mine = PoolInstance::new(&SEED, domain);
    let theirs = PoolInstance::new(&[0x5b; 32], domain);
    let ours = deposit(&mut pool, &mine, 0);
    let not_ours = deposit(&mut pool, &theirs, 0);

    let recovered = scan::recover(
        &PoolInstance::new(&SEED, domain),
        &[ours.output.clone(), not_ours.output.clone()],
    )
    .expect("recover");
    assert_eq!(recovered.notes.len(), 1, "a wallet found a note that is not its own");
    assert_eq!(recovered.balance(), u128::from(DENOMINATION));
    assert!(
        recovered.diagnostics.is_empty(),
        "somebody else's payload was recorded as a problem with ours"
    );

    // And the other way round, so this is a property of the pair and not of
    // the order they were deposited in.
    let theirs_recovered =
        scan::recover(&PoolInstance::new(&[0x5b; 32], domain), &[ours.output, not_ours.output])
            .expect("recover");
    assert_eq!(theirs_recovered.notes.len(), 1);
}

/// Gate 26 and section 2.5: a payer who kept a descriptor pays it twice.
///
/// Both notes are real, both are the wallet's, and both are spendable. The
/// wallet must import both -- discarding the second would lose money to
/// somebody else's mistake -- mark the index reused, and never issue it again.
#[test]
fn two_notes_sent_to_one_descriptor_are_both_recovered_and_the_index_is_burnt() {
    let frontier = shielded_pool_circuit::tree::Frontier::new();
    let nullifiers = shielded_pool_circuit::imt::State::genesis();
    let mut pool = Pool::deploy().expect("deploy the pool");
    let domain = wire::execution_domain(
        shielded_pool_circuit_crosscheck::wire::WireProbe::deploy()
            .expect("the wire probe")
            .domain_inputs()
            .expect("the domain inputs")
            .0,
        &pool.account().expect("the pool's account"),
    );
    let wallet = PoolInstance::new(&SEED, domain);

    // The descriptor a payer was given. Issuing it once is all the wallet
    // ever does; what the payer does with it is not up to the wallet.
    let descriptor =
        shielded_pool_wallet::descriptor::Descriptor::issue(&wallet, 2).expect("a descriptor");
    assert_eq!(descriptor.note_key_index, 2);

    // Paid twice, with different note secrets, so the two notes are genuinely
    // different notes and not the same one seen twice.
    let first = deposit(&mut pool, &wallet, 2);
    let second = {
        let plaintext = Plaintext {
            slot: 0,
            kind: Kind::Ordinary,
            amount: u128::from(DENOMINATION),
            note_secret: Fr::from(0x1111_2222u64),
            owner_nf_key_hash: wallet.owner_nf_key_hash(2).expect("an owner hash"),
            note_key_index: 2,
            pq_auth_key_hash: wallet.pq_auth_key_hash(2).expect("a key hash"),
        };
        let sealed =
            delivery::seal(&descriptor.mlkem_encapsulation_key, domain, &plaintext).expect("seal");
        let owner = notes::owner_commitment(
            plaintext.owner_nf_key_hash,
            plaintext.pq_auth_key_hash,
            plaintext.note_secret,
        );
        pool.send(
            DENOMINATION + COMPUTE_FEE,
            Pool::deposit_body(DENOMINATION, owner, byte_chain(&sealed).expect("payload"))
                .expect("deposit body"),
        )
        .expect("deposit")
        .expect_success();
        let output_data_hash = wire::output_data_hash(&sealed);
        ObservedOutput {
            slot: 0,
            output_data: sealed,
            chain: ChainSlot {
                output_data_hash,
                note_body: notes::note_body_commitment(
                    owner,
                    Fr::from(u128::from(DENOMINATION)),
                    output_data_hash,
                ),
                recovered: None,
            },
        }
    };
    assert_ne!(
        dec(first.output.chain.note_body),
        dec(second.chain.note_body),
        "the two payments produced the same note"
    );

    let recovered =
        scan::recover(&PoolInstance::new(&SEED, domain), &[first.output.clone(), second.clone()])
            .expect("recover");

    assert_eq!(recovered.notes.len(), 2, "the second payment to a used descriptor was lost");
    assert_eq!(
        recovered.balance(),
        2 * u128::from(DENOMINATION),
        "only one of the two notes was counted"
    );
    assert!(
        recovered.notes.iter().all(|note| note.note_key_index == 2 && note.spendable),
        "a note at a reused index was imported unspendable"
    );
    // Both derive the same one-time PQ key, which is exactly the privacy
    // degradation section 2.5 describes -- and exactly why the index is burnt.
    assert!(recovered.reused.contains(&2), "the reused index was not marked");
    assert!(!recovered.may_issue(2), "the wallet would hand out the reused index again");
    assert_eq!(recovered.next_note_key_index, 3);
}
