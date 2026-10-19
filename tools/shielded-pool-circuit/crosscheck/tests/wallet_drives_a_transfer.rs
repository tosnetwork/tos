/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The wallet builds every output of a real transfer, and then a restored
//! wallet finds them.
//!
//! This is the shape the product actually has. A transfer's three outputs are
//! the only place a dummy can exist -- a deposit mints for the amount it
//! admitted, so a deposit is always ordinary -- and a dummy is what makes the
//! wire shape say nothing about how many outputs are real. So the claim that a
//! dummy consumes an index and carries no balance can only be tested here.
//!
//! Every output payload below is sealed by the wallet to itself, the circuit
//! proves the note bodies those payloads describe, the contract verifies the
//! proof and publishes the bodies, and a wallet built from nothing but the
//! seed is then handed the chain's outputs.

mod support;

use ark_ff::AdditiveGroup;

use std::collections::BTreeSet;

use shielded_pool_circuit::circuit::{
    HeldNote, OutputNote, ShieldedTransactionCircuit, TransactionBuilder,
};
use shielded_pool_circuit::domains::dummy_owner_nf_hash;
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::{groth16, imt, notes, wire};
use shielded_pool_circuit_crosscheck::pool::{dec, development_vk_bytes, Pool, DENOMINATION};
use shielded_pool_circuit_crosscheck::transact::{Anchor, AuthKey, Transact};
use shielded_pool_circuit_crosscheck::wire::byte_chain;
use shielded_pool_wallet::delivery::{self, Kind, Plaintext};
use shielded_pool_wallet::import::ChainSlot;
use shielded_pool_wallet::keys::PoolInstance;
use shielded_pool_wallet::scan::{self, ObservedOutput};

const TOS: u64 = 1_000_000_000;
const COMPUTE_FEE: u64 = 3 * TOS;
const SEED: [u8; 32] = [0x3e; 32];

fn seal(wallet: &PoolInstance, plaintext: &Plaintext) -> Vec<u8> {
    delivery::seal(
        &wallet.mlkem_encapsulation_key().expect("a key"),
        wallet.execution_domain(),
        plaintext,
    )
    .expect("seal the payload")
}

#[test]
fn a_wallet_builds_a_transfers_outputs_and_recovers_them() {
    let mut frontier = shielded_pool_circuit::tree::Frontier::new();
    let nullifiers = imt::State::genesis();
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

    // --- the note to be spent, deposited with a payload the wallet sealed --
    let input_index = 0u64;
    let input_secret = Fr::from(0xa11ce_u64);
    let input_plaintext = Plaintext {
        slot: 0,
        kind: Kind::Ordinary,
        amount: u128::from(DENOMINATION),
        note_secret: input_secret,
        owner_nf_key_hash: wallet.owner_nf_key_hash(input_index).expect("an owner hash"),
        note_key_index: input_index,
        pq_auth_key_hash: wallet.pq_auth_key_hash(input_index).expect("a key hash"),
    };
    let input_payload = seal(&wallet, &input_plaintext);
    let input_owner = notes::owner_commitment(
        input_plaintext.owner_nf_key_hash,
        input_plaintext.pq_auth_key_hash,
        input_secret,
    );
    pool.send(
        DENOMINATION + COMPUTE_FEE,
        Pool::deposit_body(DENOMINATION, input_owner, byte_chain(&input_payload).expect("payload"))
            .expect("deposit body"),
    )
    .expect("deposit")
    .expect_success();

    let input_data_hash = wire::output_data_hash(&input_payload);
    let input_body = notes::note_body_commitment(
        input_owner,
        Fr::from(u128::from(DENOMINATION)),
        input_data_hash,
    );
    let (_, root) = frontier.append(notes::note_commitment(input_body, Fr::ZERO)).expect("append");
    assert_eq!(pool.get("commitment_root").expect("root"), dec(root));

    // --- the three outputs, all the wallet's -----------------------------
    //
    // Two real notes and a dummy. The dummy names the fixed owner constant
    // rather than this wallet's owner hash, so the note it produces is owned
    // by nobody -- but its index is the wallet's, and consuming it is the
    // point.
    let half = u128::from(DENOMINATION) / 2;
    let amounts = [half, u128::from(DENOMINATION) - half, 0u128];
    let kinds = [Kind::Ordinary, Kind::Ordinary, Kind::Dummy];
    let indices = [1u64, 2, 3];

    let mut plaintexts = Vec::new();
    let mut payloads = Vec::new();
    for slot in 0..3usize {
        let plaintext = Plaintext {
            slot: slot as u8,
            kind: kinds[slot],
            amount: amounts[slot],
            note_secret: Fr::from(0x5ec0_0000u64 + indices[slot]),
            owner_nf_key_hash: match kinds[slot] {
                Kind::Dummy => dummy_owner_nf_hash(),
                _ => wallet.owner_nf_key_hash(indices[slot]).expect("an owner hash"),
            },
            note_key_index: indices[slot],
            pq_auth_key_hash: wallet.pq_auth_key_hash(indices[slot]).expect("a key hash"),
        };
        payloads.push(seal(&wallet, &plaintext));
        plaintexts.push(plaintext);
    }
    let output_data_hash: [Fr; 3] = [
        wire::output_data_hash(&payloads[0]),
        wire::output_data_hash(&payloads[1]),
        wire::output_data_hash(&payloads[2]),
    ];
    let outputs: [OutputNote; 3] = std::array::from_fn(|slot| OutputNote {
        is_dummy: kinds[slot] == Kind::Dummy,
        owner_nf_key_hash: plaintexts[slot].owner_nf_key_hash,
        pq_auth_key_hash: plaintexts[slot].pq_auth_key_hash,
        note_secret: plaintexts[slot].note_secret,
        amount: Fr::from(amounts[slot]),
    });

    // --- the transfer ----------------------------------------------------
    //
    // The phantom slot's key is a throwaway rather than a wallet index. A
    // phantom leaves no payload on chain, so an index spent on one would be
    // invisible to mnemonic-only recovery and would later be reissued.
    let phantom_key = AuthKey::generate().expect("a throwaway key");
    let now: u32 = pool.bc.now().try_into().expect("a unix time");
    let valid_until = now + 600;

    let held = || {
        [
            HeldNote {
                is_phantom: false,
                owner_nf_key: wallet.owner_nf_key(input_index).expect("a key"),
                note_secret: input_secret,
                amount: Fr::from(u128::from(DENOMINATION)),
                output_data_hash: input_data_hash,
                leaf_index: 0,
            },
            HeldNote {
                is_phantom: true,
                owner_nf_key: Fr::from(13u64),
                note_secret: Fr::from(17u64),
                amount: Fr::ZERO,
                output_data_hash: Fr::from(19u64),
                leaf_index: 0,
            },
        ]
    };
    let builder = TransactionBuilder {
        execution_domain: domain,
        valid_until,
        intent_nonce: Fr::from(0x2468_1357u64),
        public_amount_out: Fr::ZERO,
        withdrawal_fee: Fr::ZERO,
        public_recipient_hash: Fr::ZERO,
        recovery_template_hash: Fr::ZERO,
        is_withdrawal: None,
        input_pq_auth_key_hash: [
            wallet.pq_auth_key_hash(input_index).expect("a key hash"),
            wire::pq_auth_key_hash(&phantom_key.public),
        ],
        outputs,
        output_data_hash,
    };
    let (public, witness) = builder.build(&frontier, root, held()).expect("build the transfer");

    let keys = groth16::development_keys(ShieldedTransactionCircuit::blank(public))
        .expect("development keys");
    assert_eq!(
        groth16::canonical_verifying_key(&keys.verifying).expect("vk bytes").bytes,
        development_vk_bytes().expect("the fixture verifying key"),
        "the prover's verifying key is not the pool's"
    );
    let proof =
        groth16::prove(&keys, ShieldedTransactionCircuit::new(public, witness), 5).expect("prove");
    let canonical = groth16::CanonicalProof::from_proof(&proof).expect("canonical proof");

    // The wallet signs with the one-time key the note it is spending is
    // locked to, derived from the index and nothing stored.
    let digest = public.transaction_intent_digest;
    let signatures = [
        wallet.sign_intent(input_index, digest).expect("a signature"),
        phantom_key.sign(digest).expect("a signature"),
    ];
    let input_public_key = wallet.mldsa_public_key(input_index).expect("a key");

    let mut tree = nullifiers.clone();
    let (witness_0, after_first) = tree.witness_for(&public.nullifier_0).expect("first witness");
    tree.apply(after_first);
    let (witness_1, _) = tree.witness_for(&public.nullifier_1).expect("second witness");

    let payload_array: [Vec<u8>; 3] =
        [payloads[0].clone(), payloads[1].clone(), payloads[2].clone()];
    let body = Transact {
        public: &public,
        proof: &canonical,
        anchor_root: root,
        anchor: Anchor::Current,
        valid_until,
        output_payloads: &payload_array,
        keys: [&input_public_key, &phantom_key.public],
        signatures: &signatures,
        witnesses: &[witness_0, witness_1],
        public_amount_out: 0,
        withdrawal_fee: 0,
        recipient: None,
        recovery_owner_commitment: Fr::ZERO,
        recovery_payload: None,
    }
    .body()
    .expect("a transact body");

    let (exit, gas) = pool.run(COMPUTE_FEE * 4, body).expect("transact");
    assert_eq!(exit, 0, "the wallet's own transfer was refused with exit {exit}");
    eprintln!("a wallet-built private transfer: {gas} gas");
    assert_eq!(
        pool.get("commitment_next_index").expect("next index"),
        "4",
        "one deposit and three outputs should leave four leaves"
    );

    // --- what a restored wallet makes of it ------------------------------
    let restored = PoolInstance::new(&SEED, domain);
    let observed: Vec<ObservedOutput> = std::iter::once(ObservedOutput {
        slot: 0,
        output_data: input_payload,
        chain: ChainSlot {
            output_data_hash: input_data_hash,
            note_body: input_body,
            recovered: None,
        },
    })
    .chain((0..3).map(|slot| ObservedOutput {
        slot: slot as u8,
        output_data: payloads[slot].clone(),
        chain: ChainSlot {
            output_data_hash: output_data_hash[slot],
            note_body: [public.note_body_0, public.note_body_1, public.note_body_2][slot],
            recovered: None,
        },
    }))
    .collect();
    let mut recovered = scan::recover(&restored, &observed).expect("recover");

    assert!(recovered.diagnostics.is_empty(), "a payload this wallet built was refused");
    assert_eq!(recovered.notes.len(), 4, "the restored wallet did not find every output");

    // Restoration is not finished until the chain has been asked which of
    // these are already spent. Discovering a payload says the wallet was sent
    // something; it does not say the wallet still has it.
    //
    // Both nullifiers this transfer published, exactly as the chain carries
    // them: the real input's, and the phantom the second slot used.
    let published: BTreeSet<Fr> = [public.nullifier_0, public.nullifier_1].into_iter().collect();
    recovered.reconcile_spent(&restored, &published).expect("reconcile against the chain");
    assert_eq!(
        scan::dummies(&recovered).len(),
        1,
        "the dummy was not recognised, or a real output was taken for one"
    );

    // The dummy carries no balance, and neither does the note this transfer
    // spent.
    //
    // This assertion used to require `DENOMINATION * 2` and was green: it
    // counted the deposit *and* the outputs that replaced it. A self-transfer
    // conserves one denomination, so that figure is what the wallet was ever
    // sent, not what it can spend -- and a wallet reporting twice its money
    // will pick inputs that no longer exist and quote a number its owner
    // cannot pay.
    assert_eq!(
        recovered.balance(),
        u128::from(DENOMINATION),
        "the spent input was counted as balance, the dummy was, or a real output was not"
    );

    // The historical figure still exists, under a name that says what it is.
    assert_eq!(
        recovered.received(),
        u128::from(DENOMINATION) * 2,
        "the deposit and its replacements are what this wallet was ever sent"
    );

    // And the consumed note cannot be chosen as an input again.
    let spendable: Vec<_> = recovered.spendable_notes().collect();
    assert_eq!(spendable.len(), 2, "the spent input is still selectable");
    assert!(
        spendable.iter().all(|note| note.note_body != input_body),
        "the note this transfer spent is still offered as an input"
    );

    // Gate 7: the dummy's index is consumed like any other, and the next
    // index is past it. Reissuing 3 would put a real note under the same
    // one-time ML-DSA key a dummy already used.
    assert_eq!(
        scan::used_indices(&recovered).into_iter().collect::<Vec<_>>(),
        vec![0, 1, 2, 3],
        "the restored wallet did not find every consumed index"
    );
    assert_eq!(recovered.next_note_key_index, 4, "the dummy's index would be reissued");
    assert!(!recovered.may_issue(3), "the dummy's index would be issued as a descriptor");
    assert!(recovered.reused.is_empty(), "nothing here reused an index");
}
