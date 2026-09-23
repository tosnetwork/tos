/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! A pool driven by a sequence of real messages, rather than one message.
//!
//! Section 19 gate 17 is about what a *run* of transactions does to the anchor
//! rings: a deposit appends one leaf and a transact appends three, so the
//! version numbers a mixed run preserves are a sparse subset of the integers,
//! and which ring slots get overwritten is not a function of how many
//! transactions have happened. Nothing about that is visible in a test that
//! sends one message.
//!
//! Everything here goes through the shipping contract by internal message,
//! with a real Groth16 proof for every transact. The prover's tree and
//! nullifier state are carried along so that each transaction is proved
//! against what the previous ones actually left behind.

#![allow(dead_code)]

use ark_ff::AdditiveGroup;
use shielded_pool_circuit::circuit::{HeldNote, ShieldedTransactionCircuit, TransactionBuilder};
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::tree::Frontier;
use shielded_pool_circuit::{groth16, imt, notes, wire};

use shielded_pool_circuit_crosscheck::pool::{
    dec, development_vk_bytes, AnchorEntry, Pool, DENOMINATION,
};
use shielded_pool_circuit_crosscheck::transact::{Anchor, AuthKey, Transact};
use shielded_pool_circuit_crosscheck::wire::byte_chain;

const TOS: u64 = 1_000_000_000;
const COMPUTE_FEE: u64 = 3 * TOS;

/// Section 6.1: the recent ring's slot count.
pub const RECENT_SLOTS: u64 = 4096;

/// A payload of the one length section 3.1 allows.
fn payload(seed: u8) -> Vec<u8> {
    (0..wire::OUTPUT_DATA_BYTES as u32).map(|i| (i as u8) ^ seed).collect()
}

/// A note this harness deposited and can still spend.
struct Spendable {
    key: AuthKey,
    owner_nf_key: Fr,
    note_secret: Fr,
    data_hash: Fr,
    leaf_index: u64,
}

/// One externally visible root, and the tree state that can prove against it.
#[derive(Clone)]
pub struct Snapshot {
    pub root: Fr,
    /// The version the *next* mutation will preserve this root under, which
    /// is the leaf count at the moment of the snapshot.
    pub version: u64,
    frontier: Frontier,
}

pub struct Traffic {
    pub pool: Pool,
    frontier: Frontier,
    nullifiers: imt::State,
    root: Fr,
    domain: Fr,
    keys: Option<groth16::DevelopmentKeys>,
    unspent: Vec<Spendable>,
    seed: u8,
    nonce: u64,
    /// Whether the prover's tree still mirrors the contract's.
    ///
    /// Moving the leaf counter breaks that on purpose: the point of moving it
    /// is to reach a ring boundary, and the roots on the far side are not
    /// ones anything here proves against.
    mirrored: bool,
}

impl Traffic {
    pub fn start() -> Self {
        let frontier = Frontier::new();
        let nullifiers = imt::State::genesis();
        let pool = Pool::deploy().expect("deploy the pool");
        let global_id = {
            let probe = shielded_pool_circuit_crosscheck::wire::WireProbe::deploy()
                .expect("deploy the wire probe");
            probe.domain_inputs().expect("the domain inputs").0
        };
        let domain = wire::execution_domain(global_id, &pool.account().expect("the pool account"));
        let root = frontier.empty_root();
        assert_eq!(
            pool.get("commitment_root").expect("commitment root"),
            dec(root),
            "the contract and the prover disagree about the empty tree"
        );
        Traffic {
            pool,
            frontier,
            nullifiers,
            root,
            domain,
            keys: None,
            unspent: Vec::new(),
            seed: 0x20,
            nonce: 0,
            mirrored: true,
        }
    }

    /// The leaf index the pool will assign next, which is also the version the
    /// next mutation preserves its pre-transaction root under.
    pub fn index(&self) -> u64 {
        self.pool.get("commitment_next_index").expect("next index").parse().expect("a number")
    }

    /// The root as it stands, with the tree state needed to prove against it
    /// after later transactions have moved on.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot { root: self.root, version: self.index(), frontier: self.frontier.clone() }
    }

    /// Move the pool's leaf counter without touching the rings.
    ///
    /// The versions skipped were never externally visible roots, so no proof
    /// can name one; what this gives up is the prover's mirror of the tree,
    /// which is why nothing after it may prove against a root taken after.
    pub fn skip_to(&mut self, index: u64) {
        self.pool.age_index_to(index).expect("move the counter");
        self.mirrored = false;
    }

    pub fn rings(&self) -> (Vec<AnchorEntry>, Vec<AnchorEntry>) {
        self.pool.anchor_rings().expect("the anchor rings")
    }

    /// One deposit: one leaf, and a note this harness can spend later.
    ///
    /// Returns the version the mutation preserved, which is the leaf index the
    /// deposit took.
    pub fn deposit(&mut self) -> u64 {
        let version = self.index();
        self.seed = self.seed.wrapping_add(1);
        let key = AuthKey::generate().expect("an ML-DSA key");
        let owner_nf_key = Fr::from(0x1000_0000u64 + version);
        let note_secret = Fr::from(0x2000_0000u64 + version);
        let bytes = payload(self.seed);
        let data_hash = wire::output_data_hash(&bytes);
        let owner = notes::owner_commitment(
            notes::owner_nf_key_hash(owner_nf_key),
            key.hash(),
            note_secret,
        );

        self.pool
            .send(
                DENOMINATION + COMPUTE_FEE,
                Pool::deposit_body(DENOMINATION, owner, byte_chain(&bytes).expect("payload"))
                    .expect("deposit body"),
            )
            .expect("deposit")
            .expect_success();

        if self.mirrored {
            let body =
                notes::note_body_commitment(owner, Fr::from(u128::from(DENOMINATION)), data_hash);
            let (assigned, root) = self
                .frontier
                .append(notes::note_commitment(body, Fr::from(version)))
                .expect("append");
            assert_eq!(assigned, version, "the contract assigned another index");
            self.root = root;
            assert_eq!(
                self.pool.get("commitment_root").expect("commitment root"),
                dec(root),
                "the prover's tree and the contract's disagree after a deposit"
            );
        }
        self.unspent.push(Spendable {
            key,
            owner_nf_key,
            note_secret,
            data_hash,
            leaf_index: version,
        });
        version
    }

    /// One transfer: three leaves, proved against `against`.
    ///
    /// Returns the version the mutation preserved and the exit code. A
    /// transfer rather than a withdrawal, because what this harness is for is
    /// the three-leaf batch, and a payout would drag the bounce path in with
    /// it.
    pub fn transfer(&mut self, anchor: Anchor, against: &Snapshot) -> (u64, i32) {
        let version = self.index();
        // A proof is against one root, so the note it spends has to have been
        // in the tree when that root was current. Taking the newest note
        // would work only for the current root.
        let position = self
            .unspent
            .iter()
            .position(|note| note.leaf_index < against.version)
            .unwrap_or_else(|| {
                panic!(
                    "no unspent note was in the tree at the root of version {}",
                    against.version
                )
            });
        let spend = self.unspent.remove(position);

        let now: u32 = self.pool.bc.now().try_into().expect("a unix time");
        let valid_until = now + 600;
        let output_payloads = [payload(1), payload(2), payload(3)];
        let output_data_hash = [
            wire::output_data_hash(&output_payloads[0]),
            wire::output_data_hash(&output_payloads[1]),
            wire::output_data_hash(&output_payloads[2]),
        ];

        let mut scenario = shielded_pool_circuit::scenario::Pool::new();
        let half = u128::from(DENOMINATION) / 2;
        let outputs = [
            scenario.real_output(Fr::from(half)),
            scenario.real_output(Fr::from(u128::from(DENOMINATION) - half)),
            scenario.dummy_output(),
        ];

        let phantom_key = AuthKey::generate().expect("an ML-DSA key");
        let held = [
            HeldNote {
                is_phantom: false,
                owner_nf_key: spend.owner_nf_key,
                note_secret: spend.note_secret,
                amount: Fr::from(u128::from(DENOMINATION)),
                output_data_hash: spend.data_hash,
                leaf_index: spend.leaf_index,
            },
            HeldNote {
                is_phantom: true,
                owner_nf_key: Fr::from(7u64),
                note_secret: Fr::from(9u64),
                amount: Fr::ZERO,
                output_data_hash: Fr::from(11u64),
                leaf_index: 0,
            },
        ];

        self.nonce += 1;
        let builder = TransactionBuilder {
            execution_domain: self.domain,
            valid_until,
            intent_nonce: Fr::from(0xfeed_0000u64 + self.nonce),
            public_amount_out: Fr::ZERO,
            withdrawal_fee: Fr::ZERO,
            public_recipient_hash: Fr::ZERO,
            recovery_template_hash: Fr::ZERO,
            is_withdrawal: None,
            input_pq_auth_key_hash: [spend.key.hash(), phantom_key.hash()],
            outputs,
            output_data_hash,
        };
        let (public, witness) = builder
            .build(&against.frontier, against.root, held)
            .expect("build the transfer");

        // The keys depend on the circuit's shape, not on this transaction, so
        // one set serves the whole run. Proving is the slow part of a
        // traffic test and generating them per message doubles it.
        if self.keys.is_none() {
            let keys = groth16::development_keys(ShieldedTransactionCircuit::blank(public))
                .expect("development keys");
            assert_eq!(
                groth16::canonical_verifying_key(&keys.verifying).expect("vk bytes").bytes,
                development_vk_bytes().expect("the fixture verifying key"),
                "the prover's verifying key is not the one the pool was deployed with"
            );
            self.keys = Some(keys);
        }
        let keys = self.keys.as_ref().expect("the keys");
        let proof =
            groth16::prove(keys, ShieldedTransactionCircuit::new(public, witness), 3).expect("prove");
        let canonical = groth16::CanonicalProof::from_proof(&proof).expect("canonical proof");

        let digest = public.transaction_intent_digest;
        let signatures =
            [spend.key.sign(digest).expect("a signature"), phantom_key.sign(digest).expect("a signature")];

        let mut tree = self.nullifiers.clone();
        let (witness_0, first) = tree.witness_for(&public.nullifier_0).expect("first witness");
        tree.apply(first);
        let (witness_1, second) = tree.witness_for(&public.nullifier_1).expect("second witness");
        tree.apply(second);

        let body = Transact {
            public: &public,
            proof: &canonical,
            anchor_root: against.root,
            anchor,
            valid_until,
            output_payloads: &output_payloads,
            keys: [&spend.key.public, &phantom_key.public],
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

        let (exit, _) = self.pool.run(COMPUTE_FEE * 4, body).expect("send the transfer");
        if exit != 0 {
            return (version, exit);
        }

        // Mirror what the contract just did, so the next transaction proves
        // against a tree that matches.
        self.nullifiers = tree;
        if !self.mirrored {
            return (version, exit);
        }
        for (offset, note_body) in
            [public.note_body_0, public.note_body_1, public.note_body_2].into_iter().enumerate()
        {
            let index = version + offset as u64;
            let (assigned, root) = self
                .frontier
                .append(notes::note_commitment(note_body, Fr::from(index)))
                .expect("append an output");
            assert_eq!(assigned, index, "the contract assigned another output index");
            self.root = root;
        }
        assert_eq!(
            self.pool.get("commitment_root").expect("commitment root"),
            dec(self.root),
            "the prover's tree and the contract's disagree after a transfer"
        );
        (version, exit)
    }
}
