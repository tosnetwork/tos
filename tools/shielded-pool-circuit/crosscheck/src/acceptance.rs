/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The gate a ceremony's output has to pass before anyone deploys it.
//!
//! A ceremony produces two things: a proving key its participants can no
//! longer forge with, and 1,248 bytes this chain has to carry forever. The
//! second is the one that can be wrong in ways nobody notices -- a key with
//! the wrong number of IC points, a key that encodes to the right length under
//! the wrong convention, a key that verifies in the proving library and is
//! refused by the VM.
//!
//! So the gate is not "does the key look right". It is: **deploy a pool
//! carrying exactly those bytes, prove a real transfer under the matching
//! proving key, send it, and require the contract to accept.** Everything
//! short of that is a claim about a serializer.
//!
//! This duplicates the happy path of `valid_proof_e2e`, which builds the same
//! transfer in order to tamper with it. Two constructions of one transaction
//! is a real cost and the alternative was worse: that test needs the witness,
//! the public inputs and the proof separately so it can break one at a time,
//! and a shared helper that exposed all three would be the test with extra
//! steps. What keeps the two from drifting is
//! [`AcceptanceOutcome::address`]: run against the development key this
//! produces the same deployment address as `Pool::deploy`, and a divergence
//! in either construction moves it.

use ark_ff::AdditiveGroup;

use shielded_pool_circuit::circuit::{HeldNote, ShieldedTransactionCircuit, TransactionBuilder};
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::groth16::{self, DevelopmentKeys};
use shielded_pool_circuit::tree::Frontier;
use shielded_pool_circuit::{imt, notes, wire};

use crate::pool::{dec, Pool, DENOMINATION};
use crate::transact::{Anchor, AuthKey, Transact};
use crate::wire::byte_chain;
use crate::{CrossCheckError, Result};

const TOS: u64 = 1_000_000_000;
const COMPUTE_FEE: u64 = 3 * TOS;

/// Section 10.1: eighteen public inputs, so nineteen IC points, and a key of
/// `48 + 3*96 + 19*48` bytes.
pub const PUBLIC_INPUTS: usize = 18;
pub const CANONICAL_VK_BYTES: usize = 48 + 96 * 3 + 48 * (PUBLIC_INPUTS + 1);

/// What the gate saw.
#[derive(Clone, Debug)]
pub struct AcceptanceOutcome {
    /// The canonical encoding's length. Has to be [`CANONICAL_VK_BYTES`].
    pub vk_bytes: usize,
    /// Its SHA-256, which is what the genesis manifest records and what a
    /// deployment is identified by.
    pub vk_sha256: String,
    pub ic_count: usize,
    /// The address a pool carrying this key is deployed at. A different key is
    /// a different address, which is why this cannot be published before the
    /// ceremony finishes.
    pub address: String,
    /// The transact's exit code. Zero, or the key is not usable.
    pub exit: i32,
    /// What that transact spent.
    ///
    /// Reported, not pinned, and **not** the figure section 14.1's ceiling is
    /// derived from. This gate builds its own transfer in its own pool, and a
    /// transact's cost moves with the pool's age and the epoch it lands in --
    /// it measures about 158 gas more here than the 1,144,235 that
    /// `valid_proof_e2e` pins, for no reason more interesting than a
    /// different number of prior messages. A ceremony's key is judged by the
    /// exit code; the ceilings are measured where they are measured.
    pub gas: i64,
}

/// Runs the gate.
///
/// `keys` is the pair a ceremony produced. `deploy_vk` is what the pool is
/// deployed with -- normally the canonical encoding of `keys.verifying`, and
/// deliberately separable so that a test can deploy one key and prove under
/// another. A gate that has only ever seen the matching pair cannot show that
/// it checks the match.
pub fn run(keys: &DevelopmentKeys, deploy_vk: &[u8]) -> Result<AcceptanceOutcome> {
    let encoded = groth16::canonical_verifying_key(&keys.verifying).map_err(|error| {
        CrossCheckError::Fixture(format!("encoding the verifying key: {error}"))
    })?;
    if encoded.ic_count != PUBLIC_INPUTS + 1 {
        return Err(CrossCheckError::Fixture(format!(
            "the verifying key has {} IC points; section 10's eighteen public inputs need {}",
            encoded.ic_count,
            PUBLIC_INPUTS + 1
        )));
    }
    if encoded.bytes.len() != CANONICAL_VK_BYTES {
        return Err(CrossCheckError::Fixture(format!(
            "the canonical verifying key is {} bytes, not {CANONICAL_VK_BYTES}",
            encoded.bytes.len()
        )));
    }
    if deploy_vk.len() != CANONICAL_VK_BYTES {
        return Err(CrossCheckError::Fixture(format!(
            "the key to deploy with is {} bytes, not {CANONICAL_VK_BYTES}",
            deploy_vk.len()
        )));
    }

    let mut frontier = Frontier::new();
    let nullifiers = imt::State::genesis();
    let mut pool = Pool::deploy_with(&[DENOMINATION], Some(deploy_vk))?;
    let address = pool.addr.to_string();

    if pool.get("commitment_root")? != dec(frontier.empty_root()) {
        return Err(CrossCheckError::Fixture(
            "the deployed pool and the prover disagree about the empty commitment tree".into(),
        ));
    }

    let global_id = crate::wire::WireProbe::deploy()?.domain_inputs()?.0;
    let domain = wire::execution_domain(global_id, &pool.account()?);

    // --- one note to spend ------------------------------------------------
    let input_key = AuthKey::generate()?;
    let phantom_key = AuthKey::generate()?;
    let owner_nf_key = Fr::from(0x11_2233_4455_6677u64);
    let note_secret = Fr::from(0x99_aabb_ccdd_eeffu64);
    let deposit_payload: Vec<u8> =
        (0..wire::OUTPUT_DATA_BYTES as u32).map(|i| (i as u8) ^ 0x21).collect();
    let deposit_data_hash = wire::output_data_hash(&deposit_payload);
    let owner_commitment = notes::owner_commitment(
        notes::owner_nf_key_hash(owner_nf_key),
        input_key.hash(),
        note_secret,
    );

    pool.send(
        DENOMINATION + COMPUTE_FEE,
        Pool::deposit_body(DENOMINATION, owner_commitment, byte_chain(&deposit_payload)?)?,
    )?
    .expect_success();

    let note_body = notes::note_body_commitment(
        owner_commitment,
        Fr::from(u128::from(DENOMINATION)),
        deposit_data_hash,
    );
    let leaf = notes::note_commitment(note_body, Fr::ZERO);
    let (leaf_index, root) = frontier
        .append(leaf)
        .map_err(|error| CrossCheckError::Fixture(format!("appending the note: {error}")))?;
    if leaf_index != 0 || pool.get("commitment_root")? != dec(root) {
        return Err(CrossCheckError::Fixture(
            "the prover's tree and the contract's disagree after one deposit".into(),
        ));
    }

    // --- the transfer -----------------------------------------------------
    let now: u32 = pool
        .bc
        .now()
        .try_into()
        .map_err(|_| CrossCheckError::Sandbox("the sandbox clock is not a unix time".into()))?;
    let valid_until = now + 600;
    let output_payloads: [Vec<u8>; 3] = [
        (0..wire::OUTPUT_DATA_BYTES as u32).map(|i| (i as u8) ^ 1).collect(),
        (0..wire::OUTPUT_DATA_BYTES as u32).map(|i| (i as u8) ^ 2).collect(),
        (0..wire::OUTPUT_DATA_BYTES as u32).map(|i| (i as u8) ^ 3).collect(),
    ];
    let output_data_hash = [
        wire::output_data_hash(&output_payloads[0]),
        wire::output_data_hash(&output_payloads[1]),
        wire::output_data_hash(&output_payloads[2]),
    ];

    let terms = shielded_pool_circuit::scenario::PublicTerms::transfer();
    let mut scenario_pool = shielded_pool_circuit::scenario::Pool::new();
    let half = u128::from(DENOMINATION) / 2;
    let outputs = [
        scenario_pool.real_output(Fr::from(half)),
        scenario_pool.real_output(Fr::from(u128::from(DENOMINATION) - half)),
        scenario_pool.dummy_output(),
    ];
    let held = [
        HeldNote {
            is_phantom: false,
            owner_nf_key,
            note_secret,
            amount: Fr::from(u128::from(DENOMINATION)),
            output_data_hash: deposit_data_hash,
            leaf_index: 0,
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

    let (public, witness) = TransactionBuilder {
        execution_domain: domain,
        valid_until,
        intent_nonce: Fr::from(0x1234_5678u64),
        public_amount_out: terms.public_amount_out,
        withdrawal_fee: terms.withdrawal_fee,
        public_recipient_hash: terms.public_recipient_hash,
        recovery_template_hash: terms.recovery_template_hash,
        is_withdrawal: None,
        input_pq_auth_key_hash: [input_key.hash(), phantom_key.hash()],
        outputs,
        output_data_hash,
    }
    .build(&frontier, root, held)
    .map_err(|error| CrossCheckError::Fixture(format!("building the transaction: {error}")))?;

    // --- the proof, under the key being judged ----------------------------
    let proof = groth16::prove(keys, ShieldedTransactionCircuit::new(public, witness), 1)
        .map_err(|error| CrossCheckError::Fixture(format!("proving: {error}")))?;
    if !groth16::verify(&keys.verifying, &public, &proof)
        .map_err(|error| CrossCheckError::Fixture(format!("verifying: {error}")))?
    {
        return Err(CrossCheckError::Fixture(
            "the proof does not verify out of circuit, so the key pair does not match itself"
                .into(),
        ));
    }
    let canonical = groth16::CanonicalProof::from_proof(&proof)
        .map_err(|error| CrossCheckError::Fixture(format!("canonical proof: {error}")))?;

    // --- and on chain -----------------------------------------------------
    let digest = public.transaction_intent_digest;
    let signatures = [input_key.sign(digest)?, phantom_key.sign(digest)?];
    let mut tree = nullifiers.clone();
    let (witness_0, after_first) = tree
        .witness_for(&public.nullifier_0)
        .map_err(|error| CrossCheckError::Fixture(format!("first witness: {error}")))?;
    tree.apply(after_first);
    let (witness_1, _) = tree
        .witness_for(&public.nullifier_1)
        .map_err(|error| CrossCheckError::Fixture(format!("second witness: {error}")))?;

    let body = Transact {
        public: &public,
        proof: &canonical,
        anchor_root: root,
        anchor: Anchor::Current,
        valid_until,
        output_payloads: &output_payloads,
        keys: [&input_key.public, &phantom_key.public],
        signatures: &signatures,
        witnesses: &[witness_0, witness_1],
        public_amount_out: 0,
        withdrawal_fee: 0,
        recipient: None,
        recovery_owner_commitment: Fr::ZERO,
        recovery_payload: None,
    }
    .body()
    .map_err(|error| CrossCheckError::Fixture(format!("a transact body: {error}")))?;

    let (exit, gas) = pool.run(COMPUTE_FEE * 4, body)?;

    Ok(AcceptanceOutcome {
        vk_bytes: encoded.bytes.len(),
        vk_sha256: encoded.sha256,
        ic_count: encoded.ic_count,
        address,
        exit,
        gas,
    })
}
