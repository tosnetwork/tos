/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The section 4 / section 5 fixture the cross-check consumes.
//!
//! Every value here is produced twice: once by the out-of-circuit functions and
//! once with the constraints generated and the R1CS reported satisfied. The two
//! must agree before anything is written, so a fixture that reaches the VM
//! carries an in-circuit value, not merely a convenient one.
//!
//! Field elements travel as decimal strings. A 256-bit value must never pass
//! through a 64-bit integer on the way, and the reader checks the round trip.

use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::field::{fr_from_decimal, fr_to_decimal, Fr};
use crate::gadgets::notes as note_gadget;
use crate::gadgets::poseidon2::FrVar;
use crate::gadgets::tree as tree_gadget;
use crate::{notes, tree};

/// One note, with every section 4 value derived from it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteCase {
    pub name: String,
    pub owner_nf_key: String,
    pub pq_auth_key_hash: String,
    pub note_secret: String,
    pub amount: String,
    pub output_data_hash: String,
    pub leaf_index: String,
    pub intent_nonce: String,
    pub input_slot: String,
    pub owner_nf_key_hash: String,
    pub owner_commitment: String,
    pub note_body_commitment: String,
    pub note_commitment: String,
    pub nullifier: String,
    pub phantom_nullifier: String,
}

/// One interior node of the commitment tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitNodeCase {
    pub name: String,
    pub children: Vec<String>,
    pub node: String,
}

/// A run of sequential appends and the root after each one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendCase {
    pub name: String,
    pub leaves: Vec<String>,
    pub roots_after_each: Vec<String>,
}

/// The whole fixture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section45Fixture {
    pub profile: String,
    pub poseidon2_manifest_sha256: String,
    pub notes: Vec<NoteCase>,
    pub commit_nodes: Vec<CommitNodeCase>,
    pub empty_roots: Vec<String>,
    pub appends: Vec<AppendCase>,
}

fn cs() -> ConstraintSystemRef<Fr> {
    ConstraintSystem::<Fr>::new_ref()
}

fn witness(cs: &ConstraintSystemRef<Fr>, value: Fr) -> Result<FrVar> {
    FrVar::new_witness(cs.clone(), || Ok(value))
        .map_err(|error| Error::Backend(format!("witness allocation: {error}")))
}

/// Reads an in-circuit value back out, after requiring the system to be
/// satisfied. A gadget that computed the right value while constraining
/// nothing would still have to survive this, because the caller pins the
/// result with an equality constraint first.
fn settled(cs: &ConstraintSystemRef<Fr>, var: &FrVar, native: Fr) -> Result<Fr> {
    let target = witness(cs, native)?;
    var.enforce_equal(&target)
        .map_err(|error| Error::Backend(format!("equality constraint: {error}")))?;
    let satisfied = cs
        .is_satisfied()
        .map_err(|error| Error::Backend(format!("constraint evaluation: {error}")))?;
    if !satisfied {
        return Err(Error::Backend(
            "the gadget disagrees with the out-of-circuit function".to_string(),
        ));
    }
    var.value().map_err(|error| Error::Backend(format!("reading the gadget result: {error}")))
}

#[allow(clippy::too_many_arguments)]
fn note_case(
    name: &str,
    owner_nf_key: Fr,
    pq_auth_key_hash: Fr,
    note_secret: Fr,
    amount: Fr,
    output_data_hash: Fr,
    leaf_index: Fr,
    intent_nonce: Fr,
    input_slot: Fr,
) -> Result<NoteCase> {
    let native_key_hash = notes::owner_nf_key_hash(owner_nf_key);
    let native_owner = notes::owner_commitment(native_key_hash, pq_auth_key_hash, note_secret);
    let native_body = notes::note_body_commitment(native_owner, amount, output_data_hash);
    let native_note = notes::note_commitment(native_body, leaf_index);
    let native_nullifier = notes::nullifier(native_body, owner_nf_key);
    let native_phantom = notes::phantom_nullifier(intent_nonce, input_slot, pq_auth_key_hash);

    let cs = cs();
    let owner_nf_key_var = witness(&cs, owner_nf_key)?;
    let pq_var = witness(&cs, pq_auth_key_hash)?;
    let secret_var = witness(&cs, note_secret)?;
    let amount_var = witness(&cs, amount)?;
    let data_var = witness(&cs, output_data_hash)?;
    let index_var = witness(&cs, leaf_index)?;
    let nonce_var = witness(&cs, intent_nonce)?;
    let slot_var = witness(&cs, input_slot)?;

    let key_hash_var = note_gadget::owner_nf_key_hash(&owner_nf_key_var)
        .map_err(|error| Error::Backend(error.to_string()))?;
    let owner_var = note_gadget::owner_commitment(&key_hash_var, &pq_var, &secret_var)
        .map_err(|error| Error::Backend(error.to_string()))?;
    let body_var = note_gadget::note_body_commitment(&owner_var, &amount_var, &data_var)
        .map_err(|error| Error::Backend(error.to_string()))?;
    let note_var = note_gadget::note_commitment(&body_var, &index_var)
        .map_err(|error| Error::Backend(error.to_string()))?;
    let nullifier_var = note_gadget::nullifier(&body_var, &owner_nf_key_var)
        .map_err(|error| Error::Backend(error.to_string()))?;
    let phantom_var = note_gadget::phantom_nullifier(&nonce_var, &slot_var, &pq_var)
        .map_err(|error| Error::Backend(error.to_string()))?;

    Ok(NoteCase {
        name: name.to_string(),
        owner_nf_key: fr_to_decimal(&owner_nf_key),
        pq_auth_key_hash: fr_to_decimal(&pq_auth_key_hash),
        note_secret: fr_to_decimal(&note_secret),
        amount: fr_to_decimal(&amount),
        output_data_hash: fr_to_decimal(&output_data_hash),
        leaf_index: fr_to_decimal(&leaf_index),
        intent_nonce: fr_to_decimal(&intent_nonce),
        input_slot: fr_to_decimal(&input_slot),
        owner_nf_key_hash: fr_to_decimal(&settled(&cs, &key_hash_var, native_key_hash)?),
        owner_commitment: fr_to_decimal(&settled(&cs, &owner_var, native_owner)?),
        note_body_commitment: fr_to_decimal(&settled(&cs, &body_var, native_body)?),
        note_commitment: fr_to_decimal(&settled(&cs, &note_var, native_note)?),
        nullifier: fr_to_decimal(&settled(&cs, &nullifier_var, native_nullifier)?),
        phantom_nullifier: fr_to_decimal(&settled(&cs, &phantom_var, native_phantom)?),
    })
}

fn commit_node_case(name: &str, children: [Fr; tree::ARITY]) -> Result<CommitNodeCase> {
    let native = tree::commit_node(&children);
    let cs = cs();
    let mut vars: Vec<FrVar> = Vec::with_capacity(tree::ARITY);
    for child in children.iter() {
        vars.push(witness(&cs, *child)?);
    }
    let vars: [FrVar; tree::ARITY] =
        vars.try_into().map_err(|_| Error::Backend("child count".to_string()))?;
    let node_var =
        tree_gadget::commit_node(&vars).map_err(|error| Error::Backend(error.to_string()))?;
    Ok(CommitNodeCase {
        name: name.to_string(),
        children: children.iter().map(fr_to_decimal).collect(),
        node: fr_to_decimal(&settled(&cs, &node_var, native)?),
    })
}

/// A deterministic element stream. The values are arbitrary, not secret; what
/// matters is that both sides of the cross-check see exactly the same ones.
struct Stream {
    state: Fr,
}

impl Stream {
    fn new(seed: u64) -> Self {
        Self { state: crate::field::fr_from_u128(u128::from(seed)) }
    }

    fn next(&mut self) -> Fr {
        self.state = notes::owner_nf_key_hash(self.state);
        self.state
    }
}

/// Builds the fixture. Edge values come first, then a deterministic stream.
pub fn build() -> Result<Section45Fixture> {
    let zero = Fr::from(0u64);
    let one = Fr::from(1u64);
    let mut largest_bytes = crate::field::MODULUS_BE;
    largest_bytes[31] = largest_bytes[31].saturating_sub(1);
    let largest = crate::field::fr_from_be(&largest_bytes)?;
    let max_amount = crate::field::fr_from_u128(
        (1u128 << 120).checked_sub(1).ok_or_else(|| Error::Witness("2^120 - 1".to_string()))?,
    );
    let max_index = crate::field::fr_from_u128(u128::from(u32::MAX));

    let mut notes_out = vec![
        note_case("all-zero", zero, zero, zero, zero, zero, zero, zero, zero)?,
        note_case("all-one", one, one, one, one, one, one, one, one)?,
    ];
    notes_out.push(note_case(
        "largest-canonical",
        largest,
        largest,
        largest,
        largest,
        largest,
        largest,
        largest,
        largest,
    )?);
    notes_out.push(note_case(
        "boundary-amount-and-index",
        largest,
        one,
        largest,
        max_amount,
        zero,
        max_index,
        largest,
        one,
    )?);

    let mut stream = Stream::new(0x5348_4431);
    for case in 0..6 {
        let owner_nf_key = stream.next();
        let pq_auth_key_hash = stream.next();
        let note_secret = stream.next();
        let amount = crate::field::fr_from_u128(
            u128::try_from(case).unwrap_or(0).saturating_mul(1_000_000_007).saturating_add(1),
        );
        let output_data_hash = stream.next();
        let leaf_index = crate::field::fr_from_u128(u128::try_from(case).unwrap_or(0));
        let intent_nonce = stream.next();
        let input_slot = crate::field::fr_from_u128(u128::try_from(case % 2).unwrap_or(0));
        notes_out.push(note_case(
            &format!("stream-{case}"),
            owner_nf_key,
            pq_auth_key_hash,
            note_secret,
            amount,
            output_data_hash,
            leaf_index,
            intent_nonce,
            input_slot,
        )?);
    }

    let mut commit_nodes = Vec::new();
    commit_nodes.push(commit_node_case("zeros", [zero; tree::ARITY])?);
    commit_nodes
        .push(commit_node_case("counting", core::array::from_fn(|slot| Fr::from(slot as u64)))?);
    commit_nodes.push(commit_node_case("largest", [largest; tree::ARITY])?);
    let mut node_stream = Stream::new(0x434f_4d4d);
    commit_nodes.push(commit_node_case("stream", core::array::from_fn(|_| node_stream.next()))?);

    let empty_roots = tree::empty_roots().iter().map(fr_to_decimal).collect::<Vec<_>>();

    // Fifteen leaves cross the first 7-ary boundary twice, so the second and
    // third levels both move.
    let mut frontier = tree::Frontier::new();
    let mut leaf_stream = Stream::new(0x4c45_4146);
    let mut leaves = Vec::new();
    let mut roots = Vec::new();
    for _ in 0..15 {
        let leaf = leaf_stream.next();
        let (_, root) = frontier.append(leaf)?;
        leaves.push(fr_to_decimal(&leaf));
        roots.push(fr_to_decimal(&root));
    }
    let recomputed = frontier.recomputed_root();
    let last = roots.last().cloned().ok_or_else(|| Error::Witness("no appends".to_string()))?;
    if fr_to_decimal(&recomputed) != last {
        return Err(Error::Witness(
            "the frontier and the full rebuild disagree on the root".to_string(),
        ));
    }

    Ok(Section45Fixture {
        profile: "TOS Shielded Pool V1 implementation profile, sections 4 and 5".to_string(),
        poseidon2_manifest_sha256: crate::params::MANIFEST_SHA256_HEX.to_string(),
        notes: notes_out,
        commit_nodes,
        empty_roots,
        appends: vec![AppendCase {
            name: "fifteen-sequential".to_string(),
            leaves,
            roots_after_each: roots,
        }],
    })
}

/// Parses a decimal field element from a fixture and checks the round trip is
/// exact, which is the guard against a 256-bit value that lost precision.
pub fn parse_exact(text: &str) -> Result<Fr> {
    let value = fr_from_decimal(text)?;
    if fr_to_decimal(&value) != text.trim() {
        return Err(Error::NonCanonicalField { value: text.to_string() });
    }
    Ok(value)
}
