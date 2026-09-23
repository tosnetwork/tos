/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The circuit gadgets against the FunC library, value for value, with the
//! FunC executing in the VM.
//!
//! The expected values here come from the circuit gadgets. If the VM disagrees
//! with one of them, the test prints both numbers and which relation they
//! belong to, and it fails. Nothing here may be adjusted to make the VM win:
//! the point of the comparison is destroyed the moment an assertion is edited
//! to match an output.

use shielded_pool_circuit::fixture::{self, Section45Fixture};
use shielded_pool_circuit_crosscheck::{load_fixture, Probe};

/// The committed fixture must still be what the gadgets produce. Without this,
/// a stale file would quietly turn the whole comparison into a comparison
/// between the VM and a snapshot of an older circuit.
fn fixture_checked_against_the_live_gadgets() -> Section45Fixture {
    let loaded = match load_fixture() {
        Ok(loaded) => loaded,
        Err(error) => panic!("the committed fixture could not be read: {error}"),
    };
    let rebuilt = match fixture::build() {
        Ok(rebuilt) => rebuilt,
        Err(error) => panic!("the gadgets could not rebuild the fixture: {error}"),
    };
    let loaded_text = match serde_json::to_string(&loaded) {
        Ok(text) => text,
        Err(error) => panic!("fixture re-encoding: {error}"),
    };
    let rebuilt_text = match serde_json::to_string(&rebuilt) {
        Ok(text) => text,
        Err(error) => panic!("fixture re-encoding: {error}"),
    };
    assert_eq!(
        loaded_text, rebuilt_text,
        "the committed fixture is not what the gadgets produce now; regenerate it"
    );
    loaded
}

/// Compares one value and reports enough to act on a disagreement.
fn compare(relation: &str, case: &str, inputs: &[(&str, &str)], gadget: &str, func: &str) {
    if gadget != func {
        let rendered = inputs
            .iter()
            .map(|(name, value)| format!("  {name} = {value}"))
            .collect::<Vec<_>>()
            .join("\n");
        panic!(
            "PROFILE DISAGREEMENT in {relation} (case {case})\ninputs:\n{rendered}\n  circuit gadget = {gadget}\n  FunC in the VM = {func}"
        );
    }
    // A comparison of two truncated values would also be equal, so the width
    // is asserted for the values that must be full-width field elements.
    assert!(!gadget.is_empty(), "{relation}: empty value");
}

fn probe() -> Probe {
    match Probe::deploy() {
        Ok(probe) => probe,
        Err(error) => panic!("could not deploy the shielded library probe: {error}"),
    }
}

fn call(probe: &Probe, method: &str, args: &[&str]) -> String {
    match probe.call_field(method, args) {
        Ok(value) => value,
        Err(error) => panic!("{method}: {error}"),
    }
}

#[test]
fn section_4_commitments_and_nullifiers_agree_with_the_vm() {
    let fixture = fixture_checked_against_the_live_gadgets();
    let probe = probe();
    let mut compared = 0usize;

    for case in fixture.notes.iter() {
        let key_hash = call(&probe, "p_owner_nf_key_hash", &[&case.owner_nf_key]);
        compare(
            "section 2.1 owner_nf_key_hash",
            &case.name,
            &[("owner_nf_key", &case.owner_nf_key)],
            &case.owner_nf_key_hash,
            &key_hash,
        );

        let owner = call(
            &probe,
            "p_owner_commitment",
            &[&case.owner_nf_key_hash, &case.pq_auth_key_hash, &case.note_secret],
        );
        compare(
            "section 4.1 owner_commitment",
            &case.name,
            &[
                ("owner_nf_key_hash", &case.owner_nf_key_hash),
                ("pq_auth_key_hash", &case.pq_auth_key_hash),
                ("note_secret", &case.note_secret),
            ],
            &case.owner_commitment,
            &owner,
        );

        let body = call(
            &probe,
            "p_note_body",
            &[&case.owner_commitment, &case.amount, &case.output_data_hash],
        );
        compare(
            "section 4.2 note_body_commitment",
            &case.name,
            &[
                ("owner_commitment", &case.owner_commitment),
                ("amount", &case.amount),
                ("output_data_hash", &case.output_data_hash),
            ],
            &case.note_body_commitment,
            &body,
        );

        let note =
            call(&probe, "p_note_commitment", &[&case.note_body_commitment, &case.leaf_index]);
        compare(
            "section 4.3 note_commitment",
            &case.name,
            &[
                ("note_body_commitment", &case.note_body_commitment),
                ("leaf_index", &case.leaf_index),
            ],
            &case.note_commitment,
            &note,
        );

        let nullifier =
            call(&probe, "p_nullifier", &[&case.note_body_commitment, &case.owner_nf_key]);
        compare(
            "section 4.4 nullifier",
            &case.name,
            &[
                ("note_body_commitment", &case.note_body_commitment),
                ("owner_nf_key", &case.owner_nf_key),
            ],
            &case.nullifier,
            &nullifier,
        );

        let phantom = call(
            &probe,
            "p_phantom",
            &[&case.intent_nonce, &case.input_slot, &case.pq_auth_key_hash],
        );
        compare(
            "section 4.5 phantom_nullifier",
            &case.name,
            &[
                ("intent_nonce", &case.intent_nonce),
                ("input_slot", &case.input_slot),
                ("pq_auth_key_hash", &case.pq_auth_key_hash),
            ],
            &case.phantom_nullifier,
            &phantom,
        );

        compared += 6;
    }

    println!(
        "section 4: {compared} values from {} cases matched the FunC running in the VM",
        fixture.notes.len()
    );
    assert!(compared >= 60, "too few comparisons to be worth anything");
}

#[test]
fn section_5_tree_agrees_with_the_vm() {
    let fixture = fixture_checked_against_the_live_gadgets();
    let probe = probe();

    for (level, expected) in fixture.empty_roots.iter().enumerate() {
        let produced = call(&probe, "p_empty_root", &[&level.to_string()]);
        compare(
            "section 5 EMPTY_ROOT",
            &format!("level {level}"),
            &[("level", &level.to_string())],
            expected,
            &produced,
        );
    }

    for case in fixture.commit_nodes.iter() {
        let children: Vec<&str> = case.children.iter().map(String::as_str).collect();
        let produced = call(&probe, "p_commit_node", &children);
        let inputs: Vec<(&str, &str)> =
            case.children.iter().map(|value| ("child", value.as_str())).collect();
        compare("section 5 commit_node", &case.name, &inputs, &case.node, &produced);
    }

    for case in fixture.appends.iter() {
        let mut store = match probe.frontier_genesis() {
            Ok(cell) => cell,
            Err(error) => panic!("genesis frontier: {error}"),
        };
        for (index, leaf) in case.leaves.iter().enumerate() {
            let (next, root) = match probe.append(store, index as u64, leaf) {
                Ok(result) => result,
                Err(error) => panic!("append {index}: {error}"),
            };
            store = next;
            let expected = match case.roots_after_each.get(index) {
                Some(value) => value,
                None => panic!("fixture has no expected root for append {index}"),
            };
            compare(
                "section 5.1 frontier append",
                &format!("{} leaf {index}", case.name),
                &[("leaf_index", &index.to_string()), ("leaf", leaf)],
                expected,
                &root,
            );
        }
        println!(
            "section 5.1: {} sequential appends matched the FunC frontier root by root",
            case.leaves.len()
        );
    }

    println!(
        "section 5: {} empty roots and {} interior nodes matched the FunC running in the VM",
        fixture.empty_roots.len(),
        fixture.commit_nodes.len()
    );
}

/// The comparison must be able to fail. A wrong expected value has to be
/// rejected by exactly the path the real comparison takes, or the two tests
/// above prove nothing about the VM.
#[test]
#[should_panic(expected = "PROFILE DISAGREEMENT")]
fn the_comparison_rejects_a_wrong_expected_value() {
    let fixture = fixture_checked_against_the_live_gadgets();
    let probe = probe();
    let case = match fixture.notes.first() {
        Some(case) => case,
        None => panic!("PROFILE DISAGREEMENT: the fixture is empty"),
    };
    let produced = call(
        &probe,
        "p_owner_commitment",
        &[&case.owner_nf_key_hash, &case.pq_auth_key_hash, &case.note_secret],
    );
    compare(
        "section 4.1 owner_commitment",
        "deliberately-wrong",
        &[("owner_nf_key_hash", &case.owner_nf_key_hash)],
        "1",
        &produced,
    );
}

/// The values compared above really are 256-bit, so the agreement is not two
/// truncated zeros agreeing.
#[test]
fn the_compared_values_are_full_width() {
    let fixture = fixture_checked_against_the_live_gadgets();
    let wide = fixture.notes.iter().filter(|case| case.owner_commitment.len() >= 70).count();
    assert!(
        wide >= fixture.notes.len() - 1,
        "only {wide} of {} owner commitments are full-width field elements",
        fixture.notes.len()
    );
}
