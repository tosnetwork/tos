//! The public proving path uses the final key and never the seeded fixture.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use ark_ff::AdditiveGroup;
use shielded_pool_ceremony::{
    audit::{audit, Audited, StartingKey},
    record::Directory,
};
use shielded_pool_circuit::{
    circuit::TransactionWitness, field::Fr, public_inputs::PublicInputs, scenario,
};
use shielded_pool_circuit_crosscheck::public_client::PublicClient;
use std::{path::PathBuf, sync::OnceLock};

const VK: &str = "49696f52f361817869f68c3ba68d0d5a854737a4133ae4616255ac4a3846778c";
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}
fn finished() -> Directory {
    Directory::at(root().join("artifacts/phase2-ceremony-2/ceremony"))
}
fn unfinished() -> Directory {
    Directory::at(root().join("artifacts/phase2-ceremony-2/participant-contribution-1/ceremony"))
}
struct Audits {
    finished: Audited,
    unfinished: Audited,
}
fn audits() -> &'static Audits {
    static AUDITS: OnceLock<Audits> = OnceLock::new();
    AUDITS.get_or_init(|| {
        let start = StartingKey::rebuild().expect("committed slice");
        Audits {
            finished: audit(&finished(), &start).expect("finished ceremony 2"),
            unfinished: audit(&unfinished(), &start).expect("participant prefix"),
        }
    })
}
fn client() -> PublicClient {
    PublicClient::load(&finished(), &audits().finished, VK, 2, &[9; 32]).expect("public client")
}
fn request(client: &PublicClient) -> (PublicInputs, TransactionWitness) {
    let (_, mut public, witness) = scenario::valid_transfer().expect("synthetic unfunded witness");
    public.execution_domain = client.execution_domain();
    (scenario::reseal(&public, &witness), witness)
}
fn refusal(result: impl IntoIterator<Item = String>, expected: &str) {
    let messages: Vec<_> = result.into_iter().collect();
    assert_eq!(messages.len(), 1, "request did not refuse");
    assert!(messages[0].contains(expected), "wrong refusal: {messages:?}");
}
#[test]
fn only_a_finished_unchanged_key_matching_the_reviewed_vk_is_loaded() {
    assert_eq!(audits().finished.vk_sha256(), VK);
    refusal(
        PublicClient::load(&finished(), &audits().finished, &"00".repeat(32), 2, &[9; 32])
            .err()
            .map(|e| e.to_string()),
        "reviewed deployment",
    );
    refusal(
        PublicClient::load(
            &unfinished(),
            &audits().unfinished,
            audits().unfinished.vk_sha256(),
            2,
            &[9; 32],
        )
        .err()
        .map(|e| e.to_string()),
        "finished audited ceremony",
    );
    refusal(
        PublicClient::load(&unfinished(), &audits().finished, VK, 2, &[9; 32])
            .err()
            .map(|e| e.to_string()),
        "changed after audit",
    );
    let _ = client();
}
#[test]
fn repeated_proofs_of_the_same_witness_have_fresh_full_width_randomness() {
    let client = client();
    let (public, witness) = request(&client);
    let a = client.prove(public, witness.clone(), 1_799_999_900).expect("first proof");
    let b = client.prove(public, witness, 1_799_999_900).expect("second proof");
    assert_ne!(a.flat(), b.flat(), "public proofs reused fixture randomness");
}
#[test]
fn wrong_pool_network_zero_secrets_and_bad_expiry_refuse_before_proving() {
    let client = client();
    let (public, witness) = request(&client);
    for domain in [
        shielded_pool_circuit::wire::execution_domain(3, &[9; 32]),
        shielded_pool_circuit::wire::execution_domain(2, &[8; 32]),
    ] {
        let wrong = PublicInputs { execution_domain: domain, ..public };
        refusal(
            client.prove(wrong, witness.clone(), 1_799_999_900).err().map(|e| e.to_string()),
            "execution domain",
        );
    }
    let mut weak = witness.clone();
    weak.intent_nonce = Fr::ZERO;
    refusal(
        client.prove(public, weak, 1_799_999_900).err().map(|e| e.to_string()),
        "must be non-zero",
    );
    for slot in 0..3 {
        let mut weak = witness.clone();
        weak.outputs[slot].note_secret = Fr::ZERO;
        refusal(
            client.prove(public, weak, 1_799_999_900).err().map(|e| e.to_string()),
            "must be non-zero",
        );
    }
    for expiry in [1_799_999_899_u64, 1_800_003_501] {
        let wrong = PublicInputs { valid_until: Fr::from(expiry), ..public };
        refusal(
            client.prove(wrong, witness.clone(), 1_799_999_900).err().map(|e| e.to_string()),
            "one-hour window",
        );
    }
    let wrong = PublicInputs {
        valid_until: Fr::from(u64::from(u32::MAX).checked_add(1).unwrap()),
        ..public
    };
    refusal(
        client.prove(wrong, witness, 1_799_999_900).err().map(|e| e.to_string()),
        "exceeds uint32",
    );
}
#[test]
fn every_validity_boundary_and_private_entropy_constraint_reaches_a_real_proof() {
    let client = client();
    let (mut public, witness) = request(&client);
    for expiry in [1_799_999_900_u32, 1_800_003_500] {
        public.valid_until = Fr::from(expiry);
        public = scenario::reseal(&public, &witness);
        client.prove(public, witness.clone(), 1_799_999_900).expect("inclusive validity boundary");
    }
    // A non-zero but inconsistent witness reaches the proof backend and must
    // not return unverified bytes or include private details in its error.
    let mut wrong = witness;
    wrong.outputs[0].amount = Fr::from(1u64);
    let error = client.prove(public, wrong, 1_799_999_900).err().expect("bad conservation");
    assert!(matches!(
        error.to_string().as_str(),
        "fixture: private proof construction failed" | "fixture: constructed proof does not verify"
    ));
}
