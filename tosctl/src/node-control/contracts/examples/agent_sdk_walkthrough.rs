//! Standalone walkthrough of the `contracts` crate as a Rust SDK for
//! constructing native AI-actor contract state and messages.
//!
//! This deliberately does not touch `tosctl`'s CLI, vault or JSON-RPC
//! plumbing: every value here is built with only the public API of this
//! crate, to show that Agent Account / Task Escrow deploy state and
//! lifecycle messages can be constructed by an external Rust integrator
//! that links against this crate directly.
//!
//! Run with: `cargo run --example agent_sdk_walkthrough -p contracts`

use chain_block::{Cell, MsgAddressInt, Serializable, base64_encode, write_boc};
use contracts::{AgentAccountContract, AgentAccountInit, TaskEscrowContract, TaskEscrowInit};
use ed25519_dalek::{Signer, SigningKey};

fn print_cell(label: &str, cell: &Cell) -> anyhow::Result<()> {
    println!("{label}: {}", base64_encode(write_boc(cell)?));
    Ok(())
}

fn main() -> anyhow::Result<()> {
    // A real integrator would derive this from their own key management;
    // this SDK never dictates how keys are stored.
    let controller = SigningKey::from_bytes(&[0x42; 32]);
    let controller_pubkey = controller.verifying_key().to_bytes();

    let owner = MsgAddressInt::with_standart(None, -1, [0x11; 32].into())?;

    // --- Agent Account: deploy state ---
    let agent_init = AgentAccountInit {
        owner: owner.clone(),
        controller_pubkey,
        max_per_tx: 500_000_000,
        daily_limit: 5_000_000_000,
        default_task_timeout_secs: 3_600,
        metadata_hash: None,
        service_endpoint_hash: None,
    };
    let agent_address = AgentAccountContract::calculate_address(-1, &agent_init)?;
    println!("agent account address: {agent_address}");
    print_cell(
        "agent account state init",
        &AgentAccountContract::build_state_init(&agent_init)?.write_to_new_cell()?.into_cell()?,
    )?;

    // --- Agent Account: a controller-signed task-send message ---
    let task_escrow_placeholder = MsgAddressInt::with_standart(None, -1, [0x22; 32].into())?;
    let payload = AgentAccountContract::build_task_send_payload(
        /* seqno */ 0,
        /* valid_until */ 1_900_000_000,
        &task_escrow_placeholder,
        /* value */ 100_000_000,
        TaskEscrowContract::accept(1)?,
    )?;
    let hash_to_sign = AgentAccountContract::task_send_hash_to_sign(&agent_address, &payload)?;
    let signature: [u8; 64] = controller.sign(&hash_to_sign).to_bytes();
    let signed = AgentAccountContract::build_signed_task_send_message(payload, &signature)?;
    let external = AgentAccountContract::build_external_task_send_message(agent_address, signed)?;
    print_cell("signed external task-send message", &external)?;

    // --- Task Escrow: deploy state, with an inline settlement attestor ---
    let attestor = SigningKey::from_bytes(&[0x99; 32]);
    let attestor_pubkey = attestor.verifying_key().to_bytes();
    let result_hash = [0x55; 32];
    let task_init = TaskEscrowInit {
        creator: owner.clone(),
        assigned_agent: None,
        verifier: None,
        budget: 1_000_000_000,
        deadline: 1_900_000_000,
        review_period: 3_600,
        settlement_policy_hash: [0x33; 32],
        permission_hash: [0x44; 32],
        attestor_pubkey: Some(attestor_pubkey),
    };
    let task_address = TaskEscrowContract::calculate_address(-1, &task_init)?;
    println!("task escrow address: {task_address}");
    print_cell(
        "task escrow state init",
        &TaskEscrowContract::build_state_init(&task_init)?.write_to_new_cell()?.into_cell()?,
    )?;

    // --- Task Escrow: lifecycle message bodies ---
    print_cell("accept message body", &TaskEscrowContract::accept(1)?)?;
    print_cell("result message body", &TaskEscrowContract::result(2, result_hash, [0x66; 32])?)?;

    // Because this task was deployed with an attestor_pubkey, settle requires
    // a signature over contracts::settle_domain_hash(task_address, result_hash,
    // payout) under that key -- not the bare result_hash, and not just
    // result_hash alone: the payout is part of what the attestor signs off
    // on too, so one signature can't be replayed to authorize a different
    // payout. The attestor is independent of the creator/verifier who
    // authorizes the settle call.
    let payout = task_init.budget;
    let domain_hash = contracts::settle_domain_hash(&task_address, &result_hash, payout)?;
    let attestation: [u8; 64] = attestor.sign(&domain_hash).to_bytes();
    print_cell(
        "settle message body (attested)",
        &TaskEscrowContract::settle_signed(3, payout, &attestation)?,
    )?;

    println!(
        "\nAll state and messages above were built without tosctl, a vault, or a network call; \
         submitting them is the caller's responsibility (any JSON-RPC client that can send an \
         external/internal message with the given StateInit/body)."
    );
    Ok(())
}
