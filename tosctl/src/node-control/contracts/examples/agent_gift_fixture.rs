use chain_block::{MsgAddressInt, base64_encode, ed25519_create_private_key, write_boc};
use contracts::{AgentAccountContract, AgentAccountInit};

const EXPECTED_BOC_BASE64: &str = "te6ccgEBAgEApgABRYn/gcFMuh/DSQZFasqNaT3ITOt7HHKnDMUAP9yhpWvoLEIMAQD7qWXpKJPScATturw4khEH749KXPRHgxeHEe/xQnydpujylIqd7JfcJr42YcyR+CxCy9kgme+pEhmIeRPzWqBYBUFHUAQAAAAqAAAAAAAAAAAAAAAAdzWUAIAEREREREREREREREREREREREREREREREREREREREREREh3NZQB";

fn main() -> anyhow::Result<()> {
    let secret = [0x42; 32];
    let key = ed25519_create_private_key(&secret)?;
    let owner = MsgAddressInt::with_params(-1, [0x11; 32])?;
    let target = MsgAddressInt::with_params(0, [0x22; 32])?;
    let init = AgentAccountInit {
        owner,
        controller_pubkey: key.verifying_key(),
        deployment_id: [0x55; 32],
        max_per_tx: 5_000_000_000,
        daily_limit: 6_000_000_000,
        default_task_timeout_secs: 3_600,
        metadata_hash: None,
        service_endpoint_hash: None,
    };
    let account = AgentAccountContract::calculate_address(-1, &init)?;
    let payload = AgentAccountContract::build_native_send_payload(
        42,
        0,
        0,
        2_000_000_000,
        &target,
        1_000_000_000,
    )?;
    let hash = AgentAccountContract::controller_hash_to_sign(&account, 42, &payload)?;
    let signature = key.sign(&hash);
    let signed = AgentAccountContract::build_signed_controller_message(payload, &signature)?;
    let message = AgentAccountContract::build_external_controller_message(account.clone(), signed)?;
    let boc = write_boc(&message)?;
    let encoded_boc = base64_encode(boc);
    anyhow::ensure!(
        encoded_boc == EXPECTED_BOC_BASE64,
        "Agent Account interface drifted from the frozen cross-implementation fixture: {encoded_boc}"
    );
    println!(
        "{}",
        serde_json::json!({
            "schema": "tos.agent-gift.rust-fixture.v1",
            "code_hash": hex::encode(AgentAccountContract::code()?.hash(0)),
            "account": account.to_string(),
            "controller_public_key": hex::encode(key.verifying_key()),
            "target": target.to_string(),
            "global_id": 42,
            "controller_epoch": 0,
            "seqno": 0,
            "valid_until": 2_000_000_000u32,
            "amount_atomic": "1000000000",
            "exact_signed_boc": encoded_boc,
        })
    );
    Ok(())
}
