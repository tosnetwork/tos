//! Diagnostic bridge: encode a live rehearsal order with the production pool builder.
//! No key or signing operation is performed here; the node supplies the authorization.

use anyhow::{Context, Result};
use chain_block::{read_single_root_boc, write_boc};
use contracts::nominator::{NewStakeParams, new_stake_with_witness};
use serde::Deserialize;
use std::io::Read;

#[derive(Deserialize)]
struct OrderInput {
    query_id: u64,
    stake_amount: u64,
    stake_at: u32,
    max_factor: u32,
    adnl_addr_hex: String,
    public_key_hex: String,
    signature_hex: String,
    witness_boc_hex: String,
}

fn main() -> Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let input: OrderInput = serde_json::from_str(&input).context("pool order input JSON")?;
    let adnl = hex::decode(&input.adnl_addr_hex).context("ADNL address hex")?;
    let public_key = hex::decode(&input.public_key_hex).context("PQ public key hex")?;
    let signature = hex::decode(&input.signature_hex).context("PQ signature hex")?;
    let witness = read_single_root_boc(
        hex::decode(&input.witness_boc_hex).context("controller witness hex")?,
    )
    .context("controller birth witness BOC")?;
    let body = new_stake_with_witness(
        &NewStakeParams {
            query_id: input.query_id,
            stake_amount: input.stake_amount,
            validator_pubkey: &public_key,
            stake_at: input.stake_at,
            max_factor: input.max_factor,
            adnl_addr: &adnl,
            signature: &signature,
        },
        Some(&witness),
    )?;
    println!("{}", hex::encode(write_boc(&body)?));
    Ok(())
}
