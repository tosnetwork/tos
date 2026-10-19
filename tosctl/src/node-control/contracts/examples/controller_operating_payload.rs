//! Encode an explicit operating deposit for offline root authorization.
//! All monetary arguments are decimal nano-TOS; this command never submits funds.
use anyhow::{Context, Result, ensure};
use contracts::validator_controller::{OperatingFunding, operating_funding_payload};
use std::str::FromStr;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() == 3 && args[0] == "withdraw" {
        let payer = chain_block::MsgAddressInt::from_str(&args[1]).context("payer address")?;
        let amount = args[2].parse().context("withdrawal amount")?;
        let payload =
            contracts::validator_controller::operating_withdrawal_payload(&payer, amount)?;
        println!("{}", chain_block::base64_encode(chain_block::write_boc(&payload)?));
        return Ok(());
    }
    ensure!(
        args.len() == 6,
        "usage: controller_operating_payload PAYER DEPOSIT ALLOWANCE PER_REQUEST_LIMIT STORAGE_FLOOR EXPIRES_AT; or: withdraw PAYER AMOUNT"
    );
    let payer = chain_block::MsgAddressInt::from_str(&args[0]).context("payer address")?;
    let payload = operating_funding_payload(&OperatingFunding {
        payer: &payer,
        deposit: args[1].parse().context("deposit")?,
        allowance: args[2].parse().context("allowance")?,
        per_request_limit: args[3].parse().context("per-request limit")?,
        storage_floor: args[4].parse().context("storage floor")?,
        expires_at: args[5].parse().context("sponsorship expiry")?,
    })?;
    println!("{}", chain_block::base64_encode(chain_block::write_boc(&payload)?));
    Ok(())
}
