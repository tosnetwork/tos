//! Explicit operating deposits for immutable validator controllers.
use chain_block::{BuilderData, Cell, Coins, IBitstring, MsgAddressInt, Serializable};

pub const FUND_OPERATIONS_KIND: u8 = 4;
pub const WITHDRAW_OPERATIONS_KIND: u8 = 5;

/// All values are explicit; a balance transfer alone never authorizes sponsorship.
/// Monetary values use nano-TOS. The signed request must be sent by `payer`.
pub struct OperatingFunding<'a> {
    pub payer: &'a MsgAddressInt,
    pub deposit: u128,
    pub allowance: u128,
    pub per_request_limit: u128,
    pub storage_floor: u128,
    pub expires_at: u32,
}

/// Payload for the root's existing PQCA signature domain, kind 4. This does not
/// sign or submit a transaction, or choose a deposit/allowance for the operator.
pub fn operating_funding_payload(config: &OperatingFunding<'_>) -> anyhow::Result<Cell> {
    let mut body = BuilderData::new();
    config.payer.write_to(&mut body)?;
    for amount in [config.deposit, config.allowance, config.per_request_limit, config.storage_floor]
    {
        anyhow::ensure!(amount < (1u128 << 120), "operating amount exceeds VarUInteger16");
        Coins::try_from(amount)?.write_to(&mut body)?;
    }
    body.append_u32(config.expires_at)?;
    Ok(body.into_cell()?)
}

/// Payload for root action kind 5. Only explicitly deposited, unreserved
/// operating funds can be withdrawn, and no relay may remain pending.
pub fn operating_withdrawal_payload(payer: &MsgAddressInt, amount: u128) -> anyhow::Result<Cell> {
    anyhow::ensure!(amount < (1u128 << 120), "operating amount exceeds VarUInteger16");
    let mut body = BuilderData::new();
    payer.write_to(&mut body)?;
    Coins::try_from(amount)?.write_to(&mut body)?;
    Ok(body.into_cell()?)
}
