//! What an operator wallet spends, besides the value, to send one message in the
//! mode tosctl uses (pay fees separately, ignore action errors).
//!
//! Mode 3 means a wallet that cannot pay its fees still accepts the external message
//! and advances its seqno, but sends nothing. The reserve below is therefore checked
//! before sending, and is an upper bound of the wallet's own charge: storage accrued
//! since it last paid plus any storage debt it already carries, its computation, the
//! import of the external message, and the forwarding of the outbound one.
//!
//! The storage terms come from the account's own storage metadata (used cells and
//! bits, last paid, due payment), never from an estimate: code and data alone omit
//! the account's library dictionary, its extra currencies under older global
//! versions, and any debt.
use crate::validator_controller::{forward_fee, gas_fee};
use chain_block::{Account, Cell, GasLimitsPrices, MsgForwardPrices, StoragePrices, UInt256};
use std::collections::HashSet;

/// An upper bound for the computation of any supported wallet sending one message.
pub const WALLET_SEND_GAS_BOUND: u64 = 20_000;
/// Bits around a body: the signed external message (signature, wallet header, an
/// inline internal message header) and the outbound message header, generously.
pub const ENVELOPE_BITS: u64 = 1_600;
/// Cells around a body in either message.
pub const ENVELOPE_CELLS: u64 = 2;
/// Far beyond any message a wallet can send; a guard against an unbounded walk.
const MAX_MESSAGE_CELLS: usize = 1 << 16;

/// Distinct cells and their data bits under `roots`, as the forwarding and storage
/// fees count them. Unlike a proposal value, a whole message has no 1024-cell limit.
pub fn tree_size(roots: &[&Cell]) -> anyhow::Result<(u64, u64)> {
    let mut seen: HashSet<UInt256> = HashSet::new();
    let mut stack: Vec<Cell> = roots.iter().map(|cell| (*cell).clone()).collect();
    let (mut cells, mut bits) = (0u64, 0u64);
    while let Some(cell) = stack.pop() {
        if !seen.insert(cell.repr_hash()) {
            continue;
        }
        anyhow::ensure!(seen.len() <= MAX_MESSAGE_CELLS, "more than {MAX_MESSAGE_CELLS} cells");
        cells = cells.checked_add(1).ok_or_else(|| anyhow::anyhow!("cell count overflows"))?;
        bits = u64::try_from(cell.bit_length())
            .ok()
            .and_then(|length| bits.checked_add(length))
            .ok_or_else(|| anyhow::anyhow!("bit count overflows"))?;
        for index in 0..cell.references_count() {
            stack.push(cell.reference(index)?);
        }
    }
    Ok((cells, bits))
}

/// A wallet's storage, as the storage phase sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalletStorage {
    pub cells: u64,
    pub bits: u64,
    /// When the wallet last paid for storage.
    pub last_paid: u32,
    /// Storage debt already recorded on the account, charged with the next fees.
    pub due_payment: u128,
}

impl WalletStorage {
    /// The storage metadata the account itself records.
    pub fn from_account(account: &Account) -> anyhow::Result<Self> {
        let info = account
            .storage_info()
            .ok_or_else(|| anyhow::anyhow!("the wallet account does not exist"))?;
        Ok(Self {
            cells: info.used().cells(),
            bits: info.used().bits(),
            last_paid: info.last_paid(),
            due_payment: info.due_payment().map_or(0, |due| due.as_u128()),
        })
    }
}

/// What the storage phase charges at `now`: the recorded debt plus the masterchain
/// fees accrued over every price period since `last_paid`, rounded up per period as
/// the executor does.
pub fn storage_due(
    prices: &[StoragePrices],
    storage: &WalletStorage,
    now: u32,
) -> anyhow::Result<u128> {
    storage_accrued(prices, storage, now)?
        .checked_add(storage.due_payment)
        .ok_or_else(|| anyhow::anyhow!("storage fee overflows"))
}

fn storage_accrued(
    prices: &[StoragePrices],
    storage: &WalletStorage,
    now: u32,
) -> anyhow::Result<u128> {
    let overflow = || anyhow::anyhow!("storage fee overflows");
    let first = match prices.first() {
        Some(first) => first,
        None => return Ok(0),
    };
    if now <= storage.last_paid || storage.last_paid == 0 || now <= first.utime_since {
        return Ok(0);
    }
    let mut last_paid = storage.last_paid;
    let mut fee: u128 = 0;
    for (index, period) in prices.iter().enumerate() {
        let end = prices.get(index.saturating_add(1)).map_or(now, |next| next.utime_since);
        if end < last_paid {
            continue;
        }
        let delta = end.saturating_sub(period.utime_since.max(last_paid));
        let per_second = u128::from(storage.bits)
            .checked_mul(u128::from(period.mc_bit_price_ps))
            .and_then(|bit_part| {
                u128::from(storage.cells)
                    .checked_mul(u128::from(period.mc_cell_price_ps))
                    .and_then(|cell_part| bit_part.checked_add(cell_part))
            })
            .ok_or_else(overflow)?;
        let period_fee = per_second
            .checked_mul(u128::from(delta))
            .and_then(|value| value.checked_add(0xffff))
            .ok_or_else(overflow)?
            >> 16;
        fee = fee.checked_add(period_fee).ok_or_else(overflow)?;
        last_paid = end;
    }
    Ok(fee)
}

/// Everything the reserve is computed from, at one block.
pub struct SendFeeInputs<'a> {
    pub gas: &'a GasLimitsPrices,
    pub forward: &'a MsgForwardPrices,
    pub storage_prices: &'a [StoragePrices],
    pub storage: &'a WalletStorage,
    /// The latest time the message can execute at.
    pub now: u32,
    pub body: &'a Cell,
}

/// The wallet's own charge for sending `body` as one message, as an upper bound.
pub fn wallet_send_reserve(inputs: &SendFeeInputs<'_>) -> anyhow::Result<u128> {
    let overflow = || anyhow::anyhow!("fee reserve overflows");
    let (cells, bits) = tree_size(&[inputs.body])?;
    let message_fee = forward_fee(
        inputs.forward,
        bits.checked_add(ENVELOPE_BITS).ok_or_else(overflow)?,
        cells.checked_add(ENVELOPE_CELLS).ok_or_else(overflow)?,
    )?;
    let compute = gas_fee(inputs.gas, WALLET_SEND_GAS_BOUND)?;
    let storage = storage_due(inputs.storage_prices, inputs.storage, inputs.now)?;
    // The external message is imported and the outbound one forwarded: two envelopes.
    compute
        .checked_add(message_fee)
        .and_then(|sum| sum.checked_add(message_fee))
        .and_then(|sum| sum.checked_add(storage))
        .ok_or_else(overflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_block::{BuilderData, IBitstring};

    fn leaf(word: u32) -> Cell {
        let mut b = BuilderData::new();
        b.append_u32(word).unwrap();
        b.into_cell().unwrap()
    }

    /// A body holding a 1024-cell value plus its wrapper is over 1024 cells and must
    /// still be sized.
    #[test]
    fn a_message_larger_than_a_proposal_value_limit_is_sized() {
        let mut cell = leaf(0);
        for word in 1..1024u32 {
            let mut b = BuilderData::new();
            b.append_u32(word).unwrap();
            b.checked_append_reference(cell).unwrap();
            cell = b.into_cell().unwrap();
        }
        let mut wrapper = BuilderData::new();
        wrapper.append_u32(0xffff).unwrap();
        wrapper.checked_append_reference(cell).unwrap();
        let body = wrapper.into_cell().unwrap();
        assert_eq!(tree_size(&[&body]).unwrap(), (1025, 1025 * 32));
    }

    /// The largest proposal value the contract accepts (1024 distinct cells), wrapped
    /// in the new-proposal message, is a body of more than 1024 cells; its reserve is
    /// still computed.
    #[test]
    fn the_reserve_covers_a_body_around_the_largest_proposal_value() {
        use crate::config_contract::messages::proposal;
        let mut value = leaf(0);
        for word in 1..1024u32 {
            let mut b = BuilderData::new();
            b.append_u32(word).unwrap();
            b.checked_append_reference(value).unwrap();
            value = b.into_cell().unwrap();
        }
        assert_eq!(proposal::value_size(Some(&value)).unwrap().0, 1024, "the value is legal");
        let cell = proposal::proposal_cell(100, Some(value), None).unwrap();
        let body = proposal::new_proposal_body(1, 2_000_000, cell, false).unwrap();
        assert!(proposal::value_size(Some(&body)).is_err(), "the body exceeds the value limit");
        let gas = GasLimitsPrices { gas_price: 65_536, ..Default::default() };
        let forward = MsgForwardPrices {
            lump_price: 1,
            bit_price: 65_536,
            cell_price: 65_536,
            ..Default::default()
        };
        let storage = WalletStorage { cells: 3, bits: 100, last_paid: 1, due_payment: 0 };
        let reserve = wallet_send_reserve(&SendFeeInputs {
            gas: &gas,
            forward: &forward,
            storage_prices: &[],
            storage: &storage,
            now: 2,
            body: &body,
        })
        .unwrap();
        // 20 000 gas plus two envelopes: 1026 cells plus two, and the value (1024 x 32
        // bits), the proposal (42 bits) and the message (129 bits) plus the envelope.
        let envelope = 1 + (1026 + 2 + 1024 * 32 + 42 + 129 + ENVELOPE_BITS as u128);
        assert_eq!(reserve, 20_000 + 2 * envelope);
    }

    #[test]
    fn storage_due_spans_price_periods_and_rounds_up() {
        let prices = [
            StoragePrices {
                utime_since: 0,
                mc_bit_price_ps: 1,
                mc_cell_price_ps: 500,
                ..Default::default()
            },
            StoragePrices {
                utime_since: 1_000,
                mc_bit_price_ps: 2,
                mc_cell_price_ps: 1_000,
                ..Default::default()
            },
        ];
        let storage = WalletStorage { cells: 3, bits: 100, last_paid: 900, due_payment: 0 };
        // 100 s at (100 + 1500) and 500 s at (200 + 3000), each rounded up.
        let first = (100 * 1_600 + 0xffff) >> 16;
        let second = (500 * 3_200 + 0xffff) >> 16;
        assert_eq!(storage_due(&prices, &storage, 1_500).unwrap(), first + second);
        assert_eq!(storage_due(&prices, &storage, 900).unwrap(), 0);
        assert_eq!(storage_due(&[], &storage, 1_500).unwrap(), 0);
        // Recorded debt is charged on top, even when nothing new has accrued.
        let indebted = WalletStorage { due_payment: 7, ..storage };
        assert_eq!(storage_due(&prices, &indebted, 1_500).unwrap(), first + second + 7);
        assert_eq!(storage_due(&prices, &indebted, 900).unwrap(), 7);
    }
}
