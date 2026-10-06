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
/// fees accrued since `last_paid`. Mirrors the node's
/// `StoragePrices::compute_storage_fees`: each price period is clipped to `now`, the
/// fixed-point (2^-16 nanoTOS) total is accumulated across periods, and it is
/// rounded up once at the end.
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
    let last_paid = storage.last_paid;
    let first = match prices.first() {
        Some(first) => first,
        None => return Ok(0),
    };
    if now <= last_paid || last_paid == 0 || now <= first.utime_since {
        return Ok(0);
    }
    // The period in force at last_paid: the last one that starts at or before it.
    let count = prices.len();
    let mut index = count;
    while index > 0
        && prices.get(index.saturating_sub(1)).is_some_and(|period| period.utime_since > last_paid)
    {
        index = index.saturating_sub(1);
    }
    index = index.saturating_sub(1);
    let mut upto = last_paid.max(first.utime_since);
    let mut total: u128 = 0;
    while upto < now {
        let Some(period) = prices.get(index) else {
            break;
        };
        let valid_until =
            prices.get(index.saturating_add(1)).map_or(now, |next| now.min(next.utime_since));
        if upto < valid_until {
            let per_second = u128::from(storage.bits)
                .checked_mul(u128::from(period.mc_bit_price_ps))
                .and_then(|bit_part| {
                    u128::from(storage.cells)
                        .checked_mul(u128::from(period.mc_cell_price_ps))
                        .and_then(|cell_part| bit_part.checked_add(cell_part))
                })
                .ok_or_else(overflow)?;
            total = per_second
                .checked_mul(u128::from(valid_until.saturating_sub(upto)))
                .and_then(|part| total.checked_add(part))
                .ok_or_else(overflow)?;
        }
        upto = valid_until;
        index = index.saturating_add(1);
    }
    // Divide by 2^16, rounding up, once.
    Ok(total.checked_add(0xffff).ok_or_else(overflow)? >> 16)
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
    fn storage_due_spans_price_periods_and_rounds_up_once() {
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
        // 100 s at (100 * 1 + 3 * 500) = 1600 and 500 s at (100 * 2 + 3 * 1000) = 3200,
        // summed in 2^-16 nanoTOS and rounded up once: ceil(1_760_000 / 65536) = 27.
        // Rounding each period separately would give 3 + 25 = 28.
        assert_eq!(storage_due(&prices, &storage, 1_500).unwrap(), 27);
        assert_eq!(storage_due(&prices, &storage, 900).unwrap(), 0);
        assert_eq!(storage_due(&[], &storage, 1_500).unwrap(), 0);
        // Recorded debt is charged on top, even when nothing new has accrued.
        let indebted = WalletStorage { due_payment: 7, ..storage };
        assert_eq!(storage_due(&prices, &indebted, 1_500).unwrap(), 27 + 7);
        assert_eq!(storage_due(&prices, &indebted, 900).unwrap(), 7);
    }

    /// The review's control: a price period that starts after `now` must not be
    /// charged up to its start. 1 cell at 1 nanoTOS per cell-second (65536 in 2^-16
    /// units), last paid at 1, now 100, debt 7, the next period from 1000: 99 s
    /// accrue, so 99 + 7 = 106 (the node), not 999 + 7 = 1006.
    #[test]
    fn a_period_that_starts_after_now_is_clipped_to_now() {
        let prices = [
            StoragePrices { utime_since: 0, mc_cell_price_ps: 65_536, ..Default::default() },
            StoragePrices { utime_since: 1_000, mc_cell_price_ps: 65_536, ..Default::default() },
        ];
        let storage = WalletStorage { cells: 1, bits: 0, last_paid: 1, due_payment: 7 };
        assert_eq!(storage_due(&prices, &storage, 100).unwrap(), 106);
    }

    /// Several periods wholly in the past, starting inside the second one, derived by
    /// hand from the node's compute_storage_fees (not callable from these tests; the
    /// sandbox runs a different executor):
    ///   periods start at 0, 100, 200, 300; last_paid 150; now 350; 2 cells, 10 bits;
    ///   period 1 (from 100): 2 * 1000 + 10 * 10 = 2100/s for 150..200 = 50 s -> 105_000
    ///   period 2 (from 200): 2 * 2000 + 10 * 20 = 4200/s for 200..300 = 100 s -> 420_000
    ///   period 3 (from 300): 2 * 3000 + 10 * 30 = 6300/s for 300..350 = 50 s -> 315_000
    ///   total 840_000 in 2^-16 nanoTOS -> ceil(840_000 / 65536) = 13; rounding each
    ///   period separately would give 2 + 7 + 5 = 14.
    /// Period 0 is never charged: last_paid is after it ends.
    #[test]
    fn several_past_periods_accumulate_and_round_once() {
        let period = |since: u32, cell: u64, bit: u64| StoragePrices {
            utime_since: since,
            mc_cell_price_ps: cell,
            mc_bit_price_ps: bit,
            ..Default::default()
        };
        let prices = [
            period(0, 1_000_000, 1_000_000),
            period(100, 1_000, 10),
            period(200, 2_000, 20),
            period(300, 3_000, 30),
        ];
        let storage = WalletStorage { cells: 2, bits: 10, last_paid: 150, due_payment: 0 };
        assert_eq!(storage_due(&prices, &storage, 350).unwrap(), 13);
        // Ending inside period 2 clips it: 105_000 + 4200 * 50 = 315_000 -> ceil 4.81 = 5.
        assert_eq!(storage_due(&prices, &storage, 250).unwrap(), 5);
    }
}
