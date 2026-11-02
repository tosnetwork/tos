// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Cell codecs for shielded pool V1: what a wallet writes to the pool and what
//! it reads back out of the pool's history and state.
//!
//! The pool publishes no events and no getter for its trees, so a wallet
//! rebuilds the pool's state by decoding every committed transaction of the
//! pool account. This module turns cells into typed values and back; it knows
//! nothing about keys, notes or proofs. Every layout here is the frozen one in
//! `crypto/smartcont/tos-shielded-pool-v1.fc` and `crypto/smartcont/shielded/`,
//! and every reader is as strict as the contract or stricter: a cell the
//! contract would have refused is refused here, and a cell this code cannot
//! model is refused rather than guessed at, because a model that differs from
//! the chain cannot plan a spend the chain will accept.

use anyhow::Context as _;
use chain_block::{
    BuilderData, Cell, CellType, GasLimitsPrices, IBitstring, MsgAddressInt, SliceData,
    TrComputePhase, Transaction, TransactionDescr, UInt256,
};

pub const OP_DEPOSIT: u32 = 0x5348_5001;
pub const OP_TRANSACT: u32 = 0x5348_5002;
pub const OP_RESERVE_TOPUP: u32 = 0x5348_5003;
/// `state_magic()` and `state_version()` in `shielded/state.fc`.
pub const STATE_MAGIC: u32 = 0x5350_5631;
pub const STATE_VERSION: u16 = 1;
/// `recovery_envelope_tag()` in `shielded/recovery.fc`: the first 32 bits of a
/// bounced body that carries the original body back in a reference.
pub const RECOVERY_ENVELOPE_TAG: u32 = 0xffff_fffe;
/// `payout_op()` in `shielded/payout.fc`.
pub const PAYOUT_OP: u32 = 0;
/// Section 3: one sealed output payload.
pub const OUTPUT_DATA_BYTES: usize = 1233;
/// The Groth16 verifying key the state cell carries.
pub const VK_BYTES: usize = 1248;
pub const MAX_DENOMINATIONS: usize = 16;
/// `index_sentinel()`: the commitment tree has 2^32 leaves.
pub const INDEX_SENTINEL: u64 = 1 << 32;
/// Section 14.1 ceilings of the V1 contract. A wallet funds a message with
/// `get_compute_fee(0, ceiling)` at live prices, which is what the contract
/// requires and all it can spend.
pub const DEPOSIT_GAS_CEILING: u64 = 230_000;
pub const TRANSACT_GAS_CEILING: u64 = 1_380_000;
pub const BOUNCE_GAS_CEILING: u64 = 240_000;
/// Coins is a VarUInteger 16 and cannot carry 2^120.
pub const MAX_COINS: u128 = (1u128 << 120) - 1;

const CHUNK_BYTES: usize = 127;

fn slice_of(cell: &Cell) -> anyhow::Result<SliceData> {
    anyhow::ensure!(
        cell.cell_type() == CellType::Ordinary && cell.level() == 0,
        "ordinary level-zero cell required"
    );
    Ok(SliceData::load_cell(cell.clone())?)
}

fn bits(slice: &mut SliceData, count: usize) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(slice.remaining_bits() >= count, "a field needs {count} bits");
    Ok(slice.get_next_bits(count)?)
}

fn uint(slice: &mut SliceData, count: usize) -> anyhow::Result<u64> {
    anyhow::ensure!(count <= 64, "an integer field of {count} bits");
    anyhow::ensure!(slice.remaining_bits() >= count, "a field needs {count} bits");
    Ok(slice.get_next_int(count)?)
}

fn word(slice: &mut SliceData) -> anyhow::Result<[u8; 32]> {
    bits(slice, 256)?.try_into().map_err(|_| anyhow::anyhow!("a 256-bit field"))
}

/// Coins: four bits of byte length, then that many bytes, big-endian.
fn coins(slice: &mut SliceData) -> anyhow::Result<u128> {
    let length = usize::try_from(uint(slice, 4)?)?;
    anyhow::ensure!(length <= 15, "coins wider than 120 bits");
    if length == 0 {
        return Ok(0);
    }
    let mut value: u128 = 0;
    for byte in bits(slice, length.saturating_mul(8))? {
        value = value
            .checked_mul(256)
            .and_then(|v| v.checked_add(u128::from(byte)))
            .context("coins overflow")?;
    }
    Ok(value)
}

fn reference(slice: &mut SliceData) -> anyhow::Result<Cell> {
    anyhow::ensure!(slice.remaining_references() >= 1, "a reference is missing");
    Ok(slice.checked_drain_reference()?)
}

fn finished(slice: &SliceData, what: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        slice.remaining_bits() == 0 && slice.remaining_references() == 0,
        "{what} carries trailing data"
    );
    Ok(())
}

/// Appends `amount` as Coins.
pub fn store_coins(builder: &mut BuilderData, amount: u128) -> anyhow::Result<()> {
    anyhow::ensure!(amount <= MAX_COINS, "coins wider than 120 bits");
    let bytes = amount.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    let length = bytes.len().saturating_sub(first);
    builder.append_bits(length, 4)?;
    if length > 0 {
        builder.append_raw(&bytes[first..], length.saturating_mul(8))?;
    }
    Ok(())
}

/// A byte string as the canonical chain of cells: 127 bytes per cell until
/// the last, which carries what is left and no reference.
pub fn byte_chain(bytes: &[u8]) -> anyhow::Result<Cell> {
    anyhow::ensure!(!bytes.is_empty(), "an empty byte chain");
    let mut cell: Option<Cell> = None;
    for chunk in bytes.chunks(CHUNK_BYTES).rev() {
        let mut builder = BuilderData::new();
        builder.append_raw(chunk, chunk.len().saturating_mul(8))?;
        if let Some(next) = cell.take() {
            builder.checked_append_reference(next)?;
        }
        cell = Some(builder.into_cell()?);
    }
    cell.context("an empty byte chain")
}

/// The inverse of [`byte_chain`] for a string of exactly `expected` bytes.
/// Any other shape -- a short full cell, a second reference, a partial byte,
/// a different length -- is refused.
pub fn read_byte_chain(cell: &Cell, expected: usize) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(expected > 0, "an empty byte chain");
    let mut out = Vec::with_capacity(expected);
    let mut current = cell.clone();
    loop {
        let mut slice = slice_of(&current)?;
        let remaining_bits = slice.remaining_bits();
        anyhow::ensure!(remaining_bits % 8 == 0, "a byte chain cell carries a partial byte");
        let here = remaining_bits / 8;
        let left = expected.saturating_sub(out.len());
        anyhow::ensure!(here > 0 && here <= left, "a byte chain cell of the wrong length");
        out.extend(bits(&mut slice, remaining_bits)?);
        match slice.remaining_references() {
            0 => {
                anyhow::ensure!(out.len() == expected, "a byte chain ends early");
                return Ok(out);
            }
            1 => {
                anyhow::ensure!(here == CHUNK_BYTES, "a byte chain cell with a successor is not full");
                current = reference(&mut slice)?;
            }
            _ => anyhow::bail!("a byte chain cell has more than one reference"),
        }
    }
}

/// Section 12.1: the deposit body after its operation code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositBody {
    pub query_id: u64,
    pub amount: u128,
    pub owner_commitment: [u8; 32],
    /// The sealed payload, exactly [`OUTPUT_DATA_BYTES`].
    pub output_data: Vec<u8>,
}

impl DepositBody {
    pub fn build(&self) -> anyhow::Result<Cell> {
        anyhow::ensure!(self.amount > 0, "a deposit of zero");
        anyhow::ensure!(
            self.output_data.len() == OUTPUT_DATA_BYTES,
            "a deposit payload is {OUTPUT_DATA_BYTES} bytes"
        );
        let mut builder = BuilderData::new();
        builder.append_u32(OP_DEPOSIT)?;
        builder.append_u64(self.query_id)?;
        store_coins(&mut builder, self.amount)?;
        builder.append_raw(&self.owner_commitment, 256)?;
        builder.checked_append_reference(byte_chain(&self.output_data)?)?;
        Ok(builder.into_cell()?)
    }

    /// Reads the body after the operation code has been consumed.
    pub fn parse(slice: &mut SliceData) -> anyhow::Result<Self> {
        anyhow::ensure!(slice.remaining_references() == 1, "a deposit body carries one reference");
        let query_id = uint(slice, 64)?;
        let amount = coins(slice)?;
        let owner_commitment = word(slice)?;
        let output_data = read_byte_chain(&reference(slice)?, OUTPUT_DATA_BYTES)?;
        finished(slice, "a deposit body")?;
        Ok(Self { query_id, amount, owner_commitment, output_data })
    }
}

/// Section 12.2: the transact body, decoded as far as a replay needs. The
/// Groth16 proof, the signatures and the nullifier witnesses are carried as
/// cells; the contract has already checked them.
#[derive(Clone, Debug)]
pub struct TransactBody {
    pub query_id: u64,
    pub anchor_kind: u8,
    pub anchor_id: u32,
    pub valid_until: u32,
    pub public_amount_out: u128,
    pub withdrawal_fee: u128,
    pub recipient: Option<MsgAddressInt>,
    pub intent_digest: [u8; 32],
    pub anchor_root: [u8; 32],
    pub nullifiers: [[u8; 32]; 2],
    pub note_bodies: [[u8; 32]; 3],
    pub payloads: [Vec<u8>; 3],
    pub groth16_proof: Cell,
    pub recovery_owner_commitment: [u8; 32],
    /// The recovery payload of a withdrawal. A transfer carries a cell in this
    /// position too; its bytes mean nothing and are not decoded.
    pub recovery_payload: Option<Vec<u8>>,
    pub recovery_cell: Cell,
    pub auth_bundle: Cell,
    pub witness_bundle: Cell,
}

impl TransactBody {
    pub fn is_withdrawal(&self) -> bool {
        self.public_amount_out > 0
    }

    /// Reads the body after the operation code has been consumed.
    pub fn parse(slice: &mut SliceData) -> anyhow::Result<Self> {
        anyhow::ensure!(slice.remaining_references() == 4, "a transact body carries four bundles");
        let query_id = uint(slice, 64)?;
        let anchor_kind = u8::try_from(uint(slice, 8)?)?;
        let anchor_id = u32::try_from(uint(slice, 32)?)?;
        let valid_until = u32::try_from(uint(slice, 32)?)?;
        let public_amount_out = coins(slice)?;
        let withdrawal_fee = coins(slice)?;
        let recipient = match uint(slice, 2)? {
            0 => None,
            2 => {
                anyhow::ensure!(uint(slice, 1)? == 0, "an anycast recipient");
                let workchain = uint(slice, 8)? as u8 as i8;
                let account = word(slice)?;
                Some(MsgAddressInt::with_params(i32::from(workchain), UInt256::from(account))?)
            }
            _ => anyhow::bail!("a recipient that is neither none nor a standard address"),
        };
        let intent_digest = word(slice)?;

        let mut proof = slice_of(&reference(slice)?)?;
        let anchor_root = word(&mut proof)?;
        let nullifiers = [word(&mut proof)?, word(&mut proof)?];
        let mut bodies = slice_of(&reference(&mut proof)?)?;
        let note_bodies = [word(&mut bodies)?, word(&mut bodies)?, word(&mut bodies)?];
        finished(&bodies, "the note bodies")?;
        let groth16_proof = reference(&mut proof)?;
        finished(&proof, "the proof bundle")?;

        let mut output = slice_of(&reference(slice)?)?;
        let recovery_owner_commitment = word(&mut output)?;
        let payloads = [
            read_byte_chain(&reference(&mut output)?, OUTPUT_DATA_BYTES)?,
            read_byte_chain(&reference(&mut output)?, OUTPUT_DATA_BYTES)?,
            read_byte_chain(&reference(&mut output)?, OUTPUT_DATA_BYTES)?,
        ];
        let recovery_cell = reference(&mut output)?;
        finished(&output, "the output bundle")?;
        let recovery_payload = if public_amount_out > 0 {
            Some(read_byte_chain(&recovery_cell, OUTPUT_DATA_BYTES)?)
        } else {
            None
        };

        let auth_bundle = reference(slice)?;
        let witness_bundle = reference(slice)?;
        finished(slice, "a transact body")?;
        anyhow::ensure!(
            (public_amount_out > 0) == recipient.is_some(),
            "a withdrawal names a recipient and a transfer names none"
        );
        Ok(Self {
            query_id,
            anchor_kind,
            anchor_id,
            valid_until,
            public_amount_out,
            withdrawal_fee,
            recipient,
            intent_digest,
            anchor_root,
            nullifiers,
            note_bodies,
            payloads,
            groth16_proof,
            recovery_owner_commitment,
            recovery_payload,
            recovery_cell,
            auth_bundle,
            witness_bundle,
        })
    }
}

/// The payout a withdrawal emitted, as its transaction shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutMessage {
    pub recipient: MsgAddressInt,
    pub value: u128,
    /// The representation hash of the payout body, which a bounce carries back.
    pub body_hash: [u8; 32],
}

/// If `body` is a bounced body carrying the pool's recovery envelope, the
/// representation hash of the original body inside it.
pub fn bounce_original_body_hash(body: &SliceData) -> anyhow::Result<Option<[u8; 32]>> {
    let mut body = body.clone();
    if body.remaining_bits() < 32 {
        return Ok(None);
    }
    if u32::try_from(uint(&mut body, 32)?)? != RECOVERY_ENVELOPE_TAG {
        return Ok(None);
    }
    if body.remaining_references() == 0 {
        // The contract throws 264 here, so no committed transaction carries this.
        anyhow::bail!("a recovery envelope without its original body");
    }
    Ok(Some(*reference(&mut body)?.repr_hash().as_array()))
}

/// Section 12: the immutable deployment configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolConfig {
    pub profile_hash: [u8; 32],
    pub poseidon_manifest_hash: [u8; 32],
    pub groth16_vk_hash: [u8; 32],
    pub withdrawal_fee: u128,
    pub denominations: Vec<u128>,
}

impl PoolConfig {
    pub fn parse(cell: &Cell) -> anyhow::Result<Self> {
        let mut slice = slice_of(cell)?;
        anyhow::ensure!(slice.remaining_references() == 1, "a config store carries one reference");
        let profile_hash = word(&mut slice)?;
        let poseidon_manifest_hash = word(&mut slice)?;
        let groth16_vk_hash = word(&mut slice)?;
        let withdrawal_fee = coins(&mut slice)?;
        anyhow::ensure!(withdrawal_fee > 0, "a withdrawal fee of zero");
        let count = usize::try_from(uint(&mut slice, 8)?)?;
        anyhow::ensure!((1..=MAX_DENOMINATIONS).contains(&count), "{count} denominations");
        let mut node = reference(&mut slice)?;
        finished(&slice, "a config store")?;
        let mut denominations = Vec::with_capacity(count);
        for remaining in (1..=count).rev() {
            let mut entry = slice_of(&node)?;
            let value = coins(&mut entry)?;
            anyhow::ensure!(value > 0, "a denomination of zero");
            denominations.push(value);
            if remaining > 1 {
                node = reference(&mut entry)?;
            }
            finished(&entry, "a denomination")?;
        }
        Ok(Self {
            profile_hash,
            poseidon_manifest_hash,
            groth16_vk_hash,
            withdrawal_fee,
            denominations,
        })
    }

    pub fn has_denomination(&self, amount: u128) -> bool {
        self.denominations.contains(&amount)
    }
}

/// Section 13: the pool's state cell, less the frontier and anchor stores,
/// which a wallet rebuilds rather than reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolState {
    pub commitment_root: [u8; 32],
    pub commitment_next_index: u64,
    pub reserved_recovery_leaves: u32,
    pub nullifier_root: [u8; 32],
    pub nullifier_next_index: u64,
    pub last_anchor_epoch: u32,
    pub native_liability: u128,
    pub reserve_floor: u128,
    pub config: PoolConfig,
    /// The verifying key bytes the pool verifies every proof against.
    pub verifying_key: Vec<u8>,
}

impl PoolState {
    pub fn parse(data: &Cell) -> anyhow::Result<Self> {
        let mut slice = slice_of(data)?;
        anyhow::ensure!(slice.remaining_references() == 4, "a state cell carries four references");
        anyhow::ensure!(u32::try_from(uint(&mut slice, 32)?)? == STATE_MAGIC, "not a pool state");
        anyhow::ensure!(
            u16::try_from(uint(&mut slice, 16)?)? == STATE_VERSION,
            "an unsupported pool state version"
        );
        let commitment_root = word(&mut slice)?;
        let commitment_next_index = uint(&mut slice, 64)?;
        let reserved_recovery_leaves = u32::try_from(uint(&mut slice, 32)?)?;
        let nullifier_root = word(&mut slice)?;
        let nullifier_next_index = uint(&mut slice, 64)?;
        let last_anchor_epoch = u32::try_from(uint(&mut slice, 32)?)?;
        let native_liability = coins(&mut slice)?;
        let reserve_floor = coins(&mut slice)?;
        let _frontier = reference(&mut slice)?;
        let _anchors = reference(&mut slice)?;
        let config = PoolConfig::parse(&reference(&mut slice)?)?;
        let verifying_key = read_byte_chain(&reference(&mut slice)?, VK_BYTES)?;
        finished(&slice, "a state cell")?;
        anyhow::ensure!(
            commitment_next_index.saturating_add(u64::from(reserved_recovery_leaves))
                <= INDEX_SENTINEL
                && nullifier_next_index <= INDEX_SENTINEL,
            "a state past the end of its trees"
        );
        Ok(Self {
            commitment_root,
            commitment_next_index,
            reserved_recovery_leaves,
            nullifier_root,
            nullifier_next_index,
            last_anchor_epoch,
            native_liability,
            reserve_floor,
            config,
            verifying_key,
        })
    }
}

/// One committed transaction of the pool account, classified.
#[derive(Clone, Debug)]
pub enum PoolTransaction {
    Deposit(DepositBody),
    Transact { body: Box<TransactBody>, payout: Option<PayoutMessage> },
    /// An authenticated recovery bounce the pool accepted. Whether it minted a
    /// note depends on the charge at the time; the replay decides that.
    Bounce { original_body_hash: [u8; 32], sender: MsgAddressInt, value: u128 },
    /// A transaction that left the pool's state as it found it, and why.
    NoStateChange(&'static str),
}

/// Classifies one transaction of the pool account.
///
/// Only a transaction whose compute phase succeeded and that was not aborted
/// changed the state; everything else -- a refused deposit, a top-up, a plain
/// transfer, a bounce without an envelope -- is history to acknowledge and
/// nothing to apply. A transaction that changed state in a way this code does
/// not model is an error, not a `NoStateChange`.
pub fn classify(transaction: &Transaction) -> anyhow::Result<PoolTransaction> {
    let TransactionDescr::Ordinary(description) = transaction.read_description()? else {
        anyhow::bail!("a pool transaction that is not ordinary");
    };
    let applied = match &description.compute_ph {
        TrComputePhase::Vm(vm) => vm.success && !description.aborted,
        TrComputePhase::Skipped(_) => false,
    };
    if !applied {
        return Ok(PoolTransaction::NoStateChange("not applied"));
    }
    let Some(message) = transaction.read_in_msg()? else {
        return Ok(PoolTransaction::NoStateChange("no inbound message"));
    };
    let Some(header) = message.int_header() else {
        // recv_external always throws, so an applied external does not exist.
        anyhow::bail!("an applied external message to the pool");
    };
    let value = header.value.coins.as_u128();
    let body = message.body().cloned().unwrap_or_default();

    if header.bounced {
        return Ok(match bounce_original_body_hash(&body)? {
            Some(original_body_hash) => PoolTransaction::Bounce {
                original_body_hash,
                sender: message.src().context("a bounce without a sender")?,
                value,
            },
            None => PoolTransaction::NoStateChange("a bounce without an envelope"),
        });
    }
    if body.remaining_bits() < 32 {
        return Ok(PoolTransaction::NoStateChange("a plain transfer"));
    }
    let mut body = body;
    let op = u32::try_from(uint(&mut body, 32)?)?;
    match op {
        OP_DEPOSIT => {
            require_no_out_messages(transaction, "a deposit")?;
            Ok(PoolTransaction::Deposit(DepositBody::parse(&mut body)?))
        }
        OP_TRANSACT => {
            let parsed = TransactBody::parse(&mut body)?;
            let payout = if parsed.is_withdrawal() {
                Some(payout_of(transaction, &parsed)?)
            } else {
                require_no_out_messages(transaction, "a transfer")?;
                None
            };
            Ok(PoolTransaction::Transact { body: Box::new(parsed), payout })
        }
        OP_RESERVE_TOPUP => Ok(PoolTransaction::NoStateChange("a reserve top-up")),
        // The contract throws 201 for anything else, so this was not applied.
        _ => anyhow::bail!("an applied message with operation {op:#010x}"),
    }
}

fn require_no_out_messages(transaction: &Transaction, what: &str) -> anyhow::Result<()> {
    let mut count = 0usize;
    transaction.iterate_out_msgs(|_| {
        count = count.saturating_add(1);
        Ok(true)
    })?;
    anyhow::ensure!(count == 0, "{what} emitted {count} messages");
    Ok(())
}

/// The single exact payout a withdrawal emitted.
fn payout_of(transaction: &Transaction, body: &TransactBody) -> anyhow::Result<PayoutMessage> {
    let recipient = body.recipient.clone().context("a withdrawal without a recipient")?;
    let mut payouts: Vec<PayoutMessage> = Vec::new();
    let mut others = 0usize;
    transaction.iterate_out_msgs(|message| {
        match (message.int_header(), message.body()) {
            (Some(header), Some(payout_body)) => {
                let mut probe = payout_body.clone();
                let is_payout = probe.remaining_bits() >= 96
                    && probe.remaining_references() == 1
                    && probe.get_next_int(32)? == u64::from(PAYOUT_OP);
                if is_payout {
                    payouts.push(PayoutMessage {
                        recipient: header.dst.clone(),
                        value: header.value.coins.as_u128(),
                        body_hash: *payout_body.clone().into_cell()?.repr_hash().as_array(),
                    });
                } else {
                    others = others.saturating_add(1);
                }
            }
            _ => others = others.saturating_add(1),
        }
        Ok(true)
    })?;
    anyhow::ensure!(
        payouts.len() == 1 && others == 0,
        "a withdrawal emitted {} payouts and {others} other messages",
        payouts.len()
    );
    let payout = payouts.remove(0);
    anyhow::ensure!(
        payout.recipient == recipient && payout.value == body.public_amount_out,
        "a withdrawal's payout differs from its body"
    );
    Ok(payout)
}

/// `get_compute_fee(0, gas)` under `prices`: the flat price for the first
/// `flat_gas_limit` gas, then `gas_price / 2^16` per gas, rounded up.
pub fn compute_fee(prices: &GasLimitsPrices, gas: u64) -> anyhow::Result<u128> {
    let variable = u128::from(gas.saturating_sub(prices.flat_gas_limit))
        .checked_mul(u128::from(prices.gas_price))
        .context("compute fee overflow")?;
    let scaled = variable.checked_add(0xffff).context("compute fee overflow")? >> 16;
    u128::from(prices.flat_gas_price).checked_add(scaled).context("compute fee overflow")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(seed: u8) -> Vec<u8> {
        (0..OUTPUT_DATA_BYTES as u32).map(|i| (i as u8) ^ seed).collect()
    }

    #[test]
    fn a_byte_chain_round_trips_and_only_the_canonical_shape_is_read() {
        let bytes = payload(0x5a);
        let cell = byte_chain(&bytes).expect("chain");
        assert_eq!(read_byte_chain(&cell, OUTPUT_DATA_BYTES).expect("read"), bytes);
        assert!(read_byte_chain(&cell, OUTPUT_DATA_BYTES + 1).is_err(), "a longer expectation");
        assert!(read_byte_chain(&cell, OUTPUT_DATA_BYTES - 1).is_err(), "a shorter expectation");
        assert!(byte_chain(&[]).is_err());

        // A chain whose first cell is not full but still has a successor.
        let mut short = BuilderData::new();
        short.append_raw(&bytes[..126], 126 * 8).expect("short");
        short.checked_append_reference(byte_chain(&bytes[126..]).expect("rest")).expect("ref");
        let short = short.into_cell().expect("cell");
        assert!(read_byte_chain(&short, OUTPUT_DATA_BYTES).is_err(), "a short full cell");

        // A partial byte.
        let mut partial = BuilderData::new();
        partial.append_bits(1, 3).expect("bits");
        assert!(read_byte_chain(&partial.into_cell().expect("cell"), 1).is_err());
    }

    #[test]
    fn a_deposit_body_round_trips() {
        let body = DepositBody {
            query_id: 7,
            amount: 10_000_000_000,
            owner_commitment: [0x42; 32],
            output_data: payload(1),
        };
        let cell = body.build().expect("build");
        let mut slice = SliceData::load_cell(cell).expect("slice");
        assert_eq!(uint(&mut slice, 32).expect("op"), u64::from(OP_DEPOSIT));
        assert_eq!(DepositBody::parse(&mut slice).expect("parse"), body);

        let zero = DepositBody { amount: 0, ..body.clone() };
        assert!(zero.build().is_err());
        let short = DepositBody { output_data: vec![1; 10], ..body };
        assert!(short.build().is_err());
    }

    #[test]
    fn coins_round_trip_at_both_ends() {
        for amount in [0u128, 1, 255, 256, 1_000_000_000, MAX_COINS] {
            let mut builder = BuilderData::new();
            store_coins(&mut builder, amount).expect("store");
            let mut slice = SliceData::load_cell(builder.into_cell().expect("cell")).expect("s");
            assert_eq!(coins(&mut slice).expect("coins"), amount);
        }
        let mut builder = BuilderData::new();
        assert!(store_coins(&mut builder, MAX_COINS + 1).is_err());
    }

    #[test]
    fn a_bounce_envelope_is_recognised_and_a_plain_bounce_is_not() {
        let original = byte_chain(&[1, 2, 3]).expect("original");
        let mut builder = BuilderData::new();
        builder.append_u32(RECOVERY_ENVELOPE_TAG).expect("tag");
        builder.checked_append_reference(original.clone()).expect("ref");
        let body = SliceData::load_cell(builder.into_cell().expect("cell")).expect("slice");
        assert_eq!(
            bounce_original_body_hash(&body).expect("ok"),
            Some(*original.repr_hash().as_array())
        );

        let mut plain = BuilderData::new();
        plain.append_u32(0xffff_ffff).expect("tag");
        let plain = SliceData::load_cell(plain.into_cell().expect("cell")).expect("slice");
        assert_eq!(bounce_original_body_hash(&plain).expect("ok"), None);
        assert_eq!(bounce_original_body_hash(&SliceData::default()).expect("ok"), None);

        let mut tagged_only = BuilderData::new();
        tagged_only.append_u32(RECOVERY_ENVELOPE_TAG).expect("tag");
        let tagged_only =
            SliceData::load_cell(tagged_only.into_cell().expect("cell")).expect("slice");
        assert!(bounce_original_body_hash(&tagged_only).is_err(), "an envelope with no body");
    }

    #[test]
    fn the_compute_fee_follows_the_executor_rule() {
        let prices = GasLimitsPrices {
            flat_gas_limit: 100,
            flat_gas_price: 667,
            gas_price: 436_907,
            ..GasLimitsPrices::default()
        };
        // flat for the first hundred gas, then rounded up per 2^16.
        assert_eq!(compute_fee(&prices, 100).expect("fee"), 667);
        assert_eq!(
            compute_fee(&prices, DEPOSIT_GAS_CEILING).expect("fee"),
            667 + (u128::from(DEPOSIT_GAS_CEILING - 100) * 436_907).div_ceil(65_536)
        );
    }
}
