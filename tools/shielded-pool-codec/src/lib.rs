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
    BuilderData, Cell, CellType, GasLimitsPrices, HashmapE, HashmapType, IBitstring, MsgAddressInt,
    SliceData, TrComputePhase, Transaction, TransactionDescr, UInt256,
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
/// Section 6's three anchor kinds, as `shielded/anchors.fc` numbers them.
pub const ANCHOR_CURRENT: u8 = 0;
pub const ANCHOR_RECENT: u8 = 1;
pub const ANCHOR_EPOCH: u8 = 2;
/// `recent_root_slots()`: the recent ring is keyed by root version modulo this.
pub const RECENT_ROOT_SLOTS: u32 = 4096;
/// `anchor_epoch_slots()` and `anchor_epoch_seconds()`: the epoch ring is
/// keyed by epoch modulo the slots, and an epoch is this many seconds.
pub const ANCHOR_EPOCH_SLOTS: u32 = 2880;
pub const ANCHOR_EPOCH_SECONDS: u32 = 30;
/// Section 10.1: the proof's three points, compressed.
pub const PROOF_A_BYTES: usize = 48;
pub const PROOF_B_BYTES: usize = 96;
pub const PROOF_C_BYTES: usize = 48;
/// Section 9.4: an ML-DSA-44 public key and signature.
pub const AUTH_KEY_BYTES: usize = 1312;
pub const AUTH_SIGNATURE_BYTES: usize = 2420;
/// Section 7.2: a nullifier path is 12 levels of 6 siblings.
pub const IMT_PATH_FIELDS: usize = 72;

const CHUNK_BYTES: usize = 127;
const ANCHOR_KEY_BITS: usize = 12;
const ANCHOR_ENTRY_BITS: usize = 288;
const IMT_PATH_FIELDS_PER_CELL: usize = 3;

fn slice_of(cell: &Cell) -> anyhow::Result<SliceData> {
    anyhow::ensure!(
        cell.cell_type() == CellType::Ordinary && cell.level() == 0,
        "ordinary level-zero cell required"
    );
    SliceData::load_cell(cell.clone())
}

fn bits(slice: &mut SliceData, count: usize) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(slice.remaining_bits() >= count, "a field needs {count} bits");
    slice.get_next_bits(count)
}

fn uint(slice: &mut SliceData, count: usize) -> anyhow::Result<u64> {
    anyhow::ensure!(count <= 64, "an integer field of {count} bits");
    anyhow::ensure!(slice.remaining_bits() >= count, "a field needs {count} bits");
    slice.get_next_int(count)
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
    slice.checked_drain_reference()
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
                anyhow::ensure!(
                    here == CHUNK_BYTES,
                    "a byte chain cell with a successor is not full"
                );
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
        builder.into_cell()
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

    /// The body as a wallet sends it, operation code first: the inverse of
    /// [`Self::parse`]. A body the contract would refuse for its shape -- an
    /// unknown anchor kind, a current anchor with an id, a transfer naming a
    /// recipient or a withdrawal naming none, a payload of the wrong length --
    /// is refused here, before anything is signed or paid for.
    pub fn build(&self) -> anyhow::Result<Cell> {
        anyhow::ensure!(
            self.anchor_kind <= ANCHOR_EPOCH,
            "an anchor kind that is not current, recent or epoch"
        );
        anyhow::ensure!(
            self.anchor_kind != ANCHOR_CURRENT || self.anchor_id == 0,
            "a current anchor carries no id"
        );
        let withdrawal = self.is_withdrawal();
        anyhow::ensure!(
            withdrawal == self.recipient.is_some(),
            "a withdrawal names a recipient and a transfer names none"
        );
        anyhow::ensure!(
            withdrawal == self.recovery_payload.is_some(),
            "a withdrawal carries a recovery payload and a transfer carries none"
        );
        anyhow::ensure!(withdrawal || self.withdrawal_fee == 0, "a transfer with a fee");

        let mut proof_bundle = BuilderData::new();
        proof_bundle.append_raw(&self.anchor_root, 256)?;
        proof_bundle.append_raw(&self.nullifiers[0], 256)?;
        proof_bundle.append_raw(&self.nullifiers[1], 256)?;
        let mut bodies = BuilderData::new();
        for body in &self.note_bodies {
            bodies.append_raw(body, 256)?;
        }
        proof_bundle.checked_append_reference(bodies.into_cell()?)?;
        proof_bundle.checked_append_reference(self.groth16_proof.clone())?;

        let mut output = BuilderData::new();
        output.append_raw(&self.recovery_owner_commitment, 256)?;
        for payload in &self.payloads {
            anyhow::ensure!(
                payload.len() == OUTPUT_DATA_BYTES,
                "an output payload is {OUTPUT_DATA_BYTES} bytes"
            );
            output.checked_append_reference(byte_chain(payload)?)?;
        }
        let recovery = match &self.recovery_payload {
            Some(payload) => {
                anyhow::ensure!(
                    payload.len() == OUTPUT_DATA_BYTES,
                    "a recovery payload is {OUTPUT_DATA_BYTES} bytes"
                );
                let chain = byte_chain(payload)?;
                anyhow::ensure!(
                    chain.repr_hash() == self.recovery_cell.repr_hash(),
                    "a recovery cell that is not the recovery payload's chain"
                );
                chain
            }
            None => self.recovery_cell.clone(),
        };
        output.checked_append_reference(recovery)?;

        let mut builder = BuilderData::new();
        builder.append_u32(OP_TRANSACT)?;
        builder.append_u64(self.query_id)?;
        builder.append_u8(self.anchor_kind)?;
        builder.append_u32(self.anchor_id)?;
        builder.append_u32(self.valid_until)?;
        store_coins(&mut builder, self.public_amount_out)?;
        store_coins(&mut builder, self.withdrawal_fee)?;
        match &self.recipient {
            None => {
                builder.append_bits(0, 2)?;
            }
            Some(recipient) => {
                anyhow::ensure!(
                    matches!(recipient, MsgAddressInt::AddrStd(std) if std.anycast.is_none()),
                    "a recipient that is not a standard address"
                );
                let workchain = i8::try_from(recipient.workchain_id())
                    .context("a recipient workchain outside a standard address")?;
                let mut account = recipient.address().clone();
                let account_bytes = word(&mut account)?;
                finished(&account, "a recipient account")?;
                builder.append_bits(2, 2)?;
                builder.append_bit_zero()?;
                builder.append_i8(workchain)?;
                builder.append_raw(&account_bytes, 256)?;
            }
        }
        builder.append_raw(&self.intent_digest, 256)?;
        builder.checked_append_reference(proof_bundle.into_cell()?)?;
        builder.checked_append_reference(output.into_cell()?)?;
        builder.checked_append_reference(self.auth_bundle.clone())?;
        builder.checked_append_reference(self.witness_bundle.clone())?;
        builder.into_cell()
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

/// Section 10.1: A and C in the root, B in its one reference.
pub fn groth16_proof_cell(a: &[u8], b: &[u8], c: &[u8]) -> anyhow::Result<Cell> {
    anyhow::ensure!(a.len() == PROOF_A_BYTES, "a proof point A of {} bytes", a.len());
    anyhow::ensure!(b.len() == PROOF_B_BYTES, "a proof point B of {} bytes", b.len());
    anyhow::ensure!(c.len() == PROOF_C_BYTES, "a proof point C of {} bytes", c.len());
    let mut ac = BuilderData::new();
    ac.append_raw(a, PROOF_A_BYTES.saturating_mul(8))?;
    ac.append_raw(c, PROOF_C_BYTES.saturating_mul(8))?;
    let mut point_b = BuilderData::new();
    point_b.append_raw(b, PROOF_B_BYTES.saturating_mul(8))?;
    ac.checked_append_reference(point_b.into_cell()?)?;
    ac.into_cell()
}

/// Section 9.4's authentication bundle: for each input, its ML-DSA-44 public
/// key and its signature over the intent digest, as four byte chains and no
/// data.
pub fn auth_bundle(keys: [&[u8]; 2], signatures: [&[u8]; 2]) -> anyhow::Result<Cell> {
    let mut builder = BuilderData::new();
    for (key, signature) in keys.into_iter().zip(signatures) {
        anyhow::ensure!(
            key.len() == AUTH_KEY_BYTES,
            "an authentication key of {} bytes",
            key.len()
        );
        anyhow::ensure!(
            signature.len() == AUTH_SIGNATURE_BYTES,
            "an authentication signature of {} bytes",
            signature.len()
        );
        builder.checked_append_reference(byte_chain(key)?)?;
        builder.checked_append_reference(byte_chain(signature)?)?;
    }
    builder.into_cell()
}

/// Section 7.1: one nullifier's non-membership witness, as the wallet that
/// tracks the nullifier tree computed it. The field elements are carried as
/// their 32 big-endian bytes; the wallet, not this codec, knows they are
/// field elements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NullifierWitness {
    pub low_index: u32,
    pub low_value: [u8; 32],
    pub low_next_index: u32,
    pub low_next_value: [u8; 32],
    /// Exactly [`IMT_PATH_FIELDS`] siblings, leaf level first.
    pub low_path: Vec<[u8; 32]>,
    pub append_path: Vec<[u8; 32]>,
}

impl NullifierWitness {
    /// Section 7.2's one encoding: 576 bits and the two path chains.
    pub fn cell(&self) -> anyhow::Result<Cell> {
        let mut builder = BuilderData::new();
        builder.append_u32(self.low_index)?;
        builder.append_raw(&self.low_value, 256)?;
        builder.append_u32(self.low_next_index)?;
        builder.append_raw(&self.low_next_value, 256)?;
        builder.checked_append_reference(path_chain(&self.low_path)?)?;
        builder.checked_append_reference(path_chain(&self.append_path)?)?;
        builder.into_cell()
    }
}

/// A path as the chain of 24 cells of three siblings each.
fn path_chain(fields: &[[u8; 32]]) -> anyhow::Result<Cell> {
    anyhow::ensure!(
        fields.len() == IMT_PATH_FIELDS,
        "a nullifier path of {} siblings, not {IMT_PATH_FIELDS}",
        fields.len()
    );
    let mut cell: Option<Cell> = None;
    for chunk in fields.chunks(IMT_PATH_FIELDS_PER_CELL).rev() {
        let mut builder = BuilderData::new();
        for field in chunk {
            builder.append_raw(field, 256)?;
        }
        if let Some(next) = cell.take() {
            builder.checked_append_reference(next)?;
        }
        cell = Some(builder.into_cell()?);
    }
    cell.context("an empty path")
}

/// The witness bundle: the two witnesses as references and no data.
pub fn witness_bundle(witnesses: &[NullifierWitness; 2]) -> anyhow::Result<Cell> {
    let mut builder = BuilderData::new();
    for witness in witnesses {
        builder.checked_append_reference(witness.cell()?)?;
    }
    builder.into_cell()
}

/// One preserved root: `id` is the root version (the commitment index at
/// preservation) in the recent ring and the epoch in the epoch ring; `slot`
/// is the dictionary key it sits under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorEntry {
    pub slot: u16,
    pub id: u32,
    pub root: [u8; 32],
}

/// Section 13.1's anchor store: the two rings of preserved commitment roots a
/// transact may anchor its proof to besides the current root. Entries are in
/// slot order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AnchorStore {
    pub recent: Vec<AnchorEntry>,
    pub epoch: Vec<AnchorEntry>,
}

impl AnchorStore {
    pub fn parse(cell: &Cell) -> anyhow::Result<Self> {
        let mut slice = slice_of(cell)?;
        anyhow::ensure!(
            slice.remaining_bits() == 0 && slice.remaining_references() == 2,
            "an anchor store carries two references and no data"
        );
        let recent = anchor_ring(&reference(&mut slice)?, RECENT_ROOT_SLOTS)?;
        let epoch = anchor_ring(&reference(&mut slice)?, ANCHOR_EPOCH_SLOTS)?;
        Ok(Self { recent, epoch })
    }

    /// The root the contract accepts as a recent anchor with `id`: the entry
    /// in the slot `id` maps to, if it still records `id` itself.
    pub fn recent_root(&self, id: u32) -> Option<[u8; 32]> {
        anchored(&self.recent, id, RECENT_ROOT_SLOTS)
    }

    /// The same for an epoch anchor. Whether the contract still accepts it
    /// also depends on the time it runs at, which this store cannot know.
    pub fn epoch_root(&self, id: u32) -> Option<[u8; 32]> {
        anchored(&self.epoch, id, ANCHOR_EPOCH_SLOTS)
    }
}

fn anchored(entries: &[AnchorEntry], id: u32, slots: u32) -> Option<[u8; 32]> {
    let slot = id.checked_rem(slots)?;
    entries.iter().find(|entry| u32::from(entry.slot) == slot && entry.id == id).map(|e| e.root)
}

/// One ring: a cell holding a `HashmapE 12` in its own encoding, one maybe
/// bit and the root when it has one. An entry the contract could never find
/// -- in a slot that is not its id's -- is refused rather than carried.
fn anchor_ring(holder: &Cell, slots: u32) -> anyhow::Result<Vec<AnchorEntry>> {
    let mut holder = slice_of(holder)?;
    anyhow::ensure!(holder.remaining_bits() >= 1, "an anchor ring without its maybe bit");
    let root = if holder.get_next_bit()? { Some(reference(&mut holder)?) } else { None };
    finished(&holder, "an anchor ring")?;
    let dictionary = HashmapE::with_hashmap(ANCHOR_KEY_BITS, root);
    let mut entries = Vec::new();
    dictionary.iterate_slices(|mut key, mut entry| {
        anyhow::ensure!(
            key.remaining_bits() == ANCHOR_KEY_BITS,
            "an anchor key of the wrong width"
        );
        let slot = u16::try_from(key.get_next_int(ANCHOR_KEY_BITS)?)?;
        anyhow::ensure!(
            entry.remaining_bits() == ANCHOR_ENTRY_BITS && entry.remaining_references() == 0,
            "an anchor entry is not the frozen 32 + 256 bit shape"
        );
        let id = u32::try_from(uint(&mut entry, 32)?)?;
        let root = word(&mut entry)?;
        anyhow::ensure!(
            id.checked_rem(slots) == Some(u32::from(slot)),
            "an anchor stored in a slot that is not its own"
        );
        entries.push(AnchorEntry { slot, id, root });
        Ok(true)
    })?;
    entries.sort_by_key(|entry| entry.slot);
    Ok(entries)
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

/// Section 13: the pool's state cell, less the frontier, which a wallet
/// rebuilds rather than reads. The anchor store is read: a spend anchored to
/// a preserved root has to know the contract still holds it.
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
    pub anchors: AnchorStore,
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
        let anchors = AnchorStore::parse(&reference(&mut slice)?).context("the anchor store")?;
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
            anchors,
        })
    }
}

/// One committed transaction of the pool account, classified.
#[derive(Clone, Debug)]
pub enum PoolTransaction {
    Deposit(DepositBody),
    Transact {
        body: Box<TransactBody>,
        payout: Option<PayoutMessage>,
    },
    /// An authenticated recovery bounce the pool accepted. Whether it minted a
    /// note depends on the charge at the time; the replay decides that.
    Bounce {
        original_body_hash: [u8; 32],
        sender: MsgAddressInt,
        value: u128,
    },
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
    use chain_block::Deserializable;

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

    /// The real pool's history from the circuit crate's sandbox run, with
    /// the state cell it ended in: two withdrawals as the chain holds them,
    /// and an anchor store with every preserved root.
    const HISTORY_FIXTURE: &str =
        include_str!("../../shielded-pool-circuit/fixtures/pool-history-development.json");

    fn fixture() -> serde_json::Value {
        let fixture: serde_json::Value = serde_json::from_str(HISTORY_FIXTURE).expect("json");
        assert_eq!(fixture["schema"], "shielded-pool-history-fixture-v1");
        fixture
    }

    fn cell_of_hex(value: &serde_json::Value) -> Cell {
        let bytes = hex::decode(value.as_str().expect("a hex string")).expect("hex");
        chain_block::read_single_root_boc(bytes).expect("a BOC")
    }

    fn fixture_transacts() -> Vec<(TransactBody, Cell)> {
        let fixture = fixture();
        let mut found = Vec::new();
        for entry in fixture["transactions"].as_array().expect("transactions") {
            let transaction = Transaction::construct_from_cell(cell_of_hex(&entry["boc"]))
                .expect("a transaction");
            let PoolTransaction::Transact { body, .. } =
                classify(&transaction).expect("classified")
            else {
                continue;
            };
            let message = transaction.read_in_msg().expect("in msg").expect("an inbound message");
            let original = message.body().expect("a body").clone().into_cell().expect("cell");
            found.push((*body, original));
        }
        found
    }

    #[test]
    fn the_fixtures_transact_bodies_rebuild_to_the_cells_the_chain_holds() {
        let transacts = fixture_transacts();
        assert_eq!(transacts.len(), 2, "the history holds two withdrawals");
        for (body, original) in &transacts {
            assert!(body.is_withdrawal());
            let rebuilt = body.build().expect("rebuilt");
            assert_eq!(rebuilt.repr_hash(), original.repr_hash(), "the rebuilt body differs");
        }
        let (first, second) = (&transacts[0].0, &transacts[1].0);
        assert_eq!((first.anchor_kind, first.anchor_id), (ANCHOR_CURRENT, 0));
        assert_eq!(second.anchor_kind, ANCHOR_RECENT, "the second spent against a recent root");
        assert_eq!(second.anchor_id, 4, "the root preserved by the first withdrawal");
    }

    fn proof_cell() -> Cell {
        groth16_proof_cell(&[1; PROOF_A_BYTES], &[2; PROOF_B_BYTES], &[3; PROOF_C_BYTES])
            .expect("a proof cell")
    }

    fn witness(seed: u8) -> NullifierWitness {
        NullifierWitness {
            low_index: u32::from(seed),
            low_value: [seed; 32],
            low_next_index: 0,
            low_next_value: [0; 32],
            low_path: (0..IMT_PATH_FIELDS).map(|i| [i as u8; 32]).collect(),
            append_path: (0..IMT_PATH_FIELDS).map(|i| [i as u8 ^ 0xff; 32]).collect(),
        }
    }

    fn transfer_body() -> TransactBody {
        TransactBody {
            query_id: 0x0102_0304_0506_0708,
            anchor_kind: ANCHOR_RECENT,
            anchor_id: 4097,
            valid_until: 1_800_000_000,
            public_amount_out: 0,
            withdrawal_fee: 0,
            recipient: None,
            intent_digest: [0xd1; 32],
            anchor_root: [0xa0; 32],
            nullifiers: [[0xf0; 32], [0xf1; 32]],
            note_bodies: [[0xb0; 32], [0xb1; 32], [0xb2; 32]],
            payloads: [payload(1), payload(2), payload(3)],
            groth16_proof: proof_cell(),
            recovery_owner_commitment: [0; 32],
            recovery_payload: None,
            recovery_cell: Cell::default(),
            auth_bundle: auth_bundle(
                [&[4; AUTH_KEY_BYTES], &[5; AUTH_KEY_BYTES]],
                [&[6; AUTH_SIGNATURE_BYTES], &[7; AUTH_SIGNATURE_BYTES]],
            )
            .expect("an auth bundle"),
            witness_bundle: witness_bundle(&[witness(1), witness(2)]).expect("witnesses"),
        }
    }

    #[test]
    fn a_transfer_body_round_trips_through_the_parser() {
        let body = transfer_body();
        let cell = body.build().expect("built");
        let mut slice = SliceData::load_cell(cell.clone()).expect("slice");
        assert_eq!(uint(&mut slice, 32).expect("op"), u64::from(OP_TRANSACT));
        let parsed = TransactBody::parse(&mut slice).expect("parsed");
        assert_eq!(parsed.query_id, body.query_id);
        assert_eq!((parsed.anchor_kind, parsed.anchor_id), (ANCHOR_RECENT, 4097));
        assert_eq!(parsed.valid_until, body.valid_until);
        assert_eq!(parsed.recipient, None);
        assert_eq!(parsed.recovery_payload, None);
        assert_eq!(parsed.payloads, body.payloads);
        assert_eq!(parsed.nullifiers, body.nullifiers);
        assert_eq!(parsed.note_bodies, body.note_bodies);
        assert_eq!(parsed.groth16_proof, body.groth16_proof);
        assert_eq!(parsed.auth_bundle, body.auth_bundle);
        assert_eq!(parsed.witness_bundle, body.witness_bundle);
        assert_eq!(parsed.build().expect("rebuilt"), cell);

        // A withdrawal, with the recipient as a standard address.
        let recipient = MsgAddressInt::with_params(0, UInt256::from([0xcc; 32])).expect("address");
        let recovery_payload = payload(9);
        let withdrawal = TransactBody {
            public_amount_out: 1_000_000_000,
            withdrawal_fee: 10_000_000,
            recipient: Some(recipient.clone()),
            recovery_owner_commitment: [0x0c; 32],
            recovery_cell: byte_chain(&recovery_payload).expect("chain"),
            recovery_payload: Some(recovery_payload.clone()),
            ..body
        };
        let cell = withdrawal.build().expect("built");
        let mut slice = SliceData::load_cell(cell.clone()).expect("slice");
        uint(&mut slice, 32).expect("op");
        let parsed = TransactBody::parse(&mut slice).expect("parsed");
        assert_eq!(parsed.recipient, Some(recipient));
        assert_eq!(parsed.recovery_payload, Some(recovery_payload));
        assert_eq!(parsed.public_amount_out, 1_000_000_000);
        assert_eq!(parsed.build().expect("rebuilt"), cell);
    }

    #[test]
    fn a_body_the_contract_would_refuse_is_refused_before_it_is_built() {
        let refuses = |body: TransactBody, why: &str| {
            let error = body.build().expect_err(why).to_string();
            assert!(error.contains(why), "{error} does not say {why:?}");
        };
        let base = transfer_body();
        refuses(TransactBody { anchor_kind: 3, ..base.clone() }, "anchor kind");
        refuses(
            TransactBody { anchor_kind: ANCHOR_CURRENT, anchor_id: 1, ..base.clone() },
            "current anchor",
        );
        let recipient = MsgAddressInt::with_params(0, UInt256::from([0xcc; 32])).expect("address");
        refuses(
            TransactBody { recipient: Some(recipient.clone()), ..base.clone() },
            "names a recipient",
        );
        refuses(TransactBody { withdrawal_fee: 1, ..base.clone() }, "transfer with a fee");
        refuses(
            TransactBody { public_amount_out: 1, withdrawal_fee: 1, ..base.clone() },
            "names a recipient",
        );
        refuses(
            TransactBody {
                public_amount_out: 1,
                withdrawal_fee: 1,
                recipient: Some(recipient.clone()),
                ..base.clone()
            },
            "recovery payload",
        );
        refuses(
            TransactBody {
                public_amount_out: 1,
                withdrawal_fee: 1,
                recipient: Some(recipient.clone()),
                recovery_payload: Some(payload(9)),
                ..base.clone()
            },
            "recovery cell",
        );
        refuses(
            TransactBody { payloads: [payload(1), vec![1; 10], payload(3)], ..base.clone() },
            "output payload",
        );
        let masterchain =
            MsgAddressInt::with_params(-1, UInt256::from([0xcc; 32])).expect("address");
        let on_masterchain = TransactBody {
            public_amount_out: 1,
            withdrawal_fee: 1,
            recipient: Some(masterchain),
            recovery_payload: Some(payload(9)),
            recovery_cell: byte_chain(&payload(9)).expect("chain"),
            ..base
        };
        // The codec carries any standard address; the pool decides what it pays.
        let mut slice = SliceData::load_cell(on_masterchain.build().expect("built")).expect("s");
        uint(&mut slice, 32).expect("op");
        assert_eq!(
            TransactBody::parse(&mut slice).expect("parsed").recipient.map(|r| r.workchain_id()),
            Some(-1)
        );
    }

    #[test]
    fn the_bundles_hold_their_frozen_shapes_and_check_their_lengths() {
        let proof = proof_cell();
        assert_eq!((proof.bit_length(), proof.references_count()), (768, 1));
        assert_eq!(proof.reference(0).expect("B").bit_length(), 768);
        assert!(groth16_proof_cell(&[1; PROOF_A_BYTES - 1], &[2; PROOF_B_BYTES], &[3; 48]).is_err());
        assert!(groth16_proof_cell(&[1; PROOF_A_BYTES], &[2; PROOF_B_BYTES + 1], &[3; 48]).is_err());

        let auth = auth_bundle(
            [&[4; AUTH_KEY_BYTES], &[5; AUTH_KEY_BYTES]],
            [&[6; AUTH_SIGNATURE_BYTES], &[7; AUTH_SIGNATURE_BYTES]],
        )
        .expect("auth");
        assert_eq!((auth.bit_length(), auth.references_count()), (0, 4));
        assert_eq!(
            read_byte_chain(&auth.reference(1).expect("sig"), AUTH_SIGNATURE_BYTES).expect("sig"),
            vec![6; AUTH_SIGNATURE_BYTES]
        );
        assert!(
            auth_bundle([&[4; AUTH_KEY_BYTES], &[5; 10]], [&[6; 2420], &[7; 2420]]).is_err(),
            "a short key"
        );
        assert!(
            auth_bundle([&[4; 1312], &[5; 1312]], [&[6; AUTH_SIGNATURE_BYTES + 1], &[7; 2420]])
                .is_err(),
            "a long signature"
        );

        let cell = witness(1).cell().expect("a witness cell");
        assert_eq!((cell.bit_length(), cell.references_count()), (576, 2));
        for path in [cell.reference(0).expect("low"), cell.reference(1).expect("append")] {
            let mut current = path;
            let mut cells = 1;
            loop {
                assert_eq!(current.bit_length(), 768, "three siblings per cell");
                match current.references_count() {
                    0 => break,
                    1 => {
                        current = current.reference(0).expect("next");
                        cells += 1;
                    }
                    n => panic!("{n} references in a path cell"),
                }
            }
            assert_eq!(cells, 24, "twelve levels of six siblings, three to a cell");
        }
        let mut short = witness(1);
        short.low_path.pop();
        assert!(short.cell().is_err(), "71 siblings");
        let mut long = witness(1);
        long.append_path.push([0; 32]);
        assert!(long.cell().is_err(), "73 siblings");
        let bundle = witness_bundle(&[witness(1), witness(2)]).expect("bundle");
        assert_eq!((bundle.bit_length(), bundle.references_count()), (0, 2));
    }

    #[test]
    fn the_fixtures_anchor_store_holds_every_preserved_root() {
        let fixture = fixture();
        let state = PoolState::parse(&cell_of_hex(&fixture["account_data"])).expect("state");
        // Four deposits at versions 0..3, the first withdrawal at 4 (three
        // outputs), the recovery mint at 7, the second withdrawal at 8.
        let ids: Vec<u32> = state.anchors.recent.iter().map(|entry| entry.id).collect();
        assert_eq!(ids, vec![0, 1, 2, 3, 4, 7, 8]);
        assert!(state.anchors.recent.iter().all(|e| u32::from(e.slot) == e.id), "below the ring");
        assert_eq!(state.commitment_next_index, 11);

        let transacts = fixture_transacts();
        // Both withdrawals spent against the root after the four deposits: the
        // first as the current root, which it then preserved as version 4, the
        // second as that recent entry.
        assert_eq!(state.anchors.recent_root(4), Some(transacts[0].0.anchor_root));
        assert_eq!(state.anchors.recent_root(4), Some(transacts[1].0.anchor_root));
        assert!(state.anchors.recent_root(0).is_some(), "the empty tree's root is preserved too");
        assert_eq!(state.anchors.recent_root(5), None, "never preserved");
        assert_eq!(state.anchors.recent_root(4 + RECENT_ROOT_SLOTS), None, "same slot, other id");
        assert_eq!(state.anchors.epoch.len(), 1, "one epoch in a sandbox run");
        assert_eq!(state.anchors.epoch[0].id, state.last_anchor_epoch);
        assert_eq!(
            state.anchors.epoch_root(state.last_anchor_epoch),
            Some(state.anchors.epoch[0].root)
        );
    }

    fn ring_cell(entries: &[(u32, u32, [u8; 32])]) -> Cell {
        let mut dictionary = HashmapE::with_bit_len(ANCHOR_KEY_BITS);
        for (slot, id, root) in entries {
            let mut key = BuilderData::new();
            key.append_bits(usize::try_from(*slot).expect("slot"), ANCHOR_KEY_BITS).expect("key");
            let mut value = BuilderData::new();
            value.append_u32(*id).expect("id");
            value.append_raw(root, 256).expect("root");
            dictionary
                .set(
                    SliceData::load_builder(key).expect("key"),
                    &SliceData::load_builder(value).expect("value"),
                )
                .expect("set");
        }
        let mut holder = BuilderData::new();
        match dictionary.data() {
            Some(root) => {
                holder.append_bit_one().expect("maybe");
                holder.checked_append_reference(root.clone()).expect("root");
            }
            None => {
                holder.append_bit_zero().expect("maybe");
            }
        }
        holder.into_cell().expect("holder")
    }

    fn store_cell(recent: Cell, epoch: Cell) -> Cell {
        let mut builder = BuilderData::new();
        builder.checked_append_reference(recent).expect("recent");
        builder.checked_append_reference(epoch).expect("epoch");
        builder.into_cell().expect("store")
    }

    #[test]
    fn an_anchor_store_is_read_as_the_contract_would_and_refused_where_it_could_not_be() {
        let empty = AnchorStore::parse(&store_cell(ring_cell(&[]), ring_cell(&[]))).expect("empty");
        assert_eq!(empty, AnchorStore::default());

        // The ring wraps: version 4096 + 5 lives in slot 5, and only its own id finds it.
        let wrapped = ring_cell(&[(5, RECENT_ROOT_SLOTS + 5, [0x55; 32]), (6, 6, [0x66; 32])]);
        let store = AnchorStore::parse(&store_cell(wrapped, ring_cell(&[]))).expect("wrapped");
        assert_eq!(store.recent_root(RECENT_ROOT_SLOTS + 5), Some([0x55; 32]));
        assert_eq!(store.recent_root(5), None, "overwritten by the later version");
        assert_eq!(store.recent_root(6), Some([0x66; 32]));
        assert_eq!(store.epoch_root(6), None, "the other ring");

        // An entry in a slot the contract would never look in for its id.
        let foreign = ring_cell(&[(5, 6, [0x66; 32])]);
        let error = AnchorStore::parse(&store_cell(foreign, ring_cell(&[]))).expect_err("foreign");
        assert!(error.to_string().contains("not its own"), "{error}");

        // An entry of the wrong shape.
        let mut dictionary = HashmapE::with_bit_len(ANCHOR_KEY_BITS);
        let mut key = BuilderData::new();
        key.append_bits(1, ANCHOR_KEY_BITS).expect("key");
        let mut value = BuilderData::new();
        value.append_u32(1).expect("id");
        dictionary
            .set(
                SliceData::load_builder(key).expect("key"),
                &SliceData::load_builder(value).expect("value"),
            )
            .expect("set");
        let mut holder = BuilderData::new();
        holder.append_bit_one().expect("maybe");
        holder.checked_append_reference(dictionary.data().expect("root").clone()).expect("root");
        let malformed = holder.into_cell().expect("holder");
        let error = AnchorStore::parse(&store_cell(malformed, ring_cell(&[]))).expect_err("shape");
        assert!(error.to_string().contains("32 + 256"), "{error}");

        // A store root that is not two references.
        let mut one = BuilderData::new();
        one.checked_append_reference(ring_cell(&[])).expect("one");
        assert!(AnchorStore::parse(&one.into_cell().expect("cell")).is_err());
    }
}
