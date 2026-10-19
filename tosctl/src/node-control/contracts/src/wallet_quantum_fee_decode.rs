// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Canonical pending intent decoding. This does not authorize signing or delivery.
use super::*;
use chain_block::Deserializable;

impl FeeIntent {
    /// Decode a saved canonical intent for cache lookup. `epoch0` must come from
    /// locally authenticated enrollment; it is not stored in the intent cell.
    /// No freshness or signing permission is implied: pass the result through
    /// `FeeJournal::retry_proven_fee` with current proofs. Expired cells may be
    /// decoded for inspection, but cannot pass the retry deadline check.
    pub fn from_cached_cell(cell: Cell, epoch0: u32) -> anyhow::Result<Self> {
        anyhow::ensure!(
            cell.cell_type() == CellType::Ordinary && cell.level() == 0,
            "ordinary cached fee intent required"
        );
        let mut s = SliceData::load_cell(cell.clone())?;
        anyhow::ensure!(s.get_next_u32()? == 0x46454534, "cached fee constructor");
        anyhow::ensure!(s.get_next_bytes(17)? == b"TOS-RESCUE-FEE-v1", "cached fee domain");
        let class = match s.get_next_byte()? {
            1 => FeeClass::RescueAuth,
            2 => FeeClass::Pop,
            3 => FeeClass::Prepare,
            _ => anyhow::bail!("cached fee class"),
        };
        anyhow::ensure!(s.get_next_int(11)? == 1024, "cached fee basechain address");
        let vault = *s.get_next_hash()?.as_array();
        let config_hash = *s.get_next_hash()?.as_array();
        let leaf = s.get_next_u32()?;
        let valid_until = s.get_next_u32()?;
        let value = Coins::construct_from(&mut s)?.as_u128();
        let payload = FeePayload::from_submission(class, s.checked_drain_reference()?)?;
        anyhow::ensure!(
            s.remaining_bits() == 0 && s.remaining_references() == 0,
            "cached fee trailing data"
        );
        anyhow::ensure!(leaf < LEAF_COUNT, "cached fee tree exhausted");
        anyhow::ensure!(value > 0, "cached fee zero value");
        let decoded = Self::encode(
            FeeBinding { vault, config_hash, epoch0, leaf, valid_until, value },
            payload,
        )?;
        anyhow::ensure!(
            decoded.cell.repr_hash() == cell.repr_hash(),
            "noncanonical cached fee intent"
        );
        Ok(decoded)
    }
}
