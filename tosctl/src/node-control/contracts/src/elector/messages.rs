/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use chain_block::{BuilderData, Cell, IBitstring};

pub mod opcodes {
    /// Opcode for voting on a complaint (internal message to elector)
    pub const VOTE_FOR_COMPLAINT: u32 = 0x56744370;
}

/// Tag used in the data-to-sign for complaint votes.
/// Matches `complaint-vote-req.fif`: B{56744350}
const COMPLAINT_VOTE_TAG: u32 = 0x56744350;

/// Build complaint vote data for signing by validator.
///
/// Format: `0x56744350 | validator_idx (16 bits) | election_id (32 bits) | complaint_hash (256 bits)`
///
/// This matches the output of `complaint-vote-req.fif`.
pub fn unsigned_complaint_vote(
    validator_idx: u16,
    election_id: u32,
    complaint_hash: &[u8; 32],
) -> anyhow::Result<BuilderData> {
    let mut builder = BuilderData::new();
    builder
        .append_u32(COMPLAINT_VOTE_TAG)?
        .append_u16(validator_idx)?
        .append_u32(election_id)?
        .append_raw(complaint_hash, 256)?;
    Ok(builder)
}

/// Builds complaint vote message body with signature.
///
/// Format: `0x56744370 | query_id (64 bits) | signature (512 bits) | unsigned_data`
///
/// This matches the output of `complaint-vote-signed.fif`.
pub fn signed_complaint_vote(
    query_id: u64,
    unsigned_body: &BuilderData,
    signature: &[u8],
) -> anyhow::Result<Cell> {
    if signature.len() != 64 {
        anyhow::bail!("signature must be 64 bytes, got {}", signature.len());
    }

    let mut builder = BuilderData::new();
    builder
        .append_u32(opcodes::VOTE_FOR_COMPLAINT)?
        .append_u64(query_id)?
        .append_raw(signature, 512)?
        .append_builder(unsigned_body)?;
    builder.into_cell()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_block::SliceData;

    #[test]
    fn test_unsigned_complaint_vote() {
        let builder = unsigned_complaint_vote(42, 1000, &[0xAB; 32]).unwrap();
        let cell = builder.into_cell().unwrap();
        let mut slice = SliceData::load_cell(cell).unwrap();

        assert_eq!(slice.get_next_u32().unwrap(), COMPLAINT_VOTE_TAG);
        assert_eq!(slice.get_next_u16().unwrap(), 42);
        assert_eq!(slice.get_next_u32().unwrap(), 1000);
        assert_eq!(slice.get_next_bits(256).unwrap(), vec![0xAB; 32]);
        assert_eq!(slice.remaining_bits(), 0);
    }

    #[test]
    fn test_signed_complaint_vote() {
        let signature = [0x11u8; 64];
        let body = unsigned_complaint_vote(123, 5000, &[0xCD; 32]).unwrap();
        let query_id: u64 = 0x1234567890ABCDEF;
        let cell = signed_complaint_vote(query_id, &body, &signature).unwrap();
        let mut slice = SliceData::load_cell(cell).unwrap();

        assert_eq!(slice.get_next_u32().unwrap(), opcodes::VOTE_FOR_COMPLAINT);
        assert_eq!(slice.get_next_u64().unwrap(), query_id);
        assert_eq!(slice.get_next_bits(512).unwrap(), signature.to_vec());

        assert_eq!(slice.get_next_u32().unwrap(), COMPLAINT_VOTE_TAG);
        assert_eq!(slice.get_next_u16().unwrap(), 123);
        assert_eq!(slice.get_next_u32().unwrap(), 5000);
        assert_eq!(slice.get_next_bits(256).unwrap(), vec![0xCD; 32]);
        assert_eq!(slice.remaining_bits(), 0);
    }

    #[test]
    fn test_signed_complaint_vote_invalid_signature_length() {
        let body = unsigned_complaint_vote(1, 100, &[0x00; 32]).unwrap();
        let query_id: u64 = 1;

        let result = signed_complaint_vote(query_id, &body, &[0u8; 32]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("signature must be 64 bytes"));

        let result = signed_complaint_vote(query_id, &body, &[0u8; 128]);
        assert!(result.is_err());
    }
}
