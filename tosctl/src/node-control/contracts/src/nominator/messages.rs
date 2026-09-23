/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use chain_block::{BuilderData, Cell, Coins, IBitstring, MsgAddressInt, Serializable, pq_bytes};

const MLDSA44_SIGNATURE_BYTES: usize = 2420;
const MLDSA44_PUBLIC_KEY_BYTES: usize = 1312;
const MLDSA44_ALGORITHM_ID: u16 = 1;

/// Opcodes for single-nominator contract messages
pub mod opcodes {
    /// Withdraw funds to owner's wallet
    pub const WITHDRAW: u32 = 0x1000;
    /// Change the validator address
    pub const CHANGE_VALIDATOR_ADDRESS: u32 = 0x1001;
    /// Send arbitrary message from nominator contract (emergency)
    pub const SEND_RAW_MSG: u32 = 0x7702;
    /// Upgrade nominator contract code (emergency)
    pub const UPGRADE: u32 = 0x9903;
    /// Send new stake to the elector
    pub const NEW_STAKE: u32 = 0x4e73744b;
    /// Recover stake from the elector
    pub const RECOVER_STAKE: u32 = 0x47657424;
}

/// Parameters for new stake message
#[derive(Debug, Clone)]
pub struct NewStakeParams<'a> {
    /// Query ID for the message (must be > 0)
    pub query_id: u64,
    /// Stake amount in nanotos
    pub stake_amount: u64,
    /// ML-DSA-44 consensus public key (1312 bytes); never a key-hash prefix.
    pub validator_pubkey: &'a [u8],
    /// Elections id fetched from elector
    pub stake_at: u32,
    /// Max factor for stake
    pub max_factor: u32,
    /// ADNL address (256 bits)
    pub adnl_addr: &'a [u8],
    /// ML-DSA-44 signature of the stake authorization
    pub signature: &'a [u8],
}

fn build_coins(amount: u64) -> anyhow::Result<BuilderData> {
    let coins = Coins::new(amount);
    let mut builder = BuilderData::new();
    coins.write_to(&mut builder)?;
    Ok(builder)
}

/// Build withdraw message body
///
/// Allows owner to withdraw funds from the contract.
/// The contract will leave MIN_TOS_FOR_STORAGE (1 TOS) in the contract.
pub fn withdraw(query_id: u64, amount: u64) -> anyhow::Result<Cell> {
    let mut builder = BuilderData::new();
    builder
        .append_u32(opcodes::WITHDRAW)?
        .append_u64(query_id)?
        .append_builder(&build_coins(amount)?)?;
    builder.into_cell()
}

/// Build change validator address message body
///
/// Allows owner to change the validator address.
/// Used when validator private key is compromised.
pub fn change_validator(
    query_id: u64,
    new_validator_address: &MsgAddressInt,
) -> anyhow::Result<Cell> {
    let mut builder = BuilderData::new();
    builder.append_u32(opcodes::CHANGE_VALIDATOR_ADDRESS)?.append_u64(query_id)?;
    new_validator_address.write_to(&mut builder)?;
    builder.into_cell()
}

/// Build send raw message body
///
/// Emergency safeguard allowing owner to send arbitrary messages
/// as the nominator contract.
pub fn raw_msg(query_id: u64, mode: u8, msg: Cell) -> anyhow::Result<Cell> {
    let mut builder = BuilderData::new();
    builder
        .append_u32(opcodes::SEND_RAW_MSG)?
        .append_u64(query_id)?
        .append_u8(mode)?
        .checked_append_reference(msg)?;
    builder.into_cell()
}

/// Build upgrade message body
///
/// Emergency safeguard to upgrade nominator contract code.
/// Should never need to use this under normal conditions.
pub fn upgrade(query_id: u64, new_code: Cell) -> anyhow::Result<Cell> {
    let mut builder = BuilderData::new();
    builder
        .append_u32(opcodes::UPGRADE)?
        .append_u64(query_id)?
        .checked_append_reference(new_code)?;
    builder.into_cell()
}

/// Build new stake message body
///
/// Sends stake to the single-nominator pool for the next validation cycle.
/// The pool's `check_new_stake_msg` consumes stake_at, max_factor, adnl_addr,
/// algorithm_id, public-key ref, signature ref, then optional witness. The
/// elector consumes a different field order and an owner declaration; this is
/// deliberately not an elector-directed body.
pub fn new_stake(params: &NewStakeParams) -> anyhow::Result<Cell> {
    new_stake_with_witness(params, None)
}

pub fn new_stake_with_witness(
    params: &NewStakeParams,
    witness: Option<&Cell>,
) -> anyhow::Result<Cell> {
    if params.validator_pubkey.len() != MLDSA44_PUBLIC_KEY_BYTES {
        anyhow::bail!(
            "a stake authorization needs an ML-DSA-44 public key of {MLDSA44_PUBLIC_KEY_BYTES} bytes, not {}",
            params.validator_pubkey.len()
        );
    }
    if params.adnl_addr.len() != 32 {
        anyhow::bail!("a stake ADNL address is 32 bytes, not {}", params.adnl_addr.len());
    }
    if params.signature.len() != MLDSA44_SIGNATURE_BYTES {
        anyhow::bail!(
            "a stake authorization is signed with ML-DSA-44, which is {MLDSA44_SIGNATURE_BYTES} \
             bytes, and this signature is {}",
            params.signature.len()
        );
    }
    let public_key_cell =
        pq_bytes::pack_pq_bytes(params.validator_pubkey, MLDSA44_PUBLIC_KEY_BYTES)?;
    let signature_cell = pq_bytes::pack_pq_bytes(params.signature, MLDSA44_SIGNATURE_BYTES)?;
    let mut builder = BuilderData::new();
    builder
        .append_u32(opcodes::NEW_STAKE)?
        .append_u64(params.query_id)?
        .append_builder(&build_coins(params.stake_amount)?)?
        .append_u32(params.stake_at)?
        .append_u32(params.max_factor)?
        .append_raw(params.adnl_addr, 256)?
        .append_u16(MLDSA44_ALGORITHM_ID)?
        .checked_append_reference(public_key_cell)?
        .checked_append_reference(signature_cell)?;
    if let Some(witness) = witness {
        builder.append_bit_one()?.checked_append_reference(witness.clone())?;
    } else {
        builder.append_bit_zero()?;
    }
    builder.into_cell()
}

/// Build recover stake message body
///
/// Recovers stake from elector of previous validation cycle.
pub fn recover_stake(query_id: u64) -> anyhow::Result<Cell> {
    let mut builder = BuilderData::new();
    builder.append_u32(opcodes::RECOVER_STAKE)?.append_u64(query_id)?;
    builder.into_cell()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_block::{Deserializable, SliceData};

    #[test]
    fn test_build_withdraw_message() {
        let query_id = 12345u64;
        let amount = 1_000_000_000u64;

        let cell = withdraw(query_id, amount).unwrap();
        let mut slice = SliceData::load_cell(cell).unwrap();

        let opcode = slice.get_next_u32().unwrap();
        assert_eq!(opcode, opcodes::WITHDRAW);

        let parsed_query_id = slice.get_next_u64().unwrap();
        assert_eq!(parsed_query_id, query_id);

        let coins = Coins::construct_from(&mut slice).unwrap();
        assert_eq!(coins.as_u128(), amount as u128);
    }

    #[test]
    fn test_build_change_validator_message() {
        let query_id = 67890u64;
        let new_validator = MsgAddressInt::with_standart(None, -1, [0xABu8; 32].into()).unwrap();

        let cell = change_validator(query_id, &new_validator).unwrap();
        let mut slice = SliceData::load_cell(cell).unwrap();

        let opcode = slice.get_next_u32().unwrap();
        assert_eq!(opcode, opcodes::CHANGE_VALIDATOR_ADDRESS);

        let parsed_query_id = slice.get_next_u64().unwrap();
        assert_eq!(parsed_query_id, query_id);

        let parsed_addr = MsgAddressInt::construct_from(&mut slice).unwrap();
        assert_eq!(parsed_addr, new_validator);
    }

    #[test]
    fn test_build_send_raw_msg() {
        let query_id = 11111u64;
        let mode = 64u8;

        let mut msg_builder = BuilderData::new();
        msg_builder.append_u32(0xDEADBEEF).unwrap();
        let msg = msg_builder.into_cell().unwrap();

        let cell = raw_msg(query_id, mode, msg.clone()).unwrap();
        let mut slice = SliceData::load_cell(cell).unwrap();

        let opcode = slice.get_next_u32().unwrap();
        assert_eq!(opcode, opcodes::SEND_RAW_MSG);

        let parsed_query_id = slice.get_next_u64().unwrap();
        assert_eq!(parsed_query_id, query_id);

        let parsed_mode = slice.get_next_byte().unwrap();
        assert_eq!(parsed_mode, mode);

        let ref_cell = slice.checked_drain_reference().unwrap();
        assert_eq!(ref_cell.repr_hash(), msg.repr_hash());
    }

    #[test]
    fn test_build_upgrade_message() {
        let query_id = 22222u64;

        let mut code_builder = BuilderData::new();
        code_builder.append_u32(0xCAFEBABE).unwrap();
        let new_code = code_builder.into_cell().unwrap();

        let cell = upgrade(query_id, new_code.clone()).unwrap();
        let mut slice = SliceData::load_cell(cell).unwrap();

        let opcode = slice.get_next_u32().unwrap();
        assert_eq!(opcode, opcodes::UPGRADE);

        let parsed_query_id = slice.get_next_u64().unwrap();
        assert_eq!(parsed_query_id, query_id);

        let ref_cell = slice.checked_drain_reference().unwrap();
        assert_eq!(ref_cell.repr_hash(), new_code.repr_hash());
    }

    #[test]
    fn test_build_new_stake_message() {
        let signature = vec![0x33u8; MLDSA44_SIGNATURE_BYTES];
        let params = NewStakeParams {
            query_id: 33333u64,
            stake_amount: 10_000_000_000_000u64,
            validator_pubkey: &[0x11u8; MLDSA44_PUBLIC_KEY_BYTES],
            stake_at: 1700000000u32,
            max_factor: 65536u32,
            adnl_addr: &[0x22u8; 32],
            signature: &signature,
        };

        let cell = new_stake(&params).unwrap();
        let mut slice = SliceData::load_cell(cell).unwrap();

        let opcode = slice.get_next_u32().unwrap();
        assert_eq!(opcode, opcodes::NEW_STAKE);

        let parsed_query_id = slice.get_next_u64().unwrap();
        assert_eq!(parsed_query_id, params.query_id);

        let coins = Coins::construct_from(&mut slice).unwrap();
        assert_eq!(coins.as_u128(), params.stake_amount as u128);

        // This value round trip is the ordering gate. The compiled pool contract
        // accepts adjacent fixed-width fields even when transposed, because it
        // parses but does not interpret their contents. Its sandbox test alone
        // cannot detect that mistake. This is pool order, not elector order.
        let parsed_stake_at = slice.get_next_u32().unwrap();
        assert_eq!(parsed_stake_at, params.stake_at);

        let parsed_max_factor = slice.get_next_u32().unwrap();
        assert_eq!(parsed_max_factor, params.max_factor);

        let adnl = slice.get_next_bits(256).unwrap();
        assert_eq!(adnl, params.adnl_addr.to_vec());

        let algorithm_id = slice.get_next_u16().unwrap();
        assert_eq!(algorithm_id, MLDSA44_ALGORITHM_ID);

        let key_cell = slice.checked_drain_reference().unwrap();
        assert_eq!(
            pq_bytes::unpack_pq_bytes(&key_cell, MLDSA44_PUBLIC_KEY_BYTES).unwrap(),
            params.validator_pubkey
        );

        let sig_cell = slice.checked_drain_reference().unwrap();
        assert_eq!(
            pq_bytes::unpack_pq_bytes(&sig_cell, MLDSA44_SIGNATURE_BYTES).unwrap(),
            params.signature
        );
        assert!(!slice.get_next_bit().unwrap());
        assert_eq!(slice.remaining_bits(), 0);
        assert_eq!(slice.remaining_references(), 0);
    }

    #[test]
    fn test_new_stake_refuses_classical_signature_before_building() {
        let params = NewStakeParams {
            query_id: 1,
            stake_amount: 1,
            validator_pubkey: &[0x11; MLDSA44_PUBLIC_KEY_BYTES],
            stake_at: 1,
            max_factor: 65536,
            adnl_addr: &[0x22; 32],
            signature: &[0x33; 64],
        };

        let error = new_stake(&params).unwrap_err().to_string();
        assert!(error.contains("ML-DSA-44"), "wrong refusal: {error}");
        assert!(error.contains("2420"), "wrong refusal: {error}");
        assert!(error.contains("64"), "wrong refusal: {error}");
    }

    #[test]
    fn test_new_stake_refuses_truncated_public_key() {
        let signature = vec![0x33; MLDSA44_SIGNATURE_BYTES];
        let params = NewStakeParams {
            query_id: 1,
            stake_amount: 1,
            validator_pubkey: &[0x11; 32],
            stake_at: 1,
            max_factor: 65536,
            adnl_addr: &[0x22; 32],
            signature: &signature,
        };
        let error = new_stake(&params).unwrap_err().to_string();
        assert!(error.contains("ML-DSA-44 public key"), "wrong refusal: {error}");
        assert!(error.contains("1312"), "wrong refusal: {error}");
        assert!(error.contains("32"), "wrong refusal: {error}");
    }

    #[test]
    fn test_pool_stake_optional_witness_is_a_final_reference() {
        let signature = vec![0x33; MLDSA44_SIGNATURE_BYTES];
        let params = NewStakeParams {
            query_id: 1,
            stake_amount: 1,
            validator_pubkey: &[0x11; MLDSA44_PUBLIC_KEY_BYTES],
            stake_at: 2,
            max_factor: 65536,
            adnl_addr: &[0x22; 32],
            signature: &signature,
        };
        let witness = BuilderData::new().into_cell().unwrap();
        let mut slice =
            SliceData::load_cell(new_stake_with_witness(&params, Some(&witness)).unwrap()).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), opcodes::NEW_STAKE);
        assert_eq!(slice.get_next_u64().unwrap(), params.query_id);
        let _stake_amount = Coins::construct_from(&mut slice).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), params.stake_at);
        assert_eq!(slice.get_next_u32().unwrap(), params.max_factor);
        assert_eq!(slice.get_next_bits(256).unwrap(), params.adnl_addr);
        assert_eq!(slice.get_next_u16().unwrap(), MLDSA44_ALGORITHM_ID);
        let _key = slice.checked_drain_reference().unwrap();
        let _signature = slice.checked_drain_reference().unwrap();
        assert!(slice.get_next_bit().unwrap());
        assert_eq!(slice.checked_drain_reference().unwrap().repr_hash(), witness.repr_hash());
        assert_eq!(slice.remaining_bits(), 0);
        assert_eq!(slice.remaining_references(), 0);
    }

    #[test]
    fn test_build_recover_stake_message() {
        let query_id = 44444u64;

        let cell = recover_stake(query_id).unwrap();
        let mut slice = SliceData::load_cell(cell).unwrap();

        let opcode = slice.get_next_u32().unwrap();
        assert_eq!(opcode, opcodes::RECOVER_STAKE);

        let parsed_query_id = slice.get_next_u64().unwrap();
        assert_eq!(parsed_query_id, query_id);

        assert_eq!(slice.remaining_bits(), 0);
    }

    #[test]
    fn test_build_coins_helper() {
        let amount = 5_000_000_000u64;

        let builder = build_coins(amount).unwrap();
        let cell = builder.into_cell().unwrap();
        let mut slice = SliceData::load_cell(cell).unwrap();

        let coins = Coins::construct_from(&mut slice).unwrap();
        assert_eq!(coins.as_u128(), amount as u128);
    }

    #[test]
    fn test_build_coins_zero() {
        let amount = 0u64;

        let builder = build_coins(amount).unwrap();
        let cell = builder.into_cell().unwrap();
        let mut slice = SliceData::load_cell(cell).unwrap();

        let coins = Coins::construct_from(&mut slice).unwrap();
        assert_eq!(coins.as_u128(), 0);
    }
}
