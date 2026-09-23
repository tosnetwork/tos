/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

use chain_block::{BuilderData, Cell, IBitstring, Serializable, StateInit};

use super::messages::{NewStakeParams, new_stake_with_witness};

/// Build a first-stake pool order only after its controller birth artifact
/// matches both the node-bound validator identity and the live admission code.
/// The caller must source `admitted_code_hash` from ConfigParam 47, not from
/// the deployment artifact itself. This function makes no network query.
pub fn new_stake_with_verified_controller_birth(
    params: &NewStakeParams<'_>,
    deployment: &StateInit,
    expected_validator_id: &[u8; 32],
    admitted_code_hash: &[u8; 32],
) -> anyhow::Result<Cell> {
    let witness =
        verified_controller_birth_witness(deployment, expected_validator_id, admitted_code_hash)?;
    new_stake_with_witness(params, Some(&witness))
}

/// Derive the first-stake witness from the controller's original deployment StateInit.
///
/// `expected_validator_id` must be the controller address held by the node and
/// recorded by the pool. `admitted_code_hash` must be read from live ConfigParam
/// 47 by the caller, not copied from this artifact. This function checks both
/// against the artifact before producing a fee-bearing pool order. It cannot
/// reconstruct birth data from an account's mutable current storage.
pub fn verified_controller_birth_witness(
    deployment: &StateInit,
    expected_validator_id: &[u8; 32],
    admitted_code_hash: &[u8; 32],
) -> anyhow::Result<Cell> {
    let code = deployment
        .code
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("controller deployment StateInit has no code"))?;
    let data = deployment
        .data
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("controller deployment StateInit has no data"))?;
    // The Elector rebuilds the ordinary code/data-only StateInit from the four
    // witness values. Other StateInit fields would produce a different address
    // even if this artifact's own hash matched the configured controller.
    let canonical = StateInit::with_code_and_data(code.clone(), data.clone());
    let actual = deployment.write_to_new_cell()?.into_cell()?;
    let canonical_cell = canonical.write_to_new_cell()?.into_cell()?;
    anyhow::ensure!(
        actual.repr_hash() == canonical_cell.repr_hash(),
        "controller deployment StateInit is not the code/data-only shape the Elector reconstructs"
    );
    anyhow::ensure!(
        canonical_cell.repr_hash().as_slice() == expected_validator_id,
        "controller deployment StateInit address differs from node-bound validator_id"
    );
    anyhow::ensure!(
        code.repr_hash().as_slice() == admitted_code_hash,
        "controller deployment code hash is not the live admitted ConfigParam 47 code"
    );

    let mut witness = BuilderData::new();
    witness.append_raw(code.repr_hash().as_slice(), 256)?;
    witness.append_u16(code.repr_depth())?;
    witness.append_raw(data.repr_hash().as_slice(), 256)?;
    witness.append_u16(data.repr_depth())?;
    anyhow::ensure!(witness.length_in_bits() == 544, "controller birth witness is not 544 bits");
    Ok(witness.into_cell()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_block::{Deserializable, SliceData};

    fn fixture() -> (StateInit, [u8; 32], [u8; 32]) {
        let mut code = BuilderData::new();
        code.append_u32(0x1234_5678).expect("code");
        let mut data = BuilderData::new();
        data.append_u64(0x9876_5432).expect("data");
        let state = StateInit::with_code_and_data(
            code.into_cell().expect("code cell"),
            data.into_cell().expect("data cell"),
        );
        let address_cell = state.write_to_new_cell().expect("state").into_cell().expect("cell");
        let mut address = [0u8; 32];
        address.copy_from_slice(address_cell.repr_hash().as_slice());
        let mut code_hash = [0u8; 32];
        code_hash.copy_from_slice(state.code.as_ref().expect("code").repr_hash().as_slice());
        (state, address, code_hash)
    }

    #[test]
    fn controller_birth_witness_matches_both_identity_and_live_policy() {
        let (state, address, code_hash) = fixture();
        let witness = verified_controller_birth_witness(&state, &address, &code_hash)
            .expect("verified witness");
        assert_eq!(witness.bit_length(), 544);
        assert_eq!(witness.references_count(), 0);
        let mut fields = SliceData::load_cell(witness).expect("witness slice");
        assert_eq!(fields.get_next_bytes(32).expect("code hash"), code_hash);
        assert_eq!(
            fields.get_next_u16().expect("code depth"),
            state.code.as_ref().expect("code").repr_depth()
        );
        assert_eq!(
            fields.get_next_bytes(32).expect("data hash"),
            state.data.as_ref().expect("data").repr_hash().as_slice()
        );
        assert_eq!(
            fields.get_next_u16().expect("data depth"),
            state.data.as_ref().expect("data").repr_depth()
        );
        assert_eq!(fields.remaining_bits(), 0);
        let mut wrong_address = address;
        wrong_address[0] ^= 1;
        assert!(
            verified_controller_birth_witness(&state, &wrong_address, &code_hash)
                .unwrap_err()
                .to_string()
                .contains("validator_id")
        );
        let mut wrong_code = code_hash;
        wrong_code[0] ^= 1;
        assert!(
            verified_controller_birth_witness(&state, &address, &wrong_code)
                .unwrap_err()
                .to_string()
                .contains("ConfigParam 47")
        );
    }

    #[test]
    fn controller_birth_witness_refuses_missing_or_noncanonical_birth_data() {
        let (state, address, code_hash) = fixture();
        let missing_data = StateInit { data: None, ..state.clone() };
        assert!(
            verified_controller_birth_witness(&missing_data, &address, &code_hash)
                .unwrap_err()
                .to_string()
                .contains("no data")
        );
        let mut noncanonical = state;
        noncanonical.set_library(Cell::default());
        assert!(
            verified_controller_birth_witness(&noncanonical, &address, &code_hash)
                .unwrap_err()
                .to_string()
                .contains("code/data-only")
        );
    }

    #[test]
    fn first_stake_pool_body_contains_verified_witness_and_refuses_bad_artifact() {
        let (state, address, code_hash) = fixture();
        let signature = vec![0x33; 2420];
        let public_key = vec![0x11; 1312];
        let params = NewStakeParams {
            query_id: 77,
            stake_amount: 10_000_000_000_000,
            validator_pubkey: &public_key,
            stake_at: 1_700_000_000,
            max_factor: 65_536,
            adnl_addr: &[0x22; 32],
            signature: &signature,
        };
        let body = new_stake_with_verified_controller_birth(&params, &state, &address, &code_hash)
            .expect("verified pool body");
        let mut fields = SliceData::load_cell(body).expect("body");
        assert_eq!(fields.get_next_u32().expect("op"), super::super::messages::opcodes::NEW_STAKE);
        assert_eq!(fields.get_next_u64().expect("query"), 77);
        let _coins = chain_block::Coins::construct_from(&mut fields).expect("stake");
        assert_eq!(fields.get_next_u32().expect("stake at"), params.stake_at);
        assert_eq!(fields.get_next_u32().expect("factor"), params.max_factor);
        assert_eq!(fields.get_next_bytes(32).expect("adnl"), params.adnl_addr);
        assert_eq!(fields.get_next_u16().expect("algorithm"), 1);
        let _key = fields.checked_drain_reference().expect("key");
        let _signature = fields.checked_drain_reference().expect("signature");
        assert!(fields.get_next_bit().expect("witness flag"));
        let witness = fields.checked_drain_reference().expect("witness");
        assert_eq!(witness.bit_length(), 544);
        assert_eq!(fields.remaining_bits(), 0);
        assert_eq!(fields.remaining_references(), 0);
        let mut wrong_address = address;
        wrong_address[0] ^= 1;
        assert!(
            new_stake_with_verified_controller_birth(&params, &state, &wrong_address, &code_hash)
                .unwrap_err()
                .to_string()
                .contains("validator_id")
        );
        let mut wrong_code = code_hash;
        wrong_code[0] ^= 1;
        assert!(
            new_stake_with_verified_controller_birth(&params, &state, &address, &wrong_code)
                .unwrap_err()
                .to_string()
                .contains("ConfigParam 47")
        );
    }
}
