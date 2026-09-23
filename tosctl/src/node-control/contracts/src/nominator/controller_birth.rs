/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

use chain_block::{
    BuilderData, Cell, Deserializable, HashmapE, IBitstring, Serializable, SliceData, StateInit,
    read_single_root_boc,
};
use std::path::Path;

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

/// Read a public birth artifact and live controller policy before building a
/// fee-bearing pool order. The two identities must agree with each other and
/// with the address derived from the original deployment StateInit.
pub fn new_stake_from_birth_artifact(
    params: &NewStakeParams<'_>,
    artifact_path: &Path,
    authorization_validator_id: &[u8; 32],
    pool_controller_id: &[u8; 32],
    live_param47: &Cell,
) -> anyhow::Result<Cell> {
    anyhow::ensure!(artifact_path.is_absolute(), "controller birth artifact path must be absolute");
    anyhow::ensure!(
        authorization_validator_id == pool_controller_id,
        "node PQ stake identity does not match the pool's validator controller"
    );
    let bytes = std::fs::read(artifact_path).map_err(|error| {
        anyhow::anyhow!(
            "controller birth artifact {} cannot be read: {error}",
            artifact_path.display()
        )
    })?;
    let deployment = StateInit::construct_from_cell(read_single_root_boc(&bytes)?)?;
    let code = deployment
        .code
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("controller deployment StateInit has no code"))?;
    let mut code_hash = [0u8; 32];
    code_hash.copy_from_slice(code.repr_hash().as_slice());
    require_live_controller_admission(live_param47, &code_hash)?;
    new_stake_with_verified_controller_birth(
        params,
        &deployment,
        authorization_validator_id,
        &code_hash,
    )
}

/// Require membership in the live ConfigParam 47 HashmapE(256), not merely
/// equality with a code hash supplied by the artifact being checked.
pub fn require_live_controller_admission(
    policy: &Cell,
    code_hash: &[u8; 32],
) -> anyhow::Result<()> {
    let mut view = SliceData::load_cell(policy.clone())?;
    anyhow::ensure!(view.get_next_bit()?, "live ConfigParam 47 has no admitted controller codes");
    let root = view.checked_drain_reference()?;
    anyhow::ensure!(
        view.remaining_bits() == 0 && view.remaining_references() == 0,
        "live ConfigParam 47 has trailing data"
    );
    let dict = HashmapE::with_hashmap(256, Some(root));
    let key = SliceData::load_builder(BuilderData::with_raw(code_hash.to_vec(), 256)?)?;
    anyhow::ensure!(
        dict.get(key)?.is_some(),
        "controller deployment code is not admitted by live ConfigParam 47"
    );
    Ok(())
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
    use chain_block::{HashmapType, SliceData, write_boc};

    fn policy(admitted_code_hash: &[u8; 32]) -> Cell {
        let mut dict = HashmapE::with_bit_len(256);
        let key = SliceData::load_builder(
            BuilderData::with_raw(admitted_code_hash.to_vec(), 256).expect("key"),
        )
        .expect("key slice");
        dict.set(key, &SliceData::default()).expect("admission");
        let mut value = BuilderData::new();
        value.append_bit_one().expect("presence");
        value
            .checked_append_reference(HashmapType::data(&dict).expect("root").clone())
            .expect("root ref");
        value.into_cell().expect("policy cell")
    }

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

    #[test]
    fn birth_artifact_requires_live_membership_and_matching_pool_controller() {
        let (state, address, code_hash) = fixture();
        let dir = tempfile::tempdir().expect("temporary artifact directory");
        let path = dir.path().join("controller-state-init.boc");
        let cell = state.write_to_new_cell().expect("state").into_cell().expect("cell");
        std::fs::write(&path, write_boc(&cell).expect("BOC")).expect("artifact");
        let signature = vec![0x33; 2420];
        let public_key = vec![0x11; 1312];
        let params = NewStakeParams {
            query_id: 1,
            stake_amount: 10_000_000_000_000,
            validator_pubkey: &public_key,
            stake_at: 1_700_000_000,
            max_factor: 65_536,
            adnl_addr: &[0x22; 32],
            signature: &signature,
        };
        let body =
            new_stake_from_birth_artifact(&params, &path, &address, &address, &policy(&code_hash))
                .expect("admitted witnessed pool order");
        let mut fields = SliceData::load_cell(body).expect("pool body");
        fields.get_next_bits(32 + 64).expect("op and query");
        let _coins = chain_block::Coins::construct_from(&mut fields).expect("stake");
        fields.get_next_bits(32 + 32 + 256 + 16).expect("pool order fields");
        fields.checked_drain_reference().expect("key");
        fields.checked_drain_reference().expect("signature");
        assert!(fields.get_next_bit().expect("witness presence"));
        assert_eq!(fields.checked_drain_reference().expect("witness").bit_length(), 544);

        let mut wrong = address;
        wrong[0] ^= 1;
        let error =
            new_stake_from_birth_artifact(&params, &path, &address, &wrong, &policy(&code_hash))
                .unwrap_err()
                .to_string();
        assert!(error.contains("pool's validator controller"), "wrong refusal: {error}");
        let error =
            new_stake_from_birth_artifact(&params, &path, &address, &address, &policy(&wrong))
                .unwrap_err()
                .to_string();
        assert!(error.contains("not admitted by live ConfigParam 47"), "wrong refusal: {error}");
        let empty_policy = BuilderData::with_raw(vec![0], 1)
            .expect("empty policy")
            .into_cell()
            .expect("empty policy cell");
        let error =
            new_stake_from_birth_artifact(&params, &path, &address, &address, &empty_policy)
                .unwrap_err()
                .to_string();
        assert!(error.contains("no admitted controller codes"), "wrong refusal: {error}");
        let error = new_stake_from_birth_artifact(
            &params,
            &dir.path().join("absent.boc"),
            &address,
            &address,
            &policy(&code_hash),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("cannot be read"), "wrong refusal: {error}");
    }
}
