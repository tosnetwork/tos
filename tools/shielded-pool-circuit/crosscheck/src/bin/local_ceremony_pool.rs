//! Compile the shielded pool from current sources and build its genesis state
//! around the audited ceremony verifying key, for an isolated local network.
//!
//! `local_pool` embeds the development key, which the shielded client refuses
//! to spend against. A pool built here verifies the proofs the public proving
//! client makes from the audited ceremony, so the client's whole spend path can
//! be exercised on a local chain. The ceremony is audited in full first: the
//! verifying key written into the state is the one the audit reconstructed,
//! never one read from a file on trust. Nothing is deployed; the output is a
//! `StateInit` and the two documents a deployment and the client need.
use std::path::PathBuf;

use chain_block::{write_boc, Serializable, StateInit};
use shielded_pool_ceremony::record::Directory;
use shielded_pool_circuit::{field::fr_to_be, wire::execution_domain};
use shielded_pool_circuit_crosscheck::pool::{dec, pool_sources};
use tos_sandbox::compile_func;

/// The global id of an isolated local network; the only network this pool is for.
const LOCAL_GLOBAL_ID: i32 = 3;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let usage =
        "expected: repository root, ceremony directory, phase-1 directory, output directory";
    let root = PathBuf::from(args.next().ok_or(usage)?);
    let ceremony = PathBuf::from(args.next().ok_or(usage)?);
    let phase1 = PathBuf::from(args.next().ok_or(usage)?);
    let out = PathBuf::from(args.next().ok_or(usage)?);
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }

    let audited = shielded_pool_prover::audit_ceremony_from(&phase1, &Directory::at(&ceremony))?;
    if !audited.is_finished() {
        return Err("the ceremony is not finished; a pool takes only a closed key".into());
    }

    std::fs::create_dir(&out)?;
    let code = compile_func(&pool_sources())?;
    let parameters = shielded_pool_genesis::parameters_with_verifying_key(
        &root,
        audited.verifying_key().to_vec(),
    )?;
    let profile_hash = shielded_pool_genesis::profile_hash(&parameters.profile_bytes);
    let reserve = parameters.reserve_floor;
    let genesis = shielded_pool_genesis::build(parameters)?;
    let init = StateInit::with_code_and_data(code.clone(), genesis.state.clone());
    let account = init.write_to_new_cell()?.into_cell()?.hash(0);
    let address = format!("0:{}", account.to_hex_string());
    let code_hash = code.hash(0).to_hex_string();
    // The configuration cell the relayer provider pins, by the same reference.
    let config_hash = genesis.state.reference(2)?.repr_hash().to_hex_string();
    let domain = execution_domain(LOCAL_GLOBAL_ID, account.as_slice());

    std::fs::write(out.join("code.boc"), write_boc(&code)?)?;
    std::fs::write(out.join("data.boc"), write_boc(&genesis.state)?)?;
    std::fs::write(out.join("state-init.boc"), write_boc(&init.serialize()?)?)?;
    let manifest = serde_json::json!({
        "scope": "isolated-local-ceremony-key", "development_verifying_key": false,
        "global_id": LOCAL_GLOBAL_ID, "global_version": 16,
        "address": address, "code_hash": code_hash,
        "initial_data_hash": genesis.state.hash(0).to_hex_string(),
        "state_init_hash": account.to_hex_string(),
        "pool_config_hash": config_hash,
        "profile_hash": hex(&profile_hash),
        "groth16_vk_hash": audited.vk_sha256(),
        "ceremony_transcript": audited.transcript(),
        "execution_domain": hex(&fr_to_be(&domain)),
        "reserve_floor_nanotos": reserve.to_string(),
        "commitment_root": dec(genesis.commitment_root),
        "nullifier_root": dec(genesis.nullifier_root)
    });
    std::fs::write(out.join("pool.json"), serde_json::to_vec_pretty(&manifest)?)?;
    // The profile the shielded client reads; the code hash is its pin on a local network.
    let profile = serde_json::json!({
        "schema": "tosctl-shield-profile-v1", "global_id": LOCAL_GLOBAL_ID,
        "pool_address": address, "pool_code_hash": code_hash
    });
    std::fs::write(out.join("pool-profile.json"), serde_json::to_vec_pretty(&profile)?)?;
    println!("{manifest}");
    Ok(())
}
