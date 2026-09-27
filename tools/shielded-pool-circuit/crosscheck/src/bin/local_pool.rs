//! Compile a local development pool from current sources, without generating
//! a withdrawal proof or changing the published ceremony artifacts.
use std::path::PathBuf;

use chain_block::{write_boc, Serializable, StateInit};
use shielded_pool_circuit_crosscheck::pool::{dec, pool_sources};
use tos_sandbox::compile_func;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let root = PathBuf::from(args.next().ok_or("expected repository and output directory")?);
    let out = PathBuf::from(args.next().ok_or("expected output directory")?);
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    std::fs::create_dir(&out)?;
    let code = compile_func(&pool_sources())?;
    let parameters = shielded_pool_genesis::development_parameters(&root)?;
    let reserve = parameters.reserve_floor;
    let genesis = shielded_pool_genesis::build(parameters)?;
    let init = StateInit::with_code_and_data(code.clone(), genesis.state.clone());
    let address = init.write_to_new_cell()?.into_cell()?.hash(0).to_hex_string();
    std::fs::write(out.join("code.boc"), write_boc(&code)?)?;
    std::fs::write(out.join("data.boc"), write_boc(&genesis.state)?)?;
    let manifest = serde_json::json!({
        "scope": "local-development", "development_verifying_key": true,
        "address": format!("0:{address}"), "global_version": 18,
        "reserve_floor_nanotos": reserve.to_string(),
        "code_hash": code.hash(0).to_hex_string(),
        "initial_data_hash": genesis.state.hash(0).to_hex_string(),
        "commitment_root": dec(genesis.commitment_root),
        "nullifier_root": dec(genesis.nullifier_root)
    });
    std::fs::write(out.join("pool.json"), serde_json::to_vec_pretty(&manifest)?)?;
    println!("{}", manifest);
    Ok(())
}
