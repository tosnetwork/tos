//! Freeze a public deployment candidate and test it locally. No RPC or sending
//! code is linked into this entry point; every output is public material.
use chain_block::{
    read_single_root_boc, write_boc, Cell, ConfigParamEnum, ConfigParams, Serializable, StateInit,
};
use serde_json::{json, Value};
use shielded_pool_ceremony::{
    audit::{audit, StartingKey},
    record::Directory,
};
use shielded_pool_circuit::{groth16, wire::OUTPUT_DATA_BYTES};
use shielded_pool_circuit_crosscheck::{
    acceptance,
    pool::{contract_gas_ceiling, pool_sources, Pool},
    public_client::PublicClient,
};
use shielded_pool_genesis::{manifest, plan, Request};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Command,
};
use tos_sandbox::{compile_func, Blockchain};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|v| format!("{v:02x}")).collect()
}
fn unhex(text: &str) -> Result<Vec<u8>> {
    if !text.is_ascii() || !text.len().is_multiple_of(2) {
        return Err("invalid configuration hex".into());
    }
    (0..text.len()).step_by(2).map(|i| Ok(u8::from_str_radix(&text[i..i + 2], 16)?)).collect()
}
fn text<'a>(v: &'a Value, field: &str) -> Result<&'a str> {
    v[field].as_str().ok_or_else(|| format!("missing {field}").into())
}
fn uint(v: &Value, field: &str) -> Result<u64> {
    v[field].as_u64().ok_or_else(|| format!("missing {field}").into())
}
fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let out = Command::new("git").arg("-C").arg(root).args(args).output()?;
    if !out.status.success() {
        return Err("cannot verify profile provenance".into());
    }
    Ok(out.stdout)
}
fn stats(cell: &Cell) -> Result<(u64, u64)> {
    let mut seen = BTreeSet::new();
    let mut todo = vec![cell.clone()];
    let mut cells = 0_u64;
    let mut bits = 0_u64;
    while let Some(cell) = todo.pop() {
        if !seen.insert(cell.repr_hash().as_slice().to_vec()) {
            continue;
        }
        cells = cells.checked_add(1).ok_or("cell count overflow")?;
        bits = bits.checked_add(u64::try_from(cell.bit_length())?).ok_or("bit count overflow")?;
        for i in 0..cell.references_count() {
            todo.push(cell.reference(i)?);
        }
    }
    Ok((cells, bits))
}
fn rounded_scaled(value: u128) -> Result<u128> {
    Ok(value.checked_add(65535).ok_or("price rounding overflow")? >> 16)
}
fn compute(config: &ConfigParams, gas: u64) -> Result<u128> {
    let p = config.gas_prices(false)?;
    let variable = u128::from(gas.saturating_sub(p.flat_gas_limit))
        .checked_mul(u128::from(p.gas_price))
        .ok_or("compute fee overflow")?;
    u128::from(p.flat_gas_price)
        .checked_add(rounded_scaled(variable)?)
        .ok_or_else(|| "compute fee overflow".into())
}
fn forward(config: &ConfigParams, bits: u64, cells: u64) -> Result<u128> {
    let p = config.fwd_prices(false)?;
    let b = u128::from(bits).checked_mul(u128::from(p.bit_price)).ok_or("bit price overflow")?;
    let c = u128::from(cells).checked_mul(u128::from(p.cell_price)).ok_or("cell price overflow")?;
    let variable = rounded_scaled(b.checked_add(c).ok_or("forwarding price overflow")?)?;
    u128::from(p.lump_price).checked_add(variable).ok_or_else(|| "forwarding fee overflow".into())
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 9 {
        return Err("usage: freeze-public-pool ROOT CEREMONY OUT PROFILE_COMMIT PROFILE_BLOB GLOBAL_ID FEES_JSON EXPECTED_VK EXPECTED_TRANSCRIPT".into());
    }
    let root = PathBuf::from(&args[0]);
    let directory = Directory::at(PathBuf::from(&args[1]));
    let out = PathBuf::from(&args[2]);
    let commit = args[3].to_str().ok_or("profile commit encoding")?;
    let blob = args[4].to_str().ok_or("profile blob encoding")?;
    let global_id: i32 = args[5].to_str().ok_or("global id encoding")?.parse()?;
    if !shielded_pool_genesis::is_object_id(commit) || !shielded_pool_genesis::is_object_id(blob) {
        return Err("profile provenance must be full git object ids".into());
    }
    let object = format!("{commit}:artifacts/shielded-pool/PROFILE.md");
    if git(&root, &["show", &object])?
        != std::fs::read(root.join("artifacts/shielded-pool/PROFILE.md"))?
    {
        return Err("profile bytes differ from reviewed commit".into());
    }
    let actual_blob = git(&root, &["rev-parse", &object])?;
    if std::str::from_utf8(&actual_blob)?.trim() != blob {
        return Err("profile blob does not match reviewed commit".into());
    }
    let fees: Value = serde_json::from_slice(&std::fs::read(&args[6])?)?;
    if fees["schema"] != "tos.shielded-pool.fee-snapshot.v1"
        || fees["global_id"].as_i64() != Some(i64::from(global_id))
        || fees["global_version"] != 16
    {
        return Err("fee snapshot network/version mismatch".into());
    }
    let now = u32::try_from(uint(&fees, "chain_time")?)?;
    let mut bc = Blockchain::with_global_version_and_base_workchain(16)?;
    let reference_config = bc.config_params().clone();
    let mut config = reference_config.clone();
    for number in [8_u32, 18, 19, 20, 21, 24, 25, 31, 43] {
        let row = &fees["parameters"][number.to_string()];
        let bytes = unhex(text(row, "boc_hex")?)?;
        if hex(&shielded_pool_genesis::sha256(&bytes)) != text(row, "boc_sha256")? {
            return Err(format!("configuration {number} digest mismatch").into());
        }
        let cell = read_single_root_boc(bytes)?;
        config.set_config(ConfigParamEnum::construct_from_cell_and_number(cell, number)?)?;
    }
    if config.global_version() != 16 {
        return Err("decoded configuration is not V16".into());
    }
    match config.config(19)? {
        Some(ConfigParamEnum::ConfigParam19(value))
            if i32::from_be_bytes(value.to_be_bytes()) == global_id => {}
        _ => return Err("decoded configuration has a different network identity".into()),
    }
    bc.set_config(config.clone())?;
    bc.set_now(now);
    let start = StartingKey::rebuild()?;
    let audited = audit(&directory, &start)?;
    let expected_vk = args[7].to_str().ok_or("VK encoding")?;
    let expected_transcript = args[8].to_str().ok_or("transcript encoding")?;
    if audited.vk_sha256() != expected_vk || audited.transcript() != expected_transcript {
        return Err("ceremony differs from the reviewed final parameters".into());
    }
    let request = Request {
        ceremony: Some(audited.clone()),
        source_commit: Some(commit.into()),
        source_blob: Some(blob.into()),
        ..Request::default()
    };
    let planned = plan(&root, request)?;
    let genesis = planned.build()?;
    let code = compile_func(&pool_sources())?;
    let rendered = manifest::render(&genesis, planned.provenance(), planned.key(), Some(&code))?;
    manifest::require_production(&root, &rendered, &planned, Some(&code))?;
    let init = StateInit::with_code_and_data(code.clone(), genesis.state.clone())
        .write_to_new_cell()?
        .into_cell()?;
    let account = shielded_pool_genesis::address(&code, &genesis.state)?;
    let address = format!("0:{}", hex(&account));
    let (cells, bits) = stats(&init)?;
    let limits = config.size_limits_config()?;
    if cells >= u64::from(limits.max_acc_state_cells)
        || cells.checked_add(2).ok_or("message cells overflow")? > u64::from(limits.max_msg_cells)
        || bits.checked_add(2046).ok_or("message bits overflow")? > u64::from(limits.max_msg_bits)
    {
        return Err("initial deployment exceeds live size limits".into());
    }
    let gas = config.gas_prices(false)?;
    let mut quotes = serde_json::Map::new();
    for (name, constant) in [
        ("deposit", "deposit_gas_ceiling"),
        ("transact", "transact_gas_ceiling"),
        ("recovery", "bounce_gas_ceiling"),
        ("topup", "topup_gas_ceiling"),
    ] {
        let ceiling = u64::try_from(contract_gas_ceiling(constant)?)?;
        if ceiling > gas.gas_limit {
            return Err("contract ceiling exceeds live per-transaction gas limit".into());
        }
        let minimum = compute(&config, ceiling)?;
        let headroom = minimum
            .checked_add(3)
            .ok_or("headroom overflow")?
            .checked_div(4)
            .ok_or("headroom division")?;
        quotes.insert(name.into(),json!({"gas_ceiling":ceiling,"compute_minimum_nanotos":minimum.to_string(),"inbound_compute_credit_with_25_percent_headroom_nanotos":minimum.checked_add(headroom).ok_or("attach overflow")?.to_string()}));
    }
    let payout_bits = u64::try_from(OUTPUT_DATA_BYTES)?
        .checked_mul(8)
        .and_then(|n| n.checked_add(96 + 768 + 256))
        .ok_or("payout bit count overflow")?;
    let payout_cells = u64::try_from(OUTPUT_DATA_BYTES.div_ceil(127))?
        .checked_add(3)
        .ok_or("payout cell count overflow")?;
    let payout_fee = forward(&config, payout_bits, payout_cells)?;
    let reference_payout_fee = forward(&reference_config, payout_bits, payout_cells)?;
    if planned.parameters().withdrawal_fee < payout_fee.max(reference_payout_fee) {
        return Err(
            "immutable withdrawal fee does not cover live and reference forwarding prices".into()
        );
    }
    let end = now.checked_add(86400).ok_or("storage horizon overflow")?;
    let storage = chain_block::accrued_storage_fee(
        &config.storage_prices()?.prices()?,
        cells,
        bits,
        now,
        end,
        false,
        false,
    )?;
    let client = PublicClient::load(&directory, &audited, expected_vk, global_id, &account)?;
    let encoded = groth16::canonical_verifying_key(&directory.read_key()?.vk)?;
    let pool = Pool::deploy_candidate(
        bc,
        code.clone(),
        genesis.state.clone(),
        global_id,
        100_000_000_000,
    )?;
    if pool.account()? != account {
        return Err("sandbox candidate address differs from frozen manifest".into());
    }
    let credit = |name: &str| -> Result<u64> {
        Ok(quotes.get(name).ok_or("missing funding quote")?
            ["inbound_compute_credit_with_25_percent_headroom_nanotos"]
            .as_str()
            .ok_or("funding quote is not canonical")?
            .parse()?)
    };
    let funding = acceptance::Funding {
        deposit_compute: credit("deposit")?,
        transact_compute: credit("transact")?,
    };
    let result =
        acceptance::run_in_pool(&encoded, pool, global_id, funding, |public, witness, time| {
            client.prove(public, witness, time)
        })?;
    if result.exit != 0 || result.address != address {
        return Err(format!(
            "exact candidate refused: exit {}, address {}",
            result.exit, result.address
        )
        .into());
    }
    let public_files = [
        ("code.boc", write_boc(&code)?),
        ("data.boc", write_boc(&genesis.state)?),
        ("state-init.boc", write_boc(&init)?),
        ("manifest.json", rendered.into_bytes()),
    ];
    let mut checksums = String::new();
    std::fs::create_dir(&out)?;
    for (name, bytes) in public_files {
        checksums.push_str(&format!("{}  {name}\n", hex(&shielded_pool_genesis::sha256(&bytes))));
        std::fs::write(out.join(name), bytes)?;
    }
    let publication = json!({"status":"OFFLINE CANDIDATE; NO LIVE GO","global_id":global_id,"global_version":16,"address":address,"code_hash":code.repr_hash().to_hex_string(),"data_hash":genesis.state.repr_hash().to_hex_string(),"state_init_hash":init.repr_hash().to_hex_string(),"vk_sha256":expected_vk,"transcript":expected_transcript,"execution_domain":hex(&shielded_pool_circuit::field::fr_to_be(&client.execution_domain())),"profile_commit":commit,"profile_blob":blob,"fee_snapshot_block":fees["block"],"fee_snapshot_sha256":hex(&shielded_pool_genesis::sha256(&std::fs::read(&args[6])?)),"quotes":quotes,"payout_body":{"bits":payout_bits,"cells":payout_cells,"current_forward_fee_nanotos":payout_fee.to_string(),"sandbox_default_forward_fee_nanotos":reference_payout_fee.to_string()},"initial_state_init":{"bits":bits,"cells":cells,"24h_rent_at_snapshot_prices_nanotos":storage.to_string()},"funding_policy":{"bootstrap_cap_nanotos":"150000000000","sender_a_nanotos":"130000000000","sender_b_nanotos":"15000000000","recipient_nanotos":"5000000000","initial_pool_endowment_nanotos":"100000000000","immutable_reserve_floor_nanotos":planned.parameters().reserve_floor.to_string(),"admin_withdrawal":false,"note":"100 TOS is endowed to the pool; compute/rent consume operational surplus above the 50 TOS immutable floor. Sender wallet/forwarding fees are separate from the quoted inbound compute credits. Revalidate the same configuration on two nodes before any live action."},"sandbox_acceptance":{"scope":"local sandbox only; exact candidate, network and live fee cells, synthetic unfunded note witnesses","exit":result.exit,"gas":result.gas,"public_prover":"OS-seeded 256-bit proof randomness; audited final proving key; no fixture prover"}});
    let bytes = serde_json::to_vec_pretty(&publication)?;
    checksums
        .push_str(&format!("{}  publication.json\n", hex(&shielded_pool_genesis::sha256(&bytes))));
    std::fs::write(out.join("publication.json"), bytes)?;
    std::fs::write(out.join("SHA256SUMS"), checksums)?;
    println!("{publication}");
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use chain_block::{BuilderData, GasLimitsPrices, IBitstring, MsgForwardPrices};

    #[test]
    fn compute_quotes_round_once_and_include_the_flat_segment() {
        let mut config = ConfigParams::default();
        let prices = GasLimitsPrices {
            flat_gas_limit: 100,
            flat_gas_price: 667,
            gas_price: 436_907,
            ..Default::default()
        };
        config.set_config(ConfigParamEnum::ConfigParam21(prices)).expect("gas prices");
        for (gas, expected) in
            [(0, 667), (100, 667), (101, 674), (230_000, 1_533_335), (1_510_000, 10_066_675)]
        {
            assert_eq!(compute(&config, gas).expect("quote"), expected);
        }
    }

    #[test]
    fn forwarding_rounds_the_combined_bit_cell_price_and_refuses_overflow() {
        let mut config = ConfigParams::default();
        config
            .set_config(ConfigParamEnum::ConfigParam25(MsgForwardPrices {
                lump_price: 5,
                bit_price: 1,
                cell_price: 1,
                ..Default::default()
            }))
            .expect("forward prices");
        assert_eq!(forward(&config, 0, 0).expect("empty quote"), 5);
        assert_eq!(forward(&config, 1, 1).expect("fractional quote"), 6);
        config
            .set_config(ConfigParamEnum::ConfigParam25(MsgForwardPrices {
                lump_price: 5,
                bit_price: u64::MAX,
                cell_price: u64::MAX,
                ..Default::default()
            }))
            .expect("large prices");
        assert!(forward(&config, u64::MAX, u64::MAX).is_err());
    }

    #[test]
    fn cell_statistics_count_shared_subtrees_once() {
        let child = Cell::default();
        let mut b = BuilderData::new();
        b.append_u32(42).expect("bits");
        b.checked_append_reference(child.clone()).expect("first ref");
        b.checked_append_reference(child).expect("shared ref");
        assert_eq!(stats(&b.into_cell().expect("cell")).expect("statistics"), (2, 32));
    }
}
