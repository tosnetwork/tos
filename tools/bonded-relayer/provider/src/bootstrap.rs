// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Local setup uses the same native wallet and durable one-send boundary.
use crate::{chain::Chain, config::Config, protocol, store::Store, transport};
use anyhow::{ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chain_block::{read_single_root_boc, write_boc, Cell, Deserializable, StateInit};
use node_contracts::Wallet;
use serde_json::json;
use std::str::FromStr;

pub async fn run(mode: &str) -> Result<()> {
    ensure!(matches!(mode, "deploy-bond" | "activate-bond"), "bootstrap operation");
    let directory = std::env::current_dir()?;
    let _lock = crate::private_io::lock(&directory)?;
    let raw = crate::private_io::read(&directory.join("provider.json"), 65536)?;
    let value = protocol::parse(&raw)?;
    let config = Config::load(&directory, &json!({"release":value["release"]}))?;
    let chain = Chain::new(&config)?;
    let (_, sequence) = chain.funding(&config).await?;
    let wallet = crate::funding::wallet(&config, &directory).await?;
    let (amount, body, init) = if mode == "deploy-bond" {
        let bytes = crate::private_io::read(&directory.join("bond-init.boc"), 65536)?;
        (
            2_000_000_000,
            Cell::default(),
            Some(StateInit::construct_from_cell(read_single_root_boc(&bytes)?)?),
        )
    } else {
        let bytes = crate::private_io::read(&directory.join("bond-activate.boc"), 65536)?;
        (1_100_000_000, read_single_root_boc(&bytes)?, None)
    };
    let request = protocol::hash(format!("{}:{mode}", config.release.scope()?).as_bytes());
    let binding = protocol::hash(&protocol::canonical(
        &json!({"mode":mode,"scope":config.release.scope()?,"sequence":sequence}),
    )?);
    let mut store = Store::open(&directory.join("leases.db"), &config.release.scope()?)?;
    let lease = store.reserve(&request, &binding, sequence)?;
    // A persisted message can be inspected, but bootstrap never retries a send
    // after an unknown outcome or signs its replacement.
    ensure!(
        lease.fresh && lease.message.is_none(),
        "bootstrap already signed; reconcile without repeating"
    );
    let message = wallet
        .build_message(
            chain_block::MsgAddressInt::from_str(&config.release.bond)?,
            amount,
            body,
            true,
            Some(sequence),
            None,
            init,
        )
        .await?;
    let bytes = write_boc(&message)?;
    store.persist_message(&request, &bytes)?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let mut random = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut random);
    let permit = hex::encode(random);
    store.permit(&request, &permit, &protocol::hash(&bytes), now)?;
    store.consume(&permit, &bytes, now)?;
    // Synchronous RPC clients run outside the async executor thread.
    let url = config.rpc_url.clone();
    let encoded = STANDARD.encode(&bytes);
    tokio::task::spawn_blocking(move || transport::rpc(&url, "sendBoc", json!({"boc":encoded})))
        .await??;
    println!(
        "{}",
        json!({"status":"submitted-not-finalized","operation":mode,"sequence":sequence,"message_hash":message.repr_hash().to_hex_string(),"message_sha256":protocol::hash(&bytes)})
    );
    Ok(())
}
