use crate::{
    model::{FullId, MANIFEST_LIMIT, Network, sha256},
    safe_io::Root,
};
use adnl::client::{AdnlClient, AdnlClientConfig};
use anyhow::{Context, Result, ensure};
use base64::Engine;
use chain_block::{
    Block, Deserializable, MerkleProof, ShardHashes, ShardStateUnsplit, read_single_root_boc,
};
use std::collections::BTreeSet;
use tl_api::{AnyBoxedSerialize, BoxedSerialize, TLObject, tos};

pub struct CheckedStates {
    pub zero: Vec<u8>,
    pub tip: Vec<u8>,
    pub coverage: Vec<String>,
    pub ancestors: BTreeSet<FullId>,
}
/// Local-only requests to a fresh validation identity inside a separate network namespace.
/// These requests force native reads; startup statistics alone are not a shard-state check.
pub async fn check_states(
    config: &AdnlClientConfig,
    held: &Network,
    frontier: &FullId,
    forks: &[FullId],
) -> Result<CheckedStates> {
    let mut client = AdnlClient::connect(config).await?;
    let result = check_inner(&mut client, held, frontier, forks).await;
    client.shutdown().await?;
    result
}
async fn query<T: BoxedSerialize>(client: &mut AdnlClient, request: &T) -> Result<TLObject> {
    let envelope = tos::rpc::lite_server::Query { data: tl_api::serialize_boxed(request)? }
        .into_tl_object()
        .into();
    let answer = client.query(&envelope).await?;
    if answer.is::<tos::lite_server::Error>() {
        let error = answer
            .downcast::<tos::lite_server::Error>()
            .map_err(|_| anyhow::anyhow!("invalid native error response"))?;
        anyhow::bail!("native state read failed ({}): {}", error.code(), error.message());
    }
    Ok(answer)
}
fn downcast<T: tl_api::AnyBoxedSerialize>(answer: TLObject) -> Result<T> {
    answer.downcast::<T>().map_err(|_| anyhow::anyhow!("unexpected native validation response"))
}
async fn check_inner(
    client: &mut AdnlClient,
    held: &Network,
    frontier: &FullId,
    forks: &[FullId],
) -> Result<CheckedStates> {
    held.validate()?;
    frontier.masterchain()?;
    let readiness = tos::rpc::engine::validator::ControlQuery {
        data: tl_api::serialize_boxed(&tos::rpc::engine::validator::GetStats {})?,
    }
    .into_tl_object()
    .into();
    let stats: tos::engine::validator::Stats = downcast(client.query(&readiness).await?)?;
    let tip = stats
        .stats()
        .iter()
        .find(|s| s.key == "masterchainblock")
        .context("native masterchain state is not initialized")?;
    ensure!(
        FullId::from_stats(&tip.value)?.seqno >= frontier.seqno,
        "native local replay has not reached the coherent frontier"
    );
    let zero: tos::lite_server::BlockState = downcast(
        query(client, &tos::rpc::lite_server::GetState { id: held.zero.native()? }).await?,
    )?;
    ensure!(
        zero.id() == &held.zero.native()?,
        "native zero-state identity differs from held anchor"
    );
    let zero_bytes = zero.data().clone();
    ensure!(
        zero_bytes.len() as u64 <= MANIFEST_LIMIT && sha256(&zero_bytes) == held.zero.file_hash,
        "native zero-state file hash mismatch"
    );
    let zero_root = read_single_root_boc(&zero_bytes)?;
    ensure!(
        hex::encode(zero_root.repr_hash().as_slice()) == held.zero.root_hash,
        "native zero-state root hash mismatch"
    );
    ensure!(
        ShardStateUnsplit::construct_from_cell(zero_root)?.global_id() == held.global_id,
        "native zero-state global id differs"
    );
    let block: tos::lite_server::BlockData = downcast(
        query(client, &tos::rpc::lite_server::GetBlock { id: frontier.native()? }).await?,
    )?;
    ensure!(block.id() == &frontier.native()?, "native block identity mismatch");
    let tip = block.data().clone();
    ensure!(
        tip.len() as u64 <= MANIFEST_LIMIT && sha256(&tip) == frontier.file_hash,
        "native block file hash mismatch"
    );
    let tip_root = read_single_root_boc(&tip)?;
    ensure!(
        hex::encode(tip_root.repr_hash().as_slice()) == frontier.root_hash,
        "native tip root hash differs"
    );
    let parsed = Block::construct_from_cell(tip_root)?;
    let info = parsed.read_info()?;
    ensure!(
        parsed.global_id() == held.global_id
            && info.seq_no() == frontier.seqno
            && info.shard() == frontier.native()?.shard(),
        "native tip coordinates or global id differ"
    );
    let response: tos::lite_server::AllShardsInfo = downcast(
        query(client, &tos::rpc::lite_server::GetAllShardsInfo { id: frontier.native()? }).await?,
    )?;
    ensure!(response.id() == &frontier.native()?, "native shard inventory frontier mismatch");
    let shards = ShardHashes::construct_from_cell(read_single_root_boc(response.data())?)?;
    let mut blocks = vec![frontier.native()?];
    let mut seen = BTreeSet::new();
    shards.iterate_shards(|shard, descr| {
        ensure!(blocks.len() < 1024, "native monitored shard count limit");
        seen.insert(shard.workchain_id());
        blocks.push(chain_block::BlockIdExt::with_params(
            shard,
            descr.seq_no,
            descr.root_hash,
            descr.file_hash,
        ));
        Ok(true)
    })?;
    let configuration: tos::lite_server::ConfigInfo = downcast(
        query(client, &tos::rpc::lite_server::GetConfigAll { mode: 0, id: frontier.native()? })
            .await?,
    )?;
    ensure!(configuration.id() == &frontier.native()?, "native configuration frontier mismatch");
    let proof =
        MerkleProof::construct_from_cell(read_single_root_boc(configuration.config_proof())?)?;
    let state: ShardStateUnsplit = proof.virtualize()?;
    ensure!(
        state.global_id() == held.global_id && state.seq_no() == frontier.seqno,
        "native configuration state identity mismatch"
    );
    let config = state.read_custom()?.context("masterchain state lacks configuration")?.config;
    config.workchains()?.iterate_with_keys(|workchain: i32, descr| {
        if descr.active && !seen.contains(&workchain) {
            ensure!(blocks.len() < 1024, "native monitored workchain count limit");
            blocks.push(chain_block::BlockIdExt::with_params(
                chain_block::ShardIdent::with_workchain_id(workchain)?,
                0,
                descr.zerostate_root_hash,
                descr.zerostate_file_hash,
            ));
        }
        Ok(true)
    })?;
    let mut coverage = Vec::new();
    for block in blocks {
        let mut address = [0; 32];
        address[..8].copy_from_slice(&block.shard().shard_prefix_without_tag().to_be_bytes());
        let account = tos::lite_server::accountid::AccountId {
            workchain: block.shard().workchain_id(),
            id: address.into(),
        };
        let read: tos::lite_server::AccountState = downcast(
            query(client, &tos::rpc::lite_server::GetAccountState { id: block.clone(), account })
                .await?,
        )?;
        ensure!(read.shardblk() == &block, "native account read used a different shard state");
        coverage.push(block.shard().to_string());
    }
    let mut ancestors = BTreeSet::new();
    for fork in forks.iter().chain(std::iter::once(&held.init)) {
        fork.masterchain()?;
        ensure!(fork.seqno <= frontier.seqno, "held fork or init anchor is ahead of generation");
        if fork.seqno == 0 {
            ensure!(
                fork == &held.zero,
                "zero-height safety anchor differs from held network zero state"
            );
            ancestors.insert(fork.clone());
            continue;
        }
        let response: tos::lite_server::BlockHeader = downcast(
            query(
                client,
                &tos::rpc::lite_server::LookupBlock {
                    mode: 1,
                    id: tos::tos_node::blockid::BlockId {
                        workchain: -1,
                        shard: i64::MIN,
                        seqno: i32::from_le_bytes(fork.seqno.to_le_bytes()),
                    },
                    lt: None,
                    utime: None,
                },
            )
            .await?,
        )?;
        ensure!(
            response.id() == &fork.native()?,
            "held fork or init block is not on imported native chain"
        );
        ancestors.insert(fork.clone());
    }
    Ok(CheckedStates { zero: zero_bytes, tip, coverage, ancestors })
}

/// Configure only fresh validation credentials; no donor identity is accepted.
pub fn fresh_control(db: &Root, address: &str) -> Result<AdnlClientConfig> {
    let config = db.bytes("config.json", MANIFEST_LIMIT)?;
    let mut config: serde_json::Value = serde_json::from_slice(&config)?;
    ensure!(
        config.get("validators").and_then(|v| v.as_array()).is_some_and(Vec::is_empty),
        "validation image contains signing registrations"
    );
    let server_seed: [u8; 32] = rand::random();
    let client_seed: [u8; 32] = rand::random();
    let server_pub = ed25519_dalek::SigningKey::from_bytes(&server_seed).verifying_key().to_bytes();
    let client_pub = ed25519_dalek::SigningKey::from_bytes(&client_seed).verifying_key().to_bytes();
    let key_id = |public: &[u8; 32]| {
        let mut bytes = 1209251014_u32.to_le_bytes().to_vec();
        bytes.extend(public);
        sha256(&bytes)
    };
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let server_id = hex::decode(key_id(&server_pub))?;
    let client_id = hex::decode(key_id(&client_pub))?;
    let address: std::net::SocketAddr = address.parse()?;
    ensure!(
        address.ip().is_loopback() && address.port() > 0,
        "validation control must be loopback only"
    );
    config["control"] = serde_json::json!([{"@type":"engine.controlInterface", "id":b64(&server_id), "port":address.port(), "allowed":[{"@type":"engine.controlProcess", "id":b64(&client_id), "permissions":1}]}]);
    config["validators"] = serde_json::json!([]);
    config["collators"] = serde_json::json!([]);
    config["extraconfig"] = serde_json::Value::Null;
    db.replace("config.json", &serde_json::to_vec(&config)?)?;
    let mut key = 1231561495_u32.to_le_bytes().to_vec();
    key.extend(server_seed);
    db.write_new(&format!("keyring/{}", hex::encode_upper(server_id)), &key)?;
    let (_, config) = AdnlClientConfig::from_json(&serde_json::json!({"server_address":address.to_string(), "server_key":{"type_id":1209251014,"pub_key":b64(&server_pub)}, "client_key":{"type_id":1209251014,"pvt_key":b64(&client_seed)}, "timeouts":{"read":{"secs":5,"nanos":0},"write":{"secs":5,"nanos":0}}}).to_string())?;
    Ok(config)
}
