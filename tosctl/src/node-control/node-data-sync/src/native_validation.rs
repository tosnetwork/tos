use crate::{
    model::{FullId, MANIFEST_LIMIT, Network, sha256},
    safe_io::Root,
};
use adnl::client::{AdnlClient, AdnlClientConfig};
use anyhow::{Context, Result, ensure};
use base64::Engine;
use chain_block::{
    Block, BlockIdExt, ConfigParams, Deserializable, MerkleProof, Serializable, ShardHashes,
    ShardStateUnsplit, UInt256, read_single_root_boc,
};
use std::collections::BTreeSet;
use tl_api::{AnyBoxedSerialize, BoxedSerialize, TLObject, tos};

pub struct CheckedStates {
    pub tip: Vec<u8>,
    pub coverage: Vec<String>,
    pub ancestors: BTreeSet<FullId>,
}

/// Upper bound for one retained diagnostic; the worker log must stay readable.
pub const DIAGNOSTIC_LIMIT: usize = 4096;

/// Truncate a diagnostic to `DIAGNOSTIC_LIMIT` bytes at a character boundary.
pub fn bounded_diagnostic(text: &str) -> String {
    if text.len() <= DIAGNOSTIC_LIMIT {
        return text.to_owned();
    }
    let mut end = DIAGNOSTIC_LIMIT;
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    format!("{}...", &text[..end])
}

/// The engine's own spelling of a block id, so diagnostics and engine errors can be matched.
pub fn describe(id: &FullId) -> String {
    format!(
        "({},{:016x},{}):{}:{}",
        id.workchain,
        u64::from_le_bytes(id.shard.to_le_bytes()),
        id.seqno,
        id.root_hash.to_ascii_uppercase(),
        id.file_hash.to_ascii_uppercase()
    )
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
async fn query<T: BoxedSerialize>(
    client: &mut AdnlClient,
    what: &str,
    request: &T,
) -> Result<TLObject> {
    let envelope = tos::rpc::lite_server::Query { data: tl_api::serialize_boxed(request)? }
        .into_tl_object()
        .into();
    let answer = client.query(&envelope).await.with_context(|| format!("native {what}"))?;
    if answer.is::<tos::lite_server::Error>() {
        let error = answer
            .downcast::<tos::lite_server::Error>()
            .map_err(|_| anyhow::anyhow!("native {what}: invalid native error response"))?;
        anyhow::bail!(
            "native {what}: native state read failed ({}): {}",
            error.code(),
            error.message()
        );
    }
    Ok(answer)
}
fn downcast<T: tl_api::AnyBoxedSerialize>(what: &str, answer: TLObject) -> Result<T> {
    answer
        .downcast::<T>()
        .map_err(|_| anyhow::anyhow!("native {what}: unexpected native validation response"))
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
    let stats: tos::engine::validator::Stats = downcast(
        "GetStats",
        client.query(&readiness).await.context("native GetStats control query")?,
    )?;
    let tip = stats
        .stats()
        .iter()
        .find(|s| s.key == "masterchainblock")
        .context("native masterchain state is not initialized")?;
    ensure!(
        FullId::from_stats(&tip.value)?.seqno >= frontier.seqno,
        "native local replay has not reached the coherent frontier"
    );
    let what = format!("GetBlock for frontier {}", describe(frontier));
    let block: tos::lite_server::BlockData = downcast(
        &what,
        query(client, &what, &tos::rpc::lite_server::GetBlock { id: frontier.native()? }).await?,
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
    let frontier_state = frontier_state_hash(&parsed)?;
    let what = format!("GetAllShardsInfo for frontier {}", describe(frontier));
    let response: tos::lite_server::AllShardsInfo = downcast(
        &what,
        query(client, &what, &tos::rpc::lite_server::GetAllShardsInfo { id: frontier.native()? })
            .await?,
    )?;
    let shards = verify_shard_inventory(frontier, &parsed, &response)
        .with_context(|| format!("native {what}"))?;
    let what = format!("GetConfigAll for frontier {}", describe(frontier));
    let configuration: tos::lite_server::ConfigInfo = downcast(
        &what,
        query(
            client,
            &what,
            &tos::rpc::lite_server::GetConfigAll { mode: 0, id: frontier.native()? },
        )
        .await?,
    )?;
    let config = verify_configuration(held, frontier, &frontier_state, &configuration)
        .with_context(|| format!("native {what}"))?;
    let blocks = monitored_blocks(frontier, &shards, &config)?;
    let mut coverage = Vec::new();
    for block in blocks {
        let mut address = [0; 32];
        address[..8].copy_from_slice(&block.shard().shard_prefix_without_tag().to_be_bytes());
        let account = tos::lite_server::accountid::AccountId {
            workchain: block.shard().workchain_id(),
            id: address.into(),
        };
        let what = format!("GetAccountState in shard state {block}");
        let read: tos::lite_server::AccountState = downcast(
            &what,
            query(
                client,
                &what,
                &tos::rpc::lite_server::GetAccountState { id: block.clone(), account },
            )
            .await?,
        )?;
        // This read only forces the engine to load the shard state. Its proofs are not
        // checked and nothing is derived from the answer: the coverage entry comes from
        // `blocks`, which is bound to the frontier above.
        ensure!(read.shardblk() == &block, "native account read used a different shard state");
        coverage.push(block.shard().to_string());
    }
    let mut ancestors = BTreeSet::new();
    for anchor in anchor_set(held, forks)? {
        if !needs_proof(frontier, &anchor)? {
            ancestors.insert(anchor);
            continue;
        }
        let what = format!(
            "GetBlockProof from frontier {} to anchor {}",
            describe(frontier),
            describe(&anchor)
        );
        let answer = query(client, &what, &anchor_request(frontier, &anchor)?)
            .await
            .map_err(|error| anchor_read_refusal(&anchor, error))?;
        let response: tos::lite_server::PartialBlockProof = downcast(&what, answer)?;
        verify_anchor_proof(held, frontier, &frontier_state, &anchor, &response)
            .with_context(|| format!("native {what}"))?;
        ancestors.insert(anchor);
    }
    Ok(CheckedStates { tip, coverage, ancestors })
}

/// Every anchor the image must descend from: the held zero state and init block, the
/// approved forks and any anchor the caller requires (for example a restore target's own
/// safety anchors). A set, so an init block equal to the zero state is proven once.
pub fn anchor_set(held: &Network, forks: &[FullId]) -> Result<BTreeSet<FullId>> {
    held.validate()?;
    let mut anchors = BTreeSet::from([held.zero.clone(), held.init.clone()]);
    for fork in forks {
        fork.masterchain()?;
        anchors.insert(fork.clone());
    }
    Ok(anchors)
}

/// Whether an anchor needs a native ancestry proof from the frontier. The frontier itself
/// needs none; an anchor beyond the frontier can never be its ancestor.
pub fn needs_proof(frontier: &FullId, anchor: &FullId) -> Result<bool> {
    frontier.masterchain()?;
    anchor.masterchain()?;
    ensure!(
        anchor.seqno <= frontier.seqno,
        "held anchor {} is ahead of generation frontier {}",
        describe(anchor),
        describe(frontier)
    );
    if anchor.seqno == frontier.seqno {
        ensure!(
            anchor == frontier,
            "held anchor {} differs from the generation frontier at the same height",
            describe(anchor)
        );
        return Ok(false);
    }
    Ok(true)
}

/// One backward proof link from the frontier to the anchor, built from the frontier's own
/// state (mode bit 0x1000) rather than the engine's latest state.
pub fn anchor_request(
    frontier: &FullId,
    anchor: &FullId,
) -> Result<tos::rpc::lite_server::GetBlockProof> {
    Ok(tos::rpc::lite_server::GetBlockProof {
        mode: 0x1001,
        known_block: frontier.native()?,
        target_block: Some(anchor.native()?),
    })
}

/// The hash of the masterchain state the frontier block produced. Every ancestry proof must
/// be a proof of exactly this state, so it inherits the frontier's corroborated identity.
pub fn frontier_state_hash(tip: &Block) -> Result<UInt256> {
    Ok(tip.read_state_update()?.new_hash)
}

/// The engine builds a backward link from the anchor's own stored proof link. A source keeps
/// those for key blocks and for blocks its archive has not yet removed; an older ordinary
/// block cannot be proven and the image is refused. The zero state needs no proof link.
pub fn anchor_read_refusal(anchor: &FullId, error: anyhow::Error) -> anyhow::Error {
    let text = format!("{error:#}").to_ascii_lowercase();
    let missing = format!("cannot load proof link for {}", describe(anchor)).to_ascii_lowercase();
    if anchor.seqno != 0 && text.contains(&missing) {
        return error.context(format!(
            "anchor proof not retained: the source no longer holds the proof link of anchor {}; \
             only the zero state and anchors whose proof link the source still holds can be proven",
            describe(anchor)
        ));
    }
    error
}

fn bounded_proof(what: &str, bytes: &[u8]) -> Result<MerkleProof> {
    ensure!(!bytes.is_empty(), "{what} is empty");
    ensure!(bytes.len() as u64 <= MANIFEST_LIMIT, "{what} exceeds the byte limit");
    read_single_root_boc(bytes)
        .and_then(MerkleProof::construct_from_cell)
        .with_context(|| format!("{what} is not a Merkle proof"))
}

/// Verify a native answer proving that `anchor` is an earlier masterchain block of the
/// frontier. The proof is a Merkle proof of the frontier's masterchain state, bound to the
/// state hash the frontier block itself records, whose previous-block dictionary holds the
/// anchor with exactly its root and file hash.
pub fn verify_anchor_proof(
    held: &Network,
    frontier: &FullId,
    frontier_state: &UInt256,
    anchor: &FullId,
    response: &tos::lite_server::PartialBlockProof,
) -> Result<()> {
    ensure!(needs_proof(frontier, anchor)?, "the frontier needs no ancestry proof");
    let from = frontier.native()?;
    let to = anchor.native()?;
    ensure!(bool::from(response.complete().clone()), "ancestry proof is incomplete");
    ensure!(response.from() == &from && response.to() == &to, "ancestry proof has other endpoints");
    let [link] = response.steps().as_slice() else {
        anyhow::bail!("ancestry proof must be exactly one link, found {}", response.steps().len());
    };
    let tos::lite_server::BlockLink::LiteServer_BlockLinkBack(link) = link else {
        anyhow::bail!("ancestry proof link is not a backward link");
    };
    ensure!(link.from == from && link.to == to, "ancestry proof link has other endpoints");
    let header = bounded_proof("frontier header proof", &link.proof)?;
    ensure!(
        hex::encode(header.hash.as_slice()) == frontier.root_hash,
        "frontier header proof belongs to another block"
    );
    let state_proof = bounded_proof("frontier state proof", &link.state_proof)?;
    ensure!(
        &state_proof.hash == frontier_state,
        "ancestry proof is not a proof of the frontier block's state"
    );
    let state: ShardStateUnsplit = state_proof.virtualize()?;
    ensure!(
        state.global_id() == held.global_id
            && state.seq_no() == frontier.seqno
            && state.shard().is_masterchain(),
        "ancestry proof state has another network or height"
    );
    let extra = state.read_custom()?.context("ancestry proof state has no masterchain extra")?;
    extra.prev_blocks.check_block(&to).map_err(|error| {
        anyhow::anyhow!(
            "anchor {} is not an earlier block of the frontier: {error}",
            describe(anchor)
        )
    })?;
    if anchor.seqno == 0 {
        ensure!(link.dest_proof.is_empty(), "zero-state anchor has an unexpected header proof");
    } else {
        let destination = bounded_proof("anchor header proof", &link.dest_proof)?;
        ensure!(
            hex::encode(destination.hash.as_slice()) == anchor.root_hash,
            "anchor header proof belongs to another block"
        );
    }
    Ok(())
}

/// The shard inventory the frontier block itself records. The engine's answer is kept as a
/// native read, but must be exactly this inventory. The answer's block proof is not checked:
/// its data is compared with the held, file-hash-checked tip, so the proof adds nothing.
pub fn verify_shard_inventory(
    frontier: &FullId,
    tip: &Block,
    response: &tos::lite_server::AllShardsInfo,
) -> Result<ShardHashes> {
    ensure!(response.id() == &frontier.native()?, "native shard inventory frontier mismatch");
    let recorded = tip
        .read_extra()?
        .read_custom()?
        .context("frontier block has no masterchain extra")?
        .shards()
        .clone();
    ensure!(!response.data().is_empty(), "native shard inventory is empty");
    ensure!(
        response.data().len() as u64 <= MANIFEST_LIMIT,
        "native shard inventory exceeds the byte limit"
    );
    let answered = ShardHashes::construct_from_cell(read_single_root_boc(response.data())?)?;
    ensure!(
        answered.serialize()?.repr_hash() == recorded.serialize()?.repr_hash(),
        "native shard inventory differs from the frontier block's shard hashes"
    );
    Ok(recorded)
}

/// The configuration the frontier's own masterchain state holds. The answer must be a
/// Merkle proof of exactly the state the frontier block records, so a proof of another
/// state with the same coordinates is refused. The answer's own header proof is not used:
/// the state hash comes from the held, file-hash-checked tip.
pub fn verify_configuration(
    held: &Network,
    frontier: &FullId,
    frontier_state: &UInt256,
    response: &tos::lite_server::ConfigInfo,
) -> Result<ConfigParams> {
    ensure!(response.id() == &frontier.native()?, "native configuration frontier mismatch");
    let proof = bounded_proof("configuration state proof", response.config_proof())?;
    ensure!(
        &proof.hash == frontier_state,
        "configuration proof is not a proof of the frontier block's state"
    );
    let state: ShardStateUnsplit = proof.virtualize()?;
    ensure!(
        state.global_id() == held.global_id
            && state.seq_no() == frontier.seqno
            && state.shard().is_masterchain(),
        "native configuration state identity mismatch"
    );
    Ok(state.read_custom()?.context("masterchain state lacks configuration")?.config)
}

/// Every shard block and every active workchain's zero state the frontier commits to,
/// derived only from the verified tip and the configuration bound to its state.
pub fn monitored_blocks(
    frontier: &FullId,
    shards: &ShardHashes,
    config: &ConfigParams,
) -> Result<Vec<BlockIdExt>> {
    let mut blocks = vec![frontier.native()?];
    let mut seen = BTreeSet::new();
    shards.iterate_shards(|shard, descr| {
        ensure!(blocks.len() < 1024, "native monitored shard count limit");
        seen.insert(shard.workchain_id());
        blocks.push(BlockIdExt::with_params(shard, descr.seq_no, descr.root_hash, descr.file_hash));
        Ok(true)
    })?;
    config.workchains()?.iterate_with_keys(|workchain: i32, descr| {
        if descr.active && !seen.contains(&workchain) {
            ensure!(blocks.len() < 1024, "native monitored workchain count limit");
            blocks.push(BlockIdExt::with_params(
                chain_block::ShardIdent::with_workchain_id(workchain)?,
                0,
                descr.zerostate_root_hash,
                descr.zerostate_file_hash,
            ));
        }
        Ok(true)
    })?;
    Ok(blocks)
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

#[cfg(test)]
#[path = "../tests/support/anchor_proof.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/support/frontier_inventory.rs"]
mod inventory_tests;
