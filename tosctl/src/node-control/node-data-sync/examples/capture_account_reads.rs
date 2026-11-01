//! Capture the engine's answers to the native shard-state read, for the account-read test
//! fixtures. Run it against a disposable local network's liteserver: it reads the newest
//! masterchain block and the basechain shard block that block records, sends
//! `liteServer.getAccountStatePrunned` for each exactly as native validation does (the shard
//! prefix without its tag, followed by zeros), and once more for the configuration contract,
//! an account that exists. Whether each account is present is recorded, not assumed. Every
//! answer is verified before it is written, as the TL bytes of the boxed answer in a `.bin`
//! file (a `.tl` file under tosctl is a schema), next to a manifest naming its block and
//! account.
use anyhow::{Context, Result, ensure};
use base64::Engine;
use chain_block::{
    BlockIdExt, Deserializable, MerkleProof, ShardHashes, ShardStateUnsplit, read_single_root_boc,
};
use node_data_sync::{
    model::{FullId, Network, sha256},
    native_validation::verify_account_read,
};
use std::path::{Path, PathBuf};
use tl_api::{AnyBoxedSerialize, BoxedSerialize, TLObject, tos};

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 5,
        "usage: capture_account_reads LITESERVER_ADDRESS LITESERVER_PUBLIC_KEY_BASE64 GLOBAL_ID OUTPUT_DIR"
    );
    let global_id: i32 = args[3].parse().context("global id")?;
    let output = PathBuf::from(&args[4]);
    std::fs::create_dir_all(&output)?;
    let client_seed: [u8; 32] = rand::random();
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    let (_, config) = adnl::client::AdnlClientConfig::from_json(
        &serde_json::json!({
            "server_address": args[1],
            "server_key": {"type_id": 1209251014, "pub_key": args[2]},
            "client_key": {"type_id": 1209251014, "pvt_key": b64(&client_seed)},
            "timeouts": {"read": {"secs": 10, "nanos": 0}, "write": {"secs": 10, "nanos": 0}},
        })
        .to_string(),
    )?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(capture(&config, global_id, &output))
}

async fn query<T: BoxedSerialize>(
    client: &mut adnl::client::AdnlClient,
    request: &T,
) -> Result<TLObject> {
    let envelope = tos::rpc::lite_server::Query { data: tl_api::serialize_boxed(request)? }
        .into_tl_object()
        .into();
    let answer = client.query(&envelope).await?;
    if answer.is::<tos::lite_server::Error>() {
        let error = answer
            .downcast::<tos::lite_server::Error>()
            .map_err(|_| anyhow::anyhow!("invalid liteserver error"))?;
        anyhow::bail!("liteserver error {}: {}", error.code(), error.message());
    }
    Ok(answer)
}

fn downcast<T: AnyBoxedSerialize>(answer: TLObject) -> Result<T> {
    answer.downcast::<T>().map_err(|_| anyhow::anyhow!("unexpected liteserver answer"))
}

async fn capture(
    config: &adnl::client::AdnlClientConfig,
    global_id: i32,
    output: &Path,
) -> Result<()> {
    let mut client = adnl::client::AdnlClient::connect(config).await?;
    let info: tos::lite_server::MasterchainInfo =
        downcast(query(&mut client, &tos::rpc::lite_server::GetMasterchainInfo {}).await?)?;
    let master = info.last().clone();
    let shards: tos::lite_server::AllShardsInfo = downcast(
        query(&mut client, &tos::rpc::lite_server::GetAllShardsInfo { id: master.clone() }).await?,
    )?;
    let shards = ShardHashes::construct_from_cell(read_single_root_boc(shards.data())?)?;
    let mut basechain = None;
    shards.iterate_shards(|shard, descr| {
        if shard.workchain_id() == 0 && basechain.is_none() {
            basechain = Some(BlockIdExt::with_params(
                shard,
                descr.seq_no,
                descr.root_hash,
                descr.file_hash,
            ));
        }
        Ok(true)
    })?;
    let basechain = basechain.context("the masterchain block records no basechain shard")?;
    let configuration: tos::lite_server::ConfigInfo = downcast(
        query(&mut client, &tos::rpc::lite_server::GetConfigAll { mode: 0, id: master.clone() })
            .await?,
    )?;
    let state: ShardStateUnsplit =
        MerkleProof::construct_from_cell(read_single_root_boc(configuration.config_proof())?)?
            .virtualize()?;
    let config_address =
        state.read_custom()?.context("masterchain state has no configuration")?.config.config_addr;
    let held = Network {
        global_id,
        zero: FullId {
            workchain: -1,
            shard: i64::MIN,
            seqno: 0,
            root_hash: "00".repeat(32),
            file_hash: "00".repeat(32),
        },
        init: FullId {
            workchain: -1,
            shard: i64::MIN,
            seqno: 0,
            root_hash: "00".repeat(32),
            file_hash: "00".repeat(32),
        },
    };
    let caller_address = |block: &BlockIdExt| {
        let mut address = [0u8; 32];
        address[..8].copy_from_slice(&block.shard().shard_prefix_without_tag().to_be_bytes());
        address
    };
    let mut config_bytes = [0u8; 32];
    config_bytes.copy_from_slice(config_address.get_bytestring(0).as_slice());
    let reads = [
        ("masterchain-caller", master.clone(), caller_address(&master)),
        ("masterchain-config", master.clone(), config_bytes),
        ("basechain-caller", basechain.clone(), caller_address(&basechain)),
    ];
    let mut manifest = Vec::new();
    for (name, block, address) in reads {
        let account = tos::lite_server::accountid::AccountId {
            workchain: block.shard().workchain_id(),
            id: address.into(),
        };
        let answer: tos::lite_server::AccountState = downcast(
            query(
                &mut client,
                &tos::rpc::lite_server::GetAccountStatePrunned {
                    id: block.clone(),
                    account: account.clone(),
                },
            )
            .await?,
        )?;
        verify_account_read(&held, &block, &account, &answer)
            .with_context(|| format!("captured {name} answer"))?;
        let bytes = tl_api::serialize_boxed(&answer)?;
        std::fs::write(output.join(format!("{name}.bin")), &bytes)?;
        manifest.push(serde_json::json!({
            "name": name,
            "workchain": block.shard().workchain_id(),
            "shard": format!("{:016x}", block.shard().shard_prefix_with_tag()),
            "seqno": block.seq_no(),
            "root_hash": hex::encode(block.root_hash().as_slice()),
            "file_hash": hex::encode(block.file_hash().as_slice()),
            "account": hex::encode(address),
            "present": !answer.state().is_empty(),
            "bytes": bytes.len(),
            "sha256": sha256(&bytes),
        }));
    }
    client.shutdown().await?;
    std::fs::write(
        output.join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({"global_id": global_id, "reads": manifest}))?,
    )?;
    println!("ACCOUNT_READ_CAPTURE_OK {}", output.display());
    Ok(())
}
