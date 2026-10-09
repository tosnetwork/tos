//! Process integration: the Rust client talks to actual validator-engine handlers.
//! Set TOS_ENGINE_BUILD to the native build, TOS_SOURCE to its source checkout,
//! and TOS_OLD_ENGINE to validator-engine built from main without these queries.
//! From tosctl/src: cargo test -p control-client --test engine_operator_reads --locked -- --ignored
use adnl::client::{AdnlClient, AdnlClientConfig};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use chain_block::{
    BlockIdExt, BuilderData, Cell, Deserializable, Ed25519KeyOption, HashmapE, IBitstring,
    Serializable, ShardIdent, ShardStateUnsplit, SliceData, UInt256, read_boc, write_boc,
};
use control_client::{
    UnsupportedControlQuery,
    client_adnl::ControlClientAdnl,
    client_api::ClientAPI,
    operator_reads::{ConfigProposalRequest, ConfigProposalsRequest, ElectorStateRequest},
};
use serde_json::{Value, json};
use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command},
    time::{Duration, Instant},
};
use tl_api::{AnyBoxedSerialize, serialize_boxed, tos};

const SERVER_SEED: [u8; 32] = [9; 32];
const CLIENT_SEED: [u8; 32] = [7; 32];

struct Node {
    process: Child,
    directory: tempfile::TempDir,
    address: String,
    block: BlockIdExt,
}
impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}
fn required_path(name: &str) -> Result<PathBuf> {
    std::env::var_os(name).map(PathBuf::from).with_context(|| format!("set {name}"))
}
fn port() -> Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}
fn encoded(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}
fn key_id(seed: &[u8; 32]) -> Result<UInt256> {
    let key = Ed25519KeyOption::from_private_key(seed)?;
    let mut bytes = 1209251014_u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(key.pub_key()?);
    Ok(UInt256::calc_sha256(&bytes))
}
fn check_output(command: &mut Command) -> Result<()> {
    let output = command.output()?;
    ensure!(output.status.success(), "command failed: {}", String::from_utf8_lossy(&output.stderr));
    Ok(())
}
// Populate the genesis accounts before boot, without a production injection hook.
fn seeded_snapshot(root: &Path, source: &Path) -> Result<()> {
    let mut state =
        ShardStateUnsplit::construct_from_bytes(&fs::read(root.join("zerostate.boc"))?)?;
    let config = state.read_custom()?.context("masterchain config")?.config;
    let accounts = state.read_accounts()?;
    let elector_id = config.elector_address()?;
    let mut elector = accounts.account(&elector_id)?.context("elector account")?;
    let mut account = elector.read_account()?;
    let data = read_boc(fs::read(
        source.join("test/validator/fixtures/control-getter/elector-data.boc"),
    )?)?
    .withdraw_single_root()?;
    ensure!(account.set_data(data), "elector is active");
    elector.write_account(&account)?;
    state.insert_account(&elector_id, &elector)?;
    let config_id = config.config_address()?;
    let mut stored = accounts.account(&config_id)?.context("config account")?;
    let mut account = stored.read_account()?;
    let mut old = SliceData::load_cell(account.get_data().context("config data")?)?;
    let parameters = old.checked_drain_reference()?;
    let mut votes = HashmapE::with_bit_len(256);
    for hash in [[4; 32], [5; 32]] {
        let value = proposal_record(hash[0] == 4)?;
        votes.set_builder(UInt256::from(hash).into(), &value)?;
    }
    let mut data = BuilderData::new();
    data.checked_append_reference(parameters)?;
    votes.write_to(&mut data)?;
    ensure!(account.set_data(data.into_cell()?), "config is active");
    stored.write_account(&account)?;
    state.insert_account(&config_id, &stored)?;
    let cell = state.serialize()?;
    let bytes = write_boc(&cell)?;
    fs::write(root.join("zerostate.rhash"), cell.repr_hash().as_slice())?;
    fs::write(root.join("zerostate.fhash"), UInt256::calc_file_hash(&bytes).as_slice())?;
    fs::write(root.join("zerostate.boc"), bytes)?;
    Ok(())
}
fn proposal_value() -> Result<Cell> {
    let mut value = BuilderData::new();
    value.append_u32(1234)?;
    value.into_cell()
}
fn proposal_record(has_value: bool) -> Result<BuilderData> {
    let mut parameter = BuilderData::new();
    parameter.append_u8(0xf3)?.append_i32(1001)?;
    if has_value {
        parameter.append_bit_one()?.checked_append_reference(proposal_value()?)?;
    } else {
        parameter.append_bit_zero()?;
    }
    parameter.append_bit_one()?.append_raw(&[6; 32], 256)?;
    let mut voters = HashmapE::with_bit_len(16);
    let mut stamp = BuilderData::new();
    stamp.append_u32(1)?;
    for id in [5_u16, 9] {
        voters.set_builder(SliceData::from_raw(id.to_be_bytes().to_vec(), 16), &stamp)?;
    }
    let mut status = BuilderData::new();
    status.append_u8(0xce)?.append_u32(1_900_000_000)?;
    status.checked_append_reference(parameter.into_cell()?)?.append_bit_one()?;
    voters.write_to(&mut status)?;
    status.append_i64(1_i64 << 40)?.append_raw(&[7; 32], 256)?;
    status.append_u8(3)?.append_u8(1)?.append_u8(2)?;
    Ok(status)
}
impl Node {
    fn start(engine: &Path, permissions: u32) -> Result<Self> {
        let source = required_path("TOS_SOURCE")?;
        let build = required_path("TOS_ENGINE_BUILD")?;
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        // Public bootstrap descriptors suffice for an observer which never signs.
        let mut validators = Vec::new();
        for index in 1_u8..=4 {
            validators.extend([index; 32]);
            validators.extend([index + 4; 32]);
            validators.extend([index + 8; 1312]);
        }
        fs::write(root.join("validator-pq.pub"), validators)?;
        let include = std::env::join_paths([
            source.join("crypto/fift/lib"),
            build.join("crypto/smartcont"),
            source.join("crypto/smartcont"),
        ])?;
        check_output(
            Command::new(build.join("crypto/create-state"))
                .args(["-I"])
                .arg(include)
                .arg(source.join("crypto/smartcont/gen-zerostate.fif"))
                .env("SOURCE_DATE_EPOCH", "1789434000")
                .current_dir(root),
        )?;
        seeded_snapshot(root, &source)?;
        let root_hash = UInt256::from_be_bytes(&fs::read(root.join("zerostate.rhash"))?);
        let file_hash = UInt256::from_be_bytes(&fs::read(root.join("zerostate.fhash"))?);
        let block = BlockIdExt::with_params(
            ShardIdent::masterchain(),
            0,
            root_hash.clone(),
            file_hash.clone(),
        );
        let wire_block = json!({"@type":"tosNode.blockIdExt","workchain":-1,
            "shard":i64::MIN,"seqno":0,"root_hash":encoded(root_hash.as_slice()),
            "file_hash":encoded(file_hash.as_slice())});
        let global = root.join("global.json");
        fs::write(
            &global,
            serde_json::to_vec(&json!({"@type":"config.global",
            "dht":{"@type":"dht.config.global","k":6,"a":3,
                "static_nodes":{"@type":"dht.nodes","nodes":[]}},
            "validator":{"@type":"validator.config.global","zero_state":wire_block,
                "init_block":wire_block,"hardforks":[]}}))?,
        )?;
        let db = root.join("db");
        let udp = format!("127.0.0.1:{}", port()?);
        let mut init = Command::new(engine);
        init.arg("-C").arg(&global).arg("-D").arg(&db).arg("-I").arg(&udp);
        check_output(&mut init)?;
        let config_path = db.join("config.json");
        let mut config: Value = serde_json::from_slice(&fs::read(&config_path)?)?;
        let server_id = key_id(&SERVER_SEED)?;
        let client_id = key_id(&CLIENT_SEED)?;
        let address = format!("127.0.0.1:{}", port()?);
        let control_port: u16 = address.rsplit(':').next().context("control port")?.parse()?;
        config["validators"] = json!([]);
        config["control"] = json!([{"@type":"engine.controlInterface",
            "id":encoded(server_id.as_slice()),"port":control_port,
            "allowed":[{"@type":"engine.controlProcess","id":encoded(client_id.as_slice()),
                "permissions":permissions}]}]);
        fs::write(config_path, serde_json::to_vec(&config)?)?;
        let mut private_key = 1231561495_u32.to_le_bytes().to_vec();
        private_key.extend(SERVER_SEED);
        let key_path = db.join("keyring").join(hex::encode_upper(server_id.as_slice()));
        fs::write(&key_path, private_key)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
        }
        let static_dir = db.join("static");
        fs::create_dir_all(&static_dir)?;
        for stem in ["zerostate", "basestate0"] {
            let hash = fs::read(root.join(format!("{stem}.fhash")))?;
            fs::copy(root.join(format!("{stem}.boc")), static_dir.join(hex::encode_upper(hash)))?;
        }
        let log = fs::File::create(root.join("engine.log"))?;
        let process = Command::new(engine)
            .arg("-C")
            .arg(global)
            .arg("-D")
            .arg(db)
            .args(["-t", "2", "--initial-sync-delay", "0", "--skip-key-sync"])
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()?;
        Ok(Self { process, directory, address, block })
    }
    fn config(&self) -> Result<AdnlClientConfig> {
        let key = Ed25519KeyOption::from_private_key(&SERVER_SEED)?;
        let (_, config) = AdnlClientConfig::from_json(
            &json!({
            "server_address":self.address,"server_key":{"type_id":1209251014,
                "pub_key":encoded(key.pub_key()?)},
            "client_key":{"type_id":1209251014,"pvt_key":encoded(&CLIENT_SEED)},
            "timeouts":{"read":{"secs":2,"nanos":0},"write":{"secs":2,"nanos":0}}})
            .to_string(),
        )?;
        Ok(config)
    }
    async fn client(&mut self) -> Result<ControlClientAdnl> {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            ensure!(self.process.try_wait()?.is_none(), "engine exited: {}", self.log()?);
            let mut client = ControlClientAdnl::new(self.config()?, 1);
            if client.connect().await.is_ok() {
                return Ok(client);
            }
            ensure!(Instant::now() < deadline, "engine did not listen: {}", self.log()?);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    fn log(&self) -> Result<String> {
        Ok(fs::read_to_string(self.directory.path().join("engine.log"))?)
    }
    async fn raw_error(&self, bytes: Vec<u8>) -> Result<String> {
        let mut client = AdnlClient::connect(&self.config()?).await?;
        let query =
            tos::rpc::engine::validator::ControlQuery { data: bytes }.into_tl_object().into();
        let answer = client.query(&query).await?;
        let error = answer
            .downcast::<tos::engine::validator::ControlQueryError>()
            .map_err(|answer| anyhow::anyhow!("expected control error, got {answer:?}"))?;
        Ok(error.message().to_owned())
    }
}

#[tokio::test]
#[ignore = "requires native engine and create-state; see module documentation"]
async fn real_engine_typed_reads_and_snapshot_binding() -> Result<()> {
    let build = required_path("TOS_ENGINE_BUILD")?;
    let mut node = Node::start(&build.join("validator-engine/validator-engine"), 1)?;
    let mut client = node.client().await?;
    let request =
        ElectorStateRequest { block: Some(node.block.clone()), wallets: vec![[3; 32], [2; 32]] };
    let deadline = Instant::now() + Duration::from_secs(60);
    let elector = loop {
        match client.get_elector_state(&request).await {
            Ok(value) => break value,
            Err(error) => {
                ensure!(Instant::now() < deadline, "elector failed: {error:#}; {}", node.log()?);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    };
    assert_eq!(elector.block, node.block);
    assert_eq!(elector.returned.iter().map(|r| r.wallet).collect::<Vec<_>>(), request.wallets);
    assert!(elector.returned.iter().all(|r| r.amount.as_u128() == 0));
    let proposals = client
        .get_config_proposals(&ConfigProposalsRequest { block: Some(node.block.clone()) })
        .await?;
    assert_eq!(proposals.block, node.block);
    assert_eq!(proposals.proposals.len(), 2);
    assert_eq!(
        proposals.proposals.iter().map(|p| p.hash).collect::<Vec<_>>(),
        vec![[4; 32], [5; 32]]
    );
    for meta in &proposals.proposals {
        assert_eq!(meta.expires, 1_900_000_000);
        assert!(meta.critical);
        assert_eq!(meta.param_id, 1001);
        assert_eq!(meta.param_hash, Some([6; 32]));
        assert_eq!(meta.voters, vec![5, 9]);
        assert_eq!(meta.weight_remaining, 1_i64 << 40);
        assert_eq!(meta.vset_id, [7; 32]);
        assert_eq!((meta.rounds_remaining, meta.wins, meta.losses), (3, 1, 2));
    }
    let detail = client
        .get_config_proposal(&ConfigProposalRequest {
            block: Some(node.block.clone()),
            hash: [4; 32],
        })
        .await?;
    assert_eq!(detail.block, node.block);
    let meta = detail.meta.context("proposal metadata")?;
    assert_eq!(meta.hash, [4; 32]);
    assert!(meta.has_value);
    let value = read_boc(detail.value.context("proposal value")?)?.withdraw_single_root()?;
    assert_eq!(value, proposal_value()?);
    for hash in [[5; 32], [8; 32]] {
        let answer = client
            .get_config_proposal(&ConfigProposalRequest { block: Some(node.block.clone()), hash })
            .await?;
        assert_eq!(answer.block, node.block);
        if hash == [5; 32] {
            let meta = answer.meta.context("metadata-only proposal")?;
            assert_eq!(meta.hash, hash);
            assert!(!meta.has_value);
        } else {
            assert!(answer.meta.is_none());
        }
        assert!(answer.value.is_none());
    }
    assert!(!elector.participants.is_empty());
    assert!(!elector.past_elections.is_empty());
    let deadline = Instant::now() + Duration::from_secs(60);
    let latest = loop {
        match client.get_elector_state(&ElectorStateRequest::default()).await {
            Ok(value) => break value,
            Err(error) => {
                ensure!(
                    format!("{error:#}").contains("not started")
                        || format!("{error:#}").contains("incoherent applied masterchain state"),
                    "latest failed: {error:#}; {}",
                    node.log()?
                );
                ensure!(
                    Instant::now() < deadline,
                    "latest never became ready: {error:#}; {}",
                    node.log()?
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    };
    assert_eq!(latest.block, node.block);
    let mut absent = node.block.clone();
    absent = BlockIdExt::with_params(
        absent.shard().clone(),
        42,
        absent.root_hash().clone(),
        absent.file_hash().clone(),
    );
    let error = client
        .get_config_proposals(&ConfigProposalsRequest { block: Some(absent) })
        .await
        .err()
        .context("unavailable historical block was accepted")?;
    assert!(format!("{error:#}").contains("getConfigProposals: control error"), "{error:#}");
    for (root_hash, file_hash) in [
        (UInt256::default(), node.block.file_hash().clone()),
        (node.block.root_hash().clone(), UInt256::default()),
    ] {
        let wrong_hash =
            BlockIdExt::with_params(ShardIdent::masterchain(), 0, root_hash, file_hash);
        let error = client
            .get_config_proposals(&ConfigProposalsRequest { block: Some(wrong_hash) })
            .await
            .err()
            .context("wrong block hash at the same height was accepted")?;
        assert!(format!("{error:#}").contains("getConfigProposals: control error"), "{error:#}");
    }
    client.ping().await?;
    client.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires native engine and create-state; see module documentation"]
async fn real_engine_authorization_and_unknown_flags() -> Result<()> {
    let build = required_path("TOS_ENGINE_BUILD")?;
    for permissions in [2, 1] {
        let mut node = Node::start(&build.join("validator-engine/validator-engine"), permissions)?;
        let mut client = node.client().await?;
        if permissions == 1 {
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                match client.get_config_proposals(&ConfigProposalsRequest::default()).await {
                    Ok(_) => break,
                    Err(error) => {
                        ensure!(
                            Instant::now() < deadline,
                            "node never became ready: {error:#}; {}",
                            node.log()?
                        );
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
        for query in [
            tos::rpc::engine::validator::GetElectorState { block: None, wallets: vec![] }
                .into_tl_object(),
            tos::rpc::engine::validator::GetConfigProposals { block: None }.into_tl_object(),
            tos::rpc::engine::validator::GetConfigProposal {
                block: None,
                hash: UInt256::default(),
            }
            .into_tl_object(),
        ] {
            let mut bytes = serialize_boxed(&query)?;
            bytes[4..8].copy_from_slice(&2_i32.to_le_bytes());
            let error = node.raw_error(bytes).await?;
            if permissions == 2 {
                assert!(error.contains("not authorized"), "{error}");
            } else {
                assert!(error.contains("invalid control getter flags"), "{error}");
            }
        }
        client.shutdown().await?;
    }
    Ok(())
}

/// A category outside 0..255 must be reported through the handler's reply
/// promise. Reporting it on the promise the reply wrapper had already taken
/// lost the error, and the reply became "Lost promise".
#[tokio::test]
#[ignore = "requires native engine and create-state; see module documentation"]
async fn real_engine_control_query_reports_category_narrowing() -> Result<()> {
    let build = required_path("TOS_ENGINE_BUILD")?;
    // vep_default | vep_modify: the default bit for the readiness probe, the
    // modify bit for the four handlers.
    let mut node = Node::start(&build.join("validator-engine/validator-engine"), 3)?;
    let mut client = node.client().await?;
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match client.get_config_proposals(&ConfigProposalsRequest::default()).await {
            Ok(_) => break,
            Err(error) => {
                ensure!(
                    Instant::now() < deadline,
                    "node never became ready: {error:#}; {}",
                    node.log()?
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    let out_of_range = vec![256];
    for (categories, priority_categories) in
        [(out_of_range.clone(), vec![]), (vec![], out_of_range.clone())]
    {
        let cases = [
            (
                "failed to add listening port: ",
                tos::rpc::engine::validator::AddListeningPort {
                    ip: 0x7f000001,
                    port: 3278,
                    categories: categories.clone(),
                    priority_categories: priority_categories.clone(),
                }
                .into_tl_object(),
            ),
            (
                "failed to del listening port: ",
                tos::rpc::engine::validator::DelListeningPort {
                    ip: 0x7f000001,
                    port: 3278,
                    categories: categories.clone(),
                    priority_categories: priority_categories.clone(),
                }
                .into_tl_object(),
            ),
            (
                "failed to add listening proxy: ",
                tos::rpc::engine::validator::AddProxy {
                    in_ip: 0x7f000001,
                    in_port: 3279,
                    out_ip: 0x7f000001,
                    out_port: 3280,
                    proxy: tos::adnl::Proxy::Adnl_Proxy_None(tos::adnl::proxy::proxy::None {
                        id: UInt256::default(),
                    }),
                    categories: categories.clone(),
                    priority_categories: priority_categories.clone(),
                }
                .into_tl_object(),
            ),
            (
                "failed to del listening proxy: ",
                tos::rpc::engine::validator::DelProxy {
                    out_ip: 0x7f000001,
                    out_port: 3280,
                    categories: categories.clone(),
                    priority_categories: priority_categories.clone(),
                }
                .into_tl_object(),
            ),
        ];
        for (prefix, query) in cases {
            let error = node.raw_error(serialize_boxed(&query)?).await?;
            // The prefix shows the handler body ran past the authorization and
            // started gates and answered through its own reply promise.
            assert!(error.contains(prefix), "{prefix}: {error}");
            assert!(error.contains("Narrow cast failed"), "{prefix}: {error}");
            assert!(!error.contains("Lost promise"), "{prefix}: {error}");
        }
    }
    client.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires an engine built from main without these queries"]
async fn old_engine_reports_named_upgrade_error_for_every_read() -> Result<()> {
    let mut node = Node::start(&required_path("TOS_OLD_ENGINE")?, 1)?;
    let mut client = node.client().await?;
    let query = tos::rpc::engine::validator::GetElectorState { block: None, wallets: vec![] }
        .into_tl_object();
    let message = node.raw_error(serialize_boxed(&query)?).await?;
    assert!(message.contains("failed to parse validator query"), "{message}");
    assert!(message.contains("Unknown constructor"), "{message}");
    println!("Old-engine control response: {message}");
    let errors = [
        client
            .get_elector_state(&ElectorStateRequest::default())
            .await
            .err()
            .context("old engine accepted elector query")?,
        client
            .get_config_proposals(&ConfigProposalsRequest::default())
            .await
            .err()
            .context("old engine accepted proposals query")?,
        client
            .get_config_proposal(&ConfigProposalRequest { block: None, hash: [0; 32] })
            .await
            .err()
            .context("old engine accepted detail query")?,
    ];
    for (error, query) in
        errors.into_iter().zip(["getElectorState", "getConfigProposals", "getConfigProposal"])
    {
        let error = error.context("operator read failed");
        assert_eq!(
            error.downcast_ref::<UnsupportedControlQuery>().map(|e| e.query),
            Some(query),
            "{error:#}"
        );
    }
    client.shutdown().await?;
    Ok(())
}
