// One authenticated control node and an independently counted public endpoint.
use adnl::{
    common::{AdnlPeers, QueryResult, Subscriber},
    server::{AdnlServer, AdnlServerConfig},
};
use anyhow::{Context, ensure};
use base64::Engine;
use chain_block::{BlockIdExt, ConfigParam15, Serializable, ShardIdent, UInt256};
use common::app_config::AppConfig;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tl_api::{TLObject, deserialize_boxed, tos};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const ELECTOR_METHODS: [&str; 4] =
    ["active_election_id", "participant_list_extended", "past_elections", "compute_returned_stake"];
#[derive(Default)]
pub struct Counts {
    pub control: AtomicUsize,
    pub wallets: Mutex<Vec<Vec<[u8; 32]>>>,
    pub public: Mutex<HashMap<String, usize>>,
}
#[derive(Clone)]
pub struct Reply {
    pub election_id: u32,
    pub finished: bool,
    pub unsupported: bool,
    pub overflow: bool,
    pub wrong_wallet: bool,
    pub participants: usize,
    pub credits: HashMap<[u8; 32], Vec<u8>>,
    pub frozen_overflow: bool,
    pub frozen_owner: [u8; 32],
}
impl Default for Reply {
    fn default() -> Self {
        Self {
            election_id: 1_700_000_000,
            finished: false,
            unsupported: false,
            overflow: false,
            wrong_wallet: false,
            participants: 1,
            credits: HashMap::new(),
            frozen_overflow: false,
            frozen_owner: [6; 32],
        }
    }
}
struct ControlReplies {
    counts: Arc<Counts>,
    reply: Arc<Mutex<Reply>>,
}
pub fn block() -> BlockIdExt {
    BlockIdExt::with_params(
        ShardIdent::masterchain(),
        17,
        UInt256::from([8; 32]),
        UInt256::from([9; 32]),
    )
}
#[async_trait::async_trait]
impl Subscriber for ControlReplies {
    async fn try_consume_query(
        &self,
        object: TLObject,
        _: &AdnlPeers,
    ) -> chain_block::Result<QueryResult> {
        let query = object
            .downcast::<tos::rpc::engine::validator::ControlQuery>()
            .map_err(|_| anyhow::anyhow!("not a control query"))?;
        let query = deserialize_boxed(query.data)?;
        let request = query
            .downcast::<tos::rpc::engine::validator::GetElectorState>()
            .map_err(|_| anyhow::anyhow!("unexpected control query"))?;
        self.counts.control.fetch_add(1, Ordering::SeqCst);
        self.counts
            .wallets
            .lock()
            .map_err(|_| anyhow::anyhow!("wallet counter poisoned"))?
            .push(request.wallets.iter().map(|wallet| *wallet.as_slice()).collect());
        let reply = self.reply.lock().map_err(|_| anyhow::anyhow!("reply lock poisoned"))?.clone();
        if reply.unsupported {
            return QueryResult::consume(
                tos::engine::validator::controlqueryerror::ControlQueryError {
                    code: 621,
                    message: "query not supported".into(),
                },
            );
        }
        let open = reply.election_id != 0;
        let returned = request
            .wallets
            .into_iter()
            .map(|wallet| {
                let amount = reply.credits.get(wallet.as_slice()).cloned().unwrap_or_default();
                tos::engine::validator::returnedstake::ReturnedStake {
                    wallet: if reply.wrong_wallet { UInt256::from([0xfe; 32]) } else { wallet },
                    amount,
                }
            })
            .collect();
        let participants = if open {
            (0..reply.participants)
                .map(|index| {
                    let mut id = [0; 32];
                    id[30..].copy_from_slice(
                        &u16::try_from(index).context("test participant index")?.to_be_bytes(),
                    );
                    Ok(tos::engine::validator::electionparticipant::ElectionParticipant {
                        id: UInt256::from(id),
                        adnl: UInt256::from([2; 32]),
                        key_id: UInt256::from([3; 32]),
                        algorithm: 2,
                        max_factor: 65536,
                        stake: if reply.overflow {
                            vec![1, 0, 0, 0, 0, 0, 0, 0, 0]
                        } else {
                            vec![7]
                        },
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()?
        } else {
            vec![]
        };
        QueryResult::consume(tos::engine::validator::electorstate::ElectorState {
            block: block(),
            elect_at: i32::from_ne_bytes(reply.election_id.to_ne_bytes()),
            elect_close: if open { -1 } else { 0 },
            min_stake: if open { vec![3] } else { vec![] },
            total_stake: if open { vec![7] } else { vec![] },
            failed: false.into(),
            finished: (open && reply.finished).into(),
            participants,
            past_elections: vec![tos::engine::validator::pastelection::PastElection {
                election_id: 1_600_000_000,
                unfreeze_at: 1_800_000_000,
                stake_held: 7200,
                vset_hash: UInt256::from([4; 32]),
                total_stake: vec![11],
                bonuses: vec![2],
                frozen: vec![tos::engine::validator::frozenstake::FrozenStake {
                    id: UInt256::from([5; 32]),
                    owner: UInt256::from(reply.frozen_owner),
                    weight: -1,
                    stake: if reply.frozen_overflow {
                        vec![1, 0, 0, 0, 0, 0, 0, 0, 0]
                    } else {
                        vec![11]
                    },
                    banned: false.into(),
                }],
            }],
            returned,
        })
    }
}
fn number(value: i64) -> serde_json::Value {
    serde_json::json!({"@type":"tvm.stackEntryNumber","number":{"@type":"tvm.numberDecimal","number":value.to_string()}})
}
fn nil() -> serde_json::Value {
    serde_json::json!({"@type":"tvm.stackEntryList","list":{"@type":"tvm.list","elements":[]}})
}
fn public_result(method: &str) -> serde_json::Value {
    let stack = match method {
        "active_election_id" => vec![number(1_700_000_001)],
        "participant_list_extended" => vec![
            number(-1),
            number(0),
            nil(),
            number(0),
            number(3),
            number(1_800_000_000),
            number(1_700_000_001),
        ],
        "past_elections" => vec![nil()],
        "compute_returned_stake" => vec![number(99)],
        _ => vec![],
    };
    serde_json::json!({"gas_used":100,"exit_code":0,"stack":stack})
}
pub struct Fixture {
    directory: tempfile::TempDir,
    server: AdnlServer,
    http: tokio::task::JoinHandle<()>,
    pub counts: Arc<Counts>,
    pub public_url: String,
}
impl Fixture {
    pub async fn new(reply: Reply) -> anyhow::Result<Self> {
        let counts = Arc::new(Counts::default());
        let reply = Arc::new(Mutex::new(reply));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let public_url = format!("http://{}", listener.local_addr()?);
        let public_counts = counts.clone();
        let cfg15 = ConfigParam15 {
            validators_elected_for: 3600,
            elections_start_before: 1800,
            elections_end_before: 600,
            stake_held_for: 7200,
        };
        let cfg15 = base64::engine::general_purpose::STANDARD
            .encode(chain_block::write_boc(&cfg15.serialize()?)?);
        let cfg1 = base64::engine::general_purpose::STANDARD.encode(chain_block::write_boc(
            &chain_block::BuilderData::with_raw(vec![0x33; 32], 256)?.into_cell()?,
        )?);
        let http = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let counts = public_counts.clone();
                let cfg15 = cfg15.clone();
                let cfg1 = cfg1.clone();
                tokio::spawn(async move {
                    let handler = async {
                        let mut input = Vec::new();
                        let mut buffer = [0; 4096];
                        loop {
                            let n = socket.read(&mut buffer).await?;
                            ensure!(n != 0, "closed HTTP fixture request");
                            input.extend_from_slice(&buffer[..n]);
                            ensure!(
                                input.len() <= 1024 * 1024,
                                "HTTP fixture request exceeds limit"
                            );
                            let Some(end) = input.windows(4).position(|w| w == b"\r\n\r\n") else {
                                continue;
                            };
                            let header = String::from_utf8_lossy(&input[..end]);
                            let length = header
                                .lines()
                                .find_map(|line| {
                                    line.to_ascii_lowercase()
                                        .strip_prefix("content-length:")
                                        .and_then(|s| s.trim().parse::<usize>().ok())
                                })
                                .context("missing request length")?;
                            if input.len() < end + 4 + length {
                                continue;
                            }
                            let request: serde_json::Value =
                                serde_json::from_slice(&input[end + 4..end + 4 + length])?;
                            let method = request["params"]["method"].as_str().unwrap_or("other");
                            *counts
                                .public
                                .lock()
                                .map_err(|_| anyhow::anyhow!("public counter poisoned"))?
                                .entry(method.into())
                                .or_default() += 1;
                            let result = if request["method"] == "getConfigParam"
                                && request["params"]["config_id"] == 15
                            {
                                serde_json::json!({"config":{"bytes":cfg15}})
                            } else if request["method"] == "getConfigParam"
                                && request["params"]["config_id"] == 1
                            {
                                serde_json::json!({"config":{"bytes":cfg1}})
                            } else if request["method"] == "getMasterchainInfo" {
                                let root =
                                    base64::engine::general_purpose::STANDARD.encode([8; 32]);
                                let file =
                                    base64::engine::general_purpose::STANDARD.encode([9; 32]);
                                serde_json::json!({
                                    "last":{"@type":"tos.blockIdExt","workchain":-1,"shard":i64::MIN.to_string(),"seqno":17,"root_hash":root,"file_hash":file},
                                    "init":{"@type":"tos.blockIdExt","workchain":-1,"shard":i64::MIN.to_string(),"seqno":0,"root_hash":root,"file_hash":file}
                                })
                            } else if request["method"] == "getAddressInformation" {
                                let zero =
                                    base64::engine::general_purpose::STANDARD.encode([0; 32]);
                                serde_json::json!({"@type":"addressInformation","balance":"0","state":"active",
                                    "last_transaction_id":{"@type":"internal.transactionId","lt":"0","hash":zero},
                                    "block_id":{"@type":"tos.blockIdExt","workchain":-1,"shard":i64::MIN.to_string(),"seqno":17,"root_hash":zero,"file_hash":zero},"sync_utime":1700000000})
                            } else {
                                public_result(method)
                            };
                            let body = serde_json::json!({"jsonrpc":"2.0","id":request["id"],"ok":true,"result":result}).to_string();
                            let response = format!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                                body.len()
                            );
                            socket.write_all(response.as_bytes()).await?;
                            return anyhow::Ok(());
                        }
                    };
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handler).await;
                });
            }
        });
        // The control server binds an address it is given, so a free port is
        // probed first. A test running in parallel can take that port before
        // the server binds it; then probe another.
        let mut attempts = 0;
        let (control_addr, server) = loop {
            let temporary = std::net::TcpListener::bind("127.0.0.1:0")?;
            let control_addr = temporary.local_addr()?;
            drop(temporary);
            let server_config = AdnlServerConfig::from_json(&serde_json::json!({"address":control_addr.to_string(),"clients":{"any":null},
                "server_key":{"type_id":1209251014,"pvt_key":"3CFeiTSlGkJf3D8w3ZXS4QS+6/0p+MFZGuv0XYMvMRo="}}).to_string())?;
            match AdnlServer::listen(
                server_config,
                vec![Arc::new(ControlReplies { counts: counts.clone(), reply: reply.clone() })],
            )
            .await
            {
                Ok(server) => break (control_addr, server),
                Err(error) => {
                    let error = anyhow::Error::from(error);
                    let in_use = error.chain().any(|cause| {
                        cause
                            .downcast_ref::<std::io::Error>()
                            .is_some_and(|io| io.kind() == std::io::ErrorKind::AddrInUse)
                    }) || format!("{error:#}").contains("Address already in use");
                    attempts += 1;
                    if !in_use || attempts >= 20 {
                        return Err(error.context("start the control server"));
                    }
                }
            }
        };
        let directory = tempfile::tempdir()?;
        let config = serde_json::json!({"nodes":{"test":{"server_address":control_addr.to_string(),
            "server_key":{"type_id":1209251014,"pub_key":"BBKmgGAxz4ZofRgMO2qhYt+K1bGlGeowukPONVAkOcU="},
            "client_key":{"type_id":1209251014,"pvt_key":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="},"timeouts":2}},
            "chain_rpc":{"urls":[public_url],"api_key":null},"http":{"bind":"127.0.0.1:0"}});
        std::fs::write(directory.path().join("config.json"), serde_json::to_vec(&config)?)?;
        Ok(Self { directory, server, http, counts, public_url })
    }
    pub fn path(&self) -> anyhow::Result<String> {
        self.directory
            .path()
            .join("config.json")
            .to_str()
            .map(str::to_owned)
            .context("test config path")
    }
    pub fn config(&self) -> anyhow::Result<AppConfig> {
        AppConfig::load(std::path::Path::new(&self.path()?))
    }
    pub fn no_public_elector(&self) -> anyhow::Result<()> {
        let counts =
            self.counts.public.lock().map_err(|_| anyhow::anyhow!("public counter poisoned"))?;
        for method in ELECTOR_METHODS {
            assert_eq!(
                counts.get(method).copied().unwrap_or(0),
                0,
                "public elector read: {method}"
            );
        }
        Ok(())
    }
    pub async fn stop(self) {
        self.http.abort();
        self.server.shutdown().await;
    }
}
