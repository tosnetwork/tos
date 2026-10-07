use super::*;
use adnl::{
    common::{AdnlPeers, QueryResult, Subscriber},
    server::{AdnlServer, AdnlServerConfig},
};
use anyhow::{Context, ensure};
use chain_block::{BlockIdExt, ShardIdent, UInt256};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tl_api::{TLObject, deserialize_boxed, tos};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default)]
struct Counts {
    control_list: AtomicUsize,
    control_detail: AtomicUsize,
    public: Mutex<HashMap<String, usize>>,
}
struct ControlReplies {
    counts: Arc<Counts>,
    unsupported: bool,
}
fn block() -> BlockIdExt {
    BlockIdExt::with_params(ShardIdent::masterchain(), 1, UInt256::default(), UInt256::default())
}
fn metadata() -> anyhow::Result<Vec<tos::engine::validator::configproposalmeta::ConfigProposalMeta>>
{
    Ok(super::offer_list_tests::live_proposals()?
        .into_iter()
        .map(|p| tos::engine::validator::configproposalmeta::ConfigProposalMeta {
            hash: UInt256::from(p.hash),
            expires: i32::from_ne_bytes(p.expires.to_ne_bytes()),
            critical: p.critical.into(),
            param_id: p.param_id,
            param_hash: p.param_hash.map(UInt256::from),
            has_value: p.has_value.into(),
            vset_id: UInt256::from(p.vset_id),
            voters: p.voters.into_iter().map(i32::from).collect(),
            weight_remaining: p.weight_remaining,
            rounds_remaining: i32::from(p.rounds_remaining),
            wins: i32::from(p.wins),
            losses: i32::from(p.losses),
        })
        .collect())
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
        if query.is::<tos::rpc::engine::validator::GetConfigProposals>() {
            self.counts.control_list.fetch_add(1, Ordering::SeqCst);
            if self.unsupported {
                return QueryResult::consume(
                    tos::engine::validator::controlqueryerror::ControlQueryError {
                        code: 621,
                        message: "query not supported".into(),
                    },
                );
            }
            return QueryResult::consume(
                tos::engine::validator::configproposals::ConfigProposals {
                    block: block(),
                    proposals: metadata()?,
                },
            );
        }
        if let Ok(request) = query.downcast::<tos::rpc::engine::validator::GetConfigProposal>() {
            self.counts.control_detail.fetch_add(1, Ordering::SeqCst);
            if self.unsupported {
                return QueryResult::consume(
                    tos::engine::validator::controlqueryerror::ControlQueryError {
                        code: 621,
                        message: "query not supported".into(),
                    },
                );
            }
            let meta = metadata()?.into_iter().find(|p| p.hash == request.hash);
            let meta = meta.map(|mut p| {
                p.has_value = true.into();
                p
            });
            let value = if meta.is_some() {
                Some(chain_block::write_boc(&chain_block::BuilderData::new().into_cell()?)?)
            } else {
                None
            };
            return QueryResult::consume(
                tos::engine::validator::configproposaldetail::ConfigProposalDetail {
                    block: block(),
                    meta,
                    value,
                },
            );
        }
        anyhow::bail!("unexpected control query")
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    server: AdnlServer,
    http: tokio::task::JoinHandle<()>,
    counts: Arc<Counts>,
}
impl Fixture {
    async fn new(unsupported: bool) -> anyhow::Result<Self> {
        let counts = Arc::new(Counts::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let public_addr = listener.local_addr()?;
        let public_counts = counts.clone();
        let http = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let counts = public_counts.clone();
                tokio::spawn(async move {
                    let mut input = Vec::new();
                    let mut buffer = [0; 4096];
                    loop {
                        let Ok(n) = socket.read(&mut buffer).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        input.extend_from_slice(&buffer[..n]);
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
                            .unwrap_or(0);
                        if input.len() < end + 4 + length {
                            continue;
                        }
                        let Ok(request) = serde_json::from_slice::<serde_json::Value>(
                            &input[end + 4..end + 4 + length],
                        ) else {
                            return;
                        };
                        let getter = request["params"]["method"]
                            .as_str()
                            .or_else(|| request["params"]["method_name"].as_str())
                            .unwrap_or("other")
                            .to_owned();
                        if let Ok(mut map) = counts.public.lock() {
                            *map.entry(getter).or_default() += 1;
                        }
                        let body = serde_json::json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32603,"message":"public proposal reads forbidden"}}).to_string();
                        let response = format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _sent = socket.write_all(response.as_bytes()).await;
                        return;
                    }
                });
            }
        });
        let temporary = std::net::TcpListener::bind("127.0.0.1:0")?;
        let control_addr = temporary.local_addr()?;
        drop(temporary);
        let config = AdnlServerConfig::from_json(&serde_json::json!({"address":control_addr.to_string(),"clients":{"any":null},
            "server_key":{"type_id":1209251014,"pvt_key":"3CFeiTSlGkJf3D8w3ZXS4QS+6/0p+MFZGuv0XYMvMRo="}}).to_string())?;
        let server = AdnlServer::listen(
            config,
            vec![Arc::new(ControlReplies { counts: counts.clone(), unsupported })],
        )
        .await?;
        let directory = tempfile::tempdir()?;
        let config = serde_json::json!({"nodes":{"test":{"server_address":control_addr.to_string(),
            "server_key":{"type_id":1209251014,"pub_key":"BBKmgGAxz4ZofRgMO2qhYt+K1bGlGeowukPONVAkOcU="},
            "client_key":{"type_id":1209251014,"pvt_key":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="},"timeouts":2}},
            "chain_rpc":{"urls":[format!("http://{public_addr}")],"api_key":null},"http":{"bind":"127.0.0.1:0"}});
        std::fs::write(directory.path().join("config.json"), serde_json::to_vec(&config)?)?;
        Ok(Self { directory, server, http, counts })
    }
    fn path(&self) -> anyhow::Result<String> {
        self.directory
            .path()
            .join("config.json")
            .to_str()
            .map(str::to_owned)
            .context("test config path")
    }
    fn no_public_proposals(&self) -> anyhow::Result<()> {
        let counts =
            self.counts.public.lock().map_err(|_| anyhow::anyhow!("counter lock poisoned"))?;
        assert_eq!(*counts.get("list_proposals").unwrap_or(&0), 0);
        assert_eq!(*counts.get("get_proposal").unwrap_or(&0), 0);
        Ok(())
    }
    async fn stop(self) {
        self.http.abort();
        self.server.shutdown().await;
    }
}

fn check_upgrade(result: anyhow::Result<()>, unsupported: bool) -> anyhow::Result<()> {
    if unsupported {
        let error = result.err().context("unsupported query accepted")?;
        ensure!(
            error.downcast_ref::<control_client::UnsupportedControlQuery>().is_some(),
            "upgrade error type lost: {error:#}"
        );
    } else {
        result?;
    }
    Ok(())
}
#[tokio::test]
async fn offer_ls_never_reads_public_proposals() -> anyhow::Result<()> {
    for unsupported in [false, true] {
        let fixture = Fixture::new(unsupported).await?;
        let result = VoteOfferLsCmd { format: super::super::output_format::OutputFormat::Json }
            .run(&fixture.path()?)
            .await;
        fixture.no_public_proposals()?;
        check_upgrade(result, unsupported)?;
        assert_eq!(fixture.counts.control_list.load(Ordering::SeqCst), 1);
        fixture.stop().await;
    }
    Ok(())
}
#[tokio::test]
async fn offer_cast_selection_never_reads_public_proposals() -> anyhow::Result<()> {
    for unsupported in [false, true] {
        let fixture = Fixture::new(unsupported).await?;
        let result = VoteOfferCastCmd { hash: None }.run(&fixture.path()?).await;
        fixture.no_public_proposals()?;
        check_upgrade(result, unsupported)?;
        assert_eq!(fixture.counts.control_list.load(Ordering::SeqCst), 1);
        fixture.stop().await;
    }
    Ok(())
}
#[tokio::test]
async fn offer_diff_never_reads_public_proposals() -> anyhow::Result<()> {
    for unsupported in [false, true] {
        let fixture = Fixture::new(unsupported).await?;
        let hash = hex::encode(super::offer_list_tests::live_proposals()?[0].hash);
        let result = VoteOfferDiffCmd { hash }.run(&fixture.path()?).await;
        fixture.no_public_proposals()?;
        check_upgrade(result, unsupported)?;
        assert_eq!(fixture.counts.control_detail.load(Ordering::SeqCst), 1);
        fixture.stop().await;
    }
    Ok(())
}
#[tokio::test]
async fn offer_create_expiry_never_reads_public_proposals() -> anyhow::Result<()> {
    for unsupported in [false, true] {
        let fixture = Fixture::new(unsupported).await?;
        let config = common::app_config::AppConfig::load(std::path::Path::new(&fixture.path()?))?;
        let client = tokio::sync::Mutex::new(operator_control_client(&config, None).await?);
        let result =
            proposal_expiry(&client, super::offer_list_tests::live_proposals()?[0].hash).await;
        fixture.no_public_proposals()?;
        if unsupported {
            check_upgrade(result.map(|_| ()), true)?;
        } else {
            assert_eq!(result?, Some(super::offer_list_tests::live_proposals()?[0].expires));
        }
        assert_eq!(fixture.counts.control_detail.load(Ordering::SeqCst), 1);
        fixture.stop().await;
    }
    Ok(())
}

#[tokio::test]
async fn offer_upgrade_errors_never_fall_back_to_public_proposals() -> anyhow::Result<()> {
    for workflow in ["ls", "cast", "diff", "create"] {
        let fixture = Fixture::new(true).await?;
        let path = fixture.path()?;
        let hash = super::offer_list_tests::live_proposals()?[0].hash;
        let result = match workflow {
            "ls" => {
                VoteOfferLsCmd { format: super::super::output_format::OutputFormat::Json }
                    .run(&path)
                    .await
            }
            "cast" => VoteOfferCastCmd { hash: None }.run(&path).await,
            "diff" => VoteOfferDiffCmd { hash: hex::encode(hash) }.run(&path).await,
            "create" => {
                let config = common::app_config::AppConfig::load(std::path::Path::new(&path))?;
                let client = tokio::sync::Mutex::new(operator_control_client(&config, None).await?);
                proposal_expiry(&client, hash).await.map(|_| ())
            }
            _ => anyhow::bail!("invalid test workflow"),
        };
        fixture.no_public_proposals()?;
        check_upgrade(result, true)?;
        fixture.stop().await;
    }
    Ok(())
}
