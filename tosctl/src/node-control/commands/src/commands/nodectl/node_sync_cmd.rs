use super::node_cmd::{NodeStatusCmd, NodeTarget, create_control_client};
use anyhow::{Result, ensure};
use node_data_sync::{collector::Collector, status::StatusExit};
use std::time::{Duration, Instant};

#[derive(clap::Args, Clone)]
pub struct NodeSyncCmd {
    #[command(subcommand)]
    action: SyncAction,
}
#[derive(clap::Subcommand, Clone)]
enum SyncAction {
    #[cfg(feature = "node-data-sync-native")]
    /// Restore only verified donor chain data, retaining this node's own signing history
    Restore(RestoreArgs),
    #[cfg(feature = "node-data-sync-native")]
    /// Resume an interrupted operation forward; never roll back an exposed replacement
    Recover(RecoverArgs),
    /// Report freshness, coherent lag and agreement with two named references
    Status(NodeStatusCmd),
}
#[cfg(feature = "node-data-sync-native")]
#[derive(clap::Args, Clone)]
struct RestoreArgs {
    /// Private JSON request binding the held context, publisher and exact signed manifest
    #[arg(long)]
    request: std::path::PathBuf,
    #[arg(long)]
    operation: std::path::PathBuf,
    /// Inspect the plan without stopping the node or downloading data
    #[arg(long)]
    dry_run: bool,
    #[command(flatten)]
    status: NodeStatusCmd,
}
#[cfg(feature = "node-data-sync-native")]
#[derive(clap::Args, Clone)]
struct RecoverArgs {
    #[arg(long)]
    operation: std::path::PathBuf,
    #[command(flatten)]
    status: NodeStatusCmd,
}
#[cfg(feature = "node-data-sync-native")]
async fn bind_context(context: &node_data_sync::context::NodeContext) -> Result<()> {
    let config = common::app_config::AppConfig::load(&context.operator_config)?;
    let (_, node) = super::utils::select_node(&config, Some(&context.node_name))?;
    let adnl = super::utils::node_adnl_config(node, None).await?;
    context.bind_control(&adnl.server_id())
}
#[cfg(feature = "node-data-sync-native")]
async fn recovered_status(
    context: &node_data_sync::context::NodeContext,
    operation: &std::path::Path,
    command: &NodeStatusCmd,
) -> Result<()> {
    let selected = NodeTarget {
        config: context
            .operator_config
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("operator config path"))?,
        node: Some(&context.node_name),
    };
    let (_, mut control) = create_control_client(&selected).await?;
    let binding = context.bind_control(&control.server_id());
    control.shutdown().await?;
    binding?;
    let mut command = command.clone();
    command.watch = true;
    status(&selected, &command).await?;
    node_data_sync::operations::complete(operation)?;
    Ok(())
}
impl NodeSyncCmd {
    pub async fn run(&self, target: &NodeTarget<'_>) -> Result<()> {
        match &self.action {
            SyncAction::Status(cmd) => status(target, cmd).await,
            #[cfg(feature = "node-data-sync-native")]
            SyncAction::Restore(args) => {
                ensure!(
                    args.status.references.len() >= 2,
                    "restore/recover requires two named references"
                );
                Collector::new(&args.status.references)?;
                let request: node_data_sync::operations::RestoreRequest =
                    serde_json::from_slice(&node_data_sync::context::read_bytes(
                        &args.request,
                        node_data_sync::model::MANIFEST_LIMIT,
                    )?)?;
                bind_context(&request.context).await?;
                let plan = node_data_sync::operations::preflight(&request)?;
                println!("{}", serde_json::to_string(&plan)?);
                if args.dry_run {
                    return Ok(());
                }
                let operation = args.operation.clone();
                let context = request.context.clone();
                let stage = operation.clone();
                tokio::task::spawn_blocking(move || {
                    node_data_sync::operations::restore(&request, &stage)
                })
                .await??;
                recovered_status(&context, &operation, &args.status).await
            }
            #[cfg(feature = "node-data-sync-native")]
            SyncAction::Recover(args) => {
                ensure!(
                    args.status.references.len() >= 2,
                    "restore/recover requires two named references"
                );
                Collector::new(&args.status.references)?;
                let operation = args.operation.clone();
                let source = operation.clone();
                let (context, _) = tokio::task::spawn_blocking(move || {
                    node_data_sync::operations::recover(&source)
                })
                .await??;
                recovered_status(&context, &operation, &args.status).await
            }
        }
    }
}
pub(super) async fn status(target: &NodeTarget<'_>, cmd: &NodeStatusCmd) -> Result<()> {
    ensure!((1..=86400).contains(&cmd.timeout), "status timeout must be 1..86400 seconds");
    let mut collector = Collector::new(&cmd.references).map_err(|error| {
        eprintln!("reference policy failed: {error:#}");
        anyhow::Error::new(StatusExit(3))
    })?;
    let (_, mut client) =
        match tokio::time::timeout(Duration::from_secs(10), create_control_client(target)).await {
            Ok(Ok(client)) => client,
            Ok(Err(error)) => {
                eprintln!("control unavailable: {error:#}");
                return Err(StatusExit(4).into());
            }
            Err(_) => {
                eprintln!("control connection deadline expired");
                return Err(StatusExit(4).into());
            }
        };
    let start = Instant::now();
    let exit = loop {
        let remaining = Duration::from_secs(cmd.timeout).saturating_sub(start.elapsed());
        let result = match tokio::time::timeout(remaining, collector.sample(&mut client)).await {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!("sync status observation deadline expired")),
        };
        let code = match result {
            Ok(sample) => {
                let code = sample.exit_code;
                if cmd.format == super::output_format::OutputFormat::Json {
                    println!("{}", serde_json::to_string(&sample)?);
                } else {
                    println!(
                        "{}; head={}, age={}s, shard_lag={}, reference_lag={:?}, stable={}s",
                        sample.reason,
                        sample.evidence.tip.seqno,
                        sample.block_age_seconds,
                        sample.shard_lag_blocks,
                        sample.reference_lag_blocks,
                        sample.stable_seconds
                    );
                }
                code
            }
            Err(error) => {
                if cmd.format == super::output_format::OutputFormat::Json {
                    println!(
                        "{}",
                        serde_json::json!({"state":"unknown", "exit_code":4,"reason":error.to_string()})
                    );
                } else {
                    println!("unknown: {error:#}");
                }
                4
            }
        };
        if !cmd.watch || code == 0 || start.elapsed() >= Duration::from_secs(cmd.timeout) {
            break code;
        }
        tokio::time::sleep(
            Duration::from_secs(5)
                .min(Duration::from_secs(cmd.timeout).saturating_sub(start.elapsed())),
        )
        .await;
    };
    client.shutdown().await?;
    if exit != 0 {
        return Err(StatusExit(exit).into());
    }
    Ok(())
}
