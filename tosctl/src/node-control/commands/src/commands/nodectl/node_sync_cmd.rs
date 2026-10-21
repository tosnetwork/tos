use super::node_cmd::{NodeStatusCmd, NodeTarget, create_control_client};
use anyhow::{Result, ensure};
use node_data_sync::{
    collector::Collector,
    status::{StatusExit, SyncStatus},
};
use std::time::Duration;
use tokio::time::Instant;

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
                let outcome = tokio::task::spawn_blocking(move || {
                    node_data_sync::operations::recover(&source)
                })
                .await??;
                match outcome {
                    node_data_sync::operations::RecoveryOutcome::Installed(result) => {
                        recovered_status(&result.0, &operation, &args.status).await
                    }
                    node_data_sync::operations::RecoveryOutcome::Aborted(report) => {
                        println!(
                            "{}",
                            serde_json::json!({"state":"aborted","reason":"Preparation aborted without exchange or automatic start. The original tree remains installed. If the selected service is inactive, use restart_command to start it; verify service state before starting a new restore.","recovery":report})
                        );
                        Ok(())
                    }
                }
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
    let mut sampler = LiveSampler { collector: &mut collector, client: &mut client };
    let exit = observe(&mut sampler, cmd.watch, Duration::from_secs(cmd.timeout), Duration::from_secs(5), |result| {
        match result {
            Ok(sample) => {
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
            }
            Err(error) => {
                if cmd.format == super::output_format::OutputFormat::Json {
                    println!("{}", serde_json::json!({"state":"unknown", "exit_code":4,"reason":error.to_string()}));
                } else { println!("unknown: {error:#}"); }
            }
        }
        Ok(())
    }).await?;
    client.shutdown().await?;
    if exit != 0 {
        return Err(StatusExit(exit).into());
    }
    Ok(())
}

trait StatusSampler {
    fn sample(&mut self) -> impl std::future::Future<Output = Result<SyncStatus>>;
}
struct LiveSampler<'a> {
    collector: &'a mut Collector,
    client: &'a mut control_client::client_adnl::ControlClientAdnl,
}
impl StatusSampler for LiveSampler<'_> {
    async fn sample(&mut self) -> Result<SyncStatus> {
        self.collector.sample(self.client).await
    }
}
async fn observe(
    sampler: &mut impl StatusSampler,
    watch: bool,
    budget: Duration,
    interval: Duration,
    mut emit: impl FnMut(std::result::Result<&SyncStatus, &anyhow::Error>) -> Result<()>,
) -> Result<u8> {
    let start = Instant::now();
    let mut last_successful = None;
    loop {
        let remaining = budget.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            if let Some(sample) = last_successful.as_ref() {
                emit(Ok(sample))?;
                return Ok(sample.exit_code);
            }
            emit(Err(&anyhow::anyhow!("sync status observation deadline expired")))?;
            return Ok(4);
        }
        let result = match tokio::time::timeout(remaining, sampler.sample()).await {
            Ok(result) => result,
            Err(_) => {
                if let Some(sample) = last_successful.as_ref() {
                    emit(Ok(sample))?;
                    return Ok(sample.exit_code);
                }
                emit(Err(&anyhow::anyhow!("sync status observation deadline expired")))?;
                return Ok(4);
            }
        };
        let code = match &result {
            Ok(sample) => {
                if matches!(sample.exit_code, 2 | 3) {
                    last_successful = Some(sample.clone());
                }
                sample.exit_code
            }
            Err(_) => 4,
        };
        emit(result.as_ref())?;
        if !watch || code == 0 {
            return Ok(code);
        }
        tokio::time::sleep(interval.min(budget.saturating_sub(start.elapsed()))).await;
    }
}

#[cfg(test)]
mod watch_tests {
    use super::*;
    struct Script {
        calls: usize,
        pending_after_first: bool,
        error_after_first: bool,
        code: u8,
    }
    impl StatusSampler for Script {
        async fn sample(&mut self) -> Result<SyncStatus> {
            self.calls += 1;
            if self.calls > 1 && self.error_after_first {
                anyhow::bail!("unavailable observation");
            }
            if self.calls > 1 && self.pending_after_first {
                std::future::pending::<()>().await;
            }
            let mut value = serde_json::json!({
                "state":"catching_up", "exit_code":2, "block_age_seconds":100,
                "shard_lag_blocks":10,"reference_lag_blocks":10,"common_id":null,
                "stable_seconds":0,"initial_sync_complete":false,"reason":"still catching up",
                "evidence":{"sampled_utc":100,"tip":{"workchain":-1,"shard":i64::MIN,"seqno":10,"root_hash":"11".repeat(32),"file_hash":"22".repeat(32)},"tip_utime":0,"coherent_tip":null,"coherent_tip_utime":null,"shard_client_seqno":0,"initial_sync_complete":false}
            });
            value["exit_code"] = serde_json::json!(self.code);
            value["state"] = serde_json::json!(match self.code {
                0 => "at_head",
                2 => "catching_up",
                3 => "policy_failure",
                _ => "unknown",
            });
            Ok(serde_json::from_value(value)?)
        }
    }
    #[tokio::test(start_paused = true)]
    async fn watch_deadline_keeps_catching_up_without_a_zero_budget_sample() -> Result<()> {
        for interval in [Duration::from_secs(5), Duration::ZERO] {
            let mut script =
                Script { calls: 0, pending_after_first: true, error_after_first: false, code: 2 };
            let mut outputs = Vec::new();
            let code = observe(&mut script, true, Duration::from_secs(1), interval, |s| {
                outputs.push(s.map(|s| s.exit_code).unwrap_or(4));
                Ok(())
            })
            .await?;
            assert_eq!(code, 2, "watch observation timeout became unknown");
            assert_eq!(
                outputs,
                vec![2, 2],
                "deadline lost the last successful catching-up observation"
            );
            assert_eq!(
                script.calls,
                if interval.is_zero() { 2 } else { 1 },
                "sample started with zero budget"
            );
        }
        let mut transient =
            Script { calls: 0, pending_after_first: false, error_after_first: true, code: 2 };
        let mut outputs = Vec::new();
        let code = observe(
            &mut transient,
            true,
            Duration::from_secs(1),
            Duration::from_millis(500),
            |s| {
                outputs.push(s.map(|s| s.exit_code).unwrap_or(4));
                Ok(())
            },
        )
        .await?;
        assert_eq!(
            code, 2,
            "deadline discarded the last successful observation after a transient error"
        );
        assert_eq!(outputs, vec![2, 4, 2]);
        let mut script =
            Script { calls: 0, pending_after_first: false, error_after_first: false, code: 2 };
        let code = observe(&mut script, true, Duration::ZERO, Duration::ZERO, |_| Ok(())).await?;
        assert_eq!(code, 4);
        assert_eq!(script.calls, 0, "sample started with zero budget");
        for expected in [0, 3, 4] {
            let mut script = Script {
                calls: 0,
                pending_after_first: true,
                error_after_first: false,
                code: expected,
            };
            let code =
                observe(&mut script, true, Duration::from_secs(1), Duration::ZERO, |_| Ok(()))
                    .await?;
            assert_eq!(code, expected, "watch changed an existing exit case");
            assert_eq!(
                script.calls,
                if expected == 0 { 1 } else { 2 },
                "watch changed policy/unknown retry behavior"
            );
        }

        Ok(())
    }
}
