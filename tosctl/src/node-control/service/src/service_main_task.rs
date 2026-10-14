/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::{
    http::http_server_task,
    indexer::IndexerStore,
    runtime_config::RuntimeConfigStore,
    task::{
        ContractsTask, ElectionsTask, IndexerTask, VotingTask,
        task_manager::{TaskController, shutdown_tasks},
    },
};
use anyhow::Context;
use common::{
    app_config::AppConfig, log::setup_log, snapshot::SnapshotStore,
    task_cancellation::CancellationCtx,
};
use elections::election_task::BindingStatusCallback;
use std::{collections::HashMap, path::Path, sync::Arc};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServiceProfile {
    Full,
    Explorer,
}

/// Runs the full service until it is cancelled. An error that ends the service
/// is returned, not only logged, so the process exits non-zero and a
/// supervisor that restarts on failure restarts it: logging it and exiting 0
/// left an election task dead after a reboot, when the node's RPC was not up
/// yet.
pub async fn run(cancellation_ctx: CancellationCtx, config_path: String) -> anyhow::Result<()> {
    run_profile(cancellation_ctx, config_path, ServiceProfile::Full).await
}

/// Runs the read-only explorer profile; errors are returned as for [`run`].
pub async fn run_explorer(
    cancellation_ctx: CancellationCtx,
    config_path: String,
) -> anyhow::Result<()> {
    run_profile(cancellation_ctx, config_path, ServiceProfile::Explorer).await
}

async fn run_profile(
    cancellation_ctx: CancellationCtx,
    config_path: String,
    profile: ServiceProfile,
) -> anyhow::Result<()> {
    let app_cfg = Arc::new(AppConfig::load(Path::new(&config_path)).map_err(|e| {
        eprintln!("Failed to open config file: {:#}", e);
        e.context("open config file")
    })?);

    let _log_guard = setup_log(Some(&app_cfg)).map_err(|e| {
        eprintln!("Failed to setup log file: {:#}", e);
        e.context("set up the log file")
    })?;

    tracing::info!(profile = ?profile, "Service started");
    let result = run_with_profile(cancellation_ctx, app_cfg, config_path, profile).await;
    if let Err(e) = &result {
        tracing::error!("service error: {:#}", e);
    }
    tracing::info!(profile = ?profile, "Service stopped");
    result
}

pub async fn run_with_config(
    cancellation_ctx: CancellationCtx,
    app_cfg: Arc<AppConfig>,
    config_path: String,
) -> anyhow::Result<()> {
    run_with_profile(cancellation_ctx, app_cfg, config_path, ServiceProfile::Full).await
}

/// The tasks a profile enables at start, in start order.
fn startup_tasks(
    app_cfg: &AppConfig,
    profile: ServiceProfile,
) -> anyhow::Result<Vec<&'static str>> {
    match profile {
        ServiceProfile::Explorer => {
            anyhow::ensure!(
                app_cfg.indexer_enabled,
                "the explorer profile serves the explorer index and cannot run with \
                 indexer_enabled = false"
            );
            Ok(vec!["indexer"])
        }
        ServiceProfile::Full => {
            let mut tasks = vec!["contracts"];
            if app_cfg.elections.is_some() {
                tasks.push("elections");
            }
            if app_cfg.voting.is_some() {
                tasks.push("voting");
            }
            // Chain-wide contract discovery is a baseline read-only
            // capability, on unless the configuration turns it off: a host
            // that only takes part in elections does not need it.
            if app_cfg.indexer_enabled {
                tasks.push("indexer");
            }
            Ok(tasks)
        }
    }
}

async fn run_with_profile(
    cancellation_ctx: CancellationCtx,
    app_cfg: Arc<AppConfig>,
    config_path: String,
    profile: ServiceProfile,
) -> anyhow::Result<()> {
    let startup = startup_tasks(&app_cfg, profile)?;
    let indexer_db_path = Path::new(&config_path).with_file_name("tosctl-indexer.db");
    let runtime_cfg = match profile {
        ServiceProfile::Full => RuntimeConfigStore::initialize(app_cfg.clone(), config_path).await,
        ServiceProfile::Explorer => {
            RuntimeConfigStore::initialize_explorer(app_cfg.clone(), config_path).await
        }
    }
    .context("initialize runtime config store")?;
    let runtime_cfg = Arc::new(runtime_cfg);
    let store = Arc::new(SnapshotStore::new());
    // A disabled indexer leaves its database untouched: it is neither created
    // nor opened, so it costs no disk reads and no file on a fresh host.
    let indexer_store = if startup.contains(&"indexer") {
        Some(Arc::new(IndexerStore::open(&indexer_db_path).context("open indexer store")?))
    } else {
        tracing::info!("explorer indexer disabled by configuration (indexer_enabled = false)");
        None
    };

    // Status callback: when the elections runner detects binding status changes,
    // update the runtime config and save to file.
    let cfg = runtime_cfg.clone();
    let on_status_change: BindingStatusCallback = Arc::new(move |statuses| {
        let _ = cfg.update_with(|app_cfg| {
            for (node_id, new_status) in &statuses {
                if let Some(binding) = app_cfg.bindings.get_mut(node_id) {
                    binding.status = *new_status;
                }
            }
        });
        cfg.save_to_file();
    });

    let mut tasks = HashMap::new();
    tasks.insert(
        "contracts",
        Arc::new(TaskController::new(
            "contracts",
            ContractsTask::new(runtime_cfg.clone(), store.clone()),
            runtime_cfg.clone(),
        )),
    );

    tasks.insert(
        "elections",
        Arc::new(TaskController::new(
            "elections",
            ElectionsTask::new(runtime_cfg.clone(), store.clone(), Some(on_status_change)),
            runtime_cfg.clone(),
        )),
    );

    tasks.insert(
        "voting",
        Arc::new(TaskController::new(
            "voting",
            VotingTask::new(runtime_cfg.clone()),
            runtime_cfg.clone(),
        )),
    );

    if let Some(indexer_store) = &indexer_store {
        tasks.insert(
            "indexer",
            Arc::new(TaskController::new(
                "indexer",
                IndexerTask::new(runtime_cfg.clone(), indexer_store.clone()),
                runtime_cfg.clone(),
            )),
        );
    }

    for name in &startup {
        let task =
            tasks.get(name).with_context(|| format!("startup task '{name}' is not registered"))?;
        let _ = task.enable().await;
    }

    let http_task_handle = tokio::spawn(http_server_task::run(
        cancellation_ctx.clone(),
        store.clone(),
        runtime_cfg.clone(),
        tasks.clone(),
        indexer_store.clone(),
        profile == ServiceProfile::Explorer,
    ));

    let max_wait = std::time::Duration::from_secs(10);
    let mut cancel = cancellation_ctx.subscribe();

    loop {
        let timeout = tokio::time::sleep(max_wait);
        tokio::pin!(timeout);

        tokio::select! {
            _ = &mut timeout => {
                // Reload config from file if changed
                if runtime_cfg.reload_from_file().await {
                    if profile == ServiceProfile::Explorer {
                        if let Some(task) = tasks.get("indexer") {
                            let _ = task.restart().await;
                        }
                    } else {
                        for task in tasks.values() {
                            let _ = task.restart().await;
                        }
                    }
                }
            }
            _ = cancel.changed() => {
                break;
            }
        }
    }
    // Orderly shutdown, bounded by a single overall grace period (not per task).
    let shutdown_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);

    // 1. Close control-operation admission first. Marking every task shutting
    //    down makes enable()/restart() and the detached finalizer refuse to
    //    start a new generation, so a control operation that races shutdown —
    //    including a restart an HTTP handler already spawned as its own task —
    //    cannot bring a task back up after it stops.
    for task in tasks.values() {
        task.begin_shutdown().await;
    }

    // 2. Drain the HTTP control API, within the overall budget. Distinguish the
    //    three outcomes: a clean drain, the task failing, and the grace expiring.
    //    On timeout the JoinHandle is dropped, which detaches the task — it is
    //    not a guarantee the HTTP server has actually stopped, so say so rather
    //    than imply a clean drain.
    match tokio::time::timeout_at(shutdown_deadline, http_task_handle).await {
        Ok(Ok(())) => tracing::info!("HTTP server drained"),
        Ok(Err(e)) => tracing::warn!("HTTP server task failed during shutdown drain: {:#}", e),
        Err(_) => tracing::warn!(
            "HTTP server did not drain within the shutdown grace period; detaching it and continuing shutdown"
        ),
    }

    // 3. Request every task to stop and wait for them to actually reach Stopped,
    //    sharing the overall deadline, so the Tokio runtime is not torn down
    //    while finalizers are still running their cleanup.
    shutdown_tasks(&tasks, shutdown_deadline).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn closed_loopback_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("addr").port()
    }

    fn config(extra: serde_json::Value) -> AppConfig {
        let mut config = serde_json::json!({
            "nodes": {},
            "chain_rpc": {"urls": ["http://127.0.0.1:3301/"]},
            "http": {},
            "master_wallet": null,
            "log": null,
            "elections": {}
        });
        for (key, value) in extra.as_object().expect("object").clone() {
            config[key] = value;
        }
        serde_json::from_value(config).expect("config")
    }

    #[test]
    fn the_indexer_starts_by_default_beside_elections() {
        let config = config(serde_json::json!({}));
        assert_eq!(
            startup_tasks(&config, ServiceProfile::Full).unwrap(),
            vec!["contracts", "elections", "indexer"]
        );
        assert_eq!(startup_tasks(&config, ServiceProfile::Explorer).unwrap(), vec!["indexer"]);
    }

    #[test]
    fn a_disabled_indexer_stays_off_while_elections_still_start() {
        let config = config(serde_json::json!({"indexer_enabled": false}));
        assert_eq!(
            startup_tasks(&config, ServiceProfile::Full).unwrap(),
            vec!["contracts", "elections"]
        );
        let error = startup_tasks(&config, ServiceProfile::Explorer)
            .expect_err("the explorer profile has nothing to serve without the indexer");
        assert!(error.to_string().contains("indexer_enabled = false"), "{error}");
    }

    #[tokio::test]
    async fn a_missing_config_is_returned_as_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("missing.json").to_string_lossy().into_owned();
        let result = run(CancellationCtx::new(), path).await;
        let message = format!("{:#}", result.expect_err("a missing config must fail the service"));
        assert!(message.contains("open config file"), "{message}");
    }

    #[tokio::test]
    async fn a_runtime_initialization_failure_is_returned_as_an_error() {
        // The service must end with an error when it cannot initialize, so
        // the process exits non-zero, instead of logging it and returning as
        // if it had stopped cleanly. Here initialization stops at the vault
        // (no VAULT_URL in the test process); after a reboot it stopped at the
        // chain RPC, which was not up yet. Both return through the same path.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tosctl-config.json");
        let config = serde_json::json!({
            "nodes": {},
            "chain_rpc": {"urls": [format!("http://127.0.0.1:{}/jsonRPC", closed_loopback_port())]},
            "http": {},
            "master_wallet": null,
            "log": null
        });
        std::fs::write(&path, config.to_string()).expect("write config");
        let result = tokio::time::timeout(
            Duration::from_secs(120),
            run(CancellationCtx::new(), path.to_string_lossy().into_owned()),
        )
        .await
        .expect("the service must give up when it cannot initialize, not run on");
        let message =
            format!("{:#}", result.expect_err("a failed initialization must fail the service"));
        assert!(message.contains("initialize runtime config store"), "{message}");
    }
}
