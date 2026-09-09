/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::runtime_config::RuntimeConfig;
use chain_block::UnixTime;
use common::{
    app_config::AppConfig,
    task_cancellation::{CancellationCtx, CancellationReason},
};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatus {
    Running,
    // The task has been signalled to stop and is being joined, but has not yet
    // confirmed exit. Reported distinctly from Stopped so callers never see a
    // task reported as fully stopped while it may still be running.
    Stopping,
    Stopped,
}

impl TaskStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskStatus::Running => "running",
            TaskStatus::Stopping => "stopping",
            TaskStatus::Stopped => "stopped",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TaskStateView {
    pub enabled: bool,
    pub status: TaskStatus,
    pub updated_at: u64,
}

/// Trait for tasks managed by `TaskController`.
///
/// Uses `&self` (not `&mut self`) so that the task can be stored in `Arc`
/// and safely shared/restarted. If a task needs mutable internal state,
/// use interior mutability (`tokio::sync::Mutex`, `AtomicU64`, etc.)
/// inside the implementing struct.
#[async_trait::async_trait]
pub trait ServiceTask: Send + Sync {
    async fn run(
        &self,
        cancellation_ctx: CancellationCtx,
        app_config: Arc<AppConfig>,
    ) -> anyhow::Result<()>;
}

struct State {
    enabled: bool,
    status: TaskStatus,
    updated_at: u64,
    cancel: Option<CancellationCtx>,
    // The running task's join handle (present only while Running).
    handle: Option<tokio::task::JoinHandle<()>>,
    // While Stopping, an abort handle for the generation being joined, so
    // enable() can force-stop it before starting a new one.
    abort: Option<tokio::task::AbortHandle>,
    // Identifies the current task instance. Bumped on each enable() so a
    // finalizer joining an older generation cannot clobber a newer state.
    generation: u64,
}

pub struct TaskController {
    name: &'static str,
    task: Arc<dyn ServiceTask>,
    state: Arc<Mutex<State>>,
    runtime_cfg: Arc<dyn RuntimeConfig>,
}

impl TaskController {
    pub fn new(
        name: &'static str,
        task: impl ServiceTask + 'static,
        runtime_cfg: Arc<dyn RuntimeConfig>,
    ) -> Self {
        Self {
            name,
            task: Arc::new(task),
            state: Arc::new(Mutex::new(State {
                enabled: true,
                status: TaskStatus::Stopped,
                updated_at: UnixTime::now(),
                cancel: None,
                handle: None,
                abort: None,
                generation: 0,
            })),
            runtime_cfg,
        }
    }

    pub async fn status(&self) -> TaskStateView {
        let st = self.state.lock().expect("failed to lock state");
        TaskStateView { enabled: st.enabled, status: st.status, updated_at: st.updated_at }
    }

    pub async fn enable(&self) -> TaskStateView {
        let mut st = self.state.lock().expect("failed to lock state");

        st.enabled = true;

        if st.status == TaskStatus::Running {
            st.updated_at = UnixTime::now();
            return TaskStateView {
                enabled: st.enabled,
                status: st.status,
                updated_at: st.updated_at,
            };
        }

        // Status is Stopped or Stopping. Force-stop any previous generation that
        // is still present before starting a new one, so two instances never run
        // concurrently: a Stopping generation (being joined by a finalizer) is
        // aborted via its abort handle, and any lingering running handle is
        // aborted directly. Bumping the generation makes the old finalizer's
        // Stopping->Stopped transition a no-op.
        if let Some(orphan) = st.handle.take() {
            orphan.abort();
        }
        if let Some(abort) = st.abort.take() {
            abort.abort();
        }
        st.generation = st.generation.wrapping_add(1);

        let cancel_ctx = CancellationCtx::new();
        let task = self.task.clone();
        let name = self.name;

        tracing::debug!("starting {} task...", name);
        let ctx = cancel_ctx.clone();
        let app_config = self.runtime_cfg.get();
        let handle = tokio::spawn(async move {
            if let Err(e) = task.run(ctx, app_config).await {
                tracing::error!("{} task error: {:#}", name, e);
            }
        });
        tracing::info!("{} task started", name);

        st.cancel = Some(cancel_ctx);
        st.handle = Some(handle);
        st.status = TaskStatus::Running;
        st.updated_at = UnixTime::now();

        TaskStateView { enabled: st.enabled, status: st.status, updated_at: st.updated_at }
    }

    pub async fn disable(&self) -> TaskStateView {
        let (view, finalizer) = {
            let mut st = self.state.lock().expect("failed to lock state");
            st.enabled = false;

            // Already stopped, or already stopping (a finalizer is driving the
            // Stopping -> Stopped transition). Don't re-signal or start a second
            // finalizer.
            if st.status == TaskStatus::Stopped || st.status == TaskStatus::Stopping {
                st.updated_at = UnixTime::now();
                return TaskStateView {
                    enabled: st.enabled,
                    status: st.status,
                    updated_at: st.updated_at,
                };
            }

            tracing::debug!("stopping {} task...", self.name);
            if let Some(mut ctx) = st.cancel.take() {
                ctx.cancel(CancellationReason::GracefullyShutdown());
            } else {
                tracing::warn!("{} task marked running but no cancellation ctx present", self.name);
            }

            // Enter Stopping synchronously, under the lock. The task has been
            // signalled but not yet joined, so it is reported Stopping, never
            // Stopped -- a subsequent enable() must treat it as still-present and
            // force-stop it rather than start a second instance. The handle moves
            // to a detached finalizer that joins it and flips Stopping -> Stopped
            // once it actually exits; an abort handle stays in state so enable()
            // can force-stop this generation first.
            match st.handle.take() {
                Some(handle) => {
                    st.abort = Some(handle.abort_handle());
                    st.status = TaskStatus::Stopping;
                    st.updated_at = UnixTime::now();
                    let view = TaskStateView {
                        enabled: st.enabled,
                        status: st.status,
                        updated_at: st.updated_at,
                    };
                    (view, Some((handle, st.generation)))
                }
                None => {
                    // No running handle to join: settle as Stopped immediately.
                    st.status = TaskStatus::Stopped;
                    st.updated_at = UnixTime::now();
                    let view = TaskStateView {
                        enabled: st.enabled,
                        status: st.status,
                        updated_at: st.updated_at,
                    };
                    (view, None)
                }
            }
        };

        // Drive Stopping -> Stopped from a detached task, independent of this
        // (HTTP-request) future's lifetime: a dropped future cannot strand
        // Stopping, and the task is never reported Stopped before it exits.
        if let Some((handle, generation)) = finalizer {
            let state = self.state.clone();
            let name = self.name;
            tokio::spawn(async move {
                let _ = handle.await;
                let mut st = state.lock().expect("failed to lock state");
                // Only finalize if this generation is still the one stopping; a
                // later enable() bumps the generation and owns the state now.
                if st.status == TaskStatus::Stopping && st.generation == generation {
                    st.status = TaskStatus::Stopped;
                    st.abort = None;
                    st.updated_at = UnixTime::now();
                    tracing::info!("{} task stopped", name);
                }
            });
        }
        view
    }

    pub async fn restart(&self) -> TaskStateView {
        let _ = self.disable().await;
        self.enable().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_rpc_client::v2::client_json_rpc::ClientJsonRpc;
    use common::app_config::{ChainRpcConfig, HttpConfig};
    use contracts::ChainProvider;
    use contracts::{NominatorWrapper, Wallet};
    use secrets_vault::vault::SecretVault;
    use std::{
        collections::HashMap,
        sync::atomic::{AtomicBool, AtomicU32, Ordering},
    };

    struct NoopRuntimeConfig {
        app_config: Arc<AppConfig>,
    }

    impl RuntimeConfig for NoopRuntimeConfig {
        fn get(&self) -> Arc<AppConfig> {
            self.app_config.clone()
        }
        fn master_wallet(&self) -> Arc<dyn Wallet> {
            panic!("NoopRuntimeConfig::master_wallet() should not be called in tests")
        }
        fn pools(&self) -> Arc<HashMap<String, Arc<dyn NominatorWrapper>>> {
            Arc::new(HashMap::new())
        }
        fn wallets(&self) -> Arc<HashMap<String, Arc<dyn Wallet>>> {
            Arc::new(HashMap::new())
        }
        fn rpc_client(&self) -> Arc<ClientJsonRpc> {
            panic!("NoopRuntimeConfig::rpc_client() should not be called in tests")
        }
        fn chain_provider(&self) -> Arc<dyn ChainProvider> {
            panic!("NoopRuntimeConfig::chain_provider() should not be called in tests")
        }
        fn vault(&self) -> Option<Arc<SecretVault>> {
            None
        }
        fn update_config(&self, _f: Box<dyn FnOnce(&mut AppConfig) + Send>) -> anyhow::Result<()> {
            anyhow::bail!("NoopRuntimeConfig::update_config() is not supported")
        }
        fn save_to_file(&self) {}
    }

    fn runtime_config() -> Arc<dyn RuntimeConfig> {
        Arc::new(NoopRuntimeConfig {
            app_config: Arc::new(AppConfig {
                nodes: HashMap::new(),
                wallets: HashMap::new(),
                pools: HashMap::new(),
                bindings: HashMap::new(),
                chain_rpc: ChainRpcConfig::default(),
                elections: None,
                voting: None,
                http: HttpConfig::default(),
                master_wallet: None,
                tick_interval: 30,
                indexer_retention_blocks: 0,
                log: None,
                bookmarks: HashMap::new(),
                agent_wallets: HashMap::new(),
                agent_tasks: HashMap::new(),
                capability_registries: HashMap::new(),
                service_actors: HashMap::new(),
                disputes: HashMap::new(),
                proof_attestations: HashMap::new(),
                alerts: Default::default(),
            }),
        })
    }

    struct WaitForeverTask {
        started: Arc<AtomicBool>,
    }

    impl WaitForeverTask {
        fn new() -> (Self, Arc<AtomicBool>) {
            let started = Arc::new(AtomicBool::new(false));
            (Self { started: started.clone() }, started)
        }
    }

    #[async_trait::async_trait]
    impl ServiceTask for WaitForeverTask {
        async fn run(
            &self,
            ctx: CancellationCtx,
            _app_config: Arc<AppConfig>,
        ) -> anyhow::Result<()> {
            self.started.store(true, Ordering::SeqCst);
            let mut rx = ctx.subscribe();
            let _ = rx.changed().await;
            Ok(())
        }
    }

    /// A task that completes immediately with `Ok(())`.
    struct ImmediateTask;

    #[async_trait::async_trait]
    impl ServiceTask for ImmediateTask {
        async fn run(
            &self,
            _ctx: CancellationCtx,
            _app_config: Arc<AppConfig>,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    /// A task that always returns an error.
    struct FailingTask;

    #[async_trait::async_trait]
    impl ServiceTask for FailingTask {
        async fn run(
            &self,
            _ctx: CancellationCtx,
            _app_config: Arc<AppConfig>,
        ) -> anyhow::Result<()> {
            anyhow::bail!("task failed on purpose")
        }
    }

    /// A task that counts how many times it has been started.
    struct CountingTask {
        count: Arc<AtomicU32>,
    }

    impl CountingTask {
        fn new() -> (Self, Arc<AtomicU32>) {
            let count = Arc::new(AtomicU32::new(0));
            (Self { count: count.clone() }, count)
        }
    }

    #[async_trait::async_trait]
    impl ServiceTask for CountingTask {
        async fn run(
            &self,
            ctx: CancellationCtx,
            _app_config: Arc<AppConfig>,
        ) -> anyhow::Result<()> {
            self.count.fetch_add(1, Ordering::SeqCst);
            let mut rx = ctx.subscribe();
            let _ = rx.changed().await;
            Ok(())
        }
    }

    /// Counts its runs and, once cancelled, still takes a while to actually
    /// return -- so a disable() join is still pending if its future is dropped.
    struct SlowToStopTask {
        runs: Arc<AtomicU32>,
        completed: Arc<AtomicU32>,
    }

    impl SlowToStopTask {
        fn new() -> (Self, Arc<AtomicU32>, Arc<AtomicU32>) {
            let runs = Arc::new(AtomicU32::new(0));
            let completed = Arc::new(AtomicU32::new(0));
            (Self { runs: runs.clone(), completed: completed.clone() }, runs, completed)
        }
    }

    #[async_trait::async_trait]
    impl ServiceTask for SlowToStopTask {
        async fn run(
            &self,
            ctx: CancellationCtx,
            _app_config: Arc<AppConfig>,
        ) -> anyhow::Result<()> {
            self.runs.fetch_add(1, Ordering::SeqCst);
            let mut rx = ctx.subscribe();
            let _ = rx.changed().await;
            // Observed cancellation, but take a while to actually exit. If the
            // generation is aborted during this window it never reaches the
            // completion marker below.
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            self.completed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    // disable() now returns Stopping and the Stopping -> Stopped transition is
    // driven by a detached finalizer once the task actually exits, so tests poll
    // for the terminal status rather than expecting it synchronously.
    async fn wait_for_status(
        ctrl: &TaskController,
        want: TaskStatus,
        timeout_ms: u64,
    ) -> TaskStatus {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
        loop {
            let got = ctrl.status().await.status;
            if got == want || std::time::Instant::now() >= deadline {
                return got;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn new_controller_is_stopped_and_enabled() {
        let ctrl = TaskController::new("test", ImmediateTask, runtime_config());
        let view = ctrl.status().await;

        assert!(view.enabled);
        assert_eq!(view.status, TaskStatus::Stopped);
    }

    #[tokio::test]
    async fn enable_starts_the_task() {
        let (task, started) = WaitForeverTask::new();
        let ctrl = TaskController::new("test", task, runtime_config());

        let view = ctrl.enable().await;

        assert!(view.enabled);
        assert_eq!(view.status, TaskStatus::Running);

        // Give the spawned task a moment to execute.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(started.load(Ordering::SeqCst), "task should have started");

        // Cleanup
        let view2 = ctrl.disable().await;
        assert_eq!(view2.status, TaskStatus::Stopping);
        assert_eq!(wait_for_status(&ctrl, TaskStatus::Stopped, 2000).await, TaskStatus::Stopped);
    }

    #[tokio::test]
    async fn enable_is_idempotent_when_already_running() {
        let (task, _started) = WaitForeverTask::new();
        let ctrl = TaskController::new("test", task, runtime_config());

        ctrl.enable().await;
        let view = ctrl.enable().await;

        assert!(view.enabled);
        assert_eq!(view.status, TaskStatus::Running);

        ctrl.disable().await;
        assert_eq!(wait_for_status(&ctrl, TaskStatus::Stopped, 2000).await, TaskStatus::Stopped);
    }

    #[tokio::test]
    async fn disable_stops_the_task() {
        let (task, _started) = WaitForeverTask::new();
        let ctrl = TaskController::new("test", task, runtime_config());

        ctrl.enable().await;
        let view = ctrl.disable().await;

        assert!(!view.enabled);
        // disable() reports Stopping synchronously; Stopped follows once joined.
        assert_eq!(view.status, TaskStatus::Stopping);
        assert_eq!(wait_for_status(&ctrl, TaskStatus::Stopped, 2000).await, TaskStatus::Stopped);
    }

    #[tokio::test]
    async fn disable_is_idempotent_when_already_stopped() {
        let ctrl = TaskController::new("test", ImmediateTask, runtime_config());

        let view = ctrl.disable().await;
        assert!(!view.enabled);
        assert_eq!(view.status, TaskStatus::Stopped);
    }

    #[tokio::test]
    async fn disable_delivers_cancellation_signal() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancelled_clone = cancelled.clone();

        struct CancellationProbe {
            flag: Arc<AtomicBool>,
        }

        #[async_trait::async_trait]
        impl ServiceTask for CancellationProbe {
            async fn run(
                &self,
                ctx: CancellationCtx,
                _app_config: Arc<AppConfig>,
            ) -> anyhow::Result<()> {
                let mut rx = ctx.subscribe();
                let _ = rx.changed().await;
                self.flag.store(true, Ordering::SeqCst);
                Ok(())
            }
        }

        let ctrl = TaskController::new(
            "test",
            CancellationProbe { flag: cancelled_clone },
            runtime_config(),
        );
        ctrl.enable().await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        ctrl.disable().await;
        // The task observes cancellation asynchronously; wait for the terminal
        // state, by which point it must have set the flag.
        assert_eq!(wait_for_status(&ctrl, TaskStatus::Stopped, 2000).await, TaskStatus::Stopped);
        assert!(cancelled.load(Ordering::SeqCst), "task should have observed cancellation");
    }

    #[tokio::test]
    async fn restart_cycles_the_task() {
        let (task, count) = CountingTask::new();
        let ctrl = TaskController::new("test", task, runtime_config());

        ctrl.enable().await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(count.load(Ordering::SeqCst), 1);

        let view = ctrl.restart().await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert!(view.enabled);
        assert_eq!(view.status, TaskStatus::Running);
        assert_eq!(count.load(Ordering::SeqCst), 2, "task should have been started twice");

        ctrl.disable().await;
    }

    #[tokio::test]
    async fn failing_task_does_not_panic_controller() {
        let ctrl = TaskController::new("test", FailingTask, runtime_config());

        let view = ctrl.enable().await;
        assert_eq!(view.status, TaskStatus::Running);

        // Let the spawned task complete with its error.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Controller should still be operational; disable should not panic.
        ctrl.disable().await;
        assert_eq!(wait_for_status(&ctrl, TaskStatus::Stopped, 2000).await, TaskStatus::Stopped);
    }

    #[tokio::test]
    async fn status_reflects_enable_disable_cycle() {
        let (task, _) = WaitForeverTask::new();
        let ctrl = TaskController::new("test", task, runtime_config());

        let v1 = ctrl.status().await;
        assert_eq!(v1.status, TaskStatus::Stopped);
        assert!(v1.enabled);

        ctrl.enable().await;
        let v2 = ctrl.status().await;
        assert_eq!(v2.status, TaskStatus::Running);
        assert!(v2.enabled);

        ctrl.disable().await;
        assert_eq!(wait_for_status(&ctrl, TaskStatus::Stopped, 2000).await, TaskStatus::Stopped);
        let v3 = ctrl.status().await;
        assert_eq!(v3.status, TaskStatus::Stopped);
        assert!(!v3.enabled);
    }

    #[tokio::test]
    async fn task_status_as_str() {
        assert_eq!(TaskStatus::Running.as_str(), "running");
        assert_eq!(TaskStatus::Stopping.as_str(), "stopping");
        assert_eq!(TaskStatus::Stopped.as_str(), "stopped");
    }

    // ── task! macro tests ───────────────────────────────────────────

    async fn dummy_run(
        _ctx: CancellationCtx,
        _app_config: Arc<AppConfig>,
        value: Arc<AtomicU32>,
        label: String,
    ) -> anyhow::Result<()> {
        value.fetch_add(1, Ordering::SeqCst);
        assert_eq!(label, "hello");
        Ok(())
    }

    crate::task!(DummyMacroTask, crate::task::task_manager::tests::dummy_run {
        value: Arc<AtomicU32>,
        label: String,
    });

    #[tokio::test]
    async fn macro_creates_struct_with_new() {
        let v = Arc::new(AtomicU32::new(0));
        let _task = DummyMacroTask::new(v, "hello".into());
    }

    #[tokio::test]
    async fn macro_task_implements_service_task() {
        let v = Arc::new(AtomicU32::new(0));
        let task = DummyMacroTask::new(v.clone(), "hello".into());

        let ctx = CancellationCtx::new();
        let runtime_cfg = runtime_config();
        task.run(ctx, runtime_cfg.get()).await.expect("task should succeed");

        assert_eq!(v.load(Ordering::SeqCst), 1, "run function should have been called");
    }

    #[tokio::test]
    async fn macro_task_clones_fields() {
        let v = Arc::new(AtomicU32::new(0));
        let task = DummyMacroTask::new(v.clone(), "hello".into());

        // Run twice to confirm fields are cloned each time (not moved).
        let ctx1 = CancellationCtx::new();
        let runtime_cfg = runtime_config();
        task.run(ctx1, runtime_cfg.get()).await.unwrap();
        let ctx2 = CancellationCtx::new();
        task.run(ctx2, runtime_cfg.get()).await.unwrap();

        assert_eq!(v.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn macro_task_works_with_controller() {
        let v = Arc::new(AtomicU32::new(0));
        let task = DummyMacroTask::new(v.clone(), "hello".into());
        let ctrl = TaskController::new("macro-test", task, runtime_config());

        ctrl.enable().await;
        // The dummy function completes immediately, give it a moment.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert_eq!(v.load(Ordering::SeqCst), 1);

        ctrl.disable().await;
        assert_eq!(wait_for_status(&ctrl, TaskStatus::Stopped, 2000).await, TaskStatus::Stopped);
    }

    async fn no_fields_run(
        _ctx: CancellationCtx,
        _app_config: Arc<AppConfig>,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    crate::task!(NoFieldsTask, crate::task::task_manager::tests::no_fields_run {});

    #[tokio::test]
    async fn macro_task_with_no_fields() {
        let task = NoFieldsTask::new();
        let ctx = CancellationCtx::new();
        let app_config = runtime_config().get();
        task.run(ctx, app_config).await.expect("zero-field task should work");
    }

    // disable() reports Stopping synchronously and never Running; a detached
    // finalizer drives Stopping -> Stopped once the task actually exits,
    // independent of the disable() future's lifetime. (Pre-fix disable() set
    // Stopped only after a cancellable join, so a dropped future stranded
    // Running; a version that set Stopped synchronously reported the task
    // stopped while it was still running.)
    #[tokio::test]
    async fn disable_enters_stopping_then_reaches_stopped_via_finalizer() {
        let (task, runs, _completed) = SlowToStopTask::new();
        let ctrl = TaskController::new("test", task, runtime_config());

        assert_eq!(ctrl.enable().await.status, TaskStatus::Running);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(runs.load(Ordering::SeqCst), 1, "task should have started once");

        // Synchronous result is Stopping -- not Stopped (task still exiting),
        // and not Running.
        assert_eq!(ctrl.disable().await.status, TaskStatus::Stopping);
        assert_eq!(ctrl.status().await.status, TaskStatus::Stopping);

        // The detached finalizer joins the task (it takes 500ms to exit) and then
        // flips to Stopped. With no finalizer this would stay Stopping forever.
        assert_eq!(wait_for_status(&ctrl, TaskStatus::Stopped, 3000).await, TaskStatus::Stopped);
    }

    // enable() while a previous generation is still Stopping must force-stop that
    // generation before starting a new one, never leave two running. The
    // superseded generation is aborted mid-exit, so it never reaches its
    // completion marker; removing the abort in enable() lets it run to
    // completion, failing this test.
    #[tokio::test]
    async fn enable_during_stopping_aborts_the_superseded_generation() {
        let (task, runs, completed) = SlowToStopTask::new();
        let ctrl = TaskController::new("test", task, runtime_config());

        assert_eq!(ctrl.enable().await.status, TaskStatus::Running);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(runs.load(Ordering::SeqCst), 1);

        // Signal stop; generation 1 is now Stopping and, left alone, would finish
        // its 500ms exit and hit the completion marker.
        assert_eq!(ctrl.disable().await.status, TaskStatus::Stopping);

        // Enable while Stopping: must abort generation 1 and start generation 2.
        assert_eq!(ctrl.enable().await.status, TaskStatus::Running);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(runs.load(Ordering::SeqCst), 2, "a fresh generation must have started");

        // Well past generation 1's 500ms natural-completion point: it was aborted
        // mid-exit, so it never completed, and generation 2 is still parked on
        // cancellation (not disabled), so it has not completed either.
        tokio::time::sleep(std::time::Duration::from_millis(700)).await;
        assert_eq!(
            completed.load(Ordering::SeqCst),
            0,
            "the superseded generation must have been aborted, not run to completion"
        );

        ctrl.disable().await;
    }
}
