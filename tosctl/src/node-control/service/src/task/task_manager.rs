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
    // Identifies the current task instance. Bumped whenever a new generation is
    // started, so a finalizer joining an older generation cannot clobber a newer
    // state.
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
                generation: 0,
            })),
            runtime_cfg,
        }
    }

    pub async fn status(&self) -> TaskStateView {
        let st = self.state.lock().expect("failed to lock state");
        TaskStateView { enabled: st.enabled, status: st.status, updated_at: st.updated_at }
    }

    // Spawn a fresh task generation and record it as Running. Takes the pieces
    // rather than &self so both enable() and the detached finalizer (which owns
    // clones) can call it.
    fn start_generation(
        st: &mut State,
        task: &Arc<dyn ServiceTask>,
        runtime_cfg: &Arc<dyn RuntimeConfig>,
        name: &'static str,
    ) {
        let cancel_ctx = CancellationCtx::new();
        let ctx = cancel_ctx.clone();
        let app_config = runtime_cfg.get();
        let task = task.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) = task.run(ctx, app_config).await {
                tracing::error!("{} task error: {:#}", name, e);
            }
        });
        st.generation = st.generation.wrapping_add(1);
        st.cancel = Some(cancel_ctx);
        st.handle = Some(handle);
        st.status = TaskStatus::Running;
        st.updated_at = UnixTime::now();
    }

    pub async fn enable(&self) -> TaskStateView {
        let mut st = self.state.lock().expect("failed to lock state");
        st.enabled = true;

        match st.status {
            TaskStatus::Running => {
                st.updated_at = UnixTime::now();
            }
            TaskStatus::Stopping => {
                // A finalizer is joining the previous generation. Because enabled
                // is now true, it will start a fresh generation once that one
                // actually exits. Do NOT spawn here: abort()/cancellation only
                // signals stop, it is not a barrier that the old generation has
                // ended, so starting now could run two generations at once.
                st.updated_at = UnixTime::now();
            }
            TaskStatus::Stopped => {
                tracing::debug!("starting {} task...", self.name);
                Self::start_generation(&mut st, &self.task, &self.runtime_cfg, self.name);
                tracing::info!("{} task started", self.name);
            }
        }

        TaskStateView { enabled: st.enabled, status: st.status, updated_at: st.updated_at }
    }

    pub async fn disable(&self) -> TaskStateView {
        let (view, finalizer) = {
            let mut st = self.state.lock().expect("failed to lock state");
            st.enabled = false;

            match st.status {
                // Stopped: nothing running. Stopping: a finalizer is already
                // joining the generation; enabled=false now means it will settle
                // to Stopped rather than restart. Either way, no new finalizer.
                TaskStatus::Stopped | TaskStatus::Stopping => {
                    st.updated_at = UnixTime::now();
                    return TaskStateView {
                        enabled: st.enabled,
                        status: st.status,
                        updated_at: st.updated_at,
                    };
                }
                TaskStatus::Running => {
                    tracing::debug!("stopping {} task...", self.name);
                    if let Some(mut ctx) = st.cancel.take() {
                        ctx.cancel(CancellationReason::GracefullyShutdown());
                    } else {
                        tracing::warn!(
                            "{} task marked running but no cancellation ctx present",
                            self.name
                        );
                    }
                    // Enter Stopping synchronously. The task is signalled but not
                    // yet joined, so it is reported Stopping, never Stopped. The
                    // handle moves to a detached finalizer.
                    let handle = st.handle.take();
                    st.status = TaskStatus::Stopping;
                    st.updated_at = UnixTime::now();
                    let view = TaskStateView {
                        enabled: st.enabled,
                        status: st.status,
                        updated_at: st.updated_at,
                    };
                    (view, handle.map(|h| (h, st.generation)))
                }
            }
        };

        // The finalizer waits for the OLD generation's JoinHandle to actually
        // complete -- the real barrier that it has ended, which cancellation
        // alone does not provide -- and only then either starts the next
        // generation (if re-enabled meanwhile) or settles to Stopped. Two
        // generations therefore never run at once. Detached, so a dropped
        // (HTTP-request) future cannot strand the transition.
        if let Some((handle, generation)) = finalizer {
            let state = self.state.clone();
            let task = self.task.clone();
            let runtime_cfg = self.runtime_cfg.clone();
            let name = self.name;
            tokio::spawn(async move {
                let _ = handle.await;
                let mut st = state.lock().expect("failed to lock state");
                if st.generation != generation {
                    // A newer generation already owns the state; nothing to do.
                    return;
                }
                if st.enabled {
                    TaskController::start_generation(&mut st, &task, &runtime_cfg, name);
                    tracing::info!("{} task restarted after stop", name);
                } else {
                    st.cancel = None;
                    st.handle = None;
                    st.status = TaskStatus::Stopped;
                    st.updated_at = UnixTime::now();
                    tracing::info!("{} task stopped", name);
                }
            });
        }
        view
    }

    /// Block until the task has actually reached `Stopped` — its detached
    /// finalizer has joined the task's `JoinHandle` and run its cleanup to
    /// completion — or until `max_wait` elapses. Returns `true` if it stopped,
    /// `false` on timeout.
    ///
    /// `disable()` only *requests* a stop and arms a detached finalizer; it
    /// returns while that finalizer is still joining the task. Process-level
    /// shutdown uses this as the barrier that the cleanup has finished before
    /// the Tokio runtime is torn down (runtime shutdown does not run detached
    /// tasks to completion, so without this barrier in-flight cleanup is
    /// dropped). It does not itself request a stop; call `disable()` first.
    pub async fn wait_stopped(&self, max_wait: std::time::Duration) -> bool {
        let deadline = tokio::time::Instant::now() + max_wait;
        loop {
            {
                let st = self.state.lock().expect("failed to lock state");
                if matches!(st.status, TaskStatus::Stopped) {
                    return true;
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    pub async fn restart(&self) -> TaskStateView {
        // disable() enters Stopping and arms the finalizer; enable() marks the
        // controller enabled again. When the old generation actually exits, the
        // finalizer starts the new one. The result is reported Stopping and
        // becomes Running once the restart completes -- no overlap with the old
        // generation.
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
    // Tracks how many generations are simultaneously inside run() (via an RAII
    // guard) and lingers after observing cancellation, widening any window in
    // which a superseding generation could start before this one has exited.
    struct ActiveGuard {
        active: Arc<AtomicU32>,
    }

    impl ActiveGuard {
        fn enter(active: &Arc<AtomicU32>, max_active: &Arc<AtomicU32>) -> Self {
            let now = active.fetch_add(1, Ordering::SeqCst) + 1;
            max_active.fetch_max(now, Ordering::SeqCst);
            Self { active: active.clone() }
        }
    }

    impl Drop for ActiveGuard {
        fn drop(&mut self) {
            self.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    struct ConcurrencyTask {
        runs: Arc<AtomicU32>,
        active: Arc<AtomicU32>,
        max_active: Arc<AtomicU32>,
        linger_ms: u64,
    }

    impl ConcurrencyTask {
        fn new(linger_ms: u64) -> (Self, Arc<AtomicU32>, Arc<AtomicU32>, Arc<AtomicU32>) {
            let runs = Arc::new(AtomicU32::new(0));
            let active = Arc::new(AtomicU32::new(0));
            let max_active = Arc::new(AtomicU32::new(0));
            (
                Self {
                    runs: runs.clone(),
                    active: active.clone(),
                    max_active: max_active.clone(),
                    linger_ms,
                },
                runs,
                active,
                max_active,
            )
        }
    }

    #[async_trait::async_trait]
    impl ServiceTask for ConcurrencyTask {
        async fn run(
            &self,
            ctx: CancellationCtx,
            _app_config: Arc<AppConfig>,
        ) -> anyhow::Result<()> {
            self.runs.fetch_add(1, Ordering::SeqCst);
            let _guard = ActiveGuard::enter(&self.active, &self.max_active);
            let mut rx = ctx.subscribe();
            let _ = rx.changed().await;
            // Observed cancellation, but take a while to actually exit; the guard
            // (and thus the active count) is not released until this returns.
            if self.linger_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(self.linger_ms)).await;
            }
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

        // restart() reports Stopping and becomes Running once the old generation
        // has exited and the finalizer starts the new one.
        let view = ctrl.restart().await;
        assert!(view.enabled);
        assert_eq!(wait_for_status(&ctrl, TaskStatus::Running, 2000).await, TaskStatus::Running);
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
        let (task, runs, _active, _max) = ConcurrencyTask::new(200);
        let ctrl = TaskController::new("test", task, runtime_config());

        assert_eq!(ctrl.enable().await.status, TaskStatus::Running);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(runs.load(Ordering::SeqCst), 1, "task should have started once");

        // Synchronous result is Stopping -- not Stopped (task still exiting),
        // and not Running.
        assert_eq!(ctrl.disable().await.status, TaskStatus::Stopping);
        assert_eq!(ctrl.status().await.status, TaskStatus::Stopping);

        // The detached finalizer joins the task (it lingers before exiting) and
        // then flips to Stopped. With no finalizer this would stay Stopping.
        assert_eq!(wait_for_status(&ctrl, TaskStatus::Stopped, 3000).await, TaskStatus::Stopped);
    }

    // A restart must never run two generations at once: the new generation starts
    // only after the old one's JoinHandle has actually completed, not merely after
    // abort()/cancellation is signalled. The task lingers after cancellation, so a
    // version that aborts-then-immediately-spawns would briefly have two live and
    // drive max_active to 2.
    #[tokio::test]
    async fn restart_never_runs_two_generations_concurrently() {
        let (task, runs, _active, max_active) = ConcurrencyTask::new(200);
        let ctrl = TaskController::new("test", task, runtime_config());

        assert_eq!(ctrl.enable().await.status, TaskStatus::Running);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert_eq!(max_active.load(Ordering::SeqCst), 1);

        // restart() -> Stopping; the finalizer waits for generation 1 to exit
        // (200ms linger) and only then starts generation 2.
        assert_eq!(ctrl.restart().await.status, TaskStatus::Stopping);
        assert_eq!(wait_for_status(&ctrl, TaskStatus::Running, 3000).await, TaskStatus::Running);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(runs.load(Ordering::SeqCst), 2, "a fresh generation must have started");

        // The overlap invariant: at no point were two generations inside run().
        assert_eq!(
            max_active.load(Ordering::SeqCst),
            1,
            "the old generation must have fully exited before the new one started"
        );

        ctrl.disable().await;
    }

    /// A task whose cleanup, run after cancellation, takes observable time. It
    /// sets `cleanup_done` only once that cleanup has finished, which mirrors a
    /// real task flushing state on shutdown.
    struct SlowCleanupTask {
        cleanup_done: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl ServiceTask for SlowCleanupTask {
        async fn run(
            &self,
            ctx: CancellationCtx,
            _app_config: Arc<AppConfig>,
        ) -> anyhow::Result<()> {
            let mut rx = ctx.subscribe();
            let _ = rx.changed().await;
            // Cleanup that takes time: the finalizer only joins (and the status
            // only settles to Stopped) once this has finished.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            self.cleanup_done.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    // The shutdown barrier must not return until a task's post-cancellation
    // cleanup has actually finished; otherwise a process exit that relies on it
    // would let the runtime drop the in-flight finalizer.
    #[tokio::test]
    async fn wait_stopped_blocks_until_cleanup_finishes() {
        let cleanup_done = Arc::new(AtomicBool::new(false));
        let ctrl = TaskController::new(
            "test",
            SlowCleanupTask { cleanup_done: cleanup_done.clone() },
            runtime_config(),
        );

        ctrl.enable().await;
        assert_eq!(wait_for_status(&ctrl, TaskStatus::Running, 2000).await, TaskStatus::Running);

        // disable() returns immediately, while cleanup is still running.
        let view = ctrl.disable().await;
        assert_eq!(view.status, TaskStatus::Stopping);
        assert!(
            !cleanup_done.load(Ordering::SeqCst),
            "cleanup should still be in progress right after disable()"
        );

        // The barrier blocks until the finalizer settles to Stopped, which only
        // happens after the slow cleanup completes.
        assert!(
            ctrl.wait_stopped(std::time::Duration::from_secs(2)).await,
            "task should reach Stopped within grace"
        );
        assert!(
            cleanup_done.load(Ordering::SeqCst),
            "wait_stopped returned before cleanup finished"
        );
        assert_eq!(ctrl.status().await.status, TaskStatus::Stopped);
    }

    // A task that never stops must make the barrier report a timeout (so the
    // caller can log and move on) rather than block forever.
    #[tokio::test]
    async fn wait_stopped_times_out_on_a_stuck_task() {
        struct StuckOnCancelTask;

        #[async_trait::async_trait]
        impl ServiceTask for StuckOnCancelTask {
            async fn run(
                &self,
                _ctx: CancellationCtx,
                _app_config: Arc<AppConfig>,
            ) -> anyhow::Result<()> {
                // Ignores cancellation entirely.
                std::future::pending::<()>().await;
                Ok(())
            }
        }

        let ctrl = TaskController::new("test", StuckOnCancelTask, runtime_config());
        ctrl.enable().await;
        assert_eq!(wait_for_status(&ctrl, TaskStatus::Running, 2000).await, TaskStatus::Running);
        ctrl.disable().await;
        assert!(
            !ctrl.wait_stopped(std::time::Duration::from_millis(200)).await,
            "stuck task must time out"
        );
    }
}
