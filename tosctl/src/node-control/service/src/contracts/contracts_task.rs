/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::runtime_config::RuntimeConfig;
use anyhow::Context;
use chain_block::{Cell, MsgAddressInt, write_boc};
use chain_rpc_client::v2::data_models::AccountState;
use common::{app_config::AppConfig, snapshot::SnapshotStore, task_cancellation::CancellationCtx};
use contracts::{ChainProvider, NominatorWrapper, Wallet};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};

/// Minimal required balance for the master wallet before it can be deployed.
/// Note: 0.1 TOS to cover the gas cost of the deploy transaction.
const DEPLOY_AMOUNT: u64 = 1_100_000_000; // 1.1 TOS
/// Minimal required balance for a wallet before it will be topped up.
const MIN_WALLET_BALANCE: u64 = 5_000_000_000; // 5 TOS
/// Gas cost for sending message from a wallet.
const WALLET_GAS: u64 = 100_000_000; // 0.1 TOS
/// Amount to top up a wallet if its balance is below the minimum threshold.
const TOP_UP_AMOUNT: u64 = 10_000_000_000; // 10 TOS
// The constants above must leave room for the gas on top of each payment; a
// change that breaks this fails the build instead of reaching the checks below.
const _: () = assert!(DEPLOY_AMOUNT.checked_add(WALLET_GAS).is_some());
const _: () = assert!(TOP_UP_AMOUNT.checked_add(WALLET_GAS).is_some());

/// The balance the master wallet needs to send `amount` to one wallet: the
/// amount plus the gas of the sending message. An overflow is an error, never
/// a clamped or wrapped requirement.
fn required_balance(amount: u64, gas: u64) -> anyhow::Result<u64> {
    amount.checked_add(gas).ok_or_else(|| {
        anyhow::anyhow!("balance requirement overflows u64: amount={} gas={}", amount, gas)
    })
}

/// The balance the master wallet needs to deploy one wallet or pool.
fn deploy_required() -> anyhow::Result<u64> {
    required_balance(DEPLOY_AMOUNT, WALLET_GAS)
}

/// The balance the master wallet needs to top up one wallet.
fn top_up_required() -> anyhow::Result<u64> {
    required_balance(TOP_UP_AMOUNT, WALLET_GAS)
}

pub(crate) async fn run(
    cancellation_ctx: CancellationCtx,
    app_config: Arc<AppConfig>,
    runtime_cfg: Arc<dyn RuntimeConfig>,
    store: Arc<SnapshotStore>,
) -> anyhow::Result<()> {
    let master_wallet = runtime_cfg.master_wallet();
    let pools = runtime_cfg.pools();
    let wallets = runtime_cfg.wallets();
    let chain_provider = runtime_cfg.chain_provider();
    let monitor = ContractsMonitor {
        master_wallet,
        pools,
        wallets,
        chain_provider,
        _store: store,
        standby: Mutex::new(None),
    };
    monitor.run_loop(cancellation_ctx, app_config.tick_interval).await
}

/// A condition the task waits out rather than fails on: nothing is wrong with
/// the node, but the master wallet cannot do the optional work it is for until
/// an operator funds it. It is reported when entered and when it changes, not
/// on every tick.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Standby {
    /// The master wallet is not deployed and holds too little to deploy itself.
    MasterUnfunded { balance: u64 },
    /// A wallet is below its minimum balance and the master wallet cannot top it up.
    TopUpUnaffordable { wallet: String, master_balance: u64, required: u64 },
}

struct ContractsMonitor {
    master_wallet: Arc<dyn Wallet>,
    pools: Arc<HashMap<String, Arc<dyn NominatorWrapper>>>,
    wallets: Arc<HashMap<String, Arc<dyn Wallet>>>,
    chain_provider: Arc<dyn ChainProvider>,
    _store: Arc<SnapshotStore>,
    /// The standby condition last reported, if the task is in one.
    standby: Mutex<Option<Standby>>,
}

impl ContractsMonitor {
    /// Records `condition` and warns about it unless it is the one already
    /// reported. Returns whether it was reported.
    fn enter_standby(&self, condition: Standby) -> bool {
        let mut standby = self.standby.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if standby.as_ref() == Some(&condition) {
            return false;
        }
        match &condition {
            Standby::MasterUnfunded { balance } => tracing::warn!(
                target: "contracts",
                "master wallet {} is not deployed and holds {:.4} TOS, below the {:.4} TOS it \
                 needs to deploy itself; fund it to let the service deploy and top up wallets",
                self.master_wallet.address(),
                *balance as f64 / 1e9,
                DEPLOY_AMOUNT as f64 / 1e9,
            ),
            Standby::TopUpUnaffordable { wallet, master_balance, required } => tracing::warn!(
                target: "contracts",
                "wallet {} is below {:.4} TOS, but the master wallet holds {:.4} TOS, below the \
                 {:.4} TOS a top-up needs; fund the master wallet or the wallet directly",
                wallet,
                MIN_WALLET_BALANCE as f64 / 1e9,
                *master_balance as f64 / 1e9,
                *required as f64 / 1e9,
            ),
        }
        *standby = Some(condition);
        true
    }

    /// Clears the standby condition, noting that it ended if there was one.
    fn leave_standby(&self) {
        let mut standby = self.standby.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(condition) = standby.take() {
            tracing::info!(target: "contracts", "no longer waiting: {:?}", condition);
        }
    }

    async fn run_loop(
        &self,
        cancellation_ctx: CancellationCtx,
        tick_interval: u64,
    ) -> anyhow::Result<()> {
        let tick_interval = Duration::from_secs(tick_interval);
        let mut cancel = cancellation_ctx.subscribe();
        let mut interval = tokio::time::interval(tick_interval);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    tracing::info!(target: "contracts", "TICK");
                    if let Err(e) = self.run().await {
                        tracing::error!(target: "contracts", "run error: {:#}", e);
                    }
                    tracing::info!(target: "contracts", "SLEEP");
                }
                _ = cancel.changed() => {
                    tracing::info!(target: "contracts", "cancel received");
                    return Ok(());
                }
            }
        }
    }

    async fn run(&self) -> anyhow::Result<()> {
        if !self.ensure_master_deployed().await? {
            return Ok(());
        }
        let mut seqno = self
            .chain_provider
            .run_get_method(self.master_wallet.address().to_string(), "seqno", vec![])
            .await?
            .i64(0)?;
        if !self.ensure_wallets_deployed(&mut seqno).await? {
            return Ok(());
        }
        if !self.ensure_pools_deployed(&mut seqno).await? {
            return Ok(());
        }
        if !self.ensure_wallet_balances(&mut seqno).await? {
            return Ok(());
        }
        self.leave_standby();
        tracing::info!(target: "contracts", "all contracts are ready");
        Ok(())
    }

    async fn account_info(&self, address: &MsgAddressInt) -> anyhow::Result<(AccountState, u64)> {
        let info =
            self.chain_provider.get_address_info(address).await.context("get_address_info")?;
        Ok((info.state, info.balance))
    }

    async fn broadcast(&self, cell: &Cell) -> anyhow::Result<()> {
        let boc = write_boc(cell).context("write_boc")?;
        self.chain_provider.send_boc(&boc).await
    }

    fn insufficient_master_balance_error(balance: u64, required: u64) -> anyhow::Error {
        anyhow::anyhow!(
            "master wallet balance is low: balance={:.4} TOS need={:.4} TOS",
            balance as f64 / 1e9,
            required as f64 / 1e9,
        )
    }

    /// Step 1: Deploy master wallet if uninitialized.
    /// Returns `true` when master is active and ready for subsequent steps.
    /// Returns an error if master is frozen. A master wallet too poor to deploy
    /// itself is a standby condition, not an error: nothing else needs it.
    async fn ensure_master_deployed(&self) -> anyhow::Result<bool> {
        let addr = self.master_wallet.address();
        let (state, balance) = self.account_info(&addr).await.context("get master wallet state")?;

        match state {
            AccountState::Active => return Ok(true),
            AccountState::Frozen => {
                anyhow::bail!("master wallet is frozen: address={}", addr);
            }
            AccountState::Uninitialized => {}
        }

        if balance < DEPLOY_AMOUNT {
            self.enter_standby(Standby::MasterUnfunded { balance });
            return Ok(false);
        }
        self.leave_standby();

        tracing::info!(
            target: "contracts",
            "deploy master wallet: address={}, balance={} TOS",
            addr,
            balance as f64 / 1e9,
        );
        let msg = self
            .master_wallet
            .deploy_message(0, Cell::default())
            .await
            .context("build master wallet deploy message")?;
        self.broadcast(&msg).await.context("send master wallet deploy")?;
        Ok(false)
    }

    /// Step 2: Deploy uninitialized wallets through the master wallet.
    ///
    /// The master wallet sends an internal message carrying the wallet's
    /// state_init and `DEPLOY_AMOUNT` TOS, deploying and funding it in one go.
    ///
    /// Returns `false` if master balance is insufficient (caller should sleep).
    async fn ensure_wallets_deployed(&self, seqno: &mut i64) -> anyhow::Result<bool> {
        let mut all_deployed = true;
        let mut processed_wallets = HashSet::new();

        for (node_id, wallet) in self.wallets.iter() {
            let wallet_addr = wallet.address();
            let is_new = processed_wallets.insert(wallet_addr.clone());
            if !is_new {
                tracing::debug!(
                    target: "contracts",
                    "[{}] skipping wallet deploy: address {} already processed",
                    node_id,
                    wallet_addr
                );
                continue;
            }

            match self.deploy_wallet(node_id, wallet.clone(), *seqno).await {
                Ok(true) => (),
                Ok(false) => {
                    all_deployed = false;
                    *seqno += 1;
                }
                Err(e) => {
                    all_deployed = false;
                    tracing::error!(target: "contracts", "[{}] deploy wallet error: {:#}", node_id, e);
                }
            };
        }
        Ok(all_deployed)
    }

    async fn deploy_wallet(
        &self,
        node_id: &str,
        wallet: Arc<dyn Wallet>,
        seqno: i64,
    ) -> anyhow::Result<bool> {
        let addr = wallet.address();
        let (state, balance) = self.account_info(&addr).await.context("wallet state")?;

        match state {
            AccountState::Active => return Ok(true),
            AccountState::Frozen => {
                anyhow::bail!("wallet is frozen: address={}", addr);
            }
            AccountState::Uninitialized => {}
        };

        tracing::info!(
            target: "contracts",
            "[{}] wallet is uninitialized: address={} balance={:.4} TOS",
            node_id, addr, balance as f64 / 1e9,
        );

        let master_balance = self.master_wallet.balance().await.context("master wallet balance")?;
        let required = deploy_required()?;
        if master_balance < required {
            return Err(Self::insufficient_master_balance_error(master_balance, required));
        }

        let si = wallet.state_init().await?;

        tracing::info!(
            target: "contracts",
            "[{}] deploy wallet: amount={:.4} TOS",
            node_id, DEPLOY_AMOUNT as f64 / 1e9,
        );
        let msg = self
            .master_wallet
            .build_message(
                addr,
                DEPLOY_AMOUNT,
                Cell::default(),
                false,
                Some(u32::try_from(seqno)?),
                None,
                Some(si),
            )
            .await?;
        self.broadcast(&msg).await?;
        Ok(false)
    }

    /// Step 3: Deploy uninitialized nominator pools through the master wallet.
    ///
    /// If a pool has a `state_init`, it is deployed in a single message (funds + code).
    /// Otherwise only funds are sent and a warning is logged.
    ///
    /// Returns `false` if master balance is insufficient (caller should sleep).
    async fn ensure_pools_deployed(&self, seqno: &mut i64) -> anyhow::Result<bool> {
        let mut all_deployed = true;
        for (node_id, pool) in self.pools.iter() {
            match self.deploy_pool(node_id, pool.clone(), *seqno).await {
                Ok(true) => (),
                Ok(false) => {
                    all_deployed = false;
                    *seqno += 1;
                }
                Err(e) => {
                    all_deployed = false;
                    tracing::error!(target: "contracts", "[{}] deploy pool error: {:#}", node_id, e);
                }
            };
        }
        Ok(all_deployed)
    }

    async fn deploy_pool(
        &self,
        node_id: &str,
        pool: Arc<dyn NominatorWrapper>,
        seqno: i64,
    ) -> anyhow::Result<bool> {
        let pool_addr = pool.address();
        let (state, _) = self.account_info(&pool_addr).await.context("get pool state")?;

        match state {
            AccountState::Active => return Ok(true),
            AccountState::Frozen => {
                anyhow::bail!("pool is frozen: address={}", pool_addr);
            }
            AccountState::Uninitialized => {}
        };

        tracing::info!(
            target: "contracts",
            "[{}] pool is uninitialized: address={}",
            node_id, pool_addr,
        );

        let master_balance =
            self.master_wallet.balance().await.context("get master wallet balance")?;
        let required = deploy_required()?;
        if master_balance < required {
            return Err(Self::insufficient_master_balance_error(master_balance, required));
        }

        if pool.state_init().is_none() {
            tracing::warn!(target: "contracts", "[{}] pool has no state_init configured, sending funds only", node_id);
        }

        tracing::info!(target: "contracts", "[{}] deploy pool: amount={:.4} TOS",
                node_id, DEPLOY_AMOUNT as f64 / 1e9);
        let msg = self
            .master_wallet
            .build_message(
                pool_addr,
                DEPLOY_AMOUNT,
                Cell::default(),
                false,
                Some(u32::try_from(seqno)?),
                None,
                pool.state_init(),
            )
            .await?;

        self.broadcast(&msg).await?;
        Ok(false)
    }

    /// Step 4: Top up active wallets whose balance is below the minimum threshold.
    async fn ensure_wallet_balances(&self, seqno: &mut i64) -> anyhow::Result<bool> {
        let mut all_topped_up = true;
        let mut processed_wallets = HashSet::new();
        for (node_id, wallet) in self.wallets.iter() {
            let addr = wallet.address();
            let is_new = processed_wallets.insert(addr.clone());
            if !is_new {
                tracing::debug!(
                    target: "contracts",
                    "[{}] skipping wallet top-up: address {} already processed",
                    node_id,
                    addr
                );
                continue;
            }

            let (state, balance) = match self.account_info(&addr).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(target: "contracts", "[{}] get wallet info error: {:#}", node_id, e);
                    continue;
                }
            };

            if state != AccountState::Active {
                continue;
            }

            if balance >= MIN_WALLET_BALANCE {
                continue;
            }

            all_topped_up = false;

            // A top-up is a convenience: the wallet may be funded some other
            // way, so a master wallet that cannot afford one is waited out.
            let master_balance =
                self.master_wallet.balance().await.context("get master wallet balance")?;
            let required = top_up_required()?;
            if master_balance < required {
                let wallet = addr.to_string();
                self.enter_standby(Standby::TopUpUnaffordable { wallet, master_balance, required });
                return Ok(false);
            }
            self.leave_standby();

            tracing::info!(
                target: "contracts",
                "[{}] top-up wallet: address={} current_balance={:.4} TOS topup_amount={:.4} TOS",
                node_id, addr, balance as f64 / 1e9, TOP_UP_AMOUNT as f64 / 1e9,
            );

            match self
                .master_wallet
                .build_message(
                    addr,
                    TOP_UP_AMOUNT,
                    Cell::default(),
                    false,
                    Some(u32::try_from(*seqno)?),
                    None,
                    None,
                )
                .await
            {
                Ok(msg) => {
                    if let Err(e) = self.broadcast(&msg).await {
                        tracing::error!(target: "contracts", "[{}] send top-up error: {:#}", node_id, e);
                    }
                    *seqno += 1;
                }
                Err(e) => {
                    tracing::error!(target: "contracts", "[{}] build top-up message error: {:#}", node_id, e);
                }
            }
        }
        Ok(all_topped_up)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ContractsMonitor, DEPLOY_AMOUNT, Standby, TOP_UP_AMOUNT, WALLET_GAS, deploy_required,
        required_balance, top_up_required,
    };
    use axum::{Json, Router, extract::State, routing::post};
    use chain_block::{Cell, MsgAddressInt, StateInit};
    use chain_rpc_client::v2::client_json_rpc::ClientJsonRpc;
    use common::snapshot::SnapshotStore;
    use contracts::DefaultChainProvider;
    use contracts::{ChainProvider, NominatorWrapper, SmartContract, Wallet};
    use std::{
        collections::HashMap,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    #[derive(Clone)]
    struct MockRpcState {
        account_state: &'static str,
        account_balance: u64,
        send_boc_calls: Arc<AtomicUsize>,
    }

    struct MockRpcServer {
        url: String,
        send_boc_calls: Arc<AtomicUsize>,
        shutdown_tx: tokio::sync::oneshot::Sender<()>,
        join: tokio::task::JoinHandle<()>,
    }

    impl MockRpcServer {
        async fn start(account_state: &'static str, account_balance: u64) -> Self {
            let send_boc_calls = Arc::new(AtomicUsize::new(0));
            let state = MockRpcState {
                account_state,
                account_balance,
                send_boc_calls: send_boc_calls.clone(),
            };
            let app = Router::new().route("/jsonRPC", post(mock_jsonrpc)).with_state(state);

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
            let join = tokio::spawn(async move {
                axum::serve(listener, app)
                    .with_graceful_shutdown(async move {
                        let _ = shutdown_rx.await;
                    })
                    .await
                    .unwrap();
            });

            Self { url: format!("http://{addr}/"), send_boc_calls, shutdown_tx, join }
        }

        async fn shutdown(self) {
            let _ = self.shutdown_tx.send(());
            let _ = self.join.await;
        }
    }

    async fn mock_jsonrpc(
        State(state): State<MockRpcState>,
        Json(request): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        let method = request.get("method").and_then(|m| m.as_str()).unwrap_or_default();
        let id = request.get("id").cloned().unwrap_or_else(|| serde_json::json!("1"));

        let response = match method {
            "getAddressInformation" => serde_json::json!({
                "result": {
                    "@type": "raw.fullAccountState",
                    "balance": state.account_balance,
                    "extra_currencies": [],
                    "code": "",
                    "data": "",
                    "last_transaction_id": {
                        "@type": "internal.transactionId",
                        "lt": "0",
                        "hash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                    },
                    "block_id": {
                        "@type": "tos.blockIdExt",
                        "workchain": -1,
                        "shard": "-9223372036854775808",
                        "seqno": 1,
                        "root_hash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                        "file_hash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                    },
                    "frozen_hash": "",
                    "sync_utime": 0,
                    "state": state.account_state
                },
                "jsonrpc": "2.0",
                "id": id
            }),
            "sendBoc" => {
                state.send_boc_calls.fetch_add(1, Ordering::Relaxed);
                serde_json::json!({
                    "result": { "@type": "ok" },
                    "jsonrpc": "2.0",
                    "id": id
                })
            }
            _ => serde_json::json!({
                "error": {
                    "code": -32601,
                    "message": format!("Method not found: {method}"),
                    "data": {"schema_version": 1, "reason": "METHOD_NOT_FOUND", "retryable": false}
                },
                "jsonrpc": "2.0",
                "id": id
            }),
        };

        Json(response)
    }

    #[derive(Clone)]
    struct DummyWallet {
        addr: MsgAddressInt,
        state_init: Option<StateInit>,
        balance: u64,
    }

    impl DummyWallet {
        fn rich(byte: u8) -> Self {
            Self { addr: addr(byte), state_init: Some(StateInit::default()), balance: u64::MAX }
        }
    }

    #[async_trait::async_trait]
    impl SmartContract for DummyWallet {
        async fn balance(&self) -> anyhow::Result<u64> {
            Ok(self.balance)
        }

        fn address(&self) -> MsgAddressInt {
            self.addr.clone()
        }
    }

    #[async_trait::async_trait]
    impl Wallet for DummyWallet {
        async fn message(
            &self,
            _dest: MsgAddressInt,
            _value: u64,
            _payload: Cell,
        ) -> anyhow::Result<Cell> {
            Ok(Cell::default())
        }

        async fn deploy_message(&self, _value: u64, _payload: Cell) -> anyhow::Result<Cell> {
            Ok(Cell::default())
        }

        async fn build_message(
            &self,
            _dest: MsgAddressInt,
            _value: u64,
            _payload: Cell,
            _bounce: bool,
            _seqno: Option<u32>,
            _state_init_external: Option<StateInit>,
            _state_init_internal: Option<StateInit>,
        ) -> anyhow::Result<Cell> {
            Ok(Cell::default())
        }

        async fn state_init(&self) -> anyhow::Result<StateInit> {
            self.state_init.clone().ok_or_else(|| anyhow::anyhow!("state_init is not set"))
        }
    }

    fn addr(byte: u8) -> MsgAddressInt {
        MsgAddressInt::with_standart(None, -1, [byte; 32].into()).unwrap()
    }

    fn build_monitor(
        rpc_url: String,
        master_wallet: Arc<dyn Wallet>,
        wallets: Arc<HashMap<String, Arc<dyn Wallet>>>,
    ) -> ContractsMonitor {
        let rpc_client = Arc::new(ClientJsonRpc::connect(rpc_url, None).unwrap());
        let chain_provider: Arc<dyn ChainProvider> =
            Arc::new(DefaultChainProvider::new(rpc_client));
        ContractsMonitor {
            master_wallet,
            pools: Arc::<HashMap<String, Arc<dyn NominatorWrapper>>>::default(),
            wallets,
            chain_provider,
            _store: Arc::new(SnapshotStore::new()),
            standby: Default::default(),
        }
    }

    #[tokio::test]
    async fn ensure_wallets_deployed_sends_once_for_shared_wallet() {
        let server = MockRpcServer::start("uninitialized", 0).await;

        let shared_wallet: Arc<dyn Wallet> = Arc::new(DummyWallet::rich(1));
        let wallets: Arc<HashMap<String, Arc<dyn Wallet>>> = Arc::new(HashMap::from([
            ("node-a".to_string(), shared_wallet.clone()),
            ("node-b".to_string(), shared_wallet),
        ]));
        let master_wallet: Arc<dyn Wallet> = Arc::new(DummyWallet::rich(9));

        let monitor = build_monitor(server.url.clone(), master_wallet, wallets);
        let mut seqno = 1;
        let all_deployed = monitor.ensure_wallets_deployed(&mut seqno).await.unwrap();

        assert!(!all_deployed);
        assert_eq!(seqno, 2);
        assert_eq!(server.send_boc_calls.load(Ordering::Relaxed), 1);

        server.shutdown().await;
    }

    #[tokio::test]
    async fn ensure_wallet_balances_sends_once_for_shared_wallet() {
        let server = MockRpcServer::start("active", 0).await;

        let shared_wallet: Arc<dyn Wallet> = Arc::new(DummyWallet::rich(2));
        let wallets: Arc<HashMap<String, Arc<dyn Wallet>>> = Arc::new(HashMap::from([
            ("node-a".to_string(), shared_wallet.clone()),
            ("node-b".to_string(), shared_wallet),
        ]));
        let master_wallet: Arc<dyn Wallet> = Arc::new(DummyWallet::rich(9));

        let monitor = build_monitor(server.url.clone(), master_wallet, wallets);
        let mut seqno = 10;
        let all_topped_up = monitor.ensure_wallet_balances(&mut seqno).await.unwrap();

        assert!(!all_topped_up);
        assert_eq!(seqno, 11);
        assert_eq!(server.send_boc_calls.load(Ordering::Relaxed), 1);

        server.shutdown().await;
    }

    fn no_wallets() -> Arc<HashMap<String, Arc<dyn Wallet>>> {
        Arc::new(HashMap::new())
    }

    /// An unfunded master wallet on an otherwise healthy node is waited out:
    /// the tick succeeds, sends nothing, and records the condition once.
    #[tokio::test]
    async fn unfunded_master_wallet_is_a_standby_not_an_error() {
        let server = MockRpcServer::start("uninitialized", 0).await;
        let master_wallet: Arc<dyn Wallet> = Arc::new(DummyWallet::rich(9));
        let monitor = build_monitor(server.url.clone(), master_wallet, no_wallets());

        monitor.run().await.expect("an unfunded master wallet is not a tick failure");
        monitor.run().await.expect("nor on the next tick");

        assert_eq!(server.send_boc_calls.load(Ordering::Relaxed), 0);
        let unfunded = Standby::MasterUnfunded { balance: 0 };
        assert_eq!(*monitor.standby.lock().unwrap(), Some(unfunded.clone()));
        // Reported on entry only; a changed balance is reported again.
        assert!(!monitor.enter_standby(unfunded));
        assert!(monitor.enter_standby(Standby::MasterUnfunded { balance: 1 }));

        server.shutdown().await;
    }

    #[tokio::test]
    async fn frozen_master_wallet_still_fails_the_tick() {
        let server = MockRpcServer::start("frozen", u64::MAX).await;
        let master_wallet: Arc<dyn Wallet> = Arc::new(DummyWallet::rich(9));
        let monitor = build_monitor(server.url.clone(), master_wallet, no_wallets());

        let error = monitor.run().await.expect_err("a frozen master wallet is an error");
        assert!(format!("{error:#}").contains("frozen"), "unexpected error: {error:#}");
        assert_eq!(*monitor.standby.lock().unwrap(), None);

        server.shutdown().await;
    }

    /// A wallet below its minimum that the master wallet cannot afford to top
    /// up is waited out, not reported as a failure on every tick.
    #[tokio::test]
    async fn unaffordable_top_up_is_a_standby_not_an_error() {
        let server = MockRpcServer::start("active", 0).await;
        let wallets: Arc<HashMap<String, Arc<dyn Wallet>>> =
            Arc::new(HashMap::from([("node-a".to_string(), Arc::new(DummyWallet::rich(2)) as _)]));
        let poor_master: Arc<dyn Wallet> =
            Arc::new(DummyWallet { balance: 1_000_000_000, ..DummyWallet::rich(9) });
        let monitor = build_monitor(server.url.clone(), poor_master, wallets);

        let mut seqno = 10;
        let all_topped_up = monitor
            .ensure_wallet_balances(&mut seqno)
            .await
            .expect("an unaffordable top-up is not a tick failure");

        assert!(!all_topped_up);
        assert_eq!(seqno, 10);
        assert_eq!(server.send_boc_calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            *monitor.standby.lock().unwrap(),
            Some(Standby::TopUpUnaffordable {
                wallet: addr(2).to_string(),
                master_balance: 1_000_000_000,
                required: TOP_UP_AMOUNT + WALLET_GAS,
            })
        );

        server.shutdown().await;
    }

    #[test]
    fn requirement_is_the_amount_plus_the_gas() {
        assert_eq!(deploy_required().unwrap(), DEPLOY_AMOUNT + WALLET_GAS);
        assert_eq!(top_up_required().unwrap(), TOP_UP_AMOUNT + WALLET_GAS);
        assert_eq!(required_balance(7, 3).unwrap(), 10);
        assert_eq!(required_balance(u64::MAX - 1, 1).unwrap(), u64::MAX);
    }

    #[test]
    fn overflowing_requirement_is_an_error_not_a_clamp() {
        let err = required_balance(u64::MAX, 1).expect_err("must not clamp to u64::MAX");
        assert!(err.to_string().contains("overflows"), "{err}");
        assert!(required_balance(u64::MAX - 5, 10).is_err());
    }
}
