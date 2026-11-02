/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use super::*;
use chain_block::{
    BuilderData, Cell, Coins, ConfigParam15, Deserializable, MsgAddressInt, SliceData,
    ValidatorSet, read_single_root_boc,
};
use common::{
    app_config::{ElectionsConfig, NodeBinding, StakePolicy},
    snapshot::SnapshotStore,
    task_cancellation::{CancellationCtx, CancellationReason},
    time_format,
};
use contracts::{
    ElectionsInfo, ElectorWrapper, NominatorWrapper, Participant, Wallet,
    elector::{FrozenParticipant, PastElections},
    nominator::{NominatorRoles, PoolData, opcodes},
};
use mockall::mock;
use std::{collections::HashMap, sync::Arc, time::Duration};

mod elector_fixture {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../test/validator/elector-control-fixture.rs"
    ));
}

// ---- Address helpers ----

const POOL_ADDR: [u8; 32] = [0xBBu8; 32];
fn wallet_address() -> MsgAddressInt {
    MsgAddressInt::standard(-1, [0xAAu8; 32])
}

fn pool_address() -> MsgAddressInt {
    MsgAddressInt::standard(-1, POOL_ADDR)
}

fn elector_address() -> MsgAddressInt {
    MsgAddressInt::standard(-1, [0x33u8; 32])
}

fn addr_bytes(addr: &MsgAddressInt) -> Vec<u8> {
    addr.address().clone().storage().to_vec()
}

fn default_cfg15() -> ConfigParam15 {
    ConfigParam15 {
        validators_elected_for: 3600,
        elections_start_before: 1800,
        elections_end_before: 600,
        stake_held_for: 7200,
    }
}

fn dummy_cell() -> Cell {
    BuilderData::new().into_cell().unwrap()
}

const ELECTION_ID: u64 = 1_700_000_000;
const KEY_ID: [u8; 32] = [0x01u8; 32];
const PUB_KEY: [u8; 32] = [0x02u8; 32];
const ADNL_ADDR: [u8; 32] = [0x03u8; 32];
const SIGNATURE: [u8; 64] = [0x04u8; 64];
const PQ_PUBLIC_KEY: [u8; 1312] = [0x05u8; 1312];
const PQ_SIGNATURE: [u8; 2420] = [0x06u8; 2420];

const MIN_STAKE: u64 = 10_000_000_000_000; // 10 000 TOS
const WALLET_BALANCE: u64 = 50_000_000_000_000; // 50 000 TOS
const POOL_BALANCE: u64 = 100_000_000_000_000; // 100 000 TOS

// ---- Mock: ElectionsProvider ----

mock! {
    ElectionsProviderImpl {}

    #[async_trait::async_trait]
    impl ElectionsProvider for ElectionsProviderImpl {
        async fn elector_snapshot(&mut self, wallets: &[[u8; 32]]) -> anyhow::Result<ElectorSnapshot>;
        async fn setup(&self) -> anyhow::Result<()>;
        async fn shutdown(&mut self) -> anyhow::Result<()>;
        async fn new_validator_key(
            &mut self,
            since: u64,
            until: u64,
        ) -> anyhow::Result<(Vec<u8>, Vec<u8>)>;
        async fn new_adnl_addr(&mut self, perm_key_id: Vec<u8>, until: u64) -> anyhow::Result<Vec<u8>>;
        async fn retain_validator_registration(&mut self, election_id:u64, key_id:&[u8], adnl:&[u8], until:u64) -> anyhow::Result<()>;
        async fn validator_config(&mut self) -> anyhow::Result<ValidatorConfig>;
        async fn election_parameters(&mut self) -> anyhow::Result<ConfigParam15>;
        async fn send_boc(&mut self, msg_boc: &[u8]) -> anyhow::Result<()>;
        async fn sign(&mut self, key_hash: Vec<u8>, data: Vec<u8>) -> anyhow::Result<Vec<u8>>;
        async fn create_pq_stake_authorization(
            &mut self,
            election_date: u32,
            max_factor: u32,
            adnl_addr: &[u8],
            src_addr: &[u8],
        ) -> anyhow::Result<control_client::client_api::PqStakeAuthorization>;
        async fn account(&mut self, address: &str) -> anyhow::Result<crate::providers::Account>;
        async fn export_public_key(&mut self, key_id: &[u8]) -> anyhow::Result<Vec<u8>>;
        async fn get_current_vset(&mut self) -> anyhow::Result<ValidatorSet>;
        async fn get_next_vset(&mut self) -> anyhow::Result<Option<ValidatorSet>>;
    }
}

// ---- Mock: ElectorWrapper ----

mock! {
    ElectorWrapperImpl {}

    #[async_trait::async_trait]
    impl contracts::SmartContract for ElectorWrapperImpl {
        async fn balance(&self) -> anyhow::Result<u64>;
        fn address(&self) -> MsgAddressInt;
    }

    #[async_trait::async_trait]
    impl ElectorWrapper for ElectorWrapperImpl {
        async fn get_active_election_id(&self) -> anyhow::Result<u64>;
        async fn participates_in(&self, pubkey: &[u8]) -> anyhow::Result<Option<Participant>>;
        async fn compute_returned_stake(&self, address: &[u8]) -> anyhow::Result<u64>;
        async fn elections_info(&self) -> anyhow::Result<ElectionsInfo>;
        async fn past_elections(&self) -> anyhow::Result<Vec<PastElections>>;
    }
}

// ---- Mock: Wallet ----

mock! {
    WalletImpl {}

    #[async_trait::async_trait]
    impl contracts::SmartContract for WalletImpl {
        async fn balance(&self) -> anyhow::Result<u64>;
        fn address(&self) -> MsgAddressInt;
    }

    #[async_trait::async_trait]
    impl Wallet for WalletImpl {
        async fn message(
            &self,
            dest: MsgAddressInt,
            value: u64,
            payload: Cell,
        ) -> anyhow::Result<Cell>;

        async fn deploy_message(
            &self,
            value: u64,
            payload: Cell,
        ) -> anyhow::Result<Cell>;

        async fn build_message(
            &self,
            dest: MsgAddressInt,
            value: u64,
            payload: Cell,
            bounce: bool,
            seqno: Option<u32>,
            state_init_external: Option<chain_block::StateInit>,
            state_init_internal: Option<chain_block::StateInit>,
        ) -> anyhow::Result<Cell>;
    }
}

// ---- Mock: NominatorWrapper ----

mock! {
    NominatorWrapperImpl {}

    #[async_trait::async_trait]
    impl contracts::SmartContract for NominatorWrapperImpl {
        async fn balance(&self) -> anyhow::Result<u64>;
        fn address(&self) -> MsgAddressInt;
    }

    #[async_trait::async_trait]
    impl NominatorWrapper for NominatorWrapperImpl {
        async fn get_roles(&self) -> anyhow::Result<NominatorRoles>;
        async fn get_pool_data(&self) -> anyhow::Result<PoolData>;
        fn state_init(&self) -> Option<chain_block::StateInit>;
    }
}

// ---- Fake Account using control_client ----

fn fake_account(balance: u64) -> crate::providers::Account {
    crate::providers::Account::new(control_client::client_api::Account::ShardAccountState(
        control_client::client_api::ShardAccountState {
            balance: balance as u128,
            ..Default::default()
        },
    ))
}

/// Checks a stake message: through the pool, the wallet sends the fees and a body
/// carrying the amount; without a pool, it sends the stake and fees straight to the
/// elector with a body that carries none. Both end with the fields the elector parses.
fn validate_message_parameters(
    dest: &MsgAddressInt,
    value: &u64,
    payload: &Cell,
    expected_stake: u64,
    via_pool: bool,
) -> bool {
    let fee = ELECTOR_STAKE_FEE + NPOOL_COMPUTE_FEE;
    let (expected_dest, expected_value) =
        if via_pool { (pool_address(), fee) } else { (elector_address(), expected_stake + fee) };
    if *dest != expected_dest {
        eprintln!("withf: dest mismatch: expected {}, got {}", expected_dest, dest);
        return false;
    }
    if *value != expected_value {
        eprintln!("withf: value mismatch: expected={}, got={}", expected_value, value);
        return false;
    }
    let Ok(mut slice) = SliceData::load_cell_ref(payload) else {
        eprintln!("withf: failed to load payload cell");
        return false;
    };
    if slice.get_next_u32().ok() != Some(opcodes::NEW_STAKE) {
        eprintln!("withf: opcode mismatch");
        return false;
    }
    if slice.get_next_u64().map_or(true, |query_id| query_id == 0) {
        eprintln!("withf: query_id should be > 0");
        return false;
    }
    if via_pool {
        let Ok(coins) = Coins::construct_from(&mut slice) else {
            return false;
        };
        if coins.as_u128() != expected_stake as u128 {
            eprintln!(
                "withf: stake mismatch: expected={}, got={}",
                expected_stake,
                coins.as_u128()
            );
            return false;
        }
    }
    if slice.get_next_u16().ok() != Some(1) {
        eprintln!("withf: algorithm mismatch");
        return false;
    }
    let Ok(key_cell) = slice.checked_drain_reference() else {
        eprintln!("withf: missing PQ public-key reference");
        return false;
    };
    if slice.get_next_u32().ok() != Some(ELECTION_ID as u32) {
        eprintln!("withf: stake_at mismatch");
        return false;
    }
    if slice.get_next_u32().ok() != Some(196608) {
        eprintln!("withf: max_factor mismatch");
        return false;
    }
    if slice.get_next_bits(256).ok() != Some(ADNL_ADDR.to_vec()) {
        eprintln!("withf: adnl mismatch");
        return false;
    }
    let Ok(sig_cell) = slice.checked_drain_reference() else {
        return false;
    };
    if chain_block::pq_bytes::unpack_pq_bytes(&key_cell, 1312).ok() != Some(PQ_PUBLIC_KEY.to_vec())
        || chain_block::pq_bytes::unpack_pq_bytes(&sig_cell, 2420).ok()
            != Some(PQ_SIGNATURE.to_vec())
        || slice.remaining_bits() != 0
        || slice.remaining_references() != 0
    {
        eprintln!("withf: PQ key, signature or trailing data mismatch");
        return false;
    }
    true
}

// ---- Builder helpers ----

fn default_binding(enable: bool) -> NodeBinding {
    NodeBinding { wallet: "wallet".to_string(), pool: None, enable, status: Default::default() }
}

struct TestHarness {
    elector_mock: MockElectorWrapperImpl,
    provider_mock: MockElectionsProviderImpl,
    wallet_mock: MockWalletImpl,
    pool_mock: Option<MockNominatorWrapperImpl>,
    elections_config: ElectionsConfig,
    bindings: HashMap<String, NodeBinding>,
}

impl TestHarness {
    fn new() -> Self {
        Self {
            elector_mock: MockElectorWrapperImpl::new(),
            provider_mock: MockElectionsProviderImpl::new(),
            wallet_mock: MockWalletImpl::new(),
            pool_mock: None,
            elections_config: ElectionsConfig {
                policy: StakePolicy::Split50,
                policy_overrides: HashMap::new(),
                max_factor: 3.0,
                tick_interval: 10,
            },
            bindings: HashMap::new(),
        }
    }

    fn with_pool(mut self) -> Self {
        self.pool_mock = Some(MockNominatorWrapperImpl::new());
        let mut binding = default_binding(true);
        binding.pool = Some("pool".to_string());
        self.bindings.insert("node-1".to_string(), binding);
        self
    }

    fn build(mut self, node_id: &str) -> ElectionRunner {
        self.bindings.entry(node_id.to_string()).or_insert_with(|| default_binding(true));

        self.provider_mock.expect_retain_validator_registration().returning(|_, _, _, _| Ok(()));
        let wallet: Arc<dyn Wallet> = Arc::new(self.wallet_mock);
        let mut wallets: HashMap<String, Arc<dyn Wallet>> = HashMap::new();
        wallets.insert(node_id.to_string(), wallet);

        let elector = Arc::new(self.elector_mock);
        fixture_snapshot(&mut self.provider_mock, elector.clone());
        let mut providers: HashMap<String, Box<dyn ElectionsProvider>> = HashMap::new();
        providers.insert(node_id.to_string(), Box::new(self.provider_mock));

        let mut pools: HashMap<String, Arc<dyn NominatorWrapper>> = HashMap::new();
        if let Some(pool) = self.pool_mock {
            pools.insert(node_id.to_string(), Arc::new(pool));
        }

        ElectionRunner::new(
            &self.elections_config,
            &self.bindings,
            elector,
            providers,
            Arc::new(wallets),
            Arc::new(pools),
        )
    }
}

// Existing lifecycle fixtures describe their fields independently. Assemble them
// in memory before the provider delivers one snapshot; these mocks do no I/O.
fn ready<T>(future: impl std::future::Future<Output = anyhow::Result<T>>) -> anyhow::Result<T> {
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(value) => value,
        std::task::Poll::Pending => anyhow::bail!("in-memory fixture unexpectedly awaited I/O"),
    }
}
fn fixture_snapshot(
    provider: &mut MockElectionsProviderImpl,
    elector: Arc<MockElectorWrapperImpl>,
) {
    provider.expect_elector_snapshot().returning(move |wallets| {
        let election_id = ready(elector.get_active_election_id())?;
        let elections = if election_id == 0 {
            ElectionsInfo {
                election_id: 0,
                elect_close: 0,
                min_stake: 0,
                total_stake: 0,
                failed: false,
                finished: false,
                participants: vec![],
            }
        } else {
            ready(elector.elections_info())?
        };
        let past_elections = if election_id == 0 || elections.finished {
            vec![]
        } else {
            ready(elector.past_elections())?
        };
        let returned = wallets
            .iter()
            .map(|wallet| {
                let amount = if election_id == 0 || elections.finished {
                    0
                } else {
                    ready(elector.compute_returned_stake(wallet))?
                };
                Ok((*wallet, amount))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(ElectorSnapshot { block: snapshot_block(), elections, past_elections, returned })
    });
}
fn snapshot_block() -> chain_block::BlockIdExt {
    chain_block::BlockIdExt::with_params(
        chain_block::ShardIdent::masterchain(),
        17,
        chain_block::UInt256::from([8; 32]),
        chain_block::UInt256::from([9; 32]),
    )
}

async fn control_runner(fixture: &elector_fixture::Fixture) -> anyhow::Result<ElectionRunner> {
    let mut harness = TestHarness::new();
    harness.elector_mock.expect_address().returning(elector_address);
    setup_wallet(&mut harness.wallet_mock);
    harness.bindings.insert("node-1".into(), default_binding(false));
    let mut runner = harness.build("node-1");
    let config = fixture.config()?;
    let adnl = config.nodes.get("test").context("fixture node")?.to_node_adnl_config(None).await?;
    let rpc = Arc::new(chain_rpc_client::v2::client_json_rpc::ClientJsonRpc::connect(
        fixture.public_url.clone(),
        None,
    )?);
    runner.nodes.get_mut("node-1").context("fixture runner node")?.api =
        Box::new(crate::providers::DefaultElectionsProvider::new(
            adnl,
            Arc::new(contracts::DefaultChainProvider::new(rpc)),
        ));
    Ok(runner)
}

async fn wire_provider(
    fixture: &elector_fixture::Fixture,
) -> anyhow::Result<Box<dyn ElectionsProvider>> {
    let config = fixture.config()?;
    let adnl = config.nodes.get("test").context("fixture node")?.to_node_adnl_config(None).await?;
    let rpc = Arc::new(chain_rpc_client::v2::client_json_rpc::ClientJsonRpc::connect(
        fixture.public_url.clone(),
        None,
    )?);
    Ok(Box::new(crate::providers::DefaultElectionsProvider::new(
        adnl,
        Arc::new(contracts::DefaultChainProvider::new(rpc)),
    )))
}

#[tokio::test]
async fn distinct_wire_credits_drive_recovery_from_one_snapshot() -> anyhow::Result<()> {
    use std::sync::atomic::Ordering;
    let fixture = elector_fixture::Fixture::new(elector_fixture::Reply {
        credits: HashMap::from([([0xaa; 32], vec![11]), ([0xbb; 32], vec![22])]),
        frozen_owner: [0xaa; 32],
        ..Default::default()
    })
    .await?;
    let mut runner = control_runner(&fixture).await?;
    let mut pool = MockNominatorWrapperImpl::new();
    pool.expect_address().returning(wallet_address);
    let node = runner.nodes.get_mut("node-1").context("pool node")?;
    node.excluded = false;
    node.pool = Some(Arc::new(pool));
    let mut extra = TestHarness::new();
    extra.elector_mock.expect_address().returning(elector_address);
    extra.wallet_mock.expect_address().returning(|| MsgAddressInt::standard(-1, [0xbb; 32]));
    let mut extra = extra.build("node-2");
    let mut node = extra.nodes.remove("node-2").context("second node")?;
    node.api = wire_provider(&fixture).await?;
    runner.nodes.insert("node-2".into(), node);
    runner.run().await?;
    assert_eq!(runner.nodes["node-1"].last_recover_amount, 11);
    assert_eq!(runner.nodes["node-2"].last_recover_amount, 22);
    for node in runner.nodes.values() {
        assert!(
            node.last_error.as_deref().is_some_and(|e| e.contains("low wallet balance")),
            "recovery must reach its funding check: {:?}",
            node.last_error
        );
    }
    let identity = <[u8; 32]>::try_from(runner.nodes["node-1"].wallet_addr())
        .map_err(|_| anyhow::anyhow!("staking account width"))?;
    assert_eq!(runner.past_elections[0].frozen_map[&identity].wallet_addr, [0xaa; 32]);
    assert_eq!(fixture.counts.control.load(Ordering::SeqCst), 1);
    fixture.no_public_elector()?;
    runner.shutdown().await?;
    fixture.stop().await;
    Ok(())
}

#[tokio::test]
async fn late_wire_overflow_preserves_populated_decision_state() -> anyhow::Result<()> {
    use std::sync::atomic::Ordering;
    for frozen_overflow in [true, false] {
        let good = elector_fixture::Fixture::new(elector_fixture::Reply {
            credits: HashMap::from([([0xaa; 32], vec![11])]),
            ..Default::default()
        })
        .await?;
        let mut runner = control_runner(&good).await?;
        runner.nodes.get_mut("node-1").context("node")?.stake_accepted = true;
        runner.nodes.get_mut("node-1").context("node")?.accepted_stake_amount = Some(123);
        runner.run().await?;
        let snapshot = serde_json::to_value(&runner.snapshot_cache.last_elections)?;
        let status = runner.snapshot_cache.last_elections_status.clone();
        assert_eq!(runner.nodes["node-1"].last_recover_amount, 11);
        let bad = elector_fixture::Fixture::new(elector_fixture::Reply {
            frozen_overflow,
            credits: HashMap::from([(
                [0xaa; 32],
                if frozen_overflow { vec![22] } else { vec![1, 0, 0, 0, 0, 0, 0, 0, 0] },
            )]),
            ..Default::default()
        })
        .await?;
        runner.nodes.get_mut("node-1").context("node")?.api.shutdown().await?;
        runner.nodes.get_mut("node-1").context("node")?.api = wire_provider(&bad).await?;
        let error = runner.run().await.err().context("late overflow accepted")?;
        assert!(
            format!("{error:#}").contains(if frozen_overflow {
                "frozen stake exceeds u64"
            } else {
                "returned stake exceeds u64"
            }),
            "wrong refusal: {error:#}"
        );
        assert_eq!(serde_json::to_value(&runner.snapshot_cache.last_elections)?, snapshot);
        assert_eq!(runner.snapshot_cache.last_elections_status, status);
        assert_eq!(runner.past_elections[0].frozen_map[&[6; 32]].stake, 11);
        assert_eq!(runner.past_elections[0].total_stake, 11);
        assert!(runner.nodes["node-1"].stake_accepted);
        assert_eq!(runner.nodes["node-1"].accepted_stake_amount, Some(123));
        assert_eq!(runner.nodes["node-1"].last_recover_amount, 11);
        assert_eq!(good.counts.control.load(Ordering::SeqCst), 1);
        assert_eq!(bad.counts.control.load(Ordering::SeqCst), 1);
        good.no_public_elector()?;
        bad.no_public_elector()?;
        runner.shutdown().await?;
        good.stop().await;
        bad.stop().await;
    }
    Ok(())
}

#[tokio::test]
async fn runner_uses_one_control_snapshot_and_no_public_elector_getters() -> anyhow::Result<()> {
    use std::sync::atomic::Ordering;
    for (election_id, finished, count) in [
        (1_700_000_000, true, 1),
        (1_700_000_002, false, 100),
        (1_700_000_002, false, 256),
        (0, false, 0),
    ] {
        let fixture = elector_fixture::Fixture::new(elector_fixture::Reply {
            election_id,
            finished,
            participants: count,
            ..Default::default()
        })
        .await?;
        let mut runner = control_runner(&fixture).await?;
        runner.run().await?;
        fixture.no_public_elector()?;
        assert_eq!(
            fixture.counts.control.load(Ordering::SeqCst),
            1,
            "one elector query per runner decision"
        );
        let snapshot =
            runner.snapshot_cache.last_elections.as_ref().context("election snapshot")?;
        assert_eq!(snapshot.election_id, u64::from(election_id));
        assert_eq!(snapshot.finished, finished);
        assert_eq!(snapshot.participants_count, u32::try_from(count)?);
        assert_eq!(runner.past_elections.len(), 1);
        assert_eq!(runner.past_elections[0].election_id, 1_600_000_000);
        assert_eq!(runner.past_elections[0].frozen_map[&[6; 32]].wallet_addr, [6; 32]);
        assert_eq!(runner.past_elections[0].frozen_map[&[6; 32]].weight, u64::MAX);
        {
            let wallets =
                fixture.counts.wallets.lock().map_err(|_| anyhow::anyhow!("wallet counter"))?;
            assert_eq!(*wallets, vec![vec![[0xaa; 32]]]);
        }
        runner.shutdown().await?;
        fixture.stop().await;
    }
    Ok(())
}

#[tokio::test]
async fn a_failed_control_snapshot_changes_no_acceptance_or_snapshot_state() -> anyhow::Result<()> {
    use std::sync::atomic::Ordering;
    for reply in [
        elector_fixture::Reply { unsupported: true, ..Default::default() },
        elector_fixture::Reply { overflow: true, ..Default::default() },
        elector_fixture::Reply { wrong_wallet: true, ..Default::default() },
    ] {
        let fixture = elector_fixture::Fixture::new(reply.clone()).await?;
        let mut runner = control_runner(&fixture).await?;
        runner.snapshot_cache.last_elections_status = ElectionsStatus::Finished;
        runner.nodes.get_mut("node-1").context("fixture node")?.stake_accepted = true;
        runner.nodes.get_mut("node-1").context("fixture node")?.accepted_stake_amount = Some(123);
        let error = runner.run().await.err().context("invalid snapshot was accepted")?;
        if reply.unsupported {
            assert!(
                error.downcast_ref::<control_client::UnsupportedControlQuery>().is_some(),
                "upgrade error lost: {error:#}"
            );
        } else {
            assert!(
                format!("{error:#}").contains(if reply.overflow {
                    "participant stake exceeds u64"
                } else {
                    "wallet order or address"
                }),
                "wrong refusal: {error:#}"
            );
        }
        assert_eq!(runner.snapshot_cache.last_elections_status, ElectionsStatus::Finished);
        assert!(runner.snapshot_cache.last_elections.is_none());
        assert!(runner.nodes["node-1"].stake_accepted);
        assert_eq!(runner.nodes["node-1"].accepted_stake_amount, Some(123));
        fixture.no_public_elector()?;
        assert_eq!(fixture.counts.control.load(Ordering::SeqCst), 1);
        runner.shutdown().await?;
        fixture.stop().await;
    }
    Ok(())
}

#[tokio::test]
async fn the_runner_loop_propagates_the_named_upgrade_error_before_publishing() -> anyhow::Result<()>
{
    use std::sync::atomic::Ordering;
    let fixture = elector_fixture::Fixture::new(elector_fixture::Reply {
        unsupported: true,
        ..Default::default()
    })
    .await?;
    let mut runner = control_runner(&fixture).await?;
    let store = Arc::new(SnapshotStore::new());
    let error = tokio::time::timeout(
        Duration::from_secs(10),
        runner.run_loop(Duration::from_secs(60), CancellationCtx::new(), store.clone(), None),
    )
    .await?
    .err()
    .context("unsupported node did not stop the runner")?;
    assert!(
        error.downcast_ref::<control_client::UnsupportedControlQuery>().is_some(),
        "upgrade error lost: {error:#}"
    );
    assert!(runner.snapshot_cache.last_elections.is_none());
    assert_eq!(fixture.counts.control.load(Ordering::SeqCst), 1);
    fixture.no_public_elector()?;
    runner.shutdown().await?;
    fixture.stop().await;
    Ok(())
}

#[tokio::test]
async fn one_runner_tick_requests_exactly_one_elector_snapshot() -> anyhow::Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let mut harness = TestHarness::new();
    harness.elector_mock.expect_address().returning(elector_address);
    setup_wallet(&mut harness.wallet_mock);
    setup_default_provider(&mut harness.provider_mock, WALLET_BALANCE, None);
    let reads = Arc::new(AtomicUsize::new(0));
    let counter = reads.clone();
    let mut stop = CancellationCtx::new();
    let cancellation = stop.clone();
    harness.provider_mock.expect_elector_snapshot().returning(move |wallets| {
        counter.fetch_add(1, Ordering::SeqCst);
        stop.cancel(CancellationReason::GracefullyShutdown());
        Ok(ElectorSnapshot {
            block: snapshot_block(),
            elections: ElectionsInfo {
                election_id: 0,
                elect_close: 0,
                min_stake: 0,
                total_stake: 0,
                failed: false,
                finished: false,
                participants: vec![],
            },
            past_elections: vec![],
            returned: wallets.iter().map(|wallet| (*wallet, 0)).collect(),
        })
    });
    let mut runner = harness.build("node-1");
    tokio::time::timeout(
        Duration::from_secs(10),
        runner.run_loop(
            Duration::from_secs(600),
            cancellation,
            Arc::new(SnapshotStore::new()),
            None,
        ),
    )
    .await??;
    assert_eq!(reads.load(Ordering::SeqCst), 1, "one elector query per runner tick");
    Ok(())
}

#[tokio::test]
async fn too_many_distinct_wallets_fails_before_a_query_or_state_change() -> anyhow::Result<()> {
    use std::sync::atomic::Ordering;
    let fixture = elector_fixture::Fixture::new(Default::default()).await?;
    let mut runner = control_runner(&fixture).await?;
    runner.snapshot_cache.last_elections_status = ElectionsStatus::Finished;
    for index in 0..16 {
        let mut other = TestHarness::new();
        other.elector_mock.expect_address().returning(elector_address);
        let mut address = [0; 32];
        address[31] = index;
        other.wallet_mock.expect_address().returning(move || MsgAddressInt::standard(-1, address));
        let name = format!("node-extra-{index:02}");
        let mut other = other.build(&name);
        runner.nodes.insert(name.clone(), other.nodes.remove(&name).context("extra node")?);
    }
    let error = runner.run().await.err().context("seventeen wallets accepted")?;
    assert!(error.to_string().contains("more than 16 distinct"), "wrong refusal: {error:#}");
    assert_eq!(fixture.counts.control.load(Ordering::SeqCst), 0);
    assert_eq!(runner.snapshot_cache.last_elections_status, ElectionsStatus::Finished);
    assert!(runner.snapshot_cache.last_elections.is_none());
    fixture.no_public_elector()?;
    fixture.stop().await;
    Ok(())
}

#[tokio::test]
async fn shared_wallets_are_requested_once_in_sorted_order() -> anyhow::Result<()> {
    use std::sync::atomic::Ordering;
    let fixture = elector_fixture::Fixture::new(elector_fixture::Reply {
        election_id: 0,
        participants: 0,
        ..Default::default()
    })
    .await?;
    let mut runner = control_runner(&fixture).await?;
    for (name, address) in [("node-2", [0xaa; 32]), ("node-3", [0x01; 32])] {
        let mut extra = TestHarness::new();
        extra.elector_mock.expect_address().returning(elector_address);
        extra.provider_mock.expect_election_parameters().returning(|| Ok(default_cfg15()));
        extra.wallet_mock.expect_address().returning(move || MsgAddressInt::standard(-1, address));
        let mut extra = extra.build(name);
        runner.nodes.insert(name.into(), extra.nodes.remove(name).context("extra node")?);
    }
    runner.run().await?;
    {
        let requests =
            fixture.counts.wallets.lock().map_err(|_| anyhow::anyhow!("wallet counter"))?;
        assert_eq!(*requests, vec![vec![[0x01; 32], [0xaa; 32]]]);
    }
    assert_eq!(fixture.counts.control.load(Ordering::SeqCst), 1);
    fixture.no_public_elector()?;
    // Only the real provider owns a connection; the extra mock nodes have none.
    runner.nodes.get_mut("node-1").context("fixture node")?.api.shutdown().await?;
    fixture.stop().await;
    Ok(())
}

// ---- Expectation helpers ----

/// Sets up a provider for a fresh election (no existing key):
/// generates transport keys, asks the node to authorize a PQ stake, and sends the pool body.
fn setup_default_provider(
    provider: &mut MockElectionsProviderImpl,
    wallet_balance: u64,
    pool_balance: Option<u64>,
) {
    provider.expect_election_parameters().returning(|| Ok(default_cfg15()));

    // validator_config: return empty (no existing key)
    provider.expect_validator_config().returning(|| Ok(ValidatorConfig::new()));

    // get_current_vset: not crucial, return error to skip
    provider.expect_get_current_vset().returning(|| Err(anyhow::anyhow!("no vset")));
    provider.expect_get_next_vset().returning(|| Ok(None));

    // new_validator_key
    provider
        .expect_new_validator_key()
        .returning(|_since, _until| Ok((KEY_ID.to_vec(), PUB_KEY.to_vec())));

    // new_adnl_addr
    provider.expect_new_adnl_addr().returning(|_key_id, _until| Ok(ADNL_ADDR.to_vec()));

    // export_public_key: needed for find_election_key
    provider.expect_export_public_key().returning(|_key_id| Ok(PUB_KEY.to_vec()));

    // sign
    provider.expect_sign().returning(|_key, _data| Ok(SIGNATURE.to_vec()));
    provider
        .expect_create_pq_stake_authorization()
        .withf(|election, max_factor, adnl, src_addr| {
            *election == ELECTION_ID as u32
                && *max_factor == 196608
                && adnl == ADNL_ADDR
                && (src_addr == POOL_ADDR || src_addr == addr_bytes(&wallet_address()))
        })
        .returning(|_, _, _, src_addr| {
            // The node is configured with the staking account as its validator id.
            Ok(control_client::client_api::PqStakeAuthorization {
                validator_id: src_addr.to_vec(),
                key_id: vec![0x08; 32],
                algorithm_id: 1,
                public_key: PQ_PUBLIC_KEY.to_vec(),
                signature: PQ_SIGNATURE.to_vec(),
            })
        });

    // account (for stake_balance and wallet_balance)
    if pool_balance.is_some() {
        // When pool exists, account is called for pool address (stake_balance)
        // and wallet address (wallet_balance)
        let pool_bal = pool_balance.unwrap();
        provider.expect_account().returning(move |address| {
            if address.contains(&hex::encode(POOL_ADDR)) {
                Ok(fake_account(pool_bal))
            } else {
                Ok(fake_account(wallet_balance))
            }
        });
    } else {
        provider.expect_account().returning(move |_addr| Ok(fake_account(wallet_balance)));
    }

    // send_boc
    provider.expect_send_boc().returning(|_boc| Ok(()));

    // shutdown
    provider.expect_shutdown().returning(|| Ok(()));
}

// Setup default elector contract state:
// - active elections
// - no participants
// - no past elections
// - no frozen stake
fn setup_default_elector(
    elector: &mut MockElectorWrapperImpl,
    election_id: u64,
    returned_stake: u64,
) {
    elector.expect_address().returning(|| elector_address());

    elector.expect_get_active_election_id().returning(move || Ok(election_id));

    elector.expect_elections_info().returning(move || {
        Ok(ElectionsInfo {
            election_id,
            elect_close: election_id - 300,
            min_stake: MIN_STAKE,
            total_stake: 0,
            failed: false,
            finished: false,
            participants: vec![],
        })
    });

    elector.expect_past_elections().returning(|| Ok(vec![]));

    elector.expect_compute_returned_stake().returning(move |_addr| Ok(returned_stake));
}

fn setup_elector_no_elections(elector: &mut MockElectorWrapperImpl) {
    elector.expect_address().returning(|| elector_address());
    elector.expect_get_active_election_id().returning(|| Ok(0));
}

fn setup_wallet(wallet: &mut MockWalletImpl) {
    wallet.expect_address().returning(|| wallet_address());
    wallet.expect_message().returning(|_dest, _value, _payload| Ok(dummy_cell()));
}

fn setup_pool(pool: &mut MockNominatorWrapperImpl) {
    pool.expect_address().returning(|| pool_address());
    pool.expect_get_roles().returning(|| {
        Ok(NominatorRoles { owner_address: wallet_address(), validator_address: wallet_address() })
    });
}

// =====================================================
// TEST: participate in elections (new key, no pool)
// =====================================================

#[tokio::test]
async fn test_participate_new_key_no_pool_stakes_directly() {
    let node_id = "node-1";
    let mut harness = TestHarness::new();

    setup_default_elector(&mut harness.elector_mock, ELECTION_ID, 0);
    setup_default_provider(&mut harness.provider_mock, WALLET_BALANCE, None);
    harness.wallet_mock.expect_address().returning(|| wallet_address());
    let fee = ELECTOR_STAKE_FEE + NPOOL_COMPUTE_FEE;
    let expected_stake = (WALLET_BALANCE - fee - MIN_NANOTOS_FOR_STORAGE) / 2;
    harness
        .wallet_mock
        .expect_message()
        .times(1)
        .withf(move |dest, value, payload| {
            validate_message_parameters(dest, value, payload, expected_stake, false)
        })
        .returning(|_dest, _value, _payload| Ok(dummy_cell()));

    let mut runner = harness.build(node_id);

    let result = runner.run().await;
    assert!(result.is_ok(), "run() failed: {:?}", result.err());

    let node = runner.nodes.get(node_id).unwrap();
    assert!(node.last_error.is_none(), "direct stake failed: {:?}", node.last_error);
    let participant = node.participant.as_ref().expect("participant after participation");
    assert_eq!(participant.pub_key, PUB_KEY.to_vec());
    assert_eq!(participant.adnl_addr, ADNL_ADDR.to_vec());
    assert_eq!(participant.election_id, ELECTION_ID);
    assert_eq!(participant.max_factor, 196608);
    assert_eq!(participant.stake, expected_stake);
    assert_eq!(participant.wallet_addr, addr_bytes(&wallet_address()));
    assert!(participant.stake_message_boc.is_some(), "the direct stake was not sent");
}

// =====================================================
// TEST: participate in elections with pool
// =====================================================

#[tokio::test]
async fn test_participate_new_key_with_pool() {
    let node_id = "node-1";
    let mut harness = TestHarness::new().with_pool();

    setup_default_elector(&mut harness.elector_mock, ELECTION_ID, 0);
    setup_default_provider(&mut harness.provider_mock, WALLET_BALANCE, Some(POOL_BALANCE));
    setup_wallet(&mut harness.wallet_mock);
    setup_pool(harness.pool_mock.as_mut().unwrap());

    let expected_stake = (POOL_BALANCE - MIN_NANOTOS_FOR_STORAGE) / 2;
    // validate the election bid payload
    harness
        .wallet_mock
        .expect_message()
        .withf(move |dest, value, payload| {
            validate_message_parameters(dest, value, payload, expected_stake, true)
        })
        .returning(|_dest, _value, _payload| Ok(dummy_cell()));

    let mut runner = harness.build(node_id);

    let result = runner.run().await;
    assert!(result.is_ok(), "run() failed: {:?}", result.err());

    let node = runner.nodes.get(node_id).unwrap();
    assert!(node.participant.is_some());
    let participant = node.participant.as_ref().unwrap();
    assert!(participant.stake > 0);
    assert_eq!(participant.stake, expected_stake);
    assert!(
        node.last_error.is_none(),
        "pool stake failed before wallet send: {:?}",
        node.last_error
    );
    // With pool, wallet_addr should be the pool address
    assert_eq!(participant.wallet_addr, addr_bytes(&pool_address()));
}

/// A node configured with another validator id signs for that account; the elector
/// would return such a stake, so the runner refuses before the wallet sends anything.
#[tokio::test]
async fn test_pool_stake_signed_for_another_account_refuses_before_wallet_message() {
    let node_id = "node-1";
    let mut harness = TestHarness::new().with_pool();
    setup_default_elector(&mut harness.elector_mock, ELECTION_ID, 0);
    harness.provider_mock.expect_create_pq_stake_authorization().returning(|_, _, _, _| {
        Ok(control_client::client_api::PqStakeAuthorization {
            validator_id: vec![0x77; 32],
            key_id: vec![0x08; 32],
            algorithm_id: 1,
            public_key: PQ_PUBLIC_KEY.to_vec(),
            signature: PQ_SIGNATURE.to_vec(),
        })
    });
    setup_default_provider(&mut harness.provider_mock, WALLET_BALANCE, Some(POOL_BALANCE));
    harness.wallet_mock.expect_address().returning(|| wallet_address());
    harness.wallet_mock.expect_message().times(0);
    setup_pool(harness.pool_mock.as_mut().expect("pool"));
    let mut runner = harness.build(node_id);
    runner.run().await.expect("runner keeps the named node error");
    let node = runner.nodes.get(node_id).expect("node");
    assert!(node.participant.is_some(), "negative control never reached the stake attempt");
    assert!(
        node.last_error.as_deref().unwrap_or("").contains("set the node's validator id"),
        "wrong local refusal: {:?}",
        node.last_error
    );
}

struct UnusedPoolProvider;

#[async_trait::async_trait]
impl contracts::ContractProvider for UnusedPoolProvider {
    async fn get_method(
        &self,
        _address: String,
        _method: &str,
        _stack: Vec<tl_api::tos::tvm::StackEntry>,
    ) -> anyhow::Result<common::tvm_stack_parser::TvmStackParser> {
        anyhow::bail!("building a stake must not query pool state")
    }

    async fn balance(&self, _address: &MsgAddressInt) -> anyhow::Result<u64> {
        anyhow::bail!("the runner reads balances through its node provider")
    }
}

fn multi_pool_stake_runner(pool_balance: u64, expect_send: bool) -> ElectionRunner {
    let mut harness = TestHarness::new();
    harness.elector_mock.expect_address().returning(elector_address);
    harness.wallet_mock.expect_address().returning(wallet_address);
    setup_default_provider(&mut harness.provider_mock, WALLET_BALANCE, Some(pool_balance));
    if expect_send {
        harness
            .wallet_mock
            .expect_message()
            .times(1)
            .withf(|dest, value, payload| {
                validate_message_parameters(
                    dest,
                    value,
                    payload,
                    MIN_STAKE + ELECTOR_STAKE_FEE,
                    true,
                )
            })
            .returning(|_, _, _| Ok(dummy_cell()));
    } else {
        harness.wallet_mock.expect_message().times(0);
    }
    let mut runner = harness.build("node-1");
    let node = runner.nodes.get_mut("node-1").expect("node");
    node.pool = Some(Arc::new(contracts::NominatorPoolWrapperImpl::new(
        Arc::new(UnusedPoolProvider),
        pool_address(),
    )));
    node.elections_address = pool_address();
    node.participant = Some(Participant {
        stake: MIN_STAKE,
        election_id: ELECTION_ID,
        max_factor: 196608,
        adnl_addr: ADNL_ADDR.to_vec(),
        wallet_addr: POOL_ADDR.to_vec(),
        ..Default::default()
    });
    runner
}

#[tokio::test]
async fn a_multi_pool_order_funds_the_confirmation_above_the_target_stake() {
    let mut runner = multi_pool_stake_runner(POOL_BALANCE, true);
    let node = runner.nodes.get_mut("node-1").expect("node");
    ElectionRunner::send_stake("node-1", node, MIN_STAKE).await.expect("funded stake");
    assert_eq!(node.participant.as_ref().expect("participant").stake, MIN_STAKE);
    assert_eq!(node.stake_submissions[0].stake, MIN_STAKE);
}

#[tokio::test]
async fn a_multi_pool_without_the_confirmation_allowance_sends_nothing() {
    let mut runner = multi_pool_stake_runner(MIN_STAKE + 10_000_000_000, false);
    let node = runner.nodes.get_mut("node-1").expect("node");
    let error = ElectionRunner::send_stake("node-1", node, MIN_STAKE).await.unwrap_err();
    assert!(error.to_string().contains("low stake balance"), "wrong refusal: {error}");
    assert!(node.stake_submissions.is_empty());
}

#[tokio::test]
async fn a_multi_pool_confirmation_overflow_sends_nothing() {
    let mut runner = multi_pool_stake_runner(u64::MAX, false);
    let node = runner.nodes.get_mut("node-1").expect("node");
    node.participant.as_mut().expect("participant").stake = u64::MAX;
    let error = ElectionRunner::send_stake("node-1", node, u64::MAX).await.unwrap_err();
    assert!(error.to_string().contains("pool stake value overflow"), "wrong refusal: {error}");
    assert!(node.stake_submissions.is_empty());
}

#[tokio::test]
async fn a_multi_pool_stake_policy_reserves_storage_and_confirmation() {
    let mut runner = multi_pool_stake_runner(POOL_BALANCE, false);
    let node = runner.nodes.get_mut("node-1").expect("node");
    node.stake_policy = StakePolicy::Fixed(u64::MAX);
    let stake = ElectionRunner::calc_stake(node, "node-1", &[], 0, MIN_STAKE)
        .await
        .expect("the available stake");
    // The contract requires ten TOS to remain and deducts one from the order.
    assert_eq!(stake, POOL_BALANCE - 11_000_000_000);
}

// =====================================================
// TEST: participate with existing key (re-stake)
// =====================================================

#[tokio::test]
async fn test_participate_existing_key_not_in_elector() {
    let node_id = "node-1";
    let mut harness = TestHarness::new();

    setup_default_provider(&mut harness.provider_mock, WALLET_BALANCE, Some(POOL_BALANCE));
    // Elector returns active elections, no returned stake
    setup_default_elector(&mut harness.elector_mock, ELECTION_ID, 0);
    setup_wallet(&mut harness.wallet_mock);

    // Return existing key in validator_config
    harness.provider_mock.expect_validator_config().returning(|| {
        let mut keys = HashMap::new();
        keys.insert(
            ELECTION_ID,
            ValidatorEntry {
                key_id: KEY_ID.to_vec(),
                public_key: vec![], // will be filled by export_public_key
                adnl_addrs: vec![(ADNL_ADDR.to_vec(), ELECTION_ID + 7200)],
                expired_at: ELECTION_ID + 7200,
            },
        );
        Ok(ValidatorConfig { keys })
    });

    let mut runner = harness.build(node_id);
    runner.refresh_validator_configs().await;
    let result = runner.run().await;
    assert!(result.is_ok(), "run() failed: {:?}", result.err());

    let node = runner.nodes.get(node_id).unwrap();
    assert!(node.participant.is_some());
    let p = node.participant.as_ref().unwrap();
    assert_eq!(p.pub_key, PUB_KEY.to_vec());
    assert_eq!(p.adnl_addr, ADNL_ADDR.to_vec());
}

// =====================================================
// TEST: stake already accepted by elector
// =====================================================

#[tokio::test]
async fn test_stake_already_accepted() {
    let node_id = "node-1";
    let mut harness = TestHarness::new().with_pool();

    let wallet_addr = addr_bytes(&pool_address());

    harness.elector_mock.expect_address().returning(|| elector_address());
    harness.elector_mock.expect_get_active_election_id().returning(|| Ok(ELECTION_ID));

    let wallet_addr_clone = wallet_addr.clone();
    harness.elector_mock.expect_elections_info().returning(move || {
        Ok(ElectionsInfo {
            election_id: ELECTION_ID,
            elect_close: ELECTION_ID + 600,
            min_stake: MIN_STAKE,
            total_stake: MIN_STAKE,
            failed: false,
            finished: false,
            participants: vec![Participant {
                pub_key: vec![0x08; 32],
                adnl_addr: ADNL_ADDR.to_vec(),
                wallet_addr: wallet_addr_clone.clone(),
                stake: MIN_STAKE,
                max_factor: 196608,
                election_id: ELECTION_ID,
                stake_message_boc: None,
            }],
        })
    });
    harness.elector_mock.expect_past_elections().returning(|| Ok(vec![]));
    harness.elector_mock.expect_compute_returned_stake().returning(|_| Ok(0));

    setup_wallet(&mut harness.wallet_mock);
    setup_pool(harness.pool_mock.as_mut().unwrap());

    let provider = &mut harness.provider_mock;
    provider.expect_election_parameters().returning(|| Ok(default_cfg15()));
    provider.expect_validator_config().returning(|| {
        let mut keys = HashMap::new();
        keys.insert(
            ELECTION_ID,
            ValidatorEntry {
                key_id: KEY_ID.to_vec(),
                public_key: vec![],
                adnl_addrs: vec![(ADNL_ADDR.to_vec(), ELECTION_ID + 7200)],
                expired_at: ELECTION_ID + 7200,
            },
        );
        Ok(ValidatorConfig { keys })
    });

    provider.expect_export_public_key().returning(|_| Ok(PUB_KEY.to_vec()));
    provider.expect_account().returning(|_| Ok(fake_account(WALLET_BALANCE)));
    provider.expect_shutdown().returning(|| Ok(()));

    let mut runner = harness.build(node_id);
    runner.refresh_validator_configs().await;
    let result = runner.run().await;
    assert!(result.is_ok(), "run() failed: {:?}", result.err());

    let node = runner.nodes.get(node_id).unwrap();
    assert!(node.stake_accepted, "stake should be accepted");
    assert!(node.participant.is_some());
    assert_eq!(node.participant.as_ref().unwrap().stake, MIN_STAKE);
}

// =====================================================
// TEST: recover stake
// =====================================================

#[tokio::test]
async fn test_recover_stake_returns_funds() {
    let node_id = "node-1";
    let mut harness = TestHarness::new();

    let returned_amount: u64 = 20_000_000_000_000; // 20 000 TOS

    // Elector has active elections, but node has stake to recover
    setup_default_elector(&mut harness.elector_mock, ELECTION_ID, returned_amount);
    setup_wallet(&mut harness.wallet_mock);

    let provider = &mut harness.provider_mock;
    provider.expect_election_parameters().returning(|| Ok(default_cfg15()));
    provider.expect_validator_config().returning(|| Ok(ValidatorConfig::new()));

    provider.expect_account().returning(|_| Ok(fake_account(WALLET_BALANCE)));
    // Expect send_boc to be called for recover
    provider.expect_send_boc().times(1).returning(|_| Ok(()));
    provider.expect_shutdown().returning(|| Ok(()));

    let mut runner = harness.build(node_id);
    let result = runner.run().await;
    assert!(result.is_ok(), "run() failed: {:?}", result.err());

    // When recover_amount > 0, the node should NOT participate in elections
    let node = runner.nodes.get(node_id).unwrap();
    assert!(node.participant.is_none(), "should not participate when recovering stake");
}

// =====================================================
// TEST: recover stake — low wallet balance
// =====================================================

#[tokio::test]
async fn test_recover_stake_low_wallet_balance() {
    let node_id = "node-1";
    let mut harness = TestHarness::new();

    let returned_amount: u64 = 20_000_000_000_000;
    let low_wallet_balance: u64 = 100_000_000; // 0.1 TOS — not enough for fees

    setup_default_elector(&mut harness.elector_mock, ELECTION_ID, returned_amount);
    setup_wallet(&mut harness.wallet_mock);

    let provider = &mut harness.provider_mock;
    provider.expect_election_parameters().returning(|| Ok(default_cfg15()));
    provider.expect_validator_config().returning(|| Ok(ValidatorConfig::new()));

    provider.expect_account().returning(move |_| Ok(fake_account(low_wallet_balance)));
    provider.expect_shutdown().returning(|| Ok(()));

    let mut runner = harness.build(node_id);
    let result = runner.run().await;
    // run() catches per-node errors and continues; it itself returns Ok
    assert!(result.is_ok());

    let node = runner.nodes.get(node_id).unwrap();
    assert!(node.last_error.is_some(), "should have an error on low balance");
}

// =====================================================
// TEST: no active elections
// =====================================================

#[tokio::test]
async fn test_no_active_elections() {
    let node_id = "node-1";
    let mut harness = TestHarness::new();

    setup_elector_no_elections(&mut harness.elector_mock);
    setup_wallet(&mut harness.wallet_mock);

    let provider = &mut harness.provider_mock;
    provider.expect_election_parameters().returning(|| Ok(default_cfg15()));
    provider.expect_validator_config().returning(|| Ok(ValidatorConfig::new()));

    provider.expect_shutdown().returning(|| Ok(()));

    let mut runner = harness.build(node_id);
    let result = runner.run().await;
    assert!(result.is_ok());

    assert_eq!(runner.snapshot_cache.last_elections_status, ElectionsStatus::Closed);
}

#[tokio::test]
async fn test_closed_elections_without_submission_stays_not_submitted() {
    let node_id = "node-1";
    let mut harness = TestHarness::new();

    setup_elector_no_elections(&mut harness.elector_mock);
    setup_wallet(&mut harness.wallet_mock);

    let provider = &mut harness.provider_mock;
    provider.expect_election_parameters().returning(|| Ok(default_cfg15()));
    provider.expect_shutdown().returning(|| Ok(()));

    let mut runner = harness.build(node_id);
    let result = runner.run().await;
    assert!(result.is_ok());
    assert_eq!(runner.snapshot_cache.last_elections_status, ElectionsStatus::Closed);

    // Simulate stale previous elections snapshot still present in cache.
    runner.snapshot_cache.last_elections = Some(ElectionsSnapshot {
        election_id: ELECTION_ID,
        elections_range: TimeRange {
            start: ELECTION_ID.saturating_sub(1800),
            start_utc: time_format::format_ts(ELECTION_ID.saturating_sub(1800)),
            end: ELECTION_ID.saturating_sub(600),
            end_utc: time_format::format_ts(ELECTION_ID.saturating_sub(600)),
        },
        ..Default::default()
    });

    let store = Arc::new(SnapshotStore::new());
    runner.publish_snapshot(&store).await;
    let snapshot = store.get();
    let node_snapshot = &snapshot.validators.controlled_nodes[0];

    assert!(!node_snapshot.is_validator);
    assert!(node_snapshot.validator_index.is_none());
}

// =====================================================
// TEST: excluded node skips elections
// =====================================================

#[tokio::test]
async fn test_excluded_node_skips_elections() {
    let node_id = "node-1";
    let mut harness = TestHarness::new();
    harness.bindings.insert(node_id.to_string(), default_binding(false));
    setup_default_elector(&mut harness.elector_mock, ELECTION_ID, 0);
    setup_wallet(&mut harness.wallet_mock);

    let provider = &mut harness.provider_mock;
    provider.expect_election_parameters().returning(|| Ok(default_cfg15()));
    provider.expect_validator_config().returning(|| Ok(ValidatorConfig::new()));

    provider.expect_export_public_key().returning(|_| Ok(PUB_KEY.to_vec()));
    provider.expect_account().returning(|_| Ok(fake_account(WALLET_BALANCE)));
    provider.expect_shutdown().returning(|| Ok(()));

    let mut runner = harness.build(node_id);
    let result = runner.run().await;
    assert!(result.is_ok());

    let node = runner.nodes.get(node_id).unwrap();
    assert!(node.participant.is_none(), "excluded node should not participate");
}

// =====================================================
// TEST: elections finished — stake_accepted set
// =====================================================

#[tokio::test]
async fn test_elections_finished_stake_accepted() {
    let node_id = "node-1";
    let mut harness = TestHarness::new().with_pool();
    harness.elections_config.policy = StakePolicy::Minimum;

    let wallet_addr_clone = addr_bytes(&pool_address());
    harness.elector_mock.expect_elections_info().returning(move || {
        Ok(ElectionsInfo {
            election_id: ELECTION_ID,
            elect_close: ELECTION_ID + 3600,
            min_stake: MIN_STAKE,
            total_stake: 0,
            failed: true,
            finished: true,
            participants: vec![Participant {
                pub_key: vec![0x08; 32],
                adnl_addr: ADNL_ADDR.to_vec(),
                wallet_addr: wallet_addr_clone.clone(),
                stake: MIN_STAKE,
                max_factor: 196608,
                election_id: ELECTION_ID,
                stake_message_boc: None,
            }],
        })
    });

    harness.provider_mock.expect_send_boc().never();

    setup_default_elector(&mut harness.elector_mock, ELECTION_ID, 0);
    setup_default_provider(&mut harness.provider_mock, WALLET_BALANCE, Some(POOL_BALANCE));

    setup_wallet(&mut harness.wallet_mock);
    setup_pool(harness.pool_mock.as_mut().unwrap());
    let mut runner = harness.build(node_id);
    let result = runner.run().await;
    assert!(result.is_ok());

    assert_eq!(runner.snapshot_cache.last_elections_status, ElectionsStatus::Finished);
    let node = runner.nodes.get(node_id).unwrap();
    assert!(node.stake_accepted);
}

// =====================================================
// TEST: run_loop cancellation
// =====================================================

#[tokio::test]
async fn test_run_loop_cancellation() {
    let node_id = "node-1";
    let mut harness = TestHarness::new();

    setup_default_provider(&mut harness.provider_mock, WALLET_BALANCE, Some(POOL_BALANCE));
    setup_elector_no_elections(&mut harness.elector_mock);
    setup_wallet(&mut harness.wallet_mock);

    let mut runner = harness.build(node_id);

    let mut ctx = CancellationCtx::new();
    let cancel_ctx = ctx.clone();
    let store = Arc::new(SnapshotStore::new());

    // Send cancel signal after short delay
    let cancel_handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        ctx.cancel(CancellationReason::GracefullyShutdown());
    });

    let result = runner.run_loop(Duration::from_secs(600), cancel_ctx, store, None).await;
    assert!(result.is_ok(), "run_loop should return Ok on cancel");

    tokio::select! {
        _ = cancel_handle => {}
        _ = tokio::time::sleep(Duration::from_secs(60)) => {
            panic!("run_loop should be cancelled by the cancel signal");
        }
    }
}

// =====================================================
// TEST: run_loop executes tick then cancels
// =====================================================

#[tokio::test]
async fn test_run_loop_tick_then_cancel() {
    let node_id = "node-1";
    let mut harness = TestHarness::new();

    // First call: active elections. Second call onwards: no elections.
    let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let cc = call_count.clone();

    harness.elector_mock.expect_address().returning(|| elector_address());
    harness.elector_mock.expect_get_active_election_id().returning(move || {
        let n = cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n == 0 { Ok(ELECTION_ID) } else { Ok(0) }
    });
    harness.elector_mock.expect_elections_info().returning(move || {
        Ok(ElectionsInfo {
            election_id: ELECTION_ID,
            elect_close: ELECTION_ID + 600,
            min_stake: MIN_STAKE,
            total_stake: 0,
            failed: false,
            finished: false,
            participants: vec![],
        })
    });
    harness.elector_mock.expect_past_elections().returning(|| Ok(vec![]));
    harness.elector_mock.expect_compute_returned_stake().returning(|_| Ok(0));

    setup_wallet(&mut harness.wallet_mock);
    setup_default_provider(&mut harness.provider_mock, WALLET_BALANCE, None);

    let mut runner = harness.build(node_id);
    let mut ctx = CancellationCtx::new();
    let cancel_ctx = ctx.clone();
    let store = Arc::new(SnapshotStore::new());

    // Cancel after one tick
    let cancel_handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        ctx.cancel(CancellationReason::GracefullyShutdown());
    });

    let result = runner.run_loop(Duration::from_millis(50), cancel_ctx, store.clone(), None).await;
    assert!(result.is_ok());

    cancel_handle.await.unwrap();

    // Snapshot should have been published
    let snapshot = store.get();
    // At least one tick happened
    assert!(snapshot.generated_at > 0);
}

// =====================================================
// TEST: fixed stake policy
// =====================================================

#[tokio::test]
async fn test_fixed_stake_policy() {
    let node_id = "node-1";
    let mut harness = TestHarness::new();
    let fixed_stake: u64 = 15_000_000_000_000; // 15 000 TOS
    harness.elections_config.policy = StakePolicy::Fixed(fixed_stake);

    setup_default_elector(&mut harness.elector_mock, ELECTION_ID, 0);
    setup_default_provider(&mut harness.provider_mock, WALLET_BALANCE, None);
    setup_wallet(&mut harness.wallet_mock);

    let mut runner = harness.build(node_id);
    let result = runner.run().await;
    assert!(result.is_ok(), "run() failed: {:?}", result.err());

    let node = runner.nodes.get(node_id).unwrap();
    assert!(node.participant.is_some());
    assert_eq!(node.participant.as_ref().unwrap().stake, fixed_stake);
}

// =====================================================
// TEST: minimum stake policy
// =====================================================

#[tokio::test]
async fn test_minimum_stake_policy() {
    let node_id = "node-1";
    let mut harness = TestHarness::new();
    harness.elections_config.policy = StakePolicy::Minimum;

    setup_default_elector(&mut harness.elector_mock, ELECTION_ID, 0);
    setup_default_provider(&mut harness.provider_mock, WALLET_BALANCE, None);
    setup_wallet(&mut harness.wallet_mock);

    let mut runner = harness.build(node_id);
    let result = runner.run().await;
    assert!(result.is_ok(), "run() failed: {:?}", result.err());

    let node = runner.nodes.get(node_id).unwrap();
    assert!(node.participant.is_some());
    assert_eq!(node.participant.as_ref().unwrap().stake, MIN_STAKE);
}

// =====================================================
// TEST: recover stake with frozen funds from past elections
// =====================================================

#[tokio::test]
async fn test_recover_with_past_elections_frozen() {
    let node_id = "node-1";
    let mut harness = TestHarness::new();
    let past_election_id = ELECTION_ID - 3600;
    let frozen_stake: u64 = 10_000_000_000_000;

    setup_default_elector(&mut harness.elector_mock, ELECTION_ID, 0);
    setup_default_provider(&mut harness.provider_mock, WALLET_BALANCE, Some(POOL_BALANCE));

    // Past elections with frozen stake
    harness.elector_mock.expect_past_elections().returning(move || {
        let mut frozen_map = HashMap::new();
        frozen_map.insert(
            PUB_KEY,
            FrozenParticipant {
                wallet_addr: [0xAAu8; 32],
                weight: 123456789123456789,
                stake: frozen_stake,
                banned: false,
            },
        );
        Ok(vec![PastElections {
            election_id: past_election_id,
            unfreeze_at: ELECTION_ID + 3600,
            stake_held: 7200,
            vset_hash: vec![0u8; 32],
            frozen_map,
            total_stake: frozen_stake,
            bonuses: 0,
        }])
    });

    setup_wallet(&mut harness.wallet_mock);

    // Return key for past election as well as current
    harness.provider_mock.expect_validator_config().returning(move || {
        let mut keys = HashMap::new();
        keys.insert(
            past_election_id,
            ValidatorEntry {
                key_id: KEY_ID.to_vec(),
                public_key: vec![],
                adnl_addrs: vec![(ADNL_ADDR.to_vec(), past_election_id + 7200)],
                expired_at: past_election_id + 7200,
            },
        );
        Ok(ValidatorConfig { keys })
    });

    let mut runner = harness.build(node_id);
    let result = runner.run().await;
    assert!(result.is_ok(), "run() failed: {:?}", result.err());

    // Node should participate; the frozen stake should be factored into calc_stake
    let node = runner.nodes.get(node_id).unwrap();
    assert!(node.participant.is_some());
    let p = node.participant.as_ref().unwrap();
    // With Split50 policy, stake = max(total_balance / 2, min_stake)
    // total_balance = frozen_stake + pool_free_balance + 0
    // pool_free_balance = WALLET_BALANCE - gas_fee - MIN_NANOTOS_FOR_STORAGE
    assert!(p.stake >= MIN_STAKE, "stake should be at least min_stake");
}

// =====================================================
// TEST: low stake balance prevents participation
// =====================================================

#[tokio::test]
async fn test_low_stake_balance() {
    let node_id = "node-1";
    let mut harness = TestHarness::new();
    let low_balance: u64 = 5_000_000_000; // 5 TOS — much less than min stake

    setup_default_elector(&mut harness.elector_mock, ELECTION_ID, 0);
    setup_wallet(&mut harness.wallet_mock);

    let provider = &mut harness.provider_mock;
    provider.expect_election_parameters().returning(|| Ok(default_cfg15()));
    provider.expect_validator_config().returning(|| Ok(ValidatorConfig::new()));

    provider.expect_export_public_key().returning(|_| Ok(PUB_KEY.to_vec()));
    provider.expect_account().returning(move |_| Ok(fake_account(low_balance)));
    provider.expect_new_validator_key().returning(|_, _| Ok((KEY_ID.to_vec(), PUB_KEY.to_vec())));
    provider.expect_new_adnl_addr().returning(|_, _| Ok(ADNL_ADDR.to_vec()));

    provider.expect_shutdown().returning(|| Ok(()));

    let mut runner = harness.build(node_id);
    let result = runner.run().await;
    // run() itself is Ok, but the node should have an error
    assert!(result.is_ok());

    let node = runner.nodes.get(node_id).unwrap();
    assert!(node.last_error.is_some(), "should have an error for low balance");
    let err = node.last_error.as_ref().unwrap();
    assert!(
        err.contains("not enough") || err.contains("low stake"),
        "error should mention insufficient balance, got: {}",
        err
    );
}

// =====================================================
// TEST: shutdown calls provider shutdown
// =====================================================

#[tokio::test]
async fn test_shutdown() {
    let node_id = "node-1";
    let mut harness = TestHarness::new();

    setup_elector_no_elections(&mut harness.elector_mock);
    setup_wallet(&mut harness.wallet_mock);

    let provider = &mut harness.provider_mock;
    provider.expect_shutdown().times(1).returning(|| Ok(()));
    provider.expect_election_parameters().returning(|| Ok(default_cfg15()));
    provider.expect_validator_config().returning(|| Ok(ValidatorConfig::new()));

    let mut runner = harness.build(node_id);
    let result = runner.shutdown().await;
    assert!(result.is_ok());
}

// =====================================================
// TEST: multiple nodes
// =====================================================

#[tokio::test]
async fn test_multiple_nodes_one_excluded() {
    // Build runner manually with two nodes
    let mut elector_mock = MockElectorWrapperImpl::new();
    setup_default_elector(&mut elector_mock, ELECTION_ID, 0);

    let elector = Arc::new(elector_mock);

    let elections_config = ElectionsConfig {
        policy: StakePolicy::Minimum,
        policy_overrides: HashMap::new(),
        max_factor: 3.0,
        tick_interval: 10,
    };

    let mut bindings = HashMap::new();
    bindings.insert(
        "node-1".to_string(),
        NodeBinding {
            wallet: "w1".to_string(),
            pool: None,
            enable: true,
            status: Default::default(),
        },
    );
    bindings.insert(
        "node-2".to_string(),
        NodeBinding {
            wallet: "w2".to_string(),
            pool: None,
            enable: false,
            status: Default::default(),
        },
    );

    let mut wallet1 = MockWalletImpl::new();
    wallet1.expect_address().returning(|| wallet_address());
    wallet1.expect_message().returning(|_, _, _| Ok(dummy_cell()));

    let mut wallet2 = MockWalletImpl::new();
    wallet2.expect_address().returning(|| MsgAddressInt::standard(-1, [0xCCu8; 32]));
    wallet2.expect_message().returning(|_, _, _| Ok(dummy_cell()));

    let mut wallets: HashMap<String, Arc<dyn Wallet>> = HashMap::new();
    wallets.insert("node-1".to_string(), Arc::new(wallet1));
    wallets.insert("node-2".to_string(), Arc::new(wallet2));

    let mut provider1 = MockElectionsProviderImpl::new();
    setup_default_provider(&mut provider1, WALLET_BALANCE, None);
    fixture_snapshot(&mut provider1, elector.clone());

    let mut provider2 = MockElectionsProviderImpl::new();
    provider2.expect_election_parameters().returning(|| Ok(default_cfg15()));
    provider2.expect_validator_config().returning(|| Ok(ValidatorConfig::new()));
    provider2.expect_get_current_vset().returning(|| Err(anyhow::anyhow!("no vset")));
    provider2.expect_get_next_vset().returning(|| Ok(None));
    provider2.expect_export_public_key().returning(|_| Ok(PUB_KEY.to_vec()));
    provider2.expect_account().returning(|_| Ok(fake_account(WALLET_BALANCE)));
    provider2.expect_shutdown().returning(|| Ok(()));

    let mut providers: HashMap<String, Box<dyn ElectionsProvider>> = HashMap::new();
    providers.insert("node-1".to_string(), Box::new(provider1));
    providers.insert("node-2".to_string(), Box::new(provider2));

    let pools = HashMap::new();

    let mut runner = ElectionRunner::new(
        &elections_config,
        &bindings,
        elector,
        providers,
        Arc::new(wallets),
        Arc::new(pools),
    );

    let result = runner.run().await;
    assert!(result.is_ok());

    // node-1 should participate
    let node1 = runner.nodes.get("node-1").unwrap();
    assert!(node1.participant.is_some(), "node-1 should participate");

    // node-2 is excluded — should not participate
    let node2 = runner.nodes.get("node-2").unwrap();
    assert!(node2.participant.is_none(), "node-2 (excluded) should not participate");
}

// =====================================================
// TEST: elections failed status
// =====================================================

#[tokio::test]
async fn test_elections_failed_still_processes_nodes() {
    let node_id = "node-1";
    let mut harness = TestHarness::new();

    harness.elector_mock.expect_address().returning(|| elector_address());
    harness.elector_mock.expect_get_active_election_id().returning(|| Ok(ELECTION_ID));

    harness.elector_mock.expect_elections_info().returning(move || {
        Ok(ElectionsInfo {
            election_id: ELECTION_ID,
            elect_close: ELECTION_ID + 600,
            min_stake: MIN_STAKE,
            total_stake: 0,
            failed: true,
            finished: false,
            participants: vec![],
        })
    });
    harness.elector_mock.expect_past_elections().returning(|| Ok(vec![]));
    harness.elector_mock.expect_compute_returned_stake().returning(|_| Ok(0));

    setup_wallet(&mut harness.wallet_mock);
    setup_default_provider(&mut harness.provider_mock, WALLET_BALANCE, None);

    let mut runner = harness.build(node_id);
    let result = runner.run().await;
    assert!(result.is_ok(), "run() failed: {:?}", result.err());

    // Unlike finished elections, failed elections don't cause early return —
    // the runner still processes nodes and tries to participate.
    let node = runner.nodes.get(node_id).unwrap();
    assert!(
        node.participant.is_some(),
        "node should still participate despite elections being marked as failed"
    );

    // The elections snapshot should be built
    assert!(runner.snapshot_cache.last_elections.is_some());
    let snapshot = runner.snapshot_cache.last_elections.as_ref().unwrap();
    assert!(snapshot.failed, "snapshot should reflect failed=true");
}

// =====================================================
// TEST: elections finished but node NOT in participants
// =====================================================

#[tokio::test]
async fn test_elections_finished_node_not_in_participants() {
    let node_id = "node-1";
    let mut harness = TestHarness::new();

    harness.elector_mock.expect_address().returning(|| elector_address());
    harness.elector_mock.expect_get_active_election_id().returning(|| Ok(ELECTION_ID));

    // Finished elections with a different participant
    harness.elector_mock.expect_elections_info().returning(move || {
        Ok(ElectionsInfo {
            election_id: ELECTION_ID,
            elect_close: ELECTION_ID + 600,
            min_stake: MIN_STAKE,
            total_stake: MIN_STAKE,
            failed: false,
            finished: true,
            participants: vec![Participant {
                pub_key: [0xFFu8; 32].to_vec(),
                adnl_addr: [0xFFu8; 32].to_vec(),
                wallet_addr: [0xFFu8; 32].to_vec(),
                stake: MIN_STAKE,
                max_factor: 196608,
                election_id: ELECTION_ID,
                stake_message_boc: None,
            }],
        })
    });

    setup_wallet(&mut harness.wallet_mock);

    let provider = &mut harness.provider_mock;
    provider.expect_election_parameters().returning(|| Ok(default_cfg15()));
    provider.expect_validator_config().returning(|| Ok(ValidatorConfig::new()));

    provider.expect_shutdown().returning(|| Ok(()));

    let mut runner = harness.build(node_id);
    let result = runner.run().await;
    assert!(result.is_ok());

    assert_eq!(runner.snapshot_cache.last_elections_status, ElectionsStatus::Finished);
    let node = runner.nodes.get(node_id).unwrap();
    assert!(!node.stake_accepted, "node should NOT have stake accepted");
}

// =====================================================
// TEST: election parameters — all nodes fail
// =====================================================

#[tokio::test]
async fn test_election_parameters_all_nodes_fail() {
    let node_id = "node-1";
    let mut harness = TestHarness::new();

    setup_elector_no_elections(&mut harness.elector_mock);
    setup_wallet(&mut harness.wallet_mock);

    let provider = &mut harness.provider_mock;
    provider.expect_election_parameters().returning(|| Err(anyhow::anyhow!("cfg15 unavailable")));
    provider.expect_validator_config().returning(|| Ok(ValidatorConfig::new()));

    provider.expect_shutdown().returning(|| Ok(()));

    let mut runner = harness.build(node_id);
    let result = runner.run().await;
    assert!(result.is_err(), "run() should fail when all nodes fail to return cfg15");
    let err = result.unwrap_err();
    assert!(
        format!("{:#}", err).contains("election parameters"),
        "error should mention election parameters, got: {:#}",
        err
    );
}

// =====================================================
// TEST: new_validator_key failure
// =====================================================

#[tokio::test]
async fn test_new_validator_key_failure() {
    let node_id = "node-1";
    let mut harness = TestHarness::new();

    setup_default_elector(&mut harness.elector_mock, ELECTION_ID, 0);
    setup_wallet(&mut harness.wallet_mock);

    let provider = &mut harness.provider_mock;
    provider.expect_election_parameters().returning(|| Ok(default_cfg15()));
    provider.expect_validator_config().returning(|| Ok(ValidatorConfig::new()));

    provider.expect_export_public_key().returning(|_| Ok(PUB_KEY.to_vec()));
    provider.expect_account().returning(|_| Ok(fake_account(WALLET_BALANCE)));
    provider.expect_new_validator_key().returning(|_, _| Err(anyhow::anyhow!("keygen failed")));
    provider.expect_shutdown().returning(|| Ok(()));

    let mut runner = harness.build(node_id);
    let result = runner.run().await;
    assert!(result.is_ok(), "run() should still be Ok, per-node error captured");

    let node = runner.nodes.get(node_id).unwrap();
    assert!(node.last_error.is_some(), "should record key generation error");
    let err = node.last_error.as_ref().unwrap();
    assert!(
        err.contains("keygen failed") || err.contains("validator key"),
        "error should mention key generation, got: {}",
        err
    );
}

// =====================================================
// TEST: send_boc failure
// =====================================================

#[tokio::test]
async fn test_send_boc_failure() {
    let node_id = "node-1";
    let mut harness = TestHarness::new().with_pool();

    setup_default_elector(&mut harness.elector_mock, ELECTION_ID, 0);
    setup_wallet(&mut harness.wallet_mock);
    setup_pool(harness.pool_mock.as_mut().unwrap());

    let provider = &mut harness.provider_mock;
    provider.expect_election_parameters().returning(|| Ok(default_cfg15()));
    provider.expect_validator_config().returning(|| Ok(ValidatorConfig::new()));

    provider.expect_export_public_key().returning(|_| Ok(PUB_KEY.to_vec()));
    provider.expect_account().returning(|_| Ok(fake_account(WALLET_BALANCE)));
    provider.expect_new_validator_key().returning(|_, _| Ok((KEY_ID.to_vec(), PUB_KEY.to_vec())));
    provider.expect_new_adnl_addr().returning(|_, _| Ok(ADNL_ADDR.to_vec()));

    provider.expect_send_boc().returning(|_| Err(anyhow::anyhow!("broadcast failed")));
    provider.expect_shutdown().returning(|| Ok(()));
    provider.expect_sign().returning(|_key, _data| Ok(SIGNATURE.to_vec()));
    provider.expect_create_pq_stake_authorization().returning(|_, _, _, _| {
        Ok(control_client::client_api::PqStakeAuthorization {
            validator_id: POOL_ADDR.to_vec(),
            key_id: vec![0x08; 32],
            algorithm_id: 1,
            public_key: PQ_PUBLIC_KEY.to_vec(),
            signature: PQ_SIGNATURE.to_vec(),
        })
    });

    let mut runner = harness.build(node_id);
    let result = runner.run().await;
    assert!(result.is_ok(), "run() should be Ok, per-node error captured");

    let node = runner.nodes.get(node_id).unwrap();
    assert!(node.last_error.is_some(), "should record send_boc error");
    let err = node.last_error.as_ref().unwrap();
    assert!(
        err.contains("broadcast failed"),
        "error should mention broadcast failure, got: {}",
        err
    );
}

// =====================================================
// TEST: Split50 stake calculation
// =====================================================

#[tokio::test]
async fn test_split50_stake_calculation() {
    let node_id = "node-1";
    let mut harness = TestHarness::new();
    harness.elections_config.policy = StakePolicy::Split50;

    setup_default_elector(&mut harness.elector_mock, ELECTION_ID, 0);
    setup_default_provider(&mut harness.provider_mock, WALLET_BALANCE, None);
    setup_wallet(&mut harness.wallet_mock);

    let mut runner = harness.build(node_id);
    let result = runner.run().await;
    assert!(result.is_ok(), "run() failed: {:?}", result.err());

    let node = runner.nodes.get(node_id).unwrap();
    assert!(node.participant.is_some());
    let p = node.participant.as_ref().unwrap();

    // With Split50: stake = max(total_balance / 2, min_stake)
    // total_balance = frozen_stake(0) + pool_free_balance + elections_stake(0)
    // pool_free_balance = WALLET_BALANCE - gas_fee - MIN_NANOTOS_FOR_STORAGE
    let gas_fee = ELECTOR_STAKE_FEE + NPOOL_COMPUTE_FEE;
    let pool_free_balance = WALLET_BALANCE - gas_fee - MIN_NANOTOS_FOR_STORAGE;
    let expected = (pool_free_balance / 2).max(MIN_STAKE);
    assert_eq!(
        p.stake, expected,
        "Split50 stake mismatch: expected={}, actual={}",
        expected, p.stake
    );
}

// =====================================================
// TEST: build_elections_snapshot
// =====================================================

#[tokio::test]
async fn test_build_elections_snapshot() {
    let node_id = "node-1";
    let mut harness = TestHarness::new();

    let wallet_addr = addr_bytes(&wallet_address());

    harness.elector_mock.expect_address().returning(|| elector_address());
    harness.elector_mock.expect_get_active_election_id().returning(|| Ok(ELECTION_ID));

    let wallet_addr_clone = wallet_addr.clone();
    harness.elector_mock.expect_elections_info().returning(move || {
        Ok(ElectionsInfo {
            election_id: ELECTION_ID,
            elect_close: ELECTION_ID + 600,
            min_stake: MIN_STAKE,
            total_stake: MIN_STAKE * 3,
            failed: false,
            finished: false,
            participants: vec![
                Participant {
                    pub_key: PUB_KEY.to_vec(),
                    adnl_addr: ADNL_ADDR.to_vec(),
                    wallet_addr: wallet_addr_clone.clone(),
                    stake: MIN_STAKE,
                    max_factor: 196608,
                    election_id: ELECTION_ID,
                    stake_message_boc: None,
                },
                Participant {
                    pub_key: [0xDD; 32].to_vec(),
                    adnl_addr: [0xEE; 32].to_vec(),
                    wallet_addr: [0xFF; 32].to_vec(),
                    stake: MIN_STAKE * 2,
                    max_factor: 196608,
                    election_id: ELECTION_ID,
                    stake_message_boc: None,
                },
            ],
        })
    });
    harness.elector_mock.expect_past_elections().returning(|| Ok(vec![]));
    harness.elector_mock.expect_compute_returned_stake().returning(|_| Ok(0));

    setup_wallet(&mut harness.wallet_mock);
    setup_default_provider(&mut harness.provider_mock, WALLET_BALANCE, None);

    let mut runner = harness.build(node_id);
    let result = runner.run().await;
    assert!(result.is_ok(), "run() failed: {:?}", result.err());

    let snapshot = runner.snapshot_cache.last_elections.as_ref().expect("snapshot should exist");
    assert_eq!(snapshot.election_id, ELECTION_ID);
    assert_eq!(snapshot.elect_close, ELECTION_ID + 600);
    assert!(!snapshot.finished);
    assert!(!snapshot.failed);
    assert_eq!(snapshot.participants_count, 2);
    assert_eq!(snapshot.min_stake, nanotos_to_dec_string(MIN_STAKE));
    assert_eq!(snapshot.participant_min_stake, Some(nanotos_to_dec_string(MIN_STAKE)));
    assert_eq!(snapshot.participant_max_stake, Some(nanotos_to_dec_string(MIN_STAKE * 2)));
    assert_eq!(snapshot.total_stake, nanotos_to_dec_string(MIN_STAKE * 3));

    // Validation range
    assert_eq!(snapshot.next_validation_range.start, ELECTION_ID);
    assert_eq!(
        snapshot.next_validation_range.end,
        ELECTION_ID + default_cfg15().validators_elected_for as u64
    );

    // Elections range
    assert_eq!(
        snapshot.elections_range.start,
        ELECTION_ID - default_cfg15().elections_start_before as u64
    );
    assert_eq!(
        snapshot.elections_range.end,
        ELECTION_ID - default_cfg15().elections_end_before as u64
    );

    // Check participants snapshot
    assert_eq!(snapshot.participants.len(), 2);
    let our_participant = snapshot
        .participants
        .iter()
        .find(|p| p.is_controlled)
        .expect("should have controlled participant");
    assert_eq!(
        our_participant.pubkey,
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &PUB_KEY)
    );
    assert_eq!(our_participant.stake, nanotos_to_dec_string(MIN_STAKE));

    let other_participant = snapshot
        .participants
        .iter()
        .find(|p| !p.is_controlled)
        .expect("should have non-controlled participant");
    assert_eq!(
        other_participant.pubkey,
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0xDD; 32])
    );
}

// =====================================================
// TEST: node without wallet is filtered out
// =====================================================

#[tokio::test]
async fn test_node_without_wallet_skipped() {
    let mut elector_mock = MockElectorWrapperImpl::new();
    setup_elector_no_elections(&mut elector_mock);
    let elector = Arc::new(elector_mock);

    let elections_config = ElectionsConfig {
        policy: StakePolicy::Minimum,
        policy_overrides: HashMap::new(),
        max_factor: 3.0,
        tick_interval: 10,
    };

    let mut bindings = HashMap::new();
    bindings.insert("node-1".to_string(), default_binding(true));

    // Provider for "node-1" exists, but no wallet for it
    let mut provider1 = MockElectionsProviderImpl::new();
    provider1.expect_shutdown().returning(|| Ok(()));

    let mut providers: HashMap<String, Box<dyn ElectionsProvider>> = HashMap::new();
    providers.insert("node-1".to_string(), Box::new(provider1));

    let wallets: HashMap<String, Arc<dyn Wallet>> = HashMap::new(); // empty!
    let pools: HashMap<String, Arc<dyn NominatorWrapper>> = HashMap::new();

    let runner = ElectionRunner::new(
        &elections_config,
        &bindings,
        elector,
        providers,
        Arc::new(wallets),
        Arc::new(pools),
    );

    assert!(
        runner.nodes.is_empty(),
        "node without wallet should be filtered out, got {} nodes",
        runner.nodes.len()
    );
}

// =====================================================
// TEST: second run() — key exists and stake in elector
// =====================================================

#[tokio::test]
async fn test_second_tick_stake_already_sent() {
    let node_id = "node-1";
    let mut harness = TestHarness::new().with_pool();
    let wallet_addr = addr_bytes(&pool_address());

    // First call: no participants. Second call: node is in participants.
    let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let cc = call_count.clone();
    let wallet_addr_clone = wallet_addr.clone();
    harness.elector_mock.expect_elections_info().times(2).returning(move || {
        let n = cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n == 0 {
            Ok(ElectionsInfo {
                election_id: ELECTION_ID,
                elect_close: u64::MAX,
                min_stake: MIN_STAKE,
                total_stake: 0,
                failed: false,
                finished: false,
                participants: vec![],
            })
        } else {
            Ok(ElectionsInfo {
                election_id: ELECTION_ID,
                elect_close: u64::MAX,
                min_stake: MIN_STAKE,
                total_stake: MIN_STAKE,
                failed: false,
                finished: false,
                participants: vec![Participant {
                    pub_key: vec![0x08; 32],
                    adnl_addr: ADNL_ADDR.to_vec(),
                    wallet_addr: wallet_addr_clone.clone(),
                    stake: MIN_STAKE,
                    max_factor: 196608,
                    election_id: ELECTION_ID,
                    stake_message_boc: None,
                }],
            })
        }
    });

    setup_wallet(&mut harness.wallet_mock);
    setup_pool(harness.pool_mock.as_mut().unwrap());

    // Provider: first validator_config call returns empty (new key path),
    // second returns the generated key (re-stake path).
    let vc_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let vcc = vc_count.clone();
    let provider = &mut harness.provider_mock;
    provider.expect_validator_config().times(2).returning(move || {
        let n = vcc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n == 0 {
            Ok(ValidatorConfig::new())
        } else {
            let mut keys = HashMap::new();
            keys.insert(
                ELECTION_ID,
                ValidatorEntry {
                    key_id: KEY_ID.to_vec(),
                    public_key: vec![],
                    adnl_addrs: vec![(ADNL_ADDR.to_vec(), ELECTION_ID + 7200)],
                    expired_at: ELECTION_ID + 7200,
                },
            );
            Ok(ValidatorConfig { keys })
        }
    });

    setup_default_elector(&mut harness.elector_mock, ELECTION_ID, 0);
    setup_default_provider(&mut harness.provider_mock, WALLET_BALANCE, Some(POOL_BALANCE));

    let mut runner = harness.build(node_id);

    // First tick: no key → generates new key, sends stake
    runner.refresh_validator_configs().await;
    runner.refresh_validator_set().await;
    let r1 = runner.run().await;
    assert!(r1.is_ok(), "first run() failed: {:?}", r1.err());
    let node = runner.nodes.get(node_id).unwrap();
    assert!(node.participant.is_some(), "should participate after first tick");
    assert!(!node.stake_accepted, "stake not yet accepted by elector");
    assert_eq!(runner.snapshot_cache.last_elections_status, ElectionsStatus::Active);

    // Second tick: validator_config now returns key, elector has participant
    runner.refresh_validator_configs().await;
    runner.refresh_validator_set().await;
    let r2 = runner.run().await;
    assert!(r2.is_ok(), "second run() failed: {:?}", r2.err());
    let node = runner.nodes.get(node_id).unwrap();
    assert!(node.participant.is_some());
    assert!(node.stake_accepted, "stake should be accepted on second tick");
}

// =====================================================
// TEST: publish_snapshot validators
// =====================================================

#[tokio::test]
async fn test_publish_snapshot_validators() {
    let node_id = "node-1";
    let mut harness = TestHarness::new();

    setup_default_elector(&mut harness.elector_mock, ELECTION_ID, 0);
    setup_default_provider(&mut harness.provider_mock, WALLET_BALANCE, None);
    setup_wallet(&mut harness.wallet_mock);

    let mut runner = harness.build(node_id);
    let _ = runner.run().await;

    let store = Arc::new(SnapshotStore::new());
    runner.publish_snapshot(&store).await;

    let snapshot = store.get();
    assert!(snapshot.generated_at > 0);

    let validators = &snapshot.validators;
    assert_eq!(validators.controlled_nodes.len(), 1);

    let node_snapshot = &validators.controlled_nodes[0];
    assert_eq!(node_snapshot.node_id, node_id);
    assert!(node_snapshot.wallet_addr.is_some());
    assert!(node_snapshot.pubkey.is_some());
    assert!(node_snapshot.adnl.is_some());
    assert!(node_snapshot.key_id.is_some());
    assert!(node_snapshot.stake.is_some());
    assert!(!node_snapshot.is_validator, "not in vset");
}

// =====================================================
// TEST: policy override per node
// =====================================================

#[tokio::test]
async fn test_policy_override_per_node() {
    let node_id = "node-1";
    let fixed_override: u64 = 20_000_000_000_000; // 20 000 TOS
    let mut harness = TestHarness::new();
    harness.elections_config.policy = StakePolicy::Minimum;
    harness
        .elections_config
        .policy_overrides
        .insert(node_id.to_string(), StakePolicy::Fixed(fixed_override));

    setup_default_elector(&mut harness.elector_mock, ELECTION_ID, 0);
    setup_default_provider(&mut harness.provider_mock, WALLET_BALANCE, None);
    setup_wallet(&mut harness.wallet_mock);

    let mut runner = harness.build(node_id);
    let result = runner.run().await;
    assert!(result.is_ok(), "run() failed: {:?}", result.err());

    let node = runner.nodes.get(node_id).unwrap();
    assert!(node.participant.is_some());
    let p = node.participant.as_ref().unwrap();
    assert_eq!(
        p.stake, fixed_override,
        "per-node override should use Fixed(20000 TOS), got: {} nanotos",
        p.stake
    );
}

// =====================================================
// TEST: withf — verify wallet.message() payload and
//       send_boc() receives valid external message
// =====================================================

#[tokio::test]
async fn test_withf_verify_stake_message_payload() {
    let node_id = "node-1";
    let mut harness = TestHarness::new();
    let fixed_stake: u64 = 15_000_000_000_000; // 15 000 TOS
    harness.elections_config.policy = StakePolicy::Fixed(fixed_stake);

    setup_default_elector(&mut harness.elector_mock, ELECTION_ID, 0);

    // -- wallet mock: verify dest, value, and payload body --
    let wallet = &mut harness.wallet_mock;
    wallet.expect_address().returning(|| wallet_address());

    wallet
        .expect_message()
        .withf(move |dest, value, payload| {
            validate_message_parameters(dest, value, payload, fixed_stake, false)
        })
        .returning(|_dest, _value, _payload| Ok(dummy_cell()));

    // -- provider mock --
    let provider = &mut harness.provider_mock;
    // -- send_boc: verify the BOC is a parseable single-root Cell --
    provider
        .expect_send_boc()
        .withf(|boc: &[u8]| match read_single_root_boc(boc) {
            Ok(_cell) => true,
            Err(e) => {
                eprintln!("withf send_boc: BOC is not parseable: {}", e);
                false
            }
        })
        .returning(|_| Ok(()));

    setup_default_provider(&mut harness.provider_mock, WALLET_BALANCE, Some(POOL_BALANCE));

    let mut runner = harness.build(node_id);
    let result = runner.run().await;
    assert!(result.is_ok(), "run() failed: {:?}", result.err());

    let node = runner.nodes.get(node_id).unwrap();
    assert!(node.participant.is_some());
    assert_eq!(node.participant.as_ref().unwrap().stake, fixed_stake);
}

// =====================================================
// TESTS: compute_node_status
// =====================================================

#[test]
fn test_compute_status_idle_when_excluded_no_recover() {
    use common::app_config::BindingStatus;
    let status = ElectionRunner::compute_node_status(true, false, false, false);
    assert_eq!(status, BindingStatus::Idle);
}

#[test]
fn test_compute_status_draining_when_excluded_with_recover() {
    use common::app_config::BindingStatus;
    let status = ElectionRunner::compute_node_status(true, false, true, false);
    assert_eq!(status, BindingStatus::Draining);
}

#[test]
fn test_compute_status_validating_when_in_vset() {
    use common::app_config::BindingStatus;
    let status = ElectionRunner::compute_node_status(false, true, false, true);
    assert_eq!(status, BindingStatus::Validating);
}

#[test]
fn test_compute_status_validating_overrides_excluded() {
    use common::app_config::BindingStatus;
    let status = ElectionRunner::compute_node_status(true, true, false, false);
    assert_eq!(status, BindingStatus::Validating);
}

#[test]
fn test_compute_status_participating_when_enabled_and_participating() {
    use common::app_config::BindingStatus;
    let status = ElectionRunner::compute_node_status(false, false, false, true);
    assert_eq!(status, BindingStatus::Participating);
}

#[test]
fn test_compute_status_draining_when_enabled_with_recover_no_participant() {
    use common::app_config::BindingStatus;
    let status = ElectionRunner::compute_node_status(false, false, true, false);
    assert_eq!(status, BindingStatus::Draining);
}

#[test]
fn test_compute_status_idle_when_enabled_no_recover_no_participant() {
    use common::app_config::BindingStatus;
    let status = ElectionRunner::compute_node_status(false, false, false, false);
    assert_eq!(status, BindingStatus::Idle);
}

// Participation status transitions across election lifecycle
// Simulates: Idle → Participating → Submitted → Accepted → Elected → Validating
// Also verifies that stale election flags don't leak after elections close.
#[tokio::test]
async fn test_participation_status_lifecycle() {
    use common::snapshot::ParticipationStatus;

    let node_id = "node-1";
    let mut harness = TestHarness::new();

    setup_elector_no_elections(&mut harness.elector_mock);
    setup_wallet(&mut harness.wallet_mock);
    let provider = &mut harness.provider_mock;
    provider.expect_election_parameters().returning(|| Ok(default_cfg15()));
    provider.expect_validator_config().returning(|| Ok(ValidatorConfig::new()));
    provider.expect_get_current_vset().returning(|| Err(anyhow::anyhow!("no vset")));
    provider.expect_get_next_vset().returning(|| Ok(None));
    provider.expect_export_public_key().returning(|_| Ok(PUB_KEY.to_vec()));
    provider.expect_account().returning(|_| Ok(fake_account(WALLET_BALANCE)));
    provider.expect_shutdown().returning(|| Ok(()));

    let mut runner = harness.build(node_id);

    // Helper to get the status of our node
    let get_status = |r: &ElectionRunner| -> ParticipationStatus {
        let participants = r.build_our_participants_snapshot();
        participants.into_iter().find(|p| p.node_id == node_id).unwrap().status
    };

    // --- Phase 1: Idle (no elections, not validating) ---
    runner.snapshot_cache.last_elections_status = ElectionsStatus::Closed;
    assert_eq!(get_status(&runner), ParticipationStatus::Idle);

    // --- Phase 2: Participating (elections active, participant set, no submissions) ---
    runner.snapshot_cache.last_elections_status = ElectionsStatus::Active;
    let node = runner.nodes.get_mut(node_id).unwrap();
    node.participant = Some(Participant {
        pub_key: PUB_KEY.to_vec(),
        adnl_addr: ADNL_ADDR.to_vec(),
        election_id: ELECTION_ID,
        wallet_addr: addr_bytes(&wallet_address()),
        stake: 0,
        max_factor: 0,
        stake_message_boc: None,
    });
    assert_eq!(get_status(&runner), ParticipationStatus::Participating);

    // --- Phase 3: Submitted (stake sent) ---
    let node = runner.nodes.get_mut(node_id).unwrap();
    node.stake_submissions.push(StakeSubmissionRecord {
        stake: 10_000_000_000_000,
        max_factor: 3 * 65536,
        submission_time: time_format::now(),
    });
    assert_eq!(get_status(&runner), ParticipationStatus::Submitted);

    // --- Phase 4: Accepted (elector accepted the stake) ---
    let node = runner.nodes.get_mut(node_id).unwrap();
    node.stake_accepted = true;
    node.accepted_stake_amount = Some(10_000_000_000_000);
    assert_eq!(get_status(&runner), ParticipationStatus::Accepted);

    // --- Phase 5: Elected (node appears in p36 / next validator set) ---
    let node = runner.nodes.get_mut(node_id).unwrap();
    node.is_next_validator = true;
    assert_eq!(get_status(&runner), ParticipationStatus::Elected);

    // --- Phase 6: Validating (p36 → p34, elections closed) ---
    // Node moves from next vset to current vset, elections are done.
    let node = runner.nodes.get_mut(node_id).unwrap();
    node.is_next_validator = false;
    node.is_validator = true;
    runner.snapshot_cache.last_elections_status = ElectionsStatus::Closed;
    assert_eq!(get_status(&runner), ParticipationStatus::Validating);

    // --- Phase 7: Verify stale flags don't leak ---
    // stake_accepted is still true from phase 4, but elections are closed.
    // Must show Validating, NOT Accepted.
    let node = runner.nodes.get(node_id).unwrap();
    assert!(node.stake_accepted, "stake_accepted should still be true (stale)");
    assert_eq!(get_status(&runner), ParticipationStatus::Validating);

    // --- Phase 8: New elections start while validating ---
    // Node is still in p34, but new election cycle begins and node submits again.
    runner.snapshot_cache.last_elections_status = ElectionsStatus::Active;
    let node = runner.nodes.get_mut(node_id).unwrap();
    node.stake_accepted = false;
    node.accepted_stake_amount = None;
    node.stake_submissions.clear();
    node.participant = Some(Participant {
        pub_key: PUB_KEY.to_vec(),
        adnl_addr: ADNL_ADDR.to_vec(),
        election_id: ELECTION_ID + 3600,
        wallet_addr: addr_bytes(&wallet_address()),
        stake: 0,
        max_factor: 0,
        stake_message_boc: None,
    });
    node.stake_submissions.push(StakeSubmissionRecord {
        stake: 15_000_000_000_000,
        max_factor: 3 * 65536,
        submission_time: time_format::now(),
    });
    // Should show Submitted (election activity), NOT Validating
    assert_eq!(get_status(&runner), ParticipationStatus::Submitted);

    // --- Phase 9: Back to idle (not validating, no elections) ---
    let node = runner.nodes.get_mut(node_id).unwrap();
    node.is_validator = false;
    node.participant = None;
    node.stake_submissions.clear();
    runner.snapshot_cache.last_elections_status = ElectionsStatus::Closed;
    assert_eq!(get_status(&runner), ParticipationStatus::Idle);
}

#[test]
fn fee_alert_precedes_actual_stake_exhaustion_and_has_exact_boundary() {
    assert!(fee_runway_warning(5_200_000_000).unwrap().is_none());
    let early = fee_runway_warning(5_199_999_999).unwrap().unwrap();
    assert!(early.contains("ELECTION_FEE_RUNWAY_LOW"));
    assert!(early.contains("next_stake_fee_nanotos=1400000000"));
    assert!(fee_runway_warning(789_690_000).unwrap().is_some());
}

#[tokio::test]
async fn existing_key_export_failure_never_becomes_a_fresh_key() {
    let mut harness = TestHarness::new();
    harness.elector_mock.expect_address().returning(elector_address);
    harness.wallet_mock.expect_address().returning(wallet_address);
    harness
        .provider_mock
        .expect_export_public_key()
        .times(1)
        .returning(|_| Err(anyhow::anyhow!("control unavailable")));
    harness.provider_mock.expect_new_validator_key().times(0);
    let mut runner = harness.build("node-1");
    let node = runner.nodes.get_mut("node-1").unwrap();
    node.validator_config
        .keys
        .insert(ELECTION_ID, ValidatorEntry { key_id: KEY_ID.to_vec(), ..Default::default() });
    assert!(
        node.find_election_key(ELECTION_ID)
            .await
            .unwrap_err()
            .to_string()
            .contains("export existing")
    );
}

#[tokio::test]
async fn fee_warning_is_visible_with_closed_elections_and_does_not_send() {
    let mut harness = TestHarness::new();
    harness.elector_mock.expect_address().returning(elector_address);
    harness.wallet_mock.expect_address().returning(wallet_address);
    harness
        .provider_mock
        .expect_account()
        .times(1)
        .returning(|_| Ok(crate::providers::Account::from_balance(4_000_000_000)));
    harness.provider_mock.expect_send_boc().times(0);
    harness.elector_mock.expect_get_active_election_id().returning(|| Ok(0));
    harness.provider_mock.expect_election_parameters().returning(|| Ok(default_cfg15()));
    harness.provider_mock.expect_get_current_vset().returning(|| Err(anyhow::anyhow!("no set")));
    harness.provider_mock.expect_get_next_vset().returning(|| Ok(None));
    harness.provider_mock.expect_validator_config().returning(|| Ok(ValidatorConfig::new()));
    harness.provider_mock.expect_shutdown().times(1).returning(|| Ok(()));
    let mut runner = harness.build("node-1");
    let mut cancellation = CancellationCtx::new();
    let signal = cancellation.clone();
    let close = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        cancellation.cancel(CancellationReason::GracefullyShutdown());
    });
    runner
        .run_loop(Duration::from_secs(600), signal, Arc::new(SnapshotStore::new()), None)
        .await
        .unwrap();
    close.await.unwrap();
    assert!(
        runner.nodes["node-1"].last_error.as_ref().unwrap().contains("ELECTION_FEE_RUNWAY_LOW")
    );
}

#[tokio::test]
async fn fee_balance_read_failure_is_an_alert_not_silent_health() {
    let mut harness = TestHarness::new();
    harness.elector_mock.expect_address().returning(elector_address);
    harness.wallet_mock.expect_address().returning(wallet_address);
    harness.provider_mock.expect_account().times(1).returning(|_| Err(anyhow::anyhow!("offline")));
    let mut runner = harness.build("node-1");
    runner.check_fee_runway().await;
    assert!(
        runner.nodes["node-1"]
            .last_error
            .as_ref()
            .unwrap()
            .contains("ELECTION_FEE_BALANCE_UNAVAILABLE")
    );
}

#[tokio::test]
async fn closed_elector_still_extends_actual_announced_duty_without_spending() {
    let mut harness = TestHarness::new();
    harness.elector_mock.expect_address().returning(elector_address);
    harness.elector_mock.expect_get_active_election_id().returning(|| Ok(0));
    harness.wallet_mock.expect_address().returning(wallet_address);
    harness.provider_mock.expect_election_parameters().returning(|| Ok(default_cfg15()));
    let until = u32::try_from(time_format::now() + 7200).unwrap();
    harness
        .provider_mock
        .expect_retain_validator_registration()
        .times(1)
        .withf(move |election, key, adnl, expires| {
            *election == ELECTION_ID
                && key == KEY_ID
                && adnl == ADNL_ADDR
                && *expires == u64::from(until) + 300
        })
        .returning(|_, _, _, _| Ok(()));
    harness.provider_mock.expect_send_boc().times(0);
    harness.provider_mock.expect_new_validator_key().times(0);
    let mut runner = harness.build("node-1");
    runner.nodes.get_mut("node-1").unwrap().validator_config.keys.insert(
        ELECTION_ID,
        ValidatorEntry {
            key_id: KEY_ID.to_vec(),
            adnl_addrs: vec![(ADNL_ADDR.to_vec(), ELECTION_ID + 7200)],
            expired_at: ELECTION_ID + 7200,
            ..Default::default()
        },
    );
    runner.snapshot_cache.last_next_validator_set = Some(
        ValidatorSet::new(
            until - 7200,
            until,
            1,
            vec![ValidatorDescr::with_params(
                chain_block::SigPubKey::from_bytes(&PUB_KEY).unwrap(),
                1,
                Some(chain_block::UInt256::from(ADNL_ADDR)),
            )],
        )
        .unwrap(),
    );
    runner.run().await.unwrap();
    let retained = &runner.nodes["node-1"].validator_config.keys[&ELECTION_ID];
    assert_eq!(retained.expired_at, u64::from(until) + 300);
    assert_eq!(retained.adnl_addrs[0].1, u64::from(until) + 300);
}

#[tokio::test]
async fn failed_registration_isolated_from_healthy_nodes_even_when_excluded() {
    for excluded in [false, true] {
        let mut bad = TestHarness::new();
        bad.elector_mock.expect_address().returning(elector_address);
        bad.wallet_mock.expect_address().returning(wallet_address);
        bad.provider_mock.expect_election_parameters().returning(|| Ok(default_cfg15()));
        bad.provider_mock
            .expect_retain_validator_registration()
            .times(1)
            .returning(|_, _, _, _| Err(anyhow::anyhow!("control offline")));
        bad.provider_mock.expect_send_boc().times(0);
        bad.provider_mock.expect_new_validator_key().times(0);
        let mut runner = bad.build("node-1");
        let node = runner.nodes.get_mut("node-1").unwrap();
        node.excluded = excluded;
        node.validator_config.keys.insert(
            ELECTION_ID,
            ValidatorEntry {
                key_id: KEY_ID.to_vec(),
                adnl_addrs: vec![(ADNL_ADDR.to_vec(), ELECTION_ID + 7200)],
                expired_at: ELECTION_ID + 7200,
                ..Default::default()
            },
        );
        let until = u32::try_from(time_format::now() + 7200).unwrap();
        runner.snapshot_cache.last_next_validator_set = Some(
            ValidatorSet::new(
                until - 7200,
                until,
                1,
                vec![ValidatorDescr::with_params(
                    chain_block::SigPubKey::from_bytes(&PUB_KEY).unwrap(),
                    1,
                    Some(chain_block::UInt256::from(ADNL_ADDR)),
                )],
            )
            .unwrap(),
        );
        let mut healthy = TestHarness::new();
        healthy.elector_mock.expect_address().returning(elector_address);
        setup_wallet(&mut healthy.wallet_mock);
        setup_default_provider(&mut healthy.provider_mock, WALLET_BALANCE, None);
        runner.nodes.extend(healthy.build("node-2").nodes);
        let snapshot = ElectorSnapshot {
            block: snapshot_block(),
            elections: ElectionsInfo {
                election_id: ELECTION_ID,
                elect_close: ELECTION_ID + 600,
                min_stake: MIN_STAKE,
                total_stake: 0,
                failed: false,
                finished: false,
                participants: vec![],
            },
            past_elections: vec![],
            returned: vec![([0xaa; 32], 0)],
        };
        runner.run_with_snapshot(snapshot).await.unwrap();
        assert!(runner.nodes["node-1"].last_error.as_ref().unwrap().contains("control offline"));
        assert!(runner.nodes["node-1"].participant.is_none());
        assert_eq!(runner.nodes["node-2"].stake_submissions.len(), 1);
        assert!(!runner.nodes["node-2"].stake_accepted);
    }
}
