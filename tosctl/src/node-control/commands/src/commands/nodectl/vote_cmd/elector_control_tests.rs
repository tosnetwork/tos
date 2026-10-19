use super::*;
use anyhow::{Context, ensure};
use contracts::{ElectorWrapper, ElectorWrapperImpl};
use elections::providers::{DefaultElectionsProvider, ElectionsProvider};
use std::{
    path::Path,
    sync::{Arc, atomic::Ordering},
};

mod elector_fixture {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../test/validator/elector-control-fixture.rs"
    ));
}
use elector_fixture::{Fixture, Reply};

fn upgrade(result: anyhow::Result<()>, unsupported: bool) -> anyhow::Result<()> {
    if unsupported {
        let error = result.err().context("unsupported elector query was accepted")?;
        ensure!(
            error.downcast_ref::<control_client::UnsupportedControlQuery>().is_some(),
            "upgrade error lost: {error:#}"
        );
    } else {
        result?;
    }
    Ok(())
}

#[tokio::test]
async fn election_ls_uses_one_control_read_and_no_public_elector_getters() -> anyhow::Result<()> {
    for unsupported in [false, true] {
        for count in [1, 100, 256] {
            let fixture =
                Fixture::new(Reply { unsupported, participants: count, ..Reply::default() })
                    .await?;
            let result =
                VoteElectionLsCmd { format: super::super::output_format::OutputFormat::Json }
                    .run(&fixture.path()?)
                    .await;
            fixture.no_public_elector()?;
            assert_eq!(
                fixture.counts.control.load(Ordering::SeqCst),
                1,
                "one control read for election listing"
            );
            assert!(
                fixture.counts.wallets.lock().map_err(|_| anyhow::anyhow!("wallet counter"))?[0]
                    .is_empty()
            );
            upgrade(result, unsupported)?;
            fixture.stop().await;
        }
    }
    Ok(())
}

#[tokio::test]
async fn election_cast_uses_one_control_read_and_no_public_elector_getters() -> anyhow::Result<()> {
    for unsupported in [false, true] {
        let fixture =
            Fixture::new(Reply { unsupported, finished: true, ..Reply::default() }).await?;
        let result =
            VoteElectionCastCmd { dry_run: true, max_factor: 3.0, stake: None, wallet: None }
                .run(&fixture.path()?)
                .await;
        fixture.no_public_elector()?;
        assert_eq!(
            fixture.counts.control.load(Ordering::SeqCst),
            1,
            "one control read for election cast"
        );
        upgrade(result, unsupported)?;
        fixture.stop().await;
    }
    Ok(())
}

#[tokio::test]
async fn public_elector_counters_have_a_positive_control() -> anyhow::Result<()> {
    let fixture = Fixture::new(Reply::default()).await?;
    let rpc = super::super::utils::try_create_rpc_client(&fixture.config()?).await?;
    let elector = ElectorWrapperImpl::new(contracts::contract_provider!(rpc));
    assert_eq!(elector.get_active_election_id().await?, 1_700_000_001);
    assert_eq!(elector.elections_info().await?.election_id, 1_700_000_001);
    assert!(elector.past_elections().await?.is_empty());
    assert_eq!(elector.compute_returned_stake(&[0; 32]).await?, 99);
    {
        let counts = fixture.counts.public.lock().map_err(|_| anyhow::anyhow!("public counter"))?;
        for method in elector_fixture::ELECTOR_METHODS {
            assert_eq!(counts.get(method).copied(), Some(1), "counter must see {method}");
        }
    }
    fixture.stop().await;
    Ok(())
}

#[tokio::test]
async fn initial_stake_decision_uses_one_snapshot_and_no_public_elector_getters()
-> anyhow::Result<()> {
    for unsupported in [false, true] {
        let fixture =
            Fixture::new(Reply { unsupported, finished: true, ..Reply::default() }).await?;
        let config = fixture.config()?;
        let adnl =
            config.nodes.get("test").context("fixture node")?.to_node_adnl_config(None).await?;
        let rpc = Arc::new(chain_rpc_client::v2::client_json_rpc::ClientJsonRpc::connect(
            fixture.public_url.clone(),
            None,
        )?);
        let mut provider = DefaultElectionsProvider::new(
            adnl,
            Arc::new(contracts::DefaultChainProvider::new(rpc)),
        );
        let result = super::super::config_wallet_cmd::stake_elections_info(&mut provider).await;
        fixture.no_public_elector()?;
        assert_eq!(
            fixture.counts.control.load(Ordering::SeqCst),
            1,
            "one control read for the initial stake decision"
        );
        if unsupported {
            upgrade(result.map(|_| ()), true)?;
        } else {
            let info = result?;
            assert_eq!(info.election_id, 1_700_000_000);
            assert!(info.finished);
            assert_eq!(info.min_stake, 3);
        }
        provider.shutdown().await?;
        fixture.stop().await;
    }
    Ok(())
}

#[tokio::test]
async fn stake_confirmation_uses_one_snapshot_per_poll_and_propagates_upgrade() -> anyhow::Result<()>
{
    for unsupported in [false, true] {
        let fixture = Fixture::new(Reply { unsupported, ..Reply::default() }).await?;
        let config = fixture.config()?;
        let adnl =
            config.nodes.get("test").context("fixture node")?.to_node_adnl_config(None).await?;
        let rpc = Arc::new(chain_rpc_client::v2::client_json_rpc::ClientJsonRpc::connect(
            fixture.public_url.clone(),
            None,
        )?);
        let mut provider = DefaultElectionsProvider::new(
            adnl,
            Arc::new(contracts::DefaultChainProvider::new(rpc)),
        );
        let result = super::super::config_wallet_cmd::wait_for_stake_accepted(
            &mut provider,
            1_700_000_000,
            &[0; 32],
            7,
            &common::task_cancellation::CancellationCtx::new(),
            std::time::Duration::from_secs(10),
        )
        .await;
        fixture.no_public_elector()?;
        assert_eq!(
            fixture.counts.control.load(Ordering::SeqCst),
            1,
            "one control read per confirmation poll"
        );
        upgrade(result, unsupported)?;
        provider.shutdown().await?;
        fixture.stop().await;
    }
    Ok(())
}

#[tokio::test]
async fn confirmation_refuses_another_election_or_a_partial_invalid_response() -> anyhow::Result<()>
{
    for reply in [
        Reply { election_id: 1_700_000_001, ..Reply::default() },
        Reply { overflow: true, ..Reply::default() },
    ] {
        let fixture = Fixture::new(reply.clone()).await?;
        let config = common::app_config::AppConfig::load(Path::new(&fixture.path()?))?;
        let adnl =
            config.nodes.get("test").context("fixture node")?.to_node_adnl_config(None).await?;
        let rpc = Arc::new(chain_rpc_client::v2::client_json_rpc::ClientJsonRpc::connect(
            fixture.public_url.clone(),
            None,
        )?);
        let mut provider = DefaultElectionsProvider::new(
            adnl,
            Arc::new(contracts::DefaultChainProvider::new(rpc)),
        );
        let error = super::super::config_wallet_cmd::wait_for_stake_accepted(
            &mut provider,
            1_700_000_000,
            &[0; 32],
            7,
            &common::task_cancellation::CancellationCtx::new(),
            std::time::Duration::from_secs(10),
        )
        .await
        .err()
        .context("invalid confirmation accepted")?;
        let message = format!("{error:#}");
        ensure!(
            message.contains(if reply.overflow {
                "participant stake exceeds u64"
            } else {
                "election changed"
            }),
            "wrong refusal: {message}"
        );
        fixture.no_public_elector()?;
        assert_eq!(fixture.counts.control.load(Ordering::SeqCst), 1);
        provider.shutdown().await?;
        fixture.stop().await;
    }
    Ok(())
}
