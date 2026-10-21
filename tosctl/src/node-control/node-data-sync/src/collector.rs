use crate::{
    model::FullId,
    status::{Observation, Stability, SyncStatus},
};
use anyhow::{Context, Result, ensure};
use chain_rpc_client::v2::{client_json_rpc::ClientJsonRpc, data_models::BlockIdExt};
use control_client::{client_adnl::ControlClientAdnl, client_api::ClientAPI};
use std::{
    collections::BTreeSet,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub struct Collector {
    references: Vec<ClientJsonRpc>,
    stability: Stability,
}
impl Collector {
    pub fn new(endpoints: &[String]) -> Result<Self> {
        ensure!(endpoints.len() <= 8, "reference count limit");
        let mut unique = BTreeSet::new();
        let mut references = Vec::new();
        for endpoint in endpoints {
            let canonical = crate::references::canonical_endpoint(endpoint)?;
            ensure!(unique.insert(canonical.clone()), "duplicate named reference endpoint");
            references.push(ClientJsonRpc::connect(canonical, None)?);
        }
        Ok(Self { references, stability: Stability::default() })
    }
    pub async fn sample(&mut self, control: &mut ControlClientAdnl) -> Result<SyncStatus> {
        let result =
            match tokio::time::timeout(Duration::from_secs(60), self.sample_inner(control)).await {
                Ok(result) => result,
                Err(_) => Err(anyhow::anyhow!("sync sample deadline expired")),
            };
        if result.is_err() {
            self.stability.missing();
        }
        result
    }
    async fn head_cohort(
        &self,
        control: &mut impl StatsSource,
    ) -> Result<(Observation, Vec<BlockIdExt>)> {
        // Retry an inconclusive cohort, never offset lag using an assumed production rate.
        for _ in 0..6 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let started = Instant::now();
            // Reference heads must not precede the target snapshot: an older answer
            // could otherwise hide lag. Fan them out together, without per-source sleeps.
            let stats = control.read_stats().await?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let observation = Observation::from_stats(&stats.stats, now)?;
            if started.elapsed() > Duration::from_millis(500) {
                continue;
            }
            let pending = self
                .references
                .iter()
                .map(|client| {
                    Box::pin(async move { Ok(client.get_masterchain_info().await?.last) })
                        as CohortFuture<'_, BlockIdExt>
                })
                .collect();
            let heads = cohort(pending).await?;
            // At the supported two-block/s rate this window spans at most one block interval.
            // Slower acquisition is inconclusive, not permission to widen the two-block bound.
            if started.elapsed() <= Duration::from_millis(500)
                && heads.iter().all(|head| head.seqno >= observation.tip.seqno)
            {
                return Ok((observation, heads));
            }
        }
        anyhow::bail!(
            "inconclusive target/reference head cohort; retry without relaxing lag bounds"
        )
    }
    async fn sample_inner(&mut self, control: &mut impl StatsSource) -> Result<SyncStatus> {
        let (mut observation, heads) = self.head_cohort(control).await?;
        let mut references = Vec::new();
        for (index, (client, head)) in self.references.iter().zip(heads).enumerate() {
            // Each configured source verifies the same captured target height.
            tokio::time::sleep(Duration::from_millis(500)).await;
            let common = if head.seqno >= observation.tip.seqno {
                client.lookup_block(-1, &i64::MIN.to_string(), observation.tip.seqno).await?
            } else {
                // A behind reference cannot establish equality at the node's height.
                self.stability.missing();
                continue;
            };
            tokio::time::sleep(Duration::from_millis(500)).await;
            let coherent = client
                .get_block_header(-1, &i64::MIN.to_string(), observation.shard_client_seqno)
                .await?;
            let coherent_id = full_id(
                coherent
                    .id
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("reference omitted coherent-tip full id"))?,
            )?;
            ensure!(
                coherent_id.seqno == observation.shard_client_seqno && coherent.gen_utime != 0,
                "reference returned another coherent height or omitted its timestamp"
            );
            if let Some(previous) = &observation.coherent_tip {
                ensure!(
                    previous == &coherent_id
                        && observation.coherent_tip_utime == Some(u64::from(coherent.gen_utime)),
                    "references disagree on coherent-tip identity or time"
                );
            } else {
                observation.coherent_tip = Some(coherent_id);
                observation.coherent_tip_utime = Some(u64::from(coherent.gen_utime));
            }
            references.push((
                format!("reference-{}", index + 1),
                full_id(&head)?,
                full_id(&common)?,
            ));
        }
        let evaluated_utc = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let preliminary = observation.clone().status_at(&references, 0, evaluated_utc)?;
        let stable = self.stability.observe(&preliminary, Instant::now())?;
        observation.status_at(&references, stable, evaluated_utc)
    }
}
pub fn full_id(value: &BlockIdExt) -> Result<FullId> {
    let id = FullId {
        workchain: value.workchain,
        shard: value.shard,
        seqno: value.seqno,
        root_hash: hex::encode(&value.root_hash),
        file_hash: hex::encode(&value.file_hash),
    };
    id.masterchain()?;
    Ok(id)
}

// Poll all reads together without spawning tasks or extending borrowed control-client lifetimes.
type CohortFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T>> + Send + 'a>>;
async fn cohort<T>(mut pending: Vec<CohortFuture<'_, T>>) -> Result<Vec<T>> {
    let mut values: Vec<Option<T>> = (0..pending.len()).map(|_| None).collect();
    std::future::poll_fn(|cx| {
        for (future, value) in pending.iter_mut().zip(values.iter_mut()) {
            if value.is_none() {
                match future.as_mut().poll(cx) {
                    std::task::Poll::Ready(Ok(result)) => *value = Some(result),
                    std::task::Poll::Ready(Err(error)) => {
                        return std::task::Poll::Ready(Err(error));
                    }
                    std::task::Poll::Pending => {}
                }
            }
        }
        if values.iter().all(Option::is_some) {
            std::task::Poll::Ready(
                values
                    .iter_mut()
                    .map(|v| v.take().context("cohort read did not complete"))
                    .collect(),
            )
        } else {
            std::task::Poll::Pending
        }
    })
    .await
}

trait StatsSource {
    async fn read_stats(&mut self) -> Result<control_client::client_api::NodeStats>;
}
impl StatsSource for ControlClientAdnl {
    async fn read_stats(&mut self) -> Result<control_client::client_api::NodeStats> {
        self.get_stats().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Control {
        start: Instant,
        unix: u64,
        delay: Duration,
        head_requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        first: bool,
    }
    impl StatsSource for Control {
        async fn read_stats(&mut self) -> Result<control_client::client_api::NodeStats> {
            let seq = 100 + (self.start.elapsed().as_millis() / 500) as u32;
            let id = FullId {
                workchain: -1,
                shard: i64::MIN,
                seqno: seq,
                root_hash: "12".repeat(32),
                file_hash: "34".repeat(32),
            };
            let time = self.unix + u64::from((seq - 100) / 2);
            let before = self.head_requests.load(std::sync::atomic::Ordering::Acquire);
            if self.first {
                assert_eq!(before, 0, "reference head preceded the first target snapshot");
                self.first = false;
            }
            tokio::time::sleep(self.delay).await;
            assert_eq!(
                self.head_requests.load(std::sync::atomic::Ordering::Acquire),
                before,
                "reference head was read before target snapshot completed"
            );
            Ok(control_client::client_api::NodeStats {
                stats: vec![
                    (
                        "masterchainblock".into(),
                        format!("(-1,8000000000000000,{seq}):{}:{}", id.root_hash, id.file_hash),
                    ),
                    ("masterchainblocktime".into(), time.to_string()),
                    ("shardclientmasterchainseqno".into(), seq.to_string()),
                ],
            })
        }
    }
    #[test]
    fn production_sample_future_remains_send() {
        fn check(collector: &mut Collector, client: &mut ControlClientAdnl) {
            fn require_send(_: impl Send) {}
            require_send(collector.sample(client));
        }
        let _ = check as fn(&mut Collector, &mut ControlClientAdnl);
    }
    #[test]
    fn advancing_chain_uses_one_head_cohort_before_historical_verification() -> Result<()> {
        tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
            let start = Instant::now();
            let unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let id = FullId {
                workchain: -1,
                shard: i64::MIN,
                seqno: 100,
                root_hash: "12".repeat(32),
                file_hash: "34".repeat(32),
            };
            let refs = crate::test_references::References::new(
                &crate::test_references::network(&id),
                &id,
                crate::test_references::Mode::Advancing { start, unix },
            )?;
            let mut collector = Collector::new(
                &refs.policy.sources.iter().map(|s| s.endpoint.clone()).collect::<Vec<_>>(),
            )?;
            let mut control = Control {
                start,
                unix,
                delay: Duration::from_millis(20),
                head_requests: refs.head_requests.clone(),
                first: true,
            };
            let result = collector.sample_inner(&mut control).await;
            assert!(
                result.is_ok(),
                "advancing-chain cohort did not complete: {:?}",
                result.as_ref().err()
            );
            let result = result?;
            assert!(
                refs.head_requests.load(std::sync::atomic::Ordering::Acquire) >= 2,
                "head recorder did not observe both references"
            );
            let current = 100 + (start.elapsed().as_millis() / 500) as u32;
            assert!(
                current >= result.evidence.tip.seqno + 3,
                "chain did not advance during verification"
            );
            assert!(
                result.reference_lag_blocks.is_some_and(|lag| lag <= 1),
                "sampling manufactured reference lag: {result:?}"
            );
            assert_eq!(result.stable_seconds, 0, "one sample bypassed five-minute qualification");
            assert_eq!(result.exit_code, 2);
            control.delay = Duration::from_millis(550);
            assert!(
                collector
                    .head_cohort(&mut control)
                    .await
                    .err()
                    .context("slow cohort was accepted")?
                    .to_string()
                    .contains("inconclusive")
            );
            Ok(())
        })
    }
}
