use crate::{
    model::FullId,
    status::{Observation, Stability, SyncStatus},
};
use anyhow::{Result, ensure};
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
    async fn sample_inner(&mut self, control: &mut ControlClientAdnl) -> Result<SyncStatus> {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let stats = control.get_stats().await?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mut observation = Observation::from_stats(&stats.stats, now)?;
        let mut references = Vec::new();
        for (index, client) in self.references.iter().enumerate() {
            // Each configured source is queried independently; no first-source fallback.
            tokio::time::sleep(Duration::from_millis(500)).await;
            let head = client.get_masterchain_info().await?;
            tokio::time::sleep(Duration::from_millis(500)).await;
            let common = if head.last.seqno >= observation.tip.seqno {
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
                full_id(&head.last)?,
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
