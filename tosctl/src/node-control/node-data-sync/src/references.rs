//! Corroboration of one exact native frontier, before publication or signing exposure.
use crate::{
    collector::full_id,
    model::{FullId, Network, hash},
};
use anyhow::{Context, Result, ensure};
use chain_rpc_client::v2::client_json_rpc::{ClientJsonRpc, canonicalize_chain_rpc_endpoint};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const MAX_RECEIPT_AGE: u64 = 30;
/// The existing typed client appends /jsonRPC. Accept its base URL or that exact
/// endpoint spelling, but give aliases one identity before duplicate detection.
pub fn canonical_endpoint(value: &str) -> Result<String> {
    let (canonical, _) = canonicalize_chain_rpc_endpoint(value)?;
    let trimmed = canonical.trim_end_matches('/');
    let base = trimmed.strip_suffix("/jsonRPC").unwrap_or(trimmed);
    Ok(canonicalize_chain_rpc_endpoint(base)?.0)
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamedReference {
    pub name: String,
    pub endpoint: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReferencePolicy {
    pub sources: Vec<NamedReference>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReferenceAnswer {
    pub source: NamedReference,
    pub head: FullId,
    pub at_frontier: FullId,
    pub observed_utc: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReferenceReceipt {
    pub network: Network,
    pub frontier: FullId,
    pub binding_sha256: String,
    pub started_utc: u64,
    pub finished_utc: u64,
    pub answers: Vec<ReferenceAnswer>,
}
/// Only live corroboration constructs this authority; a serialized receipt is not authority.
pub struct Corroborated {
    receipt: ReferenceReceipt,
    checked: Instant,
}
pub fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
impl ReferencePolicy {
    pub fn from_endpoints(endpoints: &[String]) -> Result<Self> {
        let sources = endpoints
            .iter()
            .enumerate()
            .map(|(i, endpoint)| NamedReference {
                name: format!("reference-{}", i + 1),
                endpoint: endpoint.clone(),
            })
            .collect();
        Self { sources }.normalized()
    }
    pub fn normalized(&self) -> Result<Self> {
        ensure!(
            (2..=8).contains(&self.sources.len()),
            "two to eight named references are required"
        );
        let mut names = BTreeSet::new();
        let mut urls = BTreeSet::new();
        let mut sources = Vec::new();
        for source in &self.sources {
            ensure!(
                !source.name.is_empty()
                    && source.name.len() <= 64
                    && source
                        .name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
                "invalid reference name"
            );
            let endpoint = canonical_endpoint(&source.endpoint)?;
            ensure!(
                names.insert(source.name.clone()) && urls.insert(endpoint.clone()),
                "duplicate named reference or endpoint"
            );
            sources.push(NamedReference { name: source.name.clone(), endpoint });
        }
        Ok(Self { sources })
    }
    pub fn corroborate(
        &self,
        network: &Network,
        frontier: &FullId,
        binding: &str,
    ) -> Result<Corroborated> {
        let policy = self.normalized()?;
        network.validate()?;
        frontier.masterchain()?;
        hash(binding)?;
        // Administrative entry points are synchronous; never nest a runtime in a caller's executor.
        let approval = std::thread::scope(|scope| {
            scope
                .spawn(|| -> Result<Corroborated> {
                    let runtime =
                        tokio::runtime::Builder::new_current_thread().enable_all().build()?;
                    runtime.block_on(async {
                        tokio::time::timeout(
                            Duration::from_secs(60),
                            policy.read(network, frontier, binding),
                        )
                        .await
                        .context("reference corroboration deadline expired")?
                    })
                })
                .join()
                .map_err(|_| anyhow::anyhow!("reference corroboration worker failed"))?
        })?;
        #[cfg(all(test, feature = "native-lifecycle-tests"))]
        crate::test_hooks::boundary("reference-corroborated")?;
        Ok(approval)
    }
    async fn read(
        &self,
        network: &Network,
        frontier: &FullId,
        binding: &str,
    ) -> Result<Corroborated> {
        let started_utc = now()?;
        let mut answers = Vec::new();
        for source in &self.sources {
            let client = ClientJsonRpc::connect(source.endpoint.clone(), None)?;
            tokio::time::sleep(Duration::from_millis(500)).await;
            let head = client
                .get_masterchain_info()
                .await
                .with_context(|| format!("{} head unavailable", source.name))?;
            if let Some(init) = head.init {
                let init = full_id(&init)?;
                ensure!(
                    init == network.zero || init == network.init,
                    "reference {} advertises another anchor",
                    source.name
                );
            }
            let head = full_id(&head.last)?;
            ensure!(
                head.seqno >= frontier.seqno,
                "reference {} is behind the required frontier",
                source.name
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
            let at = client
                .lookup_block(-1, &i64::MIN.to_string(), frontier.seqno)
                .await
                .with_context(|| format!("{} frontier unavailable", source.name))?;
            let at_frontier = full_id(&at)?;
            ensure!(
                &at_frontier == frontier,
                "reference {} disagrees with the exact frontier full id",
                source.name
            );
            answers.push(ReferenceAnswer {
                source: source.clone(),
                head,
                at_frontier,
                observed_utc: now()?,
            });
        }
        let receipt = ReferenceReceipt {
            network: network.clone(),
            frontier: frontier.clone(),
            binding_sha256: binding.to_owned(),
            started_utc,
            finished_utc: now()?,
            answers,
        };
        receipt.validate(network, frontier, binding)?;
        Ok(Corroborated { receipt, checked: Instant::now() })
    }
}
impl ReferenceReceipt {
    pub fn validate(&self, network: &Network, frontier: &FullId, binding: &str) -> Result<()> {
        ensure!(
            &self.network == network
                && &self.frontier == frontier
                && self.binding_sha256 == binding,
            "reference receipt binding mismatch"
        );
        network.validate()?;
        frontier.masterchain()?;
        hash(binding)?;
        let normalized =
            ReferencePolicy { sources: self.answers.iter().map(|a| a.source.clone()).collect() }
                .normalized()?;
        ensure!(
            self.started_utc <= self.finished_utc && self.finished_utc - self.started_utc <= 60,
            "reference receipt interval invalid"
        );
        for (answer, canonical) in self.answers.iter().zip(&normalized.sources) {
            answer.head.masterchain()?;
            ensure!(
                &answer.source == canonical
                    && &answer.at_frontier == frontier
                    && answer.head.seqno >= frontier.seqno
                    && (self.started_utc..=self.finished_utc).contains(&answer.observed_utc),
                "reference answer does not establish the bound frontier"
            );
        }
        Ok(())
    }
    pub fn ensure_fresh(&self) -> Result<()> {
        let current = now()?;
        ensure!(
            self.finished_utc <= current && current - self.finished_utc <= MAX_RECEIPT_AGE,
            "reference approval expired or clock moved backwards"
        );
        Ok(())
    }
}
impl Corroborated {
    pub fn receipt(&self) -> Result<ReferenceReceipt> {
        ensure!(
            self.checked.elapsed() <= Duration::from_secs(MAX_RECEIPT_AGE),
            "reference approval expired before exposure"
        );
        self.receipt.ensure_fresh()?;
        Ok(self.receipt.clone())
    }
}
