use crate::model::FullId;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub sampled_utc: u64,
    pub tip: FullId,
    pub tip_utime: u64,
    pub coherent_tip: Option<FullId>,
    pub coherent_tip_utime: Option<u64>,
    pub shard_client_seqno: u32,
    pub initial_sync_complete: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncState {
    AtHead,
    CatchingUp,
    PolicyFailure,
    Unknown,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncStatus {
    pub state: SyncState,
    pub exit_code: u8,
    pub block_age_seconds: u64,
    pub shard_lag_blocks: u32,
    pub reference_lag_blocks: Option<u32>,
    pub common_id: Option<FullId>,
    pub stable_seconds: u64,
    pub initial_sync_complete: bool,
    pub evidence: Observation,
    pub reason: String,
}
impl Observation {
    pub fn from_stats(stats: &[(String, String)], sampled_utc: u64) -> Result<Self> {
        let mut map = BTreeMap::new();
        for (key, value) in stats {
            ensure!(
                map.insert(key.as_str(), value.as_str()).is_none(),
                "duplicate control statistic: {key}"
            );
        }
        let get = |name: &str| {
            map.get(name).copied().with_context(|| format!("missing control statistic {name}"))
        };
        let tip = FullId::from_stats(get("masterchainblock")?)?;
        tip.masterchain()?;
        let tip_utime = get("masterchainblocktime")?.parse()?;
        let shard_client_seqno = get("shardclientmasterchainseqno")?.parse()?;
        ensure!(shard_client_seqno <= tip.seqno, "shard-client frontier is ahead of masterchain");
        ensure!(tip_utime <= sampled_utc.saturating_add(5), "node tip timestamp is in the future");
        let initial_sync_complete = !map.keys().any(|key| key.starts_with("process.initial_sync"));
        Ok(Self {
            sampled_utc,
            tip,
            tip_utime,
            coherent_tip: None,
            coherent_tip_utime: None,
            shard_client_seqno,
            initial_sync_complete,
        })
    }
    /// Each reference tuple carries its head and independently queried id at this node's height.
    pub fn status(
        self,
        references: &[(String, FullId, FullId)],
        stable_seconds: u64,
    ) -> Result<SyncStatus> {
        let coherent = match (&self.coherent_tip, self.coherent_tip_utime) {
            (Some(id), Some(time)) => {
                id.masterchain()?;
                ensure!(
                    id.seqno == self.shard_client_seqno
                        && time <= self.tip_utime
                        && time <= self.sampled_utc.saturating_add(5),
                    "coherent-tip evidence disagrees with control statistics"
                );
                Some(time)
            }
            (None, None) => None,
            _ => anyhow::bail!("incomplete coherent-tip evidence"),
        };
        let age = self.sampled_utc.saturating_sub(coherent.map_or(self.tip_utime, |time| time));
        let lag =
            self.tip.seqno.checked_sub(self.shard_client_seqno).context("negative shard lag")?;
        let mut names = std::collections::BTreeSet::new();
        let mut reference_lag = 0_u32;
        let mut equal = references.len() >= 2;
        for (name, head, common) in references {
            head.masterchain()?;
            common.masterchain()?;
            ensure!(names.insert(name), "two observations from one named reference");
            ensure!(
                common.seqno == self.tip.seqno,
                "reference did not bind the requested common height"
            );
            ensure!(head.seqno >= common.seqno, "reference head precedes its common-height answer");
            if head.seqno == common.seqno {
                ensure!(head == common, "reference gives two full ids at one height");
            }
            equal &= common == &self.tip;
            reference_lag = reference_lag.max(head.seqno.saturating_sub(self.tip.seqno));
        }
        let fresh = self.initial_sync_complete
            && coherent.is_some()
            && age <= 30
            && lag <= 2
            && reference_lag <= 2
            && equal;
        let at_head = fresh && stable_seconds >= 300;
        let unknown = references.len() < 2 || coherent.is_none();
        let state = if unknown {
            SyncState::Unknown
        } else if !equal {
            SyncState::PolicyFailure
        } else if at_head {
            SyncState::AtHead
        } else {
            SyncState::CatchingUp
        };
        let exit_code = if unknown {
            4
        } else if !equal {
            3
        } else if at_head {
            0
        } else {
            2
        };
        let reason = if unknown {
            "two named references and verified coherent-tip evidence are required"
        } else if !equal {
            "full block ids disagree"
        } else if !self.initial_sync_complete {
            "initial sync is active"
        } else if age > 30 {
            "head is stale"
        } else if lag > 2 || reference_lag > 2 {
            "block lag exceeds threshold"
        } else if !at_head {
            "five-minute stability window is incomplete"
        } else {
            "fresh coherent head agrees with two references"
        }
        .to_owned();
        Ok(SyncStatus {
            state,
            exit_code,
            block_age_seconds: age,
            shard_lag_blocks: lag,
            reference_lag_blocks: (!unknown).then_some(reference_lag),
            common_id: equal.then(|| self.tip.clone()),
            stable_seconds: if fresh { stable_seconds } else { 0 },
            initial_sync_complete: self.initial_sync_complete,
            evidence: self,
            reason,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasuredBudget {
    pub production_blocks_per_second: f64,
    pub replay_blocks_per_second: f64,
    pub restore_before_replay_seconds: f64,
    pub equality_window_seconds: f64,
    pub safety_margin_seconds: f64,
}
impl MeasuredBudget {
    pub fn projected_seconds(&self, lag_blocks: u32) -> Result<f64> {
        let p = self.production_blocks_per_second;
        let a = self.replay_blocks_per_second;
        let i = self.restore_before_replay_seconds;
        ensure!(
            [p, a, i, self.equality_window_seconds, self.safety_margin_seconds]
                .iter()
                .all(|v| v.is_finite() && *v >= 0.0),
            "invalid measured timing"
        );
        ensure!(
            a > p && p > 0.0 && self.equality_window_seconds >= 300.0,
            "measurement cannot establish a catch-up bound"
        );
        let result = i
            + (f64::from(lag_blocks) + p * i) / (a - p)
            + self.equality_window_seconds
            + self.safety_margin_seconds;
        ensure!(result.is_finite(), "projected timing overflow");
        Ok(result)
    }
}

/// Continuous qualification uses a monotonic clock; a failed or missing sample resets it.
#[derive(Default)]
pub struct Stability {
    since: Option<std::time::Instant>,
    last: Option<std::time::Instant>,
}
impl Stability {
    pub fn observe(&mut self, status: &SyncStatus, now: std::time::Instant) -> Result<u64> {
        if let Some(last) = self.last {
            ensure!(now >= last, "status clock moved backwards");
        }
        let gap = self.last.is_some_and(|last| now.duration_since(last).as_secs() > 30);
        self.last = Some(now);
        let qualified = status.initial_sync_complete
            && status.block_age_seconds <= 30
            && status.shard_lag_blocks <= 2
            && status.reference_lag_blocks.is_some_and(|lag| lag <= 2)
            && status.common_id.is_some();
        if !qualified || gap {
            self.since = None;
        }
        if !qualified {
            return Ok(0);
        }
        let start = self.since.get_or_insert(now);
        Ok(now.duration_since(*start).as_secs())
    }
    pub fn missing(&mut self) {
        self.since = None;
        self.last = None;
    }
}

#[derive(Debug)]
pub struct StatusExit(pub u8);
impl std::fmt::Display for StatusExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "node sync status exit {}", self.0)
    }
}
impl std::error::Error for StatusExit {}
