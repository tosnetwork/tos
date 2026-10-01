//! Strict, finite C04 native consensus DTO. This is observation, not business state.
use crate::{
    native::required_nullable,
    wire::{hash, U64},
};
use serde::{
    de::{MapAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use std::collections::{BTreeMap, BTreeSet};

fn unique_map<'de, D, V>(deserializer: D) -> Result<BTreeMap<String, V>, D::Error>
where
    D: Deserializer<'de>,
    V: Deserialize<'de>,
{
    struct Unique<V>(std::marker::PhantomData<V>);
    impl<'de, V: Deserialize<'de>> Visitor<'de> for Unique<V> {
        type Value = BTreeMap<String, V>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a map with unique keys")
        }
        fn visit_map<M: MapAccess<'de>>(self, mut access: M) -> Result<Self::Value, M::Error> {
            let mut out = BTreeMap::new();
            while let Some((key, value)) = access.next_entry::<String, V>()? {
                if out.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate C04 map key"));
                }
            }
            Ok(out)
        }
    }
    deserializer.deserialize_map(Unique(std::marker::PhantomData))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncompleteReason {
    CasExhaustion,
    ContextCapacity,
    CounterSaturation,
    LedgerCapacity,
    ObservationGap,
    PendingCapacity,
    ScopeUnapproved,
    SessionLifecycleUnverified,
    SnapshotContention,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Live {
    #[serde(deserialize_with = "unique_map")]
    pub phases: BTreeMap<String, U64>,
    #[serde(deserialize_with = "unique_map")]
    pub outcomes: BTreeMap<String, U64>,
    #[serde(deserialize_with = "unique_map")]
    pub failures: BTreeMap<String, U64>,
    pub pending: U64,
    #[serde(deserialize_with = "required_nullable")]
    pub oldest_age_ns: Option<U64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayRow {
    #[serde(deserialize_with = "unique_map")]
    pub phases: BTreeMap<String, U64>,
    #[serde(deserialize_with = "unique_map")]
    pub terminals: BTreeMap<String, U64>,
    pub pending: U64,
    #[serde(deserialize_with = "required_nullable")]
    pub oldest_age_ns: Option<U64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VoteReplay {
    pub signed_record: ReplayRow,
    pub intent_only: ReplayRow,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", deny_unknown_fields)]
pub enum Action {
    #[serde(rename = "proposal")]
    Proposal {
        accounting_complete: bool,
        incomplete_reasons: Vec<IncompleteReason>,
        live: Live,
        #[serde(deserialize_with = "required_nullable")]
        replay: Option<VoteReplay>,
    },
    #[serde(rename = "notarize_vote")]
    NotarizeVote {
        accounting_complete: bool,
        incomplete_reasons: Vec<IncompleteReason>,
        live: Live,
        replay: VoteReplay,
    },
    #[serde(rename = "finalize_vote")]
    FinalizeVote {
        accounting_complete: bool,
        incomplete_reasons: Vec<IncompleteReason>,
        live: Live,
        replay: VoteReplay,
    },
    #[serde(rename = "skip_vote")]
    SkipVote {
        accounting_complete: bool,
        incomplete_reasons: Vec<IncompleteReason>,
        live: Live,
        replay: VoteReplay,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    pub supported: bool,
    pub contract_valid: bool,
    pub performance_gate: bool,
    pub enabled: bool,
    #[serde(deserialize_with = "required_nullable")]
    pub reason: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    #[serde(deserialize_with = "required_nullable")]
    pub scope_id: Option<String>,
    pub workchain: i32,
    pub shard: U64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    Active,
    Stopping,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub network_id: String,
    pub scope: Scope,
    pub session_id: String,
    #[serde(deserialize_with = "required_nullable")]
    pub current_slot: Option<u32>,
    #[serde(deserialize_with = "required_nullable")]
    pub last_finalized_slot: Option<u32>,
    pub lifecycle: Lifecycle,
    #[serde(deserialize_with = "required_nullable")]
    pub stop_started_monotonic_ns: Option<U64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sessions {
    pub active: U64,
    pub started: U64,
    pub stop_started: U64,
    #[serde(deserialize_with = "required_nullable")]
    pub stopped: Option<U64>,
    pub stopping: U64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Consensus {
    pub actions: Vec<Action>,
    #[serde(deserialize_with = "unique_map")]
    pub capabilities: BTreeMap<String, Capability>,
    pub contexts: Vec<Context>,
    pub instrumentation_complete: bool,
    pub incomplete_reasons: Vec<IncompleteReason>,
    pub repeated_requests: U64,
    pub retired_requests: U64,
    pub post_terminal_progress: U64,
    pub sessions: Sessions,
}

fn exact(map: &BTreeMap<String, U64>, names: &[&str]) -> bool {
    map.len() == names.len() && names.iter().all(|name| map.contains_key(*name))
}
fn reasons(valid: bool, values: &[IncompleteReason]) -> bool {
    values.windows(2).all(|v| v[0] < v[1]) && (valid == values.is_empty())
}
const OUTCOMES: &[&str] = &["enqueued", "failed", "cancelled", "suppressed", "unknown"];
const TERMINALS: &[&str] = &["applied", "failed", "cancelled", "suppressed", "unknown"];
const PROPOSAL_PHASES: &[&str] = &["requested", "signed", "candidate_published"];
const VOTE_PHASES: &[&str] = &[
    "requested",
    "intent_committed",
    "signed",
    "signed_committed",
    "local_applied",
    "broadcast_enqueued",
];
const PROPOSAL_FAILURES: &[&str] =
    &["missing_signer", "sign_backend", "finality_behind", "superseded", "cancelled"];
const VOTE_FAILURES: &[&str] = &[
    "missing_signer",
    "sign_backend",
    "finality_behind",
    "superseded",
    "cancelled",
    "intent_storage",
    "signed_storage",
    "journal_unusable",
    "duplicate_or_stale",
];
const SIGNED_REPLAY: &[&str] = &["requested", "restored_signed", "local_applied"];
const INTENT_REPLAY: &[&str] = &["requested", "signed", "signed_committed", "local_applied"];
const POSITIVE: &[&str] = &[
    "leader_progress",
    "local_actions",
    "session_lifecycle",
    "storage_commit_ack",
    "typed_consensus_progress",
];
const NEGATIVE: &[(&str, &str)] = &[
    ("cohort_success_rate", "closed_cohort_not_implemented"),
    ("durable_finality", "hardware_power_loss_not_proven"),
    ("network_result", "local_enqueue_is_not_network_observation"),
    ("pq_queue", "synchronous_signer_no_queue"),
    ("vote_assigned", "no_independent_assigned_denominator"),
    ("vote_deadline", "no_frozen_protocol_deadline"),
];
impl Consensus {
    /// A session outside the approved masterchain scope is active.
    pub fn unapproved_scope(&self) -> bool {
        self.contexts.iter().any(|c| c.scope.scope_id.is_none())
    }
    /// Older publishers reported the unapproved scope as an incomplete reason.
    pub fn legacy_scope_reason(&self) -> bool {
        self.incomplete_reasons.contains(&IncompleteReason::ScopeUnapproved)
    }
    pub fn validate(&self, network: &str) -> Result<(), String> {
        if self.actions.len() != 4
            || self.capabilities.len() != 11
            || self.contexts.len() > 8
            || !self.incomplete_reasons.windows(2).all(|v| v[0] < v[1])
        {
            return Err("invalid C04 inventory bounds".into());
        }
        let mut all_reasons = BTreeSet::new();
        for (index, action) in self.actions.iter().enumerate() {
            let (actual, complete, reasons_list, live, replay): (
                usize,
                bool,
                &Vec<IncompleteReason>,
                &Live,
                Option<&VoteReplay>,
            ) = match action {
                Action::Proposal { accounting_complete, incomplete_reasons, live, replay } => {
                    if replay.is_some() {
                        return Err("proposal replay must be null".into());
                    }
                    (0, *accounting_complete, incomplete_reasons, live, None)
                }
                Action::NotarizeVote { accounting_complete, incomplete_reasons, live, replay } => {
                    (1, *accounting_complete, incomplete_reasons, live, Some(replay))
                }
                Action::FinalizeVote { accounting_complete, incomplete_reasons, live, replay } => {
                    (2, *accounting_complete, incomplete_reasons, live, Some(replay))
                }
                Action::SkipVote { accounting_complete, incomplete_reasons, live, replay } => {
                    (3, *accounting_complete, incomplete_reasons, live, Some(replay))
                }
            };
            if actual != index
                || !reasons(complete, reasons_list)
                || !exact(&live.outcomes, OUTCOMES)
                || !exact(&live.phases, if index == 0 { PROPOSAL_PHASES } else { VOTE_PHASES })
                || !exact(
                    &live.failures,
                    if index == 0 { PROPOSAL_FAILURES } else { VOTE_FAILURES },
                )
                || (live.pending.0 == 0 && live.oldest_age_ns.is_some())
                || (complete && live.pending.0 > 0 && live.oldest_age_ns.is_none())
            {
                return Err("invalid C04 action row".into());
            }
            all_reasons.extend(reasons_list.iter().copied());
            if let Some(replay) = replay {
                for (row, phases) in
                    [(&replay.signed_record, SIGNED_REPLAY), (&replay.intent_only, INTENT_REPLAY)]
                {
                    if !exact(&row.phases, phases)
                        || !exact(&row.terminals, TERMINALS)
                        || (row.pending.0 == 0 && row.oldest_age_ns.is_some())
                        || (complete && row.pending.0 > 0 && row.oldest_age_ns.is_none())
                    {
                        return Err("invalid C04 replay row".into());
                    }
                }
            }
        }
        for (name, reason) in NEGATIVE {
            let cap = self.capabilities.get(*name).ok_or("missing C04 capability")?;
            if cap.supported
                || cap.contract_valid
                || cap.performance_gate
                || cap.enabled
                || cap.reason.as_deref() != Some(*reason)
            {
                return Err("invalid unsupported C04 capability".into());
            }
        }
        for name in POSITIVE {
            let cap = self.capabilities.get(*name).ok_or("missing C04 capability")?;
            if cap.supported {
                if cap.reason.is_some() {
                    return Err("supported C04 capability has reason".into());
                }
            } else if cap.enabled
                || cap.contract_valid
                || cap.performance_gate
                || !matches!(
                    cap.reason.as_deref(),
                    Some(
                        "not_implemented"
                            | "observation_incomplete"
                            | "lifecycle_unverified"
                            | "scope_unapproved"
                    )
                )
            {
                return Err("invalid unavailable C04 capability".into());
            }
            if cap.enabled && !cap.supported {
                return Err("invalid C04 enablement".into());
            }
        }
        let mut seen = BTreeSet::new();
        let mut unapproved_scope = false;
        for context in &self.contexts {
            if !hash(&context.network_id)
                || context.network_id != network
                || !hash(&context.session_id)
                || !seen.insert((
                    context.scope.workchain,
                    context.scope.shard.0,
                    context.session_id.as_str(),
                ))
                || !matches!(context.scope.scope_id.as_deref(), None | Some("masterchain"))
                || (context.scope.scope_id.as_deref() == Some("masterchain")
                    && (context.scope.workchain != -1
                        || context.scope.shard.0 != 9_223_372_036_854_775_808))
                || matches!(context.lifecycle, Lifecycle::Active)
                    && context.stop_started_monotonic_ns.is_some()
                || matches!(context.lifecycle, Lifecycle::Stopping)
                    && context.stop_started_monotonic_ns.is_none()
            {
                return Err("invalid C04 context".into());
            }
            unapproved_scope |= context.scope.scope_id.is_none();
        }
        if unapproved_scope {
            let cap = self
                .capabilities
                .get("typed_consensus_progress")
                .ok_or("missing typed progress capability")?;
            // The envelope's coverage names the unapproved scope; older
            // publishers reported it as an incomplete reason, still accepted.
            if cap.supported || cap.reason.as_deref() != Some("scope_unapproved") {
                return Err("unapproved C04 context scope".into());
            }
        }
        if self.sessions.stopped.is_none() {
            let cap =
                self.capabilities.get("session_lifecycle").ok_or("missing lifecycle capability")?;
            if cap.supported
                || cap.reason.as_deref() != Some("lifecycle_unverified")
                || !self.incomplete_reasons.contains(&IncompleteReason::SessionLifecycleUnverified)
            {
                return Err("unverified C04 session drain".into());
            }
        }
        if !all_reasons.is_subset(&self.incomplete_reasons.iter().copied().collect())
            || (self.instrumentation_complete
                && (!self.incomplete_reasons.is_empty() || self.sessions.stopped.is_none()))
            || (!self.instrumentation_complete && self.incomplete_reasons.is_empty())
            || (self.post_terminal_progress.0 > 0
                && (!self.incomplete_reasons.contains(&IncompleteReason::ObservationGap)
                    || !self.actions.iter().any(|action| match action {
                        Action::Proposal { incomplete_reasons, .. }
                        | Action::NotarizeVote { incomplete_reasons, .. }
                        | Action::FinalizeVote { incomplete_reasons, .. }
                        | Action::SkipVote { incomplete_reasons, .. } => {
                            incomplete_reasons.contains(&IncompleteReason::ObservationGap)
                        }
                    })))
        {
            return Err("inconsistent C04 completeness".into());
        }
        Ok(())
    }
}
