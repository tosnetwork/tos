//! Fixed catalog of metrics derived from consecutive archived native samples.
//! Every point is computed from evidence already delivered to the run; there
//! is no PromQL, no resampling and no interpolation. Gaps and resets are
//! explicit so a short or broken history never looks like a healthy flat line.
use crate::{
    consensus_v2::{Action, Consensus, Lifecycle},
    evidence::StoredEvidence,
    native::{NativePayload, NativePayloadV2, NativePayloadV3, PqSnapshot},
    query_output::{CoverageDto, LabelDto, MetricSeriesDto, PointDto},
    wire::U64,
};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// One point per sample.
    Gauge,
    /// Difference between consecutive samples of one process epoch.
    Delta,
}

#[derive(Debug, Clone, Copy)]
pub struct MetricSpec {
    pub id: &'static str,
    pub unit: &'static str,
    pub kind: Kind,
}

pub const CATALOG: &[MetricSpec] = &[
    MetricSpec { id: "native_consensus_last_finalized_slot", unit: "slots", kind: Kind::Gauge },
    MetricSpec { id: "native_consensus_finalized_slot_advance", unit: "slots", kind: Kind::Delta },
    MetricSpec { id: "native_consensus_current_slot", unit: "slots", kind: Kind::Gauge },
    MetricSpec { id: "native_sessions_active", unit: "sessions", kind: Kind::Gauge },
    MetricSpec { id: "native_sessions_stopping", unit: "sessions", kind: Kind::Gauge },
    MetricSpec { id: "native_proposal_enqueued_delta", unit: "operations", kind: Kind::Delta },
    MetricSpec { id: "native_notarize_vote_enqueued_delta", unit: "operations", kind: Kind::Delta },
    MetricSpec { id: "native_finalize_vote_enqueued_delta", unit: "operations", kind: Kind::Delta },
    MetricSpec { id: "native_skip_vote_enqueued_delta", unit: "operations", kind: Kind::Delta },
    MetricSpec { id: "native_proposal_failed_delta", unit: "operations", kind: Kind::Delta },
    MetricSpec { id: "native_notarize_vote_failed_delta", unit: "operations", kind: Kind::Delta },
    MetricSpec { id: "native_finalize_vote_failed_delta", unit: "operations", kind: Kind::Delta },
    MetricSpec { id: "native_skip_vote_failed_delta", unit: "operations", kind: Kind::Delta },
    MetricSpec { id: "native_proposal_pending", unit: "operations", kind: Kind::Gauge },
    MetricSpec { id: "native_notarize_vote_pending", unit: "operations", kind: Kind::Gauge },
    MetricSpec { id: "native_finalize_vote_pending", unit: "operations", kind: Kind::Gauge },
    MetricSpec { id: "native_skip_vote_pending", unit: "operations", kind: Kind::Gauge },
    MetricSpec { id: "native_vote_oldest_pending_age_ms", unit: "milliseconds", kind: Kind::Gauge },
    MetricSpec { id: "native_pq_sign_failed_delta", unit: "operations", kind: Kind::Delta },
    MetricSpec { id: "native_pq_verify_failed_delta", unit: "operations", kind: Kind::Delta },
    MetricSpec { id: "native_pq_sign_succeeded_delta", unit: "operations", kind: Kind::Delta },
    MetricSpec { id: "native_chain_applied_seqno", unit: "blocks", kind: Kind::Gauge },
    MetricSpec { id: "native_chain_applied_age_seconds", unit: "seconds", kind: Kind::Gauge },
    MetricSpec { id: "native_chain_served_gap", unit: "blocks", kind: Kind::Gauge },
];

pub fn spec(metric_id: &str) -> Option<&'static MetricSpec> {
    CATALOG.iter().find(|spec| spec.id == metric_id)
}

pub fn catalog_ids() -> impl Iterator<Item = &'static str> {
    CATALOG.iter().map(|spec| spec.id)
}

/// Typed view over one derived native row's retained origin payload.
#[derive(Debug, Clone)]
pub enum Native {
    V1(Box<NativePayload>),
    V2(Box<NativePayloadV2>),
    V3(Box<NativePayloadV3>),
}

impl Native {
    pub fn consensus(&self) -> Option<&Consensus> {
        match self {
            Self::V1(_) => None,
            Self::V2(v) => v.consensus.as_ref(),
            Self::V3(v) => v.consensus.as_ref(),
        }
    }
    pub fn pq_sign(&self) -> Option<&PqSnapshot> {
        match self {
            Self::V1(v) => v.pq_sign.as_ref(),
            Self::V2(v) => v.pq_sign.as_ref(),
            Self::V3(v) => v.pq_sign.as_ref(),
        }
    }
    pub fn pq_verify(&self) -> Option<&PqSnapshot> {
        match self {
            Self::V1(v) => v.pq_verify.as_ref(),
            Self::V2(v) => v.pq_verify.as_ref(),
            Self::V3(v) => v.pq_verify.as_ref(),
        }
    }
    pub fn chain(&self) -> Option<&crate::native::ChainAnchors> {
        match self {
            Self::V3(v) => v.chain.as_ref(),
            _ => None,
        }
    }
}

/// Parse the retained origin payload of a derived native consensus row.
/// Returns `Ok(None)` for rows that are not native projections.
pub fn parse_row(entry: &StoredEvidence) -> Result<Option<Native>, &'static str> {
    let payload = &entry.record.payload;
    if entry.record.source_id != "native_core"
        || payload.get("component").and_then(Value::as_str) != Some("consensus")
    {
        return Ok(None);
    }
    let origin = payload.get("origin_payload").ok_or("SCHEMA_MISMATCH")?.clone();
    let parsed = match payload.get("origin_source_version").and_then(Value::as_str) {
        Some("native-core-v1") => {
            Native::V1(Box::new(serde_json::from_value(origin).map_err(|_| "SCHEMA_MISMATCH")?))
        }
        Some("native-core-v2") => {
            Native::V2(Box::new(serde_json::from_value(origin).map_err(|_| "SCHEMA_MISMATCH")?))
        }
        Some("native-core-v3") => {
            Native::V3(Box::new(serde_json::from_value(origin).map_err(|_| "SCHEMA_MISMATCH")?))
        }
        _ => return Err("SCHEMA_MISMATCH"),
    };
    Ok(Some(parsed))
}

fn action_row<'a>(consensus: &'a Consensus, name: &str) -> Option<&'a crate::consensus_v2::Live> {
    consensus.actions.iter().find_map(|action| match action {
        Action::Proposal { live, .. } if name == "proposal" => Some(live),
        Action::NotarizeVote { live, .. } if name == "notarize_vote" => Some(live),
        Action::FinalizeVote { live, .. } if name == "finalize_vote" => Some(live),
        Action::SkipVote { live, .. } if name == "skip_vote" => Some(live),
        _ => None,
    })
}

fn masterchain_max(
    consensus: &Consensus,
    pick: impl Fn(&crate::consensus_v2::Context) -> Option<u32>,
) -> Option<u64> {
    consensus
        .contexts
        .iter()
        .filter(|context| {
            context.scope.scope_id.as_deref() == Some("masterchain")
                && matches!(context.lifecycle, Lifecycle::Active)
        })
        .filter_map(pick)
        .map(u64::from)
        .max()
}

/// The raw counter or gauge value behind a catalog metric for one sample.
/// `None` means the sample does not carry the field; no zero is invented.
pub fn raw_value(spec: &MetricSpec, native: &Native) -> Option<u64> {
    let consensus = native.consensus();
    let action = |name: &str| consensus.and_then(|c| action_row(c, name));
    let sum_failures = |name: &str| {
        action(name).map(|live| live.failures.values().fold(0u64, |acc, v| acc.saturating_add(v.0)))
    };
    let outcome =
        |name: &str, key: &str| action(name).and_then(|live| live.outcomes.get(key)).map(|v| v.0);
    match spec.id {
        "native_consensus_last_finalized_slot" | "native_consensus_finalized_slot_advance" => {
            consensus.and_then(|c| masterchain_max(c, |context| context.last_finalized_slot))
        }
        "native_consensus_current_slot" => {
            consensus.and_then(|c| masterchain_max(c, |context| context.current_slot))
        }
        "native_sessions_active" => consensus.map(|c| c.sessions.active.0),
        "native_sessions_stopping" => consensus.map(|c| c.sessions.stopping.0),
        "native_proposal_enqueued_delta" => outcome("proposal", "enqueued"),
        "native_notarize_vote_enqueued_delta" => outcome("notarize_vote", "enqueued"),
        "native_finalize_vote_enqueued_delta" => outcome("finalize_vote", "enqueued"),
        "native_skip_vote_enqueued_delta" => outcome("skip_vote", "enqueued"),
        "native_proposal_failed_delta" => sum_failures("proposal"),
        "native_notarize_vote_failed_delta" => sum_failures("notarize_vote"),
        "native_finalize_vote_failed_delta" => sum_failures("finalize_vote"),
        "native_skip_vote_failed_delta" => sum_failures("skip_vote"),
        "native_proposal_pending" => action("proposal").map(|live| live.pending.0),
        "native_notarize_vote_pending" => action("notarize_vote").map(|live| live.pending.0),
        "native_finalize_vote_pending" => action("finalize_vote").map(|live| live.pending.0),
        "native_skip_vote_pending" => action("skip_vote").map(|live| live.pending.0),
        "native_vote_oldest_pending_age_ms" => consensus.map(|c| {
            ["notarize_vote", "finalize_vote", "skip_vote", "proposal"]
                .iter()
                .filter_map(|name| action_row(c, name))
                .filter_map(|live| live.oldest_age_ns.map(|age| age.0 / 1_000_000))
                .max()
                .unwrap_or(0)
        }),
        "native_pq_sign_failed_delta" => native.pq_sign().map(|pq| pq.failed.0),
        "native_pq_verify_failed_delta" => native.pq_verify().map(|pq| pq.failed.0),
        "native_pq_sign_succeeded_delta" => native.pq_sign().map(|pq| pq.succeeded.0),
        "native_chain_applied_seqno" => native.chain().map(|chain| u64::from(chain.applied.seqno)),
        "native_chain_applied_age_seconds" => native.chain().map(|chain| {
            chain.observed_unix_seconds.0.saturating_sub(chain.applied_advanced_unix_seconds.0)
        }),
        "native_chain_served_gap" => native.chain().and_then(|chain| {
            chain
                .served
                .as_ref()
                .map(|served| u64::from(chain.applied.seqno.saturating_sub(served.seqno)))
        }),
        _ => None,
    }
}

pub struct Sample<'a> {
    pub entry: &'a StoredEvidence,
    pub native: Native,
}

/// Derive one series for a node from its ordered native samples. Samples
/// before `start` only seed the delta baseline and never emit points.
pub fn derive(
    spec: &MetricSpec,
    node_id: &str,
    scope_id: &str,
    samples: &[Sample<'_>],
    start_ms: i64,
    end_ms: i64,
) -> Result<MetricSeriesDto, &'static str> {
    let mut points = Vec::new();
    let mut source_evidence_ids = Vec::new();
    let mut gaps: Vec<String> = Vec::new();
    let mut missing_fields: Vec<String> = Vec::new();
    let mut reset_count = 0u64;
    let mut clock = "valid";
    let mut previous: Option<(&str, u64)> = None;
    let push_gap = |gaps: &mut Vec<String>, text: String| {
        if gaps.len() < 32 && !gaps.contains(&text) {
            gaps.push(text);
        }
    };
    for sample in samples {
        let record = &sample.entry.record;
        let at = record.observed_at_ms;
        let in_window = at >= start_ms && at < end_ms;
        let value = raw_value(spec, &sample.native);
        if !record.quality.clock_valid {
            clock = "invalid";
        }
        match spec.kind {
            Kind::Gauge => {
                if !in_window {
                    continue;
                }
                source_evidence_ids.push(sample.entry.evidence_id.clone());
                if value.is_none() && !missing_fields.iter().any(|f| f == spec.id) {
                    missing_fields.push(spec.id.to_owned());
                }
                points.push(PointDto { at: time(at)?, value: value.map(|v| v as f64) });
            }
            Kind::Delta => {
                let epoch = record.process_epoch.as_str();
                let Some(current) = value else {
                    if in_window {
                        push_gap(&mut gaps, format!("sample without {} at {}", spec.id, time(at)?));
                    }
                    previous = None;
                    continue;
                };
                match previous {
                    Some((prior_epoch, prior)) if prior_epoch == epoch => {
                        if in_window {
                            source_evidence_ids.push(sample.entry.evidence_id.clone());
                            match current.checked_sub(prior) {
                                Some(delta) => points
                                    .push(PointDto { at: time(at)?, value: Some(delta as f64) }),
                                None => {
                                    reset_count = reset_count.saturating_add(1);
                                    push_gap(
                                        &mut gaps,
                                        format!("counter regression at {}", time(at)?),
                                    );
                                }
                            }
                        }
                    }
                    Some(_) => {
                        reset_count = reset_count.saturating_add(1);
                        if in_window {
                            push_gap(&mut gaps, format!("process epoch changed at {}", time(at)?));
                        }
                    }
                    None => {
                        if in_window {
                            push_gap(&mut gaps, format!("no prior sample before {}", time(at)?));
                        }
                    }
                }
                previous = Some((epoch, current));
            }
        }
    }
    let status = if points.is_empty() || !gaps.is_empty() || !missing_fields.is_empty() {
        "partial"
    } else {
        "complete"
    };
    Ok(MetricSeriesDto {
        metric_id: spec.id.to_owned(),
        node_id: node_id.to_owned(),
        scope_id: scope_id.to_owned(),
        labels: Vec::<LabelDto>::new(),
        unit: spec.unit.to_owned(),
        semantic_type: match spec.kind {
            Kind::Gauge => "gauge",
            Kind::Delta => "counter",
        }
        .into(),
        population: match spec.kind {
            Kind::Gauge => "archived native samples at source cadence; step_seconds not applied",
            Kind::Delta => {
                "difference between consecutive archived native samples of one process epoch; step_seconds not applied"
            }
        }
        .into(),
        clock: clock.into(),
        samples_count: U64(points.len() as u64),
        points: Some(points),
        summary: None,
        expected_samples: None,
        coverage: CoverageDto {
            status: status.into(),
            missing_fields,
            gaps,
            sampling_policy: "native_fixed_15s_archive".into(),
        },
        reset_count: U64(reset_count),
        source_evidence_ids,
    })
}

fn time(ms: i64) -> Result<String, &'static str> {
    use chrono::{SecondsFormat, TimeZone, Utc};
    Utc.timestamp_millis_opt(ms)
        .single()
        .map(|v| v.to_rfc3339_opts(SecondsFormat::Millis, true))
        .ok_or("SCHEMA_MISMATCH")
}
