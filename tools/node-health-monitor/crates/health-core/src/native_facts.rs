//! Deterministic validator facts derived from the bounded native snapshot.
//!
//! The native publisher reports raw counters, pending ages and typed session
//! contexts. This module turns them into the fixed rule facts without adding
//! a duty denominator, a protocol deadline or any success proxy the source
//! does not carry. Legitimate refusals (duplicate, stale, superseded,
//! cancelled, finality-behind) are never counted as local failures.
use crate::{
    consensus_v2::{Action, Consensus, Lifecycle, Live},
    native::{NativeRecord, PqSnapshot},
    rules::{Fact, FactId},
    wire::U64,
};
use serde::{Deserialize, Serialize};

/// Fixed catalog of facts this derivation produces for one native sample.
/// The manager inventory must list exactly these facts for the native source.
pub const CATALOG: [FactId; 7] = [
    FactId::ChainProgressAgeMs,
    FactId::ActionFailures,
    FactId::ActionOldestMs,
    FactId::PqSigningFailures,
    FactId::StorageAckFailures,
    FactId::StorageUsable,
    FactId::SessionStopPendingMs,
];
/// Local execution failures. Storage keys are absent from the proposal row.
const LOCAL_FAILURES: [&str; 5] =
    ["missing_signer", "sign_backend", "intent_storage", "signed_storage", "journal_unusable"];
const STORAGE_FAILURES: [&str; 3] = ["intent_storage", "signed_storage", "journal_unusable"];

/// Per-node state carried between consecutive samples of one process epoch.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativeFactState {
    pub process_epoch: String,
    pub source_epoch: String,
    /// Highest finalized masterchain slot seen and when it last advanced.
    pub finalized_slot: Option<u32>,
    pub finalized_advanced_ms: Option<u64>,
    /// Highest applied masterchain seqno (v3 anchors) and when it advanced.
    pub applied_seqno: Option<u32>,
    pub applied_advanced_ms: Option<u64>,
    /// First observation of a session stop that has not completed.
    pub stopping_since_ms: Option<u64>,
}

/// Derived facts plus the reasons a fact is missing. `complete` is true only
/// when every catalog fact is present and the publisher reports intact
/// counters; unsupported capabilities do not make counters incomplete.
#[derive(Debug, Clone)]
pub struct DerivedFacts {
    pub facts: Vec<Fact>,
    pub complete: bool,
    pub missing: Vec<&'static str>,
}

fn live(action: &Action) -> &Live {
    match action {
        Action::Proposal { live, .. }
        | Action::NotarizeVote { live, .. }
        | Action::FinalizeVote { live, .. }
        | Action::SkipVote { live, .. } => live,
    }
}
fn sum(consensus: &Consensus, keys: &[&str]) -> Option<u64> {
    let mut total = 0u64;
    for action in &consensus.actions {
        for key in keys {
            if let Some(v) = live(action).failures.get(*key) {
                total = total.checked_add(v.0)?;
            }
        }
    }
    Some(total)
}
fn oldest_ms(consensus: &Consensus) -> Option<u64> {
    let mut oldest = 0u64;
    for action in &consensus.actions {
        let row = live(action);
        if row.pending.0 > 0 {
            let age = row.oldest_age_ns?.0.checked_div(1_000_000)?;
            oldest = oldest.max(age);
        }
        let replay = match action {
            Action::Proposal { replay, .. } => replay.as_ref(),
            Action::NotarizeVote { replay, .. }
            | Action::FinalizeVote { replay, .. }
            | Action::SkipVote { replay, .. } => Some(replay),
        };
        if let Some(replay) = replay {
            for row in [&replay.signed_record, &replay.intent_only] {
                if row.pending.0 > 0 {
                    let age = row.oldest_age_ns?.0.checked_div(1_000_000)?;
                    oldest = oldest.max(age);
                }
            }
        }
    }
    Some(oldest)
}
fn requested(consensus: &Consensus) -> u64 {
    consensus
        .actions
        .iter()
        .filter_map(|a| live(a).phases.get("requested").map(|v| v.0))
        .fold(0u64, |acc, v| acc.saturating_add(v))
}
/// Counter integrity reasons. Scope approval and lifecycle verification are
/// capability gaps, not evidence that counters were dropped or saturated.
fn counters_intact(consensus: &Consensus) -> bool {
    use crate::consensus_v2::IncompleteReason::*;
    !consensus.incomplete_reasons.iter().any(|r| {
        matches!(
            r,
            CasExhaustion
                | ContextCapacity
                | CounterSaturation
                | LedgerCapacity
                | ObservationGap
                | PendingCapacity
                | SnapshotContention
        )
    })
}
/// Finalized slot of the single active approved masterchain session, if any.
fn finalized_slot(consensus: &Consensus) -> Option<u32> {
    let mut found = None;
    for c in &consensus.contexts {
        if c.scope.scope_id.as_deref() == Some("masterchain")
            && matches!(c.lifecycle, Lifecycle::Active)
        {
            if let Some(slot) = c.last_finalized_slot {
                found = Some(found.map_or(slot, |f: u32| f.max(slot)));
            }
        }
    }
    found
}

/// Derive the fixed facts for one sample observed at `observed_ms` (UTC ms).
/// The state is reset when the process or source epoch changes.
pub fn derive(
    record: &NativeRecord,
    observed_ms: u64,
    state: &mut NativeFactState,
) -> Result<DerivedFacts, String> {
    let (process_epoch, source_epoch) = match record {
        NativeRecord::V1(v) => (&v.process_epoch, &v.source_epoch),
        NativeRecord::V2(v) => (&v.process_epoch, &v.source_epoch),
        NativeRecord::V3(v) => (&v.process_epoch, &v.source_epoch),
    };
    if state.process_epoch != *process_epoch || state.source_epoch != *source_epoch {
        *state = NativeFactState {
            process_epoch: process_epoch.clone(),
            source_epoch: source_epoch.clone(),
            ..NativeFactState::default()
        };
    }
    let (pq_sign, consensus, chain, quality): (
        Option<&PqSnapshot>,
        Option<&Consensus>,
        Option<&crate::native::ChainAnchors>,
        &crate::native::Quality,
    ) = match record {
        NativeRecord::V1(v) => (v.payload.pq_sign.as_ref(), None, None, &v.quality),
        NativeRecord::V2(v) => {
            (v.payload.pq_sign.as_ref(), v.payload.consensus.as_ref(), None, &v.quality)
        }
        NativeRecord::V3(v) => (
            v.payload.pq_sign.as_ref(),
            v.payload.consensus.as_ref(),
            v.payload.chain.as_ref(),
            &v.quality,
        ),
    };
    let mut facts = Vec::with_capacity(CATALOG.len());
    let mut missing = Vec::new();
    let mut push = |id: FactId, value: Option<u64>, reason: &'static str| match value {
        Some(v) => facts.push(Fact { id, value: U64(v) }),
        None => missing.push(reason),
    };

    // Chain progress: prefer the publisher's own applied-advance clock (v3);
    // otherwise track the finalized masterchain slot across samples.
    let chain_age = if let Some(anchors) = chain {
        let seqno = anchors.applied.seqno;
        if state.applied_seqno.is_none_or(|s| seqno > s) {
            state.applied_seqno = Some(seqno);
            state.applied_advanced_ms = Some(observed_ms);
        }
        anchors
            .observed_unix_seconds
            .0
            .checked_sub(anchors.applied_advanced_unix_seconds.0)
            .and_then(|s| s.checked_mul(1000))
    } else if let Some(slot) = consensus.and_then(finalized_slot) {
        if state.finalized_slot.is_none_or(|s| slot > s) {
            state.finalized_slot = Some(slot);
            state.finalized_advanced_ms = Some(observed_ms);
        }
        state.finalized_advanced_ms.and_then(|t| observed_ms.checked_sub(t))
    } else {
        None
    };
    push(FactId::ChainProgressAgeMs, chain_age, "no_masterchain_progress_source");

    push(
        FactId::ActionFailures,
        consensus.and_then(|c| sum(c, &LOCAL_FAILURES)),
        "no_consensus_actions",
    );
    push(FactId::ActionOldestMs, consensus.and_then(oldest_ms), "no_pending_age");
    push(FactId::PqSigningFailures, pq_sign.map(|p| p.failed.0), "pq_sign_unavailable");
    push(
        FactId::StorageAckFailures,
        consensus.and_then(|c| sum(c, &STORAGE_FAILURES)),
        "no_consensus_actions",
    );
    // Storage is unusable only when votes were requested and no commit
    // acknowledgement was ever observed; an idle node is not unusable.
    push(
        FactId::StorageUsable,
        consensus.map(|c| {
            let ack = c.capabilities.get("storage_commit_ack").is_some_and(|cap| cap.supported);
            u64::from(ack || requested(c) == 0)
        }),
        "no_consensus_actions",
    );
    let stop_pending = consensus.map(|c| {
        if c.sessions.stopping.0 > 0 {
            let since = *state.stopping_since_ms.get_or_insert(observed_ms);
            observed_ms.saturating_sub(since)
        } else {
            state.stopping_since_ms = None;
            0
        }
    });
    push(FactId::SessionStopPendingMs, stop_pending, "no_consensus_sessions");

    let intact = consensus.is_none_or(counters_intact)
        && quality.producer_dropped.0 == 0
        && quality.relay_dropped.0 == 0
        && quality.parse_errors.0 == 0
        && pq_sign.is_none_or(|p| p.complete);
    let complete = intact && facts.len() == CATALOG.len();
    Ok(DerivedFacts { facts, complete, missing })
}
