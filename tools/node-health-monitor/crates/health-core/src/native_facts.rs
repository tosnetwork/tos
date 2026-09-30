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
/// Version of the derived fact catalog. It is appended to the fact frame's
/// source epoch so that a catalog change starts a new source epoch instead of
/// producing a second body for an already archived generation, which M would
/// rightly quarantine as a source conflict.
pub const CATALOG_VERSION: u32 = 2;
pub const CATALOG: [FactId; 8] = [
    FactId::InitializationPendingMs,
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
const STORAGE_COMMIT_PHASES: [&str; 2] = ["intent_committed", "signed_committed"];

/// A node whose applied chain advanced within this window counts as initialized.
pub const INITIALIZED_CHAIN_AGE_MS: u64 = 60_000;
/// Trailing window over which unexplained anonymous memory growth is measured.
pub const MEMORY_GROWTH_WINDOW_MS: u64 = 900_000;
const MEMORY_SAMPLES_MAX: usize = 128;

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
    /// First sample of this process epoch; initialization is measured from it.
    pub first_seen_ms: Option<u64>,
    /// Bounded trailing window of (observed_ms, anon_bytes) process samples.
    pub anon_samples: Vec<(u64, u64)>,
    /// Vote storage requests and commit acknowledgements at the previous sample.
    #[serde(default)]
    pub storage_requested: Option<u64>,
    #[serde(default)]
    pub storage_committed: Option<u64>,
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
/// Commit acknowledgements the node recorded for its vote storage writes.
fn committed(consensus: &Consensus) -> u64 {
    consensus
        .actions
        .iter()
        .flat_map(|a| STORAGE_COMMIT_PHASES.iter().filter_map(|k| live(a).phases.get(*k)))
        .fold(0u64, |acc, v| acc.saturating_add(v.0))
}
/// Storage usability from what the node did, not from whether the publisher's
/// bounded observation stream stayed gap-free. A proven commit-ack capability
/// or an idle node is usable. Otherwise, within one epoch, new vote storage
/// requests with no new commit acknowledgement since the previous sample mean
/// the journal is not acknowledging (0); acknowledged commits mean it is (1).
/// The first sample of an epoch is usable only if commits were ever
/// acknowledged. A replay that overflowed the observation ledger therefore no
/// longer reads as an unusable journal for the rest of the process lifetime.
fn storage_usable(state: &mut NativeFactState, consensus: &Consensus) -> u64 {
    let ack = consensus.capabilities.get("storage_commit_ack").is_some_and(|cap| cap.supported);
    let requests = requested(consensus);
    let commits = committed(consensus);
    let previous = state.storage_requested.zip(state.storage_committed);
    state.storage_requested = Some(requests);
    state.storage_committed = Some(commits);
    if ack || requests == 0 {
        return 1;
    }
    match previous {
        Some((old_requests, old_commits)) => {
            u64::from(!(requests > old_requests && commits <= old_commits))
        }
        None => u64::from(commits > 0),
    }
}
fn requested(consensus: &Consensus) -> u64 {
    consensus
        .actions
        .iter()
        .filter_map(|a| live(a).phases.get("requested").map(|v| v.0))
        .fold(0u64, |acc, v| acc.saturating_add(v))
}
/// Counter integrity reasons. Scope approval, lifecycle verification and an
/// observation gap (a bounded publication that once missed a diagnostic
/// observation, latched for the process lifetime) are coverage gaps; they do
/// not mean the cumulative action, storage or PQ counters were dropped or
/// saturated, so the facts derived from those counters stay usable.
fn counters_intact(consensus: &Consensus) -> bool {
    use crate::consensus_v2::IncompleteReason::*;
    !consensus.incomplete_reasons.iter().any(|r| {
        matches!(
            r,
            CasExhaustion
                | ContextCapacity
                | CounterSaturation
                | LedgerCapacity
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

    // Initialization: a validator is initialized once a consensus session is
    // active; any node is initialized once its applied chain advanced within
    // the last minute. Until then the pending time counts from the first
    // sample of this process epoch.
    let first_seen = *state.first_seen_ms.get_or_insert(observed_ms);
    let session_active = consensus.is_some_and(|c| c.sessions.active.0 > 0);
    let chain_recent =
        chain.is_some() && chain_age.is_some_and(|age| age <= INITIALIZED_CHAIN_AGE_MS);
    let initialization = if consensus.is_none() && chain.is_none() {
        None
    } else if session_active || chain_recent {
        Some(0)
    } else {
        Some(observed_ms.saturating_sub(first_seen))
    };
    push(FactId::InitializationPendingMs, initialization, "no_initialization_source");

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
    // acknowledgement followed; an idle node is not unusable, and neither is a
    // node whose publisher merely lost observation events during a replay.
    push(
        FactId::StorageUsable,
        consensus.map(|c| storage_usable(state, c)),
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

/// Gap between the applied masterchain block and the block served to lite
/// clients (v3 anchors). `None` when the node serves no lite state, which is
/// not a gap of zero.
pub fn chain_gap(record: &NativeRecord) -> Option<u64> {
    let NativeRecord::V3(v) = record else { return None };
    let chain = v.payload.chain.as_ref()?;
    let served = chain.served.as_ref()?;
    Some(u64::from(chain.applied.seqno.saturating_sub(served.seqno)))
}

/// Age of the last key block the node knows, in ms, from the v3 anchors'
/// own clocks (observation time minus the key block's time). Absent when the
/// publisher has no key block anchor; never invented from the zero state.
pub fn key_block_age_ms(record: &NativeRecord) -> Option<u64> {
    let NativeRecord::V3(v) = record else { return None };
    let chain = v.payload.chain.as_ref()?;
    let key = chain.key_block.as_ref()?.as_ref()?;
    chain.observed_unix_seconds.0.checked_sub(key.unix_seconds.0)?.checked_mul(1000)
}

/// Duty facts from the node-state section: validator-set membership and the
/// assigned leader windows that neither started nor ended for a protocol
/// reason (superseded, finality behind). Absent without the section.
pub fn duty_facts(record: &NativeRecord) -> Option<Vec<Fact>> {
    let NativeRecord::V3(v) = record else { return None };
    let state = v.payload.node_state.as_ref()?.as_ref()?;
    let w = &state.duties.leader_windows;
    let missed = w
        .assigned
        .0
        .saturating_sub(w.started.0)
        .saturating_sub(w.superseded.0)
        .saturating_sub(w.suppressed_behind.0);
    Some(vec![
        Fact { id: FactId::DutyMember, value: U64(u64::from(state.duties.member)) },
        Fact { id: FactId::DutyWindowsMissed, value: U64(missed) },
    ])
}

/// Queue facts from the manager's real waiter queues: total unfinished waits
/// and the oldest wait across queues. Absent without the section.
pub fn queue_facts(record: &NativeRecord) -> Option<Vec<Fact>> {
    let NativeRecord::V3(v) = record else { return None };
    let state = v.payload.node_state.as_ref()?.as_ref()?;
    let depth = state.queues.iter().fold(0u64, |acc, q| acc.saturating_add(q.depth));
    let oldest = state.queues.iter().map(|q| q.oldest_age_ms.0).max().unwrap_or(0);
    Some(vec![
        Fact { id: FactId::QueueDepth, value: U64(depth) },
        Fact { id: FactId::QueueOldestMs, value: U64(oldest) },
    ])
}

/// Storage facts: disk used under the database root in permille, and how far
/// garbage collection trails the applied masterchain block. GC lag needs the
/// applied anchor; without it only the disk fact is produced.
pub fn storage_facts(record: &NativeRecord) -> Option<Vec<Fact>> {
    let NativeRecord::V3(v) = record else { return None };
    let state = v.payload.node_state.as_ref()?.as_ref()?;
    let total = state.storage.db_total_bytes.0;
    let used = total.saturating_sub(state.storage.db_free_bytes.0);
    let permille = u128::from(used)
        .checked_mul(1000)
        .and_then(|u| u.checked_div(u128::from(total)))
        .and_then(|u| u64::try_from(u).ok())?;
    let mut facts = vec![Fact { id: FactId::DiskUsedPermille, value: U64(permille) }];
    if let Some(chain) = v.payload.chain.as_ref() {
        let lag = u64::from(chain.applied.seqno.saturating_sub(state.storage.gc_seqno));
        facts.push(Fact { id: FactId::StateGcLagBlocks, value: U64(lag) });
    }
    Some(facts)
}

/// Diagnostic coverage counter: every record the native publisher or its
/// relay dropped or failed to parse. Monotonic within a process epoch.
pub fn diagnostic_drops(record: &NativeRecord) -> u64 {
    let q = match record {
        NativeRecord::V1(v) => &v.quality,
        NativeRecord::V2(v) => &v.quality,
        NativeRecord::V3(v) => &v.quality,
    };
    q.producer_dropped.0.saturating_add(q.relay_dropped.0).saturating_add(q.parse_errors.0)
}

/// Anonymous memory growth of the node process over the trailing window:
/// current anon bytes minus the smallest anon sample still inside the window.
/// The state is bounded and reset with the process epoch by `derive`.
pub fn process_memory_growth(
    state: &mut NativeFactState,
    observed_ms: u64,
    anon_bytes: u64,
) -> u64 {
    state.anon_samples.retain(|(at, _)| observed_ms.saturating_sub(*at) <= MEMORY_GROWTH_WINDOW_MS);
    state.anon_samples.push((observed_ms, anon_bytes));
    if state.anon_samples.len() > MEMORY_SAMPLES_MAX {
        state.anon_samples.remove(0);
    }
    let floor = state.anon_samples.iter().map(|(_, b)| *b).min().unwrap_or(anon_bytes);
    anon_bytes.saturating_sub(floor)
}
