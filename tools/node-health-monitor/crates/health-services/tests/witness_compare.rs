//! External witness comparison: fork, lag, ahead, staleness and missing witnesses.
use std::collections::BTreeMap;
use tos_health_services::witness_compare::{compare, AnchorSample, FRESH_MS};

fn s(observed_ms: u64, seqno: u32, root: &str) -> AnchorSample {
    AnchorSample { observed_ms, seqno, root_hash: root.into(), process_epoch: "e".into() }
}
fn observers(samples: Vec<(&str, Vec<AnchorSample>)>) -> BTreeMap<String, Vec<AnchorSample>> {
    samples.into_iter().map(|(n, v)| (n.to_owned(), v)).collect()
}

#[test]
fn agreeing_heads_within_lag_are_not_a_disagreement() {
    let now = 1_000_000;
    let node = vec![s(now - 5_000, 1000, "a"), s(now - 20_000, 990, "b")];
    let obs = observers(vec![("o5", vec![s(now - 3_000, 1010, "c"), s(now - 18_000, 990, "b")])]);
    let d = compare(&node, &obs, now, 150).unwrap();
    assert_eq!(d.value, 0);
    assert_eq!(d.witnesses, 1);
}

#[test]
fn different_root_at_the_same_seqno_is_a_fork() {
    let now = 1_000_000;
    let node = vec![s(now - 5_000, 1000, "a"), s(now - 20_000, 990, "mine")];
    let obs =
        observers(vec![("o5", vec![s(now - 3_000, 1010, "c"), s(now - 18_000, 990, "theirs")])]);
    let d = compare(&node, &obs, now, 150).unwrap();
    assert_eq!(d.value, 1);
    assert_eq!(d.reason.as_deref(), Some("fork_at_990_vs_o5"));
}

#[test]
fn lagging_far_behind_every_fresh_observer_is_a_disagreement_but_being_ahead_is_not() {
    let now = 1_000_000;
    let behind = vec![s(now - 5_000, 500, "a")];
    let obs = observers(vec![
        ("o5", vec![s(now - 3_000, 1010, "c")]),
        ("o6", vec![s(now - 3_000, 1005, "d")]),
    ]);
    let d = compare(&behind, &obs, now, 150).unwrap();
    assert_eq!(d.value, 1);
    assert_eq!(d.reason.as_deref(), Some("behind_observers_by_510"));
    assert_eq!(d.witnesses, 2);
    let ahead = vec![s(now - 5_000, 2000, "a")];
    assert_eq!(compare(&ahead, &obs, now, 150).unwrap().value, 0);
}

#[test]
fn stale_anchors_do_not_judge_and_missing_witnesses_yield_no_fact() {
    let now = 10_000_000;
    let stale_node = vec![s(now - FRESH_MS - 1, 1000, "a")];
    let obs = observers(vec![("o5", vec![s(now - 3_000, 1010, "c")])]);
    assert!(compare(&stale_node, &obs, now, 150).is_none());
    let node = vec![s(now - 5_000, 1000, "a")];
    let stale_obs = observers(vec![("o5", vec![s(now - FRESH_MS - 1, 1010, "c")])]);
    assert!(compare(&node, &stale_obs, now, 150).is_none());
    assert!(compare(&node, &BTreeMap::new(), now, 150).is_none());
    // An old fork sample beyond freshness still counts as a fork: history does not heal.
    let forked = vec![s(now - 5_000, 1000, "a"), s(now - 300_000, 900, "mine")];
    let obs2 =
        observers(vec![("o5", vec![s(now - 3_000, 1010, "c"), s(now - 290_000, 900, "theirs")])]);
    assert_eq!(compare(&forked, &obs2, now, 150).unwrap().value, 1);
}
