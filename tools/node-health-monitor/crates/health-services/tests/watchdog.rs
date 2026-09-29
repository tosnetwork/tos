use serde_json::json;
use tos_health_services::watchdog::WatchdogState;
fn webhook(epoch: &str, sequence: &str, status: &str, monitor: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"version":"4","alerts":[{"status":status,"labels":{"alertname":"Watchdog","monitor_id":monitor},"annotations":{"monitor_epoch":epoch,"evaluation_sequence":sequence},"fingerprint":"fingerprint","startsAt":"2026-09-29T00:00:00Z"}]})).unwrap()
}
#[test]
fn pipeline_requires_own_firing_new_evaluation() {
    let s = WatchdogState::new("monitor1".into(), vec![b'a'; 32]).unwrap();
    assert_eq!(
        s.accept_pipeline(&webhook("p1", "9007199254740993", "firing", "monitor1")).unwrap(),
        1
    );
    assert_eq!(
        s.accept_pipeline(&webhook("p1", "9007199254740993", "firing", "monitor1")).unwrap(),
        0
    );
    assert_eq!(s.accept_pipeline(&webhook("p2", "1", "firing", "monitor1")).unwrap(), 1);
    assert!(s.accept_pipeline(&webhook("p1", "9007199254740994", "firing", "monitor1")).is_err());
    assert_eq!(s.accept_pipeline(&webhook("p2", "2", "resolved", "monitor1")).unwrap(), 0);
    assert_eq!(s.accept_pipeline(&webhook("p2", "2", "firing", "other")).unwrap(), 0);
    assert!(s.accept_pipeline(&webhook("p2", "02", "firing", "monitor1")).is_err());
}
