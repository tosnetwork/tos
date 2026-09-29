use serde_json::json;
use tos_health_services::watchdog::{send_notice, NoticeTracker, WatchdogState};
fn webhook(epoch: &str, sequence: &str, status: &str, monitor: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"version":"4","alerts":[{"status":status,"labels":{"alertname":"Watchdog","monitor_id":monitor},"annotations":{"monitor_epoch":epoch,"evaluation_sequence":sequence},"fingerprint":"fingerprint","startsAt":"2026-09-29T00:00:00Z"}]})).unwrap()
}
#[test]
fn pipeline_requires_own_firing_new_evaluation() {
    let s = WatchdogState::new("monitor1".into(), vec![b'a'; 32]).unwrap();
    assert!(s.accept_pipeline(&webhook("p1", "1", "firing", "monitor1")).is_err());
    assert!(s.receive_process("p1", 1).unwrap());
    assert_eq!(
        s.accept_pipeline(&webhook("p1", "9007199254740993", "firing", "monitor1")).unwrap(),
        1
    );
    assert_eq!(
        s.accept_pipeline(&webhook("p1", "9007199254740993", "firing", "monitor1")).unwrap(),
        0
    );
    assert!(s.accept_pipeline(&webhook("p2", "1", "firing", "monitor1")).is_err());
    assert!(s.receive_process("p2", 1).unwrap());
    assert_eq!(s.accept_pipeline(&webhook("p2", "1", "firing", "monitor1")).unwrap(), 1);
    assert!(s.accept_pipeline(&webhook("p1", "9007199254740994", "firing", "monitor1")).is_err());
    assert_eq!(s.accept_pipeline(&webhook("p2", "2", "resolved", "monitor1")).unwrap(), 0);
    assert_eq!(s.accept_pipeline(&webhook("p2", "2", "firing", "other")).unwrap(), 0);
    assert!(s.accept_pipeline(&webhook("p2", "02", "firing", "monitor1")).is_err());
}

#[tokio::test]
async fn own_observer_heartbeat_and_notice_delivery_are_distinct_from_monitor_fault() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let state = WatchdogState::new_with_epoch(
        "monitor1".into(),
        "observer1".into(),
        "observer-epoch-1".into(),
        vec![b'a'; 32],
    )
    .unwrap();
    let read = |path: &str, auth: bool| {
        let state = state.clone();
        let path = path.to_owned();
        async move {
            let mut builder = Request::builder().uri(path);
            if auth {
                builder = builder.header("authorization", format!("Bearer {}", "a".repeat(32)));
            }
            let response = tos_health_services::watchdog::router(state)
                .oneshot(builder.body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = response.status();
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let value = if body.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::from_slice(&body).unwrap()
            };
            (status, value)
        }
    };
    assert_eq!(read("/v1/watchdog/heartbeat", false).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(read("/v1/watchdog/heartbeat?force=true", true).await.0, StatusCode::BAD_REQUEST);
    let monitor_status = state.unavailable().unwrap();
    let (_, initial) = read("/v1/watchdog/heartbeat", true).await;
    assert_eq!(initial["observer_epoch"], "observer-epoch-1");
    assert_eq!(initial["sequence"], "0");
    assert_eq!(initial["notification_transport"], "unknown");
    assert_eq!(state.completed_tick().unwrap(), 1);
    state.notice_result(false).unwrap();
    let (_, failed) = read("/v1/watchdog/heartbeat", true).await;
    assert_eq!(failed["sequence"], "1");
    assert_eq!(failed["notification_transport"], "delivery_failed");
    assert_eq!(
        read("/v1/watchdog/heartbeat", true).await.1["sequence"],
        "1",
        "repeated heartbeat reads cannot manufacture a new O tick"
    );
    state.notice_result(true).unwrap();
    assert_eq!(state.completed_tick().unwrap(), 2);
    let (_, recovered) = read("/v1/watchdog/heartbeat", true).await;
    assert_eq!(recovered["sequence"], "2");
    assert_eq!(recovered["notification_transport"], "accepted_by_receiver");
    assert_eq!(
        state.unavailable().unwrap(),
        monitor_status,
        "O notice acceptance does not mark the monitored M process/pipeline healthy"
    );
}

#[tokio::test]
async fn direct_observer_notice_has_stable_timestamp_key_and_bounded_retry() {
    use axum::{
        http::{HeaderMap, StatusCode},
        routing::post,
        Json, Router,
    };
    use sha2::{Digest, Sha256};
    use std::sync::{Arc, Mutex};
    let seen = Arc::new(Mutex::new(Vec::new()));
    let received = seen.clone();
    let app = Router::new().route(
        "/notice",
        post(move |headers: HeaderMap, Json(payload): Json<serde_json::Value>| {
            let received = received.clone();
            async move {
                assert_eq!(headers.get("authorization").unwrap(), "Bearer observer-secret");
                let key = headers.get("idempotency-key").unwrap().to_str().unwrap();
                let body = serde_json::to_vec(&payload).unwrap();
                let hash = format!("{:x}", Sha256::digest(&body));
                assert_eq!(headers.get("x-content-sha256").unwrap(), hash.as_str());
                assert_eq!(payload["idempotency_key"], key);
                received.lock().unwrap().push((key.to_owned(), payload["observed_at"].clone()));
                StatusCode::ACCEPTED
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(1))
        .build()
        .unwrap();
    let mut notices = NoticeTracker::new("observer1".into(), "observer-process-1".into()).unwrap();
    assert!(notices.due(0, false, false).unwrap().is_none());
    let url = format!("http://{address}/notice");
    for now in [45_000, 60_000, 75_000, 135_000] {
        let (key, body) = notices.due(now, true, false).unwrap().unwrap();
        send_notice(&client, &url, "observer-secret", &key, &body).await.unwrap();
        assert!(notices.due(now + 1, true, false).unwrap().is_none());
    }
    let receipts = seen.lock().unwrap().clone();
    assert_eq!(receipts.len(), 4);
    assert!(receipts.iter().all(|entry| entry == &receipts[0]));
    assert!(notices.due(136_000, false, false).unwrap().is_none());
    let (new_key, body) = notices.due(137_000, true, false).unwrap().unwrap();
    assert_ne!(new_key, receipts[0].0);
    assert!(body["observed_at"].as_str().is_some());
    server.abort();
}
