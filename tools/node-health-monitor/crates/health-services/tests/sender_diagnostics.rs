use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tos_health_core::{
    rules::{Fact, FactFrame, FactId},
    wire::U64,
};
use tos_health_services::sender_diagnostics::{deliver_frame, DeliveryFailure, SenderDiagnostics};

#[test]
fn successful_delivery_is_silent_and_flapping_keeps_the_emission_budget() {
    let mut diagnostics = SenderDiagnostics::new();
    let start = Instant::now();
    assert!(diagnostics.observe("node1", "source1", Ok(()), start).is_none());
    let first =
        diagnostics.observe("node1", "source1", Err(DeliveryFailure::Http(429)), start).unwrap();
    assert!(first.contains("last_category=rate_limit last_http_status=429"));
    for second in 1..60 {
        let now = start + Duration::from_secs(second);
        assert!(diagnostics.observe("node1", "source1", Ok(()), now).is_none());
        assert!(diagnostics
            .observe("node1", "source1", Err(DeliveryFailure::Connect), now)
            .is_none());
    }
    let summary = diagnostics
        .observe(
            "node1",
            "source1",
            Err(DeliveryFailure::Http(503)),
            start + Duration::from_secs(60),
        )
        .unwrap();
    assert!(summary.contains("failures=60 last_category=http_server_error last_http_status=503"));
    assert!(summary.contains("recovery=pending"));
    assert!(diagnostics
        .observe("node1", "source1", Ok(()), start + Duration::from_secs(61))
        .is_none());
    let recovery =
        diagnostics.observe("node1", "source1", Ok(()), start + Duration::from_secs(120)).unwrap();
    assert!(recovery.contains("unresolved_lanes=0 recovery=complete"));
    assert!(diagnostics
        .observe("node1", "source1", Ok(()), start + Duration::from_secs(180))
        .is_none());
}

#[test]
fn successful_lanes_do_not_claim_a_failing_lane_recovered() {
    for (failed_node, failed_source, good_node, good_source) in [
        ("node1", "native_storage", "node1", "native_core"),
        ("node1", "witness", "node2", "witness"),
    ] {
        let start = Instant::now();
        let mut diagnostics = SenderDiagnostics::new();
        assert!(diagnostics
            .observe(failed_node, failed_source, Err(DeliveryFailure::Timeout), start)
            .unwrap()
            .contains("recovery=pending"));
        for second in 1..60 {
            let now = start + Duration::from_secs(second);
            assert!(diagnostics.observe(good_node, good_source, Ok(()), now).is_none());
            assert!(diagnostics
                .observe(failed_node, failed_source, Err(DeliveryFailure::Timeout), now)
                .is_none());
        }
        let report = diagnostics
            .observe(good_node, good_source, Ok(()), start + Duration::from_secs(60))
            .unwrap();
        assert!(report.contains("unresolved_lanes=1 recovery=pending"));
        assert!(report.contains("failures=59"));
        assert!(diagnostics
            .observe(failed_node, failed_source, Ok(()), start + Duration::from_secs(61))
            .is_none());
        assert!(diagnostics
            .observe(good_node, good_source, Ok(()), start + Duration::from_secs(120))
            .unwrap()
            .contains("recovery=complete"));
    }
}

#[test]
fn unresolved_lane_storage_and_counter_are_bounded() {
    let start = Instant::now();
    let mut diagnostics = SenderDiagnostics::new();
    for n in 0..257 {
        diagnostics.observe(&format!("node{n}"), "source", Err(DeliveryFailure::Transport), start);
    }
    for n in 0..257 {
        diagnostics.observe(&format!("node{n}"), "source", Ok(()), start);
    }
    let report =
        diagnostics.observe("good", "source", Ok(()), start + Duration::from_secs(60)).unwrap();
    assert!(report.contains("unresolved_lanes=0 recovery=unknown"));
    assert!(report.len() < 256);
}

fn frame() -> FactFrame {
    FactFrame {
        schema_version: 1,
        network_id: "a".repeat(64),
        node_id: "node1".into(),
        scope_id: "node".into(),
        source_id: "edge_probe".into(),
        process_epoch: "epoch1".into(),
        source_epoch: "epoch1".into(),
        generation: U64(1),
        source_age_ms: U64(0),
        request_duration_ms: U64(0),
        observed_at: "2026-10-10T00:00:00Z".into(),
        clock_valid: true,
        complete: true,
        facts: vec![Fact { id: FactId::Reachable, value: U64(1) }],
    }
}

#[tokio::test]
async fn http_delivery_reports_status_transport_body_and_bounded_retry() {
    use axum::{http::StatusCode, routing::post, Router};
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let app = Router::new()
        .route("/ok", post(|| async { StatusCode::OK }))
        .route(
            "/429",
            post(|| async { (StatusCode::TOO_MANY_REQUESTS, "do not log this secret body") }),
        )
        .route("/503", post(|| async { StatusCode::SERVICE_UNAVAILABLE }))
        .route("/large", post(|| async { "x".repeat(4097) }))
        .route(
            "/slow",
            post(|| async {
                tokio::time::sleep(Duration::from_millis(500)).await;
                StatusCode::OK
            }),
        )
        .route(
            "/retry",
            post(move || {
                let h = h.clone();
                async move {
                    if h.fetch_add(1, Ordering::SeqCst) == 0 {
                        StatusCode::TOO_MANY_REQUESTS
                    } else {
                        StatusCode::OK
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client =
        reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(2)).build().unwrap();
    for (path, expected) in [
        ("ok", Ok(())),
        ("429", Err(DeliveryFailure::Http(429))),
        ("503", Err(DeliveryFailure::Http(503))),
        ("large", Err(DeliveryFailure::Body)),
    ] {
        let outcome = deliver_frame(
            &client,
            &format!("http://{address}/{path}"),
            "private-token",
            &frame(),
            false,
        )
        .await;
        assert_eq!(outcome, expected, "{path}");
    }
    assert_eq!(
        deliver_frame(&client, &format!("http://{address}/retry"), "token", &frame(), true).await,
        Ok(())
    );
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    let impatient =
        reqwest::Client::builder().no_proxy().timeout(Duration::from_millis(50)).build().unwrap();
    assert_eq!(
        deliver_frame(&impatient, &format!("http://{address}/slow"), "token", &frame(), false)
            .await,
        Err(DeliveryFailure::Timeout)
    );
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    let client =
        reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(2)).build().unwrap();
    assert_eq!(
        deliver_frame(&client, &format!("http://{address}/ok"), "token", &frame(), false).await,
        Err(DeliveryFailure::Connect)
    );
}
