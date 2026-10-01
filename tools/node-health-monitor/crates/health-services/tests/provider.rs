//! The chat-completions provider adapter against an owned local mock only.
//! No external host is contacted; every non-diagnosis path is rules-only.
use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeSet, VecDeque},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
use tos_health_services::provider::{diagnose, private_only_url, Outcome, ProviderConfig};

#[derive(Clone)]
enum Reply {
    Json(Value),
    Sse(&'static str),
    Status(u16),
    Redirect(String),
    Text(&'static str),
}

#[derive(Clone)]
struct Mock {
    replies: Arc<Mutex<VecDeque<Reply>>>,
    requests: Arc<AtomicUsize>,
    bodies: Arc<Mutex<Vec<Value>>>,
}

async fn handler(State(mock): State<Mock>, body: String) -> Response {
    mock.requests.fetch_add(1, Ordering::SeqCst);
    if let Ok(value) = serde_json::from_str::<Value>(&body) {
        mock.bodies.lock().unwrap().push(value);
    }
    let reply = mock.replies.lock().unwrap().pop_front().unwrap_or(Reply::Status(500));
    match reply {
        Reply::Json(value) => (StatusCode::OK, axum::Json(value)).into_response(),
        Reply::Sse(text) => {
            let mut response = (StatusCode::OK, Body::from(text)).into_response();
            response
                .headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
            response
        }
        Reply::Status(code) => StatusCode::from_u16(code).unwrap().into_response(),
        Reply::Redirect(location) => {
            let mut response = StatusCode::FOUND.into_response();
            response.headers_mut().insert(header::LOCATION, location.parse().unwrap());
            response
        }
        Reply::Text(text) => (StatusCode::OK, text).into_response(),
    }
}

async fn serve(replies: Vec<Reply>) -> (String, Mock) {
    let mock = Mock {
        replies: Arc::new(Mutex::new(replies.into())),
        requests: Arc::new(AtomicUsize::new(0)),
        bodies: Arc::new(Mutex::new(Vec::new())),
    };
    let app = Router::new().route("/v1/chat/completions", post(handler)).with_state(mock.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://127.0.0.1:{port}/"), mock)
}

fn config(base_url: &str) -> ProviderConfig {
    ProviderConfig {
        enabled: true,
        profile: "chat_completions".into(),
        base_url: base_url.into(),
        model: "local-mock".into(),
        egress: "private_only".into(),
        api_key_env: None,
        timeout_seconds: 5,
        max_output_tokens: 1536,
    }
}

fn delivered() -> BTreeSet<String> {
    BTreeSet::from(["a".repeat(64)])
}

fn valid_diagnosis() -> String {
    json!({"status":"analysis","summary":"Finalized slot is flat.",
        "findings":[{"claim":"finalized slot flat","basis":"observed","evidence_ids":["a".repeat(64)]}],
        "missing_evidence":[],"recommended_runbooks":["inspect_consensus_queues"]})
    .to_string()
}

fn completion(content: &str, finish: &str) -> Value {
    json!({"id":"m","object":"chat.completion","choices":[{"index":0,"finish_reason":finish,
        "message":{"role":"assistant","content":content,"refusal":null}}]})
}

const PACKAGE: &[u8] = br#"{"schema_version":2,"status":"partial"}"#;
const PROMPT: &str = "Use only authorized cached evidence.";

#[tokio::test]
async fn disabled_and_non_private_endpoints_never_send_a_request() {
    let (unrelated_url, unrelated) = serve(vec![]).await;
    let mut disabled = config(&unrelated_url);
    disabled.enabled = false;
    let report = diagnose(&disabled, PROMPT, PACKAGE, &delivered()).await;
    assert_eq!(report.outcome, Outcome::Disabled);
    assert_eq!(report.requests, 0);
    for public in [
        "http://93.184.216.34/",
        "http://example.invalid/",
        "https://api.example.invalid/v1",
        "http://8.8.8.8:8080/",
        "http://[2001:db8::1]/",
        "ftp://127.0.0.1/",
        "http://user@127.0.0.1/",
    ] {
        assert!(private_only_url(public).is_err(), "{public}");
        let report = diagnose(&config(public), PROMPT, PACKAGE, &delivered()).await;
        assert!(
            matches!(report.outcome, Outcome::EgressRefused(_)),
            "{public}: {:?}",
            report.outcome
        );
        assert_eq!(report.requests, 0, "{public}");
    }
    for private in
        ["http://127.0.0.1:9/", "http://localhost:9/", "http://10.1.2.3:9/", "http://[::1]:9/"]
    {
        assert!(private_only_url(private).is_ok(), "{private}");
    }
    let mut wrong_profile = config(&unrelated_url);
    wrong_profile.profile = "responses".into();
    let report = diagnose(&wrong_profile, PROMPT, PACKAGE, &delivered()).await;
    assert!(matches!(report.outcome, Outcome::EgressRefused(_)));
    let mut external = config(&unrelated_url);
    external.egress = "external_authorized".into();
    let report = diagnose(&external, PROMPT, PACKAGE, &delivered()).await;
    assert!(matches!(report.outcome, Outcome::EgressRefused(_)));
    let mut missing_key = config(&unrelated_url);
    missing_key.api_key_env = Some("NHM_TEST_KEY_THAT_DOES_NOT_EXIST".into());
    let report = diagnose(&missing_key, PROMPT, PACKAGE, &delivered()).await;
    assert_eq!(report.outcome, Outcome::TransportFailed("api key unavailable".into()));
    assert_eq!(
        unrelated.requests.load(Ordering::SeqCst),
        0,
        "no configured-host request was ever sent"
    );
}

#[tokio::test]
async fn redirect_is_refused_and_the_target_is_never_contacted() {
    let (target_url, target) =
        serve(vec![Reply::Json(completion(&valid_diagnosis(), "stop"))]).await;
    let (origin_url, origin) =
        serve(vec![Reply::Redirect(format!("{target_url}v1/chat/completions"))]).await;
    let report = diagnose(&config(&origin_url), PROMPT, PACKAGE, &delivered()).await;
    assert_eq!(report.outcome, Outcome::HttpStatus(302));
    assert_eq!(report.requests, 1);
    assert_eq!(origin.requests.load(Ordering::SeqCst), 1);
    assert_eq!(target.requests.load(Ordering::SeqCst), 0, "redirect target was contacted");
}

#[tokio::test]
async fn every_provider_failure_is_rules_only_without_retry() {
    let cases: Vec<(&str, Reply, Outcome, usize)> = vec![
        ("http 500", Reply::Status(500), Outcome::HttpStatus(500), 1),
        ("http 401", Reply::Status(401), Outcome::HttpStatus(401), 1),
        (
            "sse error event",
            Reply::Sse("data: {\"error\":{\"message\":\"overloaded\"}}\n\ndata: [DONE]\n\n"),
            Outcome::TransportFailed("stream error event".into()),
            1,
        ),
        ("json refusal", Reply::Json(json!({"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":null,"refusal":"I cannot help with that."}}]})), Outcome::Refusal, 1),
        ("content filter", Reply::Json(completion(&valid_diagnosis(), "content_filter")), Outcome::Refusal, 1),
        ("truncated by length", Reply::Json(completion("{\"status\":\"analysis\"", "length")), Outcome::Incomplete, 1),
        ("empty content", Reply::Json(completion("", "stop")), Outcome::Incomplete, 1),
        (
            "done without content",
            Reply::Sse("data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\ndata: [DONE]\n\n"),
            Outcome::Incomplete,
            1,
        ),
        (
            "stream without done",
            Reply::Sse("data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"{\\\"status\\\"\"},\"finish_reason\":null}]}\n\n"),
            Outcome::Incomplete,
            1,
        ),
        ("200 non-json body", Reply::Text("<html>ok</html>"), Outcome::InvalidJson("provider body is not JSON".into()), 1),
    ];
    for (label, reply, expected, requests) in cases {
        let (url, mock) = serve(vec![reply]).await;
        let report = diagnose(&config(&url), PROMPT, PACKAGE, &delivered()).await;
        assert_eq!(report.outcome, expected, "{label}");
        assert!(report.outcome.rules_only(), "{label}");
        assert_eq!(report.requests as usize, requests, "{label}");
        assert_eq!(mock.requests.load(Ordering::SeqCst), requests, "{label}");
    }
}

#[tokio::test]
async fn invalid_diagnosis_is_repaired_exactly_once() {
    let (url, mock) = serve(vec![
        Reply::Json(completion("The node looks fine to me.", "stop")),
        Reply::Json(completion("{\"status\":\"analysis\"} trailing text", "stop")),
        Reply::Json(completion(&valid_diagnosis(), "stop")),
    ])
    .await;
    let report = diagnose(&config(&url), PROMPT, PACKAGE, &delivered()).await;
    assert_eq!(report.outcome, Outcome::InvalidJson("invalid diagnosis JSON".into()));
    assert_eq!(report.requests, 2, "exactly one repair request");
    assert_eq!(mock.requests.load(Ordering::SeqCst), 2);
    {
        let bodies = mock.bodies.lock().unwrap();
        assert_eq!(bodies[0]["messages"].as_array().unwrap().len(), 2);
        assert_eq!(bodies[0]["stream"], false);
        assert_eq!(bodies[0]["max_tokens"], 1536);
        let repair = &bodies[1]["messages"];
        assert_eq!(repair.as_array().unwrap().len(), 4);
        assert!(repair[3]["content"].as_str().unwrap().contains("invalid diagnosis JSON"));
    }

    let (url, mock) = serve(vec![
        Reply::Json(completion("not json", "stop")),
        Reply::Json(completion(&valid_diagnosis(), "stop")),
    ])
    .await;
    let report = diagnose(&config(&url), PROMPT, PACKAGE, &delivered()).await;
    assert!(matches!(report.outcome, Outcome::Diagnosis(_)), "{:?}", report.outcome);
    assert_eq!(report.requests, 2);
    assert_eq!(mock.requests.load(Ordering::SeqCst), 2);

    let undelivered = json!({"status":"analysis","summary":"Cites a foreign id.",
        "findings":[{"claim":"x","basis":"observed","evidence_ids":["f".repeat(64)]}],
        "missing_evidence":[],"recommended_runbooks":[]})
    .to_string();
    let (url, _) = serve(vec![
        Reply::Json(completion(&undelivered, "stop")),
        Reply::Json(completion(&undelivered, "stop")),
    ])
    .await;
    let report = diagnose(&config(&url), PROMPT, PACKAGE, &delivered()).await;
    assert_eq!(report.outcome, Outcome::InvalidJson("evidence not delivered in run".into()));
    assert_eq!(report.requests, 2);
}

#[tokio::test]
async fn streamed_valid_diagnosis_is_accepted_and_package_is_the_only_user_content() {
    let diagnosis = valid_diagnosis();
    let (head, tail) = diagnosis.split_at(20);
    let stream = format!(
        "data: {}\n\ndata: {}\n\ndata: {}\n\ndata: [DONE]\n\n",
        json!({"choices":[{"index":0,"delta":{"role":"assistant","content":head},"finish_reason":null}]}),
        json!({"choices":[{"index":0,"delta":{"content":tail},"finish_reason":null}]}),
        json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]})
    );
    let leaked: &'static str = Box::leak(stream.into_boxed_str());
    let (url, mock) = serve(vec![Reply::Sse(leaked)]).await;
    let report = diagnose(&config(&url), PROMPT, PACKAGE, &delivered()).await;
    let Outcome::Diagnosis(parsed) = report.outcome else {
        panic!("streamed diagnosis refused");
    };
    assert_eq!(parsed.findings[0].evidence_ids[0], "a".repeat(64));
    assert_eq!(report.requests, 1);
    let bodies = mock.bodies.lock().unwrap();
    assert_eq!(bodies[0]["messages"][1]["content"], std::str::from_utf8(PACKAGE).unwrap());
    assert_eq!(bodies[0]["messages"][0]["content"], PROMPT);
    assert!(bodies[0].get("tools").is_none());
}
