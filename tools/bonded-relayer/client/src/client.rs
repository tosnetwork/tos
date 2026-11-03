// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! The quote, submit and status calls, each one attempt through the Tor
//! proxy to the endpoint the authenticated Bond declared. No retry, no
//! second transport, no re-signing: an ambiguous submit is reported as
//! unknown with the identity needed to ask about it later.
use crate::{
    bond,
    http::{self, HttpError, RESPONSE_LIMIT},
    onion::OnionEndpoint,
    quote::{self, Terms, MAX_QUOTE_BYTES, RESPONSE_SCHEMA},
    release::Release,
    request::{Request, MAX_WIRE_BYTES},
    socks::TorProxy,
    wire,
};
use node_contracts::relayer_bond::BondInit;
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::Instant;

pub const STATUS_SCHEMA: &str = "tos.br1.status.v1";
pub const LIVE: [&str; 4] = ["reserved", "prepared", "unknown", "broadcast"];
pub const TERMINAL: [&str; 3] = ["executed", "rejected", "cancelled"];
pub const MAX_ACCEPTANCE_BYTES: usize = 16 * 1024;
pub const MIN_TIMEOUT_SECS: u64 = 1;
pub const MAX_TIMEOUT_SECS: u64 = 60;

#[derive(Debug)]
pub enum ClientError {
    /// A local check failed before anything was sent.
    Rejected(String),
    /// The relayer answered with a well-formed status other than 200/202.
    Refused { status: u16 },
    /// No well-formed answer: the transport, the daemon or the framing failed.
    Unavailable(String),
    /// A submit whose outcome is not known. Nothing was retried; ask the
    /// relayer about `request_id` and read the chain.
    SubmissionUnknown { request_id: String, cause: String },
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Rejected(what) => write!(f, "{what}"),
            ClientError::Refused { status } => {
                write!(f, "relayer refused the request (HTTP {status})")
            }
            ClientError::Unavailable(what) => write!(f, "relayer response unavailable: {what}"),
            ClientError::SubmissionUnknown { request_id, cause } => {
                write!(f, "submission result unavailable; reconcile request {request_id} ({cause})")
            }
        }
    }
}
impl std::error::Error for ClientError {}

fn rejected(error: impl std::fmt::Display) -> ClientError {
    ClientError::Rejected(error.to_string())
}

/// An authenticated quote: the terms the pinned worker signed, their
/// identity and the capability token they are bound to.
#[derive(Clone, Debug)]
pub struct Quote {
    pub identity: String,
    pub terms: Terms,
    /// The terms exactly as signed.
    pub terms_value: Value,
    /// The canonical envelope, for the journal and for re-verification.
    pub envelope: Vec<u8>,
    pub status_token: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finality {
    pub checkpoint_root: String,
    pub proof_digest: String,
}

/// The relayer's claim about one request. It is a claim: only the wallet's
/// own verified chain reads settle a spend.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub schema: String,
    pub request_id: String,
    pub release: String,
    pub status: String,
    pub message_hash: Option<String>,
    pub acceptance_b64: Option<String>,
    pub finality: Option<Finality>,
    pub requires_independent_verification: bool,
}

impl Status {
    pub fn is_terminal(&self) -> bool {
        TERMINAL.contains(&self.status.as_str())
    }
}

/// A fresh 32-byte status capability, lowercase hex.
pub fn random_token() -> String {
    loop {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        if bytes.iter().any(|b| *b != 0) {
            return hex::encode(bytes);
        }
    }
}

/// The local clock, in Unix seconds. Quote and submission windows are
/// judged by a reading taken after the exchange, never before it: a quote
/// issued while the request was in flight is honest, and a window that
/// closed while the answer was in flight is closed.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

fn system_clock() -> Clock {
    Arc::new(|| {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|elapsed| elapsed.as_secs()).unwrap_or(0)
    })
}

pub struct Client {
    endpoint: OnionEndpoint,
    scope: String,
    worker_key: Vec<u8>,
    proxy: TorProxy,
    timeout: Duration,
    clock: Clock,
}

impl Client {
    /// From the release pins and the Bond's public StateInit: the endpoint
    /// and the quote worker come from the authenticated Bond and nowhere
    /// else. This proves identity, not current eligibility.
    pub fn from_bond(
        release: &Release,
        bond_init_b64: &str,
        proxy: TorProxy,
        timeout_secs: u64,
    ) -> Result<Self, ClientError> {
        let init = bond::identity(release, bond_init_b64).map_err(rejected)?;
        Self::from_identity(release, &init, proxy, timeout_secs)
    }

    /// From a `BondInit` the caller authenticated against `release` already.
    pub fn from_identity(
        release: &Release,
        init: &BondInit,
        proxy: TorProxy,
        timeout_secs: u64,
    ) -> Result<Self, ClientError> {
        let scope = release.scope().map_err(rejected)?;
        if wire::hash(&init.worker_key) != release.worker_key_hash {
            return Err(rejected("Bond identity does not match wallet release"));
        }
        let endpoint = OnionEndpoint::parse(&init.endpoint).map_err(rejected)?;
        if !(MIN_TIMEOUT_SECS..=MAX_TIMEOUT_SECS).contains(&timeout_secs) {
            return Err(rejected("relay timeout out of range"));
        }
        Ok(Self {
            endpoint,
            scope,
            worker_key: init.worker_key.clone(),
            proxy,
            timeout: Duration::from_secs(timeout_secs),
            clock: system_clock(),
        })
    }

    /// Replaces the system clock, for tests that fix or step time.
    pub fn set_clock(&mut self, clock: Clock) {
        self.clock = clock;
    }

    pub fn endpoint(&self) -> &OnionEndpoint {
        &self.endpoint
    }

    pub fn scope(&self) -> &str {
        &self.scope
    }

    pub fn proxy(&self) -> &TorProxy {
        &self.proxy
    }

    /// One POST and its JSON answer, under one deadline.
    async fn request(&self, path: &str, payload: &Value) -> Result<Value, ClientError> {
        let body = wire::canonical(payload).map_err(rejected)?;
        if body.len() > MAX_WIRE_BYTES {
            return Err(rejected("request exceeds body bound"));
        }
        let deadline = Instant::now() + self.timeout;
        let mut stream = self
            .proxy
            .connect(&self.endpoint, deadline)
            .await
            .map_err(|error| ClientError::Unavailable(error.to_string()))?;
        let response =
            match http::exchange(&mut stream, &self.endpoint.authority(), path, &body, deadline)
                .await
            {
                Ok(response) => response,
                Err(HttpError::Malformed(what)) => {
                    return Err(ClientError::Unavailable(what.to_owned()))
                }
                Err(error) => return Err(ClientError::Unavailable(error.to_string())),
            };
        if !matches!(response.status, 200 | 202) {
            return Err(ClientError::Refused { status: response.status });
        }
        // The answer's bytes are untrusted and never echoed into an error.
        wire::parse_object(&response.body, RESPONSE_LIMIT)
            .map_err(|_| ClientError::Unavailable("malformed JSON answer".to_owned()))
    }

    /// Authenticates an envelope value against this client's worker and
    /// scope; returns the signed terms and their identity.
    fn authenticate(&self, envelope: &Value) -> Result<(Value, Terms, String), ClientError> {
        let terms_value =
            quote::verify_envelope(&self.worker_key, envelope, &self.scope).map_err(rejected)?;
        let terms = quote::check_terms(&terms_value, &self.scope).map_err(rejected)?;
        let identity = quote::identity(&terms_value).map_err(rejected)?;
        Ok((terms_value, terms, identity))
    }

    /// `POST /v1/quote`. `token` is this session's fresh status capability.
    /// The quote's window is judged by the clock as read after the answer
    /// arrived and was authenticated.
    pub async fn quote(&self, slot: u8, lifetime: u64, token: &str) -> Result<Quote, ClientError> {
        let access = quote::status_hash(token).map_err(rejected)?;
        if slot > 2 {
            return Err(rejected("quote slot out of range"));
        }
        if !(1..=quote::MAX_LIFETIME).contains(&lifetime) {
            return Err(rejected("quote lifetime out of range"));
        }
        let result = self
            .request(
                "/v1/quote",
                &json!({"slot": slot, "lifetime": lifetime, "status_token": token}),
            )
            .await?;
        wire::fields(&result, &["schema", "quote_id", "quote"])
            .map_err(|_| rejected("unexpected quote response"))?;
        if result["schema"] != RESPONSE_SCHEMA || !result["quote"].is_object() {
            return Err(rejected("unexpected quote response"));
        }
        let envelope = wire::canonical(&result["quote"]).map_err(rejected)?;
        if envelope.len() > MAX_QUOTE_BYTES {
            return Err(rejected("quote envelope too large"));
        }
        let (terms_value, terms, identity) = self.authenticate(&result["quote"])?;
        let now = (self.clock)();
        let quote_id = result["quote_id"].as_str().unwrap_or_default();
        if identity != quote_id
            || terms.status_hash != access
            || terms.slot != slot
            || terms.valid_until.checked_sub(terms.issued_at) != Some(lifetime)
            || !(terms.issued_at <= now && now < terms.valid_until)
        {
            return Err(rejected("quote binding or lifetime mismatch"));
        }
        Ok(Quote { identity, terms, terms_value, envelope, status_token: token.to_owned() })
    }

    /// Re-authenticates a quote from its stored envelope and token.
    fn reverify(&self, stored: &Quote) -> Result<Terms, ClientError> {
        let envelope = wire::parse_object(&stored.envelope, MAX_QUOTE_BYTES).map_err(rejected)?;
        let (terms_value, terms, identity) = self.authenticate(&envelope)?;
        if wire::canonical(&terms_value).map_err(rejected)?
            != wire::canonical(&stored.terms_value).map_err(rejected)?
            || identity != stored.identity
            || terms.status_hash != quote::status_hash(&stored.status_token).map_err(rejected)?
        {
            return Err(rejected("quote object is not authenticated"));
        }
        Ok(terms)
    }

    /// `POST /v1/submit`, once. The request must be the one the quote was
    /// taken for, and still inside the window by the clock as read just
    /// before it leaves. Any failure after the request has been sent is
    /// unknown, not failed.
    pub async fn submit(&self, request: &Request, stored: &Quote) -> Result<Status, ClientError> {
        let terms = self.reverify(stored)?;
        let request_id = request.identity().map_err(rejected)?;
        let now = (self.clock)();
        if request.release != self.scope
            || request.quote_hash != stored.identity
            || request.fee_slot != terms.slot
            || request.fee_note_index != terms.note_index
            || u64::from(request.valid_until) > terms.valid_until
            || request.funding_cap > terms.funding_cap
            || u64::from(request.valid_until) <= now
        {
            return Err(rejected("candidate does not match the selected quote"));
        }
        let payload = json!({
            "request": serde_json::to_value(request).map_err(rejected)?,
            "status_token": stored.status_token,
        });
        // From here on the request may have reached the relayer.
        let outcome = async {
            let response = self.request("/v1/submit", &payload).await?;
            self.view(&response, &request_id)
        }
        .await;
        outcome.map_err(|cause| ClientError::SubmissionUnknown {
            request_id: request_id.clone(),
            cause: cause.to_string(),
        })
    }

    /// `POST /v1/status`: read-only on both sides.
    pub async fn status(&self, request_id: &str, token: &str) -> Result<Status, ClientError> {
        wire::digest_str(request_id).map_err(rejected)?;
        quote::status_hash(token).map_err(rejected)?;
        let response = self
            .request("/v1/status", &json!({"request_id": request_id, "status_token": token}))
            .await?;
        self.view(&response, request_id)
    }

    fn view(&self, value: &Value, request_id: &str) -> Result<Status, ClientError> {
        wire::fields(
            value,
            &[
                "schema",
                "request_id",
                "release",
                "status",
                "message_hash",
                "acceptance_b64",
                "finality",
                "requires_independent_verification",
            ],
        )
        .map_err(|_| rejected("status identity or semantics mismatch"))?;
        let status: Status = serde_json::from_value(value.clone())
            .map_err(|_| rejected("status identity or semantics mismatch"))?;
        if status.schema != STATUS_SCHEMA
            || status.request_id != request_id
            || status.release != self.scope
            || !(LIVE.contains(&status.status.as_str())
                || TERMINAL.contains(&status.status.as_str()))
            || !status.requires_independent_verification
        {
            return Err(rejected("status identity or semantics mismatch"));
        }
        if let Some(hash) = &status.message_hash {
            wire::digest_str(hash).map_err(rejected)?;
        }
        if let Some(text) = &status.acceptance_b64 {
            wire::decode_bounded(text, MAX_ACCEPTANCE_BYTES)
                .map_err(|_| rejected("invalid acceptance encoding"))?;
        }
        match (&status.finality, status.status.as_str()) {
            (Some(finality), "executed" | "rejected") => {
                wire::digest_str(&finality.checkpoint_root).map_err(rejected)?;
                wire::digest_str(&finality.proof_digest).map_err(rejected)?;
            }
            (None, "executed" | "rejected") => {
                return Err(rejected("terminal status lacks proof locator"))
            }
            (Some(_), _) => return Err(rejected("nonterminal status carries finality")),
            (None, _) => {}
        }
        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bond::tests::fixture;
    use crate::http::{receive, response_bytes};
    use crate::quote::tests::descriptor_b64;
    use crate::socks::{
        tests::{listen, Peer},
        Isolation,
    };
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use fips204::ml_dsa_44;
    use std::sync::{Arc, Mutex};
    use tokio::io::AsyncWriteExt;

    const NOW: u64 = 1_700_000_000;

    /// What the fake relayer does; a test flips these.
    #[derive(Default)]
    struct Behaviour {
        drop_submit: bool,
        /// Answer every request with this status instead of serving it.
        canned_status: Option<u16>,
        canned_path: String,
        /// The body of a canned answer, in place of the default one.
        canned_body: Option<Vec<u8>>,
        /// A clock the relayer moves to this reading as it answers, so the
        /// client's reading before the exchange and after it differ.
        advance: Option<(Arc<std::sync::atomic::AtomicU64>, u64)>,
        /// Alter the signed terms before answering (an honest worker signing
        /// terms the client must still refuse).
        tamper: Option<fn(&mut Value)>,
        /// Alter the status view.
        tamper_status: Option<fn(&mut Value)>,
        paths: Vec<String>,
    }

    struct Relayer {
        scope: String,
        public: Vec<u8>,
        private: ml_dsa_44::PrivateKey,
        behaviour: Arc<Mutex<Behaviour>>,
    }

    impl Relayer {
        fn answer(&self, start: &str, body: &[u8]) -> Option<Vec<u8>> {
            let path = start.split(' ').nth(1).unwrap_or_default().to_owned();
            let mut behaviour = self.behaviour.lock().ok()?;
            behaviour.paths.push(path.clone());
            if let Some((clock, reading)) = &behaviour.advance {
                clock.store(*reading, std::sync::atomic::Ordering::SeqCst);
            }
            if let Some(status) = behaviour.canned_status {
                if path.starts_with(&behaviour.canned_path) {
                    let body = behaviour.canned_body.clone();
                    return Some(response_bytes(
                        status,
                        "Refused",
                        body.as_deref().unwrap_or(br#"{"error":"busy"}"#),
                    ));
                }
            }
            let payload = wire::parse_object(body, MAX_WIRE_BYTES).ok()?;
            let view = |request_id: &str, status: &str| {
                let mut v = json!({
                    "schema": STATUS_SCHEMA, "request_id": request_id, "release": self.scope,
                    "status": status, "message_hash": "0a".repeat(32), "acceptance_b64": null,
                    "finality": null, "requires_independent_verification": true,
                });
                if let Some(tamper) = behaviour.tamper_status {
                    tamper(&mut v);
                }
                wire::canonical(&v).ok()
            };
            match path.as_str() {
                "/v1/quote" => {
                    let token = payload["status_token"].as_str()?;
                    let lifetime = payload["lifetime"].as_u64()?;
                    let mut terms = json!({
                        "schema": quote::TERMS_SCHEMA, "release": self.scope, "nonce": "0a".repeat(32),
                        "note_index": 5, "issued_at": NOW, "valid_until": NOW + lifetime,
                        "slot": payload["slot"], "amount": 7, "funding_cap": 250_000_000u64,
                        "descriptor_b64": descriptor_b64(5), "status_hash": quote::status_hash(token).ok()?,
                        "success": quote::SUCCESS,
                    });
                    if let Some(tamper) = behaviour.tamper {
                        tamper(&mut terms);
                    }
                    let envelope =
                        quote::sign_envelope(&self.private, &self.public, &terms).ok()?;
                    let response = json!({"schema": RESPONSE_SCHEMA, "quote_id": quote::identity(&terms).ok()?, "quote": envelope});
                    Some(response_bytes(200, "OK", &wire::canonical(&response).ok()?))
                }
                "/v1/submit" => {
                    if behaviour.drop_submit {
                        return None;
                    }
                    let request: Request =
                        serde_json::from_value(payload["request"].clone()).ok()?;
                    Some(response_bytes(
                        202,
                        "Accepted",
                        &view(&request.identity().ok()?, "broadcast")?,
                    ))
                }
                "/v1/status" => {
                    let id = payload["request_id"].as_str()?;
                    Some(response_bytes(200, "OK", &view(id, "broadcast")?))
                }
                _ => Some(response_bytes(404, "Not Found", br#"{"error":"not_found"}"#)),
            }
        }
    }

    /// A relayer behind a fake SOCKS peer; returns the client and the knobs.
    async fn stand_up() -> anyhow::Result<(Client, Arc<Mutex<Behaviour>>, Peer, Release)> {
        let (release, init_b64, init, private) = fixture()?;
        let relayer = Arc::new(Relayer {
            scope: release.scope()?,
            public: init.worker_key.clone(),
            private,
            behaviour: Arc::default(),
        });
        let behaviour = relayer.behaviour.clone();
        let peer = Peer::default();
        let port = listen(peer.clone(), move |mut stream| {
            let relayer = relayer.clone();
            async move {
                let deadline = Instant::now() + Duration::from_secs(3);
                let Ok((start, _, body)) = receive(&mut stream, MAX_WIRE_BYTES, deadline).await
                else {
                    return;
                };
                if let Some(answer) = relayer.answer(&start, &body) {
                    let _ = stream.write_all(&answer).await;
                }
                let _ = stream.shutdown().await;
            }
        })
        .await?;
        let mut client =
            Client::from_bond(&release, &init_b64, TorProxy::new(port, Isolation::random())?, 3)?;
        at(&mut client, NOW);
        Ok((client, behaviour, peer, release))
    }

    /// Fixes the client's clock at `now`.
    fn at(client: &mut Client, now: u64) {
        client.set_clock(Arc::new(move || now));
    }

    /// A clock the fake relayer moves when it answers: it reads `before` until
    /// the relayer has answered and `after` from then on, so only a reading
    /// taken after the exchange sees `after`.
    fn advanced_by_the_relayer(
        behaviour: &Arc<Mutex<Behaviour>>,
        before: u64,
        after: u64,
    ) -> anyhow::Result<Clock> {
        let reading = Arc::new(std::sync::atomic::AtomicU64::new(before));
        behaviour.lock().map_err(|_| anyhow::anyhow!("lock"))?.advance =
            Some((reading.clone(), after));
        Ok(Arc::new(move || reading.load(std::sync::atomic::Ordering::SeqCst)))
    }

    fn request_for(client: &Client, q: &Quote) -> Request {
        Request {
            release: client.scope().to_owned(),
            intent: "0b".repeat(32),
            body_b64: STANDARD.encode(b"TEST-ONLY-body"),
            body_sha256: wire::hash(b"TEST-ONLY-body"),
            nullifiers: ["0c".repeat(32), "0d".repeat(32)],
            quote_hash: q.identity.clone(),
            fee_note_body: "0e".repeat(32),
            fee_slot: q.terms.slot,
            fee_note_index: q.terms.note_index,
            valid_until: u32::try_from(q.terms.valid_until).unwrap_or(u32::MAX),
            funding_cap: q.terms.funding_cap,
        }
    }

    #[tokio::test]
    async fn quote_submit_status_through_socks_only() -> anyhow::Result<()> {
        let (mut client, behaviour, peer, _) = stand_up().await?;
        let token = random_token();
        at(&mut client, NOW + 10);
        let q = client.quote(2, 300, &token).await?;
        assert_eq!((q.terms.amount, q.terms.slot, q.terms.valid_until - NOW), (7, 2, 300));
        let request = request_for(&client, &q);
        at(&mut client, NOW + 20);
        let status = client.submit(&request, &q).await?;
        assert_eq!(
            (status.status.as_str(), status.request_id.as_str()),
            ("broadcast", request.identity()?.as_str())
        );
        assert!(!status.is_terminal());
        let again = client.status(&request.identity()?, &token).await?;
        assert_eq!(again.status, "broadcast");
        let targets = peer.targets.lock().map_err(|_| anyhow::anyhow!("lock"))?.clone();
        assert_eq!(targets.len(), 3);
        assert!(targets.iter().all(|t| t.0.ends_with(".onion") && t.1 == 80));
        let credentials = peer.credentials.lock().map_err(|_| anyhow::anyhow!("lock"))?.clone();
        assert!(credentials.iter().all(|c| c == &credentials[0]));
        assert!(!String::from_utf8_lossy(&credentials[0].0).contains(&token));
        assert_eq!(
            behaviour.lock().map_err(|_| anyhow::anyhow!("lock"))?.paths,
            ["/v1/quote", "/v1/submit", "/v1/status"]
        );
        Ok(())
    }

    #[tokio::test]
    async fn quote_binding_lifetime_and_window_are_checked() -> anyhow::Result<()> {
        let (mut client, behaviour, _, _) = stand_up().await?;
        let token = random_token();
        assert!(matches!(client.quote(3, 300, &token).await, Err(ClientError::Rejected(_))));
        assert!(matches!(client.quote(2, 301, &token).await, Err(ClientError::Rejected(_))));
        assert!(matches!(
            client.quote(2, 300, &"00".repeat(32)).await,
            Err(ClientError::Rejected(_))
        ));
        // Outside the window on the local clock, read after the answer.
        at(&mut client, NOW - 1);
        assert!(matches!(client.quote(2, 300, &token).await, Err(ClientError::Rejected(_))));
        at(&mut client, NOW + 300);
        assert!(matches!(client.quote(2, 300, &token).await, Err(ClientError::Rejected(_))));
        at(&mut client, NOW);
        // An honest signature over terms that do not match the request.
        let tampers: [fn(&mut Value); 4] = [
            |t| t["slot"] = json!(1),
            |t| t["valid_until"] = json!(NOW + 299),
            |t| t["status_hash"] = json!("0f".repeat(32)),
            |t| t["note_index"] = json!(6),
        ];
        for tamper in tampers {
            behaviour.lock().map_err(|_| anyhow::anyhow!("lock"))?.tamper = Some(tamper);
            assert!(matches!(client.quote(2, 300, &token).await, Err(ClientError::Rejected(_))));
        }
        behaviour.lock().map_err(|_| anyhow::anyhow!("lock"))?.tamper = None;
        assert!(client.quote(2, 300, &token).await.is_ok());
        Ok(())
    }

    /// The relayer's clock is honest and the exchange takes time: the quote
    /// is issued after the request left. The window is judged by the clock
    /// as read when the answer is in hand, so ordinary latency never refuses
    /// a fresh quote, and a window that closed in flight is closed.
    #[tokio::test]
    async fn the_window_is_judged_after_the_answer_arrives() -> anyhow::Result<()> {
        let (mut client, behaviour, _, _) = stand_up().await?;
        let token = random_token();
        // The relayer issues at NOW. This clock reads NOW - 5 until the
        // relayer has answered and NOW + 2 from then on: a reading taken
        // before the exchange refuses the honest quote, one taken after
        // accepts it.
        client.set_clock(advanced_by_the_relayer(&behaviour, NOW - 5, NOW + 2)?);
        assert_eq!((client.clock)(), NOW - 5);
        let q = client.quote(2, 300, &token).await?;
        assert_eq!(q.terms.issued_at, NOW);
        assert_eq!((client.clock)(), NOW + 2);
        // A window that closed while the answer was in flight is closed,
        // whatever the clock said when the request left.
        client.set_clock(advanced_by_the_relayer(&behaviour, NOW, NOW + 300)?);
        assert_eq!((client.clock)(), NOW);
        assert!(matches!(client.quote(2, 300, &token).await, Err(ClientError::Rejected(_))));
        behaviour.lock().map_err(|_| anyhow::anyhow!("lock"))?.advance = None;
        // A submission is judged by the clock as read just before it leaves.
        let request = request_for(&client, &q);
        at(&mut client, NOW + 300);
        assert!(matches!(client.submit(&request, &q).await, Err(ClientError::Rejected(_))));
        at(&mut client, NOW + 10);
        assert!(client.submit(&request, &q).await.is_ok());
        Ok(())
    }

    /// An answer's bytes are untrusted and may echo what was sent, the status
    /// capability included; no error ever carries them.
    #[tokio::test]
    async fn an_answers_bytes_never_reach_an_error() -> anyhow::Result<()> {
        let (client, behaviour, _, _) = stand_up().await?;
        let token = random_token();
        let reflected = format!(r#"{{"error":"TEST-ONLY-MARKER {token}"}}"#);
        {
            let mut b = behaviour.lock().map_err(|_| anyhow::anyhow!("lock"))?;
            b.canned_status = Some(400);
            b.canned_body = Some(reflected.clone().into_bytes());
        }
        for shown in [
            client.quote(2, 300, &token).await.err().map(|e| e.to_string()),
            client.status(&"11".repeat(32), &token).await.err().map(|e| e.to_string()),
        ] {
            let shown = shown.ok_or_else(|| anyhow::anyhow!("refused"))?;
            assert!(shown.contains("400"), "{shown}");
            assert!(!shown.contains("TEST-ONLY-MARKER") && !shown.contains(&token), "{shown}");
        }
        // A 200 whose body is not the protocol's is unavailable with a fixed
        // message, never the body.
        {
            let mut b = behaviour.lock().map_err(|_| anyhow::anyhow!("lock"))?;
            b.canned_status = Some(200);
            b.canned_body = Some(format!("TEST-ONLY-MARKER {token} not json").into_bytes());
        }
        match client.quote(2, 300, &token).await {
            Err(ClientError::Unavailable(what)) => assert_eq!(what, "malformed JSON answer"),
            other => anyhow::bail!("expected unavailable, got {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn refusals_are_refused_and_malformed_is_unavailable() -> anyhow::Result<()> {
        let (client, behaviour, _, _) = stand_up().await?;
        let token = random_token();
        for status in [429u16, 503] {
            behaviour.lock().map_err(|_| anyhow::anyhow!("lock"))?.canned_status = Some(status);
            assert!(
                matches!(client.quote(2, 300, &token).await, Err(ClientError::Refused { status: s }) if s == status)
            );
            assert!(
                matches!(client.status(&"11".repeat(32), &token).await, Err(ClientError::Refused { status: s }) if s == status)
            );
        }
        behaviour.lock().map_err(|_| anyhow::anyhow!("lock"))?.canned_status = None;
        Ok(())
    }

    #[tokio::test]
    async fn a_refused_or_lost_submit_is_unknown_and_never_retried() -> anyhow::Result<()> {
        let (mut client, behaviour, _, _) = stand_up().await?;
        let token = random_token();
        let q = client.quote(2, 300, &token).await?;
        let request = request_for(&client, &q);
        at(&mut client, NOW + 1);
        {
            let mut b = behaviour.lock().map_err(|_| anyhow::anyhow!("lock"))?;
            b.canned_status = Some(503);
            b.canned_path = "/v1/submit".into();
        }
        match client.submit(&request, &q).await {
            Err(ClientError::SubmissionUnknown { request_id, cause }) => {
                assert_eq!(request_id, request.identity()?);
                assert!(cause.contains("503"), "{cause}");
            }
            other => anyhow::bail!("expected unknown, got {other:?}"),
        }
        {
            let mut b = behaviour.lock().map_err(|_| anyhow::anyhow!("lock"))?;
            b.canned_status = None;
            b.drop_submit = true;
        }
        assert!(matches!(
            client.submit(&request, &q).await,
            Err(ClientError::SubmissionUnknown { .. })
        ));
        // The original is asked about, not resent.
        assert_eq!(client.status(&request.identity()?, &token).await?.status, "broadcast");
        let paths = behaviour.lock().map_err(|_| anyhow::anyhow!("lock"))?.paths.clone();
        assert_eq!(paths.iter().filter(|p| p.as_str() == "/v1/submit").count(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn a_request_that_does_not_match_its_quote_is_rejected_before_sending(
    ) -> anyhow::Result<()> {
        let (mut client, behaviour, _, _) = stand_up().await?;
        let token = random_token();
        let q = client.quote(2, 300, &token).await?;
        let good = request_for(&client, &q);
        let mut wrong = good.clone();
        wrong.quote_hash = "0f".repeat(32);
        assert!(matches!(client.submit(&wrong, &q).await, Err(ClientError::Rejected(_))));
        let mut wrong = good.clone();
        wrong.valid_until += 1;
        assert!(matches!(client.submit(&wrong, &q).await, Err(ClientError::Rejected(_))));
        let mut wrong = good.clone();
        wrong.funding_cap += 1;
        assert!(matches!(client.submit(&wrong, &q).await, Err(ClientError::Rejected(_))));
        let mut wrong = good.clone();
        wrong.fee_note_index += 1;
        assert!(matches!(client.submit(&wrong, &q).await, Err(ClientError::Rejected(_))));
        // Expired on the local clock, read just before sending.
        at(&mut client, NOW + 300);
        assert!(matches!(client.submit(&good, &q).await, Err(ClientError::Rejected(_))));
        at(&mut client, NOW);
        // A quote whose stored envelope was altered is not authenticated.
        let mut altered = q.clone();
        altered.terms_value["amount"] = json!(8);
        assert!(matches!(client.submit(&good, &altered).await, Err(ClientError::Rejected(_))));
        let mut altered = q.clone();
        altered.status_token = random_token();
        assert!(matches!(client.submit(&good, &altered).await, Err(ClientError::Rejected(_))));
        assert!(behaviour
            .lock()
            .map_err(|_| anyhow::anyhow!("lock"))?
            .paths
            .iter()
            .all(|p| p != "/v1/submit"));
        Ok(())
    }

    #[tokio::test]
    async fn status_shape_and_semantics() -> anyhow::Result<()> {
        let (client, behaviour, _, _) = stand_up().await?;
        let token = random_token();
        let id = "11".repeat(32);
        let tampers: [fn(&mut Value); 7] = [
            |v| v["requires_independent_verification"] = json!(false),
            |v| v["status"] = json!("done"),
            |v| v["release"] = json!("0f".repeat(32)),
            |v| v["request_id"] = json!("12".repeat(32)),
            |v| {
                v["finality"] =
                    json!({"checkpoint_root": "0a".repeat(32), "proof_digest": "0b".repeat(32)})
            },
            |v| {
                v["status"] = json!("executed");
            },
            |v| v["acceptance_b64"] = json!("AB="),
        ];
        for tamper in tampers {
            behaviour.lock().map_err(|_| anyhow::anyhow!("lock"))?.tamper_status = Some(tamper);
            assert!(matches!(client.status(&id, &token).await, Err(ClientError::Rejected(_))));
        }
        behaviour.lock().map_err(|_| anyhow::anyhow!("lock"))?.tamper_status = Some(|v| {
            v["status"] = json!("executed");
            v["finality"] =
                json!({"checkpoint_root": "0a".repeat(32), "proof_digest": "0b".repeat(32)});
            v["acceptance_b64"] = json!(STANDARD.encode([1u8; 64]));
        });
        let status = client.status(&id, &token).await?;
        assert!(status.is_terminal());
        assert_eq!(status.finality.as_ref().map(|f| f.proof_digest.clone()), Some("0b".repeat(32)));
        assert!(matches!(
            client.status(&"00".repeat(32), &token).await,
            Err(ClientError::Rejected(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn the_endpoint_comes_from_the_authenticated_bond_and_nothing_else() -> anyhow::Result<()>
    {
        let (release, init_b64, init, _) = fixture()?;
        let proxy = || TorProxy::new(9050, Isolation::random());
        let client = Client::from_bond(&release, &init_b64, proxy()?, 60)?;
        assert_eq!(client.endpoint().origin(), init.endpoint);
        let mut wrong = release.clone();
        wrong.worker_key_hash = "0f".repeat(32);
        assert!(matches!(
            Client::from_bond(&wrong, &init_b64, proxy()?, 60),
            Err(ClientError::Rejected(_))
        ));
        let mut other = init.clone();
        other.endpoint = "https://example.invalid".into();
        assert!(matches!(
            Client::from_identity(&release, &other, proxy()?, 60),
            Err(ClientError::Rejected(_))
        ));
        assert!(matches!(
            Client::from_identity(&release, &init, proxy()?, 0),
            Err(ClientError::Rejected(_))
        ));
        assert!(matches!(
            Client::from_identity(&release, &init, proxy()?, 61),
            Err(ClientError::Rejected(_))
        ));
        // No daemon on this port: unavailable, and no other transport exists.
        let closed = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
        let port = closed.local_addr()?.port();
        drop(closed);
        let client =
            Client::from_identity(&release, &init, TorProxy::new(port, Isolation::random())?, 1)?;
        assert!(matches!(
            client.quote(2, 300, &random_token()).await,
            Err(ClientError::Unavailable(_))
        ));
        Ok(())
    }
}
