//! A fixed local native sampler. HTTP consumers have access only to NativeCache.
use crate::edge::EdgeState;
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tos_health_core::{
    freshness::Freshness,
    native::{immutable_metrics, NativeEnvelope},
};
#[derive(Debug)]
pub struct NativeCache {
    pub network: Option<String>,
    freshness: Freshness,
    body: Option<String>,
    started: Instant,
    typed: Option<(NativeEnvelope, Instant)>,
}
impl Default for NativeCache {
    fn default() -> Self {
        Self {
            network: None,
            freshness: Freshness::default(),
            body: None,
            started: Instant::now(),
            typed: None,
        }
    }
}
impl NativeCache {
    fn now(&self) -> u64 {
        self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    }
    pub fn read(&self) -> Option<String> {
        if self.freshness.usable(self.now(), 30_000) {
            self.body.clone()
        } else {
            None
        }
    }
    pub fn publish(
        &mut self,
        process: &str,
        generation: u64,
        body: String,
        age: u64,
        duration: u64,
    ) -> Result<bool, String> {
        if body.len() > 2_097_152 || !body.ends_with("# EOF\n") {
            return Err("invalid native body".into());
        }
        // C01 freezes and identifies the complete returned body, including
        // exporter transport fields from the completed generation.
        let stable = immutable_metrics(&body);
        let hash = format!("{:x}", Sha256::digest(stable.as_bytes()));
        let accepted = self
            .freshness
            .observe(process, "native-v1", generation, &hash, self.now(), age, duration)
            .map_err(str::to_owned)?;
        if accepted {
            self.body = Some(body);
            self.typed = None;
        }
        Ok(accepted)
    }
    pub fn read_typed(&self) -> Option<NativeEnvelope> {
        if !self.freshness.usable(self.now(), 30_000) {
            return None;
        }
        let (value, accepted) = self.typed.as_ref()?;
        let mut value = value.clone();
        value.source_age_ms = value
            .source_age_ms?
            .checked_add(accepted.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);
        if value.source_age_ms.is_none_or(|age| age > 30_000) {
            return None;
        }
        Some(value)
    }
    pub fn publish_typed(
        &mut self,
        value: NativeEnvelope,
        body: String,
        duration: u64,
    ) -> Result<bool, String> {
        value.paired(
            &value.node_id,
            &value.payload.network_id,
            &value.generation.0.to_string(),
            &value.process_epoch,
            &body,
        )?;
        let age = value.source_age_ms.ok_or("missing source age")?;
        let adjusted_age = age.checked_add(duration).ok_or("age overflow")?;
        if adjusted_age > 30_000 {
            return Err("native pair stale".into());
        }
        let accepted = self
            .freshness
            .observe(
                &value.process_epoch,
                &value.source_epoch,
                value.generation.0,
                &value.immutable_hash()?,
                self.now(),
                age,
                duration,
            )
            .map_err(str::to_owned)?;
        if accepted {
            let mut value = value;
            value.source_age_ms = Some(adjusted_age);
            value.received_at =
                Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
            self.typed = Some((value, Instant::now()));
            self.body = Some(body);
        }
        Ok(accepted)
    }
}
pub struct NativeSampler {
    client: reqwest::Client,
    address: SocketAddr,
    state: EdgeState,
    next_due: Instant,
    network: Option<String>,
}
impl NativeSampler {
    pub fn new(address: SocketAddr, state: EdgeState) -> Result<Self, String> {
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err("native address must be loopback".into());
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(3))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { client, address, state, next_due: Instant::now(), network: None })
    }
    pub fn with_network(mut self, network: String) -> Result<Self, String> {
        if !tos_health_core::wire::hash(&network) {
            return Err("invalid network identity".into());
        }
        self.state.native.lock().map_err(|_| "native cache unavailable")?.network =
            Some(network.clone());
        self.network = Some(network);
        Ok(self)
    }
    pub async fn collect(&mut self) -> Result<bool, String> {
        if Instant::now() < self.next_due {
            return Err("native collection not due".into());
        }
        self.next_due = Instant::now() + Duration::from_secs(15);
        let epoch = {
            let cache = self.state.cache.lock().map_err(|_| "process cache unavailable")?;
            let sample = cache.as_ref().ok_or("process cache cold")?;
            if !sample.quality.usable(chrono::Utc::now().timestamp_millis(), 30_000, false) {
                return Err("process sample stale".into());
            }
            sample.process_epoch.clone()
        };
        let started = Instant::now();
        let mut response = self
            .client
            .get(format!("http://{}/metrics", self.address))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if response.status() != reqwest::StatusCode::OK {
            return Err("native unavailable".into());
        }
        if response.content_length().is_some_and(|n| n > 2_097_152) {
            return Err("native body limit".into());
        }
        let generation_header = response
            .headers()
            .get("x-tos-snapshot-generation")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let epoch_header = response
            .headers()
            .get("x-tos-process-epoch")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            if bytes.len().saturating_add(chunk.len()) > 2_097_152 {
                return Err("native body limit".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let body = String::from_utf8(bytes).map_err(|_| "native not UTF-8")?;
        if let Some(network) = &self.network {
            // One cache-only paired read per scheduled scrape. No mismatch retry.
            let response = self
                .client
                .get(format!("http://{}/health-snapshot", self.address))
                .send()
                .await
                .map_err(|e| e.to_string())?;
            let bytes = crate::bounded_body(response, 262_144).await?;
            let value: NativeEnvelope =
                serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            value.paired(
                &self.state.node,
                network,
                generation_header.as_deref().ok_or("missing exact generation header")?,
                epoch_header.as_deref().ok_or("missing native epoch header")?,
                &body,
            )?;
            let current_epoch = self
                .state
                .cache
                .lock()
                .map_err(|_| "process cache unavailable")?
                .as_ref()
                .map(|e| e.process_epoch.clone());
            if current_epoch.as_deref() != Some(&epoch) {
                return Err("process epoch changed".into());
            }
            return self
                .state
                .native
                .lock()
                .map_err(|_| "native cache unavailable")?
                .publish_typed(value, body, started.elapsed().as_millis() as u64);
        }
        let scalar = |suffix: &str| -> Result<&str, String> {
            let mut found = None;
            for line in body.lines().filter(|l| !l.starts_with('#')) {
                let mut words = line.split_whitespace();
                if words.next().is_some_and(|name| name.ends_with(suffix)) {
                    if found.is_some() {
                        return Err("duplicate native marker".into());
                    }
                    found = words.next();
                    if words.next().is_some() {
                        return Err("invalid native marker".into());
                    }
                }
            }
            found.ok_or_else(|| "missing native marker".into())
        };
        let generation = tos_health_core::wire::exact_u64(scalar("_exporter_snapshot_generation")?)
            .map_err(str::to_owned)?;
        if generation > 9_007_199_254_740_991 {
            return Err("native float generation precision exhausted".into());
        }
        let completed = scalar("_exporter_snapshot_completed_timestamp_seconds")?
            .parse::<f64>()
            .map_err(|_| "invalid native timestamp")?;
        let wall = chrono::Utc::now().timestamp_millis() as f64;
        let age = wall - completed * 1000.;
        if !age.is_finite() || !(0.0..=30_000.).contains(&age) {
            return Err("native timestamp stale or future".into());
        }
        let current_epoch = self
            .state
            .cache
            .lock()
            .map_err(|_| "process cache unavailable")?
            .as_ref()
            .map(|e| e.process_epoch.clone());
        if current_epoch.as_deref() != Some(&epoch) {
            return Err("process epoch changed".into());
        }
        self.state.native.lock().map_err(|_| "native cache unavailable")?.publish(
            &epoch,
            generation,
            body,
            age.ceil() as u64,
            started.elapsed().as_millis() as u64,
        )
    }
    pub async fn run(mut self) {
        loop {
            tokio::time::sleep_until(tokio::time::Instant::from_std(self.next_due)).await;
            let _ = self.collect().await;
        }
    }
}
pub fn cache() -> Arc<Mutex<NativeCache>> {
    Arc::new(Mutex::new(NativeCache::default()))
}
