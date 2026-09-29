//! A fixed local native sampler. HTTP consumers have access only to NativeCache.
use crate::edge::EdgeState;
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tos_health_core::freshness::Freshness;
#[derive(Debug)]
pub struct NativeCache {
    freshness: Freshness,
    body: Option<String>,
    started: Instant,
}
impl Default for NativeCache {
    fn default() -> Self {
        Self { freshness: Freshness::default(), body: None, started: Instant::now() }
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
        // The native exporter appends live transport counters after its immutable sample.
        // They must not become the content identity of that sample.
        let stable: String = body
            .lines()
            .filter(|line| {
                ![
                    "_exporter_collection_inflight",
                    "_exporter_collection_skipped_total",
                    "_exporter_collection_failures_total",
                ]
                .iter()
                .any(|name| line.contains(name))
            })
            .map(|s| format!("{s}\n"))
            .collect();
        let hash = format!("{:x}", Sha256::digest(stable.as_bytes()));
        let accepted = self
            .freshness
            .observe(process, "native-v1", generation, &hash, self.now(), age, duration)
            .map_err(str::to_owned)?;
        if accepted {
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
        Ok(Self { client, address, state, next_due: Instant::now() })
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
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            if bytes.len().saturating_add(chunk.len()) > 2_097_152 {
                return Err("native body limit".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let body = String::from_utf8(bytes).map_err(|_| "native not UTF-8")?;
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
