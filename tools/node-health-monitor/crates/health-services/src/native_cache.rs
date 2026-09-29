//! A fixed local native sampler. HTTP consumers have access only to NativeCache.
use crate::edge::EdgeState;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    net::SocketAddr,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tos_health_core::{
    edge_snapshot::NativeProcessBinding,
    freshness::Freshness,
    native::{immutable_metrics, parse_native, NativeEnvelope, NativeRecord},
    wire::U64,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessProbe {
    epoch: String,
    pid: u32,
    start_ticks: u64,
    exe_identity_sha256: String,
    listener_inode: u64,
    listener_addr: SocketAddr,
}
impl ProcessProbe {
    fn local_hex(address: SocketAddr) -> String {
        match address {
            SocketAddr::V4(addr) => {
                addr.ip().octets().iter().rev().map(|byte| format!("{byte:02X}")).collect()
            }
            SocketAddr::V6(addr) => addr
                .ip()
                .octets()
                .chunks_exact(4)
                .flat_map(|chunk| chunk.iter().rev())
                .map(|byte| format!("{byte:02X}"))
                .collect(),
        }
    }
    pub(crate) fn capture(pid: u32, listener_addr: SocketAddr) -> Result<Self, String> {
        let started = Instant::now();
        if pid == 0 || !listener_addr.ip().is_loopback() || listener_addr.port() == 0 {
            return Err("invalid native process binding target".into());
        }
        let proc = Path::new("/proc").join(pid.to_string());
        let epoch = crate::edge::process_epoch_from(Path::new("/proc"), pid)?;
        let start_ticks = epoch
            .rsplit(':')
            .next()
            .ok_or("missing process start")?
            .parse::<u64>()
            .map_err(|_| "invalid process start")?;
        let exe_path = proc.join("exe");
        let exe = fs::read_link(&exe_path).map_err(|e| e.to_string())?;
        let meta = fs::metadata(&exe_path).map_err(|e| e.to_string())?;
        let mut identity = exe.as_os_str().as_bytes().to_vec();
        identity.extend_from_slice(&meta.dev().to_le_bytes());
        identity.extend_from_slice(&meta.ino().to_le_bytes());
        let exe_identity_sha256 = format!("{:x}", Sha256::digest(&identity));
        let tcp = if listener_addr.is_ipv4() { "tcp" } else { "tcp6" };
        let table = proc.join("net").join(tcp);
        let mut raw = Vec::new();
        fs::File::open(&table)
            .map_err(|e| e.to_string())?
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut raw)
            .map_err(|e| e.to_string())?;
        if raw.len() > 4 * 1024 * 1024 {
            return Err("native socket table too large".into());
        }
        let raw = String::from_utf8(raw).map_err(|_| "native socket table not UTF-8")?;
        let expected = format!("{}:{:04X}", Self::local_hex(listener_addr), listener_addr.port());
        let mut socket_inode = None;
        for line in raw.lines().skip(1) {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() > 9 && fields[1].eq_ignore_ascii_case(&expected) && fields[3] == "0A" {
                let inode = fields[9].parse::<u64>().map_err(|_| "invalid native socket inode")?;
                if inode == 0 || socket_inode.replace(inode).is_some() {
                    return Err("ambiguous native listener".into());
                }
            }
        }
        let listener_inode = socket_inode.ok_or("native listener not found")?;
        let target = format!("socket:[{listener_inode}]");
        let mut owned = false;
        let mut inspected = 0usize;
        for entry in fs::read_dir(proc.join("fd")).map_err(|e| e.to_string())? {
            inspected += 1;
            if inspected > 8192 {
                return Err("native process FD inventory too large".into());
            }
            if started.elapsed() > Duration::from_secs(1) {
                return Err("native identity probe deadline".into());
            }
            let entry = entry.map_err(|e| e.to_string())?;
            if fs::read_link(entry.path()).is_ok_and(|link| link == Path::new(&target)) {
                owned = true;
            }
        }
        if !owned {
            return Err("native listener not owned by configured PID".into());
        }
        if crate::edge::process_epoch_from(Path::new("/proc"), pid)? != epoch {
            return Err("process changed during native identity check".into());
        }
        if started.elapsed() > Duration::from_secs(1) {
            return Err("native identity probe deadline".into());
        }
        Ok(Self { epoch, pid, start_ticks, exe_identity_sha256, listener_inode, listener_addr })
    }
    pub(crate) fn binding(&self, native_epoch: &str) -> NativeProcessBinding {
        NativeProcessBinding {
            kind: "native_process_binding".into(),
            process_epoch: self.epoch.clone(),
            native_epoch: native_epoch.into(),
            pid: self.pid,
            start_ticks: U64(self.start_ticks),
            exe_identity_sha256: self.exe_identity_sha256.clone(),
            listener_inode: U64(self.listener_inode),
            listener_addr: self.listener_addr.to_string(),
            checked_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        }
    }
}

/// Bounded local ownership check for a fixture or native sampler. The sampler
/// additionally repeats it after the paired HTTP reads before publication.
pub fn verified_binding(
    pid: u32,
    address: SocketAddr,
    native_epoch: &str,
) -> Result<NativeProcessBinding, String> {
    if native_epoch.is_empty() || native_epoch.len() > 128 {
        return Err("invalid native publisher epoch".into());
    }
    Ok(ProcessProbe::capture(pid, address)?.binding(native_epoch))
}
#[derive(Debug)]
pub struct NativeCache {
    pub network: Option<String>,
    freshness: Freshness,
    body: Option<String>,
    started: Instant,
    typed: Option<(NativeRecord, Instant)>,
    binding: Option<NativeProcessBinding>,
}
impl Default for NativeCache {
    fn default() -> Self {
        Self {
            network: None,
            freshness: Freshness::default(),
            body: None,
            started: Instant::now(),
            typed: None,
            binding: None,
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
    pub fn age_ms(&self) -> Option<u64> {
        self.freshness.age(self.now())
    }
    pub fn usable(&self) -> bool {
        self.freshness.usable(self.now(), 30_000)
    }
    pub fn configured(&self) -> bool {
        self.network.is_some()
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
            self.binding = None;
        }
        Ok(accepted)
    }
    pub fn read_typed(&self) -> Option<NativeEnvelope> {
        match self.read_record()? {
            NativeRecord::V1(v) => Some(v),
            NativeRecord::V2(_) => None,
        }
    }
    pub fn read_record(&self) -> Option<NativeRecord> {
        if !self.freshness.usable(self.now(), 30_000) {
            return None;
        }
        let (value, accepted) = self.typed.as_ref()?;
        let mut value = value.clone();
        let age = value
            .source_age_ms()?
            .checked_add(accepted.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);
        if age.is_none_or(|age| age > 30_000) {
            return None;
        }
        value.set_source_age_ms(age);
        Some(value)
    }
    pub fn read_binding(&self) -> Option<NativeProcessBinding> {
        self.read_record()?;
        self.binding.clone()
    }
    pub fn publish_typed(
        &mut self,
        value: NativeEnvelope,
        body: String,
        duration: u64,
    ) -> Result<bool, String> {
        self.publish_record(NativeRecord::V1(value), body, duration)
    }
    pub fn publish_record(
        &mut self,
        value: NativeRecord,
        body: String,
        duration: u64,
    ) -> Result<bool, String> {
        self.publish_record_with_binding(value, body, duration, None)
    }
    pub fn publish_record_with_binding(
        &mut self,
        value: NativeRecord,
        body: String,
        duration: u64,
        binding: Option<NativeProcessBinding>,
    ) -> Result<bool, String> {
        if binding.as_ref().is_some_and(|b| b.native_epoch != value.process_epoch()) {
            return Err("native publisher epoch binding mismatch".into());
        }
        value.paired(
            value.node_id(),
            value.network_id(),
            &value.generation().0.to_string(),
            value.process_epoch(),
            &body,
        )?;
        let age = value.source_age_ms().ok_or("missing source age")?;
        let adjusted_age = age.checked_add(duration).ok_or("age overflow")?;
        if adjusted_age > 30_000 {
            return Err("native pair stale".into());
        }
        let accepted = self
            .freshness
            .observe(
                value.process_epoch(),
                match &value {
                    NativeRecord::V1(v) => &v.source_epoch,
                    NativeRecord::V2(v) => &v.source_epoch,
                },
                value.generation().0,
                &value.immutable_hash()?,
                self.now(),
                age,
                duration,
            )
            .map_err(str::to_owned)?;
        if accepted {
            let mut value = value;
            value.set_source_age_ms(Some(adjusted_age));
            value.set_received_at(Some(
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            ));
            self.typed = Some((value, Instant::now()));
            self.body = Some(body);
            self.binding = binding;
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
const NATIVE_INTERVAL: Duration = Duration::from_secs(15);

#[doc(hidden)]
pub fn next_due_after_completion(next_due: Instant, completed: Instant) -> Instant {
    if next_due <= completed {
        completed + NATIVE_INTERVAL
    } else {
        next_due
    }
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
        self.next_due = Instant::now() + NATIVE_INTERVAL;
        let (epoch, pid) = {
            let cache = self.state.cache.lock().map_err(|_| "process cache unavailable")?;
            let sample = cache.as_ref().ok_or("process cache cold")?;
            if !sample.quality.usable(chrono::Utc::now().timestamp_millis(), 30_000, false) {
                return Err("process sample stale".into());
            }
            let pid = if self.network.is_some() {
                Some(
                    sample.payload["pid"]
                        .as_u64()
                        .and_then(|value| u32::try_from(value).ok())
                        .ok_or("process PID unavailable")?,
                )
            } else {
                None
            };
            (sample.process_epoch.clone(), pid)
        };
        let before = if self.network.is_some() {
            let probe = ProcessProbe::capture(pid.ok_or("process PID unavailable")?, self.address)?;
            if probe.epoch != epoch {
                return Err("process identity changed before native collection".into());
            }
            Some(probe)
        } else {
            None
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
            let value = parse_native(&bytes)?;
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
            let after = ProcessProbe::capture(pid.ok_or("process PID unavailable")?, self.address)?;
            if before.as_ref() != Some(&after) {
                return Err("native process/listener changed during paired collection".into());
            }
            let binding = after.binding(value.process_epoch());
            return self
                .state
                .native
                .lock()
                .map_err(|_| "native cache unavailable")?
                .publish_record_with_binding(
                    value,
                    body,
                    started.elapsed().as_millis() as u64,
                    Some(binding),
                );
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
            self.next_due = next_due_after_completion(self.next_due, Instant::now());
        }
    }
}
pub fn cache() -> Arc<Mutex<NativeCache>> {
    Arc::new(Mutex::new(NativeCache::default()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn actual_run_waits_full_interval_after_source_misses_tick() {
        let calls = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let done = completed.clone();
        let app = Router::new().route(
            "/metrics",
            get(move || {
                let seen = seen.clone();
                let done = done.clone();
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(16_500)).await;
                    done.fetch_add(1, Ordering::SeqCst);
                    let timestamp = chrono::Utc::now().timestamp_millis() as f64 / 1000.;
                    format!(
                        "# TYPE test_exporter_snapshot_generation gauge\n\
                         test_exporter_snapshot_generation 1\n\
                         # TYPE test_exporter_snapshot_completed_timestamp_seconds gauge\n\
                         test_exporter_snapshot_completed_timestamp_seconds {timestamp}\n\
                         # EOF\n"
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let state = EdgeState::new("v1".into(), vec![b'e'; 32]);
        let pid =
            std::fs::read_link("/proc/self").unwrap().to_string_lossy().parse::<u32>().unwrap();
        *state.cache.lock().unwrap() = Some(crate::edge::sample_process("v1", pid, 1).unwrap());
        let mut sampler = NativeSampler::new(address, state).unwrap();
        // Test-only override: production remains at three seconds. Twenty
        // seconds lets an actual synthetic source cross the 15-second tick.
        sampler.client =
            reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(20)).build().unwrap();
        let runner = tokio::spawn(sampler.run());
        tokio::time::timeout(Duration::from_secs(18), async {
            while completed.load(Ordering::SeqCst) != 1 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1, "missed tick caused immediate catch-up");
        assert_eq!(completed.load(Ordering::SeqCst), 1);
        runner.abort();
        server.abort();
    }
}
