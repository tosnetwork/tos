use serde::Deserialize;
use std::{
    future::Future,
    path::PathBuf,
    time::{Duration, Instant},
};
use tos_health_services::watchdog::{send_notice, NoticeTracker, WatchdogState};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    monitor_url: String,
    receiver_url: String,
    ca_file: PathBuf,
    identity_file: PathBuf,
    monitor_token_file: PathBuf,
    receiver_token_file: PathBuf,
    observer_id: String,
    monitor_id: String,
    pipeline_listen: String,
    pipeline_token_file: PathBuf,
    #[serde(default)]
    witness_development: Option<WitnessDevelopment>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WitnessDevelopment {
    development_only: bool,
    plan_file: PathBuf,
    cache_listen: String,
    read_token_file: PathBuf,
    source_ca_file: PathBuf,
    source_identity_file: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Heartbeat {
    schema_version: u32,
    sequence: String,
    process_epoch: String,
}
/// An O lane exiting (Err, panic, or unexpected Ok) preempts even a slow
/// monitor request or notice delivery. The process then fails nonzero; it
/// never reports a V fault or claims remote witness cancellation.
async fn supervise_tick<F>(
    pipeline: &mut tokio::task::JoinHandle<std::io::Result<()>>,
    cache: &mut Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    source: &mut Option<tokio::task::JoinHandle<Result<(), &'static str>>>,
    tick: F,
) -> Result<(), String>
where
    F: Future<Output = Result<(), String>>,
{
    tokio::select! {
        biased;
        result = pipeline => {
            eprintln!("watchdog pipeline listener stopped: {result:?}");
            Err("watchdog pipeline listener unavailable".into())
        }
        result = async { cache.as_mut().unwrap().await }, if cache.is_some() => {
            eprintln!("witness cache listener stopped: {result:?}");
            Err("witness cache listener unavailable".into())
        }
        result = async { source.as_mut().unwrap().await }, if source.is_some() => {
            eprintln!("witness source owner stopped: {result:?}; remote completion remains unknown");
            Err("witness source owner unavailable".into())
        }
        result = tick => result,
    }
}
#[tokio::main(worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        return Err("usage: health-watchdog CONFIG_JSON".into());
    }
    let bytes = std::fs::read(&args[1])?;
    if bytes.len() > 16_384 {
        return Err("config too large".into());
    }
    let config: Config = serde_json::from_slice(&bytes)?;
    if !tos_health_services::alias(&config.observer_id) {
        return Err("invalid observer alias".into());
    }
    for endpoint in [&config.monitor_url, &config.receiver_url] {
        let url = reqwest::Url::parse(endpoint)?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("fixed HTTPS endpoints are required".into());
        }
    }
    let client = tos_health_services::client(&config.ca_file, &config.identity_file)?;
    let monitor_token =
        String::from_utf8(tos_health_services::secret(&config.monitor_token_file)?)?;
    let receiver_token =
        String::from_utf8(tos_health_services::secret(&config.receiver_token_file)?)?;
    let mut frozen_witness_plan = if let Some(witness) = &config.witness_development {
        if !witness.development_only {
            return Err("witness production activation is unsupported".into());
        }
        let plan = tos_health_core::witness::Plan::read_file(&witness.plan_file)?;
        if plan.observer_id != config.observer_id {
            return Err("witness observer ID mismatch".into());
        }
        Some(plan)
    } else {
        None
    };
    let observer_epoch = frozen_witness_plan
        .as_ref()
        .map(|plan| plan.observer_epoch.clone())
        .unwrap_or(tos_health_services::hex(&tos_health_services::random_token()?));
    let started = Instant::now();
    let state = WatchdogState::new_with_epoch(
        config.monitor_id.clone(),
        config.observer_id.clone(),
        observer_epoch.clone(),
        tos_health_services::secret(&config.pipeline_token_file)?,
    )?;
    let listener =
        tokio::net::TcpListener::bind(tos_health_services::loopback(&config.pipeline_listen)?)
            .await?;
    let router = tos_health_services::watchdog::router(state.clone());
    let mut pipeline_server = tokio::spawn(async move { axum::serve(listener, router).await });
    let mut witness_server = None;
    let mut witness_poller = None;
    if let Some(witness) = &config.witness_development {
        let plan = frozen_witness_plan.take().ok_or("witness plan absent")?;
        let cache = tos_health_services::witness::WitnessCache::new(
            plan,
            tos_health_services::secret(&witness.read_token_file)?,
        )?;
        let source = tos_health_services::witness::WitnessClient::new(
            &witness.source_ca_file,
            &witness.source_identity_file,
        )?;
        let listener =
            tokio::net::TcpListener::bind(tos_health_services::loopback(&witness.cache_listen)?)
                .await?;
        let cache_router = tos_health_services::witness::router(cache.clone());
        witness_server =
            Some(tokio::spawn(async move { axum::serve(listener, cache_router).await }));
        witness_poller = Some(tokio::spawn(async move {
            tos_health_services::witness::run_fixed(cache, source).await
        }));
    }
    let mut notices = NoticeTracker::new(config.observer_id.clone(), observer_epoch)?;
    let mut last_health = None;
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            result = supervise_tick(&mut pipeline_server, &mut witness_server, &mut witness_poller, async {
                interval.tick().await;
                let now = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
                if let Ok(response) =
                    client.get(&config.monitor_url).bearer_auth(&monitor_token).send().await
                {
                    if let Ok(bytes) = tos_health_services::bounded_body(response, 4096).await {
                        if let Ok(heartbeat) = serde_json::from_slice::<Heartbeat>(&bytes) {
                            if heartbeat.schema_version == 1
                                && !heartbeat.process_epoch.is_empty()
                                && heartbeat.process_epoch.len() <= 128
                            {
                                if let Ok(sequence) = tos_health_core::wire::exact_u64(&heartbeat.sequence) {
                                    let _ = state.receive_process(&heartbeat.process_epoch, sequence);
                                }
                            }
                        }
                    }
                }
                let (process_unavailable, pipeline_unavailable) = state.unavailable()?;
                let due = notices.due(now, process_unavailable, pipeline_unavailable)?;
                if last_health != Some((process_unavailable, pipeline_unavailable)) {
                    eprintln!("watchdog status process_unavailable={} pipeline_unavailable={} observed_unix_ms={}",
                        process_unavailable, pipeline_unavailable, chrono::Utc::now().timestamp_millis());
                    last_health = Some((process_unavailable, pipeline_unavailable));
                }
                if let Some((key, alert)) = due {
                    match send_notice(&client, &config.receiver_url, &receiver_token, &key, &alert).await {
                        Ok(()) => {
                            state.notice_result(true)?;
                            eprintln!("watchdog alert accepted by receiver; end-user receipt unverified");
                        }
                        Err(error) => {
                            state.notice_result(false)?;
                            eprintln!("watchdog alert delivery failed; stable-key retry scheduled: {error}");
                        }
                    }
                }
                state.completed_tick()?;
                Ok::<(), String>(())
            }) => result?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn unexpected_source_lane_exit_preempts_slow_notice_work() {
        let mut pipeline =
            tokio::spawn(async { std::future::pending::<std::io::Result<()>>().await });
        let mut cache = None;
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let mut source = Some(tokio::spawn(async move {
            release_rx.await.unwrap();
            Err("synthetic owner failure")
        }));
        let release = tokio::spawn(async move {
            entered_rx.await.unwrap();
            release_tx.send(()).unwrap();
        });
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            supervise_tick(&mut pipeline, &mut cache, &mut source, async {
                entered_tx.send(()).unwrap();
                tokio::time::sleep(Duration::from_secs(5)).await;
                Ok(())
            }),
        )
        .await
        .unwrap();
        release.await.unwrap();
        assert_eq!(result.unwrap_err(), "witness source owner unavailable");
        pipeline.abort();
    }
    #[tokio::test]
    async fn unexpected_cache_listener_ok_is_still_fatal() {
        let mut pipeline =
            tokio::spawn(async { std::future::pending::<std::io::Result<()>>().await });
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let mut cache = Some(tokio::spawn(async move {
            release_rx.await.unwrap();
            Ok(())
        }));
        let mut source = None;
        let release = tokio::spawn(async move {
            entered_rx.await.unwrap();
            release_tx.send(()).unwrap();
        });
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            supervise_tick(&mut pipeline, &mut cache, &mut source, async {
                entered_tx.send(()).unwrap();
                tokio::time::sleep(Duration::from_secs(5)).await;
                Ok(())
            }),
        )
        .await
        .unwrap();
        release.await.unwrap();
        assert_eq!(result.unwrap_err(), "witness cache listener unavailable");
        pipeline.abort();
    }
}
