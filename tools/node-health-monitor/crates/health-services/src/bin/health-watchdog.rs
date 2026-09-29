use serde::Deserialize;
use std::{
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
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Heartbeat {
    schema_version: u32,
    sequence: String,
    process_epoch: String,
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
    let started = Instant::now();
    let state = WatchdogState::new(
        config.monitor_id.clone(),
        tos_health_services::secret(&config.pipeline_token_file)?,
    )?;
    let listener =
        tokio::net::TcpListener::bind(tos_health_services::loopback(&config.pipeline_listen)?)
            .await?;
    let router = tos_health_services::watchdog::router(state.clone());
    let _server = tokio::spawn(async move { axum::serve(listener, router).await });
    let mut notices = NoticeTracker::new(
        config.observer_id.clone(),
        tos_health_services::hex(&tos_health_services::random_token()?),
    )?;
    let mut last_health = None;
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {_=interval.tick()=>{},_=tokio::signal::ctrl_c()=>return Ok(())}
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
                        if let Ok(sequence) = tos_health_core::wire::exact_u64(&heartbeat.sequence)
                        {
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
                    eprintln!("watchdog alert accepted by receiver; end-user receipt unverified")
                }
                Err(error) => {
                    eprintln!("watchdog alert delivery failed; stable-key retry scheduled: {error}")
                }
            }
        }
    }
}
