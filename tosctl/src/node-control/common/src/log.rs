/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::app_config::{AppConfig, LogConfig, LogOutput, LogRotation};
use tracing_subscriber::{Layer, Registry, layer::SubscriberExt, util::SubscriberInitExt};

pub fn setup_log(
    config: Option<&AppConfig>,
) -> anyhow::Result<Option<tracing_appender::non_blocking::WorkerGuard>> {
    let default_log_config = LogConfig::default();
    let log_config = config.and_then(|c| c.log.as_ref()).unwrap_or(&default_log_config);
    let level = log_config.level;

    let make_filter = || -> anyhow::Result<tracing_subscriber::EnvFilter> {
        let base = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level.as_str()));
        without_constraint_system_spans(base)
    };

    let make_layer = || {
        tracing_subscriber::fmt::layer()
            .with_file(false)
            .with_line_number(false)
            .with_thread_ids(false)
            .with_thread_names(false)
            .with_target(true)
            .with_level(true)
    };

    let make_file_appender = || -> anyhow::Result<(tracing_appender::non_blocking::NonBlocking, tracing_appender::non_blocking::WorkerGuard)> {
        let log_file = log_config.path.as_ref().ok_or(anyhow::anyhow!("log.path is required when output is 'file' or 'all'"))?;
        let log_dir = log_file.parent().unwrap_or(std::path::Path::new("."));
        let log_name = log_file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("tosctl.log");

        let mut condition = rolling_file::RollingConditionBasic::new()
            .max_size(log_config.max_size_mb * 1_000_000);

        condition = match log_config.rotation {
            LogRotation::Hourly => condition.hourly(),
            LogRotation::Never => condition,
            LogRotation::Daily => condition.daily(),
        };

        let file_appender = rolling_file::BasicRollingFileAppender::new(
            log_dir.join(log_name),
            condition,
            log_config.max_files,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create log file appender: {e}"))?;

        Ok(tracing_appender::non_blocking(file_appender))
    };

    let mut layers: Vec<Box<dyn Layer<Registry> + Send + Sync>> = Vec::new();
    let guard: Option<tracing_appender::non_blocking::WorkerGuard> = match &log_config.output {
        LogOutput::Console => {
            layers.push(make_layer().with_ansi(true).with_filter(make_filter()?).boxed());
            None
        }
        LogOutput::File => {
            let (non_blocking, guard) = make_file_appender()?;
            layers.push(
                make_layer()
                    .with_writer(non_blocking)
                    .with_ansi(false)
                    .with_filter(make_filter()?)
                    .boxed(),
            );
            Some(guard)
        }
        LogOutput::All => {
            let (non_blocking, guard) = make_file_appender()?;
            layers.push(make_layer().with_ansi(true).with_filter(make_filter()?).boxed());
            layers.push(
                make_layer()
                    .with_writer(non_blocking)
                    .with_ansi(false)
                    .with_filter(make_filter()?)
                    .boxed(),
            );
            Some(guard)
        }
    };

    match tracing_subscriber::registry().with(layers).try_init() {
        Ok(()) => Ok(guard),
        Err(e) => {
            tracing::warn!("Global subscriber already set, skipping re-init: {e}");
            Ok(guard)
        }
    }
}

/// The zero-knowledge gadget library opens an `info`-level span, target `r1cs`, around every
/// constraint it emits and records its arguments; a recorded argument formats the whole
/// constraint system it belongs to. Under a formatting subscriber that turns one circuit
/// synthesis into quadratic time and tens of gigabytes of text, so those spans are never
/// wanted here. The directive names the target and therefore outranks any level the
/// environment or the configuration sets, including `trace`.
fn without_constraint_system_spans(
    filter: tracing_subscriber::EnvFilter,
) -> anyhow::Result<tracing_subscriber::EnvFilter> {
    let directive = "r1cs=off"
        .parse()
        .map_err(|e| anyhow::anyhow!("the constraint-system span directive does not parse: {e}"))?;
    Ok(filter.add_directive(directive))
}

#[cfg(test)]
mod tests {
    use super::without_constraint_system_spans;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tracing_subscriber::{EnvFilter, Layer, layer::SubscriberExt};

    /// Counts what reaches a layer behind the filter under test.
    #[derive(Default)]
    struct Seen {
        spans: AtomicUsize,
        events: AtomicUsize,
    }

    struct Counting(Arc<Seen>);

    impl<S: tracing::Subscriber> Layer<S> for Counting {
        fn on_new_span(
            &self,
            _attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            self.0.spans.fetch_add(1, Ordering::SeqCst);
        }

        fn on_event(
            &self,
            _event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            self.0.events.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn observe(base: EnvFilter) -> anyhow::Result<Arc<Seen>> {
        let seen = Arc::new(Seen::default());
        let filter = without_constraint_system_spans(base)?;
        let subscriber =
            tracing_subscriber::registry().with(Counting(Arc::clone(&seen)).with_filter(filter));
        tracing::subscriber::with_default(subscriber, || {
            tracing::info_span!(target: "r1cs", "permute").in_scope(|| {
                tracing::info!(target: "r1cs", "constraint");
            });
            tracing::info_span!(target: "tosctl", "command").in_scope(|| {
                tracing::info!(target: "tosctl", "progress");
            });
        });
        Ok(seen)
    }

    #[test]
    fn gadget_spans_are_dropped_and_the_program_s_own_kept() -> anyhow::Result<()> {
        let seen = observe(EnvFilter::new("info"))?;
        anyhow::ensure!(seen.spans.load(Ordering::SeqCst) == 1, "one span reaches the layer");
        anyhow::ensure!(seen.events.load(Ordering::SeqCst) == 1, "one event reaches the layer");
        Ok(())
    }

    #[test]
    fn a_trace_level_from_the_environment_does_not_bring_them_back() -> anyhow::Result<()> {
        let seen = observe(EnvFilter::new("trace"))?;
        anyhow::ensure!(seen.spans.load(Ordering::SeqCst) == 1, "one span reaches the layer");
        anyhow::ensure!(seen.events.load(Ordering::SeqCst) == 1, "one event reaches the layer");
        Ok(())
    }

    #[test]
    fn the_filter_under_test_is_the_one_that_drops_them() -> anyhow::Result<()> {
        // The control: the same observation without the directive sees both spans.
        let seen = Arc::new(Seen::default());
        let subscriber = tracing_subscriber::registry()
            .with(Counting(Arc::clone(&seen)).with_filter(EnvFilter::new("info")));
        tracing::subscriber::with_default(subscriber, || {
            tracing::info_span!(target: "r1cs", "permute").in_scope(|| {});
            tracing::info_span!(target: "tosctl", "command").in_scope(|| {});
        });
        anyhow::ensure!(seen.spans.load(Ordering::SeqCst) == 2, "both spans reach the layer");
        Ok(())
    }
}
